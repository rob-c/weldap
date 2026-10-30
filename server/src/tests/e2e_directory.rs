//! `LdapDirectory` end to end against a fake 389 DS on loopback (LDAPS with a test certificate): TLS to the
//! directory, simple binds, the membership read, the service account, and every way the directory can fail.

use crate::config;
use crate::directory::{Directory, Failure, LdapDirectory, Membership};
use crate::secret::SecretBuf;
use crate::tests::support::{bind_response, lock, parse, pki, search_done, search_entry, Leaf, TempDir};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const USERS: &str = "cn=weldap-users,ou=groups,dc=example,dc=org";
const ADMINS: &str = "cn=weldap-admins,ou=groups,dc=example,dc=org";
const SVC_DN: &str = "cn=svc,dc=example,dc=org";
const SVC_PW: &[u8] = b"service secret";

fn dn(uun: &str) -> String {
    format!("uid={uun},ou=people,dc=example,dc=org")
}

#[derive(Clone, Default)]
struct Script {
    passwords: HashMap<String, Vec<u8>>,
    /// Bind result code by DN, overriding the password check.
    codes: HashMap<String, u8>,
    entries: HashMap<String, Vec<&'static str>>,
    hang_up_after_bind: bool,
    /// Read the bind request, then close without answering it (the bind reply read hits EOF).
    drop_before_bind_reply: bool,
}

#[derive(Default)]
struct Seen {
    binds: Vec<(String, Vec<u8>)>,
    ops: Vec<u8>,
}

struct FakeLdaps {
    addr: SocketAddr,
    seen: Arc<Mutex<Seen>>,
}

fn read_message(s: &mut impl Read) -> Option<Vec<u8>> {
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr).ok()?;
    let mut msg = hdr.to_vec();
    let len = if hdr[1] < 0x80 {
        usize::from(hdr[1])
    } else {
        let mut l = vec![0u8; usize::from(hdr[1] & 0x7f)];
        s.read_exact(&mut l).ok()?;
        msg.extend_from_slice(&l);
        l.iter().fold(0usize, |a, b| (a << 8) | usize::from(*b))
    };
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).ok()?;
    msg.extend(body);
    Some(msg)
}

fn conversation(s: &mut impl ReadWrite, script: &Script, seen: &Mutex<Seen>) -> Option<()> {
    loop {
        let m = read_message(s)?;
        let (_, body, _) = parse(&m)?;
        let (_, id, rest) = parse(body)?;
        let id = *id.first()?;
        let (tag, op, _) = parse(rest)?;
        lock(seen).ops.push(tag);
        match tag {
            0x60 => {
                let (_, _version, r) = parse(op)?;
                let (_, name, r) = parse(r)?;
                let (_, pw, _) = parse(r)?;
                let name = String::from_utf8_lossy(name).into_owned();
                lock(seen).binds.push((name.clone(), pw.to_vec()));
                if script.drop_before_bind_reply {
                    return None;
                }
                let code = script.codes.get(&name).copied().unwrap_or_else(|| {
                    if script.passwords.get(&name).is_some_and(|p| p.as_slice() == pw) {
                        0
                    } else {
                        49
                    }
                });
                s.write_all(&bind_response(id, code)).ok()?;
                if script.hang_up_after_bind {
                    return None;
                }
            }
            0x63 => {
                let (_, base, _) = parse(op)?;
                let base = String::from_utf8_lossy(base).into_owned();
                let reply = match script.entries.get(&base) {
                    Some(groups) => [search_entry(id, &base, &[("memberOf", groups)]), search_done(id, 0)].concat(),
                    None => search_done(id, 32),
                };
                s.write_all(&reply).ok()?;
            }
            _ => return None, // unbind or anything else: hang up
        }
        s.flush().ok()?;
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn fake(script: Script, cert: &Leaf) -> FakeLdaps {
    let key = PrivateKeyDer::from_pem_slice(cert.key_pem.as_bytes()).unwrap();
    let chain: Vec<CertificateDer<'static>> = vec![cert.der.clone()];
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let (cfg, script, seen) = (cfg.clone(), script.clone(), seen2.clone());
            std::thread::spawn(move || {
                let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
                let conn = rustls::ServerConnection::new(cfg).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                let _ = conversation(&mut tls, &script, &seen);
            });
        }
    });
    FakeLdaps { addr, seen }
}

fn script() -> Script {
    let mut s = Script::default();
    s.passwords.insert(dn("alice"), b"alice password".to_vec());
    s.passwords.insert(dn("root1"), b"root password".to_vec());
    s.passwords.insert(dn("ghost"), b"ghost password".to_vec()); // can bind, has no readable entry
    s.passwords.insert(SVC_DN.into(), SVC_PW.to_vec());
    s.entries.insert(dn("alice"), vec![USERS, "cn=staff,ou=groups,dc=example,dc=org"]);
    s.entries.insert(dn("root1"), vec!["CN=WELDAP-USERS, OU=Groups, DC=Example, DC=Org", ADMINS]);
    s.entries.insert(dn("plain"), vec![]);
    s
}

struct Env {
    dir: LdapDirectory,
    tmp: TempDir,
}

fn env_for(port: u16, svc_password: Option<&[u8]>, edit: impl FnOnce(&mut config::Directory)) -> Env {
    let tmp = TempDir::new();
    let ca = tmp.write("dir-ca.crt", &pki().dir_ca.pem);
    let pw_file = match svc_password {
        Some(p) => tmp.write("svc", [p, b"\n"].concat()),
        None => tmp.path("missing"),
    };
    let mut cfg = config::Directory {
        host: "127.0.0.1".into(),
        port,
        server_name: "ldap.test".into(),
        ca: ca.clone(),
        user_dn_template: "uid={0},ou=people,dc=example,dc=org".into(),
        users_group: USERS.into(),
        admins_group: ADMINS.into(),
        service_dn: SVC_DN.into(),
        service_password_file: pw_file,
        timeout_seconds: 1,
    };
    edit(&mut cfg);
    Env { dir: LdapDirectory::new(cfg, crate::tls::directory_client(&ca).unwrap()), tmp }
}

fn env(f: &FakeLdaps) -> Env {
    env_for(f.addr.port(), Some(SVC_PW), |_| {})
}

fn secret(b: &[u8]) -> SecretBuf {
    let mut s = SecretBuf::with_capacity(b.len());
    s.extend_from_slice(b).unwrap();
    s
}

fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

const U: Membership = Membership { user: true, admin: false };
const UA: Membership = Membership { user: true, admin: true };
const NO: Membership = Membership { user: false, admin: false };

// ---------- authenticate ----------

#[test]
fn authenticate_member() {
    let f = fake(script(), &pki().dir_server);
    assert_eq!(env(&f).dir.authenticate("alice", secret(b"alice password")), Ok(U));
    let seen = lock(&f.seen);
    assert_eq!(seen.binds, vec![(dn("alice"), b"alice password".to_vec())]);
}

#[test]
fn authenticate_admin_with_spelling_variants() {
    let f = fake(script(), &pki().dir_server);
    assert_eq!(env(&f).dir.authenticate("root1", secret(b"root password")), Ok(UA));
}

#[test]
fn authenticate_full_exchange_ends_with_unbind() {
    let f = fake(script(), &pki().dir_server);
    env(&f).dir.authenticate("alice", secret(b"alice password")).unwrap();
    assert!(eventually(|| lock(&f.seen).ops == [0x60, 0x63, 0x42]), "{:x?}", lock(&f.seen).ops);
}

#[test]
fn authenticate_wrong_password() {
    let f = fake(script(), &pki().dir_server);
    assert_eq!(env(&f).dir.authenticate("alice", secret(b"nope")), Err(Failure::Invalid));
    assert_eq!(lock(&f.seen).ops, [0x60], "no search after a failed bind");
}

#[test]
fn authenticate_unknown_user_is_invalid() {
    let f = fake(script(), &pki().dir_server);
    assert_eq!(env(&f).dir.authenticate("nobody", secret(b"x")), Err(Failure::Invalid));
}

fn refused_by_policy(code: u8, want: Failure) {
    let f = fake(
        {
            let mut s = script();
            s.codes.insert(dn("alice"), code);
            s
        },
        &pki().dir_server,
    );
    assert_eq!(env(&f).dir.authenticate("alice", secret(b"alice password")), Err(want));
}

crate::cases! { refused_by_policy;
    locked_account_denied: 53, Failure::Denied;
    password_policy_denied: 19, Failure::Denied;
    insufficient_access_denied: 50, Failure::Denied;
    busy_is_error: 51, Failure::Error("directory_result");
}

#[test]
fn bound_but_no_entry_is_error() {
    let f = fake(script(), &pki().dir_server);
    assert_eq!(env(&f).dir.authenticate("ghost", secret(b"ghost password")), Err(Failure::Error("self_read")));
}

#[test]
fn directory_down_is_unavailable() {
    let e = env_for(closed_port(), Some(SVC_PW), |_| {});
    assert_eq!(e.dir.authenticate("alice", secret(b"alice password")), Err(Failure::Unavailable));
}

#[test]
fn untrusted_directory_certificate_never_gets_the_password() {
    let f = fake(script(), &pki().dir_rogue);
    assert_eq!(env(&f).dir.authenticate("alice", secret(b"alice password")), Err(Failure::Unavailable));
    assert!(lock(&f.seen).binds.is_empty());
}

#[test]
fn wrong_server_name_never_gets_the_password() {
    let f = fake(script(), &pki().dir_server);
    let e = env_for(f.addr.port(), Some(SVC_PW), |c| c.server_name = "other.test".into());
    assert_eq!(e.dir.authenticate("alice", secret(b"alice password")), Err(Failure::Unavailable));
    assert!(lock(&f.seen).binds.is_empty());
}

#[test]
fn invalid_server_name_is_unavailable() {
    let f = fake(script(), &pki().dir_server);
    let e = env_for(f.addr.port(), Some(SVC_PW), |c| c.server_name = "not a name!".into());
    assert_eq!(e.dir.authenticate("alice", secret(b"alice password")), Err(Failure::Unavailable));
}

#[test]
fn hang_up_after_bind_is_unavailable() {
    let mut s = script();
    s.hang_up_after_bind = true;
    let f = fake(s, &pki().dir_server);
    assert_eq!(env(&f).dir.authenticate("alice", secret(b"alice password")), Err(Failure::Unavailable));
}

#[test]
fn silent_directory_times_out() {
    // Accepts TCP, never speaks TLS: the configured timeout ends it.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let held = std::thread::spawn(move || l.accept().map(|(s, _)| s));
    let e = env_for(port, Some(SVC_PW), |_| {});
    let started = Instant::now();
    assert_eq!(e.dir.authenticate("alice", secret(b"alice password")), Err(Failure::Unavailable));
    assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
    drop(held.join());
}

// ---------- status (service account) ----------

#[test]
fn status_reads_each_user_in_order() {
    let f = fake(script(), &pki().dir_server);
    let uuns: Vec<String> = ["alice", "nobody", "root1", "plain"].map(String::from).to_vec();
    assert_eq!(env(&f).dir.status(&uuns), Ok(vec![U, NO, UA, NO]));
    let seen = lock(&f.seen);
    assert_eq!(seen.binds, vec![(SVC_DN.to_string(), SVC_PW.to_vec())], "service password, newline trimmed");
    assert_eq!(seen.ops[..5], [0x60, 0x63, 0x63, 0x63, 0x63]);
}

#[test]
fn status_empty_list_still_binds() {
    let f = fake(script(), &pki().dir_server);
    assert_eq!(env(&f).dir.status(&[]), Ok(vec![]));
}

#[test]
fn status_wrong_service_password() {
    let f = fake(script(), &pki().dir_server);
    let e = env_for(f.addr.port(), Some(b"stale secret"), |_| {});
    assert_eq!(e.dir.status(&["alice".into()]), Err(Failure::Error("service_bind")));
}

#[test]
fn status_service_account_locked() {
    let mut s = script();
    s.codes.insert(SVC_DN.into(), 53);
    let f = fake(s, &pki().dir_server);
    assert_eq!(env(&f).dir.status(&["alice".into()]), Err(Failure::Error("service_bind")));
}

#[test]
fn status_missing_service_secret_does_not_connect() {
    let f = fake(script(), &pki().dir_server);
    let e = env_for(f.addr.port(), None, |_| {});
    assert_eq!(e.dir.status(&["alice".into()]), Err(Failure::Error("service_secret")));
    assert!(lock(&f.seen).ops.is_empty());
}

#[test]
fn status_oversized_service_secret() {
    let f = fake(script(), &pki().dir_server);
    let e = env_for(f.addr.port(), Some(&[b'x'; 2000]), |_| {});
    assert_eq!(e.dir.status(&["alice".into()]), Err(Failure::Error("service_secret")));
}

#[test]
fn status_empty_service_secret_is_never_an_anonymous_bind() {
    let f = fake(script(), &pki().dir_server);
    let e = env_for(f.addr.port(), Some(b""), |_| {});
    assert_eq!(e.dir.status(&["alice".into()]), Err(Failure::Error("service_bind")));
    assert!(lock(&f.seen).binds.is_empty());
}

#[test]
fn status_service_bind_connection_dropped_is_unavailable() {
    // The service bind reply never arrives: status returns Unavailable (not a service_bind error).
    let mut s = script();
    s.drop_before_bind_reply = true;
    let f = fake(s, &pki().dir_server);
    assert_eq!(env(&f).dir.status(&["alice".into()]), Err(Failure::Unavailable));
}

#[test]
fn status_directory_down() {
    let e = env_for(closed_port(), Some(SVC_PW), |_| {});
    assert_eq!(e.dir.status(&["alice".into()]), Err(Failure::Unavailable));
}

#[test]
fn status_hang_up_mid_read() {
    let mut s = script();
    s.hang_up_after_bind = true;
    let f = fake(s, &pki().dir_server);
    assert_eq!(env(&f).dir.status(&["alice".into()]), Err(Failure::Unavailable));
}

#[test]
fn status_service_secret_file_changes_are_picked_up() {
    let f = fake(script(), &pki().dir_server);
    let e = env_for(f.addr.port(), Some(b"stale secret"), |_| {});
    assert!(e.dir.status(&["alice".into()]).is_err());
    std::fs::write(e.tmp.path("svc"), SVC_PW).unwrap();
    assert_eq!(e.dir.status(&["alice".into()]), Ok(vec![U]));
}

fn eventually(f: impl Fn() -> bool) -> bool {
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn raw_tcp_helper_sanity() {
    // The fake speaks only TLS: plain bytes get no LDAP answer.
    let f = fake(script(), &pki().dir_server);
    let mut tcp = TcpStream::connect(f.addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.write_all(&bind_response(1, 0)).unwrap();
    let mut buf = [0u8; 64];
    let n = tcp.read(&mut buf).unwrap_or(0);
    assert!(n == 0 || buf[0] == 0x15, "a TLS alert or nothing");
}
