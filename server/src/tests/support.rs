//! Shared test fixtures: a scripted directory, in-memory LDAP streams and BER builders, a throwaway PKI
//! (rcgen), a TLS client, temp dirs, and the audit-line checks.

use crate::directory::{Directory, Failure, Membership};
use crate::secret::SecretBuf;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, RevokedCertParams, SerialNumber,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;
use time::OffsetDateTime;

/// Table-driven tests: `cases! { check; name: arg, arg; name2: arg, arg; }` makes one `#[test]` per row.
#[macro_export]
macro_rules! cases {
    ($check:path; $($name:ident: $($arg:expr),+;)+) => {
        $(
            #[test]
            fn $name() {
                $check($($arg),+);
            }
        )+
    };
}

pub fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------- temp dirs ----------

pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> TempDir {
        static N: AtomicUsize = AtomicUsize::new(0);
        let n = N.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("weldap-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    pub fn write(&self, name: &str, data: impl AsRef<[u8]>) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, data).unwrap();
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------- audit lines ----------

const KEYS: &[&str] = &["ts", "event", "device", "uun", "result", "reason", "ms", "uuns", "keys"];

fn allowed_value(s: &str) -> bool {
    s == "?"
        || (!s.is_empty()
            && s.len() <= 63
            && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'))
}

/// Every line is one flat JSON object with known keys and allow-listed values, and contains none of `secrets`
/// (raw or base64).
pub fn assert_clean(lines: &[String], secrets: &[&[u8]]) {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    for line in lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|_| panic!("not JSON: {line}"));
        let obj = v.as_object().unwrap_or_else(|| panic!("not an object: {line}"));
        for (k, v) in obj {
            assert!(KEYS.contains(&k.as_str()), "key {k} not allow-listed: {line}");
            match v {
                serde_json::Value::String(s) => assert!(allowed_value(s), "value {s:?} not allow-listed: {line}"),
                serde_json::Value::Number(n) => assert!(n.is_u64(), "{line}"),
                _ => panic!("unexpected value type: {line}"),
            }
        }
        for s in secrets.iter().filter(|s| s.len() >= 4) {
            let raw = String::from_utf8_lossy(s);
            assert!(!line.contains(raw.as_ref()), "secret in audit line: {line}");
            assert!(!line.contains(&b64.encode(s)), "secret (base64) in audit line: {line}");
        }
    }
}

// ---------- directory fake ----------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    Auth { uun: String, password: Vec<u8> },
    Status(Vec<String>),
}

#[derive(Default)]
pub struct FakeState {
    /// uun -> correct password; authenticate returns `members[uun]` on a match, Invalid otherwise.
    pub passwords: HashMap<String, Vec<u8>>,
    pub members: HashMap<String, Membership>,
    /// Overrides the outcome of every authenticate / status call.
    pub auth_outcome: Option<Result<Membership, Failure>>,
    pub status_outcome: Option<Result<Vec<Membership>, Failure>>,
    pub calls: Vec<Call>,
}

/// A directory that records every call (with the password it was handed) and answers from a script.
#[derive(Clone, Default)]
pub struct FakeDirectory(pub Arc<Mutex<FakeState>>);

impl FakeDirectory {
    pub fn with_user(self, uun: &str, password: &[u8], m: Membership) -> Self {
        {
            let mut s = lock(&self.0);
            s.passwords.insert(uun.into(), password.into());
            s.members.insert(uun.into(), m);
        }
        self
    }
    pub fn set_auth(&self, r: Result<Membership, Failure>) {
        lock(&self.0).auth_outcome = Some(r);
    }
    pub fn set_status(&self, r: Result<Vec<Membership>, Failure>) {
        lock(&self.0).status_outcome = Some(r);
    }
    pub fn calls(&self) -> Vec<Call> {
        lock(&self.0).calls.clone()
    }
    pub fn boxed(&self) -> Box<dyn Directory> {
        Box::new(self.clone())
    }
}

impl Directory for FakeDirectory {
    fn authenticate(&self, uun: &str, password: SecretBuf) -> Result<Membership, Failure> {
        let mut s = lock(&self.0);
        s.calls.push(Call::Auth { uun: uun.into(), password: password.as_slice().to_vec() });
        if let Some(r) = s.auth_outcome {
            return r;
        }
        match s.passwords.get(uun) {
            Some(p) if p.as_slice() == password.as_slice() => Ok(s.members.get(uun).copied().unwrap_or_default()),
            _ => Err(Failure::Invalid),
        }
    }

    fn status(&self, uuns: &[String]) -> Result<Vec<Membership>, Failure> {
        let mut s = lock(&self.0);
        s.calls.push(Call::Status(uuns.to_vec()));
        if let Some(r) = &s.status_outcome {
            return r.clone();
        }
        Ok(uuns.iter().map(|u| s.members.get(u).copied().unwrap_or_default()).collect())
    }
}

// ---------- in-memory LDAP stream ----------

#[derive(Default)]
pub struct MockState {
    pub input: Vec<u8>,
    pub pos: usize,
    pub output: Vec<u8>,
    pub fail_write: bool,
    pub fail_flush: bool,
}

/// A byte stream for `Ldap<S>`: reads the scripted replies (then EOF), records what is written.
#[derive(Clone, Default)]
pub struct Mock(pub Rc<RefCell<MockState>>);

impl Mock {
    pub fn replying(input: Vec<u8>) -> Mock {
        Mock(Rc::new(RefCell::new(MockState { input, ..MockState::default() })))
    }
    pub fn output(&self) -> Vec<u8> {
        self.0.borrow().output.clone()
    }
}

impl Read for Mock {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut s = self.0.borrow_mut();
        let n = buf.len().min(s.input.len() - s.pos);
        buf[..n].copy_from_slice(&s.input[s.pos..s.pos + n]);
        s.pos += n;
        Ok(n)
    }
}

impl Write for Mock {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut s = self.0.borrow_mut();
        if s.fail_write {
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        s.output.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if self.0.borrow().fail_flush {
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
}

// ---------- BER, written independently of ldap.rs ----------

pub fn ber_len(n: usize) -> Vec<u8> {
    let [b0, b1, b2, b3] = u32::try_from(n).unwrap().to_be_bytes();
    match n {
        0..=0x7f => vec![b3],
        0x80..=0xff => vec![0x81, b3],
        0x100..=0xffff => vec![0x82, b2, b3],
        0x1_0000..=0xff_ffff => vec![0x83, b1, b2, b3],
        _ => vec![0x84, b0, b1, b2, b3],
    }
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(ber_len(content.len()));
    v.extend_from_slice(content);
    v
}

/// `LDAPMessage`: SEQUENCE { messageID, protocolOp }.
pub fn msg(id: u8, op: &[u8]) -> Vec<u8> {
    let mut c = tlv(0x02, &[id]);
    c.extend_from_slice(op);
    tlv(0x30, &c)
}

/// An LDAPResult-shaped op (bindResponse 0x61, searchResDone 0x65): code, matchedDN "", diagnostic "".
pub fn result_op(tag: u8, code: u8) -> Vec<u8> {
    let mut c = tlv(0x0a, &[code]);
    c.extend(tlv(0x04, b""));
    c.extend(tlv(0x04, b""));
    tlv(tag, &c)
}

pub fn bind_response(id: u8, code: u8) -> Vec<u8> {
    msg(id, &result_op(0x61, code))
}

pub fn search_done(id: u8, code: u8) -> Vec<u8> {
    msg(id, &result_op(0x65, code))
}

/// searchResEntry with the given attributes and values.
pub fn search_entry(id: u8, dn: &str, attrs: &[(&str, &[&str])]) -> Vec<u8> {
    let mut list = Vec::new();
    for (name, values) in attrs {
        let mut set = Vec::new();
        for v in *values {
            set.extend(tlv(0x04, v.as_bytes()));
        }
        let mut one = tlv(0x04, name.as_bytes());
        one.extend(tlv(0x31, &set));
        list.extend(tlv(0x30, &one));
    }
    let mut c = tlv(0x04, dn.as_bytes());
    c.extend(tlv(0x30, &list));
    msg(id, &tlv(0x64, &c))
}

/// Splits one TLV (short or long form) off `buf`; None if it does not fit.
pub fn parse(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = buf.split_first()?;
    let (&l, rest) = rest.split_first()?;
    let (len, rest) = if l < 0x80 {
        (usize::from(l), rest)
    } else {
        let n = usize::from(l & 0x7f);
        if rest.len() < n {
            return None;
        }
        (rest[..n].iter().fold(0usize, |a, b| (a << 8) | usize::from(*b)), &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

// ---------- test PKI ----------

pub struct Ca {
    pub pem: String,
    issuer: Issuer<'static, KeyPair>,
}

pub struct Leaf {
    pub pem: String,
    pub key_pem: String,
    pub der: CertificateDer<'static>,
    pub serial: u64,
}

fn days(n: i64) -> OffsetDateTime {
    OffsetDateTime::now_utc() + time::Duration::days(n)
}

impl Ca {
    pub fn new(name: &str) -> Ca {
        let mut p = CertificateParams::new(Vec::new()).unwrap();
        p.distinguished_name.push(DnType::CommonName, name);
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        p.not_before = days(-30);
        p.not_after = days(3650);
        let key = KeyPair::generate().unwrap();
        let cert = p.self_signed(&key).unwrap();
        Ca { pem: cert.pem(), issuer: Issuer::new(p, key) }
    }

    /// A leaf for a device (client auth) or a server (server auth, `sans` as DNS names).
    pub fn leaf(&self, cn: Option<&str>, sans: &[&str], serial: u64, client: bool) -> Leaf {
        let mut p = CertificateParams::new(sans.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()).unwrap();
        p.distinguished_name = rcgen::DistinguishedName::new();
        if let Some(cn) = cn {
            p.distinguished_name.push(DnType::CommonName, cn);
        }
        p.distinguished_name.push(DnType::OrganizationName, "WELDAP tests");
        p.serial_number = Some(SerialNumber::from(serial));
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages =
            vec![if client { ExtendedKeyUsagePurpose::ClientAuth } else { ExtendedKeyUsagePurpose::ServerAuth }];
        p.use_authority_key_identifier_extension = true;
        p.not_before = days(-1);
        p.not_after = days(90);
        let key = KeyPair::generate().unwrap();
        let cert = p.signed_by(&key, &self.issuer).unwrap();
        Leaf { pem: cert.pem(), key_pem: key.serialize_pem(), der: cert.der().clone(), serial }
    }

    pub fn device(&self, cn: &str, serial: u64) -> Leaf {
        self.leaf(Some(cn), &[], serial, true)
    }

    /// A CRL revoking `serials`, valid from `from` to `until` days from now.
    pub fn crl(&self, serials: &[u64], from: i64, until: i64) -> String {
        let p = CertificateRevocationListParams {
            this_update: days(from),
            next_update: days(until),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: serials
                .iter()
                .map(|s| RevokedCertParams {
                    serial_number: SerialNumber::from(*s),
                    revocation_time: days(-1),
                    reason_code: None,
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        p.signed_by(&self.issuer).unwrap().pem().unwrap()
    }
}

/// One PKI per test process (key generation is the slow part).
pub struct Pki {
    pub device_ca: Ca,
    pub rogue_ca: Ca,
    pub server_ca: Ca,
    pub server: Leaf,
    pub device: Leaf,
    pub revoked: Leaf,
    pub rogue_device: Leaf,
    /// A successor device CA with its own name (CA rollover) and a device it issued.
    pub next_ca: Ca,
    pub next_device: Leaf,
    /// Directory side: 389 DS's certificate for "ldap.test" and its CA.
    pub dir_ca: Ca,
    pub dir_server: Leaf,
    pub dir_rogue: Leaf,
}

pub const DEVICE: &str = "laptop-01";
pub const REVOKED: &str = "stolen-02";

pub fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let device_ca = Ca::new("WELDAP device CA");
        let rogue_ca = Ca::new("WELDAP device CA"); // same name, different key
        let server_ca = Ca::new("WELDAP server CA");
        let dir_ca = Ca::new("Directory CA");
        let next_ca = Ca::new("WELDAP device CA 2");
        Pki {
            next_device: next_ca.device("laptop-05", 1),
            next_ca,
            server: server_ca.leaf(Some("localhost"), &["localhost"], 10, false),
            device: device_ca.device(DEVICE, 1),
            revoked: device_ca.device(REVOKED, 2),
            rogue_device: rogue_ca.device(DEVICE, 1),
            dir_server: dir_ca.leaf(Some("ldap.test"), &["ldap.test"], 20, false),
            dir_rogue: rogue_ca.leaf(Some("ldap.test"), &["ldap.test"], 21, false),
            device_ca,
            rogue_ca,
            server_ca,
            dir_ca,
        }
    })
}

/// The server's TLS files in `dir`: (cert, key, device CA, CRL).
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub ca: PathBuf,
    pub crl: PathBuf,
}

impl Pki {
    pub fn files(&self, dir: &TempDir, crl_pem: &str) -> TlsFiles {
        TlsFiles {
            cert: dir.write("server.crt", &self.server.pem),
            key: dir.write("server.key", &self.server.key_pem),
            ca: dir.write("device-ca.crt", &self.device_ca.pem),
            crl: dir.write("device-ca.crl", crl_pem),
        }
    }

    /// The usual CRL: the stolen device revoked, valid for a week.
    pub fn crl(&self) -> String {
        self.device_ca.crl(&[self.revoked.serial], -1, 7)
    }
}

/// Rewrites a file and moves its mtime forward, so a reload is detected even on coarse-mtime filesystems.
pub fn replace(path: &Path, data: &str) {
    let old = std::fs::metadata(path).and_then(|m| m.modified()).unwrap();
    std::fs::write(path, data).unwrap();
    let f = std::fs::File::options().write(true).open(path).unwrap();
    f.set_modified(old + Duration::from_secs(5)).unwrap();
}

// ---------- TLS client ----------

pub fn client(identity: Option<&Leaf>, tls12_only: bool) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(pki().server_ca.pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let versions: &[&rustls::SupportedProtocolVersion] =
        if tls12_only { &[&rustls::version::TLS12] } else { &[&rustls::version::TLS13] };
    let b = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots);
    Arc::new(match identity {
        Some(l) => {
            let chain = vec![l.der.clone()];
            let key = PrivateKeyDer::from_pem_slice(l.key_pem.as_bytes()).unwrap();
            b.with_client_auth_cert(chain, key).unwrap()
        }
        None => b.with_no_client_auth(),
    })
}

pub fn connect(
    addr: SocketAddr,
    cfg: Arc<rustls::ClientConfig>,
) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let conn = rustls::ClientConnection::new(cfg, ServerName::try_from("localhost").unwrap()).unwrap();
    rustls::StreamOwned::new(conn, tcp)
}

/// Sends raw bytes (normally a length-prefixed frame) and reads one framed reply; None if there is none.
pub fn exchange_raw(addr: SocketAddr, cfg: Arc<rustls::ClientConfig>, bytes: &[u8]) -> Option<Vec<u8>> {
    let mut tls = connect(addr, cfg);
    tls.write_all(bytes).ok()?;
    tls.flush().ok()?;
    let mut len = [0u8; 4];
    tls.read_exact(&mut len).ok()?;
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    tls.read_exact(&mut body).ok()?;
    Some(body)
}

pub fn frame(body: &[u8]) -> Vec<u8> {
    let mut f = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    f.extend_from_slice(body);
    f
}

pub fn exchange(
    addr: SocketAddr,
    cfg: Arc<rustls::ClientConfig>,
    body: &serde_json::Value,
) -> Option<serde_json::Value> {
    let reply = exchange_raw(addr, cfg, &frame(&serde_json::to_vec(body).unwrap()))?;
    Some(serde_json::from_slice(&reply).unwrap())
}

/// Distinct 16-byte request ids, base64.
pub fn fresh_rid() -> String {
    use base64::Engine;
    static N: AtomicUsize = AtomicUsize::new(1);
    let n = N.fetch_add(1, Ordering::SeqCst) as u64;
    let mut rid = [0x5au8; 16];
    rid[..8].copy_from_slice(&n.to_be_bytes());
    rid[8..].copy_from_slice(&u64::from(std::process::id()).to_be_bytes());
    base64::engine::general_purpose::STANDARD.encode(rid)
}
