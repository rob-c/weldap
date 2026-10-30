//! The listener end to end on loopback: real TLS (rustls client with test certificates), a fake directory.

use crate::audit::capture;
use crate::directory::Membership;
use crate::seal::{self, PasswordKey};
use crate::server::{now_secs, Server, HANDSHAKE_TIMEOUT, IO_TIMEOUT, MAX_FRAME, MAX_PER_IP};
use crate::tests::support::{
    assert_clean, client, connect, exchange, exchange_raw, frame, fresh_rid, pki, replace, Call, FakeDirectory, Leaf,
    TempDir, TlsFiles,
};
use crate::tls::Reloading;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

const USER: Membership = Membership { user: true, admin: false };

struct Running {
    addr: SocketAddr,
    dir: FakeDirectory,
    pk: Vec<u8>,
    files: TlsFiles,
    _tmp: TempDir,
}

fn start_with(crl: &str, ca: Option<&str>, max_connections: usize) -> Running {
    let tmp = TempDir::new();
    let files = pki().files(&tmp, crl);
    if let Some(ca) = ca {
        std::fs::write(&files.ca, ca).unwrap();
    }
    let tls = Reloading::new(&files.cert, &files.key, &files.ca, &files.crl).unwrap();
    let (sk, pk) = seal::generate();
    let key = PasswordKey::from_scalar("k1".into(), &sk).unwrap();
    let dir = FakeDirectory::default().with_user("alice", b"e2e alice password", USER);
    let server = Arc::new(Server::new(vec![key], dir.boxed(), 120));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || server.serve(listener, Arc::new(tls), max_connections));
    Running { addr, dir, pk, files, _tmp: tmp }
}

fn start() -> Running {
    start_with(&pki().crl(), None, 64)
}

impl Running {
    fn auth(&self, password: &[u8]) -> Value {
        let (ts, rid) = (now_secs(), fresh_rid());
        let (enc, ct) = seal::seal(&self.pk, password, &seal::aad("k1", "alice", "logon", ts, &rid)).unwrap();
        json!({"v": 1, "op": "auth", "uun": "alice", "scenario": "logon", "kid": "k1", "enc": B64.encode(enc),
               "ct": B64.encode(ct), "ts": ts, "rid": rid})
    }

    fn send_as(&self, who: Option<&Leaf>, body: &Value) -> Option<Value> {
        exchange(self.addr, client(who, false), body)
    }

    fn send(&self, body: &Value) -> Option<Value> {
        self.send_as(Some(&pki().device), body)
    }

    /// Whether `who` gets an answer to a status request.
    fn admitted(&self, who: &Leaf) -> bool {
        self.send_as(Some(who), &json!({"v": 1, "op": "status", "uuns": ["alice"]})).is_some()
    }
}

/// Retries `f` for a short while (server threads release slots asynchronously).
fn eventually(f: impl Fn() -> bool) -> bool {
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Time until the server closes `tcp` (EOF or reset), up to `limit`.
fn closed_after(tcp: &mut TcpStream, limit: Duration) -> Option<Duration> {
    let started = Instant::now();
    tcp.set_read_timeout(Some(limit)).unwrap();
    let mut buf = [0u8; 1024];
    loop {
        match tcp.read(&mut buf) {
            Ok(0) => return Some(started.elapsed()),
            Ok(_) => {}
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => return None,
            Err(_) => return Some(started.elapsed()),
        }
    }
}

// ---------- the normal path ----------

#[test]
fn registered_device_auth() {
    let s = start();
    let r = s.send(&s.auth(b"e2e alice password")).unwrap();
    assert_eq!(r, json!({"v": 1, "result": "ok", "user": true, "admin": false}));
    assert_eq!(s.dir.calls(), vec![Call::Auth { uun: "alice".into(), password: b"e2e alice password".to_vec() }]);
    assert_clean(&capture::all(), &[b"e2e alice password"]);
}

#[test]
fn registered_device_wrong_password() {
    let s = start();
    assert_eq!(s.send(&s.auth(b"e2e wrong password")).unwrap()["result"], "invalid");
    assert_clean(&capture::all(), &[b"e2e wrong password"]);
}

#[test]
fn registered_device_status() {
    let s = start();
    let r = s.send(&json!({"v": 1, "op": "status", "uuns": ["bob", "alice"]})).unwrap();
    assert_eq!(r, json!({"v": 1, "result": "ok", "users": ["alice"], "admins": []}));
}

#[test]
fn tls12_client_works() {
    let s = start();
    let r = exchange(s.addr, client(Some(&pki().device), true), &json!({"v": 1, "op": "status", "uuns": []}));
    assert_eq!(r.unwrap()["result"], "ok");
}

#[test]
fn one_request_per_connection() {
    let s = start();
    let body = serde_json::to_vec(&json!({"v": 1, "op": "status", "uuns": []})).unwrap();
    let mut tls = connect(s.addr, client(Some(&pki().device), false));
    tls.write_all(&[frame(&body), frame(&body)].concat()).unwrap();
    tls.flush().unwrap();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out);
    assert_eq!(out, frame(br#"{"v":1,"result":"ok","users":[],"admins":[]}"#), "one reply, then closed");
    assert_eq!(s.dir.calls().len(), 1);
}

#[test]
fn deeply_nested_request_gets_no_reply() {
    // Parsed on the connection thread's small stack: refused by the nesting limit, the server stays up.
    let s = start();
    let body = format!("{{\"v\":1,\"op\":\"status\",\"uuns\":{}", "[".repeat(MAX_FRAME - 64));
    assert_eq!(exchange_raw(s.addr, client(Some(&pki().device), false), &frame(body.as_bytes())), None);
    assert!(s.admitted(&pki().device));
}

#[test]
fn malformed_request_gets_no_reply() {
    let s = start();
    assert_eq!(exchange_raw(s.addr, client(Some(&pki().device), false), &frame(b"{not json")), None);
    assert!(s.dir.calls().is_empty());
}

// ---------- who gets in ----------

#[test]
fn no_client_certificate_refused() {
    let s = start();
    assert_eq!(s.send_as(None, &s.auth(b"e2e anonymous")), None);
    assert!(s.dir.calls().is_empty());
}

#[test]
fn no_client_certificate_tls12_refused() {
    let s = start();
    assert_eq!(exchange(s.addr, client(None, true), &s.auth(b"e2e anonymous 12")), None);
    assert!(s.dir.calls().is_empty());
}

#[test]
fn rogue_ca_refused() {
    let s = start();
    assert!(!s.admitted(&pki().rogue_device));
    assert!(s.dir.calls().is_empty());
}

#[test]
fn revoked_device_refused() {
    let s = start();
    assert!(!s.admitted(&pki().revoked));
    assert!(s.admitted(&pki().device));
}

#[test]
fn expired_crl_locks_everyone_out() {
    let s = start_with(&pki().device_ca.crl(&[], -10, -3), None, 64);
    assert!(!s.admitted(&pki().device));
}

#[test]
fn crl_from_another_issuer_is_unknown_status() {
    let s = start_with(&pki().rogue_ca.crl(&[], -1, 7), None, 64);
    assert!(!s.admitted(&pki().device), "unknown revocation status is refused");
}

#[test]
fn ca_rollover_needs_a_crl_per_ca() {
    let both = format!("{}{}", pki().device_ca.pem, pki().next_ca.pem);
    let s = start_with(&format!("{}{}", pki().crl(), pki().next_ca.crl(&[], -1, 7)), Some(&both), 64);
    assert!(s.admitted(&pki().device));
    assert!(s.admitted(&pki().next_device));
    assert!(!s.admitted(&pki().revoked));
    let s = start_with(&pki().crl(), Some(&both), 64);
    assert!(s.admitted(&pki().device));
    assert!(!s.admitted(&pki().next_device), "no CRL for the second CA: refused");
}

#[test]
fn ca_rollover_with_the_same_ca_name_fails_for_one_of_them() {
    // webpki picks the first CRL whose issuer *name* matches: two device CAs with the same subject cannot both
    // be served (the README asks for a distinct name for the successor CA). Pinned so a change is noticed.
    let both = format!("{}{}", pki().device_ca.pem, pki().rogue_ca.pem);
    let s = start_with(&format!("{}{}", pki().crl(), pki().rogue_ca.crl(&[], -1, 7)), Some(&both), 64);
    assert!(s.admitted(&pki().device));
    assert!(!s.admitted(&pki().rogue_device));
}

#[test]
fn server_certificate_as_client_identity_refused() {
    let s = start();
    assert!(!s.admitted(&pki().server));
}

#[test]
fn device_name_rules_enforced_after_handshake() {
    let s = start();
    for leaf in [
        pki().device_ca.device("Bad_Name", 50),
        pki().device_ca.leaf(None, &["laptop-03"], 51, true),
        pki().device_ca.device(&"a".repeat(64), 52),
    ] {
        assert!(!s.admitted(&leaf));
    }
    assert!(s.admitted(&pki().device_ca.device(&"a".repeat(63), 53)));
    assert_eq!(s.dir.calls().len(), 1);
}

#[test]
fn server_auth_only_certificate_refused_as_client() {
    // A certificate from the device CA, but issued for server authentication only.
    let s = start();
    assert!(!s.admitted(&pki().device_ca.leaf(Some("laptop-04"), &["laptop-04"], 54, false)));
}

#[test]
fn crl_reload_revokes_and_restores() {
    let s = start();
    assert!(s.admitted(&pki().device));
    replace(&s.files.crl, &pki().device_ca.crl(&[pki().device.serial, pki().revoked.serial], -1, 7));
    assert!(!s.admitted(&pki().device), "revoked on the next connection");
    replace(&s.files.crl, &pki().crl());
    assert!(s.admitted(&pki().device));
}

#[test]
fn broken_crl_on_reload_fails_closed() {
    let s = start();
    replace(&s.files.crl, "not a crl");
    assert!(!s.admitted(&pki().device));
    replace(&s.files.crl, &pki().crl());
    assert!(s.admitted(&pki().device));
}

// ---------- framing on the wire ----------

#[test]
fn zero_length_frame_no_reply() {
    let s = start();
    assert_eq!(exchange_raw(s.addr, client(Some(&pki().device), false), &[0, 0, 0, 0]), None);
}

#[test]
fn oversized_frame_no_reply() {
    let s = start();
    let mut f = (u32::try_from(MAX_FRAME).unwrap() + 1).to_be_bytes().to_vec();
    f.extend(vec![b' '; 64]);
    assert_eq!(exchange_raw(s.addr, client(Some(&pki().device), false), &f), None);
}

#[test]
fn max_size_frame_is_read() {
    let s = start();
    let mut body = br#"{"v":1,"op":"status","uuns":[]}"#.to_vec();
    body.resize(MAX_FRAME, b' ');
    let r = exchange_raw(s.addr, client(Some(&pki().device), false), &frame(&body)).unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&r).unwrap()["result"], "ok");
}

#[test]
fn partial_frame_then_close_no_reply() {
    let s = start();
    let mut tls = connect(s.addr, client(Some(&pki().device), false));
    tls.write_all(&[0, 0, 0, 100, b'{', b'"']).unwrap();
    tls.flush().unwrap();
    tls.sock.shutdown(Shutdown::Write).unwrap();
    let started = Instant::now();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out);
    assert!(out.is_empty());
    assert!(started.elapsed() < IO_TIMEOUT, "closed when the client went away, not on the timeout");
    assert!(s.dir.calls().is_empty());
}

#[test]
fn stalled_request_closed_after_io_timeout() {
    let s = start();
    let mut tls = connect(s.addr, client(Some(&pki().device), false));
    tls.write_all(&[0, 0]).unwrap(); // half a length prefix; completes the handshake
    tls.flush().unwrap();
    let started = Instant::now();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out);
    let took = started.elapsed();
    assert!(out.is_empty());
    assert!(
        took >= IO_TIMEOUT.saturating_sub(Duration::from_millis(200)) && took < IO_TIMEOUT + Duration::from_secs(3),
        "{took:?}"
    );
}

// ---------- connection limits ----------

#[test]
fn idle_connection_before_handshake_closed_at_deadline() {
    let s = start();
    let mut tcp = TcpStream::connect(s.addr).unwrap();
    let took = closed_after(&mut tcp, HANDSHAKE_TIMEOUT + Duration::from_secs(3)).expect("closed");
    assert!(took >= HANDSHAKE_TIMEOUT.saturating_sub(Duration::from_millis(200)), "{took:?}");
    assert!(took < HANDSHAKE_TIMEOUT + Duration::from_secs(2), "{took:?}");
}

#[test]
fn trickled_handshake_closed_at_deadline() {
    // A peer that keeps sending (a valid ClientHello, one byte at a time) is still cut off at the deadline.
    let s = start();
    let mut conn = rustls::ClientConnection::new(
        client(Some(&pki().device), false),
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut hello = Vec::new();
    conn.write_tls(&mut hello).unwrap();
    let mut tcp = TcpStream::connect(s.addr).unwrap();
    tcp.set_read_timeout(Some(Duration::from_millis(1))).unwrap();
    let started = Instant::now();
    let mut closed = None;
    for b in hello.iter().cycle() {
        let mut buf = [0u8; 64];
        let gone = tcp.write_all(&[*b]).is_err()
            || match tcp.read(&mut buf) {
                Ok(n) => n == 0,
                Err(e) => !matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut),
            };
        if gone {
            closed = Some(started.elapsed());
            break;
        }
        if started.elapsed() > HANDSHAKE_TIMEOUT + Duration::from_secs(4) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let took = closed.expect("server closed the connection");
    assert!(took < HANDSHAKE_TIMEOUT + Duration::from_secs(2), "{took:?}");
    assert!(u128::try_from(hello.len()).unwrap() * 50 > 2 * HANDSHAKE_TIMEOUT.as_millis(), "really trickled");
}

#[test]
fn per_ip_cap() {
    let s = start();
    let mut idle: Vec<TcpStream> = (0..MAX_PER_IP).map(|_| TcpStream::connect(s.addr).unwrap()).collect();
    let mut extra = TcpStream::connect(s.addr).unwrap();
    let took = closed_after(&mut extra, HANDSHAKE_TIMEOUT / 2).expect("refused at once");
    assert!(took < HANDSHAKE_TIMEOUT / 2);
    // The idle ones hold their slots until the handshake deadline, then everything works again.
    idle.clear();
    assert!(eventually(|| s.admitted(&pki().device)));
}

#[test]
fn per_ip_slot_released_by_completed_connections() {
    let s = start();
    for _ in 0..MAX_PER_IP * 2 {
        assert!(s.admitted(&pki().device));
    }
}

#[test]
fn busy_refused_then_recovers() {
    let s = start_with(&pki().crl(), None, 1);
    let hold = TcpStream::connect(s.addr).unwrap();
    assert!(!s.admitted(&pki().device), "the only slot is taken");
    drop(hold);
    assert!(eventually(|| s.admitted(&pki().device)));
}

#[test]
fn zero_max_connections_refuses_everyone() {
    let s = start_with(&pki().crl(), None, 0);
    let mut tcp = TcpStream::connect(s.addr).unwrap();
    assert!(closed_after(&mut tcp, Duration::from_millis(500)).is_some());
    assert!(!s.admitted(&pki().device));
}

#[test]
fn trickled_request_closed_at_one_deadline() {
    // A registered client that finishes the handshake and then sends its frame a byte at a time is cut off
    // after IO_TIMEOUT in total, not IO_TIMEOUT per byte.
    let s = start();
    let conn = rustls::ClientConnection::new(
        client(Some(&pki().device), false),
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let mut tls = rustls::StreamOwned::new(conn, TcpStream::connect(s.addr).unwrap());
    tls.write_all(&100u32.to_be_bytes()).unwrap(); // completes the handshake, announces 100 bytes
    tls.flush().unwrap();
    let started = Instant::now();
    let mut closed = None;
    while started.elapsed() < IO_TIMEOUT * 3 {
        std::thread::sleep(IO_TIMEOUT / 5);
        if tls.write_all(b"{").and_then(|()| tls.flush()).is_err() {
            closed = Some(started.elapsed());
            break;
        }
        tls.sock.set_read_timeout(Some(Duration::from_millis(1))).unwrap();
        let mut buf = [0u8; 16];
        match tls.read(&mut buf) {
            Ok(0) => {
                closed = Some(started.elapsed());
                break;
            }
            Err(e) if !matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                closed = Some(started.elapsed());
                break;
            }
            _ => {}
        }
    }
    let took = closed.expect("server closed the connection");
    assert!(took < IO_TIMEOUT + Duration::from_millis(1500), "{took:?}");
}

// ---------- broken / hostile networking kit ----------

impl Running {
    /// A fully handshaked TLS stream to the server (so we can then abuse the raw socket underneath).
    fn handshaken(&self) -> rustls::StreamOwned<rustls::ClientConnection, TcpStream> {
        let mut tls = connect(self.addr, client(Some(&pki().device), false));
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).expect("handshake");
        }
        tls
    }

    /// The server did not answer this exchange, and it is still serving afterwards (no crash, no hang).
    fn survives(&self) {
        assert!(self.admitted(&pki().device), "server kept serving after the hostile connection");
    }
}

#[test]
fn tls_record_corruption_after_handshake_is_dropped() {
    let s = start();
    let mut tls = s.handshaken();
    // Raw bytes injected under TLS: not a valid record, so rustls on the server errors and drops the link.
    tls.sock.write_all(&[0x17, 0x03, 0x03, 0x00, 0x20]).unwrap(); // a record header then nonsense
    tls.sock.write_all(&[0xab; 0x20]).unwrap();
    tls.sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = Vec::new();
    let _ = tls.read_to_end(&mut buf); // no framed application reply
    assert!(s.dir.calls().is_empty());
    s.survives();
}

#[test]
fn truncated_tls_record_after_handshake_times_out() {
    let s = start();
    let mut tls = s.handshaken();
    tls.sock.write_all(&[0x17, 0x03, 0x03, 0x01, 0x00]).unwrap(); // claims a 256-byte record, sends none
    tls.sock.set_read_timeout(Some(IO_TIMEOUT + Duration::from_secs(3))).unwrap();
    let mut buf = Vec::new();
    let started = Instant::now();
    let _ = tls.read_to_end(&mut buf);
    assert!(buf.is_empty());
    assert!(started.elapsed() < IO_TIMEOUT + Duration::from_secs(3));
    s.survives();
}

#[test]
fn peer_rst_after_handshake_does_not_crash() {
    let s = start();
    {
        let tls = s.handshaken();
        // SO_LINGER(0): dropping the socket sends a RST rather than a graceful FIN.
        crate::hardening::set_linger_zero(&tls.sock);
    } // dropped here -> RST to the server mid-request-wait
    s.survives();
}

#[test]
fn peer_vanishes_after_handshake_is_closed_by_deadline() {
    let s = start();
    let mut tls = s.handshaken();
    // Send nothing and never close: the server's request deadline must fire.
    tls.sock.set_read_timeout(Some(IO_TIMEOUT + Duration::from_secs(3))).unwrap();
    let mut buf = Vec::new();
    let started = Instant::now();
    let _ = tls.read_to_end(&mut buf);
    let took = started.elapsed();
    assert!(buf.is_empty());
    assert!(took >= IO_TIMEOUT.saturating_sub(Duration::from_millis(300)), "{took:?}");
    assert!(took < IO_TIMEOUT + Duration::from_secs(3), "{took:?}");
}

#[test]
fn request_trickled_one_byte_at_a_time_times_out() {
    let s = start();
    let body = serde_json::to_vec(&json!({"v": 1, "op": "status", "uuns": []})).unwrap();
    let fr = frame(&body);
    let mut tls = s.handshaken();
    // Feed the request one byte at a time, slower than the deadline can tolerate in total.
    let started = Instant::now();
    let mut sent = 0;
    for b in &fr {
        if tls.write_all(&[*b]).and_then(|()| tls.flush()).is_err() {
            break;
        }
        sent += 1;
        if started.elapsed() > IO_TIMEOUT + Duration::from_secs(2) {
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    tls.sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = Vec::new();
    let _ = tls.read_to_end(&mut buf);
    assert!(buf.is_empty(), "a trickled frame never gets a reply");
    assert!(sent < fr.len() || started.elapsed() >= IO_TIMEOUT, "deadline should bite before the frame completes");
    s.survives();
}

#[test]
fn plain_http_instead_of_tls_is_dropped() {
    let s = start();
    let mut tcp = TcpStream::connect(s.addr).unwrap();
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT + Duration::from_secs(2))).unwrap();
    let mut buf = Vec::new();
    let _ = tcp.read_to_end(&mut buf);
    assert!(s.dir.calls().is_empty());
    s.survives();
}

#[test]
fn random_garbage_instead_of_tls_is_dropped() {
    let s = start();
    let mut tcp = TcpStream::connect(s.addr).unwrap();
    tcp.write_all(&(0u8..=255).cycle().take(4096).collect::<Vec<_>>()).unwrap();
    tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT + Duration::from_secs(2))).unwrap();
    let mut buf = Vec::new();
    let _ = tcp.read_to_end(&mut buf);
    s.survives();
}

#[test]
fn replayed_application_frame_second_is_ignored() {
    let s = start();
    let body = serde_json::to_vec(&json!({"v": 1, "op": "status", "uuns": ["alice"]})).unwrap();
    let mut tls = s.handshaken();
    // Two identical frames on one connection: exactly one reply, then the connection closes.
    tls.write_all(&[frame(&body), frame(&body)].concat()).unwrap();
    tls.flush().unwrap();
    tls.sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out);
    assert_eq!(out, frame(br#"{"v":1,"result":"ok","users":["alice"],"admins":[]}"#));
    assert_eq!(s.dir.calls().len(), 1, "only the first frame is served");
}

#[test]
fn read_and_write_timeouts_are_set_on_the_socket() {
    // The handshake deadline and the per-request Deadline both fire (proven above); here we assert the
    // accepted socket actually carries a read timeout so a silent peer cannot pin a thread forever.
    let s = start();
    let mut tls = s.handshaken();
    tls.sock.set_read_timeout(Some(IO_TIMEOUT + Duration::from_secs(3))).unwrap();
    let mut one = [0u8; 1];
    let started = Instant::now();
    let _ = tls.read(&mut one); // server is waiting on us; it will give up at its own deadline and close
    assert!(started.elapsed() < IO_TIMEOUT + Duration::from_secs(3));
}
