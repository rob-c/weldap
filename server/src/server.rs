//! Client-facing protocol. One request per TLS connection: 4-byte big-endian length, then JSON.
//!
//!   auth:   {"v":1,"op":"auth","uun","scenario","kid","enc","ct","ts","rid"}
//!           -> {"v":1,"result":"ok","user":bool,"admin":bool}
//!              | {"v":1,"result":"invalid"|"denied"|"throttled"|"unavailable"|"error"}
//!   status: {"v":1,"op":"status","uuns":[uun..]}   (at most `MAX_STATUS_UUNS`, the accounts this client manages)
//!           -> {"v":1,"result":"ok","users":[uun..],"admins":[uun..]} (subsets of the request) | unavailable/error
//!
//! "unavailable" (directory unreachable) is the only result a client turns into its offline path. Clients never
//! learn anything about the directory beyond these two flags for UUNs they already know.

use crate::audit::{event, V};
use crate::directory::{Directory, Failure};
use crate::seal::{self, PasswordKey};
use crate::tls::Reloading;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rustls::{ServerConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_FRAME: usize = 16 * 1024;
pub const MAX_STATUS_UUNS: usize = 100;
// Shorter under test so the timeout paths run in a second, not ten.
pub const IO_TIMEOUT: Duration = Duration::from_secs(if cfg!(test) { 2 } else { 10 });
/// Whole-handshake deadline: an unauthenticated peer cannot hold a connection slot for longer.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 5 });
/// Concurrent connections per source address (before authentication), so one host cannot take every slot.
pub const MAX_PER_IP: usize = 8;
// Enough for a TLS handshake plus serde_json's maximum nesting (128) in an optimised build, with margin (the
// release-mode test run checks it). Unoptimised builds (tests, coverage) need several times more.
const THREAD_STACK: usize = if cfg!(debug_assertions) { 2048 } else { 256 } * 1024;
pub const FAIL_LIMIT: usize = 5;
const FAIL_WINDOW: Duration = Duration::from_secs(300);
pub const DEVICE_LIMIT: usize = 30;
const DEVICE_WINDOW: Duration = Duration::from_secs(60);

// Requests: strict schema, unknown fields rejected. No Debug: these are never printed.
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Request {
    Auth(AuthRequest),
    Status(StatusRequest),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthRequest {
    v: u32,
    uun: String,
    scenario: String,
    kid: String,
    enc: String,
    ct: String,
    ts: u64,
    rid: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusRequest {
    v: u32,
    uuns: Vec<String>,
}

#[derive(Serialize, Default)]
struct Reply {
    v: u32,
    result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    admin: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    users: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    admins: Option<Vec<String>>,
}

fn reply(result: &'static str) -> Reply {
    Reply { v: 1, result, ..Default::default() }
}

/// A valid username: lowercase ASCII alphanumeric, length 1..=20. Deliberately a strict subset of
/// `audit::is_identifier` (which also allows `-`, up to 63), so every UUN accepted here logs verbatim and
/// never degrades to "?" in the audit trail. If you widen this, widen `is_identifier` to match.
pub fn valid_uun(s: &str) -> bool {
    !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

type Window = Mutex<HashMap<String, VecDeque<Instant>>>;

/// Keys (devices, UUNs) tracked before idle ones are swept out.
const WINDOW_SWEEP: usize = 4096;

/// Sliding-window rate check. `record` selects the mode:
///
/// - `record == true`: push this attempt, then return whether the count is now strictly over `limit`.
/// - `record == false` (peek): do not push; return whether the window already sits at `limit` -- i.e. whether
///   recording one more attempt would exceed it.
///
/// The final `n > limit || (!record && n >= limit)` encodes exactly that asymmetry; keep both terms. Callers
/// peek before serving and record only an actually-invalid attempt, so a valid login never spends the budget.
fn over(map: &Window, key: &str, limit: usize, window: Duration, record: bool) -> bool {
    let Ok(mut m) = map.lock() else { return true }; // fail closed
    if m.len() >= WINDOW_SWEEP {
        // Without this every UUN or device ever seen would stay in memory for the life of the process.
        m.retain(|_, q| q.back().is_some_and(|t| t.elapsed() <= window));
    }
    let q = m.entry(key.to_string()).or_default();
    while q.front().is_some_and(|t| t.elapsed() > window) {
        q.pop_front();
    }
    if record {
        q.push_back(Instant::now());
    }
    let n = q.len();
    if n == 0 {
        m.remove(key);
    }
    n > limit || (!record && n >= limit)
}

type PerIp = Arc<Mutex<HashMap<IpAddr, usize>>>;

/// One of an address's `MAX_PER_IP` connection slots; released when dropped.
struct IpSlot {
    map: PerIp,
    ip: IpAddr,
}

impl IpSlot {
    fn take(map: &PerIp, ip: IpAddr) -> Option<IpSlot> {
        let mut m = map.lock().ok()?; // fail closed
        let n = m.entry(ip).or_default();
        if *n >= MAX_PER_IP {
            return None;
        }
        *n += 1;
        Some(IpSlot { map: map.clone(), ip })
    }
}

impl Drop for IpSlot {
    fn drop(&mut self) {
        // Unreachable panics: with panic = abort the mutex is never poisoned, and this slot's entry exists
        // (we added it in `take` and only remove it at zero).
        let mut m = self.map.lock().expect("per_ip mutex not poisoned (panic = abort)");
        let n = m.get_mut(&self.ip).expect("this slot's IP entry is present");
        *n -= 1;
        if *n == 0 {
            m.remove(&self.ip);
        }
    }
}

/// Counts a live connection against `max_connections`; releasing it (drop) decrements, so a refused or
/// failed-to-spawn connection frees its place without a separate branch.
struct ActiveGuard(Arc<AtomicUsize>);

impl ActiveGuard {
    fn acquire(active: &Arc<AtomicUsize>) -> ActiveGuard {
        active.fetch_add(1, Ordering::SeqCst);
        ActiveGuard(active.clone())
    }
    fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct Server {
    keys: Vec<PasswordKey>,
    directory: Box<dyn Directory>,
    max_skew: u64,
    seen_rids: Mutex<HashMap<[u8; 16], u64>>,
    failures: Window,
    device_rate: Window,
}

impl Server {
    pub fn new(keys: Vec<PasswordKey>, directory: Box<dyn Directory>, max_skew: u64) -> Server {
        Server {
            keys,
            directory,
            max_skew,
            seen_rids: Mutex::default(),
            failures: Window::default(),
            device_rate: Window::default(),
        }
    }

    /// One request from an authenticated client: the reply frame body, or None (malformed: no reply at all).
    pub fn handle(&self, device: &str, frame: &[u8], now: u64) -> Option<Vec<u8>> {
        let started = Instant::now();
        let reply = match serde_json::from_slice::<Request>(frame) {
            Ok(Request::Auth(r)) => self.auth(device, &r, now, started),
            Ok(Request::Status(r)) => self.status(device, &r),
            Err(_) => {
                event("request_rejected", &[("device", V::Id(device)), ("reason", V::S("malformed"))]);
                return None;
            }
        };
        serde_json::to_vec(&reply).ok()
    }

    fn auth(&self, device: &str, r: &AuthRequest, now: u64, started: Instant) -> Reply {
        let done = |result: &'static str, reason: &'static str, uun: &str| {
            event(
                "auth",
                &[
                    ("device", V::Id(device)),
                    ("uun", V::Id(uun)),
                    ("result", V::S(result)),
                    ("reason", V::S(reason)),
                    ("ms", V::N(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX))),
                ],
            );
            reply(result)
        };
        if r.v != 1 || !valid_uun(&r.uun) || !(r.scenario == "logon" || r.scenario == "unlock") {
            return done("error", "bad_request", "-");
        }
        if over(&self.device_rate, device, DEVICE_LIMIT, DEVICE_WINDOW, true) {
            return done("throttled", "device_rate", &r.uun);
        }
        if over(&self.failures, &r.uun, FAIL_LIMIT, FAIL_WINDOW, false) {
            return done("throttled", "user_failures", &r.uun);
        }
        if r.ts.abs_diff(now) > self.max_skew {
            return done("error", "stale_or_future", &r.uun);
        }
        let (Ok(enc), Ok(ct), Ok(rid)) = (B64.decode(&r.enc), B64.decode(&r.ct), B64.decode(&r.rid)) else {
            return done("error", "bad_encoding", &r.uun);
        };
        let Ok(rid) = <[u8; 16]>::try_from(rid.as_slice()) else {
            return done("error", "bad_rid", &r.uun);
        };
        // Replay: each request id is accepted once while its timestamp is inside the window.
        {
            let Ok(mut seen) = self.seen_rids.lock() else {
                return done("error", "internal", &r.uun);
            };
            let horizon = now.saturating_sub(2 * self.max_skew);
            seen.retain(|_, t| *t >= horizon);
            if seen.insert(rid, now).is_some() {
                return done("error", "replay", &r.uun);
            }
        }
        let Some(key) = self.keys.iter().find(|k| k.kid == r.kid) else {
            return done("error", "unknown_kid", &r.uun);
        };
        let aad = seal::aad(&r.kid, &r.uun, &r.scenario, r.ts, &r.rid);
        let Ok(password) = key.open(&enc, &ct, &aad) else {
            return done("error", "unseal", &r.uun);
        };
        if password.is_empty() {
            return done("invalid", "empty_password", &r.uun);
        }
        // `password` is moved into the directory call and zeroed there as soon as the bind request is written.
        match self.directory.authenticate(&r.uun, password) {
            Ok(m) => {
                let mut out = done("ok", if m.user { "member" } else { "not_member" }, &r.uun);
                out.user = Some(m.user);
                out.admin = Some(m.admin);
                out
            }
            Err(Failure::Invalid) => {
                over(&self.failures, &r.uun, FAIL_LIMIT, FAIL_WINDOW, true);
                done("invalid", "invalid_credentials", &r.uun)
            }
            Err(Failure::Denied) => done("denied", "directory_refused", &r.uun),
            Err(Failure::Unavailable) => done("unavailable", "directory_unreachable", &r.uun),
            Err(Failure::Error(reason)) => done("error", reason, &r.uun),
        }
    }

    fn status(&self, device: &str, r: &StatusRequest) -> Reply {
        let done = |result: &'static str, reason: &'static str, n: usize| {
            event(
                "status",
                &[
                    ("device", V::Id(device)),
                    ("result", V::S(result)),
                    ("reason", V::S(reason)),
                    ("uuns", V::N(n as u64)),
                ],
            );
            reply(result)
        };
        if r.v != 1 || r.uuns.len() > MAX_STATUS_UUNS || !r.uuns.iter().all(|u| valid_uun(u)) {
            return done("error", "bad_request", 0);
        }
        if over(&self.device_rate, device, DEVICE_LIMIT, DEVICE_WINDOW, true) {
            return done("throttled", "device_rate", r.uuns.len());
        }
        let mut uuns = r.uuns.clone();
        uuns.sort();
        uuns.dedup();
        match self.directory.status(&uuns) {
            Ok(m) if m.len() == uuns.len() => {
                let pick = |f: fn(&crate::directory::Membership) -> bool| {
                    uuns.iter().zip(&m).filter(|(_, m)| f(m)).map(|(u, _)| u.clone()).collect::<Vec<_>>()
                };
                let mut out = done("ok", "read", uuns.len());
                out.users = Some(pick(|m| m.user));
                out.admins = Some(pick(|m| m.admin));
                out
            }
            Ok(_) => done("error", "partial_read", uuns.len()),
            Err(Failure::Unavailable) => done("unavailable", "directory_unreachable", uuns.len()),
            Err(Failure::Error(reason)) => done("error", reason, uuns.len()),
            Err(_) => done("error", "directory_refused", uuns.len()),
        }
    }

    /// Accepts clients until the listener fails. Each connection: TLS handshake (client certificate from the
    /// device CA, not revoked), one framed request, one framed reply.
    // The server owns its listener and TLS configuration for the life of the process.
    #[allow(clippy::needless_pass_by_value)]
    pub fn serve(self: Arc<Self>, listener: TcpListener, tls: Arc<Reloading>, max_connections: usize) {
        let active = Arc::new(AtomicUsize::new(0));
        let per_ip = PerIp::default();
        event("listening", &[]);
        // `flatten()` drops accept() errors (transient: fd exhaustion, a connection aborted before accept) and
        // keeps serving, with no branch of our own to leave uncovered.
        for stream in listener.incoming().flatten() {
            let active = ActiveGuard::acquire(&active);
            if active.count() > max_connections {
                event("connection_refused", &[("reason", V::S("busy"))]);
                continue; // `active` drops here -> count decremented
            }
            let Some(slot) = stream.peer_addr().ok().and_then(|a| IpSlot::take(&per_ip, a.ip())) else {
                event("connection_refused", &[("reason", V::S("per_ip"))]);
                continue; // `active` drops here -> count decremented
            };
            // Keepalive so a firewall that silently drops the flow is eventually detected and the thread freed.
            crate::hardening::enable_keepalive(&stream);
            let (server, tls) = (self.clone(), tls.clone());
            // The guard and slot move into the connection thread and are released when it ends. If the spawn
            // itself fails, the closure is dropped here and the same Drop code releases both -> no extra branch.
            let _ = std::thread::Builder::new().stack_size(THREAD_STACK).spawn(move || {
                server.connection(stream, &tls);
                drop((slot, active));
            });
        }
    }

    fn connection(&self, mut tcp: TcpStream, tls: &Reloading) {
        let _ = tcp.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
        let Ok(cfg) = tls.get() else {
            event("handshake_refused", &[("reason", V::S("tls_config"))]);
            return;
        };
        // Unreachable: `cfg` comes from `tls::server_config` and is always a valid rustls server config.
        let mut conn = ServerConnection::new(cfg).expect("server TLS config is always valid");
        if handshake(&mut conn, &mut tcp, Instant::now() + HANDSHAKE_TIMEOUT).is_err() {
            // No certificate, unknown CA, revoked, expired, wrong protocol, too slow: all the same, nothing parsed.
            event("handshake_refused", &[("reason", V::S("tls"))]);
            return;
        }
        // The request read is bounded per-read by `Deadline`; the write timeout guards a stuck reply writer.
        let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));
        let mut tls = StreamOwned::new(conn, tcp);
        let Some(device) = device_name(&tls.conn) else {
            event("handshake_refused", &[("reason", V::S("device_name"))]);
            return;
        };
        // One deadline for the whole request, not per read: a registered client cannot trickle its frame in.
        let Ok(frame) = read_frame(&mut Deadline { sock: &mut tls, until: Instant::now() + IO_TIMEOUT }) else {
            return;
        };
        let Some(body) = self.handle(&device, &frame, now_secs()) else { return };
        // Unreachable: a reply is a few hundred bytes, never anywhere near u32::MAX.
        let len = u32::try_from(body.len()).expect("reply length fits in u32");
        let _ = tls.write_all(&len.to_be_bytes());
        let _ = tls.write_all(&body);
        let _ = tls.flush();
        tls.conn.send_close_notify();
        let _ = tls.conn.complete_io(&mut tls.sock);
    }
}

/// A stream whose next read can be bounded by a deadline. The TLS stream over a `TcpStream` implements it with
/// the socket read timeout; tests implement it with a fake to drive the timeout and error paths.
trait DeadlineSock: Read + Write {
    fn set_read_deadline(&mut self, left: Duration) -> std::io::Result<()>;
}

impl DeadlineSock for TcpStream {
    fn set_read_deadline(&mut self, left: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(left))
    }
}

impl DeadlineSock for StreamOwned<ServerConnection, TcpStream> {
    fn set_read_deadline(&mut self, left: Duration) -> std::io::Result<()> {
        self.sock.set_read_timeout(Some(left))
    }
}

/// Reads from the stream until `until`, then fails: each read's timeout is the time left. Holds a trait object
/// (not a generic) so there is a single instantiation and every branch is measured once.
struct Deadline<'a> {
    sock: &'a mut dyn DeadlineSock,
    until: Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        self.sock.set_read_deadline(left)?;
        self.sock.read(buf)
    }
}

/// Drives the TLS handshake by hand (rustls' `complete_io` keeps reading for as long as bytes trickle in), so
/// the whole handshake, not each read, is bounded by `deadline`. `sock` is a trait object (one instantiation).
fn handshake(conn: &mut ServerConnection, sock: &mut dyn DeadlineSock, deadline: Instant) -> Result<(), ()> {
    loop {
        while conn.wants_write() {
            if conn.write_tls(sock).map_err(|_| ())? == 0 {
                return Err(());
            }
        }
        if !conn.is_handshaking() {
            return Ok(());
        }
        // A zero timeout would mean "block forever": the deadline has passed.
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || sock.set_read_deadline(left).is_err() || conn.read_tls(sock).map_err(|_| ())? == 0 {
            return Err(());
        }
        if conn.process_new_packets().is_err() {
            let _ = conn.write_tls(sock); // the alert, best effort
            return Err(());
        }
    }
}

/// The client's registered name: CN of its (already verified) certificate, `[a-z0-9-]{1,63}`.
pub fn device_name(conn: &ServerConnection) -> Option<String> {
    // Unreachable: mandatory client-certificate verification means a peer certificate is always present here.
    let certs = conn.peer_certificates().expect("client auth is mandatory, so a peer certificate is present");
    let der = certs.first().expect("a verified certificate chain is never empty");
    cert_device_name(der.as_ref())
}

/// The device name is the certificate CN, held to the same charset and length as `audit::is_identifier`
/// (lowercase alphanumeric or `-`, up to 63) so an authenticated device always logs verbatim, never as "?".
/// Keep this rule and `is_identifier` in lockstep.
pub fn cert_device_name(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = cert.subject().iter_common_name().next()?.as_str().ok()?.to_string();
    let ok = !cn.is_empty()
        && cn.len() <= 63
        && cn.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    ok.then_some(cn)
}

pub fn read_frame(r: &mut impl Read) -> Result<Vec<u8>, ()> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).map_err(|_| ())?;
    let len = u32::from_be_bytes(len) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(());
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).map_err(|_| ())?;
    Ok(buf)
}

#[cfg(test)]
#[path = "tests/unit_server.rs"]
mod tests;
