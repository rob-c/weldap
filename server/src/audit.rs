//! The only output the server ever writes about requests: one JSON line per event on stdout.
//!
//! There is no debug or trace mode, at any setting. Values can only be `&'static str` (event names,
//! results, reasons chosen in code), numbers, or identifiers that pass a strict allow-list check
//! (device names and UUNs); anything else is replaced by "?". Request bodies, ciphertexts, LDAP
//! diagnostics and error strings from the network never reach this module, and `SecretBuf` cannot be
//! passed to it at all.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

pub enum V<'a> {
    S(&'static str),
    N(u64),
    /// An identifier from the network: logged only if it is `[a-z0-9-]{1,63}`.
    Id(&'a str),
}

/// Names safe to log verbatim (anything else is redacted to "?"). This is the *superset* rule: the UUN check
/// (`server::valid_uun`) and the device-name check (`server::cert_device_name`) must each stay within it, so
/// every name those accept logs as itself. `audit` is deliberately dependency-free, so the predicate is
/// duplicated here rather than shared across that boundary.
fn is_identifier(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub fn event(name: &'static str, fields: &[(&'static str, V)]) {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut line = format!("{{\"ts\":{ts},\"event\":\"{name}\"");
    for (k, v) in fields {
        match v {
            V::S(s) => write!(line, ",\"{k}\":\"{s}\""),
            V::N(n) => write!(line, ",\"{k}\":{n}"),
            V::Id(s) if is_identifier(s) => write!(line, ",\"{k}\":\"{s}\""),
            V::Id(_) => write!(line, ",\"{k}\":\"?\""),
        }
        .unwrap_or_default(); // writing to a String cannot fail
    }
    line.push_str("}\n");
    emit(&line);
}

#[cfg(not(test))]
fn emit(line: &str) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
}

#[cfg(test)]
fn emit(line: &str) {
    capture::push(line.trim_end());
}

/// Tests only: events are captured instead of printed, per thread (for exact assertions) and for the whole
/// process (for "nothing secret, ever" checks across server threads).
#[cfg(test)]
pub mod capture {
    use std::cell::RefCell;
    use std::sync::{Mutex, PoisonError};

    thread_local! {
        static LINES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }
    static ALL: Mutex<Vec<String>> = Mutex::new(Vec::new());

    pub(super) fn push(line: &str) {
        LINES.with(|l| l.borrow_mut().push(line.to_string()));
        ALL.lock().unwrap_or_else(PoisonError::into_inner).push(line.to_string());
    }

    /// This thread's lines since the last call.
    pub fn take() -> Vec<String> {
        LINES.with(|l| std::mem::take(&mut *l.borrow_mut()))
    }

    /// Every line any thread has written so far.
    pub fn all() -> Vec<String> {
        ALL.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

#[cfg(test)]
#[path = "tests/unit_audit.rs"]
mod tests;
