//! TLS configuration loading and reloading. Handshakes against these configs are in `tests/e2e_serve.rs`.

use super::*;
use crate::tests::support::{pki, replace, Ca, TempDir};

fn files(dir: &TempDir) -> crate::tests::support::TlsFiles {
    pki().files(dir, &pki().crl())
}

#[test]
fn server_config_ok() {
    let dir = TempDir::new();
    let f = files(&dir);
    let cfg = server_config(&f.cert, &f.key, &f.ca, &f.crl).unwrap();
    assert_eq!(cfg.send_tls13_tickets, 0, "no session tickets");
}

#[test]
fn crl_file_missing() {
    let dir = TempDir::new();
    let f = files(&dir);
    let e = server_config(&f.cert, &f.key, &f.ca, &dir.path("missing.crl")).err().unwrap();
    assert!(e.contains("missing.crl"), "{e}");
}

#[test]
fn crl_file_empty_refuses_to_run() {
    let dir = TempDir::new();
    let f = files(&dir);
    std::fs::write(&f.crl, "").unwrap();
    let e = server_config(&f.cert, &f.key, &f.ca, &f.crl).err().unwrap();
    assert!(e.contains("refusing to run without revocation"), "{e}");
}

#[test]
fn crl_file_with_only_a_certificate() {
    let dir = TempDir::new();
    let f = files(&dir);
    std::fs::write(&f.crl, &pki().device_ca.pem).unwrap();
    assert!(server_config(&f.cert, &f.key, &f.ca, &f.crl).is_err());
}

#[test]
fn crl_file_garbage() {
    let dir = TempDir::new();
    let f = files(&dir);
    std::fs::write(&f.crl, "-----BEGIN X509 CRL-----\nnot base64 at all!\n-----END X509 CRL-----\n").unwrap();
    assert!(server_config(&f.cert, &f.key, &f.ca, &f.crl).is_err());
}

#[test]
fn crl_der_garbage_refused() {
    let dir = TempDir::new();
    let f = files(&dir);
    std::fs::write(&f.crl, "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n").unwrap();
    assert!(server_config(&f.cert, &f.key, &f.ca, &f.crl).is_err());
}

#[test]
fn device_ca_missing() {
    let dir = TempDir::new();
    let f = files(&dir);
    assert!(server_config(&f.cert, &f.key, &dir.path("nope.crt"), &f.crl).is_err());
}

#[test]
fn device_ca_empty() {
    let dir = TempDir::new();
    let f = files(&dir);
    std::fs::write(&f.ca, "").unwrap();
    let e = server_config(&f.cert, &f.key, &f.ca, &f.crl).err().unwrap();
    assert!(e.contains("no certificates"), "{e}");
}

#[test]
fn device_ca_garbage() {
    let dir = TempDir::new();
    let f = files(&dir);
    std::fs::write(&f.ca, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").unwrap();
    assert!(server_config(&f.cert, &f.key, &f.ca, &f.crl).is_err());
}

#[test]
fn server_cert_missing_or_empty() {
    let dir = TempDir::new();
    let f = files(&dir);
    assert!(server_config(&dir.path("nope"), &f.key, &f.ca, &f.crl).is_err());
    std::fs::write(&f.cert, "").unwrap();
    assert!(server_config(&f.cert, &f.key, &f.ca, &f.crl).is_err());
}

#[test]
fn server_key_missing_or_garbage() {
    let dir = TempDir::new();
    let f = files(&dir);
    assert!(server_config(&f.cert, &dir.path("nope"), &f.ca, &f.crl).is_err());
    std::fs::write(&f.key, "not a key").unwrap();
    assert!(server_config(&f.cert, &f.key, &f.ca, &f.crl).is_err());
}

#[test]
fn server_key_must_match_certificate() {
    let dir = TempDir::new();
    let f = files(&dir);
    std::fs::write(&f.key, &pki().device.key_pem).unwrap();
    assert!(server_config(&f.cert, &f.key, &f.ca, &f.crl).is_err());
}

#[test]
fn several_cas_and_crls_accepted() {
    let dir = TempDir::new();
    let f = files(&dir);
    std::fs::write(&f.ca, format!("{}{}", pki().device_ca.pem, pki().rogue_ca.pem)).unwrap();
    std::fs::write(&f.crl, format!("{}{}", pki().crl(), pki().rogue_ca.crl(&[], -1, 7))).unwrap();
    assert!(server_config(&f.cert, &f.key, &f.ca, &f.crl).is_ok());
}

#[test]
fn expired_crl_still_loads() {
    // Loading succeeds; every handshake then fails closed (see e2e_serve::expired_crl_locks_everyone_out).
    let dir = TempDir::new();
    let f = pki().files(&dir, &pki().device_ca.crl(&[], -10, -3));
    assert!(server_config(&f.cert, &f.key, &f.ca, &f.crl).is_ok());
}

#[test]
fn directory_client_ok_and_errors() {
    let dir = TempDir::new();
    let ca = dir.write("dir-ca.crt", &pki().dir_ca.pem);
    assert!(directory_client(&ca).is_ok());
    assert!(directory_client(&dir.path("nope")).is_err());
    assert!(directory_client(&dir.write("empty.crt", "")).is_err());
}

fn reloading(dir: &TempDir) -> (Reloading, crate::tests::support::TlsFiles) {
    let f = files(dir);
    (Reloading::new(&f.cert, &f.key, &f.ca, &f.crl).unwrap(), f)
}

#[test]
fn reloading_keeps_config_while_unchanged() {
    let dir = TempDir::new();
    let (r, _) = reloading(&dir);
    let a = r.get().unwrap();
    let b = r.get().unwrap();
    assert!(Arc::ptr_eq(&a, &b));
}

#[test]
fn reloading_picks_up_new_crl() {
    let dir = TempDir::new();
    let (r, f) = reloading(&dir);
    let a = r.get().unwrap();
    replace(&f.crl, &pki().device_ca.crl(&[1, 2], -1, 7));
    let b = r.get().unwrap();
    assert!(!Arc::ptr_eq(&a, &b));
    assert!(Arc::ptr_eq(&b, &r.get().unwrap()), "and only once");
}

#[test]
fn reloading_picks_up_new_ca() {
    let dir = TempDir::new();
    let (r, f) = reloading(&dir);
    let a = r.get().unwrap();
    replace(&f.ca, &format!("{}{}", pki().device_ca.pem, Ca::new("next CA").pem));
    assert!(!Arc::ptr_eq(&a, &r.get().unwrap()));
}

#[test]
fn reloading_ignores_server_cert_changes() {
    let dir = TempDir::new();
    let (r, f) = reloading(&dir);
    let a = r.get().unwrap();
    replace(&f.cert, &pki().server.pem);
    assert!(Arc::ptr_eq(&a, &r.get().unwrap()));
}

#[test]
fn failed_reload_fails_closed_then_recovers() {
    let dir = TempDir::new();
    let (r, f) = reloading(&dir);
    r.get().unwrap();
    replace(&f.crl, "");
    assert!(r.get().is_err(), "a broken CRL refuses everyone");
    assert!(r.get().is_err(), "and keeps refusing");
    replace(&f.crl, &pki().crl());
    assert!(r.get().is_ok());
}

#[test]
fn deleted_crl_fails_closed() {
    let dir = TempDir::new();
    let (r, f) = reloading(&dir);
    r.get().unwrap();
    std::fs::remove_file(&f.crl).unwrap();
    assert!(r.get().is_err());
}

#[test]
fn reloading_new_needs_valid_files() {
    let dir = TempDir::new();
    let f = files(&dir);
    assert!(Reloading::new(&f.cert, &f.key, &f.ca, &dir.path("nope")).is_err());
}

// ---------- malformed PEM contents (per-item parse errors) ----------

const BAD_PEM: &str = "-----BEGIN CERTIFICATE-----\n!!!! not base64 !!!!\n-----END CERTIFICATE-----\n";

#[test]
fn device_ca_pem_item_unparseable() {
    let dir = TempDir::new();
    let f = files(&dir);
    std::fs::write(&f.ca, BAD_PEM).unwrap();
    assert!(server_config(&f.cert, &f.key, &f.ca, &f.crl).is_err());
}

#[test]
fn server_cert_pem_item_unparseable() {
    let dir = TempDir::new();
    let f = files(&dir);
    std::fs::write(&f.cert, BAD_PEM).unwrap();
    assert!(server_config(&f.cert, &f.key, &f.ca, &f.crl).is_err());
}

// ---------- Reloading::get with poisoned locks (fail closed) ----------

fn poison_mutex<T>(m: &std::sync::Mutex<T>) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _g = m.lock().unwrap();
        panic!("poison");
    }));
}

fn poison_rwlock_write<T>(l: &std::sync::RwLock<T>) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _g = l.write().unwrap();
        panic!("poison");
    }));
}

#[test]
fn reloading_get_stamp_poisoned_fails_closed() {
    let dir = TempDir::new();
    let (r, _) = reloading(&dir);
    poison_mutex(&r.stamp);
    assert!(r.get().is_err());
}

#[test]
fn reloading_get_current_read_poisoned_fails_closed() {
    let dir = TempDir::new();
    let (r, _) = reloading(&dir);
    poison_rwlock_write(&r.current);
    assert!(r.get().is_err());
}

#[test]
fn reloading_get_current_write_poisoned_on_reload_fails_closed() {
    let dir = TempDir::new();
    let (r, f) = reloading(&dir);
    poison_rwlock_write(&r.current);
    replace(&f.crl, &pki().device_ca.crl(&[1, 2, 3], -1, 7)); // force a reload so the write lock is taken
    assert!(r.get().is_err());
}
