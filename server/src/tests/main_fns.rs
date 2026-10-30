//! `main.rs` helpers: private key files and argument lookup.

use crate::tests::support::TempDir;
use crate::{arg, load_key, seal, write_private};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::os::unix::fs::PermissionsExt;

#[test]
fn keygen_files_round_trip() {
    let dir = TempDir::new();
    let (sk, pk) = seal::generate();
    let path = dir.path("k1.key");
    write_private(&path, B64.encode(&sk).as_bytes()).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o400);
    let key = load_key("k1", &path).unwrap();
    assert_eq!(key.kid, "k1");
    assert_eq!(key.public_bytes(), pk);
}

#[test]
fn write_private_never_overwrites() {
    let dir = TempDir::new();
    let path = dir.write("exists.key", "old");
    assert!(write_private(&path, b"new").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"old");
}

#[test]
fn load_key_accepts_trailing_newlines() {
    let dir = TempDir::new();
    let (sk, pk) = seal::generate();
    let path = dir.write("k.key", format!("{}\r\n\n", B64.encode(&sk)));
    assert_eq!(load_key("k", &path).unwrap().public_bytes(), pk);
}

fn load_err(content: &[u8]) {
    let dir = TempDir::new();
    let path = dir.write("k.key", content);
    let e = load_key("k", &path).err().unwrap();
    assert!(e.contains("k.key"), "{e}");
}

crate::cases! { load_err;
    key_empty: b"";
    key_not_base64: b"not base64 at all";
    key_too_short: B64.encode([1u8; 31]).as_bytes();
    key_too_long: B64.encode([1u8; 33]).as_bytes();
    key_zero: B64.encode([0u8; 32]).as_bytes();
    key_over_order: B64.encode([0xffu8; 32]).as_bytes();
    key_file_too_big: &[b'A'; 300];
    key_with_spaces: format!(" {}", B64.encode([1u8; 32])).as_bytes();
}

#[test]
fn load_key_missing_file() {
    let e = load_key("k", std::path::Path::new("/nonexistent/k.key")).err().unwrap();
    assert!(e.starts_with("/nonexistent/k.key"), "{e}");
}

#[test]
fn arg_lookup() {
    let args: Vec<String> = ["weldap-server", "serve", "--config", "/etc/x.json", "--kid"].map(String::from).to_vec();
    assert_eq!(arg(&args, "--config").as_deref(), Some("/etc/x.json"));
    assert_eq!(arg(&args, "--kid"), None, "flag without a value");
    assert_eq!(arg(&args, "--out"), None);
}
