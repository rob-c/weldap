//! WELDAP server: the only thing WELDAP clients talk to, and the only thing that talks to the directory.
//!
//!   weldap-server serve --config /etc/weldap/server.json
//!   weldap-server keygen --kid <id> --out <private-key-file>    prints the public key for clients
//!   weldap-server pubkey --key <private-key-file>
//!
//! Private key files hold the 32-byte P-256 scalar, base64, mode 0400.

// `unsafe` only in secret.rs (locked memory) and hardening.rs (process limits), each with a module-level allow.
#![deny(unsafe_code)]

mod audit;
mod config;
mod directory;
mod hardening;
mod ldap;
mod seal;
mod secret;
mod server;
mod tls;

#[cfg(test)]
mod tests;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use secret::SecretBuf;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroize;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn fail(msg: &str) -> ! {
    // Startup errors only (paths, config syntax): never request data.
    eprintln!("weldap-server: {msg}");
    std::process::exit(1);
}

/// Reads a base64 private key file into locked memory and decodes it there.
fn load_key(kid: &str, path: &Path) -> Result<seal::PasswordKey, String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut text = SecretBuf::read_from(&mut file, 256).map_err(|e| format!("{}: {e}", path.display()))?;
    text.trim_newlines();
    let mut scalar = [0u8; 48];
    let n = B64.decode_slice(text.as_slice(), &mut scalar).map_err(|_| format!("{}: not base64", path.display()))?;
    drop(text);
    let key = seal::PasswordKey::from_scalar(kid.to_string(), &scalar[..n]);
    scalar.zeroize();
    key.map_err(|e| format!("{}: {e}", path.display()))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") => {
            if let Err(e) = hardening::harden_process() {
                fail(&e);
            }
            let path = PathBuf::from(arg(&args, "--config").unwrap_or_else(|| "/etc/weldap/server.json".into()));
            let cfg = config::Config::load(&path).unwrap_or_else(|e| fail(&e));
            let keys = cfg
                .password_keys
                .iter()
                .map(|k| load_key(&k.kid, &k.private_key))
                .collect::<Result<Vec<_>, _>>()
                .unwrap_or_else(|e| fail(&e));
            let tls = tls::Reloading::new(&cfg.server_cert, &cfg.server_key, &cfg.device_ca, &cfg.device_crl)
                .unwrap_or_else(|e| fail(&e));
            let directory_tls = tls::directory_client(&cfg.directory.ca).unwrap_or_else(|e| fail(&e));
            let listener = std::net::TcpListener::bind(&cfg.listen)
                .unwrap_or_else(|e| fail(&format!("listen {}: {e}", cfg.listen)));
            audit::event("started", &[("keys", audit::V::N(keys.len() as u64))]);
            let directory = Box::new(directory::LdapDirectory::new(cfg.directory, directory_tls));
            let server = Arc::new(server::Server::new(keys, directory, cfg.max_clock_skew_seconds));
            server.serve(listener, Arc::new(tls), cfg.max_connections);
        }
        Some("keygen") => {
            let kid = arg(&args, "--kid").unwrap_or_else(|| fail("--kid required"));
            let out = PathBuf::from(arg(&args, "--out").unwrap_or_else(|| fail("--out required")));
            let (mut sk, pk) = seal::generate();
            let mut text = B64.encode(&sk);
            sk.zeroize();
            write_private(&out, text.as_bytes()).unwrap_or_else(|e| fail(&e));
            text.zeroize();
            println!("kid={kid} public={}", B64.encode(pk));
        }
        Some("pubkey") => {
            let key = PathBuf::from(arg(&args, "--key").unwrap_or_else(|| fail("--key required")));
            let k = load_key("-", &key).unwrap_or_else(|e| fail(&e));
            println!("public={}", B64.encode(k.public_bytes()));
        }
        _ => fail("usage: weldap-server serve [--config F] | keygen --kid K --out F | pubkey --key F"),
    }
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(data).map_err(|e| format!("{}: {e}", path.display()))
}
