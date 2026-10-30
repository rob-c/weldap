//! Test client: does exactly what a WELDAP client does on the wire (mTLS with a device certificate, password
//! sealed with HPKE), so the server can be tested without Windows. Also checks interop with the C++ sealer.
//!
//!   weldap-probe auth   --server H:P --name N --ca F --cert F --key F --kid K --pub B64 --uun U --password-file F
//!                       [--scenario logon] [--replay] [--skew SECONDS] [--other-kid K]
//!   weldap-probe status --server H:P --name N --ca F --cert F --key F --uuns a,b,c
//!   weldap-probe raw    --server H:P ... --body JSON
//!   weldap-probe open   --key F --enc B64 --ct B64 --aad-hex HEX     (decrypts a C++-sealed message)
//!   weldap-probe seal   --pub B64 --password-file F --aad-hex HEX    (prints enc and ct as base64)

#![deny(unsafe_code)] // only the included secret.rs allows it

#[path = "../seal.rs"]
#[allow(dead_code)]
mod seal;
#[path = "../secret.rs"]
#[allow(dead_code)]
mod secret;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}
fn need(args: &[String], name: &str) -> String {
    arg(args, name).unwrap_or_else(|| {
        eprintln!("missing {name}");
        std::process::exit(2)
    })
}

fn connect(args: &[String]) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for c in CertificateDer::pem_file_iter(need(args, "--ca")).map_err(|e| e.to_string())? {
        roots.add(c.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    }
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots);
    let cfg = match (arg(args, "--cert"), arg(args, "--key")) {
        (Some(c), Some(k)) => {
            let chain = CertificateDer::pem_file_iter(c)
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            let key = PrivateKeyDer::from_pem_file(k).map_err(|e| e.to_string())?;
            builder.with_client_auth_cert(chain, key).map_err(|e| e.to_string())?
        }
        _ => builder.with_no_client_auth(),
    };
    let tcp = TcpStream::connect(need(args, "--server")).map_err(|e| e.to_string())?;
    let name = ServerName::try_from(need(args, "--name")).map_err(|e| e.to_string())?;
    let conn = rustls::ClientConnection::new(Arc::new(cfg), name).map_err(|e| e.to_string())?;
    Ok(rustls::StreamOwned::new(conn, tcp))
}

fn exchange(args: &[String], body: &[u8]) -> String {
    let mut tls = match connect(args) {
        Ok(t) => t,
        Err(e) => return format!("connect-failed: {e}"),
    };
    let Ok(len) = u32::try_from(body.len()) else {
        return "refused: body too large".into();
    };
    let sent = tls.write_all(&len.to_be_bytes()).and_then(|()| tls.write_all(body)).and_then(|()| tls.flush());
    if let Err(e) = sent {
        return format!("refused: {e}");
    }
    let mut len = [0u8; 4];
    if let Err(e) = tls.read_exact(&mut len) {
        return format!("refused: {e}");
    }
    let mut reply = vec![0u8; u32::from_be_bytes(len) as usize];
    if let Err(e) = tls.read_exact(&mut reply) {
        return format!("refused: {e}");
    }
    String::from_utf8_lossy(&reply).into_owned()
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("auth") => {
            let kid = need(&args, "--kid");
            let uun = need(&args, "--uun");
            let scenario = arg(&args, "--scenario").unwrap_or_else(|| "logon".into());
            let skew: i64 = arg(&args, "--skew").map_or(0, |s| s.parse().unwrap());
            let ts = now().checked_add_signed(skew).expect("--skew out of range");
            let mut rid = [0u8; 16];
            getrandom(&mut rid);
            let rid = B64.encode(rid);
            let pk = B64.decode(need(&args, "--pub")).expect("--pub base64");
            let mut password = std::fs::read(need(&args, "--password-file")).expect("password file");
            while password.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                password.pop();
            }
            let aad = seal::aad(&kid, &uun, &scenario, ts, &rid);
            let (enc, ct) = seal::seal(&pk, &password, &aad).expect("seal");
            let sent_kid = arg(&args, "--other-kid").unwrap_or(kid);
            let body = serde_json::json!({"op": "auth", "v": 1, "uun": uun, "scenario": scenario, "kid": sent_kid,
                "enc": B64.encode(enc), "ct": B64.encode(ct), "ts": ts, "rid": rid});
            let body = serde_json::to_vec(&body).unwrap();
            println!("{}", exchange(&args, &body));
            if args.iter().any(|a| a == "--replay") {
                println!("{}", exchange(&args, &body));
            }
        }
        Some("status") => {
            let uuns: Vec<&str> = arg(&args, "--uuns")
                .map(|s| s.leak().split(',').filter(|u| !u.is_empty()).collect())
                .unwrap_or_default();
            let body = serde_json::to_vec(&serde_json::json!({"op": "status", "v": 1, "uuns": uuns})).unwrap();
            println!("{}", exchange(&args, &body));
        }
        Some("raw") => println!("{}", exchange(&args, need(&args, "--body").as_bytes())),
        Some("open") => {
            let text = std::fs::read_to_string(need(&args, "--key")).expect("key");
            let sk = B64.decode(text.trim()).expect("key base64");
            let key = seal::PasswordKey::from_scalar("-".into(), &sk).expect("key");
            let aad = hex(&need(&args, "--aad-hex"));
            match key.open(&B64.decode(need(&args, "--enc")).unwrap(), &B64.decode(need(&args, "--ct")).unwrap(), &aad)
            {
                Ok(p) => println!("opened {} bytes: {}", p.len(), String::from_utf8_lossy(p.as_slice())),
                Err(()) => println!("open failed"),
            }
        }
        Some("seal") => {
            let pk = B64.decode(need(&args, "--pub")).unwrap();
            let pw = std::fs::read(need(&args, "--password-file")).unwrap();
            let (enc, ct) = seal::seal(&pk, &pw, &hex(&need(&args, "--aad-hex"))).unwrap();
            println!("enc={} ct={}", B64.encode(enc), B64.encode(ct));
        }
        _ => {
            eprintln!("usage: weldap-probe auth|status|raw|open|seal ...");
            std::process::exit(2);
        }
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn getrandom(buf: &mut [u8]) {
    ::getrandom::fill(buf).expect("OS RNG");
}
