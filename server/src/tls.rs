//! TLS: the device-facing server (client certificate from the device CA, CRL enforced) and the
//! directory-facing client (389 DS certificate verified against the directory CA).

use rustls::client::WebPkiServerVerifier;
use rustls::crypto::ring;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(ring::default_provider())
}

fn roots(path: &Path) -> Result<RootCertStore, String> {
    let mut store = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(path).map_err(|e| format!("{}: {e}", path.display()))? {
        store
            .add(cert.map_err(|e| format!("{}: {e}", path.display()))?)
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    if store.is_empty() {
        return Err(format!("{}: no certificates", path.display()));
    }
    Ok(store)
}

pub fn server_config(
    cert: &Path,
    key: &Path,
    device_ca: &Path,
    device_crl: &Path,
) -> Result<Arc<ServerConfig>, String> {
    let crls: Vec<CertificateRevocationListDer<'static>> = CertificateRevocationListDer::pem_file_iter(device_crl)
        .map_err(|e| format!("{}: {e}", device_crl.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", device_crl.display()))?;
    if crls.is_empty() {
        return Err(format!("{}: no CRL (refusing to run without revocation)", device_crl.display()));
    }
    // Revocation status is mandatory: unknown status is refused, and an expired CRL fails closed.
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots(device_ca)?), provider())
        .with_crls(crls)
        .enforce_revocation_expiration()
        .build()
        .map_err(|e| format!("client verifier: {e}"))?;
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| format!("{}: {e}", cert.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(|e| format!("{}: {e}", key.display()))?;
    let mut cfg = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("TLS 1.3 and 1.2 are supported by the ring provider") // fixed list: cannot fail
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|e| format!("server certificate: {e}"))?;
    cfg.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    cfg.send_tls13_tickets = 0;
    Ok(Arc::new(cfg))
}

pub fn directory_client(ca: &Path) -> Result<Arc<ClientConfig>, String> {
    // Unreachable: `roots` already guaranteed a non-empty store and there are no CRLs to reject.
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots(ca)?), provider())
        .build()
        .expect("server verifier builds from a non-empty root store");
    let mut cfg = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("TLS 1.3 and 1.2 are supported by the ring provider") // fixed list: cannot fail
        .with_webpki_verifier(verifier)
        .with_no_client_auth();
    cfg.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(cfg))
}

/// Server config that is rebuilt when the device CA or CRL file changes (CRL publication, CA rollover).
pub struct Reloading {
    paths: [std::path::PathBuf; 4],
    stamp: std::sync::Mutex<(Option<SystemTime>, Option<SystemTime>)>,
    current: std::sync::RwLock<Arc<ServerConfig>>,
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

impl Reloading {
    pub fn new(cert: &Path, key: &Path, ca: &Path, crl: &Path) -> Result<Reloading, String> {
        let cfg = server_config(cert, key, ca, crl)?;
        Ok(Reloading {
            paths: [cert.into(), key.into(), ca.into(), crl.into()],
            stamp: std::sync::Mutex::new((mtime(ca), mtime(crl))),
            current: std::sync::RwLock::new(cfg),
        })
    }

    /// The config to use for the next handshake; reloads first if the CA or CRL changed. A reload that
    /// fails keeps nothing usable: it returns Err so the connection is refused (fail closed).
    pub fn get(&self) -> Result<Arc<ServerConfig>, &'static str> {
        let [cert, key, ca, crl] = &self.paths;
        let now = (mtime(ca), mtime(crl));
        let mut stamp = self.stamp.lock().map_err(|_| "poisoned")?;
        if *stamp != now {
            let cfg = server_config(cert, key, ca, crl).map_err(|_| "reload failed")?;
            *self.current.write().map_err(|_| "poisoned")? = cfg;
            *stamp = now;
            crate::audit::event("tls_reloaded", &[]);
        }
        Ok(self.current.read().map_err(|_| "poisoned")?.clone())
    }
}

#[cfg(test)]
#[path = "tests/unit_tls.rs"]
mod tests;
