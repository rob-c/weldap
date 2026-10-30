//! Server configuration (JSON). Paths only: secrets live in their own files, read into locked memory.

use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// e.g. "0.0.0.0:8636"
    pub listen: String,
    /// Server TLS certificate chain + key (from a server CA, never the device CA).
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    /// The device CA certificate and its CRL: the only way in.
    pub device_ca: PathBuf,
    pub device_crl: PathBuf,
    /// Password keys (HPKE private keys), newest first; several during a rotation.
    pub password_keys: Vec<PasswordKeyFile>,
    pub directory: Directory,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_skew")]
    pub max_clock_skew_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordKeyFile {
    pub kid: String,
    pub private_key: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    pub host: String,
    pub port: u16,
    pub server_name: String,
    pub ca: PathBuf,
    /// e.g. "uid={0},ou=people,dc=example,dc=org"
    pub user_dn_template: String,
    pub users_group: String,
    pub admins_group: String,
    /// Read-only account the server uses for membership checks (FR-12); clients hold no directory credential.
    pub service_dn: String,
    pub service_password_file: PathBuf,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

fn default_max_connections() -> usize {
    64
}
fn default_skew() -> u64 {
    120
}
fn default_timeout() -> u64 {
    5
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let cfg: Config = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        if !cfg.directory.user_dn_template.contains("{0}") {
            return Err("directory.user_dn_template needs {0}".into());
        }
        if cfg.password_keys.is_empty() {
            return Err("password_keys is empty".into());
        }
        Ok(cfg)
    }
}

#[cfg(test)]
#[path = "tests/unit_config.rs"]
mod tests;
