//! The directory behind the server (389 DS). Everything LDAP-shaped stays on this side of the trait:
//! clients only ever learn two flags per user.

use crate::config;
use crate::ldap::{Ldap, LdapError};
use crate::secret::SecretBuf;
use rustls::ClientConfig;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Membership {
    pub user: bool,
    pub admin: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Wrong password or no such user.
    Invalid,
    /// The directory refused the account (locked, disabled, policy).
    Denied,
    /// Could not reach the directory: the client takes its offline path.
    Unavailable,
    /// Anything else; the reason is for the audit line only.
    Error(&'static str),
}

pub trait Directory: Send + Sync {
    /// Binds as the user (the password is consumed and zeroed as soon as the bind request is written), then
    /// reads the user's own membership.
    fn authenticate(&self, uun: &str, password: SecretBuf) -> Result<Membership, Failure>;
    /// Membership of each UUN (same order), read with the server's own account. All or nothing.
    fn status(&self, uuns: &[String]) -> Result<Vec<Membership>, Failure>;
}

pub struct LdapDirectory {
    cfg: config::Directory,
    tls: Arc<ClientConfig>,
}

impl LdapDirectory {
    pub fn new(cfg: config::Directory, tls: Arc<ClientConfig>) -> LdapDirectory {
        LdapDirectory { cfg, tls }
    }

    fn connect(&self) -> Result<Ldap<crate::ldap::LdapsStream>, Failure> {
        let c = &self.cfg;
        Ldap::connect(&c.host, c.port, &c.server_name, self.tls.clone(), Duration::from_secs(c.timeout_seconds))
            .map_err(|_| Failure::Unavailable)
    }
}

impl Directory for LdapDirectory {
    fn authenticate(&self, uun: &str, password: SecretBuf) -> Result<Membership, Failure> {
        let mut ldap = self.connect()?;
        let dn = user_dn(&self.cfg, uun);
        bind_result(ldap.bind(&dn, password))?;
        let m = membership(&mut ldap, &self.cfg, uun)?.ok_or(Failure::Error("self_read"));
        ldap.unbind();
        m
    }

    fn status(&self, uuns: &[String]) -> Result<Vec<Membership>, Failure> {
        let secret = std::fs::File::open(&self.cfg.service_password_file)
            .and_then(|mut f| SecretBuf::read_from(&mut f, 1024))
            .map(|mut s| {
                s.trim_newlines();
                s
            })
            .map_err(|_| Failure::Error("service_secret"))?;
        let mut ldap = self.connect()?;
        match bind_result(ldap.bind(&self.cfg.service_dn, secret)) {
            Ok(()) => {}
            Err(Failure::Unavailable) => return Err(Failure::Unavailable),
            Err(_) => return Err(Failure::Error("service_bind")),
        }
        let out = uuns.iter().map(|u| membership(&mut ldap, &self.cfg, u).map(Option::unwrap_or_default)).collect();
        ldap.unbind();
        out
    }
}

pub fn user_dn(cfg: &config::Directory, uun: &str) -> String {
    cfg.user_dn_template.replace("{0}", uun)
}

/// Maps a simple-bind outcome: 0 ok, 49 invalid, 19/50/53 refused by policy.
pub fn bind_result(r: Result<u32, LdapError>) -> Result<(), Failure> {
    match r {
        Ok(0) => Ok(()),
        Ok(49) => Err(Failure::Invalid),
        Ok(19 | 50 | 53) => Err(Failure::Denied),
        Ok(_) => Err(Failure::Error("directory_result")),
        Err(LdapError::Unreachable) => Err(Failure::Unavailable),
        Err(LdapError::Protocol) => Err(Failure::Error("directory_protocol")),
    }
}

/// The user's membership from their entry's memberOf; None if there is no such entry.
pub fn membership<S: Read + Write>(
    ldap: &mut Ldap<S>,
    cfg: &config::Directory,
    uun: &str,
) -> Result<Option<Membership>, Failure> {
    match ldap.read_entry(&user_dn(cfg, uun), ("uid", uun), &["memberOf"]) {
        Ok((0, Some(entry))) => {
            let groups: Vec<String> =
                entry.values("memberOf").map(|v| normalize_dn(&String::from_utf8_lossy(v))).collect();
            let has = |g: &str| groups.contains(&normalize_dn(g));
            Ok(Some(Membership { user: has(&cfg.users_group), admin: has(&cfg.admins_group) }))
        }
        Ok((0, None) | (32, _)) => Ok(None),
        Ok(_) => Err(Failure::Error("entry_read")),
        Err(LdapError::Unreachable) => Err(Failure::Unavailable),
        Err(LdapError::Protocol) => Err(Failure::Error("directory_protocol")),
    }
}

/// Lower case, no spaces around ',' and '=': the comparison form of a DN.
pub fn normalize_dn(dn: &str) -> String {
    dn.split(',')
        .map(|p| match p.split_once('=') {
            Some((k, v)) => format!("{}={}", k.trim(), v.trim()),
            None => p.trim().to_string(),
        })
        .collect::<Vec<_>>()
        .join(",")
        .to_ascii_lowercase()
}

#[cfg(test)]
#[path = "tests/unit_directory.rs"]
mod tests;
