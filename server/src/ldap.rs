//! Server-internal: the only code anywhere in WELDAP that speaks LDAP. Minimal LDAP v3 client over TLS (LDAPS):
//! simple bind, base-object search, unbind. Written here rather than using an LDAP library so that the password goes from a `SecretBuf` into a `SecretBuf`-held bind
//! request and from there only into the TLS writer, which encrypts the record in place. BER parsing is
//! bounds-checked and size-capped; nothing parsed from the directory is ever logged.

use crate::secret::SecretBuf;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

const MAX_MESSAGE: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdapError {
    /// Could not reach or handshake with the directory: the device takes its offline path.
    Unreachable,
    /// Reached it, but the exchange went wrong (malformed reply, unexpected message).
    Protocol,
}

pub struct Entry {
    pub attrs: Vec<(String, Vec<Vec<u8>>)>,
}

impl Entry {
    pub fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.attrs
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .flat_map(|(_, v)| v.iter().map(Vec::as_slice))
    }
}

/// One directory connection. Generic over the stream so the BER handling can be tested on byte buffers.
pub struct Ldap<S: Read + Write> {
    s: S,
    msgid: u8,
}

pub type LdapsStream = StreamOwned<ClientConnection, TcpStream>;

// ---------- BER writing ----------

fn len_bytes(n: usize) -> Vec<u8> {
    if let Ok(short @ 0..=0x7f) = u8::try_from(n) {
        return vec![short];
    }
    // Long form: 0x80 | count, then the length's big-endian bytes without leading zeros.
    let mut out = vec![0x80];
    for b in n.to_be_bytes().into_iter().skip_while(|b| *b == 0) {
        out.push(b);
        out[0] += 1;
    }
    out
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(len_bytes(content.len()));
    out.extend_from_slice(content);
    out
}

fn int(tag: u8, v: u8) -> Vec<u8> {
    // Small non-negative integers only (message ids 1..=127, version 3, limits); top bit clear.
    tlv(tag, &[v & 0x7f])
}

// ---------- BER reading ----------

/// Splits one TLV off the front of `buf`: (tag, content, rest).
fn take(buf: &[u8]) -> Result<(u8, &[u8], &[u8]), LdapError> {
    if buf.len() < 2 {
        return Err(LdapError::Protocol);
    }
    let tag = buf[0];
    let (len, hdr) = if buf[1] < 0x80 {
        (usize::from(buf[1]), 2)
    } else {
        let n = usize::from(buf[1] & 0x7f);
        if n == 0 || n > 4 || buf.len() < 2 + n {
            return Err(LdapError::Protocol);
        }
        (buf[2..2 + n].iter().fold(0usize, |a, b| (a << 8) | usize::from(*b)), 2 + n)
    };
    if len > buf.len() - hdr {
        return Err(LdapError::Protocol);
    }
    Ok((tag, &buf[hdr..hdr + len], &buf[hdr + len..]))
}

fn small_uint(content: &[u8]) -> Result<u32, LdapError> {
    if content.is_empty() || content.len() > 4 {
        return Err(LdapError::Protocol);
    }
    Ok(content.iter().fold(0u32, |a, b| (a << 8) | u32::from(*b)))
}

/// Read and write timeouts for a directory socket, as one fallible step (so the whole thing is one error
/// region). A zero `d` is rejected by the first call, which is how the unit test reaches the error path.
fn set_timeouts(tcp: &TcpStream, d: Duration) -> std::io::Result<()> {
    tcp.set_read_timeout(Some(d)).and_then(|()| tcp.set_write_timeout(Some(d)))
}

impl Ldap<LdapsStream> {
    pub fn connect(
        host: &str,
        port: u16,
        server_name: &str,
        tls: Arc<ClientConfig>,
        timeout: Duration,
    ) -> Result<Self, LdapError> {
        // A resolver error and an empty result both mean "unreachable": one branch covers both.
        let addr = (host, port).to_socket_addrs().ok().and_then(|mut a| a.next()).ok_or(LdapError::Unreachable)?;
        let tcp = TcpStream::connect_timeout(&addr, timeout).map_err(|_| LdapError::Unreachable)?;
        // Unreachable: the socket is connected and `timeout` is non-zero here (a zero one fails connect above).
        set_timeouts(&tcp, timeout).expect("setting timeouts on a freshly connected socket cannot fail");
        let name = ServerName::try_from(server_name.to_string()).map_err(|_| LdapError::Unreachable)?;
        // Unreachable: the directory client config is built by `tls::directory_client` and is always valid.
        let conn = ClientConnection::new(tls, name).expect("directory TLS client config is always valid");
        let mut tls = StreamOwned::new(conn, tcp);
        // Finish the handshake (server certificate verified against the directory CA) before any secret.
        while tls.conn.is_handshaking() {
            tls.conn.complete_io(&mut tls.sock).map_err(|_| LdapError::Unreachable)?;
        }
        Ok(Ldap::new(tls))
    }
}

impl<S: Read + Write> Ldap<S> {
    pub fn new(s: S) -> Self {
        Ldap { s, msgid: 0 }
    }

    fn next_id(&mut self) -> u8 {
        self.msgid = self.msgid % 127 + 1;
        self.msgid
    }

    fn read_message(&mut self) -> Result<Vec<u8>, LdapError> {
        // Tag + length header first, then exactly the content.
        let mut hdr = [0u8; 2];
        self.s.read_exact(&mut hdr).map_err(|_| LdapError::Unreachable)?;
        if hdr[0] != 0x30 {
            return Err(LdapError::Protocol);
        }
        let len = if hdr[1] < 0x80 {
            usize::from(hdr[1])
        } else {
            let n = usize::from(hdr[1] & 0x7f);
            if n == 0 || n > 4 {
                return Err(LdapError::Protocol);
            }
            let mut l = [0u8; 4];
            self.s.read_exact(&mut l[..n]).map_err(|_| LdapError::Unreachable)?;
            l[..n].iter().fold(0usize, |a, b| (a << 8) | usize::from(*b))
        };
        if len > MAX_MESSAGE {
            return Err(LdapError::Protocol);
        }
        let mut body = vec![0u8; len];
        self.s.read_exact(&mut body).map_err(|_| LdapError::Unreachable)?;
        Ok(body)
    }

    /// Splits an `LDAPMessage` body into (protocolOp tag, its content), checking the message id.
    fn op(body: &[u8], id: u8) -> Result<(u8, &[u8]), LdapError> {
        let (t, mid, rest) = take(body)?;
        if t != 0x02 || small_uint(mid)? != u32::from(id) {
            return Err(LdapError::Protocol);
        }
        let (tag, content, _controls) = take(rest)?;
        Ok((tag, content))
    }

    /// Simple bind. The password is consumed: it is copied into the (locked) request buffer, both are
    /// zeroed as soon as the request is in the TLS writer, before the reply is even read.
    /// Returns the LDAP result code (0 = success, 49 = invalid credentials, ...).
    pub fn bind(&mut self, dn: &str, password: SecretBuf) -> Result<u32, LdapError> {
        if password.is_empty() {
            return Err(LdapError::Protocol); // an empty simple bind is an anonymous bind: never
        }
        let id = self.next_id();
        let dn_tlv = tlv(0x04, dn.as_bytes());
        let pw_len = len_bytes(password.len());
        let version = int(0x02, 3);
        let bind_len = version.len() + dn_tlv.len() + 1 + pw_len.len() + password.len();
        let bind_hdr = len_bytes(bind_len);
        let msgid = int(0x02, id);
        let msg_len = msgid.len() + 1 + bind_hdr.len() + bind_len;
        let msg_hdr = len_bytes(msg_len);

        // Built in one locked, exactly-sized buffer: the password is copied straight in, never into a Vec.
        let req = SecretBuf::concat(&[
            &[0x30],
            &msg_hdr,
            &msgid,
            &[0x60],
            &bind_hdr,
            &version,
            &dn_tlv,
            &[0x80],
            &pw_len,
            password.as_slice(),
        ]);
        drop(password);
        let written = self.s.write_all(req.as_slice()).and_then(|()| self.s.flush());
        drop(req);
        written.map_err(|_| LdapError::Unreachable)?;

        let body = self.read_message()?;
        let (tag, content) = Self::op(&body, id)?;
        if tag != 0x61 {
            return Err(LdapError::Protocol);
        }
        let (t, code, _) = take(content)?;
        if t != 0x0a {
            return Err(LdapError::Protocol);
        }
        small_uint(code)
    }

    /// Base-object search of `dn` with an equality filter; returns (result code, entry if any).
    pub fn read_entry(
        &mut self,
        dn: &str,
        filter: (&str, &str),
        attrs: &[&str],
    ) -> Result<(u32, Option<Entry>), LdapError> {
        let id = self.next_id();
        let mut filt = tlv(0x04, filter.0.as_bytes());
        filt.extend(tlv(0x04, filter.1.as_bytes()));
        let mut attr_list = Vec::new();
        for a in attrs {
            attr_list.extend(tlv(0x04, a.as_bytes()));
        }
        let mut search = tlv(0x04, dn.as_bytes());
        search.extend(tlv(0x0a, &[0])); // scope: baseObject
        search.extend(tlv(0x0a, &[0])); // derefAliases: never
        search.extend(int(0x02, 1)); // sizeLimit
        search.extend(int(0x02, 10)); // timeLimit (s)
        search.extend(tlv(0x01, &[0])); // typesOnly: false
        search.extend(tlv(0xa3, &filt)); // equalityMatch
        search.extend(tlv(0x30, &attr_list));
        let mut msg = int(0x02, id);
        msg.extend(tlv(0x63, &search));
        self.s.write_all(&tlv(0x30, &msg)).and_then(|()| self.s.flush()).map_err(|_| LdapError::Unreachable)?;

        let mut entry = None;
        loop {
            let body = self.read_message()?;
            let (tag, content) = Self::op(&body, id)?;
            match tag {
                0x64 => {
                    if entry.is_some() {
                        return Err(LdapError::Protocol); // base search: at most one entry
                    }
                    let (_, _name, rest) = take(content)?;
                    let (t, mut list, _) = take(rest)?;
                    if t != 0x30 {
                        return Err(LdapError::Protocol);
                    }
                    let mut attrs = Vec::new();
                    while !list.is_empty() {
                        let (t, one, rest) = take(list)?;
                        list = rest;
                        if t != 0x30 {
                            return Err(LdapError::Protocol);
                        }
                        let (_, name, rest) = take(one)?;
                        let (t, mut set, _) = take(rest)?;
                        if t != 0x31 {
                            return Err(LdapError::Protocol);
                        }
                        let mut values = Vec::new();
                        while !set.is_empty() {
                            let (_, v, rest) = take(set)?;
                            set = rest;
                            values.push(v.to_vec());
                        }
                        attrs.push((String::from_utf8_lossy(name).into_owned(), values));
                    }
                    entry = Some(Entry { attrs });
                }
                0x73 => {} // search result reference: ignored
                0x65 => {
                    let (t, code, _) = take(content)?;
                    if t != 0x0a {
                        return Err(LdapError::Protocol);
                    }
                    return Ok((small_uint(code)?, entry));
                }
                _ => return Err(LdapError::Protocol),
            }
        }
    }

    pub fn unbind(mut self) {
        let id = self.next_id();
        let mut msg = int(0x02, id);
        msg.extend_from_slice(&[0x42, 0x00]);
        let _ = self.s.write_all(&tlv(0x30, &msg));
        let _ = self.s.flush();
    }
}

#[cfg(test)]
#[path = "tests/unit_ldap.rs"]
mod tests;
