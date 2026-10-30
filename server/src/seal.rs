//! Sealed passwords: HPKE (RFC 9180) base mode, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM.
//! The Windows credential provider seals the password to the server's public password key inside `LogonUI`;
//! only this process holds the private key. The AAD binds the ciphertext to the key id, user, scenario,
//! timestamp and request id, so it cannot be moved to another user or replayed (the server also keeps a
//! replay cache of request ids).

use crate::secret::SecretBuf;
use hpke::aead::{AeadTag, AesGcm256};
use hpke::kdf::HkdfSha256;
use hpke::kem::DhP256HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};

pub type Kem = DhP256HkdfSha256;
pub const INFO: &[u8] = b"WELDAP password v1";
pub const ENC_LEN: usize = 65; // uncompressed P-256 point
pub const TAG_LEN: usize = 16;
pub const MAX_PASSWORD_BYTES: usize = 256;

/// Exactly what the client authenticates alongside the ciphertext (ASCII, '\n'-separated).
pub fn aad(kid: &str, uun: &str, scenario: &str, ts: u64, rid_b64: &str) -> Vec<u8> {
    format!("WELDAP-auth-v1\n{kid}\n{uun}\n{scenario}\n{ts}\n{rid_b64}").into_bytes()
}

pub struct PasswordKey {
    pub kid: String,
    sk: <Kem as hpke::Kem>::PrivateKey,
}

impl PasswordKey {
    /// `scalar` is the raw 32-byte private key; the caller zeroes its copy.
    pub fn from_scalar(kid: String, scalar: &[u8]) -> Result<PasswordKey, &'static str> {
        let sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(scalar).map_err(|_| "invalid P-256 private key")?;
        Ok(PasswordKey { kid, sk })
    }

    pub fn public_bytes(&self) -> Vec<u8> {
        Kem::sk_to_pk(&self.sk).to_bytes().to_vec()
    }

    /// Decrypts straight into locked memory. Any failure (wrong key, tampered AAD or ciphertext,
    /// oversize) is one opaque error.
    pub fn open(&self, enc: &[u8], ct_and_tag: &[u8], aad: &[u8]) -> Result<SecretBuf, ()> {
        if enc.len() != ENC_LEN || ct_and_tag.len() < TAG_LEN || ct_and_tag.len() > TAG_LEN + MAX_PASSWORD_BYTES {
            return Err(());
        }
        // A client can send any 65-byte enc; `from_bytes` rejects anything not on the P-256 curve (tested).
        let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| ())?;
        // Unreachable: `from_bytes` already validated the point, and DH on prime-order P-256 cannot fail.
        let mut ctx = hpke::setup_receiver::<AesGcm256, HkdfSha256, Kem>(&OpModeR::Base, &self.sk, &encapped, INFO)
            .expect("encapped key validated on-curve by from_bytes; P-256 DH cannot fail");
        let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - TAG_LEN);
        // Unreachable: the length guard above makes `tag` exactly TAG_LEN bytes.
        let tag = AeadTag::<AesGcm256>::from_bytes(tag).expect("tag slice is exactly TAG_LEN after the length guard");
        let mut buf = SecretBuf::concat(&[ct]);
        // On failure `buf` (partly decrypted garbage) is zeroed when dropped.
        ctx.open_inout_detached(buf.as_mut_slice().into(), aad, &tag).map_err(|_| ())?;
        Ok(buf)
    }
}

/// Client side, for the probe and tests: returns (enc, ciphertext || tag).
#[cfg_attr(not(test), allow(dead_code))]
pub fn seal(public: &[u8], password: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(public).map_err(|_| "invalid public key")?;
    // Unreachable: setup/seal with a valid public key (checked above) and AES-256-GCM cannot fail. hpke draws the
    // ephemeral key from its own getrandom-backed RNG.
    let (enc, mut ctx) = hpke::setup_sender::<AesGcm256, HkdfSha256, Kem>(&OpModeS::Base, &pk, INFO)
        .expect("sender setup with a valid public key cannot fail");
    let mut out = password.to_vec();
    let tag = ctx.seal_inout_detached((&mut out[..]).into(), aad).expect("AES-256-GCM seal cannot fail");
    out.extend_from_slice(&tag.to_bytes());
    Ok((enc.to_bytes().to_vec(), out))
}

/// A new password key pair: (private scalar, public point).
pub fn generate() -> (Vec<u8>, Vec<u8>) {
    let (sk, pk) = Kem::gen_keypair();
    (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
}

#[cfg(test)]
#[path = "tests/unit_seal.rs"]
mod tests;
