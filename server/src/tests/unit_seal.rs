//! HPKE sealing: round trips, AAD binding, tampering, sizes, keys, and a published known-answer vector.
//! Self-contained (no shared test helpers): this module is also compiled into the probe.

use super::*;

const PW: &[u8] = b"correct horse battery staple";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn pair() -> (PasswordKey, Vec<u8>) {
    let (sk, pk) = generate();
    (PasswordKey::from_scalar("k1".into(), &sk).unwrap(), pk)
}

fn a() -> Vec<u8> {
    aad("k1", "alice", "logon", 1_700_000_000, "cmlkcmlkcmlkcmlkcmlkcg==")
}

#[test]
fn aad_exact_bytes() {
    assert_eq!(aad("k1", "alice", "unlock", 42, "UklE"), b"WELDAP-auth-v1\nk1\nalice\nunlock\n42\nUklE".to_vec());
}

#[test]
fn aad_fields_are_separated() {
    // Moving a character across a field boundary changes the AAD.
    assert_ne!(aad("k1", "ab", "logon", 1, "r"), aad("k1a", "b", "logon", 1, "r"));
    assert_ne!(aad("k", "x", "logon", 11, "r"), aad("k", "x", "logon", 1, "1r"));
}

#[test]
fn round_trip() {
    let (key, pk) = pair();
    assert_eq!(key.public_bytes(), pk);
    let (enc, ct) = seal(&pk, PW, &a()).unwrap();
    assert_eq!(enc.len(), ENC_LEN);
    assert_eq!(ct.len(), PW.len() + TAG_LEN);
    assert_eq!(key.open(&enc, &ct, &a()).unwrap().as_slice(), PW);
}

#[test]
fn round_trip_lengths() {
    let (key, pk) = pair();
    for len in [0, 1, 2, 15, 16, 17, 64, 255, MAX_PASSWORD_BYTES] {
        let pw: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
        let (enc, ct) = seal(&pk, &pw, &a()).unwrap();
        assert_eq!(key.open(&enc, &ct, &a()).unwrap().as_slice(), pw.as_slice(), "len {len}");
    }
}

#[test]
fn oversize_refused() {
    let (key, pk) = pair();
    let (enc, ct) = seal(&pk, &[b'x'; MAX_PASSWORD_BYTES + 1], &a()).unwrap();
    assert!(key.open(&enc, &ct, &a()).is_err());
}

#[test]
fn empty_aad_round_trip_and_binding() {
    let (key, pk) = pair();
    let (enc, ct) = seal(&pk, PW, b"").unwrap();
    assert!(key.open(&enc, &ct, b"").is_ok());
    assert!(key.open(&enc, &ct, &a()).is_err());
}

#[test]
fn every_aad_field_binds() {
    let (key, pk) = pair();
    let (enc, ct) = seal(&pk, PW, &a()).unwrap();
    for other in [
        aad("k2", "alice", "logon", 1_700_000_000, "cmlkcmlkcmlkcmlkcmlkcg=="),
        aad("k1", "bob", "logon", 1_700_000_000, "cmlkcmlkcmlkcmlkcmlkcg=="),
        aad("k1", "alice", "unlock", 1_700_000_000, "cmlkcmlkcmlkcmlkcmlkcg=="),
        aad("k1", "alice", "logon", 1_700_000_001, "cmlkcmlkcmlkcmlkcmlkcg=="),
        aad("k1", "alice", "logon", 1_700_000_000, "cmlkcmlkcmlkcmlkcmlkcw=="),
    ] {
        assert!(key.open(&enc, &ct, &other).is_err());
    }
    let mut extended = a();
    extended.push(b'\n');
    assert!(key.open(&enc, &ct, &extended).is_err());
    assert!(key.open(&enc, &ct, &a()[..a().len() - 1]).is_err());
}

#[test]
fn every_bit_of_ciphertext_and_tag() {
    let (key, pk) = pair();
    let (enc, ct) = seal(&pk, PW, &a()).unwrap();
    for bit in 0..ct.len() * 8 {
        let mut bad = ct.clone();
        bad[bit / 8] ^= 1 << (bit % 8);
        assert!(key.open(&enc, &bad, &a()).is_err(), "bit {bit}");
    }
}

#[test]
fn every_bit_of_enc() {
    let (key, pk) = pair();
    let (enc, ct) = seal(&pk, PW, &a()).unwrap();
    for bit in 0..enc.len() * 8 {
        let mut bad = enc.clone();
        bad[bit / 8] ^= 1 << (bit % 8);
        assert!(key.open(&bad, &ct, &a()).is_err(), "bit {bit}");
    }
}

#[test]
fn every_bit_of_aad() {
    let (key, pk) = pair();
    let (enc, ct) = seal(&pk, PW, &a()).unwrap();
    for bit in 0..a().len() * 8 {
        let mut bad = a();
        bad[bit / 8] ^= 1 << (bit % 8);
        assert!(key.open(&enc, &ct, &bad).is_err(), "bit {bit}");
    }
}

#[test]
fn truncations_refused() {
    let (key, pk) = pair();
    let (enc, ct) = seal(&pk, PW, &a()).unwrap();
    for n in 0..ct.len() {
        assert!(key.open(&enc, &ct[..n], &a()).is_err(), "ct[..{n}]");
        assert!(key.open(&enc, &ct[ct.len() - n..], &a()).is_err(), "ct[-{n}..]");
    }
    for n in 0..enc.len() {
        assert!(key.open(&enc[..n], &ct, &a()).is_err(), "enc[..{n}]");
    }
    let mut longer = ct.clone();
    longer.push(0);
    assert!(key.open(&enc, &longer, &a()).is_err());
    let mut enc66 = enc.clone();
    enc66.push(0);
    assert!(key.open(&enc66, &ct, &a()).is_err());
}

#[test]
fn tag_only_is_empty_password_not_garbage() {
    // Exactly a tag: the empty plaintext (the server then answers "invalid" without the directory).
    let (key, pk) = pair();
    let (enc, ct) = seal(&pk, b"", &a()).unwrap();
    assert_eq!(ct.len(), TAG_LEN);
    assert!(key.open(&enc, &ct, &a()).unwrap().is_empty());
    assert!(key.open(&enc, &[0u8; TAG_LEN], &a()).is_err());
}

#[test]
fn wrong_key_refused() {
    let (_, pk) = pair();
    let (other, _) = pair();
    let (enc, ct) = seal(&pk, PW, &a()).unwrap();
    assert!(other.open(&enc, &ct, &a()).is_err());
}

#[test]
fn invalid_points_refused() {
    let (key, pk) = pair();
    let (_, ct) = seal(&pk, PW, &a()).unwrap();
    let mut not_on_curve = vec![0x04];
    not_on_curve.extend([0x11; 64]);
    let mut compressed_tag = pk.clone();
    compressed_tag[0] = 0x02;
    for enc in [vec![0u8; ENC_LEN], not_on_curve, compressed_tag, vec![0xff; ENC_LEN]] {
        assert!(key.open(&enc, &ct, &a()).is_err());
    }
}

#[test]
fn reusing_enc_with_other_ciphertext_refused() {
    let (key, pk) = pair();
    let (enc1, _) = seal(&pk, PW, &a()).unwrap();
    let (_, ct2) = seal(&pk, PW, &a()).unwrap();
    assert!(key.open(&enc1, &ct2, &a()).is_err());
}

#[test]
fn sealing_is_randomised() {
    let (_, pk) = pair();
    let (e1, c1) = seal(&pk, PW, &a()).unwrap();
    let (e2, c2) = seal(&pk, PW, &a()).unwrap();
    assert_ne!(e1, e2);
    assert_ne!(c1, c2);
}

#[test]
fn seal_refuses_bad_public_key() {
    assert!(seal(&[], PW, b"").is_err());
    assert!(seal(&[0x04; ENC_LEN], PW, b"").is_err());
    let (sk, _) = generate();
    assert!(seal(&sk, PW, b"").is_err(), "a scalar is not a point");
}

#[test]
fn private_key_validation() {
    let n_minus_1 = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550");
    let n = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    assert!(PasswordKey::from_scalar("k".into(), &n_minus_1).is_ok());
    for bad in [vec![], vec![1u8; 31], vec![1u8; 33], vec![0u8; 32], n, vec![0xff; 32]] {
        assert!(PasswordKey::from_scalar("k".into(), &bad).is_err(), "{bad:02x?}");
    }
}

#[test]
fn generated_keys() {
    let (sk1, pk1) = generate();
    let (sk2, pk2) = generate();
    assert_eq!((sk1.len(), pk1.len()), (32, ENC_LEN));
    assert_eq!(pk1[0], 0x04, "uncompressed point");
    assert_ne!(sk1, sk2);
    assert_ne!(pk1, pk2);
    let key = PasswordKey::from_scalar("kid".into(), &sk1).unwrap();
    assert_eq!(key.kid, "kid");
    assert_eq!(key.public_bytes(), pk1);
}

// CFRG HPKE test vectors (test-vectors.json of draft-irtf-cfrg-hpke, the vectors published with RFC 9180):
// mode_base, DHKEM(P-256, HKDF-SHA256) 0x0010, HKDF-SHA256 0x0001, AES-256-GCM 0x0002 — exactly our suite.
// (RFC 9180 A.3.1 prints the AES-128-GCM variant; same KEM and KDF.)
const KAT_SKR: &str = "317f915db7bc629c48fe765587897e01e282d3e8445f79f27f65d031a88082b2";
const KAT_PKR: &str = "04abc7e49a4c6b3566d77d0304addc6ed0e98512ffccf505e6a8e3eb25c685136f853148544876de76c0f2ef99cdc3a05ccf5ded7860c7c021238f9e2073d2356c";
const KAT_ENC: &str = "04c06b4f6bebc7bb495cb797ab753f911aff80aefb86fd8b6fcc35525f3ab5f03e0b21bd31a86c6048af3cb2d98e0d3bf01da5cc4c39ff5370d331a4f1f7d5a4e0";
const KAT_INFO: &str = "4f6465206f6e2061204772656369616e2055726e";
const KAT_AAD0: &str = "436f756e742d30";
const KAT_CT0: &str = "58c61a45059d0c5704560e9d88b564a8b63f1364b8d1fcb3c4c6ddc1d291742465e902cd216f8908da49f8f96f";
const KAT_AAD1: &str = "436f756e742d31";
const KAT_CT1: &str = "b4e7c90d1dd62cb563694956eb517ab55d5e7d1f6366a0066c04ababaa444dbaf60a30d7bb7d3e91b969762dee";
const KAT_PT: &str = "4265617574792069732074727574682c20747275746820626561757479";

fn kat_open(key: &PasswordKey, info: &[u8], aad: &str, ct: &str) -> Result<Vec<u8>, hpke::HpkeError> {
    let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(&hex(KAT_ENC)).unwrap();
    let mut ctx = hpke::setup_receiver::<AesGcm256, HkdfSha256, Kem>(&OpModeR::Base, &key.sk, &encapped, info)?;
    ctx.open(&hex(ct), &hex(aad))
}

#[test]
fn kat_public_key_derivation() {
    let key = PasswordKey::from_scalar("kat".into(), &hex(KAT_SKR)).unwrap();
    assert_eq!(key.public_bytes(), hex(KAT_PKR));
}

#[test]
fn kat_open_first_message() {
    let key = PasswordKey::from_scalar("kat".into(), &hex(KAT_SKR)).unwrap();
    assert_eq!(kat_open(&key, &hex(KAT_INFO), KAT_AAD0, KAT_CT0).unwrap(), hex(KAT_PT));
}

#[test]
fn kat_second_message_needs_sequence_one() {
    // A fresh receiver context is at sequence 0; the vector's second ciphertext used nonce ^ 1.
    let key = PasswordKey::from_scalar("kat".into(), &hex(KAT_SKR)).unwrap();
    assert!(kat_open(&key, &hex(KAT_INFO), KAT_AAD1, KAT_CT1).is_err());
    let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(&hex(KAT_ENC)).unwrap();
    let mut ctx =
        hpke::setup_receiver::<AesGcm256, HkdfSha256, Kem>(&OpModeR::Base, &key.sk, &encapped, &hex(KAT_INFO)).unwrap();
    assert_eq!(ctx.open(&hex(KAT_CT0), &hex(KAT_AAD0)).unwrap(), hex(KAT_PT));
    assert_eq!(ctx.open(&hex(KAT_CT1), &hex(KAT_AAD1)).unwrap(), hex(KAT_PT));
}

#[test]
fn kat_info_is_bound() {
    // Our `open` uses INFO ("WELDAP password v1"): the vector's ciphertext does not open there.
    let key = PasswordKey::from_scalar("kat".into(), &hex(KAT_SKR)).unwrap();
    assert!(kat_open(&key, INFO, KAT_AAD0, KAT_CT0).is_err());
    assert!(key.open(&hex(KAT_ENC), &hex(KAT_CT0), &hex(KAT_AAD0)).is_err());
}

#[test]
fn kat_tampering_refused() {
    let key = PasswordKey::from_scalar("kat".into(), &hex(KAT_SKR)).unwrap();
    assert!(kat_open(&key, &hex(KAT_INFO), KAT_AAD1, KAT_CT0).is_err());
    let mut ct = hex(KAT_CT0);
    ct[0] ^= 1;
    let encapped = <Kem as hpke::Kem>::EncappedKey::from_bytes(&hex(KAT_ENC)).unwrap();
    let mut ctx =
        hpke::setup_receiver::<AesGcm256, HkdfSha256, Kem>(&OpModeR::Base, &key.sk, &encapped, &hex(KAT_INFO)).unwrap();
    assert!(ctx.open(&ct, &hex(KAT_AAD0)).is_err());
}
