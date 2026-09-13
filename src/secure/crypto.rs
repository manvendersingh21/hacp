//! Pure, guardian-private primitives. No filesystem, clock, global state or secret export.
use super::{
    envelope::{decode_hex, encode_hex, SecureEnvelope},
    SecureError,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct IdentitySecret {
    seed: [u8; 32],
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct EphemeralSecret {
    scalar: [u8; 32],
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub(super) struct SessionKeys {
    i2r: [u8; 32],
    r2i: [u8; 32],
}

impl IdentitySecret {
    pub(super) fn from_seed(seed: Zeroizing<[u8; 32]>) -> Self {
        Self { seed: *seed }
    }
    pub(super) fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self, SecureError> {
        let mut seed = Zeroizing::new([0; 32]);
        rng.try_fill_bytes(&mut *seed)
            .map_err(|_| SecureError::GuardianUnavailable)?;
        Ok(Self::from_seed(seed))
    }
    pub(super) fn public_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.seed)
            .verifying_key()
            .to_bytes()
    }
    // Private even within the guardian module tree: callers can sign only typed envelopes.
    fn sign(&self, input: &[u8]) -> String {
        encode_hex(&SigningKey::from_bytes(&self.seed).sign(input).to_bytes())
    }
    pub(super) fn sign_hello(
        &self,
        env: &SecureEnvelope,
        context: &str,
    ) -> Result<String, SecureError> {
        Ok(self.sign(&env.hello_signing_input(context)?))
    }
    pub(super) fn sign_ack(
        &self,
        env: &SecureEnvelope,
        context: &str,
        hello: &SecureEnvelope,
    ) -> Result<String, SecureError> {
        Ok(self.sign(&env.ack_signing_input(context, hello)?))
    }
    pub(super) fn sign_message(&self, env: &SecureEnvelope) -> Result<String, SecureError> {
        Ok(self.sign(&env.message_signing_input()?))
    }
}
impl EphemeralSecret {
    pub(super) fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Result<Self, SecureError> {
        let mut scalar = Zeroizing::new([0; 32]);
        rng.try_fill_bytes(&mut *scalar)
            .map_err(|_| SecureError::GuardianUnavailable)?;
        Ok(Self { scalar: *scalar })
    }
    pub(super) fn public_key(&self) -> [u8; 32] {
        x25519_dalek::x25519(self.scalar, x25519_dalek::X25519_BASEPOINT_BYTES)
    }
    pub(super) fn establish(
        &self,
        peer: &[u8; 32],
        ni: &[u8; 32],
        nr: &[u8; 32],
        context: &str,
        initiator: &str,
        responder: &str,
    ) -> Result<(String, SessionKeys), SecureError> {
        let shared = Zeroizing::new(x25519_dalek::x25519(self.scalar, *peer));
        // RFC 7748 non-contributory inputs must not create predictable session keys.
        if shared.iter().fold(0u8, |a, b| a | b) == 0 {
            return Err(SecureError::BadHandshakeSignature);
        }
        schedule(&shared, ni, nr, context, initiator, responder)
    }
}
fn schedule(
    shared: &[u8; 32],
    ni: &[u8; 32],
    nr: &[u8; 32],
    context: &str,
    initiator: &str,
    responder: &str,
) -> Result<(String, SessionKeys), SecureError> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ni);
    salt[32..].copy_from_slice(nr);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let ctx = [
        b"HACP-SECURE/v1/session".as_slice(),
        context.as_bytes(),
        initiator.as_bytes(),
        responder.as_bytes(),
    ]
    .concat();
    let mut sid = [0; 16];
    let mut keys = SessionKeys {
        i2r: [0; 32],
        r2i: [0; 32],
    };
    for (label, out) in [
        (b"sid".as_slice(), sid.as_mut_slice()),
        (b"k_i2r".as_slice(), keys.i2r.as_mut_slice()),
        (b"k_r2i".as_slice(), keys.r2i.as_mut_slice()),
    ] {
        hk.expand(&[ctx.as_slice(), label].concat(), out)
            .map_err(|_| SecureError::GuardianUnavailable)?;
    }
    Ok((encode_hex(&sid), keys))
}
pub(super) fn random_nonce(rng: &mut (impl RngCore + CryptoRng)) -> Result<[u8; 32], SecureError> {
    let mut n = [0; 32];
    rng.try_fill_bytes(&mut n)
        .map_err(|_| SecureError::GuardianUnavailable)?;
    Ok(n)
}
pub(super) fn bytes32(hex: &str) -> Result<[u8; 32], SecureError> {
    decode_hex(hex)?
        .try_into()
        .map_err(|_| SecureError::SchemaViolation)
}
pub(super) fn verify(pk: &[u8; 32], input: &[u8], sig: &str) -> bool {
    let Ok(pk) = VerifyingKey::from_bytes(pk) else {
        return false;
    };
    let Ok(bytes) = decode_hex(sig) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&bytes) else {
        return false;
    };
    pk.verify_strict(input, &sig).is_ok()
}
pub(super) fn nonce96(seq: u64) -> [u8; 12] {
    let mut n = [0; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}
impl SessionKeys {
    pub(super) fn seal(
        &self,
        initiator: bool,
        seq: u64,
        aad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>, SecureError> {
        let key = if initiator { &self.i2r } else { &self.r2i };
        ChaCha20Poly1305::new(key.into())
            .encrypt(Nonce::from_slice(&nonce96(seq)), Payload { msg: pt, aad })
            .map_err(|_| SecureError::GuardianUnavailable)
    }
    pub(super) fn open(
        &self,
        initiator: bool,
        seq: u64,
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, SecureError> {
        let key = if initiator { &self.r2i } else { &self.i2r };
        ChaCha20Poly1305::new(key.into())
            .decrypt(Nonce::from_slice(&nonce96(seq)), Payload { msg: ct, aad })
            .map_err(|_| SecureError::TamperDetected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::{assert_impl_all, assert_not_impl_any};
    assert_impl_all!(IdentitySecret: Zeroize, ZeroizeOnDrop);
    assert_impl_all!(EphemeralSecret: Zeroize, ZeroizeOnDrop);
    assert_impl_all!(SessionKeys: Zeroize, ZeroizeOnDrop);
    assert_not_impl_any!(IdentitySecret: std::fmt::Debug, std::fmt::Display, Clone, serde::Serialize);
    assert_not_impl_any!(EphemeralSecret: std::fmt::Debug, std::fmt::Display, Clone, serde::Serialize);
    assert_not_impl_any!(SessionKeys: std::fmt::Debug, std::fmt::Display, Clone, serde::Serialize);
    #[test]
    fn rfc7748_x25519_and_noncontributory_rejection() {
        let a = EphemeralSecret {
            scalar: bytes32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap(),
        };
        let b =
            bytes32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f").unwrap();
        assert_eq!(
            encode_hex(&a.public_key()),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(
            encode_hex(&x25519_dalek::x25519(a.scalar, b)),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
        assert!(matches!(
            a.establish(
                &[0; 32],
                &[1; 32],
                &[2; 32],
                "s-test",
                "urn:hacp:agent:a",
                "urn:hacp:agent:b"
            ),
            Err(SecureError::BadHandshakeSignature)
        ));
    }
    #[test]
    fn rfc5869_hkdf_sha256() {
        let hk = Hkdf::<Sha256>::new(
            Some(&decode_hex("000102030405060708090a0b0c").unwrap()),
            &[0x0b; 22],
        );
        let mut out = [0; 42];
        hk.expand(&decode_hex("f0f1f2f3f4f5f6f7f8f9").unwrap(), &mut out)
            .unwrap();
        assert_eq!(
            encode_hex(&out),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }
    #[test]
    fn rfc8032_ed25519() {
        let identity = IdentitySecret::from_seed(Zeroizing::new(
            bytes32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap(),
        ));
        // RFC's empty-message test exercises the private primitive; no raw signing endpoint exists.
        let sig = identity.sign(b"");
        assert_eq!(
            encode_hex(&identity.public_key()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(sig,"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        assert!(verify(&identity.public_key(), b"", &sig));
        assert!(!verify(&identity.public_key(), b"different", &sig));
    }
    #[test]
    fn rfc8439_chacha20poly1305() {
        let key =
            bytes32("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
        let nonce = decode_hex("070000004041424344454647").unwrap();
        let aad = decode_hex("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt=b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let cipher = ChaCha20Poly1305::new((&key).into());
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: pt, aad: &aad })
            .unwrap();
        assert_eq!(encode_hex(&ct),"d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691");
        assert_eq!(
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ct,
                        aad: &aad
                    }
                )
                .unwrap(),
            pt
        );
    }
    #[test]
    fn nonce_layout_and_directional_separation() {
        for (seq, hex) in [
            (1, "000000000000000000000001"),
            (1u64 << 32, "000000000000000100000000"),
            (u64::MAX - 1, "00000000fffffffffffffffe"),
        ] {
            assert_eq!(encode_hex(&nonce96(seq)), hex);
        }
        let (_, keys) = schedule(
            &[3; 32],
            &[1; 32],
            &[2; 32],
            "s-test",
            "urn:hacp:agent:a",
            "urn:hacp:agent:b",
        )
        .unwrap();
        assert_ne!(keys.i2r, keys.r2i);
        let ct = keys.seal(true, 0, b"aad", b"payload").unwrap();
        assert_eq!(keys.open(false, 0, b"aad", &ct).unwrap(), b"payload");
        assert_eq!(
            keys.open(true, 0, b"aad", &ct),
            Err(SecureError::TamperDetected)
        );
    }
    #[test]
    fn independent_python_golden_envelope() {
        // Independently computed with Python cryptography (OpenSSL), public test seeds only.
        let v:serde_json::Value=serde_json::from_str(r#"{"hello":{"v":1,"kind":"hello","from":"urn:hacp:agent:a","to":"urn:hacp:agent:b","contract":"","epub":"5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22","nonce":"0505050505050505050505050505050505050505050505050505050505050505","sig":"277a5d6bea0fd256f2beb24bb8ffeae59df9bfe65389c5ff64a2c6abc66aeed2a49460d7cea0dcc939957ddb030c11463c64fd1a837697fe6b0a03af43a30200"},"ack":{"v":1,"kind":"ack","from":"urn:hacp:agent:b","to":"urn:hacp:agent:a","contract":"","sid":"90a4477ca226f4f1c9091dbd19ff8134","epub":"ac01b2209e86354fb853237b5de0f4fab13c7fcbf433a61c019369617fecf10b","nonce":"0606060606060606060606060606060606060606060606060606060606060606","sig":"fa6a01b38f8cba7d2c8e3b881463538db65d9596dda810af0b9050ce88b552e17f3dda8e3440cc9e91eb3f06c4d4d47a4fe0b3074b6a640ee67d0e7827ba2d0f"},"msg":{"v":1,"kind":"msg","from":"urn:hacp:agent:a","to":"urn:hacp:agent:b","contract":"","sid":"90a4477ca226f4f1c9091dbd19ff8134","seq":0,"ct":"7b554e86e93fe3cf170e302141f2a664e790f33e3cce2ea81f3b0556ad74","sig":"9079a0f956d617c860f8e281f286b3df14636eb59397195891ce1ae91565d99adcb8bf250eaf7f92bd8b5095f2192febb09a6323a252e327078ab52e0b7d5f08"},"aad":"{\"contract\":\"\",\"from\":\"urn:hacp:agent:a\",\"kind\":\"msg\",\"seq\":0,\"sid\":\"90a4477ca226f4f1c9091dbd19ff8134\",\"to\":\"urn:hacp:agent:b\",\"v\":1}","sid":"90a4477ca226f4f1c9091dbd19ff8134","k_i2r":"29e2b396b9e49e1820c2d2c36081a2575ac5e2c339cd4adb707fbc5751de0d07","k_r2i":"ca19177a442be76e77154f56207e9197e6530c89641ddfe843f951170aa6a3e9"}"#).unwrap();
        let a = IdentitySecret::from_seed(Zeroizing::new([1; 32]));
        let b = IdentitySecret::from_seed(Zeroizing::new([2; 32]));
        let ea = EphemeralSecret { scalar: [3; 32] };
        let eb = EphemeralSecret { scalar: [4; 32] };
        let (sid, keys) = ea
            .establish(
                &eb.public_key(),
                &[5; 32],
                &[6; 32],
                "s-golden",
                "urn:hacp:agent:a",
                "urn:hacp:agent:b",
            )
            .unwrap();
        assert_eq!(sid, v["sid"].as_str().unwrap());
        assert_eq!(encode_hex(&keys.i2r), v["k_i2r"].as_str().unwrap());
        assert_eq!(encode_hex(&keys.r2i), v["k_r2i"].as_str().unwrap());
        let hello: SecureEnvelope = serde_json::from_value(v["hello"].clone()).unwrap();
        let ack: SecureEnvelope = serde_json::from_value(v["ack"].clone()).unwrap();
        let msg: SecureEnvelope = serde_json::from_value(v["msg"].clone()).unwrap();
        assert_eq!(
            a.sign_hello(&hello, "s-golden").unwrap(),
            hello.sig.clone().unwrap()
        );
        assert_eq!(
            b.sign_ack(&ack, "s-golden", &hello).unwrap(),
            ack.sig.clone().unwrap()
        );
        assert_eq!(
            String::from_utf8(msg.aad_bytes().unwrap()).unwrap(),
            v["aad"].as_str().unwrap()
        );
        assert_eq!(
            encode_hex(
                &keys
                    .seal(true, 0, &msg.aad_bytes().unwrap(), b"golden payload")
                    .unwrap()
            ),
            msg.ct.clone().unwrap()
        );
        assert_eq!(a.sign_message(&msg).unwrap(), msg.sig.clone().unwrap());
        assert!(!verify(
            &a.public_key(),
            &hello.hello_signing_input("s-golden").unwrap(),
            msg.sig.as_ref().unwrap()
        ));
        assert!(!verify(
            &a.public_key(),
            &msg.message_signing_input().unwrap(),
            hello.sig.as_ref().unwrap()
        ));
        assert!(!verify(
            &b.public_key(),
            &hello.hello_signing_input("s-golden").unwrap(),
            ack.sig.as_ref().unwrap()
        ));
    }
}
