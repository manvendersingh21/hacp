//! Guardian-held identity and ephemeral session lifecycle. Replay/delivery belongs to transport.
//!
//! This opaque object cannot serialize, print, clone or export its key material.
//! The per-sequence cryptographic operations are crate-private; agent requests go
//! through the guardian and transport transaction, never through this API.
use super::{
    crypto::{self, EphemeralSecret, IdentitySecret, SessionKeys},
    envelope::{decode_hex, encode_hex, Kind, SecureEnvelope},
    SecureError,
};
use rand_core::OsRng;
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Debug, serde::Serialize)]
pub struct SessionInfo {
    pub sid: String,
    pub peer: String,
    pub local: String,
    pub hacp_session: String,
    pub state: String,
    pub send_seq: u64,
}
struct Pending {
    hello: SecureEnvelope,
    hacp_session: String,
    pin: [u8; 32],
    ephemeral: EphemeralSecret,
    order: u64,
}
struct Session {
    info: SessionInfo,
    keys: SessionKeys,
    pin: [u8; 32],
    initiator: bool,
    order: u64,
    // Only public handshake data survives establishment; ephemeral scalars do not.
    hello: SecureEnvelope,
    ack: SecureEnvelope,
}
pub struct SessionManager {
    local: String,
    identity: IdentitySecret,
    pending: VecDeque<Pending>,
    active: BTreeMap<String, Session>,
    order: u64,
}
pub(super) fn valid_urn(urn: &str) -> bool {
    let Some(s) = urn.strip_prefix("urn:hacp:agent:") else {
        return false;
    };
    !s.is_empty()
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn context_ok(s: &str) -> Result<(), SecureError> {
    if s.is_empty() {
        Err(SecureError::SchemaViolation)
    } else {
        Ok(())
    }
}
fn handshake(kind: Kind, from: &str, to: &str, epub: [u8; 32], nonce: [u8; 32]) -> SecureEnvelope {
    SecureEnvelope {
        v: 1,
        kind,
        from: from.into(),
        to: to.into(),
        contract: String::new(),
        sid: None,
        seq: None,
        epub: Some(encode_hex(&epub)),
        nonce: Some(encode_hex(&nonce)),
        sig: None,
        ct: None,
        ts: None,
    }
}
fn required(v: &Option<String>) -> Result<&str, SecureError> {
    v.as_deref().ok_or(SecureError::SchemaViolation)
}
impl SessionManager {
    pub fn new(local: &str) -> Result<Self, SecureError> {
        Self::with_identity(local, IdentitySecret::generate(&mut OsRng)?)
    }
    pub(super) fn with_identity(
        local: &str,
        identity: IdentitySecret,
    ) -> Result<Self, SecureError> {
        if !valid_urn(local) {
            return Err(SecureError::SchemaViolation);
        }
        Ok(Self {
            local: local.into(),
            identity,
            pending: VecDeque::new(),
            active: BTreeMap::new(),
            order: 0,
        })
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.identity.public_key()
    }
    fn next_order(&mut self) -> Result<u64, SecureError> {
        self.order = self
            .order
            .checked_add(1)
            .ok_or(SecureError::SessionExhausted)?;
        Ok(self.order)
    }
    fn bound_pending(&mut self, peer: &str) {
        loop {
            let count = self.pending.iter().filter(|p| p.hello.to == peer).count()
                + self
                    .active
                    .values()
                    .filter(|s| s.info.peer == peer && s.info.state == "AckSent")
                    .count();
            if count < 4 {
                break;
            }
            let pending = self
                .pending
                .iter()
                .enumerate()
                .filter(|(_, p)| p.hello.to == peer)
                .min_by_key(|(_, p)| p.order)
                .map(|(i, p)| (i, p.order));
            let active = self
                .active
                .iter()
                .filter(|(_, s)| s.info.peer == peer && s.info.state == "AckSent")
                .min_by_key(|(_, s)| s.order)
                .map(|(sid, s)| (sid.clone(), s.order));
            match (pending, active) {
                (Some((i, a)), Some((sid, b))) => {
                    if a < b {
                        self.pending.remove(i);
                    } else {
                        self.active.remove(&sid);
                    }
                }
                (Some((i, _)), None) => {
                    self.pending.remove(i);
                }
                (None, Some((sid, _))) => {
                    self.active.remove(&sid);
                }
                _ => break,
            }
        }
    }
    pub fn initiate(
        &mut self,
        peer: &str,
        hacp_session: &str,
        pin: &[u8; 32],
    ) -> Result<SecureEnvelope, SecureError> {
        context_ok(hacp_session)?;
        if !valid_urn(peer) || peer == self.local {
            return Err(SecureError::IdentityMismatch);
        }
        let ephemeral = EphemeralSecret::generate(&mut OsRng)?;
        let mut hello = handshake(
            Kind::Hello,
            &self.local,
            peer,
            ephemeral.public_key(),
            crypto::random_nonce(&mut OsRng)?,
        );
        hello.sig = Some(self.identity.sign_hello(&hello, hacp_session)?);
        hello.validate()?;
        let order = self.next_order()?;
        self.bound_pending(peer);
        self.pending.push_back(Pending {
            hello: hello.clone(),
            hacp_session: hacp_session.into(),
            pin: *pin,
            ephemeral,
            order,
        });
        Ok(hello)
    }
    pub fn respond(
        &mut self,
        hacp_session: &str,
        hello: &SecureEnvelope,
        pin: &[u8; 32],
    ) -> Result<SecureEnvelope, SecureError> {
        hello.validate()?;
        context_ok(hacp_session)?;
        if hello.kind != Kind::Hello {
            return Err(SecureError::SchemaViolation);
        }
        if hello.to != self.local || hello.from == self.local {
            return Err(SecureError::IdentityMismatch);
        }
        let transcript = hello.hello_signing_input(hacp_session)?;
        if !crypto::verify(pin, &transcript, required(&hello.sig)?) {
            return Err(SecureError::BadHandshakeSignature);
        }
        // Exact authenticated hello retransmission reuses its public ack, never its DH scalar.
        if let Some(s) = self.active.values().find(|s| {
            !s.initiator
                && s.info.hacp_session == hacp_session
                && s.pin == *pin
                && s.hello.sig == hello.sig
                && s.hello.from == hello.from
        }) {
            return Ok(s.ack.clone());
        }
        let ephemeral = EphemeralSecret::generate(&mut OsRng)?;
        let nr = crypto::random_nonce(&mut OsRng)?;
        let (sid, keys) = ephemeral.establish(
            &crypto::bytes32(required(&hello.epub)?)?,
            &crypto::bytes32(required(&hello.nonce)?)?,
            &nr,
            hacp_session,
            &hello.from,
            &self.local,
        )?;
        let mut ack = handshake(
            Kind::Ack,
            &self.local,
            &hello.from,
            ephemeral.public_key(),
            nr,
        );
        ack.sid = Some(sid.clone());
        ack.sig = Some(self.identity.sign_ack(&ack, hacp_session, hello)?);
        ack.validate()?;
        let order = self.next_order()?;
        self.bound_pending(&hello.from);
        self.active.insert(
            sid.clone(),
            Session {
                info: SessionInfo {
                    sid,
                    peer: hello.from.clone(),
                    local: self.local.clone(),
                    hacp_session: hacp_session.into(),
                    state: "AckSent".into(),
                    send_seq: 0,
                },
                keys,
                pin: *pin,
                initiator: false,
                order,
                hello: hello.clone(),
                ack: ack.clone(),
            },
        );
        Ok(ack)
    }
    pub fn complete(
        &mut self,
        hacp_session: &str,
        ack: &SecureEnvelope,
    ) -> Result<String, SecureError> {
        ack.validate()?;
        context_ok(hacp_session)?;
        if ack.kind != Kind::Ack {
            return Err(SecureError::SchemaViolation);
        }
        if ack.to != self.local || ack.from == self.local {
            return Err(SecureError::IdentityMismatch);
        }
        let sid = required(&ack.sid)?;
        if let Some(s) = self.active.get(sid) {
            if s.initiator && s.info.hacp_session == hacp_session && s.ack == *ack {
                return Ok(sid.into());
            }
        }
        // Ack has no hello identifier. Try only the bounded pending set for this route/context.
        let mut selected = None;
        for (i, p) in self
            .pending
            .iter()
            .enumerate()
            .filter(|(_, p)| p.hello.to == ack.from && p.hacp_session == hacp_session)
        {
            if crypto::verify(
                &p.pin,
                &ack.ack_signing_input(hacp_session, &p.hello)?,
                required(&ack.sig)?,
            ) {
                selected = Some(i);
                break;
            }
        }
        let Some(i) = selected else {
            return Err(SecureError::BadHandshakeSignature);
        };
        let p = &self.pending[i];
        let (derived, keys) = p.ephemeral.establish(
            &crypto::bytes32(required(&ack.epub)?)?,
            &crypto::bytes32(required(&p.hello.nonce)?)?,
            &crypto::bytes32(required(&ack.nonce)?)?,
            hacp_session,
            &self.local,
            &ack.from,
        )?;
        if derived != sid {
            return Err(SecureError::BadHandshakeSignature);
        }
        let p = self.pending.remove(i).ok_or(SecureError::SessionUnknown)?;
        self.active.insert(
            derived.clone(),
            Session {
                info: SessionInfo {
                    sid: derived.clone(),
                    peer: ack.from.clone(),
                    local: self.local.clone(),
                    hacp_session: hacp_session.into(),
                    state: "Established".into(),
                    send_seq: 0,
                },
                keys,
                pin: p.pin,
                initiator: true,
                order: p.order,
                hello: p.hello,
                ack: ack.clone(),
            },
        );
        Ok(derived)
    }
    pub fn info(&self, sid: &str) -> Result<SessionInfo, SecureError> {
        self.active
            .get(sid)
            .map(|s| s.info.clone())
            .ok_or(SecureError::SessionUnknown)
    }
    pub fn sessions(&self) -> Vec<SessionInfo> {
        self.active.values().map(|s| s.info.clone()).collect()
    }
    pub(crate) fn seal(
        &mut self,
        sid: &str,
        seq: u64,
        contract: &str,
        payload: &[u8],
    ) -> Result<SecureEnvelope, SecureError> {
        let s = self.active.get(sid).ok_or(SecureError::SessionUnknown)?;
        if seq == u64::MAX || s.info.send_seq == u64::MAX {
            self.active.remove(sid);
            return Err(SecureError::SessionExhausted);
        }
        if seq != s.info.send_seq {
            return Err(SecureError::ReplayRejected);
        }
        let mut env = SecureEnvelope {
            v: 1,
            kind: Kind::Msg,
            from: self.local.clone(),
            to: s.info.peer.clone(),
            contract: contract.into(),
            sid: Some(sid.into()),
            seq: Some(seq),
            epub: None,
            nonce: None,
            sig: None,
            ct: None,
            ts: None,
        };
        let aad = env.aad_bytes()?;
        let ct = s.keys.seal(s.initiator, seq, &aad, payload)?;
        // Burn before any later fallible work: ciphertext generation spends this nonce.
        self.active
            .get_mut(sid)
            .ok_or(SecureError::SessionUnknown)?
            .info
            .send_seq += 1;
        env.ct = Some(encode_hex(&ct));
        let finish = (|| {
            env.sig = Some(self.identity.sign_message(&env)?);
            env.validate()?;
            Ok(env)
        })();
        if finish.is_err() {
            self.active.remove(sid);
        }
        finish
    }
    pub(crate) fn verify_message(&self, env: &SecureEnvelope) -> Result<(), SecureError> {
        env.validate()?;
        if env.kind != Kind::Msg {
            return Err(SecureError::SchemaViolation);
        }
        let s = self
            .active
            .get(required(&env.sid)?)
            .ok_or(SecureError::SessionUnknown)?;
        if env.from != s.info.peer || env.to != self.local {
            return Err(SecureError::IdentityMismatch);
        }
        if !crypto::verify(&s.pin, &env.message_signing_input()?, required(&env.sig)?) {
            return Err(SecureError::BadMessageSignature);
        }
        Ok(())
    }
    pub(crate) fn open_authenticated(
        &mut self,
        env: &SecureEnvelope,
    ) -> Result<Vec<u8>, SecureError> {
        self.verify_message(env)?;
        let sid = required(&env.sid)?;
        let seq = env.seq.ok_or(SecureError::SchemaViolation)?;
        if seq == u64::MAX {
            self.active.remove(sid);
            return Err(SecureError::SessionExhausted);
        }
        let s = self
            .active
            .get_mut(sid)
            .ok_or(SecureError::SessionUnknown)?;
        let pt = s.keys.open(
            s.initiator,
            seq,
            &env.aad_bytes()?,
            &decode_hex(required(&env.ct)?)?,
        )?;
        s.info.state = "Established".into();
        Ok(pt)
    }
    pub fn close(&mut self, sid: &str) -> Result<(), SecureError> {
        self.active
            .remove(sid)
            .map(|_| ())
            .ok_or(SecureError::SessionUnknown)
    }
    pub(super) fn close_context(&mut self, context: &str) {
        self.pending.retain(|p| p.hacp_session != context);
        self.active.retain(|_, s| s.info.hacp_session != context);
    }
}

#[cfg(test)]
mod tests {
    use super::super::transport::{ContractView, Transport};
    use super::*;
    use static_assertions::assert_not_impl_any;
    assert_not_impl_any!(SessionManager: std::fmt::Debug, std::fmt::Display, Clone, serde::Serialize);
    fn pair() -> (SessionManager, SessionManager, String) {
        let mut a = SessionManager::new("urn:hacp:agent:a").unwrap();
        let mut b = SessionManager::new("urn:hacp:agent:b").unwrap();
        let hello = a
            .initiate("urn:hacp:agent:b", "s-test", &b.public_key())
            .unwrap();
        let ack = b.respond("s-test", &hello, &a.public_key()).unwrap();
        let sid = a.complete("s-test", &ack).unwrap();
        (a, b, sid)
    }
    #[test]
    fn mutual_handshake_directions_and_close() {
        let (mut a, mut b, sid) = pair();
        assert_eq!(b.info(&sid).unwrap().state, "AckSent");
        let env = a.seal(&sid, 0, "", b"a to b").unwrap();
        assert_eq!(b.open_authenticated(&env).unwrap(), b"a to b");
        assert_eq!(b.info(&sid).unwrap().state, "Established");
        let env = b.seal(&sid, 0, "", b"b to a").unwrap();
        assert_eq!(a.open_authenticated(&env).unwrap(), b"b to a");
        b.close(&sid).unwrap();
        assert_eq!(b.verify_message(&env), Err(SecureError::SessionUnknown));
        let restarted = SessionManager::new("urn:hacp:agent:b").unwrap();
        assert!(matches!(
            restarted.info(&sid),
            Err(SecureError::SessionUnknown)
        ));
    }
    #[test]
    fn valid_signature_bad_tag_does_not_advance_transport_window() {
        let (mut a, mut b, sid) = pair();
        let mut ta = Transport::new();
        let mut tb = Transport::new();
        let good = ta
            .seal(
                &mut a,
                &sid,
                "",
                b"canary payload",
                &ContractView::Bootstrap,
            )
            .unwrap();
        let mut bad = good.clone();
        let mut ct = decode_hex(bad.ct.as_ref().unwrap()).unwrap();
        ct[0] ^= 1;
        bad.ct = Some(encode_hex(&ct));
        bad.sig = Some(a.identity.sign_message(&bad).unwrap());
        let report = tb.receive(&mut b, &bad, &ContractView::Bootstrap);
        assert_eq!(report.rejected, vec![SecureError::TamperDetected]);
        assert!(report.delivered.is_empty());
        assert_eq!(tb.status(&sid).recv_high, None);
        let report = tb.receive(&mut b, &good, &ContractView::Bootstrap);
        assert_eq!(report.delivered.len(), 1);
        assert_eq!(report.delivered[0].payload, b"canary payload");
        assert_eq!(tb.status(&sid).recv_high, Some(0));
    }
    #[test]
    fn handshake_tampering_context_pins_and_derived_sid() {
        let mut a = SessionManager::new("urn:hacp:agent:a").unwrap();
        let mut b = SessionManager::new("urn:hacp:agent:b").unwrap();
        let hello = a
            .initiate("urn:hacp:agent:b", "s-test", &b.public_key())
            .unwrap();
        assert!(matches!(
            b.respond("s-other", &hello, &a.public_key()),
            Err(SecureError::BadHandshakeSignature)
        ));
        assert!(matches!(
            b.respond("s-test", &hello, &b.public_key()),
            Err(SecureError::BadHandshakeSignature)
        ));
        assert!(b.sessions().is_empty());
        let ack = b.respond("s-test", &hello, &a.public_key()).unwrap();
        for field in ["epub", "nonce", "sid"] {
            let mut bad = ack.clone();
            match field {
                "epub" => bad.epub = Some("01".repeat(32)),
                "nonce" => bad.nonce = Some("02".repeat(32)),
                _ => bad.sid = Some("03".repeat(16)),
            };
            assert_eq!(
                a.complete("s-test", &bad),
                Err(SecureError::BadHandshakeSignature)
            );
        }
        let sid = a.complete("s-test", &ack).unwrap();
        assert_eq!(a.complete("s-test", &ack).unwrap(), sid);
        assert_eq!(b.respond("s-test", &hello, &a.public_key()).unwrap(), ack);
    }
    #[test]
    fn bounded_pending_and_ephemeral_lifetimes() {
        let mut a = SessionManager::new("urn:hacp:agent:a").unwrap();
        let mut b = SessionManager::new("urn:hacp:agent:b").unwrap();
        let mut hellos = Vec::new();
        let mut sids = Vec::new();
        for _ in 0..10 {
            let h = a
                .initiate("urn:hacp:agent:b", "s-test", &b.public_key())
                .unwrap();
            let ack = b.respond("s-test", &h, &a.public_key()).unwrap();
            sids.push(ack.sid.unwrap());
            hellos.push(h);
        }
        assert_eq!(a.pending.len(), 4);
        assert_eq!(b.sessions().len(), 4);
        assert!(b.info(&sids[0]).is_err());
        assert!(hellos
            .windows(2)
            .all(|h| h[0].epub != h[1].epub && h[0].nonce != h[1].nonce));
        let h = &hellos[9];
        for _ in 0..10 {
            b.respond("s-test", h, &a.public_key()).unwrap();
        }
        assert_eq!(b.sessions().len(), 4);
    }
    #[test]
    fn nonce_floor_exhaustion_and_authentication_order() {
        let (mut a, mut b, sid) = pair();
        let env = a.seal(&sid, 0, "", b"payload").unwrap();
        assert_eq!(
            a.seal(&sid, 0, "", b"reuse"),
            Err(SecureError::ReplayRejected)
        );
        assert_eq!(a.verify_message(&env), Err(SecureError::IdentityMismatch));
        let mut bad = env.clone();
        bad.to = "urn:hacp:agent:c".into();
        bad.sig = Some("00".repeat(64));
        assert_eq!(b.verify_message(&bad), Err(SecureError::IdentityMismatch));
        bad = env.clone();
        bad.ct = Some("00".repeat(24));
        assert_eq!(
            b.open_authenticated(&bad),
            Err(SecureError::BadMessageSignature)
        );
        a.active.get_mut(&sid).unwrap().info.send_seq = u64::MAX - 1;
        let last = a.seal(&sid, u64::MAX - 1, "", b"last").unwrap();
        assert_eq!(last.seq, Some(u64::MAX - 1));
        assert_eq!(
            a.seal(&sid, u64::MAX, "", b"exhausted"),
            Err(SecureError::SessionExhausted)
        );
        assert!(a.info(&sid).is_err());
        let mut impossible = env;
        impossible.seq = Some(u64::MAX);
        impossible.sig = Some(a.identity.sign_message(&impossible).unwrap());
        assert_eq!(
            b.open_authenticated(&impossible),
            Err(SecureError::SessionExhausted)
        );
        assert!(b.info(&sid).is_err());
    }
}
