//! Guardian-only transport transactions. The guardian serializes access to this
//! state and SessionManager together; neither counters nor held envelopes persist.
use super::{
    envelope::{Kind, SecureEnvelope},
    session::SessionManager,
    SecureError,
};
use crate::v2::canon;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone)]
pub enum ContractView {
    Bootstrap,
    Pending,
    /// The snapshot may contain several independent contracts. Current entries
    /// are Frozen views, including a settled contract's last frozen revision.
    /// Bootstrap remains possible for a negotiation that has never frozen,
    /// including its final no-agreement notification.
    Observed {
        current: Vec<ContractView>,
        superseded: Vec<String>,
        bootstrap: bool,
    },
    Frozen {
        contract_id: String,
        revision: u64,
        content: Value,
        digest: String,
    },
}
impl ContractView {
    fn check(&self, claimed: &str) -> Result<(), SecureError> {
        match self {
            Self::Observed {
                current,
                superseded,
                bootstrap,
            } => {
                let mut matched = false;
                for entry in current {
                    let Self::Frozen { digest, .. } = entry else {
                        return Err(SecureError::ContractMismatch);
                    };
                    let binding = format!(
                        "sha256:{}",
                        digest.strip_prefix("sha256:").unwrap_or(digest)
                    );
                    // Validate every observation, including records unrelated to
                    // this claim; malformed control state never authorizes data.
                    entry.check(&binding)?;
                    matched |= binding == claimed;
                }
                if superseded.iter().any(|digest| digest == claimed) {
                    return Err(SecureError::ContractMismatch);
                }
                if matched || (claimed.is_empty() && (*bootstrap || current.is_empty())) {
                    Ok(())
                } else if !claimed.is_empty() && (*bootstrap || current.is_empty()) {
                    Err(SecureError::ContractPending)
                } else {
                    Err(SecureError::ContractMismatch)
                }
            }
            Self::Bootstrap | Self::Pending => {
                if claimed.is_empty() {
                    Ok(())
                } else {
                    Err(SecureError::ContractPending)
                }
            }
            Self::Frozen {
                contract_id,
                revision,
                content,
                digest,
            } => {
                let computed = canon::digest_of(
                    &json!({"contract_id":contract_id,"revision":revision,"content":content}),
                )
                .map_err(|_| SecureError::ContractMismatch)?;
                if digest.strip_prefix("sha256:").unwrap_or(digest) != computed
                    || claimed != format!("sha256:{computed}")
                {
                    Err(SecureError::ContractMismatch)
                } else {
                    Ok(())
                }
            }
        }
    }
}
#[derive(Serialize)]
pub struct Delivery {
    pub sid: String,
    pub from: String,
    pub contract: String,
    pub seq: u64,
    pub payload: Vec<u8>,
}
#[derive(Debug, Serialize)]
pub struct Held {
    pub sid: String,
    pub seq: u64,
    pub reason: String,
}
#[derive(Default, Serialize)]
pub struct ReceiveReport {
    pub delivered: Vec<Delivery>,
    pub held: Vec<Held>,
    pub rejected: Vec<SecureError>,
    pub aborted: Option<SecureError>,
}
#[derive(Debug, Default, Serialize)]
pub struct TransportStatus {
    pub send_seq: u64,
    pub recv_high: Option<u64>,
    pub held: usize,
}
#[derive(Default)]
struct Window {
    send_seq: u64,
    high: Option<u64>,
    delivery_next: u64,
    held: BTreeMap<u64, SecureEnvelope>,
}
impl Window {
    fn next(&self) -> u64 {
        self.high.map_or(0, |n| n + 1)
    }
}
// Deliberately not Clone: copying a replay window would create a second receiver.
#[derive(Default)]
pub struct Transport {
    windows: HashMap<String, Window>,
}
impl Transport {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn status(&self, sid: &str) -> TransportStatus {
        self.windows
            .get(sid)
            .map_or_else(TransportStatus::default, |w| TransportStatus {
                send_seq: w.send_seq,
                recv_high: w.high,
                held: w.held.len(),
            })
    }
    pub fn close(&mut self, manager: &mut SessionManager, sid: &str) -> Result<(), SecureError> {
        self.windows.remove(sid);
        manager.close(sid)
    }
    pub fn seal(
        &mut self,
        manager: &mut SessionManager,
        sid: &str,
        contract: &str,
        payload: &[u8],
        view: &ContractView,
    ) -> Result<SecureEnvelope, SecureError> {
        self.windows.retain(|known, _| manager.info(known).is_ok());
        manager.info(sid)?;
        match view.check(contract) {
            // The sender may observe a revision before the receiver; pending is
            // a receive disposition and cannot authorize plaintext delivery.
            Ok(()) | Err(SecureError::ContractPending) => {}
            Err(e) => {
                let _ = self.close(manager, sid);
                return Err(e);
            }
        }
        let w = self.windows.entry(sid.to_owned()).or_default();
        if w.send_seq == u64::MAX {
            let _ = self.close(manager, sid);
            return Err(SecureError::SessionExhausted);
        }
        let seq = w.send_seq;
        let envelope = manager.seal(sid, seq, contract, payload)?;
        // Commit before returning to the edge writer: a failed write must never
        // cause a second plaintext to be encrypted under this sequence nonce.
        w.send_seq = seq + 1;
        Ok(envelope)
    }
    fn abort(
        &mut self,
        manager: &mut SessionManager,
        sid: &str,
        error: SecureError,
        report: &mut ReceiveReport,
    ) {
        let _ = self.close(manager, sid);
        for delivery in &mut report.delivered {
            delivery.payload.fill(0);
        }
        report.delivered.clear();
        report.held.clear();
        report.aborted = Some(error);
    }
    pub fn receive(
        &mut self,
        manager: &mut SessionManager,
        env: &SecureEnvelope,
        view: &ContractView,
    ) -> ReceiveReport {
        let mut report = ReceiveReport::default();
        self.windows.retain(|known, _| manager.info(known).is_ok());
        if let Err(e) = env.validate() {
            report.rejected.push(e);
            return report;
        }
        if env.kind != Kind::Msg {
            report.rejected.push(SecureError::SchemaViolation);
            return report;
        }
        let sid = env.sid.as_deref().expect("validated msg sid");
        let seq = env.seq.expect("validated msg seq");
        // A validates lookup/routing and pinned signature. No replay decision or
        // decryption occurs until this succeeds, including for exact duplicates.
        if let Err(e) = manager.verify_message(env) {
            report.rejected.push(e);
            return report;
        }
        let w = self.windows.entry(sid.to_owned()).or_default();
        if w.high.is_some_and(|high| seq <= high) || w.held.contains_key(&seq) {
            report.rejected.push(SecureError::ReplayRejected);
            return report;
        }
        if seq == u64::MAX {
            self.abort(manager, sid, SecureError::SessionExhausted, &mut report);
            return report;
        }
        if seq > w.next() {
            if w.held.len() >= 64 {
                self.abort(manager, sid, SecureError::HoldOverflow, &mut report);
                return report;
            }
            let newest_gap = w.held.keys().copied().filter(|n| *n >= w.next()).max();
            if newest_gap.is_some_and(|newest| seq > newest) {
                self.abort(manager, sid, SecureError::SequenceGap, &mut report);
                return report;
            }
            w.held.insert(seq, env.clone());
            report.held.push(Held {
                sid: sid.into(),
                seq,
                reason: "SequencePending".into(),
            });
            return report;
        }
        let mut plaintext = match manager.open_authenticated(env) {
            Ok(pt) => pt,
            Err(e) => {
                report.rejected.push(e);
                return report;
            }
        };
        w.high = Some(seq);
        let binding = view.check(&env.contract);
        // Hold ciphertext only, including when waiting for lower sequence delivery.
        plaintext.fill(0);
        drop(plaintext);
        if let Err(e) = binding {
            if e != SecureError::ContractPending {
                self.abort(manager, sid, e, &mut report);
                return report;
            }
        }
        if w.held.len() >= 64 {
            self.abort(manager, sid, SecureError::HoldOverflow, &mut report);
            return report;
        }
        w.held.insert(seq, env.clone());
        self.drain(manager, sid, view, &mut report);
        report
    }
    pub fn observe(
        &mut self,
        manager: &mut SessionManager,
        sid: &str,
        view: &ContractView,
    ) -> ReceiveReport {
        let mut report = ReceiveReport::default();
        if let Err(e) = manager.info(sid) {
            self.windows.remove(sid);
            report.rejected.push(e);
            return report;
        }
        self.drain(manager, sid, view, &mut report);
        report
    }
    fn drain(
        &mut self,
        manager: &mut SessionManager,
        sid: &str,
        view: &ContractView,
        report: &mut ReceiveReport,
    ) {
        // Authenticate contiguous gap-held envelopes even if delivery is waiting
        // on a contract observation. This keeps auth high and delivery separate.
        loop {
            let Some(w) = self.windows.get_mut(sid) else {
                return;
            };
            let next = w.next();
            let Some(env) = w.held.get(&next) else {
                break;
            };
            match manager.open_authenticated(env) {
                Ok(mut pt) => {
                    pt.fill(0);
                    w.high = Some(next);
                }
                Err(e) => {
                    w.held.remove(&next);
                    report.rejected.push(e);
                    break;
                }
            }
            if let Err(e) = view.check(&env.contract) {
                if e != SecureError::ContractPending {
                    self.abort(manager, sid, e, report);
                    return;
                }
            }
        }
        loop {
            let Some(w) = self.windows.get_mut(sid) else {
                return;
            };
            let next = w.delivery_next;
            if !w.high.is_some_and(|high| next <= high) {
                break;
            }
            let Some(env) = w.held.get(&next) else {
                break;
            };
            match view.check(&env.contract) {
                Ok(()) => {}
                Err(SecureError::ContractPending) => break,
                Err(e) => {
                    self.abort(manager, sid, e, report);
                    return;
                }
            }
            // Reopen immutable ciphertext at delivery time; held plaintext is
            // never retained or emitted before the latest binding check passes.
            let payload = match manager.open_authenticated(env) {
                Ok(pt) => pt,
                Err(e) => {
                    self.abort(manager, sid, e, report);
                    return;
                }
            };
            report.delivered.push(Delivery {
                sid: sid.into(),
                from: env.from.clone(),
                contract: env.contract.clone(),
                seq: next,
                payload,
            });
            w.held.remove(&next);
            w.delivery_next = next + 1;
        }
        if let Some(w) = self.windows.get(sid) {
            for (&seq, env) in &w.held {
                // A contradictory later held revision aborts even while an earlier
                // pending revision prevents delivery; it must not silently stall.
                if w.high.is_some_and(|high| seq <= high) {
                    if let Err(e) = view.check(&env.contract) {
                        if e != SecureError::ContractPending {
                            self.abort(manager, sid, e, report);
                            return;
                        }
                    }
                }
                report.held.push(Held {
                    sid: sid.into(),
                    seq,
                    reason: if w.high.is_some_and(|high| seq <= high) {
                        "ContractPending"
                    } else {
                        "SequencePending"
                    }
                    .into(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn nonce_exhaustion_closes_without_wrapping() {
        let (mut a, _b, sid) = pair();
        let mut t = Transport::new();
        t.windows.entry(sid.clone()).or_default().send_seq = u64::MAX;
        assert_eq!(
            t.seal(
                &mut a,
                &sid,
                "",
                b"must not encrypt",
                &ContractView::Bootstrap
            )
            .err(),
            Some(SecureError::SessionExhausted)
        );
        assert!(a.info(&sid).is_err());
        assert!(!t.windows.contains_key(&sid));
    }
    #[test]
    fn observe_contradiction_discards_partial_batch_and_closes() {
        let (mut a, mut b, sid) = pair();
        let mut sender = Transport::new();
        let mut receiver = Transport::new();
        let content = json!({"x":1});
        let digest =
            canon::digest_of(&json!({"contract_id":"c-one","revision":1,"content":content}))
                .unwrap();
        let valid = format!("sha256:{digest}");
        let other = format!("sha256:{}", "00".repeat(32));
        for contract in [&valid, &other] {
            let env = sender
                .seal(
                    &mut a,
                    &sid,
                    contract,
                    b"must remain sealed",
                    &ContractView::Pending,
                )
                .unwrap();
            let r = receiver.receive(&mut b, &env, &ContractView::Pending);
            assert!(r.delivered.is_empty());
        }
        let view = ContractView::Frozen {
            contract_id: "c-one".into(),
            revision: 1,
            content,
            digest,
        };
        let r = receiver.observe(&mut b, &sid, &view);
        assert!(r.delivered.is_empty());
        assert_eq!(r.aborted, Some(SecureError::ContractMismatch));
        assert!(b.info(&sid).is_err());
    }
}
