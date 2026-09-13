#![cfg(feature = "guardian")]
use hacp::secure::{
    envelope::SecureEnvelope,
    session::SessionManager,
    transport::{ContractView, ReceiveReport, Transport},
    SecureError,
};
use serde_json::json;
use std::sync::{Arc, Barrier, Mutex};
const A: &str = "urn:hacp:agent:a";
const B: &str = "urn:hacp:agent:b";
struct Pair {
    a: SessionManager,
    b: SessionManager,
    ta: Transport,
    tb: Transport,
    sid: String,
}
impl Pair {
    fn new() -> Self {
        let mut a = SessionManager::new(A).unwrap();
        let mut b = SessionManager::new(B).unwrap();
        let hello = a.initiate(B, "s-test", &b.public_key()).unwrap();
        let ack = b.respond("s-test", &hello, &a.public_key()).unwrap();
        let sid = a.complete("s-test", &ack).unwrap();
        Self {
            a,
            b,
            ta: Transport::new(),
            tb: Transport::new(),
            sid,
        }
    }
    fn send(&mut self, payload: &[u8]) -> SecureEnvelope {
        self.ta
            .seal(
                &mut self.a,
                &self.sid,
                "",
                payload,
                &ContractView::Bootstrap,
            )
            .unwrap()
    }
    fn recv(&mut self, e: &SecureEnvelope) -> ReceiveReport {
        self.tb.receive(&mut self.b, e, &ContractView::Bootstrap)
    }
}
fn frozen(id: &str, revision: u64) -> (ContractView, String) {
    let content = json!({"inputs":[],"outputs":["payload"],"acceptance":["true"]});
    let digest = hacp::v2::canon::digest_of(
        &json!({"contract_id":id,"revision":revision,"content":content}),
    )
    .unwrap();
    (
        ContractView::Frozen {
            contract_id: id.into(),
            revision,
            content,
            digest: digest.clone(),
        },
        format!("sha256:{digest}"),
    )
}
fn no_plaintext(r: &ReceiveReport) {
    assert!(r.delivered.is_empty());
}
#[test]
fn normal_bidirectional_exchange_and_replay_regression() {
    let mut p = Pair::new();
    let mut originals = Vec::new();
    for seq in 0..6 {
        let env = p.send(format!("A {seq}").as_bytes());
        assert_eq!(env.seq, Some(seq));
        let r = p.recv(&env);
        assert_eq!(r.delivered[0].payload, format!("A {seq}").as_bytes());
        originals.push(env);
        let env =
            p.tb.seal(
                &mut p.b,
                &p.sid,
                "",
                format!("B {seq}").as_bytes(),
                &ContractView::Bootstrap,
            )
            .unwrap();
        assert_eq!(env.seq, Some(seq));
        let r = p.ta.receive(&mut p.a, &env, &ContractView::Bootstrap);
        assert_eq!(r.delivered[0].payload, format!("B {seq}").as_bytes());
    }
    for env in &originals {
        let r = p.recv(env);
        no_plaintext(&r);
        assert_eq!(r.rejected, vec![SecureError::ReplayRejected]);
        assert!(r.aborted.is_none());
    }
    assert_eq!(p.tb.status(&p.sid).recv_high, Some(5));
}
#[test]
fn tampering_signature_order_and_state_unchanged() {
    let mut p = Pair::new();
    let original = p.send(b"secret");
    for field in ["ct", "sig", "contract", "seq", "ts"] {
        let mut env = original.clone();
        match field {
            "ct" => env.ct = Some("00".repeat(env.ct.as_ref().unwrap().len() / 2)),
            "sig" => env.sig = Some("00".repeat(64)),
            "contract" => env.contract = format!("sha256:{}", "00".repeat(32)),
            "seq" => env.seq = Some(4),
            "ts" => env.ts = Some("2026-09-13T00:00:00Z".into()),
            _ => unreachable!(),
        }
        let r = p.recv(&env);
        no_plaintext(&r);
        assert_eq!(r.rejected, vec![SecureError::BadMessageSignature]);
        assert_eq!(p.tb.status(&p.sid).recv_high, None);
    }
    assert_eq!(p.recv(&original).delivered.len(), 1);
    let mut tampered = original.clone();
    tampered.ct = Some("00".repeat(22));
    assert_eq!(
        p.recv(&tampered).rejected,
        vec![SecureError::BadMessageSignature]
    );
    assert_eq!(
        p.recv(&original).rejected,
        vec![SecureError::ReplayRejected]
    );
}
#[test]
fn wrong_recipient_sender_reflection_and_session_fail() {
    let mut p = Pair::new();
    let original = p.send(b"secret");
    let mut env = original.clone();
    env.to = A.into();
    assert_eq!(p.recv(&env).rejected, vec![SecureError::IdentityMismatch]);
    env = original.clone();
    env.from = "urn:hacp:agent:mallory".into();
    assert_eq!(p.recv(&env).rejected, vec![SecureError::IdentityMismatch]);
    assert_eq!(
        p.ta.receive(&mut p.a, &original, &ContractView::Bootstrap)
            .rejected,
        vec![SecureError::IdentityMismatch]
    );
    env = original.clone();
    env.sid = Some("00".repeat(16));
    assert_eq!(p.recv(&env).rejected, vec![SecureError::SessionUnknown]);
    assert_eq!(p.tb.status(&p.sid).recv_high, None);
    assert_eq!(p.recv(&original).delivered.len(), 1);
}
#[test]
fn pinned_identity_impersonation_and_handshake_context_fail() {
    let a = SessionManager::new(A).unwrap();
    let mut fake = SessionManager::new(A).unwrap();
    let mut b = SessionManager::new(B).unwrap();
    let hello = fake.initiate(B, "s-one", &b.public_key()).unwrap();
    assert_eq!(
        b.respond("s-one", &hello, &a.public_key()).err(),
        Some(SecureError::BadHandshakeSignature)
    );
    assert_eq!(
        b.respond("s-two", &hello, &fake.public_key()).err(),
        Some(SecureError::BadHandshakeSignature)
    );
    assert!(b.sessions().is_empty());
}
#[test]
fn reordered_gap_drains_in_order_and_duplicate_hold_rejects() {
    let mut p = Pair::new();
    let zero = p.send(b"0");
    let one = p.send(b"1");
    let r = p.recv(&one);
    no_plaintext(&r);
    assert_eq!(r.held[0].reason, "SequencePending");
    assert_eq!(p.tb.status(&p.sid).recv_high, None);
    assert_eq!(p.recv(&one).rejected, vec![SecureError::ReplayRejected]);
    let r = p.recv(&zero);
    assert_eq!(
        r.delivered.iter().map(|d| d.seq).collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert_eq!(p.tb.status(&p.sid).held, 0);
}
#[test]
fn missing_sequence_then_newer_aborts() {
    let mut p = Pair::new();
    let _zero = p.send(b"missing");
    let one = p.send(b"1");
    let two = p.send(b"2");
    assert_eq!(p.recv(&one).held.len(), 1);
    let r = p.recv(&two);
    no_plaintext(&r);
    assert_eq!(r.aborted, Some(SecureError::SequenceGap));
    assert_eq!(p.b.info(&p.sid).err(), Some(SecureError::SessionUnknown));
    assert_eq!(p.recv(&one).rejected, vec![SecureError::SessionUnknown]);
}
#[test]
fn contract_pending_stays_sealed_until_valid_observation() {
    let mut p = Pair::new();
    let (view, digest) = frozen("c-one", 1);
    for seq in 0..3 {
        let env =
            p.ta.seal(
                &mut p.a,
                &p.sid,
                &digest,
                format!("secret {seq}").as_bytes(),
                &view,
            )
            .unwrap();
        let r = p.tb.receive(&mut p.b, &env, &ContractView::Pending);
        no_plaintext(&r);
        assert!(r.held.iter().all(|h| h.reason == "ContractPending"));
        assert_eq!(p.tb.status(&p.sid).recv_high, Some(seq));
        assert_eq!(
            p.tb.receive(&mut p.b, &env, &ContractView::Pending)
                .rejected,
            vec![SecureError::ReplayRejected]
        );
    }
    let r = p.tb.observe(&mut p.b, &p.sid, &view);
    assert_eq!(
        r.delivered.iter().map(|d| d.seq).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(r.delivered[2].payload, b"secret 2");
    assert!(p.tb.observe(&mut p.b, &p.sid, &view).delivered.is_empty());
}
#[test]
fn wrong_contract_wrong_revision_and_corrupt_observation_abort() {
    for mode in 0..4 {
        let mut p = Pair::new();
        let (view, digest) = frozen("c-one", 1);
        let env =
            p.ta.seal(&mut p.a, &p.sid, &digest, b"secret", &view)
                .unwrap();
        let other = match mode {
            0 => frozen("c-two", 1).0,
            1 => frozen("c-one", 2).0,
            2 => {
                let mut v = view.clone();
                if let ContractView::Frozen {
                    ref mut content, ..
                } = v
                {
                    *content = json!({"forged":true});
                }
                v
            }
            _ => {
                let mut v = view;
                if let ContractView::Frozen { ref mut digest, .. } = v {
                    *digest = "00".repeat(32);
                }
                v
            }
        };
        let r = p.tb.receive(&mut p.b, &env, &other);
        no_plaintext(&r);
        assert_eq!(r.aborted, Some(SecureError::ContractMismatch));
        assert!(p.b.info(&p.sid).is_err());
    }
}
#[test]
fn frozen_context_rejects_empty_bootstrap_and_send_mismatch() {
    let mut p = Pair::new();
    let (view, _) = frozen("c-one", 1);
    let env = p.send(b"bootstrap");
    let r = p.tb.receive(&mut p.b, &env, &view);
    no_plaintext(&r);
    assert_eq!(r.aborted, Some(SecureError::ContractMismatch));
    assert_eq!(
        p.ta.seal(&mut p.a, &p.sid, "", b"secret", &view).err(),
        Some(SecureError::ContractMismatch)
    );
    assert!(p.a.info(&p.sid).is_err());
}
#[test]
fn pending_queue_and_gap_share_capacity() {
    for gap in [false, true] {
        let mut p = Pair::new();
        let (view, digest) = frozen("c-one", 1);
        for _ in 0..64 {
            let env =
                p.ta.seal(&mut p.a, &p.sid, &digest, b"sealed", &view)
                    .unwrap();
            let r = p.tb.receive(&mut p.b, &env, &ContractView::Pending);
            no_plaintext(&r);
            assert!(r.aborted.is_none());
        }
        assert_eq!(p.tb.status(&p.sid).held, 64);
        if gap {
            let _ =
                p.ta.seal(&mut p.a, &p.sid, &digest, b"missing", &view)
                    .unwrap();
        }
        let env =
            p.ta.seal(&mut p.a, &p.sid, &digest, b"overflow", &view)
                .unwrap();
        let r = p.tb.receive(&mut p.b, &env, &ContractView::Pending);
        no_plaintext(&r);
        assert_eq!(r.aborted, Some(SecureError::HoldOverflow));
        assert_eq!(p.tb.status(&p.sid).held, 0);
    }
}
#[test]
fn concurrent_duplicate_delivers_at_most_once() {
    let mut p = Pair::new();
    let env = Arc::new(p.send(b"exactly once"));
    let receiver = Arc::new(Mutex::new((p.b, p.tb)));
    let barrier = Arc::new(Barrier::new(16));
    let tasks: Vec<_> = (0..16)
        .map(|_| {
            let receiver = receiver.clone();
            let barrier = barrier.clone();
            let env = env.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let mut state = receiver.lock().unwrap();
                let (manager, transport) = &mut *state;
                let r = transport.receive(manager, &env, &ContractView::Bootstrap);
                (r.delivered.len(), r.rejected)
            })
        })
        .collect();
    let results: Vec<_> = tasks.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().map(|r| r.0).sum::<usize>(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| r.1 == vec![SecureError::ReplayRejected])
            .count(),
        15
    );
}
#[test]
fn failed_edge_write_still_spends_sequence_and_restart_rejects_old_session() {
    let mut p = Pair::new();
    let lost = p.send(b"not written");
    let next = p.send(b"next");
    assert_eq!(lost.seq, Some(0));
    assert_eq!(next.seq, Some(1));
    let mut restarted = SessionManager::new(B).unwrap();
    let r =
        p.tb.receive(&mut restarted, &lost, &ContractView::Bootstrap);
    no_plaintext(&r);
    assert_eq!(r.rejected, vec![SecureError::SessionUnknown]);
    assert_ne!(Pair::new().sid, p.sid);
}

#[cfg(unix)]
mod process_tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use hacp::secure::{client, guardian};
    use serde_json::Value;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    struct Harness {
        root: PathBuf,
        project: PathBuf,
        sockets: [PathBuf; 2],
        children: Vec<Child>,
    }
    impl Drop for Harness {
        fn drop(&mut self) {
            for child in &mut self.children {
                let _ = child.kill();
                let _ = child.wait();
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    impl Harness {
        fn new() -> Self {
            let root = PathBuf::from("/tmp").join(format!("hst-{}", uuid::Uuid::new_v4().simple()));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let project = root.join("project");
            fs::create_dir(&project).unwrap();
            let stores = [root.join("a"), root.join("b")];
            guardian::initialize(&stores[0], A).unwrap();
            guardian::initialize(&stores[1], B).unwrap();
            let apub = fs::read_to_string(stores[0].join("identity.pub")).unwrap();
            let bpub = fs::read_to_string(stores[1].join("identity.pub")).unwrap();
            guardian::pin_peer(&stores[0], B, &bpub, true).unwrap();
            guardian::pin_peer(&stores[1], A, &apub, true).unwrap();
            let sockets = [root.join("a.sock"), root.join("b.sock")];
            let mut h = Self {
                root,
                project,
                sockets,
                children: Vec::new(),
            };
            for (i, store) in stores.iter().enumerate() {
                let child = Command::new(env!("CARGO_BIN_EXE_hacp-secure-guardian"))
                    .args(["serve", "--degraded", "--store"])
                    .arg(store)
                    .arg("--project")
                    .arg(&h.project)
                    .arg("--socket")
                    .arg(&h.sockets[i])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                h.children.push(child);
            }
            let until = Instant::now() + Duration::from_secs(5);
            while !h.sockets.iter().all(|p| p.exists()) {
                assert!(Instant::now() < until, "guardian startup timeout");
                std::thread::sleep(Duration::from_millis(10));
            }
            h
        }
        fn cli(&self, i: usize, args: &[&str]) -> Value {
            let out = Command::new(env!("CARGO_BIN_EXE_hacp-secure"))
                .arg("--socket")
                .arg(&self.sockets[i])
                .args(args)
                .output()
                .unwrap();
            let v: Value = serde_json::from_slice(&out.stdout).unwrap();
            assert!(out.status.success(), "CLI failed: {v}");
            assert_eq!(v["ok"], true);
            v
        }
        fn handshake(&self) -> String {
            self.cli(0, &["session", "--peer", B, "--hacp-session", "s-e2e"]);
            self.cli(1, &["recv", "--hacp-session", "s-e2e"]);
            self.cli(0, &["recv", "--hacp-session", "s-e2e"]);
            let status = self.cli(0, &["status"]);
            assert_eq!(status["mode"], "degraded");
            status["sessions"][0]["sid"].as_str().unwrap().into()
        }
        fn send(&self, i: usize, sid: &str, payload: &[u8], contract: Option<&str>) -> Value {
            let file = self.root.join(format!("payload-{i}"));
            fs::write(&file, payload).unwrap();
            let mut args = vec![
                "send",
                "--sid",
                sid,
                "--payload-file",
                file.to_str().unwrap(),
            ];
            if let Some(digest) = contract {
                args.extend(["--contract", digest]);
            }
            self.cli(i, &args)
        }
        fn recv(&self, i: usize) -> Value {
            self.cli(i, &["recv", "--hacp-session", "s-e2e"])
        }
        fn freeze(&self) -> String {
            let (view, digest) = frozen("c-e2e", 1);
            let ContractView::Frozen {
                content,
                digest: bare,
                ..
            } = view
            else {
                unreachable!()
            };
            fs::create_dir_all(self.project.join(".hacp")).unwrap();
            fs::write(self.project.join(".hacp/session.json"),serde_json::to_vec(&json!({"session":{"session_id":"s-e2e"},"contracts":{"c-e2e":{"contract":{"state":"executing","revisions":[{"number":1,"content":content,"digest":bare}]}}}})).unwrap()).unwrap();
            digest
        }
    }
    fn edge_bytes(path: &Path) -> Vec<u8> {
        let mut bytes = Vec::new();
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                bytes.extend(edge_bytes(&entry.path()));
            } else {
                bytes.extend(fs::read(entry.path()).unwrap());
            }
        }
        bytes
    }
    #[test]
    fn real_cli_bidirectional_bound_exchange_and_no_plaintext_on_edge() {
        let h = Harness::new();
        let sid = h.handshake();
        let digest = h.freeze();
        let original_state = fs::read(h.project.join(".hacp/session.json")).unwrap();
        let canary = b"HACP_PRIVATE_PAYLOAD_7ac3e09d";
        for i in 0..2 {
            for seq in 0..3 {
                let sent = h.send(i, &sid, canary, Some(&digest));
                assert_eq!(sent["seq"], seq);
            }
        }
        let wire = edge_bytes(&h.project.join(".hacp-secure"));
        assert!(!wire.windows(canary.len()).any(|w| w == canary));
        let encoded = STANDARD.encode(canary);
        assert!(!wire.windows(encoded.len()).any(|w| w == encoded.as_bytes()));
        for i in 0..2 {
            let r = h.recv(i);
            let deliveries = r["delivered"].as_array().unwrap();
            assert_eq!(deliveries.len(), 3);
            for (seq, d) in deliveries.iter().enumerate() {
                assert_eq!(d["seq"], seq);
                assert_eq!(
                    STANDARD.decode(d["payload_b64"].as_str().unwrap()).unwrap(),
                    canary
                );
            }
            assert!(h.recv(i)["delivered"].as_array().unwrap().is_empty());
        }
        assert_eq!(
            fs::read(h.project.join(".hacp/session.json")).unwrap(),
            original_state
        );
    }
    #[test]
    fn real_edge_tamper_replay_routing_and_concurrent_open() {
        let h = Harness::new();
        let sid = h.handshake();
        let sent = h.send(0, &sid, b"protected", None);
        let path = h.project.join(sent["envelope_path"].as_str().unwrap());
        let original = fs::read(&path).unwrap();
        let mut env: Value = serde_json::from_slice(&original).unwrap();
        env["ct"] = json!("00".repeat(env["ct"].as_str().unwrap().len() / 2));
        fs::write(&path, serde_json::to_vec(&env).unwrap()).unwrap();
        let r = h.recv(1);
        assert!(r["delivered"].as_array().unwrap().is_empty());
        assert!(r["rejected"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["error"] == "BadMessageSignature"));
        env = serde_json::from_slice(&original).unwrap();
        env["to"] = json!("urn:hacp:agent:c");
        fs::write(&path, serde_json::to_vec(&env).unwrap()).unwrap();
        let r = h.recv(1);
        assert!(r["delivered"].as_array().unwrap().is_empty());
        assert!(r["rejected"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["error"] == "IdentityMismatch"));
        fs::write(&path, &original).unwrap();
        fs::write(path.with_file_name("copied-message.json"), &original).unwrap();
        let barrier = Arc::new(Barrier::new(8));
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let socket = h.sockets[1].clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    client::request(&socket, &json!({"op":"open","hacp_session":"s-e2e"})).unwrap()
                })
            })
            .collect();
        let results: Vec<_> = tasks.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(
            results
                .iter()
                .map(|r| r["delivered"].as_array().unwrap().len())
                .sum::<usize>(),
            1
        );
        assert!(h.recv(1)["delivered"].as_array().unwrap().is_empty());
    }
    #[test]
    fn real_plaintext_downgrade_before_handshake_and_guardian_down_fail_closed() {
        let mut h = Harness::new();
        use sha2::{Digest, Sha256};
        let scope = hacp::secure::envelope::encode_hex(&Sha256::digest(b"s-e2e"));
        let edge = h.project.join(".hacp-secure/handshakes").join(scope);
        fs::create_dir_all(&edge).unwrap();
        fs::write(
            edge.join("plaintext.json"),
            b"{\"payload\":\"downgrade-canary\"}",
        )
        .unwrap();
        let r = h.recv(1);
        assert!(r["delivered"].as_array().unwrap().is_empty());
        assert!(r["aborted"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["error"] == "DowngradeDetected"));
        h.children[0].kill().unwrap();
        h.children[0].wait().unwrap();
        let before = edge_bytes(&h.project.join(".hacp-secure"));
        let payload = h.root.join("offline-payload");
        fs::write(&payload, b"OFFLINE_PLAINTEXT_CANARY").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_hacp-secure"))
            .arg("--socket")
            .arg(&h.sockets[0])
            .args([
                "send",
                "--sid",
                "00000000000000000000000000000000",
                "--payload-file",
            ])
            .arg(payload)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let err: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(err["error"], "GuardianUnavailable");
        assert_eq!(edge_bytes(&h.project.join(".hacp-secure")), before);
    }
    #[test]
    fn real_observer_rejects_wrong_revision_and_corrupt_digest() {
        for corrupt in [false, true] {
            let h = Harness::new();
            let sid = h.handshake();
            let digest = h.freeze();
            h.send(0, &sid, b"bound-secret", Some(&digest));
            let path = h.project.join(".hacp/session.json");
            let mut state: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            let record = &mut state["contracts"]["c-e2e"]["contract"]["revisions"][0];
            if corrupt {
                record["content"] = json!({"forged":true});
            } else {
                record["number"] = json!(2);
                record["digest"] = json!(hacp::v2::canon::digest_of(
                    &json!({"contract_id":"c-e2e","revision":2,"content":record["content"]})
                )
                .unwrap());
            }
            fs::write(path, serde_json::to_vec(&state).unwrap()).unwrap();
            let result = h.recv(1);
            assert!(result["delivered"].as_array().unwrap().is_empty());
            assert!(result["aborted"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["error"] == "ContractMismatch"));
        }
    }
    #[test]
    fn guardian_socket_and_cli_have_no_verification_bypass() {
        let h = Harness::new();
        for op in [
            "sign", "export", "derive", "debug", "dump", "key", "seal_raw",
        ] {
            assert_eq!(
                client::request(&h.sockets[0], &json!({"op":op})).err(),
                Some(SecureError::UnknownOperation)
            );
        }
        assert_eq!(
            client::request(&h.sockets[0], &json!({"op":"status","skip_verify":true})).err(),
            Some(SecureError::SchemaViolation)
        );
        assert_eq!(client::request(&h.sockets[0],&json!({"op":"seal","sid":"0","contract":"","payload_b64":"","signing_input":"forgery"})).err(),Some(SecureError::SchemaViolation));
        let output = Command::new(env!("CARGO_BIN_EXE_hacp-secure"))
            .arg("--socket")
            .arg(&h.sockets[0])
            .args(["status", "--skip-verify", "true"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap()["error"],
            "SchemaViolation"
        );
    }
}
