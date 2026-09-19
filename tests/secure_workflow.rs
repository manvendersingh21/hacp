#![cfg(unix)]
//! Integration boundaries: the skill adapter never sees keys or manages counters.
use base64::{engine::general_purpose::STANDARD, Engine};
use hacp::{
    secure::{workflow::Workflow, SecureError},
    v2::Envelope,
};
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};
const A: &str = "urn:hacp:agent:a";
const B: &str = "urn:hacp:agent:b";
const CONTEXT: &str = "s-workflow";

struct Socket {
    root: PathBuf,
    task: Option<thread::JoinHandle<Vec<Value>>>,
}
impl Socket {
    fn new(replies: Vec<Value>) -> Self {
        let root = PathBuf::from("/tmp").join(format!("hsw-{}", uuid::Uuid::new_v4().simple()));
        fs::create_dir(&root).unwrap();
        let listener = UnixListener::bind(root.join("g.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let task = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut requests = vec![];
            for response in replies {
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "adapter omitted expected guardian operation"
                            );
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("accept: {e}"),
                    }
                };
                // BSD may inherit the listener's nonblocking flag on accept.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                requests.push(serde_json::from_str(&line).unwrap());
                writeln!(stream, "{response}").unwrap();
            }
            requests
        });
        Self {
            root,
            task: Some(task),
        }
    }
    fn workflow(&self) -> Workflow {
        Workflow::new(&self.root.join("g.sock"), A, B, CONTEXT).unwrap()
    }
    fn finish(mut self) -> Vec<Value> {
        self.task.take().unwrap().join().unwrap()
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn message(from: &str, to: &str, context: &str) -> Envelope {
    Envelope::new(
        context,
        from,
        to,
        "hacp.skill.ask",
        json!({"text":"ordinary HACP question"}),
    )
}
fn delivery(m: &Envelope) -> Value {
    json!({"sid":"1".repeat(32),"from":B,"seq":0,"contract":"",
        "payload_b64":STANDARD.encode(serde_json::to_vec(m).unwrap())})
}
fn inbox(delivered: Vec<Value>) -> Value {
    json!({"ok":true,"delivered":delivered,"held":[],"rejected":[],"aborted":[]})
}
fn status(context: &str, sid: &str) -> Value {
    json!({"peer":B,"hacp_session":context,"sid":sid,"state":"Established"})
}
#[test]
fn key_free_send_selects_hacp_context_and_passes_only_structured_payload() {
    let sid = "1".repeat(32);
    let socket = Socket::new(vec![
        json!({"ok":true,"sessions":[status("s-other", &"2".repeat(32)),status(CONTEXT,&sid)]}),
        json!({"ok":true}),
    ]);
    let m = message(A, B, CONTEXT);
    let binding = format!("sha256:{}", "3".repeat(64));
    socket.workflow().send(&m, &binding).unwrap();
    let requests = socket.finish();
    assert_eq!(requests[0], json!({"op":"status"}));
    assert_eq!(requests[1]["op"], "seal");
    assert_eq!(requests[1]["sid"], sid);
    assert_eq!(requests[1]["contract"], binding);
    assert_eq!(requests[1].as_object().unwrap().len(), 4);
    let actual: Envelope = serde_json::from_slice(
        &STANDARD
            .decode(requests[1]["payload_b64"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(actual.message_id, m.message_id);
}
#[test]
fn setup_uses_existing_guardian_session_verb_without_agent_crypto() {
    let socket = Socket::new(vec![json!({"ok":true,"sessions":[]}), json!({"ok":true})]);
    socket.workflow().ensure_session(true).unwrap();
    assert_eq!(
        socket.finish()[1],
        json!({"op":"session","peer":B,"hacp_session":CONTEXT})
    );
}
#[test]
fn missing_guardian_or_ambiguous_session_never_falls_back() {
    let root = PathBuf::from("/tmp").join(format!("missing-{}", uuid::Uuid::new_v4()));
    let flow = Workflow::new(&root, A, B, CONTEXT).unwrap();
    assert_eq!(
        flow.send(&message(A, B, CONTEXT), "").err(),
        Some(SecureError::GuardianUnavailable)
    );
    let socket = Socket::new(vec![
        json!({"ok":true,"sessions":[status(CONTEXT,"one"),status(CONTEXT,"two")]}),
    ]);
    assert_eq!(
        socket.workflow().send(&message(A, B, CONTEXT), "").err(),
        Some(SecureError::SessionUnknown)
    );
    assert_eq!(socket.finish().len(), 1);
}
#[test]
fn authenticated_delivery_is_retained_alongside_attack_and_hold_reports() {
    let m = message(B, A, CONTEXT);
    let mut response = inbox(vec![delivery(&m)]);
    response["rejected"] = json!([{"error":"ReplayRejected"},{"error":"BadMessageSignature"}]);
    response["held"] = json!([{"reason":"SequencePending"}]);
    let socket = Socket::new(vec![response]);
    let received = socket.workflow().receive().unwrap();
    assert_eq!(received.messages.len(), 1);
    assert_eq!(received.messages[0].message_id, m.message_id);
    assert_eq!(
        received.errors,
        vec![
            SecureError::ReplayRejected,
            SecureError::BadMessageSignature
        ]
    );
    assert!(received.held);
    assert_eq!(
        socket.finish(),
        vec![json!({"op":"open","hacp_session":CONTEXT})]
    );
}
#[test]
fn inner_sender_recipient_and_context_must_match_authenticated_delivery() {
    for (from, to, context) in [(A, A, CONTEXT), (B, B, CONTEXT), (B, A, "s-wrong")] {
        let socket = Socket::new(vec![inbox(vec![delivery(&message(from, to, context))])]);
        let received = socket.workflow().receive().unwrap();
        assert!(received.messages.is_empty());
        assert_eq!(received.errors, vec![SecureError::IdentityMismatch]);
        socket.finish();
    }
    let mut d = delivery(&message(B, A, CONTEXT));
    d["from"] = json!("urn:hacp:agent:mallory");
    let socket = Socket::new(vec![inbox(vec![d])]);
    let received = socket.workflow().receive().unwrap();
    assert!(received.messages.is_empty());
    assert_eq!(received.errors, vec![SecureError::IdentityMismatch]);
    socket.finish();
}
#[test]
fn plaintext_delivery_and_malformed_inner_payload_are_rejected() {
    for (field, value, error) in [
        ("sid", json!(""), SecureError::DowngradeDetected),
        (
            "payload_b64",
            json!(STANDARD.encode(b"not a HACP envelope")),
            SecureError::SchemaViolation,
        ),
    ] {
        let mut d = delivery(&message(B, A, CONTEXT));
        d[field] = value;
        let socket = Socket::new(vec![inbox(vec![d])]);
        let received = socket.workflow().receive().unwrap();
        assert!(received.messages.is_empty());
        assert_eq!(received.errors, vec![error]);
        socket.finish();
    }
}
#[test]
fn wrong_outbound_identity_is_rejected_before_contacting_guardian() {
    let flow = Workflow::new(&PathBuf::from("/missing.sock"), A, B, CONTEXT).unwrap();
    for m in [message(B, A, CONTEXT), message(A, B, "s-wrong")] {
        assert_eq!(flow.send(&m, "").err(), Some(SecureError::IdentityMismatch));
    }
}

#[cfg(feature = "guardian")]
mod bindings {
    use super::*;
    use hacp::secure::{
        session::SessionManager,
        transport::{ContractView, Transport},
    };
    fn frozen(id: &str, revision: u64) -> (ContractView, String) {
        let content = json!({"outputs":[id],"inputs":[],"acceptance":["true"]});
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
    fn pair() -> (SessionManager, SessionManager, String) {
        let mut a = SessionManager::new(A).unwrap();
        let mut b = SessionManager::new(B).unwrap();
        let hello = a.initiate(B, CONTEXT, &b.public_key()).unwrap();
        let ack = b.respond(CONTEXT, &hello, &a.public_key()).unwrap();
        let sid = a.complete(CONTEXT, &ack).unwrap();
        (a, b, sid)
    }
    #[test]
    fn simultaneous_contracts_deliver_under_each_current_binding() {
        let (one, d1) = frozen("c-one", 1);
        let (two, d2) = frozen("c-two", 1);
        let view = ContractView::Observed {
            current: vec![one, two],
            superseded: vec![],
            bootstrap: false,
        };
        let (mut a, mut b, sid) = pair();
        let (mut ta, mut tb) = (Transport::new(), Transport::new());
        for binding in [d1, d2] {
            let env = ta.seal(&mut a, &sid, &binding, b"bound", &view).unwrap();
            let received = tb.receive(&mut b, &env, &view);
            assert_eq!(received.delivered.len(), 1);
            assert_eq!(received.delivered[0].contract, binding);
        }
        // With no pending proposal, an unknown digest is a contradiction, even
        // when multiple current contracts make selection necessary.
        let (unknown, binding) = frozen("c-unobserved", 1);
        let env = ta
            .seal(&mut a, &sid, &binding, b"wrong contract", &unknown)
            .unwrap();
        let received = tb.receive(&mut b, &env, &view);
        assert!(received.delivered.is_empty());
        assert_eq!(received.aborted, Some(SecureError::ContractMismatch));
    }
    #[test]
    fn pending_contract_holds_unknown_and_superseded_revision_still_aborts() {
        let (one, d1) = frozen("c-one", 1);
        let (two, d2) = frozen("c-two", 1);
        let pending = ContractView::Observed {
            current: vec![one.clone()],
            superseded: vec![],
            bootstrap: true,
        };
        let (mut a, mut b, sid) = pair();
        let (mut ta, mut tb) = (Transport::new(), Transport::new());
        let env = ta
            .seal(&mut a, &sid, &d2, b"not observed yet", &two)
            .unwrap();
        let r = tb.receive(&mut b, &env, &pending);
        assert!(r.delivered.is_empty());
        assert_eq!(r.held[0].reason, "ContractPending");
        let current = ContractView::Observed {
            current: vec![one, two],
            superseded: vec![],
            bootstrap: false,
        };
        assert_eq!(tb.observe(&mut b, &sid, &current).delivered.len(), 1);
        let old = ta
            .seal(&mut a, &sid, &d1, b"old revision", &current)
            .unwrap();
        let (next, _) = frozen("c-one", 2);
        let superseded = ContractView::Observed {
            current: vec![next],
            superseded: vec![d1],
            bootstrap: true,
        };
        let r = tb.receive(&mut b, &old, &superseded);
        assert!(r.delivered.is_empty());
        assert_eq!(r.aborted, Some(SecureError::ContractMismatch));
    }
    #[test]
    fn empty_bootstrap_requires_observed_pending_negotiation() {
        let (one, _) = frozen("c-one", 1);
        for bootstrap in [true, false] {
            let view = ContractView::Observed {
                current: vec![one.clone()],
                superseded: vec![],
                bootstrap,
            };
            let (mut a, mut b, sid) = pair();
            let env = Transport::new()
                .seal(&mut a, &sid, "", b"proposal", &ContractView::Bootstrap)
                .unwrap();
            let result = Transport::new().receive(&mut b, &env, &view);
            if bootstrap {
                assert_eq!(result.delivered.len(), 1);
            } else {
                assert_eq!(result.aborted, Some(SecureError::ContractMismatch));
            }
        }
    }
}
