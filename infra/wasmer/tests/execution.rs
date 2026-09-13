#![cfg(unix)]
//! Execution bridge against a scripted guardian socket. The `test_*` cases
//! that name Wasmer run it for real; the rest use a recording executor.
//! Real two-guardian crypto is exercised by scripts/demo-hacp-wasmer.py.

use base64::{engine::general_purpose::STANDARD, Engine};
use hacp::v2::Envelope;
use hacp_wasmer_sandbox::execution::{
    ExecutionClient, ExecutionPayload, ExecutionPolicy, ExecutionService, PayloadFile, REQUEST_KIND, RESULT_KIND,
};
use hacp_wasmer_sandbox::{
    ExecutionRequest, ExecutionResult, SandboxExecutor, WasmerCliExecutor, DEFAULT_PYTHON_PACKAGE,
};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const A: &str = "urn:hacp:agent:a";
const B: &str = "urn:hacp:agent:b";
const CONTEXT: &str = "s-execution";
const SID: &str = "11111111111111111111111111111111";

fn binding() -> String {
    format!("sha256:{}", "3".repeat(64))
}

/// Answers one scripted reply per connection and records every request.
struct Guardian {
    root: PathBuf,
    task: Option<JoinHandle<Vec<Value>>>,
}

impl Guardian {
    fn new(replies: Vec<Value>) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        // Short path: Unix socket names are limited to ~100 bytes.
        let root = PathBuf::from("/tmp").join(format!(
            "hxe-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let listener = UnixListener::bind(root.join("g.sock")).unwrap();
        listener.set_nonblocking(true).unwrap();
        let task = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(60);
            let mut requests = Vec::new();
            for reply in replies {
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "expected guardian operation never came");
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("accept: {e}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap()).read_line(&mut line).unwrap();
                requests.push(serde_json::from_str(&line).unwrap());
                writeln!(stream, "{reply}").unwrap();
            }
            requests
        });
        Self { root, task: Some(task) }
    }

    fn socket(&self) -> PathBuf {
        self.root.join("g.sock")
    }

    fn finish(mut self) -> Vec<Value> {
        self.task.take().unwrap().join().unwrap()
    }
}

impl Drop for Guardian {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[derive(Default)]
struct Recording {
    requests: RefCell<Vec<ExecutionRequest>>,
}

impl SandboxExecutor for Recording {
    fn execute(&self, request: &ExecutionRequest) -> ExecutionResult {
        self.requests.borrow_mut().push(request.clone());
        ExecutionResult {
            exit_code: Some(0),
            stdout: "recorded\n".into(),
            stderr: String::new(),
            output_truncated: false,
            duration: Duration::from_millis(1),
            failure: None,
        }
    }
}

fn policy() -> ExecutionPolicy {
    ExecutionPolicy {
        allowed_peers: vec![A.into()],
        allowed_packages: vec![DEFAULT_PYTHON_PACKAGE.into()],
        max_timeout_ms: 10_000,
        max_output_bytes: 64 * 1024,
        max_args: 8,
        max_files: 4,
        max_total_file_bytes: 64 * 1024,
        allowed_env: vec!["SANDBOX_GREETING".into()],
        allowed_network: vec![],
    }
}

fn payload(code: &str) -> ExecutionPayload {
    ExecutionPayload {
        package: DEFAULT_PYTHON_PACKAGE.into(),
        args: vec!["/work/main.py".into()],
        files: vec![PayloadFile { path: "main.py".into(), content_b64: STANDARD.encode(code) }],
        env: Default::default(),
        network: vec![],
        timeout_ms: 5_000,
        max_output_bytes: None,
    }
}

fn request_envelope(body: Value) -> Envelope {
    Envelope::new(CONTEXT, A, B, REQUEST_KIND, body)
}

fn delivery(message: &Envelope, contract: &str) -> Value {
    json!({"sid": SID, "from": message.from, "seq": 0, "contract": contract,
        "payload_b64": STANDARD.encode(serde_json::to_vec(message).unwrap())})
}

fn open_reply(delivered: Vec<Value>) -> Value {
    json!({"ok": true, "delivered": delivered, "held": [], "rejected": [], "aborted": []})
}

fn status_reply(peer: &str) -> Value {
    json!({"ok": true, "sessions": [{"peer": peer, "hacp_session": CONTEXT, "sid": SID, "state": "Established"}]})
}

fn sealed(request: &Value) -> Envelope {
    assert_eq!(request["op"], "seal");
    serde_json::from_slice(&STANDARD.decode(request["payload_b64"].as_str().unwrap()).unwrap()).unwrap()
}

fn wasmer() -> WasmerCliExecutor {
    WasmerCliExecutor::from_host(vec![DEFAULT_PYTHON_PACKAGE.into()])
        .expect("wasmer must be installed to run the execution tests (see infra/wasmer/README.md)")
}

#[test]
fn test_bound_request_runs_in_wasmer_and_result_is_sealed_under_the_same_binding() {
    let request = request_envelope(serde_json::to_value(payload("print('bridged through HACP')")).unwrap());
    let guardian = Guardian::new(vec![
        open_reply(vec![delivery(&request, &binding())]),
        status_reply(A),
        json!({"ok": true, "sid": SID, "seq": 0}),
    ]);
    let service = ExecutionService::new(&guardian.socket(), B, CONTEXT, policy(), wasmer()).unwrap();
    let outcomes = service.step().unwrap();
    let requests = guardian.finish();

    assert_eq!(outcomes.len(), 1, "{outcomes:?}");
    assert_eq!(outcomes[0].status, "executed", "{outcomes:?}");
    assert!(outcomes[0].replied);
    assert_eq!(requests[0], json!({"op": "open", "hacp_session": CONTEXT}));
    assert_eq!(requests[2]["sid"], SID);
    assert_eq!(requests[2]["contract"], binding());
    let reply = sealed(&requests[2]);
    assert_eq!(reply.kind, RESULT_KIND);
    assert_eq!((reply.from.as_str(), reply.to.as_str()), (B, A));
    assert_eq!(reply.in_reply_to.as_deref(), Some(request.message_id.as_str()));
    assert_eq!(reply.body["status"], "completed");
    assert_eq!(reply.body["exit_code"], 0);
    assert_eq!(reply.body["stdout"].as_str().unwrap().trim(), "bridged through HACP");
}

#[test]
fn test_wasmer_timeout_is_reported_as_a_failed_result() {
    let mut body = payload("while True: pass");
    body.timeout_ms = 1_500;
    let request = request_envelope(serde_json::to_value(body).unwrap());
    let guardian = Guardian::new(vec![
        open_reply(vec![delivery(&request, &binding())]),
        status_reply(A),
        json!({"ok": true}),
    ]);
    let service = ExecutionService::new(&guardian.socket(), B, CONTEXT, policy(), wasmer()).unwrap();
    let outcomes = service.step().unwrap();
    let reply = sealed(&guardian.finish()[2]);
    assert_eq!(outcomes[0].status, "failed");
    assert_eq!(outcomes[0].detail, "TimedOut");
    assert_eq!(reply.body["status"], "failed");
    assert_eq!(reply.body["failure"]["kind"], "TimedOut");
    assert!(reply.body["duration_ms"].as_u64().unwrap() < 10_000, "{}", reply.body);
}

#[test]
fn unbound_or_out_of_policy_requests_never_reach_the_executor() {
    let recording = Recording::default();
    let mut hacp_env = payload("print(1)");
    hacp_env.env.insert("HACP_SESSION_KEY".into(), "x".into());
    let mut net = payload("print(1)");
    net.network = vec!["ipv4:allow=127.0.0.1:80".into()];
    let cases = [
        (serde_json::to_value(payload("print(1)")).unwrap(), String::new(), "Unbound"),
        (serde_json::to_value(hacp_env).unwrap(), binding(), "EnvNotAllowed"),
        (serde_json::to_value(net).unwrap(), binding(), "NetworkNotAllowed"),
        (json!({"package": DEFAULT_PYTHON_PACKAGE, "timeout_ms": 1, "host_path": "/etc"}), binding(), "Malformed"),
    ];
    for (body, contract, code) in cases {
        let request = request_envelope(body);
        let guardian = Guardian::new(vec![
            open_reply(vec![delivery(&request, &contract)]),
            status_reply(A),
            json!({"ok": true}),
        ]);
        let service = ExecutionService::new(&guardian.socket(), B, CONTEXT, policy(), &recording).unwrap();
        let outcomes = service.step().unwrap();
        let reply = sealed(&guardian.finish()[2]);
        assert_eq!((outcomes[0].status.as_str(), outcomes[0].detail.as_str()), ("denied", code));
        assert_eq!(reply.body["status"], "denied");
        assert_eq!(reply.body["denial"]["code"], code);
    }
    assert!(recording.requests.borrow().is_empty());
}

#[test]
fn guardian_rejections_and_misaddressed_deliveries_execute_nothing() {
    let recording = Recording::default();
    let good = serde_json::to_value(payload("print(1)")).unwrap();
    let to_self = Envelope::new(CONTEXT, A, A, REQUEST_KIND, good.clone());
    let wrong_context = Envelope::new("s-other", A, B, REQUEST_KIND, good.clone());
    let mut forged_sender = delivery(&request_envelope(good.clone()), &binding());
    forged_sender["from"] = json!("urn:hacp:agent:mallory");
    let mut plaintext = delivery(&request_envelope(good), &binding());
    plaintext["sid"] = json!("");
    let mut report = open_reply(vec![
        delivery(&to_self, &binding()),
        delivery(&wrong_context, &binding()),
        forged_sender,
        plaintext,
    ]);
    report["rejected"] = json!([{"file": "x", "error": "TamperDetected"}]);
    report["aborted"] = json!([{"sid": SID, "error": "ContractMismatch"}]);
    let guardian = Guardian::new(vec![report]);
    let service = ExecutionService::new(&guardian.socket(), B, CONTEXT, policy(), &recording).unwrap();
    let outcomes = service.step().unwrap();
    assert_eq!(guardian.finish().len(), 1, "nothing may be sealed");
    let details: Vec<&str> = outcomes.iter().map(|o| o.detail.as_str()).collect();
    assert!(outcomes.iter().all(|o| o.status == "rejected" && !o.replied), "{outcomes:?}");
    assert_eq!(
        details,
        ["TamperDetected", "ContractMismatch", "IdentityMismatch", "IdentityMismatch", "IdentityMismatch", "DowngradeDetected"]
    );
    assert!(recording.requests.borrow().is_empty());
}

#[test]
fn repeated_guardian_rejections_are_reported_once() {
    let recording = Recording::default();
    let report = |files: &[&str]| {
        let mut r = open_reply(vec![]);
        r["rejected"] = files.iter().map(|f| json!({"file": f, "error": "ReplayRejected"})).collect();
        r
    };
    // Each open rescans the edge, so earlier frames are rejected again every time.
    let guardian = Guardian::new(vec![
        report(&["00000000000000000001-a.json"]),
        report(&["00000000000000000001-a.json"]),
        report(&["00000000000000000001-a.json", "00000000000000000002-a.json"]),
    ]);
    let service = ExecutionService::new(&guardian.socket(), B, CONTEXT, policy(), &recording).unwrap();
    let counts: Vec<usize> = (0..3).map(|_| service.step().unwrap().len()).collect();
    guardian.finish();
    assert_eq!(counts, [1, 0, 1], "a new frame is still reported; repeats are not");
    assert!(recording.requests.borrow().is_empty());
}

#[test]
fn ordinary_hacp_messages_are_left_alone() {
    let recording = Recording::default();
    let question = Envelope::new(CONTEXT, A, B, "hacp.skill.ask", json!({"text": "hello"}));
    let guardian = Guardian::new(vec![open_reply(vec![delivery(&question, &binding())])]);
    let service = ExecutionService::new(&guardian.socket(), B, CONTEXT, policy(), &recording).unwrap();
    let outcomes = service.step().unwrap();
    assert_eq!(guardian.finish().len(), 1);
    assert_eq!(outcomes[0].status, "ignored");
    assert!(recording.requests.borrow().is_empty());
}

#[test]
fn client_seals_request_and_accepts_only_the_matching_bound_reply() {
    let body = payload("print(1)");
    let guardian = Guardian::new(vec![status_reply(B), json!({"ok": true})]);
    let client = ExecutionClient::new(&guardian.socket(), A, B, CONTEXT).unwrap();
    let request_id = client.send(&body, &binding()).unwrap();
    let requests = guardian.finish();
    assert_eq!(requests[1]["contract"], binding());
    let sent = sealed(&requests[1]);
    assert_eq!((sent.kind.as_str(), sent.message_id.as_str()), (REQUEST_KIND, request_id.as_str()));
    assert_eq!(serde_json::from_value::<ExecutionPayload>(sent.body).unwrap(), body);

    let reply = |in_reply_to: &str| {
        let mut m = Envelope::new(CONTEXT, B, A, RESULT_KIND, json!({"status": "completed"}));
        m.in_reply_to = Some(in_reply_to.into());
        m
    };
    let other = reply(&format!("m-{}", "0".repeat(32)));
    let matching = reply(&request_id);
    let guardian = Guardian::new(vec![open_reply(vec![delivery(&other, &binding()), delivery(&matching, &binding())])]);
    let client = ExecutionClient::new(&guardian.socket(), A, B, CONTEXT).unwrap();
    let returned = client.await_result(&request_id, &binding(), Duration::from_secs(5)).unwrap().unwrap();
    guardian.finish();
    assert_eq!(returned.result_id, matching.message_id);
    assert_eq!(returned.body["status"], "completed");

    let guardian = Guardian::new(vec![open_reply(vec![delivery(&matching, &format!("sha256:{}", "4".repeat(64)))])]);
    let client = ExecutionClient::new(&guardian.socket(), A, B, CONTEXT).unwrap();
    assert!(client.await_result(&request_id, &binding(), Duration::from_secs(5)).is_err());
    guardian.finish();
}

#[test]
fn runtime_failures_do_not_leak_host_paths_to_the_requester() {
    let missing = WasmerCliExecutor::new("/secret/host/path/wasmer", "/secret/host/.wasmer", vec![DEFAULT_PYTHON_PACKAGE.into()]);
    let request = request_envelope(serde_json::to_value(payload("print(1)")).unwrap());
    let guardian = Guardian::new(vec![
        open_reply(vec![delivery(&request, &binding())]),
        status_reply(A),
        json!({"ok": true}),
    ]);
    let service = ExecutionService::new(&guardian.socket(), B, CONTEXT, policy(), missing).unwrap();
    let outcomes = service.step().unwrap();
    let reply = sealed(&guardian.finish()[2]);
    assert_eq!(outcomes[0].detail, "RuntimeUnavailable");
    assert_eq!(reply.body["failure"]["kind"], "RuntimeUnavailable");
    assert!(!reply.body.to_string().contains("/secret/host"), "{}", reply.body);
}
