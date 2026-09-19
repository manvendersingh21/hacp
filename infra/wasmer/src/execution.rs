//! Guardian-side execution bridge: authorized HACP Secure delivery → policy →
//! [`ExecutionRequest`] → [`SandboxExecutor`] → [`ExecutionResult`] → sealed reply.
//!
//! Trust split:
//!
//! * `hacp-secure-guardian` decrypts, authenticates the sender, checks the
//!   session, and delivers a message only if its sealed contract binding
//!   matches the frozen HACP contract it observes for that session.
//! * This module holds no keys and cannot: it links the `hacp` crate without
//!   the `guardian` feature, so crypto and session state are not compiled in.
//!   It talks to the guardian only through the existing socket verbs
//!   (`open`, `status`, `seal`).
//! * Before anything runs it requires a contract binding and an allowlisted
//!   requester, checks the request against an operator [`ExecutionPolicy`],
//!   and builds the [`ExecutionRequest`] from the approved fields only. The
//!   sandbox receives that request and nothing else.

use crate::{Capability, ExecutionFailure, ExecutionRequest, ExecutionResult, ResourceLimits, SandboxExecutor, SandboxFile, RESERVED_ENV_PREFIX};
use base64::{engine::general_purpose::STANDARD, Engine};
use hacp::secure::{client, workflow::Workflow, SecureError};
use hacp::v2::{agent_urn, Envelope};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

/// Application kind of an execution request. Not a HACP registry kind: HACP
/// delivers unregistered kinds, and EXECUTE stays a contract state.
pub const REQUEST_KIND: &str = "sandbox.execution.request";
pub const RESULT_KIND: &str = "sandbox.execution.result";

/// Body of a [`REQUEST_KIND`] message. Unknown fields are refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPayload {
    pub package: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub files: Vec<PayloadFile>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub network: Vec<String>,
    pub timeout_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadFile {
    /// Relative to the guest work directory.
    pub path: String,
    pub content_b64: String,
}

/// Operator policy for the execution service. Loaded from a local file, never
/// from HACP messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionPolicy {
    /// Agent URNs allowed to request execution.
    pub allowed_peers: Vec<String>,
    pub allowed_packages: Vec<String>,
    pub max_timeout_ms: u64,
    pub max_output_bytes: usize,
    pub max_args: usize,
    pub max_files: usize,
    pub max_total_file_bytes: usize,
    /// Guest variable names a request may set. `HACP_*` is refused regardless.
    #[serde(default)]
    pub allowed_env: Vec<String>,
    /// Exact Wasmer `--net` allow rules a request may use.
    #[serde(default)]
    pub allowed_network: Vec<String>,
}

/// Why a delivered request was refused without running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    Unbound,
    PeerNotAllowed(String),
    Malformed(String),
    PackageNotAllowed(String),
    TimeoutOutOfPolicy(u64),
    OutputLimitOutOfPolicy(usize),
    TooManyArgs(usize),
    TooManyFiles(usize),
    FilesTooLarge,
    EnvNotAllowed(String),
    NetworkNotAllowed(String),
}

impl Denial {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unbound => "Unbound",
            Self::PeerNotAllowed(_) => "PeerNotAllowed",
            Self::Malformed(_) => "Malformed",
            Self::PackageNotAllowed(_) => "PackageNotAllowed",
            Self::TimeoutOutOfPolicy(_) => "TimeoutOutOfPolicy",
            Self::OutputLimitOutOfPolicy(_) => "OutputLimitOutOfPolicy",
            Self::TooManyArgs(_) => "TooManyArgs",
            Self::TooManyFiles(_) => "TooManyFiles",
            Self::FilesTooLarge => "FilesTooLarge",
            Self::EnvNotAllowed(_) => "EnvNotAllowed",
            Self::NetworkNotAllowed(_) => "NetworkNotAllowed",
        }
    }
}

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unbound => write!(f, "request is not bound to a frozen HACP contract"),
            Self::PeerNotAllowed(peer) => write!(f, "{peer} may not request execution"),
            Self::Malformed(msg) => write!(f, "malformed execution request: {msg}"),
            Self::PackageNotAllowed(package) => write!(f, "package `{package}` is not allowed by policy"),
            Self::TimeoutOutOfPolicy(ms) => write!(f, "timeout {ms} ms is outside policy"),
            Self::OutputLimitOutOfPolicy(bytes) => write!(f, "output limit {bytes} bytes is outside policy"),
            Self::TooManyArgs(n) => write!(f, "{n} arguments exceed policy"),
            Self::TooManyFiles(n) => write!(f, "{n} files exceed policy"),
            Self::FilesTooLarge => write!(f, "staged files exceed the policy size limit"),
            Self::EnvNotAllowed(key) => write!(f, "guest variable `{key}` is not allowed by policy"),
            Self::NetworkNotAllowed(rule) => write!(f, "network rule `{rule}` is not allowed by policy"),
        }
    }
}

/// Turns an authenticated, contract-bound request into the only data the
/// sandbox will see. `contract` is the binding the guardian verified.
pub fn authorize(policy: &ExecutionPolicy, from: &str, contract: &str, body: &Value) -> Result<ExecutionRequest, Denial> {
    if contract.is_empty() {
        return Err(Denial::Unbound);
    }
    if !policy.allowed_peers.iter().any(|peer| peer == from) {
        return Err(Denial::PeerNotAllowed(from.to_owned()));
    }
    let payload = ExecutionPayload::deserialize(body).map_err(|e| Denial::Malformed(e.to_string()))?;
    if !policy.allowed_packages.contains(&payload.package) {
        return Err(Denial::PackageNotAllowed(payload.package));
    }
    if payload.timeout_ms == 0 || payload.timeout_ms > policy.max_timeout_ms {
        return Err(Denial::TimeoutOutOfPolicy(payload.timeout_ms));
    }
    let max_output_bytes = payload.max_output_bytes.unwrap_or(policy.max_output_bytes);
    if max_output_bytes == 0 || max_output_bytes > policy.max_output_bytes {
        return Err(Denial::OutputLimitOutOfPolicy(max_output_bytes));
    }
    if payload.args.len() > policy.max_args {
        return Err(Denial::TooManyArgs(payload.args.len()));
    }
    if payload.files.len() > policy.max_files {
        return Err(Denial::TooManyFiles(payload.files.len()));
    }
    let mut files = Vec::with_capacity(payload.files.len());
    let mut total = 0usize;
    for file in payload.files {
        // Reject on the encoded size first so an oversized payload is never decoded.
        if file.content_b64.len() / 4 * 3 > policy.max_total_file_bytes {
            return Err(Denial::FilesTooLarge);
        }
        let contents = STANDARD
            .decode(&file.content_b64)
            .map_err(|_| Denial::Malformed(format!("file `{}` is not base64", file.path)))?;
        total = total.saturating_add(contents.len());
        if total > policy.max_total_file_bytes {
            return Err(Denial::FilesTooLarge);
        }
        files.push(SandboxFile { path: file.path, contents });
    }
    let mut capabilities = Vec::new();
    for (key, value) in payload.env {
        if key.to_ascii_uppercase().starts_with(RESERVED_ENV_PREFIX) || !policy.allowed_env.contains(&key) {
            return Err(Denial::EnvNotAllowed(key));
        }
        capabilities.push(Capability::Env { key, value });
    }
    if let Some(rule) = payload.network.iter().find(|rule| !policy.allowed_network.contains(rule)) {
        return Err(Denial::NetworkNotAllowed(rule.clone()));
    }
    if !payload.network.is_empty() {
        capabilities.push(Capability::Network { rules: payload.network });
    }
    Ok(ExecutionRequest {
        package: payload.package,
        args: payload.args,
        files,
        capabilities,
        limits: ResourceLimits { timeout: Duration::from_millis(payload.timeout_ms), max_output_bytes },
    })
}

/// Body of the [`RESULT_KIND`] reply for a request that ran (or failed to).
pub fn result_body(result: &ExecutionResult) -> Value {
    let failure = result.failure.as_ref().map(|failure| {
        // Host-side failures can mention host paths; the requester gets a fixed text.
        let (kind, detail) = match failure {
            ExecutionFailure::InvalidRequest(msg) => ("InvalidRequest", msg.clone()),
            ExecutionFailure::RuntimeUnavailable(_) => ("RuntimeUnavailable", "wasmer runtime unavailable".to_owned()),
            ExecutionFailure::TimedOut(_) => ("TimedOut", failure.to_string()),
            ExecutionFailure::Io(_) => ("Io", "sandbox host error".to_owned()),
        };
        json!({"kind": kind, "detail": detail})
    });
    json!({
        "status": if result.failure.is_none() { "completed" } else { "failed" },
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "output_truncated": result.output_truncated,
        "duration_ms": u64::try_from(result.duration.as_millis()).unwrap_or(u64::MAX),
        "failure": failure,
    })
}

/// Body of the [`RESULT_KIND`] reply for a request that was refused.
pub fn denial_body(denial: &Denial) -> Value {
    json!({"status": "denied", "denial": {"code": denial.code(), "detail": denial.to_string()}})
}

/// What the service did with one guardian report entry. Public metadata only:
/// never payloads or guest output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Outcome {
    pub message_id: Option<String>,
    pub from: Option<String>,
    /// `executed`, `failed`, `denied`, `rejected` or `ignored`.
    pub status: String,
    pub detail: String,
    /// Whether the reply was sealed by the guardian.
    pub replied: bool,
}

impl Outcome {
    fn rejected(error: impl fmt::Display) -> Self {
        Self { message_id: None, from: None, status: "rejected".into(), detail: error.to_string(), replied: false }
    }
}

/// An authenticated message as the guardian delivered it.
struct Delivered {
    from: String,
    contract: String,
    message: Envelope,
}

/// Checks a guardian delivery the same way the skill adapter does: secure
/// session, sender agrees with the authenticated sender, addressed to us, in
/// this HACP session.
fn decode(delivery: &Value, local: &str, context: &str) -> Result<Delivered, SecureError> {
    if delivery["sid"].as_str().is_none_or(str::is_empty) {
        return Err(SecureError::DowngradeDetected);
    }
    let from = delivery["from"].as_str().ok_or(SecureError::SchemaViolation)?.to_owned();
    let contract = delivery["contract"].as_str().ok_or(SecureError::SchemaViolation)?.to_owned();
    let bytes = STANDARD
        .decode(delivery["payload_b64"].as_str().ok_or(SecureError::SchemaViolation)?)
        .map_err(|_| SecureError::SchemaViolation)?;
    let message: Envelope = serde_json::from_slice(&bytes).map_err(|_| SecureError::SchemaViolation)?;
    message.validate().map_err(|_| SecureError::SchemaViolation)?;
    if message.from != from || message.to != local || message.session_id != context {
        return Err(SecureError::IdentityMismatch);
    }
    Ok(Delivered { from, contract, message })
}

fn guardian_report(socket: &Path, context: &str) -> Result<Value, SecureError> {
    let report = client::request(socket, &json!({"op": "open", "hacp_session": context}))?;
    for field in ["delivered", "rejected", "aborted"] {
        if !report[field].is_array() {
            return Err(SecureError::GuardianUnavailable);
        }
    }
    Ok(report)
}

fn validate_identities(local: &str, context: &str, others: &[&str]) -> Result<(), SecureError> {
    if context.is_empty() || agent_urn::parse(local).is_err() || others.iter().any(|urn| agent_urn::parse(urn).is_err()) {
        return Err(SecureError::SchemaViolation);
    }
    Ok(())
}

impl<T: SandboxExecutor + ?Sized> SandboxExecutor for &T {
    fn execute(&self, request: &ExecutionRequest) -> ExecutionResult {
        (**self).execute(request)
    }
}

/// Execution service for the executing peer. Owns `open` for its HACP session.
pub struct ExecutionService<E> {
    socket: PathBuf,
    local: String,
    context: String,
    policy: ExecutionPolicy,
    executor: E,
    /// Guardian rejections already reported. Every `open` rescans the edge, so
    /// each earlier frame comes back as `ReplayRejected` on every poll.
    reported: RefCell<BTreeSet<(String, String)>>,
}

impl<E: SandboxExecutor> ExecutionService<E> {
    pub fn new(socket: &Path, local: &str, context: &str, policy: ExecutionPolicy, executor: E) -> Result<Self, SecureError> {
        let peers: Vec<&str> = policy.allowed_peers.iter().map(String::as_str).collect();
        validate_identities(local, context, &peers)?;
        Ok(Self {
            socket: socket.into(),
            local: local.into(),
            context: context.into(),
            policy,
            executor,
            reported: RefCell::default(),
        })
    }

    /// One guardian `open`: every delivered request is authorized, executed
    /// and answered; guardian rejections are reported (each distinct one once)
    /// and nothing runs.
    pub fn step(&self) -> Result<Vec<Outcome>, SecureError> {
        let report = guardian_report(&self.socket, &self.context)?;
        let mut outcomes = Vec::new();
        for (field, subject) in [("rejected", "file"), ("aborted", "sid")] {
            for entry in report[field].as_array().into_iter().flatten() {
                let error: SecureError = serde_json::from_value(entry["error"].clone()).unwrap_or(SecureError::GuardianUnavailable);
                let key = (format!("{field}:{}", entry[subject].as_str().unwrap_or_default()), error.to_string());
                if self.reported.borrow_mut().insert(key) {
                    outcomes.push(Outcome::rejected(error));
                }
            }
        }
        for delivery in report["delivered"].as_array().into_iter().flatten() {
            outcomes.push(self.handle(delivery));
        }
        Ok(outcomes)
    }

    fn handle(&self, delivery: &Value) -> Outcome {
        let Delivered { from, contract, message } = match decode(delivery, &self.local, &self.context) {
            Ok(delivered) => delivered,
            Err(error) => return Outcome::rejected(error),
        };
        let mut outcome = Outcome {
            message_id: Some(message.message_id.clone()),
            from: Some(from.clone()),
            status: "ignored".into(),
            detail: format!("kind {}", message.kind),
            replied: false,
        };
        if message.kind != REQUEST_KIND {
            return outcome;
        }
        let body = match authorize(&self.policy, &from, &contract, &message.body) {
            Ok(request) => {
                let result = self.executor.execute(&request);
                outcome.status = if result.failure.is_none() { "executed" } else { "failed" }.into();
                outcome.detail = match &result.failure {
                    None => format!("exit {}", result.exit_code.map_or_else(|| "none".into(), |c| c.to_string())),
                    Some(failure) => failure_kind(failure).into(),
                };
                result_body(&result)
            }
            Err(denial) => {
                outcome.status = "denied".into();
                outcome.detail = denial.code().into();
                denial_body(&denial)
            }
        };
        let mut reply = Envelope::new(&self.context, &self.local, &from, RESULT_KIND, body);
        reply.in_reply_to = Some(message.message_id);
        // The reply carries the request's binding, so the guardian seals it
        // under the same frozen contract it verified on the way in.
        outcome.replied = Workflow::new(&self.socket, &self.local, &from, &self.context)
            .and_then(|workflow| workflow.send(&reply, &contract))
            .is_ok();
        outcome
    }
}

fn failure_kind(failure: &ExecutionFailure) -> &'static str {
    match failure {
        ExecutionFailure::InvalidRequest(_) => "InvalidRequest",
        ExecutionFailure::RuntimeUnavailable(_) => "RuntimeUnavailable",
        ExecutionFailure::TimedOut(_) => "TimedOut",
        ExecutionFailure::Io(_) => "Io",
    }
}

/// The requesting peer's key-free side.
pub struct ExecutionClient {
    socket: PathBuf,
    local: String,
    peer: String,
    context: String,
}

/// A result that came back over HACP Secure for a request we sent.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReturnedResult {
    pub request_id: String,
    pub result_id: String,
    pub contract: String,
    pub body: Value,
}

impl ExecutionClient {
    pub fn new(socket: &Path, local: &str, peer: &str, context: &str) -> Result<Self, SecureError> {
        validate_identities(local, context, &[peer])?;
        Ok(Self { socket: socket.into(), local: local.into(), peer: peer.into(), context: context.into() })
    }

    /// Seals a request under `contract` through the local guardian and returns
    /// its message id.
    pub fn send(&self, payload: &ExecutionPayload, contract: &str) -> Result<String, SecureError> {
        let body = serde_json::to_value(payload).map_err(|_| SecureError::SchemaViolation)?;
        let request = Envelope::new(&self.context, &self.local, &self.peer, REQUEST_KIND, body);
        Workflow::new(&self.socket, &self.local, &self.peer, &self.context)?.send(&request, contract)?;
        Ok(request.message_id)
    }

    /// Polls the guardian until the reply to `request_id` arrives or `wait`
    /// expires (`Ok(None)`). A reply under a different binding is refused.
    /// Other deliveries on this session are consumed and dropped.
    pub fn await_result(&self, request_id: &str, contract: &str, wait: Duration) -> Result<Option<ReturnedResult>, SecureError> {
        let deadline = Instant::now() + wait;
        loop {
            let report = guardian_report(&self.socket, &self.context)?;
            for delivery in report["delivered"].as_array().into_iter().flatten() {
                let Ok(Delivered { from, contract: binding, message }) = decode(delivery, &self.local, &self.context) else {
                    continue;
                };
                if from != self.peer || message.kind != RESULT_KIND || message.in_reply_to.as_deref() != Some(request_id) {
                    continue;
                }
                if binding != contract {
                    return Err(SecureError::ContractMismatch);
                }
                return Ok(Some(ReturnedResult {
                    request_id: request_id.into(),
                    result_id: message.message_id,
                    contract: binding,
                    body: message.body,
                }));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(200));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_PYTHON_PACKAGE;

    const A: &str = "urn:hacp:agent:a";
    const BINDING: &str = "sha256:3333333333333333333333333333333333333333333333333333333333333333";

    fn policy() -> ExecutionPolicy {
        ExecutionPolicy {
            allowed_peers: vec![A.into()],
            allowed_packages: vec![DEFAULT_PYTHON_PACKAGE.into()],
            max_timeout_ms: 10_000,
            max_output_bytes: 4096,
            max_args: 2,
            max_files: 2,
            max_total_file_bytes: 16,
            allowed_env: vec!["SANDBOX_GREETING".into(), "HACP_SESSION_KEY".into()],
            allowed_network: vec!["ipv4:allow=127.0.0.1:8080".into()],
        }
    }

    fn body() -> Value {
        json!({"package": DEFAULT_PYTHON_PACKAGE, "args": ["/work/main.py"], "timeout_ms": 2000,
            "files": [{"path": "main.py", "content_b64": STANDARD.encode("print(1)")}]})
    }

    fn with(field: &str, value: Value) -> Value {
        let mut body = body();
        body[field] = value;
        body
    }

    fn denial(body: Value) -> Denial {
        authorize(&policy(), A, BINDING, &body).unwrap_err()
    }

    #[test]
    fn approved_fields_map_exactly_onto_the_execution_request() {
        let mut requested = with("env", json!({"SANDBOX_GREETING": "hi"}));
        requested["network"] = json!(["ipv4:allow=127.0.0.1:8080"]);
        requested["max_output_bytes"] = json!(1024);
        let request = authorize(&policy(), A, BINDING, &requested).unwrap();
        assert_eq!(
            request,
            ExecutionRequest {
                package: DEFAULT_PYTHON_PACKAGE.into(),
                args: vec!["/work/main.py".into()],
                files: vec![SandboxFile { path: "main.py".into(), contents: b"print(1)".to_vec() }],
                capabilities: vec![
                    Capability::Env { key: "SANDBOX_GREETING".into(), value: "hi".into() },
                    Capability::Network { rules: vec!["ipv4:allow=127.0.0.1:8080".into()] },
                ],
                limits: ResourceLimits { timeout: Duration::from_millis(2000), max_output_bytes: 1024 },
            }
        );
        let minimal = authorize(&policy(), A, BINDING, &body()).unwrap();
        assert!(minimal.capabilities.is_empty(), "nothing is granted unless requested and approved");
        assert_eq!(minimal.limits.max_output_bytes, 4096);
    }

    #[test]
    fn contract_binding_and_requester_are_required() {
        assert_eq!(authorize(&policy(), A, "", &body()).unwrap_err(), Denial::Unbound);
        let mallory = "urn:hacp:agent:mallory";
        assert_eq!(authorize(&policy(), mallory, BINDING, &body()).unwrap_err(), Denial::PeerNotAllowed(mallory.into()));
    }

    #[test]
    fn request_outside_policy_is_denied() {
        assert_eq!(denial(with("package", json!("wasmer/bash"))), Denial::PackageNotAllowed("wasmer/bash".into()));
        assert_eq!(denial(with("timeout_ms", json!(0))), Denial::TimeoutOutOfPolicy(0));
        assert_eq!(denial(with("timeout_ms", json!(10_001))), Denial::TimeoutOutOfPolicy(10_001));
        assert_eq!(denial(with("max_output_bytes", json!(4097))), Denial::OutputLimitOutOfPolicy(4097));
        assert_eq!(denial(with("args", json!(["a", "b", "c"]))), Denial::TooManyArgs(3));
        let file = json!({"path": "x", "content_b64": ""});
        assert_eq!(denial(with("files", json!([file, file, file]))), Denial::TooManyFiles(3));
        let big = STANDARD.encode([0u8; 12]);
        let files = json!([{"path": "a", "content_b64": big}, {"path": "b", "content_b64": big}]);
        assert_eq!(denial(with("files", files)), Denial::FilesTooLarge);
        let huge = json!([{"path": "a", "content_b64": "A".repeat(1 << 20)}]);
        assert_eq!(denial(with("files", huge)), Denial::FilesTooLarge);
        assert_eq!(denial(with("network", json!(["ipv4:allow=1.1.1.1:443"]))), Denial::NetworkNotAllowed("ipv4:allow=1.1.1.1:443".into()));
        assert_eq!(denial(with("env", json!({"PATH": "/usr/bin"}))), Denial::EnvNotAllowed("PATH".into()));
    }

    #[test]
    fn hacp_variables_are_refused_even_if_policy_lists_them() {
        assert_eq!(denial(with("env", json!({"HACP_SESSION_KEY": "x"}))), Denial::EnvNotAllowed("HACP_SESSION_KEY".into()));
        assert_eq!(denial(with("env", json!({"hacp_session_key": "x"}))), Denial::EnvNotAllowed("hacp_session_key".into()));
    }

    #[test]
    fn payload_schema_is_closed() {
        for body in [
            with("host_path", json!("/etc/passwd")),
            with("files", json!([{"path": "x", "host_path": "/etc/passwd"}])),
            with("files", json!([{"path": "x", "content_b64": "not base64!"}])),
            json!({"package": DEFAULT_PYTHON_PACKAGE}),
            json!("print(1)"),
        ] {
            assert!(matches!(denial(body.clone()), Denial::Malformed(_)), "{body}");
        }
    }

    #[test]
    fn result_bodies_carry_no_host_detail() {
        let result = |failure| ExecutionResult {
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            output_truncated: false,
            duration: Duration::from_millis(5),
            failure: Some(failure),
        };
        let io = result_body(&result(ExecutionFailure::Io("staging /private/host/dir".into())));
        let runtime = result_body(&result(ExecutionFailure::RuntimeUnavailable("/opt/host/wasmer".into())));
        let timeout = result_body(&result(ExecutionFailure::TimedOut(Duration::from_secs(2))));
        assert_eq!((io["status"].as_str(), io["failure"]["kind"].as_str()), (Some("failed"), Some("Io")));
        assert!(!io.to_string().contains("/private/host") && !runtime.to_string().contains("/opt/host"));
        assert_eq!(timeout["failure"]["kind"], "TimedOut");
        assert_eq!(timeout["duration_ms"], 5);
        let denied = denial_body(&Denial::Unbound);
        assert_eq!(denied["status"], "denied");
        assert_eq!(denied["denial"]["code"], "Unbound");
    }
}
