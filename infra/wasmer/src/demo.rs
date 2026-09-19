//! Isolation scenarios shared by the `hacp-wasmer-demo` binary and the tests.
//!
//! Each scenario plants fake, randomly generated canaries on the host, asks a
//! guest program to go find them, and decides the verdict on the host side:
//! a check counts as BLOCKED only if the canary never shows up in guest output
//! and the host observed no side effect. The guest's own report is not
//! trusted.

use crate::{ExecutionRequest, ExecutionResult, SandboxExecutor, DEFAULT_PYTHON_PACKAGE, GUEST_WORK_DIR};
use std::collections::hash_map::RandomState;
use std::env;
use std::fs;
use std::hash::{BuildHasher, Hasher};
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const HELLO_PY: &str = include_str!("../examples/hello.py");
pub const FILESYSTEM_DENIED_PY: &str = include_str!("../examples/filesystem-denied.py");
pub const ENV_DENIED_PY: &str = include_str!("../examples/env-denied.py");
pub const NETWORK_DENIED_PY: &str = include_str!("../examples/network-denied.py");
pub const WASMER_TOKEN_DENIED_PY: &str = include_str!("../examples/wasmer-token-denied.py");

pub const HELLO_OUTPUT: &str = "HACP Wasmer sandbox works";

/// Host variables standing in for future HACP secrets, plus a fake Wasmer
/// registry token (the CLI would pick up `WASMER_TOKEN` if it were inherited).
pub const SECRET_ENV_VARS: [&str; 3] = ["HACP_GUARDIAN_PRIVATE_KEY", "HACP_SESSION_KEY", "WASMER_TOKEN"];

/// Prefix of every fake secret value, so nothing real is ever used.
pub const FAKE_SECRET_PREFIX: &str = "FAKE-";

/// The one variable the demo grants explicitly.
pub const GRANTED_ENV: (&str, &str) = ("SANDBOX_GREETING", "hello-from-guardian");

#[derive(Debug, Clone)]
pub struct Check {
    pub label: &'static str,
    pub passed: bool,
    pub verdict: &'static str,
    pub details: Vec<String>,
}

impl Check {
    fn new(label: &'static str, words: (&'static str, &'static str), passed: bool, details: Vec<String>) -> Self {
        let verdict = if passed { words.0 } else { words.1 };
        Self { label, passed, verdict, details }
    }
}

const PASS_FAIL: (&str, &str) = ("PASS", "FAIL");
const BLOCKED_EXPOSED: (&str, &str) = ("BLOCKED", "EXPOSED");

pub fn random_token() -> String {
    let mut hasher = RandomState::new().build_hasher();
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default();
    hasher.write_u128(nanos);
    format!("{:016x}", hasher.finish())
}

/// Adds fake HACP secrets — and `FORWARD_HOST_ENV=true`, which would make a
/// naive Wasmer invocation forward all of them — to a command's environment.
pub fn plant_secret_env(cmd: &mut Command) {
    let token = random_token();
    cmd.env("FORWARD_HOST_ENV", "true");
    for name in SECRET_ENV_VARS {
        cmd.env(name, format!("{FAKE_SECRET_PREFIX}{name}-{token}"));
    }
}

pub fn secret_env_planted() -> bool {
    SECRET_ENV_VARS
        .iter()
        .all(|name| env::var(name).is_ok_and(|v| v.starts_with(FAKE_SECRET_PREFIX)))
}

pub fn run_all(executor: &dyn SandboxExecutor, wasmer_dir: &Path) -> Vec<Check> {
    vec![
        normal_execution(executor),
        host_filesystem(executor),
        host_secrets(executor),
        unauthorized_network(executor),
        wasmer_token(executor, wasmer_dir),
    ]
}

pub fn normal_execution(executor: &dyn SandboxExecutor) -> Check {
    let request = ExecutionRequest::new(DEFAULT_PYTHON_PACKAGE)
        .file("hello.py", HELLO_PY)
        .arg(format!("{GUEST_WORK_DIR}/hello.py"));
    let result = executor.execute(&request);
    let passed = result.succeeded() && result.stdout.trim() == HELLO_OUTPUT;
    Check::new("NORMAL EXECUTION", PASS_FAIL, passed, describe(&result))
}

/// Fake guardian key storage and HACP runtime state on the host filesystem.
pub struct PlantedSecretFiles {
    pub root: PathBuf,
    pub key_file: PathBuf,
    pub state_file: PathBuf,
    pub canary: String,
}

impl PlantedSecretFiles {
    pub fn plant() -> io::Result<Self> {
        let token = random_token();
        let root = env::temp_dir().join(format!("hacp-wasmer-demo-secrets-{token}"));
        let keys = root.join("guardian").join("keys");
        let state = root.join("hacp-runtime");
        fs::create_dir_all(&keys)?;
        fs::create_dir_all(&state)?;
        let canary = format!("{FAKE_SECRET_PREFIX}HACP-KEY-MATERIAL-{token}");
        let key_file = keys.join("guardian_ed25519.key");
        let state_file = state.join("session-state.json");
        fs::write(&key_file, &canary)?;
        fs::write(&state_file, format!("{{\"session_key\":\"{canary}\"}}\n"))?;
        Ok(Self { root, key_file, state_file, canary })
    }
}

impl Drop for PlantedSecretFiles {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub fn host_filesystem(executor: &dyn SandboxExecutor) -> Check {
    const LABEL: &str = "HOST FILESYSTEM ACCESS";
    let secrets = match PlantedSecretFiles::plant() {
        Ok(secrets) => secrets,
        Err(e) => return Check::new(LABEL, BLOCKED_EXPOSED, false, vec![format!("could not plant host canaries: {e}")]),
    };
    let write_probe = secrets.root.join("guest-write-probe.txt");
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let repo_root = repo_root.canonicalize().unwrap_or(repo_root);

    // The key file must stay first: the guest also tries to reach it by
    // traversal and through a symlink.
    let mut targets = vec![
        secrets.key_file.clone(),
        secrets.state_file.clone(),
        secrets.root.clone(),
        repo_root.join(".hacp"),
        repo_root,
        PathBuf::from("/etc/passwd"),
    ];
    targets.extend(env::var_os("HOME").map(PathBuf::from));
    targets.extend(env::current_dir().ok());

    let mut request = ExecutionRequest::new(DEFAULT_PYTHON_PACKAGE)
        .file("filesystem-denied.py", FILESYSTEM_DENIED_PY)
        .arg(format!("{GUEST_WORK_DIR}/filesystem-denied.py"))
        .arg(write_probe.to_string_lossy());
    request.args.extend(targets.iter().map(|t| t.to_string_lossy().into_owned()));

    let result = executor.execute(&request);
    let canary_leaked = output_contains(&result, &secrets.canary);
    let guest_exposed = guest_reported_exposure(&result);
    let probe_created = write_probe.exists();
    let key_intact = fs::read_to_string(&secrets.key_file).is_ok_and(|c| c == secrets.canary);
    let passed = guest_finished(&result) && !canary_leaked && !guest_exposed && !probe_created && key_intact;

    let mut details = describe(&result);
    details.push(host_note("fake key material absent from guest output", !canary_leaked));
    details.push(host_note("guest write probe absent on host", !probe_created));
    details.push(host_note("fake key file unchanged on host", key_intact));
    Check::new(LABEL, BLOCKED_EXPOSED, passed, details)
}

pub fn host_secrets(executor: &dyn SandboxExecutor) -> Check {
    const LABEL: &str = "HOST SECRET ACCESS";
    if !secret_env_planted() {
        let msg = format!(
            "fake secrets are not in this process's environment ({}); run hacp-wasmer-demo, which plants them",
            SECRET_ENV_VARS.join(", ")
        );
        return Check::new(LABEL, BLOCKED_EXPOSED, false, vec![msg]);
    }
    let secret_values: Vec<String> = SECRET_ENV_VARS.iter().filter_map(|name| env::var(name).ok()).collect();

    let (granted_key, granted_value) = GRANTED_ENV;
    let mut request = ExecutionRequest::new(DEFAULT_PYTHON_PACKAGE)
        .file("env-denied.py", ENV_DENIED_PY)
        .arg(format!("{GUEST_WORK_DIR}/env-denied.py"))
        .arg(granted_key)
        .grant(crate::Capability::Env { key: granted_key.into(), value: granted_value.into() });
    request.args.extend(SECRET_ENV_VARS.iter().map(|name| name.to_string()));

    let result = executor.execute(&request);
    let leaked = secret_values.iter().any(|value| output_contains(&result, value));
    let grant_line = format!("GRANTED {granted_key}={granted_value}");
    let grant_seen = result.stdout.lines().any(|line| line == grant_line);
    let passed = guest_finished(&result) && !leaked && !guest_reported_exposure(&result) && grant_seen;

    let mut details = describe(&result);
    details.push(format!(
        "host > host env holds {} and FORWARD_HOST_ENV={}",
        SECRET_ENV_VARS.join(", "),
        env::var("FORWARD_HOST_ENV").unwrap_or_default()
    ));
    details.push(host_note("fake secret values absent from guest output", !leaked));
    details.push(host_note("explicitly granted variable visible to guest", grant_seen));
    Check::new(LABEL, BLOCKED_EXPOSED, passed, details)
}

pub fn unauthorized_network(executor: &dyn SandboxExecutor) -> Check {
    const LABEL: &str = "UNAUTHORIZED NETWORK";
    let listener = match HostListener::start() {
        Ok(listener) => listener,
        Err(e) => return Check::new(LABEL, BLOCKED_EXPOSED, false, vec![format!("could not start host listener: {e}")]),
    };
    let request = ExecutionRequest::new(DEFAULT_PYTHON_PACKAGE)
        .file("network-denied.py", NETWORK_DENIED_PY)
        .arg(format!("{GUEST_WORK_DIR}/network-denied.py"))
        .arg(listener.port.to_string());

    let result = executor.execute(&request);
    let connections = listener.stop();
    let passed = guest_finished(&result) && !guest_reported_exposure(&result) && connections == 0;

    let mut details = describe(&result);
    details.push(format!("host > connections received by host listener: {connections}"));
    Check::new(LABEL, BLOCKED_EXPOSED, passed, details)
}

/// The runtime process needs `WASMER_DIR`, which holds the registry token of
/// a logged-in host. The guest must not be able to read it.
pub fn wasmer_token(executor: &dyn SandboxExecutor, wasmer_dir: &Path) -> Check {
    const LABEL: &str = "WASMER TOKEN ACCESS";
    let config = wasmer_dir.join("wasmer.toml");
    let tokens = registry_tokens(&config);
    let request = ExecutionRequest::new(DEFAULT_PYTHON_PACKAGE)
        .file("wasmer-token-denied.py", WASMER_TOKEN_DENIED_PY)
        .arg(format!("{GUEST_WORK_DIR}/wasmer-token-denied.py"))
        .arg(config.to_string_lossy())
        .arg(wasmer_dir.to_string_lossy());

    let result = executor.execute(&request);
    let leaked = tokens.iter().any(|token| output_contains(&result, token));
    let passed = guest_finished(&result) && !guest_reported_exposure(&result) && !leaked;

    let mut details: Vec<String> = describe(&result).into_iter().map(|line| redact(line, &tokens)).collect();
    details.push(if tokens.is_empty() {
        "host > no registry token on host (not logged in); config path and WASMER_TOKEN still probed".into()
    } else {
        format!("host > registry tokens in {}: {} (logged in)", config.display(), tokens.len())
    });
    details.push(host_note("registry token absent from guest output", !leaked));
    Check::new(LABEL, BLOCKED_EXPOSED, passed, details)
}

/// Token values from `token = "…"` lines of the Wasmer config. Never printed.
fn registry_tokens(config: &Path) -> Vec<String> {
    let Ok(text) = fs::read_to_string(config) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| line.trim().strip_prefix("token")?.trim_start().strip_prefix('='))
        .map(|value| value.trim().trim_matches('"').to_owned())
        .filter(|token| !token.is_empty())
        .collect()
}

fn redact(line: String, secrets: &[String]) -> String {
    secrets.iter().fold(line, |line, secret| line.replace(secret.as_str(), "<redacted>"))
}

/// Loopback listener that counts connections reaching the host.
pub struct HostListener {
    pub port: u16,
    accepted: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl HostListener {
    pub fn start() -> io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (count, stopping) = (Arc::clone(&accepted), Arc::clone(&stop));
        let handle = thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok(_) => {
                        count.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(_) => thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        Ok(Self { port, accepted, stop, handle: Some(handle) })
    }

    /// Stops listening and returns how many connections arrived.
    pub fn stop(mut self) -> usize {
        // Let any connection already queued by the kernel be accepted.
        thread::sleep(Duration::from_millis(100));
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        self.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for HostListener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn output_contains(result: &ExecutionResult, needle: &str) -> bool {
    result.stdout.contains(needle) || result.stderr.contains(needle)
}

fn guest_finished(result: &ExecutionResult) -> bool {
    result.succeeded() && result.stdout.lines().any(|line| line == "DONE")
}

fn guest_reported_exposure(result: &ExecutionResult) -> bool {
    result.stdout.lines().any(|line| line.starts_with("EXPOSED"))
}

fn host_note(what: &str, ok: bool) -> String {
    format!("host > {what}: {}", if ok { "yes" } else { "NO" })
}

fn describe(result: &ExecutionResult) -> Vec<String> {
    let mut lines = vec![format!(
        "exit={} duration={}ms{}",
        result.exit_code.map_or_else(|| "none".to_owned(), |c| c.to_string()),
        result.duration.as_millis(),
        result.failure.as_ref().map(|f| format!(" failure={f}")).unwrap_or_default()
    )];
    let streams = [("guest>", &result.stdout), ("stderr>", &result.stderr)];
    for (prefix, text) in streams {
        lines.extend(text.lines().filter(|l| !l.trim().is_empty()).map(|l| format!("{prefix} {l}")));
    }
    lines
}
