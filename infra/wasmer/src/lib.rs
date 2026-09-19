//! Wasmer sandbox adapter for HACP — hackathon proof of concept.
//!
//! The boundary HACP will call later is [`SandboxExecutor::execute`]: an
//! [`ExecutionRequest`] goes in, an [`ExecutionResult`] comes out.
//!
//! Isolation rules enforced by [`WasmerCliExecutor`]:
//!
//! * The guest sees no host directory except a fresh, per-execution staging
//!   directory mounted at [`GUEST_WORK_DIR`]. Files enter it only as in-memory
//!   bytes carried by the request; a request cannot name a host path.
//! * The Wasmer process is spawned with a cleared environment, so no host
//!   variable (secrets, `FORWARD_HOST_ENV`, registry tokens) reaches the
//!   guest. Guest variables come only from [`Capability::Env`].
//! * Networking is off unless [`Capability::Network`] grants explicit allow
//!   rules.
//! * Stdin is closed, runs are bounded by a wall-clock timeout, and captured
//!   output is capped.
//!
//! The executor itself never sees HACP Secure. [`execution`] connects it to a
//! guardian through the key-free client only: guardian keys, session state and
//! envelopes never enter this crate.

pub mod demo;
pub mod execution;

use std::env;
use std::fmt;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Guest directory where explicitly provided files are staged.
pub const GUEST_WORK_DIR: &str = "/work";

/// Pinned Python package used by the demo and tests.
pub const DEFAULT_PYTHON_PACKAGE: &str = "python/python@3.13.20";

/// Environment keys with this prefix are refused as guest variables: HACP
/// runtime values never enter the sandbox, even by explicit grant.
pub const RESERVED_ENV_PREFIX: &str = "HACP_";

/// What to run and exactly what it may touch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionRequest {
    /// Wasmer package to run, e.g. `python/python@3.13.20`. Must be on the
    /// executor's allowlist.
    pub package: String,
    /// Arguments passed to the package's entrypoint.
    pub args: Vec<String>,
    /// Files staged under [`GUEST_WORK_DIR`]. Contents are bytes, never host
    /// paths.
    pub files: Vec<SandboxFile>,
    /// Capabilities explicitly granted to this run. Everything else is denied.
    pub capabilities: Vec<Capability>,
    pub limits: ResourceLimits,
}

impl ExecutionRequest {
    pub fn new(package: impl Into<String>) -> Self {
        Self {
            package: package.into(),
            args: Vec::new(),
            files: Vec::new(),
            capabilities: Vec::new(),
            limits: ResourceLimits::default(),
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn file(mut self, path: impl Into<String>, contents: impl Into<Vec<u8>>) -> Self {
        self.files.push(SandboxFile {
            path: path.into(),
            contents: contents.into(),
        });
        self
    }

    pub fn grant(mut self, capability: Capability) -> Self {
        self.capabilities.push(capability);
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.limits.timeout = timeout;
        self
    }
}

/// A file handed to the guest by value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxFile {
    /// Path relative to [`GUEST_WORK_DIR`], e.g. `src/main.py`.
    pub path: String,
    pub contents: Vec<u8>,
}

/// A capability the guest does not have unless it is listed in the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// One guest environment variable. The host environment is never
    /// forwarded.
    Env { key: String, value: String },
    /// Network access limited to Wasmer `--net` allow rules, e.g.
    /// `ipv4:allow=127.0.0.1:8080` or `dns:allow=example.com:443`.
    Network { rules: Vec<String> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Wall-clock limit; the runtime is killed when it expires.
    pub timeout: Duration,
    /// Bytes kept per output stream; the rest is drained and dropped.
    pub max_output_bytes: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_output_bytes: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    /// Exit code of the guest (or of the Wasmer CLI if it failed before the
    /// guest started). `None` when the run was killed or never started.
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// True when either stream exceeded `max_output_bytes`.
    pub output_truncated: bool,
    pub duration: Duration,
    /// Why the execution itself failed, as opposed to the guest exiting
    /// non-zero.
    pub failure: Option<ExecutionFailure>,
}

impl ExecutionResult {
    pub fn succeeded(&self) -> bool {
        self.failure.is_none() && self.exit_code == Some(0)
    }

    fn failed(failure: ExecutionFailure, started: Instant) -> Self {
        Self {
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            output_truncated: false,
            duration: started.elapsed(),
            failure: Some(failure),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionFailure {
    /// The request asked for something the executor refuses to grant.
    InvalidRequest(String),
    /// The Wasmer runtime could not be found or started.
    RuntimeUnavailable(String),
    /// The run exceeded its timeout and was killed.
    TimedOut(Duration),
    /// Staging, spawning or waiting failed on the host.
    Io(String),
}

impl fmt::Display for ExecutionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(msg) => write!(f, "invalid execution request: {msg}"),
            Self::RuntimeUnavailable(msg) => write!(f, "wasmer runtime unavailable: {msg}"),
            Self::TimedOut(after) => write!(f, "execution timed out after {after:?}"),
            Self::Io(msg) => write!(f, "sandbox host error: {msg}"),
        }
    }
}

impl std::error::Error for ExecutionFailure {}

/// The adapter boundary HACP will call.
pub trait SandboxExecutor {
    fn execute(&self, request: &ExecutionRequest) -> ExecutionResult;
}

/// Runs requests with the `wasmer` CLI.
#[derive(Debug, Clone)]
pub struct WasmerCliExecutor {
    wasmer_bin: PathBuf,
    wasmer_dir: PathBuf,
    staging_root: PathBuf,
    allowed_packages: Vec<String>,
}

impl WasmerCliExecutor {
    pub fn new(
        wasmer_bin: impl Into<PathBuf>,
        wasmer_dir: impl Into<PathBuf>,
        allowed_packages: Vec<String>,
    ) -> Self {
        Self {
            wasmer_bin: wasmer_bin.into(),
            wasmer_dir: wasmer_dir.into(),
            staging_root: env::temp_dir(),
            allowed_packages,
        }
    }

    /// Locates Wasmer on this host: `HACP_WASMER_BIN`, else `wasmer` on
    /// `PATH`; Wasmer home from `WASMER_DIR`, else `$HOME/.wasmer`. These
    /// configure the runtime process only — none of them reaches the guest.
    pub fn from_host(allowed_packages: Vec<String>) -> Result<Self, ExecutionFailure> {
        let bin = match env::var_os("HACP_WASMER_BIN") {
            Some(path) => PathBuf::from(path),
            None => find_on_path("wasmer").ok_or_else(|| {
                ExecutionFailure::RuntimeUnavailable(
                    "`wasmer` not found on PATH; install it (see infra/wasmer/README.md) or set HACP_WASMER_BIN".into(),
                )
            })?,
        };
        let dir = env::var_os("WASMER_DIR")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".wasmer")))
            .ok_or_else(|| {
                ExecutionFailure::RuntimeUnavailable(
                    "cannot locate the Wasmer home directory; set WASMER_DIR".into(),
                )
            })?;
        Ok(Self::new(bin, dir, allowed_packages))
    }

    /// Where per-execution staging directories are created.
    pub fn with_staging_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.staging_root = root.into();
        self
    }

    /// The Wasmer home the runtime process uses (holds cache and registry
    /// credentials). Never mounted into the guest.
    pub fn wasmer_dir(&self) -> &Path {
        &self.wasmer_dir
    }

    pub fn runtime_version(&self) -> Result<String, ExecutionFailure> {
        let unavailable =
            |msg: String| ExecutionFailure::RuntimeUnavailable(format!("{}: {msg}", self.wasmer_bin.display()));
        let output = Command::new(&self.wasmer_bin)
            .env_clear()
            .env("WASMER_DIR", &self.wasmer_dir)
            .arg("--version")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| unavailable(e.to_string()))?;
        if !output.status.success() {
            return Err(unavailable(String::from_utf8_lossy(&output.stderr).trim().to_owned()));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    fn validate(&self, request: &ExecutionRequest) -> Result<(), ExecutionFailure> {
        let invalid = |msg: String| Err(ExecutionFailure::InvalidRequest(msg));
        if !self.allowed_packages.iter().any(|p| p == &request.package) {
            return invalid(format!("package `{}` is not on the executor allowlist", request.package));
        }
        if request.limits.timeout.is_zero() {
            return invalid("timeout must be greater than zero".into());
        }
        for file in &request.files {
            let path = Path::new(&file.path);
            let confined = !file.path.is_empty()
                && !file.path.contains('\0')
                && path.components().all(|c| matches!(c, Component::Normal(_)));
            if !confined {
                return invalid(format!(
                    "file path `{}` must be relative to {GUEST_WORK_DIR} with no root, `.` or `..`",
                    file.path
                ));
            }
        }
        for capability in &request.capabilities {
            match capability {
                Capability::Env { key, value } => {
                    let well_formed = key.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
                    if !well_formed || value.contains('\0') {
                        return invalid(format!("malformed environment variable `{key}`"));
                    }
                    if key.to_ascii_uppercase().starts_with(RESERVED_ENV_PREFIX) {
                        return invalid(format!(
                            "environment variable `{key}` uses the reserved {RESERVED_ENV_PREFIX} prefix"
                        ));
                    }
                }
                Capability::Network { rules } => {
                    // An empty rule list would become a bare `--net`: full host networking.
                    if rules.is_empty() {
                        return invalid("network capability needs at least one explicit allow rule".into());
                    }
                    for rule in rules {
                        let allow_rule = rule.contains(":allow=")
                            && !rule.contains(',')
                            && !rule.chars().any(char::is_whitespace);
                        if !allow_rule {
                            return invalid(format!("network rule `{rule}` is not a single allow rule"));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn command(&self, request: &ExecutionRequest, run_dir: &Path, work_dir: &Path) -> Result<Command, ExecutionFailure> {
        let work = work_dir.to_str().filter(|p| !p.contains(':')).ok_or_else(|| {
            ExecutionFailure::Io(format!("staging directory {} cannot be used as a volume", work_dir.display()))
        })?;

        let mut cmd = Command::new(&self.wasmer_bin);
        // Never inherit the host environment: WASMER_DIR is all the runtime
        // process needs, and the guest does not see it.
        cmd.env_clear()
            .env("WASMER_DIR", &self.wasmer_dir)
            .current_dir(run_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .args(["run", "--quiet", "--no-tty", "--volume"])
            .arg(format!("{work}:{GUEST_WORK_DIR}"));

        let mut net_rules = Vec::new();
        for capability in &request.capabilities {
            match capability {
                Capability::Env { key, value } => {
                    cmd.arg("--env").arg(format!("{key}={value}"));
                }
                Capability::Network { rules } => net_rules.extend(rules.iter().map(String::as_str)),
            }
        }
        if !net_rules.is_empty() {
            cmd.arg(format!("--net={}", net_rules.join(",")));
        }
        cmd.arg(&request.package).arg("--").args(&request.args);
        Ok(cmd)
    }

    fn run(&self, request: &ExecutionRequest, run_dir: &Path, started: Instant) -> ExecutionResult {
        let work_dir = run_dir.join("work");
        if let Err(e) = stage_files(&work_dir, &request.files) {
            return ExecutionResult::failed(ExecutionFailure::Io(format!("staging files: {e}")), started);
        }
        let mut cmd = match self.command(request, run_dir, &work_dir) {
            Ok(cmd) => cmd,
            Err(failure) => return ExecutionResult::failed(failure, started),
        };
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let msg = format!("{}: {e}", self.wasmer_bin.display());
                return ExecutionResult::failed(ExecutionFailure::RuntimeUnavailable(msg), started);
            }
            Err(e) => {
                return ExecutionResult::failed(ExecutionFailure::Io(format!("spawning wasmer: {e}")), started)
            }
        };

        let cap = request.limits.max_output_bytes;
        let stdout = capture(child.stdout.take(), cap);
        let stderr = capture(child.stderr.take(), cap);
        let waited = wait_with_timeout(&mut child, request.limits.timeout);
        let (stdout, stdout_truncated) = stdout.join().unwrap_or_default();
        let (stderr, stderr_truncated) = stderr.join().unwrap_or_default();

        let (exit_code, failure) = match waited {
            Ok(Some(status)) => match status.code() {
                Some(code) => (Some(code), None),
                None => (None, Some(ExecutionFailure::Io(format!("wasmer terminated abnormally: {status}")))),
            },
            Ok(None) => (None, Some(ExecutionFailure::TimedOut(request.limits.timeout))),
            Err(e) => (None, Some(ExecutionFailure::Io(format!("waiting for wasmer: {e}")))),
        };
        ExecutionResult {
            exit_code,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            output_truncated: stdout_truncated || stderr_truncated,
            duration: started.elapsed(),
            failure,
        }
    }
}

impl SandboxExecutor for WasmerCliExecutor {
    fn execute(&self, request: &ExecutionRequest) -> ExecutionResult {
        let started = Instant::now();
        if let Err(failure) = self.validate(request) {
            return ExecutionResult::failed(failure, started);
        }
        let run_dir = match create_run_dir(&self.staging_root) {
            Ok(dir) => dir,
            Err(e) => {
                return ExecutionResult::failed(ExecutionFailure::Io(format!("creating staging directory: {e}")), started)
            }
        };
        let result = self.run(request, &run_dir, started);
        // Anything the guest wrote to /work is discarded with the run.
        let _ = fs::remove_dir_all(&run_dir);
        result
    }
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    env::split_paths(&env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

fn create_run_dir(root: &Path) -> io::Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let dir = root.join(format!(
        "hacp-wasmer-{}-{nanos}-{}",
        std::process::id(),
        RUN_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    // `create`, not `create_all`: fails rather than reuse an existing directory.
    builder.create(&dir)?;
    Ok(dir)
}

fn stage_files(work_dir: &Path, files: &[SandboxFile]) -> io::Result<()> {
    fs::create_dir(work_dir)?;
    for file in files {
        let dest = work_dir.join(&file.path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest)?
            .write_all(&file.contents)?;
    }
    Ok(())
}

fn capture<R: Read + Send + 'static>(stream: Option<R>, limit: usize) -> JoinHandle<(Vec<u8>, bool)> {
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut truncated = false;
        let Some(mut stream) = stream else {
            return (kept, truncated);
        };
        let mut buf = [0u8; 8192];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let room = limit.saturating_sub(kept.len());
                    kept.extend_from_slice(&buf[..n.min(room)]);
                    truncated |= n > room;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        (kept, truncated)
    })
}

/// `Ok(None)` means the timeout expired and the child was killed.
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                child.wait()?;
                return Ok(None);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offline_executor() -> WasmerCliExecutor {
        WasmerCliExecutor::new("/nonexistent/wasmer", "/nonexistent/.wasmer", vec![DEFAULT_PYTHON_PACKAGE.into()])
    }

    fn rejection(request: ExecutionRequest) -> String {
        match offline_executor().execute(&request).failure {
            Some(ExecutionFailure::InvalidRequest(msg)) => msg,
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    fn python() -> ExecutionRequest {
        ExecutionRequest::new(DEFAULT_PYTHON_PACKAGE)
    }

    #[test]
    fn rejects_packages_outside_the_allowlist() {
        assert!(rejection(ExecutionRequest::new("wasmer/bash")).contains("allowlist"));
        assert!(rejection(ExecutionRequest::new("python/python")).contains("allowlist"));
    }

    #[test]
    fn rejects_file_paths_that_leave_the_work_dir() {
        for path in ["", "/etc/passwd", "../secret", "a/../../b", "./x"] {
            assert!(rejection(python().file(path, "x")).contains("must be relative"), "{path}");
        }
    }

    #[test]
    fn rejects_hacp_and_malformed_env_grants() {
        let env = |key: &str| Capability::Env { key: key.into(), value: "v".into() };
        assert!(rejection(python().grant(env("HACP_GUARDIAN_KEY"))).contains("reserved"));
        assert!(rejection(python().grant(env("hacp_session"))).contains("reserved"));
        assert!(rejection(python().grant(env("BAD=KEY"))).contains("malformed"));
        assert!(rejection(python().grant(env("1ABC"))).contains("malformed"));
    }

    #[test]
    fn rejects_blanket_or_non_allow_network_grants() {
        let net = |rules: &[&str]| Capability::Network { rules: rules.iter().map(|r| r.to_string()).collect() };
        assert!(rejection(python().grant(net(&[]))).contains("at least one"));
        assert!(rejection(python().grant(net(&["dns:deny=evil.test:*"]))).contains("allow rule"));
        assert!(rejection(python().grant(net(&["ipv4:allow=1.2.3.4:80,ipv4:allow=*:*"]))).contains("allow rule"));
    }

    #[test]
    fn rejects_zero_timeout() {
        assert!(rejection(python().timeout(Duration::ZERO)).contains("timeout"));
    }

    #[test]
    fn missing_runtime_is_reported_and_staging_is_cleaned_up() {
        let root = env::temp_dir().join(format!("hacp-wasmer-unit-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let result = offline_executor()
            .with_staging_root(&root)
            .execute(&python().file("dir/main.py", "print(1)"));
        let leftovers = fs::read_dir(&root).unwrap().count();
        fs::remove_dir_all(&root).unwrap();
        assert!(matches!(result.failure, Some(ExecutionFailure::RuntimeUnavailable(_))), "{result:?}");
        assert_eq!(leftovers, 0, "staging directory was not removed");
    }
}
