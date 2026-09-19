//! Execution service for the executing peer (guardian side, key-free).
//!
//! Receives authenticated, contract-bound execution requests from the local
//! HACP Secure guardian, authorizes them against an operator policy, runs them
//! in Wasmer, and seals each result back through the same guardian.
//!
//! usage: hacp-exec-guardian --socket PATH --agent URN --context HACP_SESSION --policy FILE
//!                           [--audit FILE] [--staging-root DIR] [--poll-ms N] [--once]

use hacp_wasmer_sandbox::execution::{ExecutionPolicy, ExecutionService};
use hacp_wasmer_sandbox::WasmerCliExecutor;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::Duration;

const USAGE: &str = "usage: hacp-exec-guardian --socket PATH --agent URN --context HACP_SESSION --policy FILE [--audit FILE] [--staging-root DIR] [--poll-ms N] [--once]";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("hacp-exec-guardian: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut flags = BTreeMap::new();
    let mut once = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--once" => once = true,
            "--socket" | "--agent" | "--context" | "--policy" | "--audit" | "--staging-root" | "--poll-ms" => {
                let value = args.next().ok_or(USAGE)?;
                if flags.insert(arg, value).is_some() {
                    return Err(USAGE.into());
                }
            }
            _ => return Err(USAGE.into()),
        }
    }
    let required = |key: &str| flags.get(key).cloned().ok_or_else(|| USAGE.to_owned());
    let policy_path = required("--policy")?;
    let policy_bytes = std::fs::read(&policy_path).map_err(|e| format!("reading policy {policy_path}: {e}"))?;
    let policy: ExecutionPolicy =
        serde_json::from_slice(&policy_bytes).map_err(|e| format!("invalid policy {policy_path}: {e}"))?;
    let poll = Duration::from_millis(match flags.get("--poll-ms") {
        Some(ms) => ms.parse().map_err(|_| USAGE)?,
        None => 250,
    });

    let mut executor = WasmerCliExecutor::from_host(policy.allowed_packages.clone()).map_err(|e| e.to_string())?;
    if let Some(root) = flags.get("--staging-root") {
        executor = executor.with_staging_root(root);
    }
    let version = executor.runtime_version().map_err(|e| e.to_string())?;
    let service = ExecutionService::new(
        &PathBuf::from(required("--socket")?),
        &required("--agent")?,
        &required("--context")?,
        policy,
        executor,
    )
    .map_err(|e| format!("invalid service identity: {e}"))?;
    eprintln!("hacp-exec-guardian ready: {version}");

    let mut audit = match flags.get("--audit") {
        Some(path) => Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map_err(|e| format!("opening audit log {path}: {e}"))?,
        ),
        None => None,
    };
    loop {
        match service.step() {
            Ok(outcomes) => {
                for outcome in outcomes {
                    let line = serde_json::to_string(&outcome).map_err(|e| e.to_string())?;
                    println!("{line}");
                    if let Some(file) = audit.as_mut() {
                        writeln!(file, "{line}").map_err(|e| format!("writing audit log: {e}"))?;
                    }
                }
            }
            Err(error) if once => return Err(format!("guardian: {error}")),
            Err(error) => eprintln!("hacp-exec-guardian: guardian: {error}"),
        }
        if once {
            return Ok(());
        }
        thread::sleep(poll);
    }
}
