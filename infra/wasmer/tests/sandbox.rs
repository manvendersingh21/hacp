//! End-to-end tests against a real Wasmer runtime. Requires `wasmer` on PATH
//! (or HACP_WASMER_BIN); see README.md.

use hacp_wasmer_sandbox::demo::{self, HostListener};
use hacp_wasmer_sandbox::{
    Capability, ExecutionFailure, ExecutionRequest, SandboxExecutor, WasmerCliExecutor, DEFAULT_PYTHON_PACKAGE,
};
use std::fs;
use std::process::Command;
use std::time::Duration;

fn executor() -> WasmerCliExecutor {
    WasmerCliExecutor::from_host(vec![DEFAULT_PYTHON_PACKAGE.to_owned()])
        .expect("wasmer must be installed to run the sandbox tests (see infra/wasmer/README.md)")
}

fn python(code: &str) -> ExecutionRequest {
    ExecutionRequest::new(DEFAULT_PYTHON_PACKAGE).arg("-c").arg(code)
}

#[test]
fn normal_execution_passes() {
    let check = demo::normal_execution(&executor());
    assert!(check.passed, "{:#?}", check.details);
}

#[test]
fn host_filesystem_is_blocked() {
    let check = demo::host_filesystem(&executor());
    assert!(check.passed, "{:#?}", check.details);
}

#[test]
fn unauthorized_network_is_blocked() {
    let check = demo::unauthorized_network(&executor());
    assert!(check.passed, "{:#?}", check.details);
}

#[test]
fn wasmer_registry_token_is_blocked() {
    let executor = executor();
    let check = demo::wasmer_token(&executor, executor.wasmer_dir());
    assert!(check.passed, "{:#?}", check.details);
}

#[test]
fn demo_blocks_planted_host_secrets_end_to_end() {
    // The demo binary re-runs itself with fake HACP secrets, a fake
    // WASMER_TOKEN and FORWARD_HOST_ENV=true in its environment.
    let output = Command::new(env!("CARGO_BIN_EXE_hacp-wasmer-demo")).output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for expected in [
        "NORMAL EXECUTION: PASS",
        "HOST FILESYSTEM ACCESS: BLOCKED",
        "HOST SECRET ACCESS: BLOCKED",
        "UNAUTHORIZED NETWORK: BLOCKED",
        "WASMER TOKEN ACCESS: BLOCKED",
    ] {
        assert!(stdout.lines().any(|line| line == expected), "missing `{expected}` in:\n{stdout}");
    }
}

#[test]
fn guest_env_holds_only_package_defaults_and_explicit_grants() {
    let request = python("import os; print(sorted(os.environ))").grant(Capability::Env {
        key: "GRANTED_ONE".into(),
        value: "1".into(),
    });
    let result = executor().execute(&request);
    assert!(result.succeeded(), "{result:?}");
    assert!(result.stdout.contains("'GRANTED_ONE'"), "{}", result.stdout);
    for host_var in ["'HOME'", "'PATH'", "'USER'", "'WASMER_DIR'", "'FORWARD_HOST_ENV'"] {
        assert!(!result.stdout.contains(host_var), "{host_var} leaked: {}", result.stdout);
    }
}

#[test]
fn network_grant_is_scoped_to_its_rule() {
    let allowed = HostListener::start().unwrap();
    let other = HostListener::start().unwrap();
    let code = format!(
        "import socket\n\
         for port in ({}, {}):\n    \
             try:\n        socket.create_connection(('127.0.0.1', port), timeout=3); print(port, 'connected')\n    \
             except OSError as e:\n        print(port, 'denied', e)",
        allowed.port, other.port
    );
    let request = python(&code).grant(Capability::Network {
        rules: vec![format!("ipv4:allow=127.0.0.1:{}", allowed.port)],
    });
    let result = executor().execute(&request);
    assert!(result.succeeded(), "{result:?}");
    assert_eq!(allowed.stop(), 1, "granted port unreachable: {}", result.stdout);
    assert_eq!(other.stop(), 0, "ungranted port reached: {}", result.stdout);
}

#[test]
fn exit_code_and_both_streams_are_captured() {
    let result = executor().execute(&python("import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"));
    assert_eq!(result.exit_code, Some(3), "{result:?}");
    assert_eq!(result.failure, None);
    assert_eq!(result.stdout.trim(), "out");
    assert!(result.stderr.contains("err"), "{result:?}");
}

#[test]
fn runaway_guest_is_killed_at_timeout() {
    let result = executor().execute(&python("while True: pass").timeout(Duration::from_secs(2)));
    assert_eq!(result.failure, Some(ExecutionFailure::TimedOut(Duration::from_secs(2))), "{result:?}");
    assert!(result.duration < Duration::from_secs(10), "{result:?}");
}

#[test]
fn output_is_capped() {
    let mut request = python("print('x' * 100000)");
    request.limits.max_output_bytes = 1024;
    let result = executor().execute(&request);
    assert!(result.succeeded(), "{result:?}");
    assert_eq!(result.stdout.len(), 1024);
    assert!(result.output_truncated);
}

#[test]
fn guest_writes_are_discarded_with_the_run() {
    let root = std::env::temp_dir().join(format!("hacp-wasmer-it-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let request = python("open('/work/out.txt', 'w').write('guest output'); print(open('/work/in.txt').read())")
        .file("in.txt", "staged input");
    let result = executor().with_staging_root(&root).execute(&request);
    let leftovers = fs::read_dir(&root).unwrap().count();
    fs::remove_dir_all(&root).unwrap();
    assert!(result.succeeded(), "{result:?}");
    assert_eq!(result.stdout.trim(), "staged input");
    assert_eq!(leftovers, 0, "staging directory survived the run");
}
