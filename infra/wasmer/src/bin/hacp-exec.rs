//! Requesting peer's client (key-free): sends one execution request over HACP
//! Secure and prints the result that comes back.
//!
//! usage: hacp-exec --socket PATH --agent URN --peer URN --context HACP_SESSION
//!                  --contract sha256:DIGEST --package PKG [--file GUEST_PATH=LOCAL_PATH]...
//!                  [--arg ARG]... [--env KEY=VALUE]... [--net RULE]...
//!                  [--timeout-ms N] [--max-output-bytes N] [--wait-secs N] [--no-wait]
//!
//! Exits 0 only when a result arrived over HACP Secure (or, with --no-wait,
//! when the request was sealed). Whether the guest succeeded is in the JSON.

use base64::{engine::general_purpose::STANDARD, Engine};
use hacp_wasmer_sandbox::execution::{ExecutionClient, ExecutionPayload, PayloadFile};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage: hacp-exec --socket PATH --agent URN --peer URN --context HACP_SESSION --contract sha256:DIGEST --package PKG [--file GUEST_PATH=LOCAL_PATH]... [--arg ARG]... [--env KEY=VALUE]... [--net RULE]... [--timeout-ms N] [--max-output-bytes N] [--wait-secs N] [--no-wait]";

fn main() -> ExitCode {
    match run() {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(output) => {
            println!("{output}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<serde_json::Value, serde_json::Value> {
    let fail = |error: String| json!({"ok": false, "error": error});
    let mut single = BTreeMap::new();
    let mut repeated: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut no_wait = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--no-wait" => no_wait = true,
            "--file" | "--arg" | "--env" | "--net" => {
                let key = match arg.as_str() {
                    "--file" => "file",
                    "--arg" => "arg",
                    "--env" => "env",
                    _ => "net",
                };
                repeated.entry(key).or_default().push(args.next().ok_or_else(|| fail(USAGE.into()))?);
            }
            "--socket" | "--agent" | "--peer" | "--context" | "--contract" | "--package" | "--timeout-ms"
            | "--max-output-bytes" | "--wait-secs" => {
                let value = args.next().ok_or_else(|| fail(USAGE.into()))?;
                if single.insert(arg, value).is_some() {
                    return Err(fail(USAGE.into()));
                }
            }
            _ => return Err(fail(USAGE.into())),
        }
    }
    let required = |key: &str| single.get(key).cloned().ok_or_else(|| fail(USAGE.into()));
    let number = |key: &str, default: u64| match single.get(key) {
        Some(value) => value.parse::<u64>().map_err(|_| fail(format!("{key} must be a number"))),
        None => Ok(default),
    };
    let mut take = |key: &str| repeated.remove(key).unwrap_or_default();

    let mut files = Vec::new();
    for spec in take("file") {
        let (guest, local) = spec.split_once('=').ok_or_else(|| fail(format!("--file expects GUEST_PATH=LOCAL_PATH, got `{spec}`")))?;
        let contents = std::fs::read(local).map_err(|e| fail(format!("reading {local}: {e}")))?;
        files.push(PayloadFile { path: guest.into(), content_b64: STANDARD.encode(contents) });
    }
    let mut env = BTreeMap::new();
    for spec in take("env") {
        let (key, value) = spec.split_once('=').ok_or_else(|| fail(format!("--env expects KEY=VALUE, got `{spec}`")))?;
        env.insert(key.to_owned(), value.to_owned());
    }
    let payload = ExecutionPayload {
        package: required("--package")?,
        args: take("arg"),
        files,
        env,
        network: take("net"),
        timeout_ms: number("--timeout-ms", 10_000)?,
        max_output_bytes: match single.get("--max-output-bytes") {
            Some(_) => Some(number("--max-output-bytes", 0)? as usize),
            None => None,
        },
    };
    let contract = required("--contract")?;
    let client = ExecutionClient::new(
        &PathBuf::from(required("--socket")?),
        &required("--agent")?,
        &required("--peer")?,
        &required("--context")?,
    )
    .map_err(|e| fail(format!("invalid identity: {e}")))?;

    let request_id = client.send(&payload, &contract).map_err(|e| fail(format!("guardian refused to seal: {e}")))?;
    if no_wait {
        return Ok(json!({"ok": true, "request_id": request_id, "sealed": true}));
    }
    let wait = Duration::from_secs(number("--wait-secs", 60)?);
    match client.await_result(&request_id, &contract, wait) {
        Ok(Some(returned)) => Ok(json!({"ok": true, "returned": returned})),
        Ok(None) => Err(json!({"ok": false, "request_id": request_id, "error": "no result before --wait-secs"})),
        Err(e) => Err(json!({"ok": false, "request_id": request_id, "error": format!("guardian: {e}")})),
    }
}
