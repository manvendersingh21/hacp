//! Agent-facing CLI: only the frozen guardian operations, never keys or bypasses.
use base64::{engine::general_purpose::STANDARD, Engine};
use hacp::secure::{client, SecureError};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::PathBuf};

fn run() -> Result<Value, SecureError> {
    let mut command = None;
    let mut flags = BTreeMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg.starts_with("--") {
            let val = args.next().ok_or(SecureError::SchemaViolation)?;
            if val.starts_with("--") || flags.insert(arg, val).is_some() {
                return Err(SecureError::SchemaViolation);
            }
        } else if command.replace(arg).is_some() {
            return Err(SecureError::SchemaViolation);
        }
    }
    let command = command.ok_or(SecureError::UnknownOperation)?;
    let allowed: &[&str] = match command.as_str() {
        "session" => &["--peer", "--hacp-session"],
        "send" => &["--sid", "--contract", "--payload-file"],
        "recv" => &["--hacp-session"],
        "status" | "fingerprint" => &[],
        _ => return Err(SecureError::UnknownOperation),
    };
    if flags.keys().any(|key| {
        !allowed.contains(&key.as_str()) && !["--socket", "--agent"].contains(&key.as_str())
    }) {
        return Err(SecureError::SchemaViolation);
    }
    let required = |key: &str| flags.get(key).cloned().ok_or(SecureError::SchemaViolation);
    let socket = if let Some(path) = flags.get("--socket") {
        PathBuf::from(path)
    } else {
        let root =
            std::env::var_os("HACP_SECURE_RUNTIME").ok_or(SecureError::GuardianUnavailable)?;
        let agent = flags
            .get("--agent")
            .cloned()
            .or_else(|| std::env::var("HACP_SECURE_AGENT").ok())
            .ok_or(SecureError::SchemaViolation)?;
        let agent = agent.strip_prefix("urn:hacp:agent:").unwrap_or(&agent);
        if agent.is_empty()
            || !agent
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(SecureError::SchemaViolation);
        }
        PathBuf::from(root).join(agent).join("guardian.sock")
    };
    let request = match command.as_str() {
        "session" => {
            json!({"op":"session","peer":required("--peer")?,"hacp_session":required("--hacp-session")?})
        }
        "send" => {
            let payload = std::fs::read(required("--payload-file")?)
                .map_err(|_| SecureError::SchemaViolation)?;
            json!({"op":"seal","sid":required("--sid")?,"contract":flags.get("--contract").cloned().unwrap_or_default(),"payload_b64":STANDARD.encode(payload)})
        }
        "recv" => json!({"op":"open","hacp_session":required("--hacp-session")?}),
        "status" => json!({"op":"status"}),
        "fingerprint" => json!({"op":"fingerprint"}),
        _ => unreachable!(),
    };
    client::request(&socket, &request)
}
fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            println!(
                "{}",
                json!({"ok":false,"error":error.to_string(),"detail":"secure operation failed"})
            );
            std::process::exit(1);
        }
    }
}
