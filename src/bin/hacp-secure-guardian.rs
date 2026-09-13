//! Operator-only guardian provisioning and service. No secret input/output flags exist.
use hacp::secure::{
    guardian::{self, Guardian, Mode},
    SecureError,
};
use serde_json::json;
use std::path::PathBuf;
fn main() {
    if let Err(e) = run() {
        eprintln!("{}", json!({"ok":false,"error":e,"detail":e.to_string()}));
        std::process::exit(1);
    }
}
fn run() -> Result<(), SecureError> {
    let mut args = std::env::args().skip(1);
    let op = args.next().ok_or(SecureError::UnknownOperation)?;
    let mut opts = std::collections::BTreeMap::new();
    let mut degraded = false;
    while let Some(k) = args.next() {
        if k == "--degraded" {
            degraded = true;
            continue;
        }
        if ![
            "--store",
            "--agent",
            "--peer",
            "--pub",
            "--require-secure",
            "--project",
            "--socket",
            "--agent-uid",
        ]
        .contains(&k.as_str())
        {
            return Err(SecureError::SchemaViolation);
        }
        let v = args.next().ok_or(SecureError::SchemaViolation)?;
        if opts.insert(k, v).is_some() {
            return Err(SecureError::SchemaViolation);
        }
    }
    let required = |key: &str| opts.get(key).cloned().ok_or(SecureError::SchemaViolation);
    let store = PathBuf::from(required("--store")?);
    match op.as_str() {
        "init" => {
            let fp = guardian::initialize(&store, &required("--agent")?)?;
            println!("{}", json!({"ok":true,"ed25519_pub_fingerprint":fp}));
        }
        "pin" => {
            let secure = match opts
                .get("--require-secure")
                .map(String::as_str)
                .unwrap_or("true")
            {
                "true" => true,
                "false" => false,
                _ => return Err(SecureError::SchemaViolation),
            };
            guardian::pin_peer(&store, &required("--peer")?, &required("--pub")?, secure)?;
            println!("{}", json!({"ok":true}));
        }
        "serve" => {
            let mode = if degraded {
                Mode::Degraded
            } else {
                Mode::Standard {
                    agent_uid: required("--agent-uid")?
                        .parse()
                        .map_err(|_| SecureError::SchemaViolation)?,
                }
            };
            let mut guardian =
                Guardian::load(&store, &PathBuf::from(required("--project")?), mode)?;
            guardian.serve(&PathBuf::from(required("--socket")?))?;
        }
        _ => return Err(SecureError::UnknownOperation),
    }
    Ok(())
}
