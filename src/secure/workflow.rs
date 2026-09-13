//! Key-free HACP workflow adapter. Only guardians handle cryptography and counters.
use super::{client, SecureError};
use crate::v2::Envelope;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub struct Workflow {
    socket: PathBuf,
    local: String,
    remote: String,
    context: String,
}
/// Successful deliveries must be durably consumed even when another edge file fails.
pub struct Inbox {
    pub messages: Vec<Envelope>,
    pub errors: Vec<SecureError>,
    pub held: bool,
}
impl Workflow {
    pub fn new(
        socket: &Path,
        local: &str,
        remote: &str,
        context: &str,
    ) -> Result<Self, SecureError> {
        if socket.as_os_str().is_empty()
            || local == remote
            || context.is_empty()
            || crate::v2::envelope::agent_urn::parse(local).is_err()
            || crate::v2::envelope::agent_urn::parse(remote).is_err()
        {
            return Err(SecureError::SchemaViolation);
        }
        Ok(Self {
            socket: socket.into(),
            local: local.into(),
            remote: remote.into(),
            context: context.into(),
        })
    }
    fn session(&self) -> Result<Option<String>, SecureError> {
        let status = client::request(&self.socket, &json!({"op":"status"}))?;
        let entries = status["sessions"]
            .as_array()
            .ok_or(SecureError::GuardianUnavailable)?;
        let mut matching = entries
            .iter()
            .filter(|s| s["peer"] == self.remote && s["hacp_session"] == self.context);
        let first = matching.next();
        if matching.next().is_some() {
            return Err(SecureError::SessionUnknown);
        }
        match first {
            None => Ok(None),
            Some(s) if matches!(s["state"].as_str(), Some("Established" | "AckSent")) => {
                let sid = s["sid"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or(SecureError::SessionUnknown)?;
                Ok(Some(sid.into()))
            }
            Some(_) => Err(SecureError::SessionExpired),
        }
    }
    /// Called at peer setup; the responder establishes through receive().
    pub fn ensure_session(&self, initiator: bool) -> Result<(), SecureError> {
        if self.session()?.is_none() && initiator {
            client::request(
                &self.socket,
                &json!({"op":"session","peer":self.remote,"hacp_session":self.context}),
            )?;
        }
        Ok(())
    }
    pub fn send(&self, message: &Envelope, contract: &str) -> Result<(), SecureError> {
        message
            .validate()
            .map_err(|_| SecureError::SchemaViolation)?;
        if message.from != self.local
            || message.to != self.remote
            || message.session_id != self.context
        {
            return Err(SecureError::IdentityMismatch);
        }
        let sid = self.session()?.ok_or(SecureError::SessionUnknown)?;
        let payload = serde_json::to_vec(message).map_err(|_| SecureError::SchemaViolation)?;
        client::request(
            &self.socket,
            &json!({"op":"seal","sid":sid,"contract":contract,"payload_b64":STANDARD.encode(payload)}),
        )?;
        Ok(())
    }
    pub fn receive(&self) -> Result<Inbox, SecureError> {
        let response = client::request(
            &self.socket,
            &json!({"op":"open","hacp_session":self.context}),
        )?;
        let mut inbox = Inbox {
            messages: vec![],
            errors: vec![],
            held: false,
        };
        let delivered = response["delivered"]
            .as_array()
            .ok_or(SecureError::GuardianUnavailable)?;
        for d in delivered {
            let decoded = self.decode(d);
            match decoded {
                Ok(m) => inbox.messages.push(m),
                Err(e) => inbox.errors.push(e),
            }
        }
        for field in ["rejected", "aborted"] {
            for entry in response[field]
                .as_array()
                .ok_or(SecureError::GuardianUnavailable)?
            {
                let error = serde_json::from_value(entry["error"].clone())
                    .unwrap_or(SecureError::GuardianUnavailable);
                inbox.errors.push(error);
            }
        }
        inbox.held = !response["held"]
            .as_array()
            .ok_or(SecureError::GuardianUnavailable)?
            .is_empty();
        Ok(inbox)
    }
    fn decode(&self, d: &Value) -> Result<Envelope, SecureError> {
        if d["sid"].as_str().is_none_or(str::is_empty) {
            return Err(SecureError::DowngradeDetected);
        }
        if d["from"] != self.remote {
            return Err(SecureError::IdentityMismatch);
        }
        let bytes = STANDARD
            .decode(
                d["payload_b64"]
                    .as_str()
                    .ok_or(SecureError::SchemaViolation)?,
            )
            .map_err(|_| SecureError::SchemaViolation)?;
        let m: Envelope =
            serde_json::from_slice(&bytes).map_err(|_| SecureError::SchemaViolation)?;
        m.validate().map_err(|_| SecureError::SchemaViolation)?;
        if m.from != self.remote || m.to != self.local || m.session_id != self.context {
            return Err(SecureError::IdentityMismatch);
        }
        Ok(m)
    }
}
