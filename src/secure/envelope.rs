//! Public wire values and canonical inputs. This module never handles secrets.
use super::SecureError;
use crate::v2::canon;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Hello,
    Ack,
    Msg,
}

// An absent optional member is allowed; explicit JSON null is not a wire value.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecureEnvelope {
    pub v: u8,
    pub kind: Kind,
    pub from: String,
    pub to: String,
    pub contract: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub sid: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub seq: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub epub: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub nonce: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub sig: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub ct: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub ts: Option<String>,
}

pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}
pub fn decode_hex(s: &str) -> Result<Vec<u8>, SecureError> {
    if s.len() % 2 != 0
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SecureError::SchemaViolation);
    }
    fn digit(b: u8) -> u8 {
        if b <= b'9' {
            b - b'0'
        } else {
            b - b'a' + 10
        }
    }
    Ok(s.as_bytes()
        .chunks_exact(2)
        .map(|c| digit(c[0]) * 16 + digit(c[1]))
        .collect())
}
fn fixed_hex(s: &str, len: usize) -> bool {
    s.len() == len * 2 && decode_hex(s).is_ok()
}
fn urn(s: &str) -> bool {
    s.strip_prefix("urn:hacp:agent:").is_some_and(|name| {
        !name.is_empty()
            && name.as_bytes()[0].is_ascii_alphanumeric()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

impl SecureEnvelope {
    pub fn from_json(bytes: &[u8]) -> Result<Self, SecureError> {
        // Direct struct deserialization also rejects duplicate keys, before normalization.
        let env: Self = serde_json::from_slice(bytes).map_err(|_| SecureError::SchemaViolation)?;
        env.validate()?;
        Ok(env)
    }
    fn header(&self) -> Result<(), SecureError> {
        let bad = SecureError::SchemaViolation;
        if self.v != 1 || !urn(&self.from) || !urn(&self.to) {
            return Err(bad);
        }
        if !self.contract.is_empty()
            && !self
                .contract
                .strip_prefix("sha256:")
                .is_some_and(|s| fixed_hex(s, 32))
        {
            return Err(bad);
        }
        for (value, len) in [
            (&self.sid, 16),
            (&self.epub, 32),
            (&self.nonce, 32),
            (&self.sig, 64),
        ] {
            if value.as_deref().is_some_and(|s| !fixed_hex(s, len)) {
                return Err(bad);
            }
        }
        if self
            .ct
            .as_deref()
            .is_some_and(|s| s.len() < 32 || decode_hex(s).is_err())
        {
            return Err(bad);
        }
        if self
            .ts
            .as_deref()
            .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_err())
        {
            return Err(bad);
        }
        match self.kind {
            Kind::Hello | Kind::Ack => {
                if !self.contract.is_empty() || self.epub.is_none() || self.nonce.is_none() {
                    return Err(bad);
                }
                if self.kind == Kind::Ack && self.sid.is_none() {
                    return Err(bad);
                }
            }
            Kind::Msg => {
                if self.sid.is_none() || self.seq.is_none() {
                    return Err(bad);
                }
            }
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), SecureError> {
        self.header()?;
        if self.sig.is_none() || (self.kind == Kind::Msg && self.ct.is_none()) {
            return Err(SecureError::SchemaViolation);
        }
        Ok(())
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SecureError> {
        self.validate()?;
        let value = serde_json::to_value(self).map_err(|_| SecureError::SchemaViolation)?;
        canon::canonical_json(&value)
            .map(String::into_bytes)
            .map_err(|_| SecureError::SchemaViolation)
    }
    pub fn aad_bytes(&self) -> Result<Vec<u8>, SecureError> {
        self.header()?;
        let mut value = serde_json::to_value(self).map_err(|_| SecureError::SchemaViolation)?;
        let obj = value.as_object_mut().ok_or(SecureError::SchemaViolation)?;
        obj.remove("ct");
        obj.remove("sig");
        canon::canonical_json(&value)
            .map(String::into_bytes)
            .map_err(|_| SecureError::SchemaViolation)
    }
    pub fn message_signing_input(&self) -> Result<Vec<u8>, SecureError> {
        if self.kind != Kind::Msg {
            return Err(SecureError::SchemaViolation);
        }
        let mut bytes = b"HACP-SECURE/v1/msg".to_vec();
        bytes.extend(self.aad_bytes()?);
        bytes.extend(decode_hex(
            self.ct.as_deref().ok_or(SecureError::SchemaViolation)?,
        )?);
        Ok(bytes)
    }
    pub fn hello_signing_input(&self, hacp_session: &str) -> Result<Vec<u8>, SecureError> {
        self.header()?;
        if self.kind != Kind::Hello {
            return Err(SecureError::SchemaViolation);
        }
        let mut bytes = b"HACP-SECURE/v1/hello".to_vec();
        for s in [hacp_session, self.from.as_str(), self.to.as_str()] {
            bytes.extend_from_slice(s.as_bytes());
        }
        bytes.extend(decode_hex(
            self.epub.as_deref().ok_or(SecureError::SchemaViolation)?,
        )?);
        bytes.extend(decode_hex(
            self.nonce.as_deref().ok_or(SecureError::SchemaViolation)?,
        )?);
        Ok(bytes)
    }
    pub fn ack_signing_input(
        &self,
        hacp_session: &str,
        hello: &Self,
    ) -> Result<Vec<u8>, SecureError> {
        self.header()?;
        hello.header()?;
        if self.kind != Kind::Ack
            || hello.kind != Kind::Hello
            || self.from != hello.to
            || self.to != hello.from
        {
            return Err(SecureError::SchemaViolation);
        }
        let mut bytes = b"HACP-SECURE/v1/ack".to_vec();
        for s in [hacp_session, self.from.as_str(), self.to.as_str()] {
            bytes.extend_from_slice(s.as_bytes());
        }
        for field in [&hello.epub, &hello.nonce, &self.epub, &self.nonce] {
            bytes.extend(decode_hex(
                field.as_deref().ok_or(SecureError::SchemaViolation)?,
            )?);
        }
        Ok(bytes)
    }
}
