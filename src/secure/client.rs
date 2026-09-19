//! Key-free guardian client. Failed IPC never falls back to the shared edge.
use super::SecureError;
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    time::Duration,
};

const MAX_RESPONSE: u64 = 16 * 1024 * 1024;

#[cfg(unix)]
pub fn request(socket: &Path, request: &Value) -> Result<Value, SecureError> {
    use std::os::unix::net::UnixStream;
    let unavailable = || SecureError::GuardianUnavailable;
    let mut stream = UnixStream::connect(socket).map_err(|_| unavailable())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| unavailable())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .map_err(|_| unavailable())?;
    let mut bytes = serde_json::to_vec(request).map_err(|_| SecureError::SchemaViolation)?;
    if bytes.len() as u64 >= MAX_RESPONSE {
        return Err(SecureError::SchemaViolation);
    }
    bytes.push(b'\n');
    stream.write_all(&bytes).map_err(|_| unavailable())?;
    let mut line = Vec::new();
    BufReader::new(stream.take(MAX_RESPONSE + 1))
        .read_until(b'\n', &mut line)
        .map_err(|_| unavailable())?;
    if line.len() as u64 > MAX_RESPONSE || line.last() != Some(&b'\n') {
        return Err(unavailable());
    }
    let response: Value = serde_json::from_slice(&line).map_err(|_| unavailable())?;
    match response.get("ok").and_then(Value::as_bool) {
        Some(true) => Ok(response),
        Some(false) => Err(response
            .get("error")
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_else(unavailable)),
        None => Err(unavailable()),
    }
}
#[cfg(not(unix))]
pub fn request(_socket: &Path, _request: &Value) -> Result<Value, SecureError> {
    Err(SecureError::GuardianUnavailable)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    fn reply(bytes: &'static [u8]) -> Result<Value, SecureError> {
        let path = std::env::temp_dir().join(format!("hacp-client-{}.sock", uuid::Uuid::new_v4()));
        let listener = UnixListener::bind(&path).unwrap();
        let task = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(socket.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&line).unwrap()["op"],
                "status"
            );
            socket.write_all(bytes).unwrap();
        });
        let result = request(&path, &serde_json::json!({"op":"status"}));
        task.join().unwrap();
        std::fs::remove_file(path).unwrap();
        result
    }
    #[test]
    fn valid_response_and_fixed_error() {
        assert_eq!(
            reply(b"{\"ok\":true,\"mode\":\"degraded\"}\n").unwrap()["mode"],
            "degraded"
        );
        assert_eq!(
            reply(b"{\"ok\":false,\"error\":\"ReplayRejected\",\"detail\":\"untrusted-canary\"}\n")
                .err(),
            Some(SecureError::ReplayRejected)
        );
    }
    #[test]
    fn malformed_truncated_or_unknown_error_fails_closed() {
        for line in [
            b"plaintext-canary\n".as_slice(),
            b"{\"ok\":true}",
            b"{}\n",
            b"{\"ok\":false,\"error\":\"canary\"}\n",
        ] {
            assert_eq!(reply(line).err(), Some(SecureError::GuardianUnavailable));
        }
    }
    #[test]
    fn absent_guardian_fails_closed() {
        assert_eq!(
            request(
                &std::env::temp_dir().join(uuid::Uuid::new_v4().to_string()),
                &serde_json::json!({"op":"seal","payload_b64":"canary"})
            )
            .err(),
            Some(SecureError::GuardianUnavailable)
        );
    }
}
