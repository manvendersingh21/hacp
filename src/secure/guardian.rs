//! Guardian-private identity store, pin policy, serialized UDS service and file edge.
//! No request/response type contains a private key, seed, signing input or session key.
use super::{
    crypto::{bytes32, IdentitySecret},
    envelope::{encode_hex, Kind, SecureEnvelope},
    session::{valid_urn, SessionManager},
    transport::{ContractView, ReceiveReport, Transport},
    SecureError,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    time::Duration,
};
use zeroize::Zeroizing;
const LIMIT: u64 = 16 * 1024 * 1024;
/// Default guardian request budget: operations per rolling 60-second window.
pub const DEFAULT_RATE_PER_MINUTE: u32 = 600;
/// Fixed-window per-minute request budget. One budget per guardian daemon spans
/// every authorized connection; the cap counts rejected and unknown operations
/// too, so error floods cannot bypass it. No state beyond (start, count).
#[derive(Clone, Copy)]
struct RateBudget {
    cap: u32,
    window: Option<(std::time::Instant, u32)>,
}
impl RateBudget {
    fn new(cap: u32) -> Self {
        Self { cap, window: None }
    }
    fn permit(&mut self) -> bool {
        let now = std::time::Instant::now();
        if let Some((start, count)) = self.window {
            if now.duration_since(start) < Duration::from_secs(60) {
                if count >= self.cap {
                    return false;
                }
                self.window = Some((start, count + 1));
                return true;
            }
        }
        self.window = Some((now, 1));
        true
    }
}
fn io_error(_: impl std::fmt::Debug) -> SecureError {
    SecureError::GuardianUnavailable
}
fn uid() -> u32 {
    unsafe { libc::geteuid() }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    urn: String,
    ed25519_pub: String,
    require_secure: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityConfig {
    urn: String,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Degraded,
    Standard { agent_uid: u32 },
}
impl Mode {
    fn label(self) -> &'static str {
        if self == Self::Degraded {
            "degraded"
        } else {
            "standard"
        }
    }
}
fn private_dir(path: &Path) -> Result<(), SecureError> {
    let m = fs::symlink_metadata(path).map_err(io_error)?;
    if !m.is_dir() || m.uid() != uid() || m.mode() & 0o077 != 0 {
        return Err(SecureError::GuardianUnavailable);
    }
    Ok(())
}
fn private_read(path: &Path) -> Result<File, SecureError> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(io_error)?;
    let m = f.metadata().map_err(io_error)?;
    if !m.is_file() || m.uid() != uid() || m.mode() & 0o077 != 0 {
        return Err(SecureError::GuardianUnavailable);
    }
    Ok(f)
}
fn private_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, SecureError> {
    let mut bytes = Zeroizing::new(Vec::new());
    private_read(path)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > LIMIT {
        return Err(SecureError::SchemaViolation);
    }
    serde_json::from_slice(&bytes).map_err(|_| SecureError::SchemaViolation)
}
fn new_private(path: &Path, bytes: &[u8]) -> Result<(), SecureError> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(io_error)?;
    f.write_all(bytes).map_err(io_error)?;
    f.sync_all().map_err(io_error)
}
/// Operator provisioning. Prints/returns only a public fingerprint; the seed is written privately.
pub fn initialize(store: &Path, local: &str) -> Result<String, SecureError> {
    if !valid_urn(local) {
        return Err(SecureError::SchemaViolation);
    }
    if !store.exists() {
        fs::create_dir(store).map_err(io_error)?;
        fs::set_permissions(store, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    private_dir(store)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.try_fill_bytes(&mut *seed).map_err(io_error)?;
    let identity = IdentitySecret::from_seed(Zeroizing::new(*seed));
    new_private(&store.join("identity.key"), &*seed)?;
    new_private(
        &store.join("identity.json"),
        &serde_json::to_vec(&IdentityConfig { urn: local.into() }).map_err(io_error)?,
    )?;
    new_private(
        &store.join("identity.pub"),
        encode_hex(&identity.public_key()).as_bytes(),
    )?;
    new_private(&store.join("peers.json"), b"[]")?;
    Ok(encode_hex(&Sha256::digest(identity.public_key())))
}
/// Operator-only out-of-band public pin provisioning. Never reachable through the socket.
pub fn pin_peer(
    store: &Path,
    peer: &str,
    public_hex: &str,
    require_secure: bool,
) -> Result<(), SecureError> {
    private_dir(store)?;
    if !valid_urn(peer) {
        return Err(SecureError::IdentityMismatch);
    }
    bytes32(public_hex)?;
    let path = store.join("peers.json");
    let mut pins: Vec<Pin> = private_json(&path)?;
    pins.retain(|p| p.urn != peer);
    pins.push(Pin {
        urn: peer.into(),
        ed25519_pub: public_hex.into(),
        require_secure,
    });
    let tmp = store.join(format!("pins-{}.tmp", uuid::Uuid::new_v4()));
    new_private(&tmp, &serde_json::to_vec(&pins).map_err(io_error)?)?;
    fs::rename(tmp, path).map_err(io_error)
}
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum Request {
    Session {
        peer: String,
        hacp_session: String,
    },
    Seal {
        sid: String,
        contract: String,
        payload_b64: String,
    },
    Open {
        hacp_session: String,
    },
    Status,
    Fingerprint,
}
pub struct Guardian {
    manager: SessionManager,
    transport: Transport,
    pins: BTreeMap<String, Pin>,
    project: PathBuf,
    project_fd: File,
    store: PathBuf,
    local: String,
    mode: Mode,
    blocked: BTreeSet<String>,
    rate: RateBudget,
}
impl Guardian {
    /// The operator chooses trusted store/runtime paths outside the hostile project.
    pub fn load(store: &Path, project: &Path, mode: Mode) -> Result<Self, SecureError> {
        private_dir(store)?;
        let store = fs::canonicalize(store).map_err(io_error)?;
        let project = fs::canonicalize(project).map_err(io_error)?;
        if store.starts_with(&project) {
            return Err(SecureError::GuardianUnavailable);
        }
        if let Mode::Standard { agent_uid } = mode {
            if agent_uid == uid() {
                return Err(SecureError::GuardianUnavailable);
            }
        }
        let cfg: IdentityConfig = private_json(&store.join("identity.json"))?;
        let mut seed = Zeroizing::new([0u8; 32]);
        let mut key = private_read(&store.join("identity.key"))?;
        if key.metadata().map_err(io_error)?.len() != 32 {
            return Err(SecureError::GuardianUnavailable);
        }
        key.read_exact(&mut *seed).map_err(io_error)?;
        let manager = SessionManager::with_identity(&cfg.urn, IdentitySecret::from_seed(seed))?;
        let list: Vec<Pin> = private_json(&store.join("peers.json"))?;
        let mut pins = BTreeMap::new();
        for p in list {
            if !valid_urn(&p.urn) || pins.contains_key(&p.urn) {
                return Err(SecureError::IdentityMismatch);
            }
            bytes32(&p.ed25519_pub)?;
            pins.insert(p.urn.clone(), p);
        }
        let project_fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&project)
            .map_err(io_error)?;
        Ok(Self {
            manager,
            transport: Transport::new(),
            pins,
            project,
            project_fd,
            store,
            local: cfg.urn,
            mode,
            blocked: BTreeSet::new(),
            rate: RateBudget::new(DEFAULT_RATE_PER_MINUTE),
        })
    }
    /// Operator-configurable request cap per rolling 60-second window. Zero is
    /// refused: an unbounded guardian is a configuration error, not a mode.
    pub fn set_rate_per_minute(&mut self, cap: u32) -> Result<(), SecureError> {
        if cap == 0 {
            return Err(SecureError::SchemaViolation);
        }
        self.rate = RateBudget::new(cap);
        Ok(())
    }
    pub fn handle_bytes(&mut self, bytes: &[u8]) -> Value {
        // Rate is checked before parsing and before op allowlisting: malformed
        // or unknown-op floods consume the same budget as valid work.
        if !self.rate.permit() {
            let e = SecureError::RateLimited;
            self.audit(e, None);
            return json!({"ok":false,"error":e,"detail":e.to_string()});
        }
        match self.dispatch(bytes) {
            Ok(v) => v,
            Err(e) => {
                self.audit(e, None);
                json!({"ok":false,"error":e,"detail":e.to_string()})
            }
        }
    }
    fn dispatch(&mut self, bytes: &[u8]) -> Result<Value, SecureError> {
        if bytes.len() as u64 > LIMIT {
            return Err(SecureError::SchemaViolation);
        }
        let v: Value = serde_json::from_slice(bytes).map_err(|_| SecureError::SchemaViolation)?;
        let op = v
            .get("op")
            .and_then(Value::as_str)
            .ok_or(SecureError::SchemaViolation)?;
        if !["session", "seal", "open", "status", "fingerprint"].contains(&op) {
            return Err(SecureError::UnknownOperation);
        }
        let allowed: &[&str] = match op {
            "session" => &["op", "peer", "hacp_session"],
            "seal" => &["op", "sid", "contract", "payload_b64"],
            "open" => &["op", "hacp_session"],
            _ => &["op"],
        };
        let obj = v.as_object().ok_or(SecureError::SchemaViolation)?;
        if obj.len() != allowed.len() || obj.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(SecureError::SchemaViolation);
        }
        let req: Request =
            serde_json::from_slice(bytes).map_err(|_| SecureError::SchemaViolation)?;
        match req {
            Request::Fingerprint => Ok(
                json!({"ok":true,"urn":self.local(),"ed25519_pub_fingerprint":encode_hex(&Sha256::digest(self.manager.public_key()))}),
            ),
            Request::Status => {
                let mut sessions:Vec<_>=self.manager.sessions().into_iter().map(|s| {let t=self.transport.status(&s.sid);json!({"sid":s.sid,"peer":s.peer,"hacp_session":s.hacp_session,"state":s.state,"send_seq":t.send_seq,"recv_high":t.recv_high,"held":t.held,"mode":self.mode.label()})}).collect();
                for pin in self.pins.values().filter(|p| !p.require_secure) {
                    sessions.push(json!({"sid":"","peer":pin.urn,"state":"insecure","send_seq":0,"recv_high":null,"held":0}));
                }
                Ok(json!({"ok":true,"mode":self.mode.label(),"sessions":sessions}))
            }
            Request::Session { peer, hacp_session } => {
                self.allowed_context(&hacp_session)?;
                let pin = self.pins.get(&peer).ok_or(SecureError::IdentityMismatch)?;
                let hello =
                    self.manager
                        .initiate(&peer, &hacp_session, &bytes32(&pin.ed25519_pub)?)?;
                let pending = hello.nonce.clone().ok_or(SecureError::SchemaViolation)?;
                self.write_handshake(&hacp_session, &hello)?;
                Ok(json!({"ok":true,"sid_pending":pending,"peer":peer,"mode":self.mode.label()}))
            }
            Request::Seal {
                sid,
                contract,
                payload_b64,
            } => {
                let info = self.manager.info(&sid)?;
                self.allowed_context(&info.hacp_session)?;
                let payload = Zeroizing::new(
                    STANDARD
                        .decode(payload_b64)
                        .map_err(|_| SecureError::SchemaViolation)?,
                );
                let view = self.contract_view(&info.hacp_session)?;
                let env =
                    self.transport
                        .seal(&mut self.manager, &sid, &contract, &payload, &view)?;
                let path = self.write_message(&env)?;
                Ok(json!({"ok":true,"sid":sid,"seq":env.seq,"envelope_path":path}))
            }
            Request::Open { hacp_session } => self.receive(&hacp_session),
        }
    }
    fn local(&self) -> String {
        self.local.clone()
    }
    fn allowed_context(&self, context: &str) -> Result<(), SecureError> {
        if context.is_empty() {
            return Err(SecureError::SchemaViolation);
        }
        if self.blocked.contains(context) {
            return Err(SecureError::DowngradeDetected);
        }
        Ok(())
    }
    fn audit(&self, error: SecureError, sid: Option<&str>) {
        self.audit_reason(error, sid, None);
    }
    fn audit_reason(&self, error: SecureError, sid: Option<&str>, reason: Option<&str>) {
        // Fixed error names and public metadata only. Never log request bodies or library errors.
        if let Ok(mut f) = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.store.join("audit.jsonl"))
        {
            let _ = writeln!(
                f,
                "{}",
                json!({"error":error,"sid":sid,"mode":self.mode.label(),"reason":reason})
            );
        }
    }
    fn abort_context(&mut self, context: &str) {
        for s in self
            .manager
            .sessions()
            .into_iter()
            .filter(|s| s.hacp_session == context)
        {
            let _ = self.transport.close(&mut self.manager, &s.sid);
        }
        self.manager.close_context(context);
        self.blocked.insert(context.into());
    }
    fn contract_view(&self, context: &str) -> Result<ContractView, SecureError> {
        // .hacp is an untrusted observation, never an identity/policy source.
        let path = self.project.join(".hacp/session.json");
        let f = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ContractView::Bootstrap)
            }
            Err(_) => return Err(SecureError::ContractMismatch),
        };
        let mut bytes = Vec::new();
        f.take(LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| SecureError::ContractMismatch)?;
        if bytes.len() as u64 > LIMIT {
            return Err(SecureError::ContractMismatch);
        }
        let state: Value =
            serde_json::from_slice(&bytes).map_err(|_| SecureError::ContractMismatch)?;
        if state.pointer("/session/session_id").and_then(Value::as_str) != Some(context) {
            return Ok(ContractView::Pending);
        }
        let mut observed = Vec::new();
        let mut superseded = Vec::new();
        let mut bootstrap = false;
        if let Some(contracts) = state.get("contracts").and_then(Value::as_object) {
            for (id, entry) in contracts {
                let c = entry.get("contract").unwrap_or(entry);
                let contract_state = c.get("state").and_then(Value::as_str);
                bootstrap |= matches!(contract_state, Some("proposed" | "countered"));
                // A decline before the first freeze still emits a bootstrap
                // negotiation notification. Terminal amendment failure instead
                // retains its last frozen revision, like successful settlement.
                if matches!(contract_state, Some("noagreement" | "withdrawn"))
                    && c.get("revisions")
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty)
                {
                    bootstrap = true;
                    continue;
                }
                // The core permits withdrawal only before a first freeze.
                if contract_state == Some("withdrawn") {
                    return Err(SecureError::ContractMismatch);
                }
                if !matches!(
                    contract_state,
                    Some(
                        "executing"
                            | "verifying"
                            | "amending"
                            | "settled"
                            | "rejected"
                            | "noagreement"
                    )
                ) {
                    continue;
                }
                let revisions = c
                    .get("revisions")
                    .and_then(Value::as_array)
                    .filter(|r| !r.is_empty())
                    .ok_or(SecureError::ContractMismatch)?;
                let mut previous = 0;
                for (index, revision) in revisions.iter().enumerate() {
                    let number = revision
                        .get("number")
                        .and_then(Value::as_u64)
                        .filter(|n| *n > previous)
                        .ok_or(SecureError::ContractMismatch)?;
                    previous = number;
                    let content = revision
                        .get("content")
                        .cloned()
                        .ok_or(SecureError::ContractMismatch)?;
                    let digest = revision
                        .get("digest")
                        .and_then(Value::as_str)
                        .ok_or(SecureError::ContractMismatch)?;
                    let computed = crate::v2::canon::digest_of(
                        &json!({"contract_id":id,"revision":number,"content":content}),
                    )
                    .map_err(|_| SecureError::ContractMismatch)?;
                    if digest.strip_prefix("sha256:").unwrap_or(digest) != computed {
                        return Err(SecureError::ContractMismatch);
                    }
                    if index + 1 == revisions.len() {
                        observed.push(ContractView::Frozen {
                            contract_id: id.clone(),
                            revision: number,
                            content,
                            digest: computed,
                        });
                    } else {
                        superseded.push(format!("sha256:{computed}"));
                    }
                }
            }
        }
        // Preserve the single-contract policy. A digest-only wire field cannot
        // distinguish an unknown contract from a conflicting known revision;
        // absent an explicit pending proposal, fail closed on that ambiguity.
        if observed.is_empty() && superseded.is_empty() {
            Ok(ContractView::Bootstrap)
        } else if observed.len() == 1 && superseded.is_empty() && !bootstrap {
            Ok(observed.remove(0))
        } else {
            Ok(ContractView::Observed {
                current: observed,
                superseded,
                bootstrap,
            })
        }
    }
    // Resolve every edge directory relative to a pinned directory descriptor. A hostile
    // rename/symlink cannot redirect envelope writes or reads into the private key store.
    fn edge_dir(&self, parts: &[&str], create: bool) -> Result<File, SecureError> {
        let mut dir = self.project_fd.try_clone().map_err(io_error)?;
        for part in std::iter::once(".hacp-secure").chain(parts.iter().copied()) {
            if part.is_empty()
                || part == "."
                || part == ".."
                || part.contains('/')
                || part.contains('\0')
            {
                return Err(SecureError::SchemaViolation);
            }
            let name = std::ffi::CString::new(part).map_err(|_| SecureError::SchemaViolation)?;
            if create {
                let r = unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), 0o700) };
                if r < 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(SecureError::GuardianUnavailable);
                }
            }
            let fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(SecureError::GuardianUnavailable);
            }
            dir = unsafe { File::from_raw_fd(fd) };
        }
        Ok(dir)
    }
    fn write_edge(
        &self,
        parts: &[&str],
        name: &str,
        env: &SecureEnvelope,
    ) -> Result<String, SecureError> {
        let dir = self.edge_dir(parts, true)?;
        let name = std::ffi::CString::new(name).map_err(|_| SecureError::SchemaViolation)?;
        let tmp =
            std::ffi::CString::new(format!(".{}.tmp", uuid::Uuid::new_v4())).map_err(io_error)?;
        let fd = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                tmp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(SecureError::GuardianUnavailable);
        }
        let mut f = unsafe { File::from_raw_fd(fd) };
        let canonical = env.canonical_bytes()?;
        let result = (|| {
            f.write_all(&canonical).map_err(io_error)?;
            f.sync_all().map_err(io_error)?;
            let r = unsafe {
                libc::linkat(
                    dir.as_raw_fd(),
                    tmp.as_ptr(),
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    0,
                )
            };
            if r < 0 {
                if std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(SecureError::GuardianUnavailable);
                }
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(SecureError::GuardianUnavailable);
                }
                let existing = unsafe { File::from_raw_fd(fd) };
                let meta = existing.metadata().map_err(io_error)?;
                if !meta.is_file() || meta.len() != canonical.len() as u64 {
                    return Err(SecureError::GuardianUnavailable);
                }
                let mut previous = Vec::new();
                existing
                    .take(LIMIT + 1)
                    .read_to_end(&mut previous)
                    .map_err(io_error)?;
                if previous != canonical {
                    return Err(SecureError::GuardianUnavailable);
                }
            }
            Ok(())
        })();
        unsafe { libc::unlinkat(dir.as_raw_fd(), tmp.as_ptr(), 0) };
        result?;
        let mut p = PathBuf::from(".hacp-secure");
        for part in parts {
            p.push(part);
        }
        p.push(name.to_string_lossy().as_ref());
        Ok(p.to_string_lossy().into_owned())
    }
    fn write_handshake(&self, context: &str, env: &SecureEnvelope) -> Result<String, SecureError> {
        let scope = encode_hex(&Sha256::digest(context.as_bytes()));
        let key = env
            .sid
            .as_ref()
            .or(env.nonce.as_ref())
            .ok_or(SecureError::SchemaViolation)?;
        self.write_edge(
            &["handshakes", &scope],
            &format!(
                "{}-{}.json",
                if env.kind == Kind::Hello {
                    "hello"
                } else {
                    "ack"
                },
                key
            ),
            env,
        )
    }
    fn write_message(&self, env: &SecureEnvelope) -> Result<String, SecureError> {
        let sid = env.sid.as_deref().ok_or(SecureError::SchemaViolation)?;
        let seq = env.seq.ok_or(SecureError::SchemaViolation)?;
        let from = env
            .from
            .strip_prefix("urn:hacp:agent:")
            .ok_or(SecureError::SchemaViolation)?;
        self.write_edge(&[sid], &format!("{seq:020}-{from}.json"), env)
    }
    fn read_edges(
        &self,
        parts: &[&str],
    ) -> Box<dyn Iterator<Item = (String, Result<Vec<u8>, SecureError>)>> {
        let dir = match self.edge_dir(parts, false) {
            Ok(d) => d,
            Err(_) => return Box::new(std::iter::empty()),
        };
        let mut path = self.project.join(".hacp-secure");
        for part in parts {
            path.push(part);
        }
        let Ok(entries) = fs::read_dir(path) else {
            return Box::new(std::iter::empty());
        };
        // Sort names only; contents are read one at a time. No fixed scan cutoff
        // that would silently starve later sequences in a long-lived session.
        let mut names: Vec<String> = entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".json"))
            .collect();
        names.sort();
        Box::new(names.into_iter().map(move |name| {
            let result = (|| {
                let cname = std::ffi::CString::new(name.as_str())
                    .map_err(|_| SecureError::SchemaViolation)?;
                let fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        cname.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(SecureError::SchemaViolation);
                }
                let f = unsafe { File::from_raw_fd(fd) };
                let metadata = f.metadata().map_err(io_error)?;
                if !metadata.is_file() || metadata.len() > LIMIT {
                    return Err(SecureError::SchemaViolation);
                }
                let mut bytes = Vec::new();
                f.take(LIMIT + 1)
                    .read_to_end(&mut bytes)
                    .map_err(io_error)?;
                if bytes.len() as u64 > LIMIT {
                    return Err(SecureError::SchemaViolation);
                }
                Ok(bytes)
            })();
            (name, result)
        }))
    }
    fn receive(&mut self, context: &str) -> Result<Value, SecureError> {
        self.allowed_context(context)?;
        let mut delivered = Vec::new();
        let mut held = Vec::new();
        let mut rejected = Vec::new();
        let mut aborted = Vec::new();
        let scope = encode_hex(&Sha256::digest(context.as_bytes()));
        let mut groups = vec![self.read_edges(&["handshakes", &scope])];
        for s in self
            .manager
            .sessions()
            .into_iter()
            .filter(|s| s.hacp_session == context)
        {
            groups.push(self.read_edges(&[&s.sid]));
        }
        let local = self.local();
        for (file, raw) in groups.into_iter().flatten() {
            let result = (|| {
                let bytes = raw?;
                let parsed = SecureEnvelope::from_json(&bytes);
                let env = match parsed {
                    Ok(e) => e,
                    Err(e) => {
                        let object: Option<Value> = serde_json::from_slice(&bytes).ok();
                        let secure = object.as_ref().is_some_and(|v| {
                            v.get("v").is_some()
                                || matches!(
                                    v.get("kind").and_then(Value::as_str),
                                    Some("hello" | "ack" | "msg")
                                )
                        });
                        if !secure {
                            // Raw sender fields are unauthenticated. They cannot select a
                            // weaker pin in a context that might require secure delivery.
                            if self.pins.values().any(|pin| pin.require_secure) {
                                self.abort_context(context);
                                return Err(SecureError::DowngradeDetected);
                            }
                            let from = object
                                .as_ref()
                                .and_then(|v| v.get("from"))
                                .and_then(Value::as_str);
                            let to = object
                                .as_ref()
                                .and_then(|v| v.get("to"))
                                .and_then(Value::as_str);
                            let pin = from.and_then(|urn| self.pins.get(urn));
                            if pin.is_some_and(|p| !p.require_secure) && to == Some(local.as_str())
                            {
                                delivered.push(json!({"sid":"","from":from,"seq":0,"contract":"","payload_b64":STANDARD.encode(&bytes)}));
                                return Ok(());
                            }
                            if pin.is_some_and(|p| p.require_secure)
                                || self.pins.values().any(|p| p.require_secure)
                            {
                                self.abort_context(context);
                                return Err(SecureError::DowngradeDetected);
                            }
                            return Err(SecureError::IdentityMismatch);
                        }
                        return Err(e);
                    }
                };
                if env.from == local && env.to != local {
                    return Ok(());
                } // Our own outbound files on the shared edge.
                match env.kind {
                    Kind::Hello => {
                        let pin = self
                            .pins
                            .get(&env.from)
                            .ok_or(SecureError::IdentityMismatch)?;
                        let ack =
                            self.manager
                                .respond(context, &env, &bytes32(&pin.ed25519_pub)?)?;
                        self.write_handshake(context, &ack)?;
                    }
                    Kind::Ack => {
                        self.manager.complete(context, &env)?;
                    }
                    Kind::Msg => {
                        let sid = env.sid.as_deref().ok_or(SecureError::SchemaViolation)?;
                        let info = self.manager.info(sid)?;
                        if info.hacp_session != context {
                            return Err(SecureError::SessionUnknown);
                        }
                        let view = match self.contract_view(context) {
                            Ok(v) => v,
                            Err(e) => {
                                let _ = self.transport.close(&mut self.manager, sid);
                                aborted.push(json!({"sid":sid,"error":e}));
                                return Err(e);
                            }
                        };
                        let high = self.transport.status(sid).recv_high;
                        let report = self.transport.receive(&mut self.manager, &env, &view);
                        for error in &report.rejected {
                            let reason = if *error == SecureError::ReplayRejected {
                                Some(if high.is_some_and(|h| env.seq.is_some_and(|n| n < h)) {
                                    "regression"
                                } else {
                                    "duplicate"
                                })
                            } else {
                                None
                            };
                            self.audit_reason(*error, Some(sid), reason);
                        }
                        if let Some(error) = report.aborted {
                            self.audit(error, Some(sid));
                        }
                        Self::append_report(
                            report,
                            &file,
                            &mut delivered,
                            &mut held,
                            &mut rejected,
                            &mut aborted,
                            sid,
                        );
                    }
                }
                Ok(())
            })();
            if let Err(e) = result {
                self.audit(e, None);
                rejected.push(json!({"file":file,"error":e}));
                if e == SecureError::DowngradeDetected {
                    aborted.push(json!({"sid":"","error":e}));
                    delivered.clear();
                    break;
                }
            }
        }
        for s in self
            .manager
            .sessions()
            .into_iter()
            .filter(|s| s.hacp_session == context)
        {
            let view = self.contract_view(context)?;
            let report = self.transport.observe(&mut self.manager, &s.sid, &view);
            Self::append_report(
                report,
                "observation",
                &mut delivered,
                &mut held,
                &mut rejected,
                &mut aborted,
                &s.sid,
            );
        }
        Ok(
            json!({"ok":true,"delivered":delivered,"held":held,"rejected":rejected,"aborted":aborted}),
        )
    }
    fn append_report(
        report: ReceiveReport,
        file: &str,
        delivered: &mut Vec<Value>,
        held: &mut Vec<Value>,
        rejected: &mut Vec<Value>,
        aborted: &mut Vec<Value>,
        sid: &str,
    ) {
        for d in report.delivered {
            delivered.push(json!({"sid":d.sid,"from":d.from,"seq":d.seq,"contract":d.contract,"payload_b64":STANDARD.encode(&d.payload)}));
        }
        for h in report.held {
            held.push(json!({"sid":h.sid,"seq":h.seq,"reason":h.reason}));
        }
        for e in report.rejected {
            rejected.push(json!({"file":file,"error":e}));
        }
        if let Some(e) = report.aborted {
            delivered.retain(|d| d.get("sid").and_then(Value::as_str) != Some(sid));
            aborted.push(json!({"sid":sid,"error":e}));
        }
    }
    /// Serial processing holds the manager and transport exclusively for the entire request.
    pub fn serve(&mut self, socket: &Path) -> Result<(), SecureError> {
        let parent = socket.parent().ok_or(SecureError::GuardianUnavailable)?;
        private_dir(parent)?;
        if fs::canonicalize(parent)
            .map_err(io_error)?
            .starts_with(&self.project)
        {
            return Err(SecureError::GuardianUnavailable);
        }
        let listener = UnixListener::bind(socket).map_err(io_error)?;
        // Mode is explicit at startup. Standard connect ACLs are provisioned by the operator.
        eprintln!("HACP Secure guardian mode={}", self.mode.label());
        for stream in listener.incoming() {
            // A transient accept failure (EMFILE, ECONNABORTED) must not kill a
            // guardian mid-session; the next connection retries.
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            if !self.authorized_stream(&stream) {
                continue;
            }
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(io_error)?;
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .map_err(io_error)?;
            let mut bytes = Zeroizing::new(Vec::new());
            let read = BufReader::new(&mut stream)
                .take(LIMIT + 1)
                .read_until(b'\n', &mut bytes);
            let response = match read {
                Ok(_) if bytes.last() == Some(&b'\n') => self.handle_bytes(&bytes),
                _ => json!({"ok":false,"error":"SchemaViolation","detail":"SchemaViolation"}),
            };
            let _ = writeln!(stream, "{}", response);
        }
        Ok(())
    }
    fn authorized_stream(&self, stream: &UnixStream) -> bool {
        let expected = match self.mode {
            Mode::Degraded => uid(),
            Mode::Standard { agent_uid } => agent_uid,
        };
        #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
        {
            let mut user = 0;
            let mut group = 0;
            unsafe {
                libc::getpeereid(stream.as_raw_fd(), &mut user, &mut group) == 0 && user == expected
            }
        }
        #[cfg(target_os = "linux")]
        {
            let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    &mut cred as *mut _ as *mut libc::c_void,
                    &mut len,
                ) == 0
                    && cred.uid == expected
            }
        }
        #[cfg(not(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "linux"
        )))]
        {
            let _ = (stream, expected);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture {
        root: PathBuf,
        store: PathBuf,
        project: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("hacp-guardian-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            let store = root.join("private");
            let project = root.join("project");
            fs::create_dir(&project).unwrap();
            initialize(&store, "urn:hacp:agent:a").unwrap();
            Self {
                root,
                store,
                project,
            }
        }
        fn guardian(&self) -> Guardian {
            Guardian::load(&self.store, &self.project, Mode::Degraded).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    #[test]
    fn rate_limit_caps_all_operations_and_recovers_next_window() {
        let fixture = Fixture::new();
        let mut g = fixture.guardian();
        g.set_rate_per_minute(2).unwrap();
        let probe = json!({"op":"fingerprint"}).to_string();
        assert_eq!(g.handle_bytes(probe.as_bytes())["ok"], true);
        // Malformed and unknown-op floods consume the same budget.
        assert_eq!(
            g.handle_bytes(br#"{"op":"status","extra":1}"#)["error"],
            "SchemaViolation"
        );
        let limited = g.handle_bytes(probe.as_bytes());
        assert_eq!(limited["error"], "RateLimited");
        assert_eq!(limited["detail"], "RateLimited");
        // Fixed shape only: no request echo, no counters, no budget details.
        assert_eq!(limited.as_object().unwrap().len(), 3);
        // A rolled-over window admits traffic again.
        let past = std::time::Instant::now()
            .checked_sub(Duration::from_secs(61))
            .expect("monotonic clock with >61s uptime");
        g.rate.window = Some((past, 2));
        assert_eq!(g.handle_bytes(probe.as_bytes())["ok"], true);
    }
    #[test]
    fn rate_limit_refuses_unbounded_configuration() {
        let fixture = Fixture::new();
        let mut g = fixture.guardian();
        assert_eq!(
            g.set_rate_per_minute(0),
            Err(SecureError::SchemaViolation)
        );
        g.set_rate_per_minute(1).unwrap();
        let probe = json!({"op":"fingerprint"}).to_string();
        assert_eq!(g.handle_bytes(probe.as_bytes())["ok"], true);
        assert_eq!(g.handle_bytes(probe.as_bytes())["error"], "RateLimited");
    }
    #[test]
    fn strict_operations_and_key_output_hygiene() {
        let fixture = Fixture::new();
        let mut g = fixture.guardian();
        let seed = Zeroizing::new(fs::read(fixture.store.join("identity.key")).unwrap());
        let hex = Zeroizing::new(encode_hex(&seed));
        let b64 = Zeroizing::new(STANDARD.encode(&seed));
        let mut outputs = String::new();
        for op in [
            "sign", "export", "derive", "debug", "dump", "key", "seal_raw",
        ] {
            let r = g.handle_bytes(json!({"op":op}).to_string().as_bytes());
            assert_eq!(r["error"], "UnknownOperation");
            outputs.push_str(&r.to_string());
        }
        for raw in [
            r#"{"op":"status","skip_verify":true}"#,
            r#"{"op":"fingerprint","key":true}"#,
            r#"{"op":"seal","sid":"a","contract":"","payload_b64":"","signing_input":"chosen"}"#,
            r#"{"op":"status","op":"status"}"#,
        ] {
            let r = g.handle_bytes(raw.as_bytes());
            assert_eq!(r["error"], "SchemaViolation");
            outputs.push_str(&r.to_string());
        }
        for op in ["status", "fingerprint"] {
            let r = g.handle_bytes(json!({"op":op}).to_string().as_bytes());
            assert_eq!(r["ok"], true);
            outputs.push_str(&r.to_string());
        }
        outputs.push_str(&fs::read_to_string(fixture.store.join("audit.jsonl")).unwrap());
        assert!(!outputs.contains(hex.as_str()));
        assert!(!outputs.contains(b64.as_str()));
        assert!(!outputs.contains("identity.key"));
    }
    #[test]
    fn private_store_rejects_permissions_symlinks_and_same_uid_standard() {
        let fixture = Fixture::new();
        assert!(matches!(
            Guardian::load(
                &fixture.store,
                &fixture.project,
                Mode::Standard { agent_uid: uid() }
            ),
            Err(SecureError::GuardianUnavailable)
        ));
        let path = fixture.store.join("identity.key");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Guardian::load(&fixture.store, &fixture.project, Mode::Degraded),
            Err(SecureError::GuardianUnavailable)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&path, fixture.store.join("saved.key")).unwrap();
        std::os::unix::fs::symlink("saved.key", &path).unwrap();
        assert!(matches!(
            Guardian::load(&fixture.store, &fixture.project, Mode::Degraded),
            Err(SecureError::GuardianUnavailable)
        ));
    }
    #[test]
    fn pinned_policy_plaintext_race_and_explicit_insecure_status() {
        for secure in [true, false] {
            let fixture = Fixture::new();
            pin_peer(&fixture.store, "urn:hacp:agent:b", &"03".repeat(32), secure).unwrap();
            let mut g = fixture.guardian();
            let scope = encode_hex(&Sha256::digest(b"s-test"));
            g.edge_dir(&["handshakes", &scope], true).unwrap();
            fs::write(
                fixture
                    .project
                    .join(".hacp-secure/handshakes")
                    .join(&scope)
                    .join("injected.json"),
                br#"{"from":"urn:hacp:agent:b","to":"urn:hacp:agent:a","payload":"plaintext"}"#,
            )
            .unwrap();
            let result = g.handle_bytes(br#"{"op":"open","hacp_session":"s-test"}"#);
            if secure {
                assert!(result["delivered"].as_array().unwrap().is_empty());
                assert_eq!(result["rejected"][0]["error"], "DowngradeDetected");
                assert!(g.blocked.contains("s-test"));
            } else {
                assert_eq!(result["delivered"].as_array().unwrap().len(), 1);
                let status = g.handle_bytes(br#"{"op":"status"}"#);
                assert_eq!(status["sessions"][0]["state"], "insecure");
            }
        }
    }
    #[test]
    fn edge_collision_is_not_success_and_symlink_cannot_redirect() {
        let fixture = Fixture::new();
        let mut g = fixture.guardian();
        let mut b = SessionManager::new("urn:hacp:agent:b").unwrap();
        let h = g
            .manager
            .initiate("urn:hacp:agent:b", "s-test", &b.public_key())
            .unwrap();
        let ack = b.respond("s-test", &h, &g.manager.public_key()).unwrap();
        let sid = g.manager.complete("s-test", &ack).unwrap();
        let env = g.manager.seal(&sid, 0, "", b"edge canary").unwrap();
        let path = g.write_message(&env).unwrap();
        assert_eq!(g.write_message(&env).unwrap(), path); // Exact retransmission is safe.
        fs::write(fixture.project.join(&path), b"preplanted wrong content").unwrap();
        assert_eq!(g.write_message(&env), Err(SecureError::GuardianUnavailable));
        assert_eq!(
            g.manager.seal(&sid, 0, "", b"reuse"),
            Err(SecureError::ReplayRejected)
        );
        let linked = "ff".repeat(16);
        std::os::unix::fs::symlink(
            &fixture.store,
            fixture.project.join(".hacp-secure").join(&linked),
        )
        .unwrap();
        assert!(g.edge_dir(&[&linked], true).is_err());
        assert!(!fs::read(fixture.project.join(path))
            .unwrap()
            .windows(11)
            .any(|w| w == b"edge canary"));
    }
    #[test]
    fn actual_hacp_observation_shape_and_corrupt_second_contract() {
        let fixture = Fixture::new();
        let g = fixture.guardian();
        let dir = fixture.project.join(".hacp");
        fs::create_dir(&dir).unwrap();
        let content = json!({"inputs":[],"outputs":["x"],"acceptance":["true"]});
        let digest = crate::v2::canon::digest_of(
            &json!({"contract_id":"c-test","revision":1,"content":content}),
        )
        .unwrap();
        let entry = json!({"contract":{"state":"executing","revisions":[{"number":1,"content":content,"digest":digest}]}});
        let mut state = json!({"session":{"session_id":"s-test"},"contracts":{"c-test":entry}});
        fs::write(dir.join("session.json"), state.to_string()).unwrap();
        assert!(matches!(
            g.contract_view("s-test"),
            Ok(ContractView::Frozen { revision: 1, .. })
        ));
        state["contracts"]["c-another"] = entry;
        fs::write(dir.join("session.json"), state.to_string()).unwrap();
        assert!(matches!(
            g.contract_view("s-test"),
            Err(SecureError::ContractMismatch)
        ));
    }
    #[test]
    fn concurrent_contracts_settlement_and_pending_proposals_are_observed() {
        let fixture = Fixture::new();
        let g = fixture.guardian();
        let dir = fixture.project.join(".hacp");
        fs::create_dir(&dir).unwrap();
        let revision = |id: &str, n: u64| {
            let content = json!({"inputs":[],"outputs":[id],"acceptance":["true"]});
            let digest = crate::v2::canon::digest_of(
                &json!({"contract_id":id,"revision":n,"content":content}),
            )
            .unwrap();
            json!({"number":n,"content":content,"digest":digest})
        };
        let old = revision("c-one", 1);
        let mut state = json!({"session":{"session_id":"s-test"},"contracts":{
            "c-one":{"contract":{"state":"executing","revisions":[old,revision("c-one",2)]}},
            "c-two":{"contract":{"state":"settled","revisions":[revision("c-two",1)]}},
            "c-next":{"contract":{"state":"proposed","revisions":[]}}
        }});
        fs::write(dir.join("session.json"), state.to_string()).unwrap();
        let ContractView::Observed {
            current,
            superseded,
            bootstrap,
        } = g.contract_view("s-test").unwrap()
        else {
            panic!("multiple contracts require a complete observation")
        };
        assert_eq!(current.len(), 2);
        assert_eq!(
            superseded,
            vec![format!("sha256:{}", old["digest"].as_str().unwrap())]
        );
        assert!(bootstrap);
        state["contracts"]["c-next"]["contract"]["state"] = json!("noagreement");
        state["contracts"]["c-two"]["contract"]["state"] = json!("noagreement");
        fs::write(dir.join("session.json"), state.to_string()).unwrap();
        let ContractView::Observed {
            current, bootstrap, ..
        } = g.contract_view("s-test").unwrap()
        else {
            panic!("terminal notifications retain their contract context")
        };
        assert_eq!(
            current.len(),
            2,
            "terminal frozen history remains attributable"
        );
        assert!(bootstrap, "never-frozen decline remains bootstrap traffic");
        state["contracts"]["c-two"]["contract"]["state"] = json!("rejected");
        state["contracts"]["c-next"]["contract"]["state"] = json!("withdrawn");
        fs::write(dir.join("session.json"), state.to_string()).unwrap();
        let ContractView::Observed {
            current, bootstrap, ..
        } = g.contract_view("s-test").unwrap()
        else {
            panic!("withdrawal and rejected verification preserve notification bindings")
        };
        assert_eq!(
            current.len(),
            2,
            "verification rejection retains its frozen revision"
        );
        assert!(bootstrap);
        state["contracts"]["c-next"]["contract"]["revisions"] = json!([revision("c-next", 1)]);
        fs::write(dir.join("session.json"), state.to_string()).unwrap();
        assert!(matches!(
            g.contract_view("s-test"),
            Err(SecureError::ContractMismatch)
        ));
        state["contracts"].as_object_mut().unwrap().remove("c-next");
        fs::write(dir.join("session.json"), state.to_string()).unwrap();
        assert!(matches!(
            g.contract_view("s-test"),
            Ok(ContractView::Observed {
                bootstrap: false,
                ..
            })
        ));
        state["contracts"]["c-one"]["contract"]["revisions"][0]["content"] = json!({"forged":true});
        fs::write(dir.join("session.json"), state.to_string()).unwrap();
        assert!(matches!(
            g.contract_view("s-test"),
            Err(SecureError::ContractMismatch)
        ));
    }
    #[test]
    fn mixed_pin_plaintext_cannot_select_weaker_policy() {
        let fixture = Fixture::new();
        pin_peer(&fixture.store, "urn:hacp:agent:b", &"03".repeat(32), true).unwrap();
        pin_peer(&fixture.store, "urn:hacp:agent:c", &"04".repeat(32), false).unwrap();
        let mut g = fixture.guardian();
        let scope = encode_hex(&Sha256::digest(b"s-secure"));
        g.edge_dir(&["handshakes", &scope], true).unwrap();
        fs::write(fixture.project.join(".hacp-secure/handshakes").join(scope).join("spoofed-insecure-peer.json"),br#"{"from":"urn:hacp:agent:c","to":"urn:hacp:agent:a","payload":"untrusted weaker-policy claim"}"#).unwrap();
        let response = g.handle_bytes(br#"{"op":"open","hacp_session":"s-secure"}"#);
        assert!(response["delivered"].as_array().unwrap().is_empty());
        assert_eq!(response["rejected"][0]["error"], "DowngradeDetected");
        assert!(g.blocked.contains("s-secure"));
    }
}
