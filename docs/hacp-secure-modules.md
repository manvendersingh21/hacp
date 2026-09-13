# HACP Secure — Implementation Modules

Status: v1 (peer b) · Session s-3337e50c7f3c4d1c81024028690f7942 · Contract c-f52fbdb9da524494aff8aed2327d36d6
Refines `docs/security-architecture.md` §10 (peer a). No module here changes the
`hacp` binary, `.hacp/` state, or any existing file under `src/`.

## 1. Structural rules

These rules turn "keys outside LLM context" from a promise into something the
build checks.

1. **Custody by module.** Only `guardian.rs` and `session.rs`, both reachable
   only from the `hacp-secure-guardian` binary, may construct or hold secret
   types. The agent-facing `hacp-secure` binary depends on `client.rs` and
   `envelope.rs` only, so it contains **no key material** and no code path that
   could produce any (INV-2, test T-40).
2. **Crypto is pure.** `crypto.rs` performs no I/O, reads no clock, and holds no
   global state. Every function is deterministic given its inputs, except key and
   nonce generation, which take an injected RNG. That makes every primitive
   testable against RFC and golden vectors.
3. **Dependency direction** (arrows mean "may use"):

```
 hacp-secure (agent CLI) ──► client ──► envelope (public types, schema, AAD builder)
                                             ▲
 hacp-secure-guardian ──► guardian ──► session ──► crypto
                             │            │
                             └────────────┴──► envelope
```

   `client` never imports `guardian`, `session` or `crypto`. `envelope` imports
   nothing secret.
4. **Secret types** (`IdentitySecret`, `EphemeralSecret`, `SessionKeys`)
   implement `Zeroize + ZeroizeOnDrop` and deliberately do **not** implement
   `Debug`, `Display`, `Clone`, `Serialize` or `JsonSchema`. The compiler then
   refuses to log, print, or send them.
5. **Fail closed by construction.** Every public guardian operation returns
   `Result<_, SecureError>`. No operation has a plaintext fallback branch.

## 2. Module inventory

| Module | New/changed | Holds secrets | I/O | Responsibility |
|---|---|---|---|---|
| `src/secure/mod.rs` | new | no | none | Facade; `SecureError` enum (architecture §8 taxonomy); feature-gates `guardian`/`session`/`crypto` behind `guardian` cargo feature |
| `src/secure/envelope.rs` | new | no | none | `SecureEnvelope` type matching `spec/schemas/secure-envelope.json`; per-kind required-field validation; canonical JSON (reuse the existing HACP canonicalizer); `aad_bytes()` = canonical header without `ct`/`sig`; `signing_input(kind)` with domain prefixes |
| `src/secure/crypto.rs` | new | transient (by reference) | none | X25519 DH, HKDF-SHA256 key schedule (`sid`, `k_i2r`, `k_r2i`), ChaCha20-Poly1305 seal/open with `nonce96 = 0x00000000 ‖ u64be(seq)`, Ed25519 sign/verify |
| `src/secure/session.rs` | new | yes (`SessionKeys`, `EphemeralSecret`) | none | Handshake state machine (`Idle → HelloSent → Established`, `Idle → AckSent → Established`); per-direction send counter; receive high-water mark; bounded hold queue (64); pending-session bound per peer; the receive pipeline (§4) |
| `src/secure/guardian.rs` | new | yes (`IdentitySecret`, pins, policy) | keyfile, `peers.json`, UDS, `.hacp-secure/` edge, read-only `.hacp/` observation | Key store (no export), pin store with `require_secure`, request server, edge writer/reader, contract-revision observer with digest recomputation (F7), startup mode label (standard/degraded), audit log (outside the project) |
| `src/secure/client.rs` | **new (proposed here)** | **no** | UDS | Thin JSON-lines client for the guardian socket. No crypto dependencies. Maps transport failure to `GuardianUnavailable` |
| `src/bin/hacp-secure.rs` | new | **no** | stdout/stderr, UDS via `client` | Agent-facing CLI (§3) |
| `src/bin/hacp-secure-guardian.rs` | new | yes | as guardian | Operator-facing daemon: `init`, `pin`, `fingerprint`, `serve` |
| `src/lib.rs` | changed (one line) | no | n/a | `pub mod secure;`, purely additive |
| `Cargo.toml` | changed | n/a | n/a | Additive deps: `x25519-dalek 2`, `ed25519-dalek 2`, `chacha20poly1305 0.10`, `hkdf 0.12`, `sha2 0.10`, `zeroize 1`, `rand_core 0.6`, `jsonschema` (dev only) |

## 3. Interfaces

### 3.1 Agent-facing CLI (`hacp-secure`) — what the LLM sees

Every command prints JSON on stdout. Errors print `{"ok":false,"error":"<SecureError name>","detail":"<non-secret text>"}`
and exit non-zero. **No command accepts or prints key material**, and no flag
or environment variable carries a secret.

| Command | Effect | Output (complete field list) |
|---|---|---|
| `hacp-secure session --peer <urn> --hacp-session <id>` | Guardian writes a `hello` to the edge | `{ok, sid_pending, peer, mode}` (`mode` is `standard` or `degraded`) |
| `hacp-secure recv --hacp-session <id>` | Guardian scans the edge: answers `hello` with `ack`, completes handshakes, runs the receive pipeline on `msg`s | `{ok, delivered:[{sid, from, seq, contract, payload_b64}], held:[{sid, seq, reason}], rejected:[{file, error}], aborted:[{sid, error}]}` |
| `hacp-secure send --sid <sid> [--contract <digest>] --payload-file <path>` | Guardian seals and writes a `msg` | `{ok, sid, seq, envelope_path}` |
| `hacp-secure status` | Session table | `{ok, mode, sessions:[{sid, peer, state, send_seq, recv_high, held}]}` |
| `hacp-secure fingerprint` | Own identity *public* key fingerprint | `{ok, urn, ed25519_pub_fingerprint}` |

`seal` and `open` are the guardian operations behind `send` and `recv`; the
architecture's names are kept on the socket API (§3.2). The agent's existing
hacp-skill workflow is unchanged: it keeps using `hacp start/join/propose/ask/poll/...`
for coordination and uses `hacp-secure send/recv` only for payloads it chooses
to protect.

### 3.2 Guardian socket API (UDS, JSON lines, one request per line)

Socket path: `$HACP_SECURE_RUNTIME/<agent>/guardian.sock`. The runtime directory is
0700, owned by the guardian uid. In standard mode the agent uid is granted
connect access and nothing else.

| `op` | Request fields | Response fields |
|---|---|---|
| `session` | `peer`, `hacp_session` | `sid_pending`, `mode` |
| `seal` | `sid`, `contract`, `payload_b64` | `seq`, `envelope_path` |
| `open` | `hacp_session` | `delivered[]`, `held[]`, `rejected[]`, `aborted[]` |
| `status` | none | `mode`, `sessions[]` |
| `fingerprint` | none | `urn`, `ed25519_pub_fingerprint` |

The allowlist above is the entire API. Any other `op`, including `sign`,
`export`, `derive` and `debug`, returns `UnknownOperation`. That is tested by
T-03, which enumerates candidate names.

### 3.3 Operator CLI (`hacp-secure-guardian`) — never invoked by agents

| Command | Effect |
|---|---|
| `init --agent <urn>` | Generate the Ed25519 identity inside the guardian and write the 0600 keyfile. Prints only the fingerprint |
| `pin --peer <urn> --pub <hex> --require-secure <true\|false>` | Add a pin after out-of-band fingerprint confirmation |
| `serve [--degraded]` | Start the socket server; refuses to start same-uid without `--degraded` and prints the degraded-mode banner |

### 3.4 Library surface (Rust signatures, indicative)

```rust
// envelope.rs — public, no secrets
pub struct SecureEnvelope { pub v: u8, pub kind: Kind, pub from: String, pub to: String,
    pub contract: String, pub sid: Option<Sid>, pub seq: Option<u64>, pub epub: Option<[u8;32]>,
    pub nonce: Option<[u8;32]>, pub sig: Option<[u8;64]>, pub ct: Option<Vec<u8>>, pub ts: Option<String> }
impl SecureEnvelope {
    pub fn validate(&self) -> Result<(), SecureError>;           // SchemaViolation
    pub fn aad_bytes(&self) -> Vec<u8>;                           // canonical, without ct/sig
    pub fn signing_input(&self) -> Vec<u8>;                       // domain prefix ‖ transcript or aad ‖ ct
}

// crypto.rs — pure
pub fn key_schedule(ikm: &[u8;32], n_a: &[u8;32], n_b: &[u8;32], hacp_session: &str,
    urn_i: &str, urn_r: &str) -> (Sid, SessionKeys);
pub fn aead_seal(k: &Key, seq: u64, aad: &[u8], pt: &[u8]) -> Vec<u8>;
pub fn aead_open(k: &Key, seq: u64, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, SecureError>; // TamperDetected
pub fn verify(pk: &VerifyingKey, msg: &[u8], sig: &[u8;64]) -> bool;

// session.rs
pub enum Verdict { Deliver(Vec<u8>), Hold(HoldReason), Reject(SecureError), Abort(SecureError) }
impl Session { pub fn receive(&mut self, env: &SecureEnvelope, view: &ContractView) -> Verdict; }
```

## 4. Receive pipeline (in `session.rs`)

The order is normative (architecture §8, F6 accepted); stage 2 applies the §9
wire policy. Each stage maps to one `SecureError`. Cheap, key-free checks run before any secret is used.

| # | Stage | Uses secret? | On failure | Disposition |
|---|---|---|---|---|
| 1 | Schema validation (`secure-envelope.json`) | no | `SchemaViolation` | drop + audit |
| 2 | Policy: plaintext or non-envelope object in a `require_secure` HACP session | no | `DowngradeDetected` | **abort** |
| 3 | `sid` lookup | no | `SessionUnknown` / `SessionExpired` | drop + audit |
| 4 | Routing: `from == session peer` and `to == self` | no | `IdentityMismatch` | drop + audit |
| 5 | Ed25519 over `HACP-SECURE/v1/msg ‖ aad ‖ ct` under the pinned key | public key only | `BadMessageSignature` | drop + audit |
| 6 | Sequence window: `seq ≤ high` gives `ReplayRejected`; `seq > high+1` is held; an envelope newer than all held ones while the earliest hole persists gives `SequenceGap` (F5) | no | `ReplayRejected` / `SequenceGap` / `HoldOverflow` | drop + audit / hold / **abort** |
| 7 | ChaCha20-Poly1305 open with the directional key | **yes** | `TamperDetected` | drop + audit |
| 8 | TIER-2: `contract` vs observed, digest-recomputed revision | no | `ContractPending` / `ContractMismatch` | hold / **abort** |
| 9 | Deliver; `high = seq` (advanced **only** after stage 7 succeeds); drain the hold queue in order | n/a | n/a | exactly-once |

## 5. Error type

```rust
pub enum SecureError {
    SchemaViolation, DowngradeDetected, SessionUnknown, SessionExpired, SessionExhausted,
    IdentityMismatch, BadHandshakeSignature, BadMessageSignature, ReplayRejected,
    SequenceGap, HoldOverflow, TamperDetected, ContractPending,
    ContractMismatch, GuardianUnavailable, UnknownOperation,
}
```

`Display` prints only the variant name and a fixed, non-secret detail string.
No variant carries bytes.

## 6. Proposed phase-2 implementation contracts

These are proposed once the design contracts settle, one owner per file, and each
must be separately agreed through HACP:

| Contract | Owner | Outputs | Acceptance anchor |
|---|---|---|---|
| P2-A crypto + envelope | peer a | `src/secure/crypto.rs`, `src/secure/envelope.rs`, `src/secure/mod.rs` | T-29, T-30, T-31, T-33, T-39 |
| P2-B session | peer a | `src/secure/session.rs` | T-06..T-23, T-32, T-37, T-38, T-41 |
| P2-C guardian + client + binaries | peer b | `src/secure/guardian.rs`, `src/secure/client.rs`, `src/bin/hacp-secure.rs`, `src/bin/hacp-secure-guardian.rs` | T-02..T-05, T-24..T-28, T-35, T-40, T-42 |
| P2-D wiring + e2e tests | peer b | `src/lib.rs`, `Cargo.toml`, `tests/secure_*.rs` | T-01, T-34, T-36, full matrix |
