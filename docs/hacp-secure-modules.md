# HACP Secure — Implementation Modules

Refines `docs/security-architecture.md`. No module changes the `hacp` binary,
`.hacp/` state, or existing files under `src/`.

## 1. Structural rules

1. **Custody by module.** Only `guardian.rs` and `session.rs` — reachable only
   from the `hacp-secure-guardian` binary — may construct or hold secret
   types. The agent-facing `hacp-secure` binary uses `client.rs` and
   `envelope.rs` only: no key material, and no code path that could produce
   any (INV-2, T-40).
2. **Crypto is pure.** `crypto.rs` does no I/O, reads no clock, holds no
   global state; key/nonce generation takes an injected RNG. Every primitive
   is testable against RFC and golden vectors.
3. **Dependency direction** ("may use"):

```
hacp-secure (agent CLI) ──► client ──► envelope (public types, schema, AAD)
hacp-secure-guardian ──► guardian ──► session ──► crypto
                             │           │
                             └───────────┴──► envelope
```

4. **Secret types** (`IdentitySecret`, `EphemeralSecret`, `SessionKeys`)
   implement `Zeroize + ZeroizeOnDrop` and deliberately not `Debug`,
   `Display`, `Clone`, `Serialize`, or `JsonSchema` — the compiler refuses to
   log, print, or send them.
5. **Fail closed by construction.** Every public guardian operation returns
   `Result<_, SecureError>`; no operation has a plaintext fallback branch.

## 2. Module inventory

| Module | Secrets | I/O | Responsibility |
|---|---|---|---|
| `src/secure/mod.rs` | no | none | Facade; `SecureError` taxonomy; feature-gates crypto behind `guardian` |
| `src/secure/envelope.rs` | no | none | `SecureEnvelope` matching the frozen schema; per-kind validation; canonical AAD builder; domain-separated signing inputs |
| `src/secure/crypto.rs` | transient | none | X25519, HKDF-SHA256 key schedule, ChaCha20-Poly1305 with `nonce96 = 0x00000000 ‖ u64be(seq)`, Ed25519 |
| `src/secure/session.rs` | yes | none | Handshake state machine; send counters; receive high-water mark; bounded hold queue; pending-session bound; the receive pipeline (§4) |
| `src/secure/guardian.rs` | yes | keyfile, peers.json, UDS, `.hacp-secure/` edge, `.hacp/` observation | Key store (no export); pins with `require_secure`; request server with per-minute rate budget; edge writer/reader; digest-recomputing contract observer; mode label; audit log outside the project |
| `src/secure/client.rs` | no | UDS | Thin JSON-lines client; maps transport failure to `GuardianUnavailable` |
| `src/secure/workflow.rs` | no | via client | Key-free adapter the hacp-skill uses: `Workflow::new/ensure_session/send/receive`, authenticated inbox, fixed errors |
| `src/bin/hacp-secure.rs` | no | stdout, UDS | Agent-facing CLI (§3.1) |
| `src/bin/hacp-secure-guardian.rs` | yes | as guardian | Operator daemon: `init`, `pin`, `serve` |

## 3. Interfaces

### 3.1 Agent CLI (`hacp-secure`) — what the LLM sees

JSON on stdout; errors are `{"ok":false,"error":"<name>","detail":"<non-secret>"}`
with non-zero exit. No command accepts or prints key material.

| Command | Effect | Output |
|---|---|---|
| `session --peer <urn> --hacp-session <id>` | Write a `hello` to the edge | `{ok, sid_pending, peer, mode}` |
| `recv --hacp-session <id>` | Scan the edge: ack hellos, complete handshakes, run the receive pipeline | `{ok, delivered[], held[], rejected[], aborted[]}` |
| `send --sid <sid> [--contract <digest>] --payload-file <path>` | Seal and write a `msg` | `{ok, sid, seq, envelope_path}` |
| `status` | Session table | `{ok, mode, sessions[]}` |
| `fingerprint` | Own public fingerprint | `{ok, urn, ed25519_pub_fingerprint}` |

The agent's hacp-skill workflow is unchanged: ordinary `hacp` commands for
coordination, `hacp-secure send/recv` only for protected payloads.

### 3.2 Guardian socket API (UDS, JSON lines)

Socket: `$HACP_SECURE_RUNTIME/<agent>/guardian.sock`, 0700 dir owned by the
guardian uid; in standard mode the agent uid may connect and nothing else.

| `op` | Request fields | Response fields |
|---|---|---|
| `session` | `peer`, `hacp_session` | `sid_pending`, `mode` |
| `seal` | `sid`, `contract`, `payload_b64` | `seq`, `envelope_path` |
| `open` | `hacp_session` | `delivered[]`, `held[]`, `rejected[]`, `aborted[]` |
| `status` | none | `mode`, `sessions[]` |
| `fingerprint` | none | `urn`, `ed25519_pub_fingerprint` |

The allowlist is the entire API; any other `op` (including `sign`, `export`,
`derive`, `debug`) returns `UnknownOperation`. Every request — valid, malformed,
or unknown — consumes the daemon's rolling per-minute budget; a spent budget
returns the fixed `RateLimited` error.

### 3.3 Operator CLI (`hacp-secure-guardian`) — never invoked by agents

| Command | Effect |
|---|---|
| `init --agent <urn>` | Generate the Ed25519 identity; 0600 keyfile; prints only the fingerprint |
| `pin --peer <urn> --pub <hex> --require-secure <bool>` | Pin a peer after out-of-band fingerprint confirmation |
| `serve [--degraded] [--rate-per-minute <n>]` | Start the socket server; refuses same-uid without `--degraded` |

`serve` defaults to 600 operations per rolling 60 seconds; zero is refused.
Transient accept failures are skipped, not fatal.

## 4. Receive pipeline (normative order; architecture §8)

Cheap, key-free checks run before any secret is used.

| # | Stage | Secret? | On failure | Disposition |
|---|---|---|---|---|
| 1 | Schema (`secure-envelope.json`) | no | `SchemaViolation` | drop + audit |
| 2 | Policy: plaintext in a `require_secure` session | no | `DowngradeDetected` | **abort** |
| 3 | `sid` lookup | no | `SessionUnknown`/`SessionExpired` | drop + audit |
| 4 | Routing: `from == session peer`, `to == self` | no | `IdentityMismatch` | drop + audit |
| 5 | Ed25519 over `HACP-SECURE/v1/msg ‖ aad ‖ ct` | public key only | `BadMessageSignature` | drop + audit |
| 6 | Sequence window | no | `ReplayRejected`/`SequenceGap`/`HoldOverflow` | drop / hold / **abort** |
| 7 | ChaCha20-Poly1305 open | **yes** | `TamperDetected` | drop + audit |
| 8 | TIER-2 contract check | no | `ContractPending`/`ContractMismatch` | hold / **abort** |
| 9 | Deliver; `high = seq` (only after stage 7); drain holds in order | n/a | n/a | exactly-once |

## 5. Error type

```rust
pub enum SecureError {
    SchemaViolation, DowngradeDetected, SessionUnknown, SessionExpired, SessionExhausted,
    IdentityMismatch, BadHandshakeSignature, BadMessageSignature, ReplayRejected,
    SequenceGap, HoldOverflow, TamperDetected, ContractPending, ContractMismatch,
    GuardianUnavailable, RateLimited, UnknownOperation,
}
```

`Display` prints only the variant name and a fixed, non-secret detail string.
No variant carries bytes.
