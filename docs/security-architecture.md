# HACP Secure — Security Architecture

Primitives: X25519 (RFC 7748) · HKDF-SHA256 (RFC 5869) · ChaCha20-Poly1305
(RFC 8439) · Ed25519 (RFC 8032). Companion: `docs/hacp-secure-threat-model.md`,
`spec/schemas/secure-envelope.json`.

## 1. Design rule and adversary

HACP Secure does **not** modify HACP (frozen 1.1 + 2.0 draft). It is a
payload-protection layer *under* the existing message flow: a payload that
must be protected is replaced by a `SecureEnvelope` before it touches the
shared file edge.

The adversary is a **prompt-injected or compromised agent reasoning loop**
with arbitrary tool calls and arbitrary writes into the shared project
directory, running as the **same OS uid** as its guardian. A guardian-uid or
root compromise is out of scope (trust kernel). The LLM context is always
untrusted: everything an agent can see is public and injectable.

| Mode | Key protection | Status |
|---|---|---|
| **Standard** | Guardian runs under a dedicated OS uid; 0600 keyfile, 0700 socket. Agent uid may *connect* but never *read*. Falsifiable: `sudo -u agent cat <keyfile>` must fail | Specified |
| **Degraded** | Same-uid guardian. Reduces to **context hygiene**: no agent-reachable tool returns, accepts, or logs key material | Documented residual risk, labeled at startup |

## 2. Actors and trust boundaries

| Actor | Sees keys? | Trusted for |
|---|---|---|
| Agent (LLM context) | **Never** — envelopes (ciphertext) only | Choosing to protect a payload |
| Guardian (per agent) | **Yes** — sole holder of private keys | All crypto: handshake, seal, open, sign |
| File edge (`.hacp-secure/`) | No — ciphertext only | Best-effort, at-least-once delivery |
| Operator | Yes, at provisioning | Identity provisioning; not message content |

```
 operator (out-of-band): init keys inside guardians, exchange pinned
   public keys by fingerprint → peers.json OUTSIDE the project
        │ pin                                 │ pin
        ▼                                     ▼
 AGENT A (untrusted, injectable)        AGENT B (untrusted, injectable)
   │ UDS: seal/open/session               ▲ UDS
   ▼                                      │
 GUARDIAN A (trust kernel, own uid)     GUARDIAN B
   │ ciphertext only                       ▲
   ▼                                       │
 ══ UNTRUSTED SHARED FILE EDGE (.hacp-secure/) ══
   no keys, no pins, no counters persist here
```

Boundary rules:

1. Everything inside an LLM context is public; the agent-facing surface
   contains no key material, so no tool call can *return* a secret.
2. The shared project directory is hostile. Only ciphertext crosses it;
   integrity comes from signatures/AEAD, never file permissions; nothing
   inside the project can change identity trust.
3. A guardian's uid is the security kernel (standard mode). In degraded mode
   that kernel is absent and only rule 1 holds — startup says so.
4. The operator is trusted for identity, not content (ephemeral DH means no
   session-key knowledge).
5. Failure is closed: every verification failure drops the envelope and
   surfaces a named error; `require_secure` sessions never fall back to
   plaintext; guardian unavailability blocks the operation.

## 3. Identity

- An agent's identity is its URN. Ed25519 keypairs are generated *inside* the
  guardian (`init`); no export command exists.
- Peer public keys are **pinned** in guardian-private `peers.json` outside the
  project: `{urn, ed25519_pub, require_secure}`, exchanged out-of-band with
  fingerprint confirmation. Nothing in `.hacp/` can change a pin or policy.
- A sender is authenticated iff its handshake signature verifies under the
  pinned key for the claimed URN; missing pin or mismatch is
  `IdentityMismatch` (fail closed).
- No certificates, rotation, or revocation. A key is replaced by operator
  re-provisioning.

## 4. Handshake and key schedule

One round trip, **signed ephemeral X25519**; identity keys never perform DH.
`hacp_session` (the existing HACP session id) is bound into every transcript.

```
A → B  hello { v:1, kind, from, to, epub:e_a_pub, nonce:n_a,
        sig = sk_a("HACP-SECURE/v1/hello" ‖ hacp_session ‖ urn_a ‖ urn_b ‖ e_a_pub ‖ n_a) }
B: verify under pinned(urn_a)               → else BadHandshakeSignature/IdentityMismatch
B → A  ack   { …, sid, epub:e_b_pub, nonce:n_b,
        sig = sk_b("HACP-SECURE/v1/ack" ‖ hacp_session ‖ urn_b ‖ urn_a ‖ e_a_pub ‖ n_a ‖ e_b_pub ‖ n_b) }
A: verify under pinned(urn_b)               → else BadHandshakeSignature/IdentityMismatch

ikm   = X25519(e_priv, e_pub_peer)
salt  = n_a ‖ n_b
ctx   = "HACP-SECURE/v1/session" ‖ hacp_session ‖ urn_initiator ‖ urn_responder
sid   = HKDF-SHA256(ikm, salt, ctx‖"sid",   16)
k_i2r = HKDF-SHA256(ikm, salt, ctx‖"k_i2r", 32)     # initiator→responder
k_r2i = HKDF-SHA256(ikm, salt, ctx‖"k_r2i", 32)     # responder→initiator
```

- Mutual authentication: signatures cover both ephemerals, both nonces, URNs,
  and the HACP session id — no swap or cross-session reuse without breaking a
  signature. Forward secrecy: ephemeral DH only.
- Replayed/flooded hellos are bounded: **at most 4 pending sessions per peer**
  (oldest evicted); an evicted hello fails at the first `msg` and must re-run.

## 5. SecureEnvelope

JSON, canonical form per HACP v2 canonical JSON rules; the canonical header
(without `ct`/`sig`) is the AAD. Exact schema:
`spec/schemas/secure-envelope.json`.

| Field | Present | Meaning |
|---|---|---|
| `v` = 1 | always | version |
| `kind` = hello\|ack\|msg | always | envelope kind |
| `from`, `to` | always | URNs |
| `contract` | always | frozen revision digest (`sha256:<64hex>`) or `""` for bootstrap |
| `sid` | ack, msg | session id |
| `seq` | msg | per-direction counter; also the AEAD nonce input |
| `epub`, `nonce` | hello, ack | ephemeral X25519 pub, handshake nonce |
| `sig` | all | Ed25519 signature (inputs below) |
| `ct` | msg | ChaCha20-Poly1305 ciphertext ‖ 16-byte tag |
| `ts` | optional | advisory only; never an auth input |

Encrypt-then-sign, with domain separation on every signed input:

```
aad     = canonical_json(envelope minus ct, sig)
nonce96 = 0x00000000 ‖ u64be(seq)
ct      = ChaCha20-Poly1305(k_dir, nonce96, aad, plaintext)
sig     = Ed25519(sk_sender, "HACP-SECURE/v1/msg" ‖ aad ‖ ct)
```

- No prefix-less signing input exists, and the guardian API exposes only
  `session`/`seal`/`open`/`status`/`fingerprint` — **no raw `sign(bytes)`**,
  so an injected agent cannot make the identity key sign chosen content.
- The required per-message signature gives third-party attributability: any
  holder of the pinned public key can attribute an envelope without AEAD keys
  (non-repudiation is in scope).
- Envelopes are written to `.hacp-secure/<sid>/<seq>-<from>.json`.

## 6. Two-tier contract binding

- **TIER-1 (always)**: every envelope is bound to the HACP session via the
  handshake transcript, HKDF `ctx`, and `sid` (in the AAD). Cross-session
  replay fails the tag.
- **TIER-2 (frozen contracts)**: envelopes sent while the referenced contract
  is frozen carry `contract = <revision digest>` in the AAD. Bootstrap traffic
  carries `""` — the digest cannot exist before the revision does.

| Receiver observation | Action |
|---|---|
| Digest matches observed frozen revision | deliver |
| Not yet observed | **HOLD** (`ContractPending`) in the bounded queue; re-evaluated on each observation; dropped at close |
| Contradicts a different observed revision | `ContractMismatch` → hard abort |

Trust source, stated honestly: the guardian observes "frozen revision" in
`.hacp/`, which a same-uid agent can rewrite. It recomputes every digest as
SHA-256 over canonical `{contract_id, revision, content}` before trusting a
record, but TIER-2 proves only an **attributable signed claim of revision D**,
not bilateral consent. Control-plane authenticity is a non-goal (signed
freezes would change HACP).

## 7. Replay protection

- The replay counter **is** the AEAD nonce (`0x00000000 ‖ u64be(seq)`);
  directional keys rule out cross-direction nonce collision; sender monotonic
  counter + receiver window make reuse detectable by construction.
- Replay state lives **only in guardian memory**. A guardian restart voids all
  sessions (`SessionExpired`); recovery is a fresh handshake. There are no
  persisted counters to roll back.
- Per direction, `high` = highest accepted seq:
  - `seq == high+1` → accept.
  - `seq <= high` → `ReplayRejected`: drop and audit (`duplicate` vs
    `regression`), never an abort — duplicates are ordinary at-least-once
    traffic; delivery stays exactly-once.
  - `seq > high+1` → hold in the bounded queue (shared with contract holds,
    capacity 64) and drain in order when the hole fills. Hard abort with
    `SequenceGap` if the queue overflows (`HoldOverflow`) or newer traffic
    arrives while the earliest hole persists — on an at-least-once edge an
    unfilled hole means deletion, turned into a visible abort instead of a
    silent stall.
- `seq == u64::MAX` → `SessionExhausted`, fail closed; only a new handshake
  recovers.
- `sid`, `from`, `to`, `contract` are in the AAD ⇒ cross-session and
  cross-contract splices fail the tag.

## 8. Verification pipeline and failure modes

Normative order; the first failing step names the error. `high` advances only
after step 7 succeeds.

```
1. JSON schema          → SchemaViolation
2. sid lookup           → SessionUnknown / SessionExpired
3. route check          → IdentityMismatch   (from ≠ session peer OR to ≠ self)
4. Ed25519 signature    → BadMessageSignature (BEFORE touching AEAD keys)
5. seq window           → ReplayRejected / gap-hold / SequenceGap
6. AEAD open            → TamperDetected
7. TIER-2 contract      → ContractPending / ContractMismatch
8. deliver
```

| Error | Trigger |
|---|---|
| `TamperDetected` | tag failure after a valid signature: buggy/malicious pinned sender or key mismatch (in-transit tampering fails at step 4) |
| `IdentityMismatch` | unpinned/misrouted/reflected envelope |
| `BadHandshakeSignature` / `BadMessageSignature` | handshake / message signature failure |
| `ReplayRejected` | duplicate or regression (no abort) |
| `SequenceGap` / `HoldOverflow` | deletion attack / queue overflow (abort) |
| `ContractPending` / `ContractMismatch` | unobserved revision (hold) / contradiction (abort) |
| `DowngradeDetected` | plaintext or unverifiable envelope in a `require_secure` session (abort) |
| `SessionUnknown` / `SessionExpired` / `SessionExhausted` | stale sid / restart / nonce budget spent |
| `SchemaViolation` | fails the wire schema |
| `GuardianUnavailable` / `RateLimited` | guardian unreachable / per-minute budget spent — both fail closed |

Error strings are fixed names plus non-secret detail; no path returns key
bytes, plaintext, or AEAD state.

## 9. Wire policy and compatibility

- The `hacp` binary, `.hacp/` state, and all hacp-skill commands are
  untouched. Agents opt in per payload via `hacp-secure send/recv`.
- Security mode is **guardian policy, not TOFU**: `require_secure` comes from
  the private pin, never inferred from arriving traffic (a plaintext race
  cannot pin a session open). Under `require_secure: true`, any plaintext or
  unverifiable envelope is `DowngradeDetected` — hard abort, never fallback.
- `GuardianUnavailable` fails closed; no plaintext code path exists.
- An agent without HACP Secure sees only hex ciphertext; hacp semantics above
  the layer are unchanged. Digest of a sealed artifact = digest of the
  envelope bytes.

## 10. Known limitations

1. Degraded mode reduces key protection to context hygiene (labeled, not silent).
2. Edge metadata is public: URNs, sizes, timing, authorship (NG — metadata
   confidentiality, traffic analysis).
3. No revocation or post-compromise security; compromise requires operator
   re-provisioning of both pin stores.
4. Gap tolerance bounded at 64 held envelopes; deletion aborts loudly; no rekey.
5. Contract holds defer delivery but contradictions always abort.
