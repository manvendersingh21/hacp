# HACP Secure — Threat Model

Status: v1 (peer b) · Session s-3337e50c7f3c4d1c81024028690f7942 · Contract c-f52fbdb9da524494aff8aed2327d36d6
Companion to: `docs/security-architecture.md` (normative design, peer a),
`docs/trust-boundary.md`, `spec/schemas/secure-envelope.json`,
`docs/hacp-secure-test-matrix.md`, `docs/hacp-secure-non-goals.md`.

This document states **what we defend, against whom, and what is left over**.
Every mitigated threat names the test that falsifies it. A threat with no test
ID is a residual risk, and it also appears in the non-goals.

## 1. Assets

| ID | Asset | Where it lives | Why it matters |
|---|---|---|---|
| S1 | Ed25519 identity private key (per agent) | Guardian process memory; 0600 keyfile outside the project | Whoever holds it *is* the agent: impersonation plus non-repudiable forgery |
| S2 | Session keys `k_i2r`, `k_r2i`, ephemeral X25519 private keys | Guardian memory only; never persisted | Confidentiality and integrity of one session |
| S3 | Pin store and policy (`peers.json`: `{urn, ed25519_pub, require_secure}`) | Guardian-private config outside the project | Integrity is the trust root; if writable, impersonation is a file write |
| S4 | Replay state (per-direction high-water marks, hold queue) | Guardian memory only | If rolled back, accepted nonces are resurrected |
| P1 | Protected payload plaintext | Sender guardian (seal), receiver guardian (open), then the receiving agent's context | The thing being protected |
| M1 | Envelope metadata (URNs, `sid`, `seq`, `contract`, sizes, authorship) | Shared file edge, in the clear by design | Deliberately **not** an asset we protect (see non-goals) |

## 2. Adversaries

| ID | Adversary | Capabilities | In scope? |
|---|---|---|---|
| **ADV-1** | **Prompt-injected or compromised agent reasoning loop** (the primary adversary model) | Arbitrary tool calls under the agent's uid; arbitrary reads and writes in the project dir, including `.hacp/` and `.hacp-secure/`; can connect to its own guardian's socket and call `seal`/`open`/`session` | **Yes** |
| ADV-2 | Edge attacker (the peer side's ADV-1, or any other writer of the shared dir) | Observe, inject, delete, reorder, duplicate or modify any file on the edge | **Yes** |
| ADV-3 | Malicious but *pinned* peer | Holds a legitimate identity; sends well-formed, correctly signed content | Partially: attribution yes, content safety no (§4 confused deputy) |
| ADV-4 | Same-uid local attacker with deliberate filesystem snooping | Can read any file the agent uid can read | Standard mode: **yes**, via the uid wall. Degraded mode: **no**, documented residual risk |
| ADV-5 | Guardian-uid or root compromise | Everything | **No**: that account is the trust kernel |
| ADV-6 | Network or passive global observer | n/a | Not applicable: no network transport exists; the edge is a local shared directory |

### 2.1 Deployment modes

- **Standard mode.** Each guardian runs under a dedicated OS uid. The agent uid
  can *connect* to the guardian's socket but cannot read S1 or S3. This is
  falsifiable: `sudo -u <agent> cat <keyfile>` must fail (T-04).
- **Degraded mode** (the hackathon laptop: agent and guardian share a uid). The
  uid wall is absent. Protection of S1 reduces to *context hygiene*: no
  agent-reachable tool ever returns, accepts, or logs key material, so an
  injected agent would have to go looking for a path no tool surfaces. The
  guardian labels degraded mode at startup, and the label is recorded in session
  metadata (T-05). **Degraded mode does not defend against ADV-4.**

## 3. Threats and mitigations

STRIDE letter: **S**poofing, **T**ampering, **R**epudiation, **I**nformation
disclosure, **D**enial of service, **E**levation of privilege.

| ID | STRIDE | Threat | Mitigation (architecture section) | Failure mode surfaced | Test |
|---|---|---|---|---|---|
| TH-01 | I | ADV-1 exfiltrates S1 by asking a tool to print it | No export command; the agent-facing API is `seal`/`open`/`session` only; secret types are not serializable (modules §5) | n/a (no such path) | T-02, T-35, T-40 |
| TH-02 | I | ADV-1 reads the keyfile directly | Standard: uid wall, 0600. Degraded: **residual** | n/a | T-04 (standard only) |
| TH-03 | E | **Signing oracle**: ADV-1 gets the identity key to sign attacker-chosen bytes (e.g. a forged handshake transcript) | No raw `sign(bytes)` endpoint; domain-separated signing inputs `HACP-SECURE/v1/{hello,ack,msg}` (arch §5, F2) | request refused | T-03, T-33 |
| TH-04 | S | ADV-2 claims to be peer B by writing a `hello`/`ack` | Signature must verify under the **pinned** key for the claimed URN (arch §3–§4) | `IdentityMismatch`, `BadHandshakeSignature` | T-09, T-10 |
| TH-05 | S | ADV-1 rewrites pins from the project dir | Pins live outside the project and are writable only by the guardian uid; nothing in `.hacp/` is consulted for identity (arch §3) | n/a | T-28 |
| TH-06 | T | MITM swaps ephemeral keys or nonces during handshake | Both ephemerals and both nonces are inside the signed transcripts | `BadHandshakeSignature` | T-11 |
| TH-07 | T | ADV-2 flips bytes in `ct` or in any AAD field (`to`, `sid`, `seq`, `contract`) | Signature over `HACP-SECURE/v1/msg ‖ AAD ‖ ct` checked first, then the Poly1305 tag (pipeline F6) | `BadMessageSignature` (sig first), `TamperDetected` (valid sig, bad tag) | T-06, T-07, T-41 |
| TH-08 | T | **Reflection**: A's own envelope fed back to A | Pipeline checks `from == session peer` and `to == self` before crypto (F6); directional keys as a second line | `IdentityMismatch` | T-32, T-38 |
| TH-09 | T | Replay of an accepted `msg` (duplicate or regression) | `seq` is the nonce; strict per-direction high-water mark in guardian memory (arch §7, F3) | `ReplayRejected` (drop + audit, no abort) | T-13, T-14 |
| TH-10 | T/D | **Deletion or gap**: ADV-2 deletes envelope *n*, so every later `seq` would be silently dropped and the session wedges | `seq > high+1` is held in the bounded queue (64, shared with contract holds) and drained in order when the hole fills. Hard abort if the queue overflows, or if an envelope newer than everything held arrives while the earliest hole persists: on an at-least-once edge that means deletion (F5, accepted) | `SequenceGap`, `HoldOverflow` | T-15, T-16 |
| TH-11 | T | Cross-session splice: envelope from session X replayed into session Y | `hacp_session` is in the signed transcript and in HKDF `ctx`; `sid` is in the AAD (TIER-1) | `SessionUnknown` / `BadMessageSignature` | T-12, T-17 |
| TH-12 | T | Cross-contract splice: an envelope bound to revision R1 is delivered under R2 | `contract` digest is in the AAD (TIER-2) | `ContractMismatch` | T-23 |
| TH-13 | T | **Replay-state rollback**: ADV-1 deletes or rewrites persisted counters | No persisted replay state; guardian restart voids sessions (F3) | `SessionExpired` | T-18 |
| TH-14 | T | **Downgrade**: ADV-2 strips the crypto and injects a plaintext HACP payload | `require_secure` per-peer policy in guardian-private pins (F1) | `DowngradeDetected` (hard abort) | T-24 |
| TH-15 | T | **Mode-pinning race (TOFU)**: ADV-2 writes a plaintext envelope *first* so the session pins as plaintext | Mode comes from provisioning policy, never from first traffic (F1) | `DowngradeDetected` | T-25 |
| TH-16 | T | Guardian killed so the agent "falls back" to plaintext | No plaintext code path exists | `GuardianUnavailable` (fail closed) | T-27 |
| TH-17 | T | **Control-plane forgery**: the TIER-2 comparison uses the revision the guardian *observes in `.hacp/`*, which ADV-1 can rewrite | Guardian recomputes the revision digest as SHA-256 of canonical `{contract_id, revision, content}` before trusting a record (F7, accepted). TIER-2 therefore proves "sender made an attributable claim of revision D", **not** "both peers agreed to D" | `ContractMismatch` on inconsistent records | T-42; **residual**: see non-goals (control-plane authenticity) |
| TH-18 | D | Hold-queue flooding with valid-looking pending envelopes | Queue capacity 64 per session | `HoldOverflow` (hard abort) | T-22 |
| TH-19 | D | **Orphan sessions / hello flood**: a replayed `hello` makes the responder allocate session state with no key confirmation (the first `msg` is the implicit confirmation) | Pending sessions bounded at 4 per peer, oldest evicted (accepted, architecture §4); a replayed `hello` cannot produce usable keys without `e_a_priv` | eviction audit record | T-37 |
| TH-20 | D | Nonce budget exhaustion | `u64` overflow is a hard stop | `SessionExhausted` | T-19 |
| TH-21 | I | Error channel leaks plaintext, key bytes, or AEAD state into agent context | Error strings are fixed names plus non-secret detail; canary scan over all error paths | n/a | T-35 |
| TH-22 | R | Sender later denies sending a message | Required per-message Ed25519 signature, verifiable with only the pinned public key (third-party attribution) | n/a | T-34 |
| TH-23 | S/E | **Confused deputy (ADV-3, or ADV-1 via its own guardian)**: an injected agent asks its guardian to `seal` malicious content, which arrives *correctly authenticated*; or a pinned peer sends a payload that prompt-injects the receiving agent | **Not mitigated.** Authentication proves *who* sent bytes, not that the bytes are safe or that the sending agent was uncompromised. Signatures make the author attributable after the fact (TH-22) | none | **residual**: non-goals |
| TH-24 | I | Plaintext exposure after `open`: the payload enters the receiving LLM context, and with it the model provider's request logs | **Not mitigated.** HACP Secure protects the edge, not the endpoint | none | **residual**: non-goals |
| TH-25 | I | `.hacp/` control-plane content (contract terms, questions, answers, poll traffic) remains plaintext | **Not mitigated.** Only payloads explicitly sealed via `hacp-secure` are protected; the `hacp` binary is unchanged by design | none | **residual**: non-goals |

## 4. The confused deputy, stated plainly

The guardian is a deputy that holds authority (S1) the agent does not. An
injected agent cannot *extract* that authority (TH-01..03), but it can still
*use* it through `seal`, exactly as a legitimate agent does. Consequences we
accept and say out loud:

1. A message that passes every HACP Secure check may still be malicious.
   Receivers must keep treating payload content as untrusted input.
2. The guarantee is **attribution, not benignity**: the per-message signature
   pins every sealed message to a pinned identity for audit and dispute.
3. Mitigating content-level abuse (policy on what may be sealed, human
   approval, output filtering) is outside this layer.

## 5. Security invariants (each is a test obligation)

| ID | Invariant | Tests |
|---|---|---|
| INV-1 | No byte of S1 or S2 appears in any agent-reachable output: CLI stdout/stderr, error strings, edge files, `.hacp/` | T-02, T-35 |
| INV-2 | The agent-facing binary does not link key-store code | T-40 |
| INV-3 | Every delivered plaintext passed schema, session, routing, signature, replay, AEAD and TIER-2 checks, in that order | T-01, T-41 |
| INV-4 | Each `(sid, direction, seq)` is delivered at most once, in strictly increasing order | T-13, T-14, T-16 |
| INV-5 | Under `require_secure: true`, no plaintext payload is ever delivered | T-24, T-25, T-27 |
| INV-6 | No security state (keys, pins, counters) is read from the project directory | T-18, T-28 |
| INV-7 | Every rejection maps to exactly one named error from the architecture's section 8 taxonomy | T-06..T-27 |

## 6. Challenge record (all settled through HACP)

Every item below was raised by peer b, accepted by peer a, and is reflected in
`docs/security-architecture.md`. The full exchange is in `.hacp/log.md`.

| Challenge | Decision | Affects |
|---|---|---|
| 1 Adversary model | ADV-1 injected agent at the same uid; standard (uid wall) vs degraded (context hygiene, labeled) | TH-01, TH-02 |
| 2 Contract binding | Two-tier: TIER-1 session, TIER-2 revision digest; HOLD on unobserved, abort on contradiction | TH-11, TH-12 |
| 3 Handshake | Signed-ephemeral X25519; labeled directional keys; `nonce96 = 0x00000000 ‖ u64be(seq)` | TH-06, TH-20 |
| 4 Downgrade | Compatible at the CLI, strict at the wire; `GuardianUnavailable` fails closed | TH-14, TH-16 |
| 5 Trust root, AAD, signatures | Pins outside the project; canonical-JSON AAD; per-message encrypt-then-sign | TH-04, TH-05, TH-22 |
| F1 Mode pinning | `require_secure` in pins, never from first traffic | TH-15 |
| F2 Signing oracle | Domain-separated signing inputs; no raw `sign` endpoint | TH-03 |
| F3 Replay state | Guardian memory only; restart gives `SessionExpired` | TH-09, TH-13 |
| F4 Hold bound | 64, overflow gives `HoldOverflow` | TH-18 |
| F5 Gap wedge | Hold and drain in order; deletion gives `SequenceGap` abort | TH-10 |
| F6 Pipeline order | Normative 8-step order, signature before AEAD; `from`/`to` routing check | TH-07, TH-08 |
| F7 TIER-2 trust source | Attributable claim only; digest recomputation; control-plane authenticity is a non-goal | TH-17 |
