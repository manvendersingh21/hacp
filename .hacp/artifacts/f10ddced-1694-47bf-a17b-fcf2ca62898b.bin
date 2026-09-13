# HACP Secure — Hackathon Scope

Status: DRAFT v3 (peer a, revised after peer b challenges 1–5 and follow-ups F1–F4) · Session s-3337e50c7f3c4d1c81024028690f7942
Related: docs/security-architecture.md, docs/trust-boundary.md, spec/schemas/secure-envelope.json

## 1. Problem

HACP today provides collaboration semantics (sessions, contracts,
verification) but no communication security. The spec is explicit: "A URN is
a name, not a signature" — authenticity is delegated to the transport, and
the file edge is readable by anything with access to the shared directory.
HACP Secure adds the smallest layer that fixes this for two agents *without*
touching the existing collaboration protocol and *without* ever exposing
private key material to the agents (LLM contexts).

## 2. Adversary model (binding)

The adversary is a **prompt-injected or compromised agent reasoning loop**
that can emit arbitrary tool calls and arbitrary writes into the shared
project directory, running as the same OS uid as its guardian. It is not a
guardian-uid attacker (that host account is the trust kernel and is out of
scope). Consequence: the LLM context is untrusted, the project directory is
hostile, and the only trusted per-agent component is its guardian under its
own privileges (standard mode: dedicated uid; degraded hackathon mode:
context hygiene only, labeled and documented).

## 3. In scope (MVP)

| # | Requirement | Met by |
|---|-------------|--------|
| R1 | Two HACP agents communicate normally through hacp-skill | Sealed payloads ride the existing file edge; hacp-skill command surface unchanged |
| R2 | Private keys inaccessible to agents | Per-agent out-of-process Key Guardian; keys never enter the project dir, command output, or any value an agent can read; dedicated-uid deployment in standard mode |
| R3 | Authenticated agent identities | Ed25519 identity keys held by guardians; peer public keys pinned out-of-band in guardian-private config; signatures over handshake transcript |
| R4 | Encrypted messages | Signed-ephemeral X25519 → HKDF-SHA256 (labeled directional keys) → ChaCha20-Poly1305 per-message AEAD; forward secrecy in scope |
| R5 | HACP contract binding (two-tier) | TIER-1: HACP session id + sid bound in every envelope's keys/AAD. TIER-2: frozen contract revision digest in the AAD of envelopes sent while executing/verifying; `""` for bootstrap traffic; HOLD-then-re-evaluate for unobserved-but-legitimate revisions |
| R6 | Replay protection | Sequence-number-as-nonce, strict guardian-memory high-water window (drop-and-audit on duplicates/regressions, never abort; exactly-once delivery), bounded gap-hold queue with loud `SequenceGap`/`HoldOverflow` aborts on deletion attacks, hard fail at overflow; no persisted replay state (restart = SessionExpired + new handshake) |
| R7 | Clear failure modes | Named error taxonomy (TamperDetected, IdentityMismatch, BadHandshakeSignature, BadMessageSignature, ReplayRejected, SequenceGap, ContractPending, HoldOverflow, ContractMismatch, DowngradeDetected, SessionUnknown, SessionExpired, SessionExhausted, SchemaViolation, GuardianUnavailable); all fail closed and loudly — no silent wedges |
| R8 | Backward-compatible agent-facing workflow, strict wire | CLI surface and hacp-skill flow unchanged; wire policy strict: security mode is guardian-private per-peer policy (`require_secure` in peers.json, provisioning-time — never inferred from traffic); plaintext under require_secure = hard abort (DowngradeDetected); guardian unreachable = fail closed |

Primitives (fixed): X25519 (RFC 7748), HKDF-SHA256 (RFC 5869),
ChaCha20-Poly1305 (RFC 8439), Ed25519 (RFC 8032).

Also in scope: **third-party attributability** — every `msg` carries a
required Ed25519 signature over (AAD ‖ ciphertext), verifiable by any holder
of the pinned public key, feeding HACP evidence/verification/dispute
(non-repudiation is in scope, not a non-goal).

## 4. Deliverables

1. `docs/hackathon-scope.md` (this file)
2. `docs/security-architecture.md`
3. `spec/schemas/secure-envelope.json` — exact wire schema
4. `docs/trust-boundary.md` — diagram
5. Implementation modules under `src/secure/` + guardian/CLI binaries
   (phase 2, only after bilateral architecture acceptance is recorded in
   HACP)
6. `docs/hacp-secure-test-matrix.md` (peer b ownership, with companion
   `docs/hacp-secure-threat-model.md`, `docs/hacp-secure-modules.md`,
   `docs/hacp-secure-non-goals.md`)
7. Non-goals: section 5 below

## 5. Explicit non-goals

- **No PKI / CA / certificate chain validation.** Pinned peer keys in
  guardian-private config, exchanged out-of-band at provisioning
  (TOFU-with-confirmation) only.
- **No key rotation, revocation, or expiry machinery.** Re-provisioning by
  the operator replaces a key. Forward secrecy covers only the session
  lifetime.
- **No post-quantum security.** Classical primitives only.
- **No group / multi-party sessions.** Exactly two participants (matches
  the HACP/2.0 bilateral core).
- **No metadata confidentiality.** Sender/recipient URNs, session id,
  sequence numbers, ciphertext length, and authorship (per-message
  signatures are publicly verifiable by design) are visible on the edge.
- **No traffic-analysis or DoS resistance.** The file edge is assumed
  best-effort, at-least-once.
- **No HSM / TPM / OS-keychain integration.** Guardian keyfile (0600) in a
  per-agent directory outside the project for the MVP; the interface is
  HSM-ready.
- **No defense against a guardian-uid compromise** (standard mode) or
  against deliberate same-uid filesystem snooping in **degraded mode**
  (documented residual risk: context hygiene only — see
  security-architecture.md §1).
- **No changes to HACP semantics.** Contracts, verification, escalation,
  digests, and the `hacp` binary remain exactly as frozen. HACP Secure is a
  payload wrapper, not a protocol revision. In particular, control-plane
  (`.hacp`) authenticity is a non-goal: TIER-2 binding proves an
  attributable signed claim of a revision, not that both peers agreed to
  it; signed freezes would be a change to HACP itself (guardians
  recompute record digests before trusting them — see
  security-architecture.md §6).
- **No secret-bearing agent tooling.** No agent command ever accepts,
  prints, stores, or transmits private key material; guardians refuse to
  export keys.
- **No rekeying, gap-tolerant ordering, or lossy-channel adaptivity.**
  Strict in-order delivery; recovery is redelivery (at-least-once edge) or
  new handshake (SessionExhausted).

## 6. Acceptance gate for implementation

Implementation contracts may be proposed only after both peers record
acceptance of this architecture through HACP: peer a's acceptance is
recorded by bilateral contract acceptance on the design package
(c-767fd5f7fea1494f90fc8b18dbd29f61), peer b's by the same acceptance event
plus their companion contracts covering the threat model, module
decomposition, test matrix, and non-goals. The challenge record (challenges
1–5, follow-ups F1–F4, and answers) lives in `.hacp/log.md`. Until both
acceptances exist, no `src/secure/` code is written.
