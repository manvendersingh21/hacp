# HACP Secure — Threat Model

Companion to `docs/security-architecture.md` (normative design) and
`docs/hacp-secure-test-matrix.md` (test IDs). Mitigated threats name the test
that falsifies them; a threat with no test ID is a residual risk and appears
in the non-goals (§6).

## 1. Assets

| ID | Asset | Where | Why it matters |
|---|---|---|---|
| S1 | Ed25519 identity private key | Guardian memory; 0600 keyfile outside the project | Holder *is* the agent: impersonation + non-repudiable forgery |
| S2 | Session keys, ephemeral X25519 privates | Guardian memory only | Confidentiality/integrity of one session |
| S3 | Pin store and policy (`peers.json`) | Guardian-private config outside the project | Trust root; if writable, impersonation is a file write |
| S4 | Replay state (high-water marks, hold queue) | Guardian memory only | Rollback resurrects accepted nonces |
| P1 | Protected payload plaintext | Sender/receiver guardian, then receiving agent context | The thing being protected |
| M1 | Envelope metadata (URNs, `sid`, `seq`, sizes, authorship) | Edge, in the clear by design | Deliberately not protected (NG-6) |

## 2. Adversaries

| ID | Adversary | In scope? |
|---|---|---|
| ADV-1 | **Prompt-injected or compromised agent loop** (primary): arbitrary tool calls and project-dir writes under the agent uid; can call its own guardian's `seal`/`open`/`session` | **Yes** |
| ADV-2 | Edge attacker (any writer of the shared dir): observe, inject, delete, reorder, duplicate, modify | **Yes** |
| ADV-3 | Malicious but *pinned* peer | Attribution yes; content safety no (§4) |
| ADV-4 | Same-uid filesystem snooper | Standard: yes (uid wall). Degraded: **no** — residual risk |
| ADV-5 | Guardian-uid or root | **No** (trust kernel) |
| ADV-6 | Network observer | n/a — no network transport exists |

## 3. Threats and mitigations

STRIDE: **S**poofing, **T**ampering, **R**epudiation, **I**nformation
disclosure, **D**enial of service, **E**levation of privilege.

| ID | STRIDE | Threat | Mitigation → failure mode | Test |
|---|---|---|---|---|
| TH-01 | I | Agent exfiltrates S1 via a tool | No export command; API is seal/open/session only → no such path | T-02, T-35, T-40 |
| TH-02 | I | Agent reads the keyfile directly | Standard: uid wall + 0600. Degraded: **residual** | T-04 (standard) |
| TH-03 | E | **Signing oracle** | No raw `sign(bytes)`; domain-separated inputs `HACP-SECURE/v1/{hello,ack,msg}` → request refused | T-03, T-33 |
| TH-04 | S | Edge attacker claims peer B's URN | Handshake signature must verify under the **pinned** key → `IdentityMismatch`/`BadHandshakeSignature` | T-09, T-10 |
| TH-05 | S | Pins rewritten from the project | Pins live outside the project, guardian-writable only → no path | T-28 |
| TH-06 | T | MITM swaps ephemerals/nonces | Both in the signed transcripts → `BadHandshakeSignature` | T-11 |
| TH-07 | T | Bytes flipped in `ct` or any AAD field | Signature first, then Poly1305 tag → `BadMessageSignature`/`TamperDetected` | T-06, T-07, T-41 |
| TH-08 | T | **Reflection** of own envelope | `from == session peer ∧ to == self` checked before crypto; directional keys → `IdentityMismatch` | T-32, T-38 |
| TH-09 | T | Replay of an accepted msg | seq-as-nonce + memory-only high-water mark → `ReplayRejected` (drop + audit, no abort) | T-13, T-14 |
| TH-10 | T/D | **Deletion/gap** wedges the session | Bounded hold queue drains reorders; overflow or persistent hole + newer traffic → `SequenceGap`/`HoldOverflow` abort | T-15, T-16, T-43 |
| TH-11 | T | Cross-session splice | `hacp_session` in transcript and HKDF ctx; `sid` in AAD → tag failure | T-12, T-17 |
| TH-12 | T | Cross-contract splice | `contract` digest in AAD → `ContractMismatch` | T-23 |
| TH-13 | T | Replay-state rollback | No persisted replay state; restart voids sessions → `SessionExpired` | T-18 |
| TH-14 | T | **Downgrade** to plaintext | `require_secure` pin policy → `DowngradeDetected` hard abort | T-24 |
| TH-15 | T | TOFU mode-pinning race | Mode from provisioning policy, never first traffic → `DowngradeDetected` | T-25 |
| TH-16 | T | Kill guardian → plaintext fallback | No plaintext code path → `GuardianUnavailable` fail closed | T-27 |
| TH-17 | T | Control-plane forgery (`.hacp` rewrite) | Digests recomputed from canonical content; TIER-2 = attributable claim only → `ContractMismatch` on inconsistency; **residual** (NG-5) | T-42 |
| TH-18 | D | Hold-queue flooding | Capacity 64 per session → `HoldOverflow` | T-22 |
| TH-19 | D | Hello flood / orphan sessions | ≤4 pending per peer, oldest evicted, audited | T-37 |
| TH-20 | D | Nonce budget exhaustion | u64 overflow is a hard stop → `SessionExhausted` | T-19 |
| TH-21 | I | Error channel leaks secrets | Fixed error names; canary scan over all error paths | T-35 |
| TH-22 | R | Sender denies sending | Required per-message signature, publicly verifiable | T-34 |
| TH-23 | S/E | **Confused deputy**: sealed content is still malicious | **Not mitigated** — attribution, not benignity; **residual** (NG-1) | — |
| TH-24 | I | Plaintext after `open` (LLM context, provider logs) | **Not mitigated** — protects the edge, not the endpoint; **residual** (NG-3) | — |
| TH-25 | I | `.hacp/` control plane stays plaintext | **Not mitigated** — `hacp` binary unchanged by design; **residual** (NG-4) | — |

## 4. The confused deputy, stated plainly

The guardian holds authority (S1) the agent cannot extract (TH-01..03) but
can still *use* through `seal`. Accepted consequences:

1. A message that passes every check may still be malicious; receivers treat
   opened payloads as untrusted input.
2. The guarantee is **attribution, not benignity**.
3. Content-level policy (what may be sealed, human approval, output
   filtering) is outside this layer.

## 5. Security invariants (test obligations)

| ID | Invariant | Tests |
|---|---|---|
| INV-1 | No byte of S1/S2 appears in any agent-reachable output | T-02, T-35 |
| INV-2 | The agent-facing binary does not link key-store code | T-40 |
| INV-3 | Every delivered plaintext passed schema, session, routing, signature, replay, AEAD, TIER-2 — in that order | T-01, T-41 |
| INV-4 | Each `(sid, direction, seq)` delivered at most once, strictly in order | T-13, T-14, T-16 |
| INV-5 | Under `require_secure`, no plaintext is ever delivered | T-24, T-25, T-27 |
| INV-6 | No security state (keys, pins, counters) is read from the project directory | T-18, T-28 |
| INV-7 | Every rejection maps to exactly one named error | T-06..T-27 |

## 6. Non-goals (claims we refuse to make)

A non-goal is a claim we refuse to make, not a bug we forgot. If a demo or
pitch implies one of these, that statement is wrong.

**Content and agent safety**

- **NG-1** Semantic safety of authenticated content (confused deputy, TH-23).
- **NG-2** Prompt-injection defense — opened payloads are untrusted input.
- **NG-3** Plaintext protection after `open` (TH-24): the edge, not the endpoint.

**Scope of encryption**

- **NG-4** Control-plane (`.hacp/`) confidentiality or authenticity (TH-25).
- **NG-5** Proof of bilateral agreement in TIER-2: an attributable signed
  claim of a revision, nothing more (TH-17).
- **NG-6/7** Metadata confidentiality, traffic analysis, padding.

**Key lifecycle**

- **NG-8** PKI, CAs, chains, directories — pinned keys are the trust root.
- **NG-9** Rotation, expiry, revocation — operator re-provisions both stores.
- **NG-10** Post-compromise security (pre-theft sessions stay safe via
  ephemeral DH).
- **NG-11** Deniability — non-repudiation is deliberately in scope.
- **NG-12** HSM/TPM/keychain — the guardian API is the seam for later.
- **NG-13** Multi-device or multi-guardian identities: one URN, one guardian.

**Adversaries not defended against**

- **NG-14** Guardian-uid or root compromise (trust kernel).
- **NG-15** Deliberate same-uid filesystem snooping in degraded mode —
  labeled at startup, never silent.
- **NG-16** Side channels (timing, cache, swap); secrets are zeroized.
- **NG-17** DoS in general — bounded resources; every DoS is a named failure,
  never a silent stall or plaintext fallback.
- **NG-18** Post-quantum security.

**Engineering scope**

- **NG-19** Changes to HACP semantics or the `hacp` binary (T-36).
- **NG-20** Group/multi-party sessions — bilateral only.
- **NG-21** In-session rekeying; recovery is a fresh handshake.
- **NG-22** Wall-clock freshness; replay protection is counter-based (`ts` advisory).
- **NG-23** Network transport — local file edge and local socket only.
- **NG-24** Formal verification or third-party audit of the handshake.
