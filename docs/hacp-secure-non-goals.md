# HACP Secure — Explicit Non-Goals

Status: v1 (peer b) · Session s-3337e50c7f3c4d1c81024028690f7942 · Contract c-f52fbdb9da524494aff8aed2327d36d6
Extends `docs/hackathon-scope.md` §5 (peer a). Every entry says what we do
**not** claim, why, and what a user must do instead. Threat IDs refer to
`docs/hacp-secure-threat-model.md`.

A non-goal is a claim we refuse to make, not a bug we forgot. If a demo, README
or pitch implies one of these, that statement is wrong.

## 1. Content and agent safety

| # | Non-goal | Why | What remains true |
|---|---|---|---|
| NG-1 | **Semantic safety of authenticated content (confused deputy).** A compromised or prompt-injected agent can ask its own guardian to seal malicious content, and a pinned peer can send a payload that injects the receiver. | Authentication proves *who* produced bytes, never that they are benign. Deciding what is safe to seal is a policy layer (TH-23). | Every sealed message is attributable to a pinned identity through its per-message signature. |
| NG-2 | **Prompt-injection defense.** | Out of layer. The receiving agent must treat opened payloads as untrusted input. | n/a |
| NG-3 | **Plaintext protection after `open`.** Once delivered, the payload is in the receiving LLM context, its transcripts and logs, and the model provider's request path. | HACP Secure protects the shared edge, not the endpoint (TH-24). | Nothing on the shared edge is plaintext. |

## 2. Scope of what is encrypted

| # | Non-goal | Why | What remains true |
|---|---|---|---|
| NG-4 | **Confidentiality or authenticity of the HACP control plane.** `.hacp/` sessions, contract terms, questions, answers, submissions and verification records stay plaintext and unsigned. | The `hacp` binary and protocol are frozen and unchanged by design (TH-25). | Only payloads explicitly sent through `hacp-secure send` are protected. |
| NG-5 | **Proof of bilateral contract agreement in TIER-2 binding.** The guardian's view of a frozen revision comes from agent-writable `.hacp/` state. | Signed freezes would change HACP semantics (TH-17). | TIER-2 proves the sender made a signed, attributable claim of revision D, and inconsistent records (digest does not match content) are rejected. |
| NG-6 | **Metadata confidentiality.** URNs, `sid`, `seq`, `contract` digest, ciphertext length, timing, and authorship (signatures are publicly verifiable) are all visible on the edge. | A shared-directory edge cannot hide who talks to whom without mixing and padding. | Payload bytes are confidential. |
| NG-7 | **Traffic-analysis resistance and padding.** | Same reason as NG-6. | n/a |

## 3. Identity and key lifecycle

| # | Non-goal | Why | What remains true |
|---|---|---|---|
| NG-8 | **PKI, certificate authorities, chain validation, or a directory service.** | Two agents with an operator present: pinned keys exchanged out of band are the smallest sound trust root. | Pins live in guardian-private `peers.json`, outside the project. |
| NG-9 | **Key rotation, expiry, or revocation.** | Needs a lifecycle protocol that is larger than the MVP. | The operator re-provisions both pin stores; old sessions die with guardian restart. |
| NG-10 | **Post-compromise security.** If an identity key is stolen, the thief can run new handshakes as that agent until an operator re-provisions pins. | Needs ratcheting or revocation (NG-9). | Session keys derived *before* the theft come from ephemeral X25519 and are not recoverable from the identity key. |
| NG-11 | **Deniability.** | We deliberately chose per-message signatures for third-party attribution; the two properties conflict. | Non-repudiation is in scope. |
| NG-12 | **HSM, TPM, secure enclave or OS keychain integration.** | Platform-specific; not needed to demonstrate the boundary. | The keyfile is 0600 under the guardian uid; the guardian socket API is the seam where hardware storage would plug in later. |
| NG-13 | **Multi-device or multi-guardian identities.** One agent URN has exactly one guardian and one key. | Simplicity. | n/a |

## 4. Adversaries we do not defend against

| # | Non-goal | Why | What remains true |
|---|---|---|---|
| NG-14 | **Guardian-uid or root compromise** (standard mode). | That account is the trust kernel. | n/a |
| NG-15 | **A same-uid attacker who deliberately snoops the filesystem, in degraded mode.** On a single-uid hackathon laptop, the agent can read the keyfile if it goes looking for it. | Without a uid wall, no userspace design prevents this. | Degraded mode refuses to start silently, prints a banner, and records the mode in session metadata. No agent tool surfaces key material (context hygiene). |
| NG-16 | **Side channels:** timing, cache, power, swap or core dumps. | Beyond library-provided constant-time primitives and `zeroize`, not addressed. | Secret types are zeroized on drop. |
| NG-17 | **Denial of service in general.** A writer to the shared edge can always delete everything or force aborts. | The edge is a shared directory. | Resource exhaustion is bounded (hold queue 64, pending sessions per peer), and every DoS shows up as a named failure, never a silent stall or a plaintext fallback. |
| NG-18 | **Post-quantum security.** | Classical primitives were the fixed brief. | n/a |

## 5. Protocol and engineering scope

| # | Non-goal | Why | What remains true |
|---|---|---|---|
| NG-19 | **Changes to HACP semantics or the `hacp` binary.** | Frozen; HACP Secure is a payload wrapper. | Existing tests and workflows pass unchanged (T-36). |
| NG-20 | **Group or multi-party sessions.** | HACP core is bilateral. | Exactly two participants. |
| NG-21 | **Rekeying within a session or lossy-channel adaptivity.** | The at-least-once edge plus a fresh handshake covers the MVP. | `SessionExhausted` and `SessionExpired` recover by a new handshake. |
| NG-22 | **Wall-clock freshness or message expiry.** `ts` is advisory. | Clocks are not trusted; replay protection is counter-based. | Replay is rejected by `seq`, not by time. |
| NG-23 | **Network transport.** No TCP, TLS, broker or daemon-to-daemon link. | The HACP edge is a shared local directory. | The guardian socket is local only. |
| NG-24 | **Formal verification or a third-party audit** of the handshake. | Hackathon timeline. | The design uses a standard signed-ephemeral (SIGMA-style) pattern with RFC primitives and known-answer tests (T-30, T-39). |
