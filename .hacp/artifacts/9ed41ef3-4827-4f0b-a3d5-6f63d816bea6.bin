# HACP Secure — Test Matrix

Status: v1 (peer b) · Session s-3337e50c7f3c4d1c81024028690f7942 · Contract c-f52fbdb9da524494aff8aed2327d36d6
Sources: `docs/security-architecture.md` §4–§9, `spec/schemas/secure-envelope.json`,
`docs/hacp-secure-threat-model.md` (TH-xx), `docs/hacp-secure-modules.md` §4 pipeline.

**Conventions.**
- **Layer:** `U` = unit test in the module; `I` = integration test with two in-process guardians and a temp edge directory; `E` = end-to-end with two real `hacp-secure-guardian` processes, the `hacp` binary, and hacp-skill commands; `S` = static or build check.
- **Expected** is what the receiver's guardian returns. "abort" means the session is torn down and further envelopes for its `sid` get `SessionUnknown`.
- **Canary:** tests marked ⚑ plant known byte patterns (identity seed, session key, plaintext) and scan *every* agent-reachable output for them: stdout, stderr, error strings, `.hacp/`, `.hacp-secure/`.
- **Mode:** `std` means the test only runs with a dedicated guardian uid; everything else runs in both modes. A `std` test skipped in degraded mode must print `SKIP(degraded)`, never pass silently.
- **Settled:** every expected result reflects decisions accepted through HACP (challenges 1–5, F1–F7). Error expectations follow the normative pipeline order in architecture §8: routing, then signature, then sequence window, then AEAD, then TIER-2.

## 1. Functional baseline and compatibility

| ID | Property | Setup / attack | Expected | Error | Layer | Threat |
|---|---|---|---|---|---|---|
| T-01 | Normal secured exchange | A and B provisioned with mutual pins; A `session`, B `recv` (sends `ack`), A `recv`; A `send` 3 msgs, B `send` 3 msgs; both `recv` | 6 payloads delivered byte-identical, in order, exactly once; `seq` 0,1,2 per direction | none | E | INV-3 |
| T-36 | Backward-compatible agent workflow | Run the existing `cargo test` suite and a full hacp-skill session (start/join/propose/accept/submit/verify/close) with the `secure` module compiled in | Existing tests pass unchanged; `hacp` CLI output and `.hacp/` format are byte-for-byte unaffected | none | E | R1, R8 |
| T-20 | Bootstrap traffic before a freeze | `send` with `contract = ""` while the HACP contract is `proposed` | Delivered | none | I | R5 |

## 2. Key custody: secrets stay out of LLM context

| ID | Property | Setup / attack | Expected | Error | Layer | Threat |
|---|---|---|---|---|---|---|
| T-02 ⚑ | No key material in agent-reachable output | Run every `hacp-secure` command in success and failure paths | No canary byte sequence (hex, base64 or raw) appears in any output or edge file | none | E | TH-01, INV-1 |
| T-03 | No signing oracle | Send socket ops `sign`, `export`, `derive`, `debug`, `dump`, `key`, `seal_raw`, plus a `seal` with an injected `signing_input` field | Every unknown op is refused; extra fields are rejected; the socket allowlist is exactly `session, seal, open, status, fingerprint` | `UnknownOperation` / `SchemaViolation` | I | TH-03 |
| T-04 | Keyfile unreadable by the agent uid *(std)* | `sudo -u <agent> cat <keyfile>`; `sudo -u <agent> cat peers.json` | Both fail with EACCES | n/a | E | TH-02 |
| T-05 | Degraded mode is loud | Start the guardian same-uid without `--degraded`; then start it with `--degraded` | First refuses to start; second prints the degraded banner; `status.mode == "degraded"` and the session metadata records it | n/a | E | §2.1 |
| T-35 ⚑ | Error channel hygiene | Fuzz each pipeline stage (1–8) to force every `SecureError` variant | Error JSON contains only the variant name plus fixed detail; canary scan is clean | all | I | TH-21 |
| T-40 | Agent binary cannot link key code | Build `hacp-secure` without the `guardian` feature; `cargo tree -e features -i` and a symbol check for `IdentitySecret`/`SessionKeys` | Build succeeds with no secret types present; `client.rs` has no `crypto` import | n/a | S | INV-2 |

## 3. Authentication and impersonation

| ID | Property | Setup / attack | Expected | Error | Layer | Threat |
|---|---|---|---|---|---|---|
| T-09 | Unpinned identity rejected | `hello` from `urn:hacp:agent:mallory` (no pin) | Rejected; no session state allocated | `IdentityMismatch` | I | TH-04 |
| T-10 | Impersonation of a pinned URN | `hello` claiming `urn:hacp:agent:a`, signed with a fresh non-pinned key | Rejected | `BadHandshakeSignature` | I | TH-04 |
| T-11 | Handshake MITM | Swap `epub` (then `nonce`) in the `ack` in transit | A rejects; no keys derived | `BadHandshakeSignature` | I | TH-06 |
| T-12 | Handshake bound to HACP session | Replay a valid `hello` from HACP session S1 into S2 | Rejected | `BadHandshakeSignature` | I | TH-11 |
| T-28 | Pins cannot be changed from the project | Plant `peers.json` and `.hacp-secure/peers.json` in the project dir with an attacker key | Ignored; the attacker's `hello` still fails | `IdentityMismatch` | I | TH-05, INV-6 |
| T-32 | Reflection | Feed A's own sealed `msg` back to A's `recv` | Rejected before crypto | `IdentityMismatch` | I | TH-08 |
| T-38 | Misrouted message | Take a valid `msg` A→B and hand it to a third provisioned guardian C | Rejected (`to != self`) | `IdentityMismatch` | I | TH-08 |
| T-34 | Third-party attribution | Verifier holding only `pk_a` checks a captured `msg` signature over `HACP-SECURE/v1/msg ‖ aad ‖ ct` | Verifies without any AEAD key; fails for `pk_b` | none | U | TH-22 |

## 4. Tampering and integrity

| ID | Property | Setup / attack | Expected | Error | Layer | Threat |
|---|---|---|---|---|---|---|
| T-06 | Ciphertext bit-flip | Flip one bit in `ct` of a valid `msg` | Dropped; nothing delivered; `high` unchanged | `BadMessageSignature` (signature is checked before AEAD) | I | TH-07 |
| T-07 | AAD field tamper | Separately modify `to`, `contract`, `sid`, `seq`, `ts` | Dropped | `BadMessageSignature` (or `IdentityMismatch` for `to`, `SessionUnknown` for `sid`) | I | TH-07 |
| T-41 | Tag failure under a valid signature | Test hook: sender signs correctly but seals with the wrong directional key | Dropped at stage 7 | `TamperDetected` | U | TH-07 |
| T-29 | Schema conformance | Validate golden `hello`/`ack`/`msg` against `spec/schemas/secure-envelope.json`; then add an unknown field, drop `sig` from a `msg`, use uppercase hex, set `v: 2`, set a non-empty `contract` on a `hello` or `ack` | Goldens pass; each mutation fails | `SchemaViolation` | U | R7 |

## 5. Replay, ordering and session lifetime

| ID | Property | Setup / attack | Expected | Error | Layer | Threat |
|---|---|---|---|---|---|---|
| T-13 | Duplicate delivery | Copy an accepted `msg` file under a new name on the edge | Delivered once only; audit reason `duplicate`; no abort | `ReplayRejected` | I | TH-09, INV-4 |
| T-14 | Regression | After seq 0–5 are delivered, re-inject seq 2 | Dropped; audit reason `regression`; no abort | `ReplayRejected` | I | TH-09 |
| T-15 | Deletion gap | Deliver seq 0–2; delete seq 3; present seq 4, then seq 5 | 4 is held; 5 arrives while the hole at 3 persists, so the session aborts. **Never a silent stall** | `SequenceGap` | I | TH-10 |
| T-16 | Gap drain (reorder) | Present seq 4 before seq 3 | 4 held; when 3 arrives both are delivered in order 3, 4; queue empty afterwards | none | I | TH-10, INV-4 |
| T-43 | Shared hold-queue overflow | Fill the queue with 64 `ContractPending` envelopes, then present one gap-held envelope | Session aborts: gap holds and contract holds share the 64 cap | `HoldOverflow` | I | TH-10, TH-18 |
| T-44 | Error order: tampered replay | Re-inject an already-delivered seq with one `ct` bit flipped | Signature fails before the window is consulted | `BadMessageSignature` | I | F6 |
| T-45 | Error order: exact replay | Re-inject an already-delivered seq byte-for-byte | Signature passes, window rejects; no abort | `ReplayRejected` | I | F6, TH-09 |
| T-46 | Failed open does not advance the window | Present seq 3 that passes signature but fails the tag (T-41 hook); then present the correct seq 3 | First is dropped with `high` unchanged; the correct one is delivered | `TamperDetected` then none | I | F6, INV-4 |
| T-17 | Cross-session splice | Move a valid `msg` from `sid` X into session Y's directory and rewrite its `sid` | Rejected | `SessionUnknown` or `BadMessageSignature` | I | TH-11 |
| T-18 | No persisted replay state | Deliver seq 0–2; restart B's guardian; re-inject seq 0–2 | All rejected (session gone); a fresh handshake yields a new `sid` and works | `SessionExpired` / `SessionUnknown` | E | TH-13, INV-6 |
| T-19 | Nonce budget | Test hook sets the send counter to `u64::MAX` | `seal` refuses; receiver refuses a `seq == u64::MAX` successor | `SessionExhausted` | U | TH-20 |
| T-37 | Orphan sessions bounded | Replay the same valid `hello` 10 times | At most 4 pending sessions for that peer; oldest evicted and audited; no memory growth | none (audit) | I | TH-19 |

## 6. Contract binding

| ID | Property | Setup / attack | Expected | Error | Layer | Threat |
|---|---|---|---|---|---|---|
| T-21 | Race tolerance | Sender binds a `msg` to revision R before the receiver's `.hacp/` shows R frozen | Held; delivered automatically when R appears | `ContractPending` → delivered | I | R5 |
| T-22 | Hold bound | 65 envelopes pending on an unobserved revision | Session aborts at 65 | `HoldOverflow` | I | TH-18 |
| T-23 | Contract contradiction | `msg` bound to R1 while the receiver has observed frozen R2 for that contract | Session aborts | `ContractMismatch` | I | TH-12 |
| T-42 | Observed record integrity | Rewrite the receiver's `.hacp/` contract record so its stored digest does not match its content | Record not trusted; message not delivered | `ContractMismatch` | I | TH-17 |

## 7. Downgrade and fail-closed

| ID | Property | Setup / attack | Expected | Error | Layer | Threat |
|---|---|---|---|---|---|---|
| T-24 | Plaintext injection | Under `require_secure: true`, drop a plaintext HACP payload into the session's edge | Session aborts; payload never delivered | `DowngradeDetected` | I | TH-14, INV-5 |
| T-25 | Mode-pinning race | Write the plaintext object *before* any `hello` | Still `DowngradeDetected`: policy comes from pins, not from first traffic | `DowngradeDetected` | I | TH-15 |
| T-26 | `require_secure: false` is explicit | Pin with `require_secure: false`; send plaintext | Accepted **and** labeled `insecure` in `status` output | none | I | F1 |
| T-27 ⚑ | Guardian down | Kill the guardian; agent runs `send` with a canary payload | Command fails; canary absent from edge and `.hacp/` | `GuardianUnavailable` | E | TH-16, INV-5 |

## 8. Cryptographic correctness (known-answer)

| ID | Property | Setup | Expected | Error | Layer | Threat |
|---|---|---|---|---|---|---|
| T-39 | Primitive vectors | RFC 7748 (X25519), RFC 5869 (HKDF-SHA256), RFC 8439 (ChaCha20-Poly1305), RFC 8032 (Ed25519) test vectors | All match | n/a | U | R3, R4 |
| T-30 | Golden SecureEnvelope | Fixed identity seeds, ephemeral keys, nonces, `hacp_session`, payload | Exact `aad_bytes` (canonical JSON), `sid`, `k_i2r`, `k_r2i`, `ct`, `sig`, committed as fixtures | n/a | U | R5 |
| T-31 | Nonce layout | `seq = 1`, `seq = 2^32`, `seq = u64::MAX - 1` | `nonce96` = `00000000 ‖ u64be(seq)` exactly | n/a | U | §7 |
| T-33 | Domain separation | A valid `msg` signature checked as a `hello`/`ack` signature, and the reverse; directional keys compared | All cross-checks fail; `k_i2r != k_r2i` | n/a | U | TH-03 |

## 9. Coverage summary

| Requirement | Tests |
|---|---|
| R1 two agents via hacp-skill | T-01, T-36 |
| R2 keys inaccessible to agents | T-02, T-03, T-04, T-05, T-35, T-40 |
| R3 authenticated identities | T-09, T-10, T-11, T-28, T-32, T-38, T-34 |
| R4 encrypted messages | T-01, T-30, T-39, T-41 |
| R5 contract binding | T-12, T-17, T-20, T-21, T-22, T-23, T-42 |
| R6 replay protection | T-13, T-14, T-15, T-16, T-18, T-19, T-37, T-43, T-45, T-46 |
| R7 clear failure modes | T-06, T-07, T-29, T-35, T-44 and every row with an Error |
| R8 backward-compatible, strict wire | T-24, T-25, T-26, T-27, T-36 |
