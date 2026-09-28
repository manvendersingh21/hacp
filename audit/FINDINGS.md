# HACP audit, 2026-09-27 (main @ 9e784bf)

Reference branch only; not for merge. Two read-only reviews, each defect
reproduced by a test in this directory. Fix branches start from `main`, turn the
relevant proof into a regression test that asserts the *fixed* behaviour, and
cite the finding ID.

- `v2_current_behaviour.rs` asserts today's (buggy) behaviour: every test passes
  while the defect exists. Copy it to `tests/` to run: `cargo test --test <name>`.
- `secure_proofs.rs` asserts the correct behaviour: its tests fail while the
  defect exists. It lives in the guardian's module tree: add
  `#[cfg(test)] #[path = "audit_proofs.rs"] mod audit_proofs;` to
  `src/secure/guardian.rs`, copy it to `src/secure/audit_proofs.rs`, and run
  `cargo test --all-features --lib audit_proofs`.

Everything else reviewed was found sound. Both reviews list what they checked:
canonical ordering, freeze digests, observer authoring, grant ledger, AEAD/AAD
binding, nonces, replay window, key hygiene, path handling.

## HACP/2.0 core (`src/v2`)

| ID | Severity | Finding | Where | Proof |
|---|---|---|---|---|
| V1 | high | A preauthorized permit can name any peer (another branch, the root, a stranger). The peer is never checked against the grantor's authority. | `grant.rs` `by_preauthorization` 425-458, `authorize_session` 513-522; `profile.rs` `authorize_siblings` 71-111 | `preauth_permit_reaches_a_peer_outside_the_grantors_authority` |
| V2 | high | One participant can end a frozen, executing contract as NoAgreement by proposing an amendment and countering itself up to `max_rounds`. The same move escapes a Rework verdict. | `contract.rs` `counter` 250-279, `propose_amendment` 486-499 | `one_party_unilaterally_exits_a_frozen_contract_via_amendment_counters`, `performer_escapes_rework_via_self_countered_amendment` |
| V3 | medium | Escalation `refer` never climbs above the first mediator, since the LCA of siblings is their parent. Parent–child delegation parties can't raise a dispute (`NotSameParent`), and `raise(a, a)` succeeds. | `escalation.rs` 96-137 | `referral_never_moves_above_the_shared_parent`, `delegation_parties_cannot_raise_but_self_dispute_can` |
| V4 | medium | A delegation contract isn't bound to a grant, so `child_authority ⊆ parent_delegable_authority` is never enforced on contracts. `escalation_path` is only checked for non-emptiness. | `contract.rs` 157-189, 209 | code reading (see §8.1) |
| V5 | medium-low | An amendment agreed by both parties at the bound lands in NoAgreement, and `propose_amendment` is never refused at the bound. Conflicts with §7.4 "without agreement". The in-crate test `amendment_bounds_end_in_no_agreement` encodes the current behaviour. | `contract.rs` 486-499, 537-544 | `mutually_agreed_amendment_at_bound_is_no_agreement` |
| V6 | medium-low | Canonical digests disagree with the Python peer for integers outside i64/u64 and for `-0`. | `canon.rs` `write_number` 140-156; `tests/interop/peer.py` | `canonical_refuses_integers_the_spec_and_python_peer_accept` |
| V7 | low (spec gap) | Rework is unbounded; 1.1 had `max_rework_rounds`. | `contract.rs` decide/rework | reading |
| V8 | low | The `"deployment"` charterer in the docs is rejected by `check_shape`. `hive-recursive-pairwise/1` can't be an Agent capability because of the `/`. `in_reply_to: null` doesn't round-trip. Spec prose says `accepted/rejected` while the wire uses `accept/reject`. | `grant.rs` 97-123, `agent.rs` 82-93, envelope, spec §9.3 | `low_items` |

## HACP Secure (`src/secure`, feature `guardian`)

| ID | Severity | Finding | Where | Proof |
|---|---|---|---|---|
| S1 | medium-high | With 5 or more hellos from one peer against a pending cap of 4, the responder re-answers old hellos, evicts every AckSent session on each `open`, and never establishes. The livelock is permanent, and re-handshaking adds hellos. An injected agent can trigger it with 5 `session` calls. | `session.rs` 111-152, 203-211; `guardian.rs` 715-785 | `proof_five_hellos_livelock_responder_never_keeps_session`, `proof_livelock_is_permanent_and_rehandshake_does_not_recover` |
| S2 | medium | A FIFO at `.hacp/session.json` blocks `contract_view` in `open(2)` forever, hanging the single-threaded guardian. Needs `O_NONBLOCK` and an is-file check, as `read_edges` already does. | `guardian.rs` 398-403 | `proof_fifo_session_json_hangs_guardian` |
| S3 | low | The rate budget is a fixed window, but the spec and docs say rolling, so 2× the cap is admitted across a window boundary. | `guardian.rs` 36-58, 261 | `proof_fixed_window_admits_double_cap_within_one_second` |
| S4 | low | Every rate-limited request appends an audit line, so the audit file grows without bound. | `guardian.rs` 273-276 | `proof_rate_limited_requests_still_append_audit_lines` |
| S5 | low | The schema's `ct` pattern accepts odd-length hex, which the code rejects. The code accepts a space-separated `ts`, which the schema's `date-time` does not. | `spec/schemas/secure-envelope.json`, `envelope.rs` 151-157 | `proof_schema_vs_code_ct_odd_and_ts_space` |
| S6 | low (docs) | `docs/hacp-secure.md` §4 says the ack signature covers the sid; it doesn't, though the sid is re-derived and checked. | `envelope.rs` 224-247 | reading |

CI to pass before any PR (`.github/workflows/ci.yml`): `cargo build --locked`,
`cargo test --locked --no-run`, `cargo test --locked`,
`cargo build --locked --features guardian`, `cargo test --locked --all-features`,
`cargo run --locked --example bilateral`, `cargo doc --locked --no-deps`,
`cargo package --locked`.
