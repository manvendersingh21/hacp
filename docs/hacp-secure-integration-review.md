# HACP Secure integration review

Peer B review for integration session `s-495a65ede8174611ae2e68db00a2fb19`.
Initial output contract: `c-10bc5986326e4e298d5cfe1cf48aeb76`, revision
`4e06b1f755f6d8a0966f5ddcc38d9d3b20c6de8206883949c3285d36b825b3dc`.
Terminal-flow follow-up: `c-41779f21b87541e097158958cc3730fa`, revision
`42879b8ccbe28283b0c748b1418bcb85a89d6d37707c285e7be77658570d3eb0`.

## Findings and corrections

The Phase 2 observer selected exactly one executing/verifying/amending
contract. The existing skill can have two simultaneous contracts, and sends
verification/completion notifications after settlement. The observer now
recomputes every retained revision, accepts a current binding from any observed
contract, retains settled/rejected/noagreement contracts' last frozen binding, and rejects a
superseded binding. It does not change SecureEnvelope, the key schedule,
signature/AAD input, nonce ownership, crypto operations, or replay state.

A proposed/countered contract, or a terminal noagreement/withdrawn contract
with no frozen history, permits bootstrap negotiation while other contracts
execute.
The latter preserves the final decline notification; a terminal contract that
has frozen history retains its latest recomputed binding instead. Unknown nonempty bindings remain held in this case or
when no frozen revision is observed. When all observed contracts are frozen,
an unmatched binding fails closed. Empty bootstrap is rejected in that state.
The digest-only frozen wire field cannot identify whether an unmatched digest
refers to an unseen contract or a conflicting revision; the integration keeps
the existing conservative contradiction behavior in this ambiguous case.

Guardian status includes the public `hacp_session` identifier so the adapter
selects a session by both peer and collaboration context. The socket allowlist
remains `session`, `seal`, `open`, `status`, and `fingerprint`. A corrupt
observation closes the secure session and reports `ContractMismatch` in the
aborted list as well as the rejected list.

The thin workflow API uses those existing Guardian verbs and passes structured
HACP messages. It validates the authenticated outer sender against the inner
sender, recipient, and session. It rejects insecure plaintext deliveries and
retains valid deliveries alongside independent replay/tamper/hold reports so
callers can persist successful receipt before surfacing an unrelated failure.

Review of the first skill patch found that trusting delivery files under
`.hacp/secure-received` would create an unauthenticated ingestion route. The
counterparty moved receipts and sent markers to operator-configured
`HACP_SECURE_STATE` outside the shared project, checks private directory
ownership/permissions and refuses symlink receipt reads, skips the receipt map
in shared snapshot serialization, and rebuilds peer visibility from local
receipts. Incoming messages retain existing schema, routing, ask/answer and
reply validation. Review also found that completion and outgoing replies must
use this authenticated view; the patch corrects those paths. These changes
add no cryptographic responsibility or manual envelope fields to the skill.
The existing agent-facing commands stay the same.

Further review found that projecting unsent messages from the shared snapshot
could cause the local Guardian to authenticate a planted outgoing message. The
patch now stages exact locally generated messages and their bindings in the
private agent state before snapshot publication. Sending requires a private
queued original that exactly matches the published message; shared bindings
and messages alone cannot authorize a seal.

A real CLI decline fixture exposed the core's `withdrawn` terminal state,
which differs from negotiation-bound `noagreement`. The follow-up observer
fix preserves never-frozen withdrawal notification delivery alongside other
frozen contracts and rejects contradictory frozen history on a withdrawn
record. The core allows withdrawal only before freeze. Verification rejection
is a post-freeze terminal state and retains its latest frozen revision, with
unit coverage alongside successful settlement and amendment-bound failure.

The reproducible demo additionally attempts forged shared receipt/snapshot
injection and a valid Guardian-delivered question absent from shared sender
bookkeeping. Initial focused counterparty verification is preserved in the archived
integration coordination record under `.hacp-history/`.
Final direct full-suite and demo results are reported in
`docs/hacp-secure-local-demo.md`; integration proceeds without further HACP
commands following the user's updated instruction.

## Focused validation

Commands executed from the integration project:

- `cargo test --locked --test secure_workflow`: 7 passed.
- `cargo test --locked --all-features --test secure_workflow`: 10 passed.
- `cargo test --locked --all-features --test secure_transport`: 17 passed.
- `cargo test --locked --all-features secure::guardian::tests`: 7 passed.
- `cargo test --locked the_registry_and_the_committed_directory_agree`: 1 passed.

The seven key-free tests cover context-selective send, ordinary session setup,
missing/ambiguous Guardian sessions, delivery plus independent errors/holds,
inner/outer identity and context consistency, plaintext/malformed rejection,
and outbound impersonation rejection before IPC. Three Guardian-feature tests
cover simultaneous contracts, pending delivery followed by observation and
superseded rejection, and bootstrap gating. An additional Guardian unit test
covers concurrent/settled/proposed observations and corruption of historical
revision content.

The schema registry keeps the separately authored `secure-envelope.json`
outside generated HACP/2.0 schemas. The existing registry regression passes;
the frozen schema is unchanged.

One test harness portability issue was corrected: accepted Unix streams can
inherit a nonblocking listener flag on BSD/macOS. The scripted Guardian fixture
explicitly switches accepted streams back to blocking mode before its bounded
read. No production test expectation was weakened.

## Security boundaries

The local demo uses the architecture's explicit same-UID degraded mode.
No API returns a Guardian private key or a session secret, and no raw-sign
operation exists, but same-UID filesystem access is not prevented by context
hygiene. Dedicated-UID isolation must be tested separately before claiming
standard-mode process isolation.

Shared `.hacp` contract state is still cooperative. Revision binding proves an
attributable digest claim and checks digest consistency; it does not prove
bilateral consent against a writer who forges all control state consistently.
Plaintext endpoint histories and model contexts are outside edge confidentiality.
No Wasmer, Tenki, or HIVE integration is included.
