# HACP Secure local integration

From this checkout, run:

```sh
python3 scripts/demo-hacp-secure.py
```

Requires Unix, Rust/Cargo, Git, and Python 3.9 or later. The first run may download pinned source and locked Cargo dependencies. The script uses the sibling `../hacp-skill` Git object database when it contains the pinned commit; `HACP_SKILL_SOURCE` can select another local source. It never modifies that source or the installed `hacp` command. It builds a disposable checkout and runs its entire existing CLI test suite. Build products are cached under `target/`; temporary projects and guardian processes are cleaned up.

The result includes these asserted outcomes (failure exits nonzero):

```text
NORMAL MESSAGE: ACCEPTED
TAMPERED MESSAGE: REJECTED
REPLAYED MESSAGE: REJECTED
IMPERSONATION: REJECTED
PLAINTEXT DOWNGRADE: REJECTED
LEGITIMATE HACP COLLABORATION: COMPLETED
```

Additional assertions cover signed metadata, wrong recipient, forged shared receipts and planted outgoing messages, contract observation holds and contradictions, bounded sequence-gap handling, secret-export and raw-sign operation rejection, and an authenticated question absent from the cooperative snapshot blocking completion until answered. Attack cases use fresh sessions so an intentional abort cannot invalidate a later positive test.

## Existing agent workflow

The actual patched `hacp` CLI executes `start`, `join`, two `propose`/`accept` exchanges, `poll`, `ask`, `answer`, two artifact `submit`/counterparty `verify` exchanges, `complete`, and recipient `poll` observing `session.close`. Both contracts are frozen concurrently and both must settle before completion. A separate decline-and-termination fixture exercises the existing negative negotiation path. The script asserts message identities and contents, encrypted edge files, absence of plaintext inbox projections, accepted verification outcomes, and the persisted `completed` outcome. It does not substitute a mock skill or infer completion from a close reason.

```text
Agent A -> hacp CLI -> key-free Workflow IPC -> Guardian A
        -> encrypted .hacp-secure edge -> Guardian B
        -> key-free Workflow IPC -> hacp CLI -> Agent B
```

An operator provisions and pins guardian public identities and supplies each agent's environment:

```sh
export HACP_SECURE=1
export HACP_SECURE_SOCKET=/absolute/path/to/that-agents-guardian.sock
export HACP_SECURE_STATE=/absolute/path/to/that-agents-private-state-directory
```

The state directory must already exist, be owned by the agent's UID, have mode 0700, and be outside the shared project. The demo provisions these automatically. Agents continue using their existing `hacp --peer a|b` commands and ordinary HACP terms. No cryptographic parameters, envelope handling, counters, or secret material enter the skill instructions or agent command flow. Secure mode must be selected when starting a fresh HACP session; existing plaintext sessions are not migrated implicitly. Missing guardian IPC, a missing private state directory, or unsetting secure mode on a marked session fails closed.

## Exact compatibility changes

`integrations/hacp-skill/source.json` pins upstream commit `0d0c6a33a1da8a6f3d864702c6ba4c2b6a348fb3`. `secure.patch` changes:

- `src/secure.rs`: optional guardian workflow glue, durable private delivery/send receipts and locally staged outgoing frames, per-message contract binding, and authenticated peer-message visibility.
- `src/store.rs`: explicit peer context, sticky secure-session marker, transient received-message map, guardian ingestion, state publication before sealing notifications, and suppression of plaintext inbox projections in secure mode.
- `src/messages.rs`: secure ingestion, authenticated history for question/answer semantics and polling, and binding capture before state transitions.
- `src/main.rs`: initialize secure-session metadata and filter status through authenticated message history.
- `src/artifacts.rs` and `src/verify.rs`: pass the already explicit peer into the store; their artifact and verification semantics are unchanged.
- `src/completion.rs`: evaluate unanswered questions using authenticated history.
- `Cargo.lock`: local HACP dependency and its key-free base64 dependency. The demo replaces the manifest's HACP dependency with this checkout's path and builds with `--locked`, default features only.

The installed skill's `SKILL.md` and agent-facing command syntax are unchanged. Cryptographic custody remains in guardians. `src/secure/workflow.rs` exposes only `Workflow::new`, `ensure_session`, `send`, `receive`, and an `Inbox` of ordinary HACP messages, fixed errors, and a hold flag. It uses the existing allowlisted socket verbs; it exposes no raw signature or key-returning operation.

Guardian correctness fixes add public HACP session context to status and observe multiple current contract revisions, including final notifications for settled/rejected/no-agreement contracts and never-frozen withdrawn proposals. Every retained record is digest-recomputed. Superseded revisions abort. An unmatched digest holds only while there is no frozen observation or an eligible bootstrap observation; otherwise it contradicts observed context and aborts. This conservative ambiguity follows the existing digest-only wire schema; no contract identifier or new field was added to SecureEnvelope.

## Security coverage and limits

The integration runs pass 164 tests with `cargo test --locked` and 204 with `cargo test --locked --all-features`. The patched skill passes its 2 unit tests and 25 CLI tests. These suites cover the protocol, schema registry, adapter, crypto/session core, guardian, transport/replay, and real process IPC. The frozen secure envelope remains separately authored and excluded from generated v2 schema registry comparisons; the registry regression passes.

The demo deliberately uses **degraded mode (same UID)**. It proves IPC API restrictions and transport behavior, not OS isolation against a hostile same-UID process. A same-UID process can read guardian-owned files despite mode 0600; standard mode requires a distinct guardian UID and operator-provisioned socket ACLs. Dedicated-UID isolation remains an unexecuted deployment test here. Neither the demo nor agent API reads private identity files or exports session secrets.

The frozen architecture explicitly leaves `.hacp` control-state authenticity outside scope. Shared snapshots, contracts, artifacts, and collaboration logs can still contain plaintext and can be modified by a shared-project writer. HACP Secure protects transported message payloads and attributable revision claims; it does not encrypt the entire workspace or authenticate bilateral freezes. Private receipt storage prevents shared-file injection from being treated as authenticated incoming messages, and private outgoing staging prevents a planted snapshot message from requesting a local signature, but cannot turn cooperative contract state into an authenticated control plane.

Guardian sessions and counters remain memory-only. Guardian restart requires fresh session establishment; the adapter fails closed for missing/expired sessions and does not silently resume counters. Local receipt persistence and remote at-most-once delivery are not a distributed transaction: an I/O failure after guardian delivery can require restarting the collaboration. A crash after sealing but before recording a send receipt can reseal the same logical message under a new guardian-owned sequence; validated message IDs deduplicate delivery. No exactly-once crash-recovery guarantee is claimed.

No Wasmer, Tenki, or HIVE integration is included.
