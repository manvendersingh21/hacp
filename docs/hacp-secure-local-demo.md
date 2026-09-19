# HACP Secure — Local Demo

```sh
python3 scripts/demo-hacp-secure.py
```

Requires Unix, Rust/Cargo, Git, Python 3.9+. The first run may download
pinned sources and locked dependencies. The script builds a disposable
hacp-skill checkout from `integrations/hacp-skill/source.json` + `secure.patch`
(reusing `../hacp-skill`'s object database when possible; `HACP_SKILL_SOURCE`
selects another source) and runs that skill's entire CLI test suite. It never
modifies the source or the installed `hacp` command. Artifacts cache under
`target/`; temp projects and guardian processes are cleaned up.

## Asserted outcomes (any failure exits non-zero)

```text
NORMAL MESSAGE: ACCEPTED
TAMPERED MESSAGE: REJECTED
REPLAYED MESSAGE: REJECTED
IMPERSONATION: REJECTED
PLAINTEXT DOWNGRADE: REJECTED
LEGITIMATE HACP COLLABORATION: COMPLETED
```

Additional assertions: signed metadata, wrong recipient, forged shared
receipts, planted outgoing messages, contract observation holds and
contradictions, bounded sequence-gap handling, secret-export and raw-sign
rejection, and an authenticated question blocking completion until answered.
Attack cases use fresh sessions so an intentional abort cannot invalidate a
later positive test.

## What runs

The patched `hacp` CLI executes start/join, two propose/accept exchanges,
poll, ask/answer, two submit/verify exchanges, complete, and close. Both
contracts freeze concurrently and both must settle. The script asserts message
identities and contents, encrypted edge files, no plaintext inbox projections,
accepted verification outcomes, and the persisted `completed` result — no mock
skill, no inference from a close reason.

```text
Agent A -> hacp CLI -> key-free Workflow IPC -> Guardian A
        -> encrypted .hacp-secure edge -> Guardian B
        -> key-free Workflow IPC -> hacp CLI -> Agent B
```

Operator provisioning per agent:

```sh
export HACP_SECURE=1
export HACP_SECURE_SOCKET=/absolute/path/to/that-agents-guardian.sock
export HACP_SECURE_STATE=/absolute/path/to/that-agents-private-state-directory
```

The state directory must pre-exist, be owned by the agent's UID, be mode 0700,
and be outside the shared project. Secure mode is selected when starting a
fresh session; plaintext sessions are not migrated. Missing IPC, a missing
state directory, or unsetting secure mode on a marked session fails closed.
Agents keep using ordinary `hacp` commands and terms; no cryptographic
parameters or secret material enter the skill instructions.

## Skill patch scope

`secure.patch` (against the commit pinned in `source.json`) adds: optional
guardian workflow glue and durable private delivery/send receipts with locally
staged outgoing frames (`src/secure.rs`); secure ingestion, sticky
secure-session marker, and suppression of plaintext inbox projections
(`src/store.rs`, `src/messages.rs`); authenticated history for questions,
answers, and polling; completion evaluated over authenticated history
(`src/completion.rs`); peer context threading (`src/artifacts.rs`,
`src/verify.rs`). `SKILL.md` and agent-facing syntax are unchanged; custody
stays in guardians; the workflow API uses only the allowlisted socket verbs.

## Coverage and limits

- `cargo test --locked`: 164 tests; `--all-features`: 204. Patched skill: 2
  unit + 25 CLI tests. Covers protocol, schema registry, adapter, crypto,
  session, guardian, transport/replay, and real process IPC.
- The demo runs **degraded mode (same UID)**: it proves IPC restrictions and
  transport behavior, not OS isolation. Dedicated-UID isolation is an
  unexecuted deployment test.
- `.hacp` control state stays cooperative and plaintext (non-goal NG-4/NG-5).
  Private receipts stop shared-file injection from being treated as
  authenticated input; they cannot authenticate bilateral freezes.
- Guardian state is memory-only; restart requires fresh sessions. Local
  receipt persistence is not a distributed transaction: a crash after sealing
  but before recording a send receipt can reseal the same logical message
  under a new sequence; message IDs deduplicate delivery. No exactly-once
  crash-recovery claim.
- No Wasmer, Tenki, or HIVE integration here (see the wasmer/tenki docs).
