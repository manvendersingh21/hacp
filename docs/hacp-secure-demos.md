# HACP Secure — Demos

Three demonstrators: local end-to-end, Wasmer sandbox execution, and a
two-VM Tenki deployment. All exit non-zero on any failed assertion. Design
and guarantees: `docs/hacp-secure.md`. Setup: `docs/hacp-secure-integration.md`.

## 1. Local end-to-end

```sh
python3 scripts/demo-hacp-secure.py
```

Requires Unix, Rust/Cargo, Git, Python 3.9+. Builds a disposable hacp-skill
checkout from `integrations/hacp-skill/source.json` + `secure.patch` (reusing
`../hacp-skill`'s object database when possible; `HACP_SKILL_SOURCE` selects
another) and runs that skill's full CLI test suite. Never modifies the source
or the installed `hacp` command; caches under `target/`; cleans up processes
and temp projects.

Asserted outcomes (fresh sessions per attack so an abort cannot poison later
assertions):

```text
NORMAL MESSAGE: ACCEPTED          TAMPERED MESSAGE: REJECTED
REPLAYED MESSAGE: REJECTED        IMPERSONATION: REJECTED
PLAINTEXT DOWNGRADE: REJECTED     LEGITIMATE HACP COLLABORATION: COMPLETED
```

Plus: signed metadata, wrong recipient, forged shared receipts, planted
outgoing messages, contract holds and contradictions, bounded gap handling,
secret-export/raw-sign rejection, and an authenticated question blocking
completion until answered.

The patched `hacp` CLI runs start/join, two propose/accept exchanges, poll,
ask/answer, two submit/verify exchanges, complete, close — both contracts
freeze concurrently and both must settle. The script asserts message
identities, encrypted edge files, no plaintext inbox projections, accepted
verifications, and the persisted `completed` result (no mock skill, no
inference from a close reason).

```text
Agent A -> hacp CLI -> key-free Workflow IPC -> Guardian A
        -> encrypted .hacp-secure edge -> Guardian B
        -> key-free Workflow IPC -> hacp CLI -> Agent B
```

Operator environment per agent (state dir must pre-exist, be owned by the
agent UID, mode 0700, outside the shared project; secure mode is chosen at
session start, plaintext sessions are not migrated; anything missing fails
closed):

```sh
export HACP_SECURE=1
export HACP_SECURE_SOCKET=/absolute/path/to/that-agents-guardian.sock
export HACP_SECURE_STATE=/absolute/path/to/that-agents-private-state-dir
```

Skill patch scope: optional guardian workflow glue, durable private
delivery/send receipts, locally staged outgoing frames, secure ingestion,
sticky secure-session marker, no plaintext inbox projections, authenticated
history for questions/answers/polling/completion. `SKILL.md` and agent-facing
syntax unchanged; custody stays in guardians; only allowlisted socket verbs.

Coverage: `cargo test --locked` 164 tests, `--all-features` 204; patched
skill 2 unit + 25 CLI tests.

## 2. Wasmer sandbox execution

Agent A asks Agent B's side to run code: request over HACP Secure, B
authorizes against operator policy, Wasmer runs it, result returns sealed.

```sh
python3 scripts/demo-hacp-wasmer.py
cargo test --locked --manifest-path infra/wasmer/Cargo.toml
```

Nothing in `src/`, `tests/`, `integrations/`, `spec/`, or the secure demo
changes — the bridge uses only existing guardian socket verbs and links
`hacp` **without** the `guardian` feature (an acceptance check fails if any
crypto crate appears in its dependency tree).

```
Agent A ── hacp-exec ──seal(binding)──► Guardian A ──► encrypted edge
Guardian B: verify, decrypt, check session + binding
  → hacp-exec-guardian (key-free): authorize against operator policy
  → ExecutionRequest (approved fields only)
  → wasmer run (env cleared, /work only, no net unless granted)
  → ExecutionResult ──seal(same binding)──► Guardian A → hacp-exec → Agent A
```

Guardian B refuses delivery on a binding mismatch; Guardian A refuses to seal
one; the bridge refuses an empty binding. Refused requests never reach
Wasmer — the requester gets a sealed `denied` result.

Wire bodies (unknown fields refused; files travel by value into `/work`; no
field can name a host path):

```json
{"package":"python/python@3.13.20","args":["/work/main.py"],
 "files":[{"path":"main.py","content_b64":"…"}],"env":{…},"network":[],
 "timeout_ms":5000,"max_output_bytes":65536}
```

```json
{"status":"completed","exit_code":0,"stdout":"…","stderr":"","output_truncated":false,"duration_ms":41,"failure":null}
{"status":"failed","exit_code":null,"failure":{"kind":"TimedOut","detail":"…"}}
{"status":"denied","denial":{"code":"NetworkNotAllowed","detail":"…"}}
```

Application kinds, not HACP registry kinds; EXECUTE remains a contract state.

Boundary: authorization happens **before** request construction (binding,
requester allowlist, package/timeout/output/arg/file/env/network policy
checks, then the executor validates again); Wasmer receives only the
`ExecutionRequest` (cleared env + `WASMER_DIR`, stdin closed, fresh 0700
`/work` removed afterwards, `HACP_*` guest variables refused at both layers);
policy is operator-owned, read at service start, unreachable from messages;
host failures report fixed text only.

Entry points:

```sh
cargo build --locked --release --manifest-path infra/wasmer/Cargo.toml --bins

# executing peer (B), key-free
hacp-exec-guardian --socket <guardian-B.sock> --agent urn:hacp:agent:b \
  --context <HACP session id> --policy <policy.json> \
  [--audit <audit.jsonl>] [--staging-root <dir>] [--poll-ms N] [--once]

# requesting peer (A), key-free
hacp-exec --socket <guardian-A.sock> --agent urn:hacp:agent:a --peer urn:hacp:agent:b \
  --context <HACP session id> --contract sha256:<frozen revision digest> \
  --package python/python@3.13.20 --file main.py=./main.py --arg /work/main.py \
  [--env K=V]... [--net RULE]... [--timeout-ms N] [--max-output-bytes N] [--wait-secs N]
```

Outcomes are metadata-only JSON (`executed`/`failed`/`denied`/`rejected`/
`ignored`). Runtime lookup: `HACP_WASMER_BIN` (else `wasmer`), `WASMER_DIR`
(else `~/.wasmer`); neither reaches the guest. Demo policy:
`infra/wasmer/exec-policy.example.json`.

Demo assertions (decided on the host — canaries, write probe, connection
counter, audit log — never from guest self-reports):

```text
EXECUTION CONTRACT: FROZEN            LEGITIMATE EXECUTION: PASS
HOST FILESYSTEM ACCESS: BLOCKED       HOST SECRET ACCESS: BLOCKED
UNAUTHORIZED NETWORK: BLOCKED         TIMEOUT: ENFORCED
UNAPPROVED EXECUTION DATA: DENIED     EXISTING HACP WORKFLOW: SETTLED
TAMPERED EXECUTION REQUEST: REJECTED
```

## 3. Tenki two-VM deployment

```sh
infra/tenki/demo-e2e.sh --dry-run && infra/tenki/demo-e2e.sh
```

Creates two billable VMs (Wasmer 7.4.1, pre-warmed `python/python@3.13.20`),
builds locked HACP Secure + bridge + patched skill; cleanup on any exit; on
interruption run `infra/tenki/destroy-peer.sh all` (operator state outside
the repo under `~/.local/state/hacp-tenki`).

Each VM: `hacp-agent` (no sudo) runs skill/client/service; `hacp-guard` runs
the guardian; `tenki` is the trusted operator. Binaries in `/usr/local/bin`,
policy root-owned at `/etc/hacp/exec-policy.json` (agent cannot sudo or
replace it). Guardian store 0700 outside the project; socket dir 0700 then
group search 0710 + socket 0660, UID check still admitting only `hacp-agent`.
The operator relays the sealed edge via SSH/sudo rsync (ownership preserved,
no keys copied); the `.hacp` snapshot has one writer per turn.

Asserts: secure question/answer, bilateral freeze, Wasmer execution and
secure return, filesystem/env/network denial with real canaries, timeout,
out-of-policy denial, submit/verify settlement, replay and tamper rejection.
Attack mutation is operator-only and never prints envelope internals.

## Limits (all demos)

- Local demos run **degraded (same-UID) mode**: they prove IPC restrictions
  and transport behavior, not OS isolation. Dedicated-UID isolation is an
  unexecuted deployment test.
- `.hacp` control state stays cooperative and plaintext (NG-4/5). Private
  receipts stop shared-file injection from counting as authenticated input;
  they cannot authenticate bilateral freezes.
- Guardian state is memory-only; restart needs fresh sessions. A crash after
  sealing but before recording a send receipt can reseal the same logical
  message under a new sequence (message IDs deduplicate delivery); no
  exactly-once crash-recovery claim.
- Wasmer: the service owns the session's inbound traffic while running
  (non-execution messages `ignored`, not re-delivered) — run execution while
  the skill is idle; concurrent demux is out of scope. The service runs as
  the agent UID: never holds keys, but a compromised agent could stop or
  replace it. Isolation strength is Wasmer/WASIX's for the pinned package on
  7.4.1; no runtime-escape claim. One contract per session.
- Tenki: trusted operator controls both VMs and the relay; snapshot needs
  serial writes; agent B shares a UID with its execution service; repos are
  not image-pinned; cold builds need network. Static acceptance alone does
  not establish cross-machine or Linux isolation — record live evidence.
