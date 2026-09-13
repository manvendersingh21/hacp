# HACP Secure × Wasmer execution integration

Agent A asks Agent B's side to run code. The request travels over HACP Secure,
Agent B's guardian side decides whether it may run, Wasmer runs it, and the
result comes back over HACP Secure.

```sh
python3 scripts/demo-hacp-wasmer.py      # local end-to-end demo; exits non-zero on any failed assertion
cargo test --locked --manifest-path infra/wasmer/Cargo.toml
```

Nothing in `src/`, `tests/`, `integrations/`, `spec/` or the HACP Secure demo
changed. The bridge uses only the guardian socket verbs that already exist.

## Flow

```
Agent A ── hacp-exec ──seal(binding)──► Guardian A ──► encrypted .hacp-secure edge
                                                              │
                                                              ▼
                                        Guardian B: verify signature, decrypt,
                                        check session, check binding == frozen contract
                                                              │ open
                                                              ▼
                                        hacp-exec-guardian (Agent B guardian side, key-free)
                                          authorize: binding present, requester allowlisted,
                                          request within operator policy
                                          build ExecutionRequest from approved fields only
                                                              │
                                                              ▼
                                        WasmerCliExecutor ── wasmer run (env cleared, /work only,
                                                              │           no network unless granted)
                                                              ▼
                                        ExecutionResult → sandbox.execution.result
                                                              │ seal(same binding)
Agent A ◄── hacp-exec ◄──open── Guardian A ◄── encrypted edge ◄── Guardian B
```

## Mapping

| Step | Where | What |
|---|---|---|
| authorized HACP execution payload | Guardian B → `ExecutionService::step` | Guardian `open` delivers only authenticated messages whose sealed `contract` binding matches the frozen HACP contract it observes for the session. The service re-checks sender, recipient and session on the inner HACP envelope. |
| → `ExecutionRequest` | `execution::authorize` | Requires a non-empty binding and a requester in `allowed_peers`; parses the closed `sandbox.execution.request` body; checks package, timeout, output cap, argument count, file count and total size, guest variables and network rules against the policy. Only then are the fields copied into an `ExecutionRequest`. |
| → `SandboxExecutor` | `WasmerCliExecutor::execute` | Unchanged PoC executor. It validates the request again (package allowlist, confined paths, no `HACP_*` variables, allow-only network rules). |
| → `ExecutionResult` | `execution::result_body` | Exit code, stdout, stderr, truncation flag, duration and failure kind. Host-side failures (`Io`, `RuntimeUnavailable`) are reported with fixed text so no host path reaches the requester. |
| → encrypted HACP response | `ExecutionService::handle` | A `sandbox.execution.result` envelope with `in_reply_to` set to the request, sealed by Guardian B under the request's binding. `hacp-exec` accepts it only if it answers its request and carries the same binding. |

Refused requests never reach Wasmer. The requester gets a sealed
`{"status":"denied","denial":{"code":…}}` result.

## Wire bodies

`sandbox.execution.request` (unknown fields are refused):

```json
{
  "package": "python/python@3.13.20",
  "args": ["/work/main.py"],
  "files": [{"path": "main.py", "content_b64": "cHJpbnQoMSk="}],
  "env": {"SANDBOX_GREETING": "hi"},
  "network": [],
  "timeout_ms": 5000,
  "max_output_bytes": 65536
}
```

Files are carried by value and staged under `/work`. There is no field that
can name a host path.

`sandbox.execution.result`:

```json
{"status": "completed", "exit_code": 0, "stdout": "…", "stderr": "", "output_truncated": false, "duration_ms": 41, "failure": null}
{"status": "failed", "exit_code": null, "failure": {"kind": "TimedOut", "detail": "execution timed out after 2s"}, …}
{"status": "denied", "denial": {"code": "NetworkNotAllowed", "detail": "…"}}
```

These are application kinds, not HACP registry kinds. HACP delivers
unregistered kinds, and EXECUTE remains a contract state, not a message.

## Security boundary

The guardian stays the security boundary.

- **Keys, sessions and envelopes stay in `hacp-secure-guardian`.** The bridge
  links `hacp` without the `guardian` feature, so crypto, key files and
  session state are not compiled in. An acceptance check fails if
  `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `hkdf` or `zeroize`
  appear in its dependency tree. The bridge sees only what `open` returns:
  sender, binding and the decrypted HACP message.
- **Execution requires contract authorization.** Guardian B refuses delivery
  when the binding does not match the frozen contract. Guardian A refuses to
  seal one. The bridge also refuses an empty binding.
- **Wasmer receives only the `ExecutionRequest`.** The Wasmer process is
  spawned with a cleared environment (plus `WASMER_DIR`), stdin closed, a
  fresh 0700 staging directory mounted at `/work` and removed afterwards, and
  no network unless a policy-approved allow rule is present. `HACP_*` guest
  variables are refused at both the policy and the executor layer, even if the
  operator lists one.
- **Policy is operator-owned.** `ExecutionPolicy` is read from a local file at
  service start. No HACP message can change it.

## Entry points

```sh
cargo build --locked --release --manifest-path infra/wasmer/Cargo.toml --bins

# executing peer (B), key-free, beside its guardian
hacp-exec-guardian --socket <guardian-B.sock> --agent urn:hacp:agent:b \
  --context <HACP session id> --policy <policy.json> \
  [--audit <audit.jsonl>] [--staging-root <dir>] [--poll-ms N] [--once]

# requesting peer (A), key-free
hacp-exec --socket <guardian-A.sock> --agent urn:hacp:agent:a --peer urn:hacp:agent:b \
  --context <HACP session id> --contract sha256:<frozen revision digest> \
  --package python/python@3.13.20 --file main.py=./main.py --arg /work/main.py \
  [--env KEY=VALUE]... [--net RULE]... [--timeout-ms N] [--max-output-bytes N] [--wait-secs N] [--no-wait]
```

The service prints and optionally appends one JSON outcome per guardian report
entry: `executed`, `failed`, `denied`, `rejected` or `ignored`. Guardian `open`
rescans the edge, so every earlier inbound frame comes back as `ReplayRejected`
on each poll. Each distinct rejection (frame file or session, plus error) is
therefore reported once per service lifetime. A newly replayed or tampered frame
is still reported. Outcomes carry metadata only, never payloads or guest output. Runtime lookup uses
`HACP_WASMER_BIN` (else `wasmer` on `PATH`) and `WASMER_DIR` (else
`~/.wasmer`). None of these reach the guest.

`infra/wasmer/exec-policy.example.json` is the demo policy: requester
`urn:hacp:agent:a`, `python/python@3.13.20`, a 10 s timeout cap, 64 KiB output
cap, one approved guest variable, and no network rules.

## Tenki deployment (agreed with the Tenki owner)

Tenki automation lives in `infra/tenki/`. It calls these binaries and never
modifies them.

| Setting | Value on each VM |
|---|---|
| Accounts | `hacp-guard` runs the guardian. `hacp-agent`, a dedicated account without sudo, runs the skill, `hacp-exec` and `hacp-exec-guardian`. `tenki` is the operator (relay, sudo) only. |
| Project | `/srv/hacp/project` (root-owned 0755 parent). Owned by `hacp-agent` with group `hacp`, 2770. The guardian can read `.hacp`. `.hacp-secure` is pre-created, owned by `hacp-guard`, 0700. |
| Wasmer | CLI 7.4.1 from `get.wasmer.io`, installed root-owned at `/usr/local/bin/wasmer`. `WASMER_DIR=/home/hacp-agent/.wasmer-exec` (0700, never logged in). `python/python@3.13.20` is pre-warmed as `hacp-agent`. |
| Guardian | `hacp-secure-guardian serve --agent-uid $(id -u hacp-agent)` as `hacp-guard`; socket `/home/hacp-guard/runtime/<a\|b>/guardian.sock`. The socket directory is 0700 when `serve` starts (its `private_dir` check), then gets group `hacp` and 0710, and the socket 0660. `getpeereid` still admits only `hacp-agent`. The key store is never opened up. |
| Execution service | `hacp-exec-guardian` on the executing peer as `hacp-agent`, with the same guardian socket, started detached (`setsid`) with an explicit runtime environment (`WASMER_DIR`, `HACP_WASMER_BIN=/usr/local/bin/wasmer`). |
| Client | `hacp-exec` on the requesting peer as `hacp-agent` |
| Policy | `/etc/hacp/exec-policy.json` (root:root 0644 under a root-owned directory), generated from `exec-policy.example.json` with `allowed_peers` set to the requesting URN |
| Staging / audit | `/home/hacp-agent/exec-staging` (0700) / `/home/hacp-agent/exec-audit.jsonl` |
| Transport | Unchanged HACP Secure file edge relayed by `infra/tenki/sync-edge.sh`. Requests and results are ordinary sealed envelopes. No ports are opened. |

Sequence on the VMs: negotiate and freeze with `/hacp`, drain both inboxes →
start the service on B → execution scenarios (run `sync-edge.sh --once` between
seal and open) → stop the service → `/hacp` submit, verify, complete → destroy
both peers.

## Demo assertions

`scripts/demo-hacp-wasmer.py` builds the guardian, the pinned patched
`hacp-skill` (and runs its test suite), and the bridge. It then runs two
degraded-mode guardians on a temporary project:

```text
EXECUTION CONTRACT: FROZEN                 real /hacp start, join, propose, accept
LEGITIMATE EXECUTION: PASS                 hello.py via A → B → Wasmer → A; no plaintext request, code or output on the edge or in .hacp
HOST FILESYSTEM ACCESS: BLOCKED            guest probes Guardian B's store and identity.key path, its socket dir, the edge, the project, $HOME, /etc/passwd, traversal, a symlink, and a host write
HOST SECRET ACCESS: BLOCKED                fake HACP_GUARDIAN_PRIVATE_KEY, HACP_SESSION_KEY, WASMER_TOKEN and FORWARD_HOST_ENV=true in the service's environment are absent in the guest; the one approved variable is present
UNAUTHORIZED NETWORK: BLOCKED              host loopback listener counts 0 connections; a request adding an allow rule outside policy is denied
TIMEOUT: ENFORCED                          `while True: pass` with timeout_ms=2000 is killed and reported TimedOut
UNAPPROVED EXECUTION DATA: DENIED          unlisted package, HACP_* variable and over-policy timeout never reach Wasmer
EXISTING HACP WORKFLOW: CONTRACT SETTLED   /hacp submit and counterparty verify settle the execution contract afterwards
TAMPERED EXECUTION REQUEST: REJECTED       one flipped ciphertext byte: Guardian B rejects it and nothing executes
```

Verdicts are decided on the host (canaries, a write probe, a connection
counter, the service audit log), not from the guest's own report. The demo
never reads guardian private files; it only passes their paths to the guest as
probe targets.

## Limits and residual risks

- **Delivery ownership.** Guardian `open` consumes deliveries for a HACP
  session. While `hacp-exec-guardian` runs for a session, it owns B's inbound
  traffic for that session: non-execution messages are reported `ignored` and
  are not re-delivered to the skill. `hacp-exec` does the same on A while it
  waits. The demo runs execution while the skill is idle, then stops the
  service before the ordinary `submit`/`verify`. Running both concurrently on
  one session would need guardian-side demultiplexing, which is outside this
  integration.
- **UID placement.** In standard mode the guardian accepts socket connections
  only from the configured agent UID, so the execution service runs as the
  agent UID. It never holds keys, but a compromised agent on B could stop or
  replace it. The local demo uses degraded (same-UID) mode, as the HACP Secure
  demo does. OS isolation is not proven locally.
- **Isolation strength** is Wasmer/WASIX's. The demo shows the isolation
  properties above for `python/python@3.13.20` on Wasmer 7.4.1. It does not
  claim resistance to runtime escapes.
- **One contract per session.** The binding check follows the guardian's
  existing single-contract observation rule. Extra concurrent negotiations in
  the same session make bindings ambiguous and are refused, as before.
