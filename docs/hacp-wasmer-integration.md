# HACP Secure × Wasmer Execution

Agent A asks Agent B's side to run code: the request travels over HACP Secure,
B's side authorizes it against operator policy, Wasmer runs it, and the result
returns over HACP Secure. Nothing in `src/`, `tests/`, `integrations/`,
`spec/`, or the secure demo changes — the bridge uses only existing guardian
socket verbs.

```sh
python3 scripts/demo-hacp-wasmer.py      # local end-to-end; non-zero on any failed assertion
cargo test --locked --manifest-path infra/wasmer/Cargo.toml
```

## Flow

```
Agent A ── hacp-exec ──seal(binding)──► Guardian A ──► encrypted edge
                                                            │ open
Guardian B: verify, decrypt, check session + binding ◄──────┘
   hacp-exec-guardian (B side, key-free): authorize against operator policy
   → ExecutionRequest (approved fields only)
   → WasmerCliExecutor: wasmer run (env cleared, /work only, no net unless granted)
   → ExecutionResult → seal(same binding) → Guardian A → hacp-exec → Agent A
```

Guardian B refuses delivery when the binding does not match the frozen
contract; Guardian A refuses to seal one; the bridge refuses an empty binding.
Refused requests never reach Wasmer — the requester gets a sealed
`{"status":"denied",...}` result.

## Wire bodies (unknown fields refused)

`sandbox.execution.request`:

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

Files travel by value and stage under `/work`; no field can name a host path.

`sandbox.execution.result`:

```json
{"status": "completed", "exit_code": 0, "stdout": "…", "stderr": "", "output_truncated": false, "duration_ms": 41, "failure": null}
{"status": "failed", "exit_code": null, "failure": {"kind": "TimedOut", "detail": "…"}}
{"status": "denied", "denial": {"code": "NetworkNotAllowed", "detail": "…"}}
```

These are application kinds, not HACP registry kinds; EXECUTE remains a
contract state, not a message.

## Security boundary

- **Keys stay in the guardian.** The bridge links `hacp` without the
  `guardian` feature; an acceptance check fails if `x25519-dalek`,
  `ed25519-dalek`, `chacha20poly1305`, `hkdf`, or `zeroize` appears in its
  dependency tree. The bridge sees only what `open` returns.
- **Authorization before construction.** `execution::authorize` requires a
  non-empty binding and an allowlisted requester, then checks package,
  timeout, output cap, argument/file counts and sizes, guest variables, and
  network rules against policy before any field is copied into an
  `ExecutionRequest`. The executor validates again.
- **Wasmer receives only the `ExecutionRequest`**: cleared environment (plus
  `WASMER_DIR`), stdin closed, fresh 0700 `/work` staging removed afterwards,
  no network without a policy-approved allow rule. `HACP_*` guest variables
  are refused at both layers even if the operator lists one.
- **Policy is operator-owned**, read from a local file at service start; no
  HACP message can change it. Host-side failures report fixed text only — no
  host path reaches the requester.

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
  [--env KEY=VALUE]... [--net RULE]... [--timeout-ms N] [--max-output-bytes N] \
  [--wait-secs N] [--no-wait]
```

The service prints (and optionally appends) one JSON outcome per guardian
report entry: `executed`, `failed`, `denied`, `rejected`, or `ignored` —
metadata only, never payloads or guest output. Runtime lookup: `HACP_WASMER_BIN`
(else `wasmer` on PATH) and `WASMER_DIR` (else `~/.wasmer`); neither reaches
the guest. `infra/wasmer/exec-policy.example.json` is the demo policy.

## Demo assertions (decided on the host, not from guest self-reports)

```text
EXECUTION CONTRACT: FROZEN                 real /hacp start, join, propose, accept
LEGITIMATE EXECUTION: PASS                 no plaintext request, code, or output on the edge or in .hacp
HOST FILESYSTEM ACCESS: BLOCKED            guest probes guardian store, socket dir, edge, $HOME, /etc, traversal, symlink, host write
HOST SECRET ACCESS: BLOCKED                fake HACP_*/WASMER_TOKEN env canaries absent in guest; the one approved variable present
UNAUTHORIZED NETWORK: BLOCKED              loopback listener counts 0 connections; out-of-policy allow rule denied
TIMEOUT: ENFORCED                          spin loop killed and reported TimedOut
UNAPPROVED EXECUTION DATA: DENIED          unlisted package, HACP_* variable, over-policy timeout never reach Wasmer
EXISTING HACP WORKFLOW: CONTRACT SETTLED   submit and counterparty verify settle afterwards
TAMPERED EXECUTION REQUEST: REJECTED       one flipped ciphertext byte; nothing executes
```

## Limits

- **Delivery ownership.** Guardian `open` consumes deliveries for a session:
  while `hacp-exec-guardian` runs, it owns B's inbound traffic (non-execution
  messages are `ignored`, not re-delivered); `hacp-exec` does the same on A
  while waiting. Run execution while the skill is idle; concurrent demux is
  out of scope.
- **UID placement.** The service runs as the agent UID (socket ACL) and never
  holds keys, but a compromised agent on B could stop or replace it. The local
  demo uses degraded mode; OS isolation is not proven locally.
- **Isolation strength** is Wasmer/WASIX's for `python/python@3.13.20` on
  7.4.1; no claim of runtime-escape resistance.
- **One contract per session** (guardian's single-contract observation rule);
  concurrent negotiations make bindings ambiguous and are refused.

Tenki deployment of these binaries: see `docs/hacp-secure-tenki-demo.md` and
`infra/tenki/README.md`.
