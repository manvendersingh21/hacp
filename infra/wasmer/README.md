# HACP Wasmer sandbox (proof of concept)

This is the sandbox half of the execution path. `src/execution.rs` wires it
into HACP Secure through the key-free guardian client; see
[docs/hacp-wasmer-integration.md](../../docs/hacp-wasmer-integration.md) and
`python3 scripts/demo-hacp-wasmer.py`.

```
Agent → hacp-skill → HACP Guardian → ExecutionRequest
                                         │
                            ┌────────────▼─────────────┐
                            │ SandboxExecutor (this)   │
                            │   WasmerCliExecutor      │
                            │     └─ wasmer run  ──► WASIX guest
                            └────────────┬─────────────┘
                                         │
Agent ← HACP Guardian ← ExecutionResult ◄┘
```

## Quick start

```sh
./infra/wasmer/demo.sh                                  # demo, exits non-zero on any failed check
cargo test --manifest-path infra/wasmer/Cargo.toml      # unit + end-to-end tests
```

Expected summary lines:

```
NORMAL EXECUTION: PASS
HOST FILESYSTEM ACCESS: BLOCKED
HOST SECRET ACCESS: BLOCKED
UNAUTHORIZED NETWORK: BLOCKED
WASMER TOKEN ACCESS: BLOCKED
RESULT: 5/5 checks as expected
```

Each check also prints what the guest tried (`guest>`) and what the host
verified independently (`host >`).

## Setup

| Dependency | Tested with | Install |
|---|---|---|
| Wasmer CLI | 7.4.1 (macOS arm64) | `brew install wasmer` or `curl https://get.wasmer.io -sSfL \| sh` |
| Rust toolchain | rustc/cargo 1.98.0 | https://rustup.rs |
| `python/python` Wasmer package | 3.13.20 (pinned) | downloaded automatically by Wasmer on first run |

There are no crate dependencies. If `wasmer` is not on `PATH`, set
`HACP_WASMER_BIN=/path/to/wasmer`. `WASMER_DIR` is respected, falling back
to `~/.wasmer`.

The first run is slower because Wasmer downloads and compiles the Python
package. Later runs take tens of milliseconds per execution.

## Why the CLI and not the embedded SDK

Wasmer offers two ways to run a WASIX package from Rust:

- **Embedded SDK:** the `wasmer` crate (7.4) plus `wasmer-wasix` (0.704).
  This gives in-process control, but pulls in a compiler backend, adds
  minutes to builds, and you have to wire up package resolution and runners
  yourself.
- **CLI:** `wasmer run <package>`. This is how Wasmer publishes and runs
  packages such as `python/python`, and it exposes exactly the switches this
  PoC needs:
  - `--volume` to mount one directory
  - `--env` for explicit variables
  - `--net=<allow rules>` for scoped networking
  - nothing forwarded unless asked

For a hackathon PoC the CLI wins. The crate stays dependency-free and builds
in about 2 s. The rest of HACP depends only on the `SandboxExecutor` trait,
so an SDK-backed executor can replace `WasmerCliExecutor` later without
changing callers.

## Layout

```
infra/wasmer/
  README.md
  demo.sh                      one-command demo
  Cargo.toml                   standalone crate (not a member of the hacp crate)
  src/lib.rs                   ExecutionRequest / ExecutionResult / SandboxExecutor / WasmerCliExecutor
  src/demo.rs                  the four checks, shared by the demo and the tests
  src/bin/hacp-wasmer-demo.rs  demo entry point
  src/execution.rs             HACP Secure bridge: policy, ExecutionService, ExecutionClient
  src/bin/hacp-exec-guardian.rs  execution service beside the executing peer's guardian
  src/bin/hacp-exec.rs         requesting peer's client
  exec-policy.example.json     operator policy used by the demo
  examples/                    guest programs (run *inside* the sandbox)
    hello.py
    filesystem-denied.py
    env-denied.py
    network-denied.py
    wasmer-token-denied.py
  tests/sandbox.rs             end-to-end tests against real Wasmer
  tests/execution.rs           bridge tests against a scripted guardian socket
```

## Adapter boundary

```rust
pub trait SandboxExecutor {
    fn execute(&self, request: &ExecutionRequest) -> ExecutionResult;
}

pub struct ExecutionRequest {
    pub package: String,               // "python/python@3.13.20"; must be on the executor allowlist
    pub args: Vec<String>,
    pub files: Vec<SandboxFile>,       // { path: relative to /work, contents: bytes }
    pub capabilities: Vec<Capability>, // Env { key, value } | Network { rules }
    pub limits: ResourceLimits,        // timeout (default 30 s), max_output_bytes per stream (default 1 MiB)
}

pub struct ExecutionResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub output_truncated: bool,
    pub duration: Duration,
    pub failure: Option<ExecutionFailure>, // InvalidRequest | RuntimeUnavailable | TimedOut | Io
}
```

`execute` never panics and never returns `Err`. Every problem ends up in
`ExecutionResult::failure`. A guest that exits non-zero is **not** a
failure: check `exit_code`, or use `succeeded()` for both at once.

Example:

```rust
let executor = WasmerCliExecutor::from_host(vec![DEFAULT_PYTHON_PACKAGE.into()])?;
let result = executor.execute(
    &ExecutionRequest::new(DEFAULT_PYTHON_PACKAGE)
        .file("main.py", "print('hi')")
        .arg("/work/main.py")
        .timeout(Duration::from_secs(5)),
);
```

## Capabilities

Everything is denied unless the request grants it.

| Capability | Default | How it is granted | Enforcement |
|---|---|---|---|
| Host filesystem | **denied** | never | Only a fresh per-run staging dir is mounted, at `/work`. The request carries file *bytes*, not host paths. |
| `/work` scratch dir | granted, read-write | always | Holds the files from the request. Deleted after every run, including anything the guest wrote. |
| Host environment | **denied** | never | `wasmer` is spawned with `env_clear()`. Only `WASMER_DIR` is set, for the runtime process; the guest doesn't see it. |
| Wasmer registry credentials | **denied** | never | `$WASMER_DIR/wasmer.toml` (login token) is read by the runtime process only; never mounted. `WASMER_TOKEN` is never inherited. |
| Guest env variables | none beyond the package defaults (`PYTHONEXECUTABLE`, `SSL_CERT_*`) | `Capability::Env { key, value }` | Keys starting with `HACP_` are refused, as are malformed keys. |
| Network | **denied** | `Capability::Network { rules }`, e.g. `ipv4:allow=127.0.0.1:8080` | Only `:allow=` rules, at least one. A blanket `--net` can't be requested. Rules become one `--net=r1,r2`. |
| Stdin | closed | never | `Stdio::null()`, which also auto-declines Wasmer's interactive network prompt. |
| Packages | only allowlisted | executor constructor | Exact string match, e.g. `python/python@3.13.20`. |
| Wall-clock time | 30 s | `limits.timeout` | The runtime process is killed at the deadline. |
| Output size | 1 MiB per stream | `limits.max_output_bytes` | Excess is drained and dropped; `output_truncated` is set. |

## How the checks are judged

Guest programs print `DENIED` or `EXPOSED` lines, but **verdicts are decided
on the host**. The guest's report alone is never trusted.

- **NORMAL EXECUTION**
  - The run exits 0.
  - stdout is exactly `HACP Wasmer sandbox works`.
- **HOST FILESYSTEM ACCESS**
  - Setup: the host plants a fake guardian key and fake HACP runtime state,
    each holding a random `FAKE-HACP-KEY-MATERIAL-<token>` value, in a temp
    dir next to the staging area.
  - The guest tries to reach, by absolute path:
    - those files and their directory
    - the repo root and its `.hacp/`
    - `$HOME`
    - `/etc/passwd`
    - the host cwd
  - It also tries:
    - `/work/../../…` traversal
    - a symlink planted inside `/work`
    - creating a new file next to the fake key
  - Result is BLOCKED only if:
    - the canary never appears in stdout or stderr
    - the probe file doesn't exist on the host
    - the key file is unchanged
    - no `EXPOSED` line was printed
- **HOST SECRET ACCESS**
  - Setup: the demo re-runs itself with fake `HACP_GUARDIAN_PRIVATE_KEY` and
    `HACP_SESSION_KEY` values, plus `FORWARD_HOST_ENV=true`, in its own
    environment. With `FORWARD_HOST_ENV=true`, a naive `wasmer run` forwards
    the whole host environment, which was verified while building this PoC.
  - Result is BLOCKED only if:
    - neither secret value appears in guest output
    - the guest can't read `/proc/self/environ`
    - the one explicitly granted variable (`SANDBOX_GREETING`) *is* visible,
      which proves grants work
- **UNAUTHORIZED NETWORK**
  - Setup: the host listens on a random loopback port.
  - The guest tries:
    - TCP to that port
    - TCP to `1.1.1.1:443`
    - a DNS lookup
  - Result is BLOCKED only if the host listener counted zero connections and
    no `EXPOSED` line was printed.
  - The test `network_grant_is_scoped_to_its_rule` shows the reverse: a
    granted port is reachable while a second, ungranted port stays blocked.

- **WASMER TOKEN ACCESS**
  - Why it matters: the `wasmer` process needs `WASMER_DIR`. On a logged-in
    host, `$WASMER_DIR/wasmer.toml` holds the registry API token.
  - The guest tries to read that file and directory by absolute path, and
    the `WASMER_TOKEN` variable. The demo also plants a fake `WASMER_TOKEN`
    in its own environment.
  - Result is BLOCKED only if no `EXPOSED` line was printed and none of the
    real token values from `wasmer.toml` appears in guest output.
  - Token values are read on the host only for that comparison. They are
    redacted from anything the demo prints.
  - When the host isn't logged in, the path and variable are still probed,
    and the demo says no token was present.

All attempts are reads, connection attempts, or creation of a new probe file
in a demo-owned temp dir. Nothing destructive runs, and every secret is a
random fake.

## HACP secret handling rule

HACP cryptographic material must never reach the sandbox: guardian keys,
session keys, SecureEnvelope state, transport state and HACP runtime state.
This PoC enforces that structurally, not by filtering:

1. The adapter has no HACP dependency and no knowledge of where keys live.
2. Host paths can't be named in a request. Only bytes staged into an empty
   directory are visible.
3. The host environment is never inherited, and `HACP_*` keys can't be
   granted explicitly.
4. Staging directories are created fresh with mode `0700` and removed after
   each run.

The Guardian is still responsible for what it puts into `files`, `args` and
`Env` values. The adapter can't tell whether a byte string is a secret.

## Security assumptions

- The Wasmer runtime (7.4.1) and its WASIX virtual filesystem and networking
  are in the trusted computing base. A Wasmer escape bug defeats this layer.
- The `wasmer` binary, `WASMER_DIR` and the registry package are trusted. The
  package is pinned by version, not by content hash.
- The host user running the executor is trusted. The `wasmer` process runs as
  that user with no additional OS sandbox.
- The checks demonstrate isolation for representative targets. They are
  evidence, not a proof.

## Limitations

- **No memory or CPU quota.** Only wall-clock timeout and output caps are
  enforced. The guest is bounded by wasm32's 4 GiB address space, and the
  CLI exposes no memory limit.
- **Ambiguous exit codes.** If `wasmer` itself fails (for example, unknown
  package), the result is a non-zero `exit_code` with `error: …` on stderr.
  That looks like a guest exit and is not classified as `failure`.
- **Host-side registry lookup.** `wasmer run` queries the registry on every
  run. The guest still has no network. `--offline` needs a local `.webc`
  passed via `--include-webc`, which isn't wired up.
- **Env values visible to local users.** Granted `Env` values are passed as
  `--env K=V`, so other local users can see them in the host process list.
- **Registry token file is world-readable.** `wasmer login` saved
  `~/.wasmer/wasmer.toml` with mode `644` on the test host. The sandbox can't
  read it, but other local users can; `chmod 600` it. The adapter doesn't
  change it.
- **Guest-visible prompt text.** Denied network access makes Wasmer print a
  notice (`The current package is requesting networking access…`) into the
  guest's stdout.
- **No output files.** `/work` is discarded, so result files are not returned
  in `ExecutionResult`.
- **No wire format yet.** The request and result types have no serde derives
  so the crate stays dependency-free.
- **Tested on macOS arm64 only.** This crate is not in the repo's CI.

## Future HACP integration point

When HACP Secure is ready, connect these, in order:

1. **Guardian → executor.** After the Guardian decrypts and authorizes an
   execution message, it builds an `ExecutionRequest` from the *policy-approved*
   fields and calls `SandboxExecutor::execute`. Keys and sessions stay on the
   Guardian side of that call.
2. **Wire mapping.** Define how an HACP execution payload maps to
   `ExecutionRequest`: package, args, files as bytes, capabilities, limits.
   Define how `ExecutionResult` maps back into the response the Guardian
   encrypts. Add `serde` derives, or mirror these types in the HACP crate.
3. **Policy.** The Guardian owns:
   - the package allowlist passed to `WasmerCliExecutor`
   - which `Env` and `Network` grants a peer may request
   - timeout and output ceilings
4. **Placement.** Decide whether the Guardian links this crate directly or
   uses it as a separate workspace member or process. Construct the executor
   once at Guardian startup with `from_host`, or explicitly with `new`.
