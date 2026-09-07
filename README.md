# HACP

HACP lets independent agents negotiate tasks, agree on contracts, exchange
artifacts and evidence, verify results, and escalate disputes. It is model-,
CLI-, language-, and runtime-neutral. **HIVE uses HACP; HACP does not require HIVE.**

This repository contains a standalone Rust library plus specifications, JSON schemas,
conformance vectors, golden transcripts, and an independent Python test peer.
It does not launch agents or provide a hosted endpoint. There is no HACP account
or protocol API key; the model or CLI you choose may require its own account.

## Use HACP without HIVE

You do **not** need to install, clone, or run HIVE. You can run the protocol's
example directly, import the Rust library into your own application, or implement
the wire protocol in another language. There is no HACP server to log into and
no HACP API key to obtain.

The repository is named `hcap`; the protocol acronym and Rust crate are **HACP**
and **`hacp`**. Use the repository spelling in Git URLs and the crate spelling in
Rust imports.

### 1. Try the standalone example

Requirements: stable Rust/Cargo. Install Python 3 as well to run the independent
interoperability test included in the full test suite. Neither tmux nor SSH,
Ollama, a database, an agent CLI, or a model account is required for this example.

```sh
git clone https://github.com/manvendersingh21/hcap.git
cd hcap
cargo run --locked --example bilateral
cargo test --locked
```

The example runs two deterministic in-process peers through agreement, freeze,
artifact submission, measured verification, settlement, and session closure.
It prints an opening JSON envelope followed by:

```text
Settled: exact content, size and digest verified; session closed.
```

The initial clone/build needs network access to download source and dependencies.
The example itself uses no network, HIVE services, or model credits. After Cargo
has cached the dependencies, add `--offline` to run it without network access.
This demonstrates the library lifecycle, not two live AI agents.

### 2. Use the library in your own Rust application

You do not need a checkout of either HACP or HIVE for this option:

```sh
cargo new --bin hacp-demo
cd hacp-demo
```

Replace the generated `[dependencies]` section in `Cargo.toml` with:

```toml
[dependencies]
hacp = { git = "https://github.com/manvendersingh21/hcap.git", rev = "697eae62e950e862b64984ef8f0b2ee86f2aeb34" }
serde_json = "1"
```

Replace `src/main.rs` with this complete program:

```rust
use hacp::v2::{Contract, ContractLimits, Relationship, Session, Task};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let requester = "urn:hacp:agent:requester";
    let worker = "urn:hacp:agent:worker";
    let mut session = Session::open("s-demo", requester, worker)?;
    session.accept(worker)?;

    let mut contract = Contract::propose(
        &session,
        "c-demo",
        Task {
            task_id: "t-demo".into(),
            summary: "Produce a greeting file".into(),
            owner: worker.into(),
        },
        Relationship::Collaboration,
        vec![],
        ContractLimits { max_rounds: 3, max_amendments: 2 },
    )?;
    let terms = json!({
        "outputs": ["greeting.txt"],
        "acceptance": ["The file contains exactly hello followed by a newline"]
    });
    contract.agree(requester, &terms)?;
    contract.agree(worker, &terms)?;
    let revision = contract.freeze(terms)?;
    println!("Frozen revision: {revision}");
    Ok(())
}
```

Run it:

```sh
cargo run
```

Expected output: `Frozen revision:` followed by a deterministic SHA-256 revision
digest. This program records an agreement; it does **not** create `greeting.txt`
or call a model. Your application supplies the worker and artifact storage, then
uses `Contract::submit` and `Contract::apply_verification` to record measured
results. See [the complete bilateral example](examples/bilateral.rs) for artifact
creation, digest/size/content checks, settlement, and session closure.

The dependency above pins the independently tested extraction commit. Update
`rev` deliberately when adopting a newer protocol revision and commit your
application's `Cargo.lock`. Cargo downloads only HACP and its dependencies, not
HIVE. For a sibling local checkout instead, use `hacp = { path = "../hcap" }`.

### 3. Use another language or your own agent runtime

Rust is one implementation, not a protocol requirement. Use the
[HACP/2.0 specification](spec/HACP-2.0-draft.md), [JSON schemas](spec/schemas), and
[golden transcripts](tests/golden) to implement your own peer in Python,
JavaScript, Go, or another language. The [independent Python peer](tests/interop/peer.py)
uses only Python's standard library; it is a narrow test implementation, not a
complete Python SDK or ready-made agent host.

To exercise the reference Rust library against that separate Python process:

```sh
# From the HACP repository, with Rust and python3 installed:
cargo test --locked --test v2_interop -- --nocapture
```

The test creates temporary file-edge directories, launches the Python peer,
exchanges envelopes, checks the artifact, and compares both transcripts. It
does not call HIVE or a model provider. To connect actual agents, write the thin
adapter described below; there is no automatic connection between existing CLI
sessions just because the library is installed.

## Package and protocol versions

The Cargo package version remains **1.1.0**: root modules implement frozen
[HACP/1.1](spec/HACP.md), while `hacp::v2` implements the separate
[HACP/2.0 draft](spec/HACP-2.0-draft.md). These wire versions are not compatible.
Use `hacp::v2` for the bilateral API shown in [the example](examples/bilateral.rs).
This guide does not assume that a crates.io release has been published.

## Connect your own agents

An adapter bridges each CLI or agent runtime to HACP:

1. Assign neutral identities such as `urn:hacp:agent:requester` and
   `urn:hacp:agent:worker`; keep vendor/model names behind the adapter.
2. Choose a transport: the [file-edge binding](spec/HACP-2.0-draft.md#12-transport-and-workspace-bindings-normative)
   supports stock CLIs; other transports can carry the same JSON envelopes.
3. Open a bilateral session and declare features. Have each side review the same
   terms; record both acceptances before freezing the revision.
4. Launch or prompt your chosen CLI using its supported interface. Translate
   its structured outputs into submissions with artifact manifests and evidence.
   A successful CLI exit or a narrated claim is not proof of completion.
5. Fetch artifact bytes, verify their digest and frozen acceptance criteria,
   then apply the verifier's record. Rework returns to execution; rejection and
   exhausted negotiations are valid terminal outcomes. Use the escalation
   objects when a dispute needs referral or resolution.

Codex, OpenCode, Claude, or another tool can participate if an adapter supplies
that bridge. Installing this library alone does not connect their sessions.
Supervision, grants, cross-branch permits, and the recursive pairwise profile
are available separately; the profile is optional, not a Core prerequisite.

## Integration trust boundaries

- Authenticate peers at the transport boundary. A URN is a name, not a signature.
  Validate envelopes and typed bodies, bind `session_id`, `from`, and `to` to the
  local session and authenticated connection, and reject observer-authored state
  changes. JSON deserialization alone does not call `validate()`.
- Edges are at-least-once: deduplicate by session and message identity before
  state transitions, rejecting the same identity with different content. Persist
  deduplication and state atomically if processing must survive restarts. The
  low-level state machines do not themselves provide a persistent receive loop.
- `Session`, `Contract`, org charts, grants and permits are host-managed state.
  Do not replace them with arbitrary remote snapshots. Only trusted deployment
  code may charter root grants or accept organizational declarations; grant IDs
  and content digests do not authenticate their issuers.
- Prefer `Contract::apply_verification` over `Contract::decide` for verdict records:
  it checks the verifier against the pending submitter and binds the record to
  the contract, revision, and artifact set. `decide` is a low-level transition
  for outcomes the host has already validated. Neither method executes checks:
  the verifier must measure every required criterion itself. Advisory checks
  that are not acceptance gates should be recorded as evidence, not as failed
  checks accompanying an accept.
- Use `CollaborationPermit::authorize_session` with the requested task class and
  current ledger/org chart at admission. `authorizes` checks only pair and expiry.
  Scope names match exactly: `work/all` is not a wildcard for cross-branch powers.
- Enforce transport size/rate limits, artifact visibility, safe artifact locations,
  process isolation, deadlines and heartbeat handling in your adapter. The core
  library does not download artifacts, execute commands, or sandbox models.

Changes in this draft bind agreement snapshots to a terms digest and permits
to a task class. Old partial agreements must collect both acceptances again;
old permits without a task class must be reissued. Old pending submissions
without an authenticated submitter need trusted migration before applying a
verification record. Never fill these fields from untrusted claims.

## Validate and package independently

From the repository root:

```sh
cargo build --locked
cargo test --locked
cargo run --example bilateral
cargo doc --no-deps --locked
cargo package --locked
```

The package includes its Python peer, schemas, and test fixtures. After changing
v2 types, regenerate schemas with `cargo run --bin emit-schemas`; schema drift
is a test failure. The frozen 1.1 implementation and its vectors remain separate.
Packaging is local; this is a Git-distributed library, not a claim of publication
on crates.io. Publishing a registry release is a separate maintainer action.

Standalone validation on 2026-09-07: a fresh public clone passed **146 tests,
zero failures, zero skips**. The isolated Cargo package passed the same suite.
The exact Rust example in this README also compiled and ran in a separate
application with **zero HIVE packages** in its resolved dependency graph.
See the [validation record](docs/STANDALONE-VALIDATION.md) for commands and scope.

## Contributing and support

Read [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, compatibility
rules, and test requirements. The [testing guide](docs/TESTING-YOUR-PROTOCOL.md)
explains the evidence behind the protocol. Report reproducible bugs and propose
changes through [GitHub issues](https://github.com/manvendersingh21/hcap/issues).
See [SECURITY.md](SECURITY.md) for vulnerability reporting and integration boundaries.

## License and origin

Licensed under [Apache License 2.0](LICENSE).

HACP was extracted from [HIVE](https://github.com/manvendersingh21/HIVE) on
2026-09-07, preserving the protocol directory's Git history. HIVE is a consumer,
not a dependency. The specifications, schemas, library, and conformance tests
are maintained here; runtime-specific deployment and live-agent reports remain
in HIVE.
