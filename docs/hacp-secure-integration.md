# HACP Secure integration and upgrade guide

This document answers: **what does merging `feat/hacp-secure` into `main`
change in the existing project, and what must operators and integrators do?**
It is the ship checklist for the HACP Secure layer (guardian-held keys,
secure envelope transport, replay protection) plus the optional Wasmer
sandbox and Tenki deployment demonstrators.

## What ships in this branch

| Area | Path | Status |
| --- | --- | --- |
| Secure layer core | `src/secure/` (crypto, envelope, guardian, session, transport, client, workflow) | new, additive |
| Agent-facing CLI | `src/bin/hacp-secure.rs` | new; default features |
| Guardian daemon | `src/bin/hacp-secure-guardian.rs` | new; requires `--features guardian` |
| Wire schema | `spec/schemas/secure-envelope.json` | new, frozen, hand-authored |
| Tests | `tests/secure_envelope.rs`, `tests/secure_transport.rs`, `tests/secure_workflow.rs` | new |
| Skill integration | `integrations/hacp-skill/` (`secure.patch`, `source.json`) | new; applied to the external hacp-skill repo |
| Wasmer sandbox | `infra/wasmer/` | new, separate Cargo workspace, optional |
| Tenki deployment | `infra/tenki/` | new, shell-based, optional |
| Demos | `scripts/demo-hacp-secure.py`, `scripts/demo-hacp-wasmer.py` | new |
| Docs | `docs/hacp-secure-*.md`, `docs/security-architecture.md`, `docs/trust-boundary.md`, `docs/hacp-wasmer-integration.md` | new |

## Changes to files that already exist on `main`

Only three existing files are modified, all additively:

1. **`Cargo.toml`** — adds `base64 = "0.22"` as a regular dependency, all
   cryptography crates (`x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`,
   `hkdf`, `zeroize`, `rand_core`, `libc`) as **optional** dependencies behind
   the new `guardian` feature, a `[[bin]]` entry for `hacp-secure-guardian`
   gated on that feature, and `static_assertions` as a dev-dependency.
   `Cargo.lock` is regenerated accordingly.
2. **`src/lib.rs`** — adds `pub mod secure;` (two lines).
3. **`src/v2/schema.rs`** — a test filter excluding the hand-authored
   `spec/schemas/secure-envelope.json` from the schemars-generated registry
   conformance check. No production code path changes.

Additionally this PR removes runtime `.hacp/` state that had been committed on
the branch and adds `.hacp/` and `.hacp-history/` to `.gitignore` (see below).

## Compatibility assessment

- **Default builds are unchanged.** `default = []`; `cargo build --locked`,
  `cargo test --locked`, the bilateral example, `cargo doc`, and
  `cargo package --locked` all run without the new crypto stack. CI
  ("Protocol checks") is green on the branch head for exactly this matrix
  on Linux and macOS.
- **No wire protocol changes.** HACP/1.1 and the HACP/2.0 draft state
  machines, revision digest preimage `{contract_id, revision, content}`, and
  all existing schemas and conformance vectors are untouched. SecureEnvelope
  is a separate, frozen schema carried inside existing envelope payloads.
- **API surface is additive.** `hacp::secure` is new; no existing public item
  changed signature or semantics. The one new always-on dependency (`base64`)
  is small and has no feature implications.
- **Packaging.** `cargo package --locked` continues to work with default
  features. Downstream `hacp = { git = ... }` consumers are unaffected unless
  they opt into `features = ["guardian"]`.

Verdict: **merging causes no breaking integration with the existing project.**
The remaining items below are the actions needed to *use* the new layer.

## Required modifications in the existing project

### 1. Repository hygiene (included in this PR)

`.hacp/` (live session state: `session.json`, `log.md`, inboxes, artifacts,
verification stdout/stderr) and `.hacp-history/` (archived coordination
records) are runtime outputs, not sources. Earlier commits on this branch had
committed a live session; this PR removes those files from Git and ignores
both directories. **No action needed by reviewers** — listed here because it
is the only change to a pre-existing tracked file (`.gitignore`) beyond the
three code files above. After merging, any checkout with stale tracked
`.hacp/` files should run `git rm -r --cached .hacp` once.

### 2. hacp-skill patch (external repository, required for skill users)

The coding-workflow skill needs the secure adapter to run encrypted sessions.
From a checkout of [hacp-skill](https://github.com/manvendersingh21/hacp-skill)
at the commit recorded in `integrations/hacp-skill/source.json`:

```sh
git apply /path/to/hacp/integrations/hacp-skill/secure.patch
```

The patch wires the skill to the `hacp-secure` CLI, moves receipts and
send-markers out of the shared project into an operator-configured private
directory (see below), and stages locally generated messages before snapshot
publication. Agent-facing commands are unchanged. The skill depends on a
**local HACP checkout built with default features only**.

### 3. Guardian deployment (required for any secure session)

```sh
cargo build --locked --features guardian
```

Run one `hacp-secure-guardian` daemon per agent under a private socket
directory owned by that agent's UID. The agent-facing `hacp-secure` CLI talks
to it over a Unix stream socket; agents never see keys. Set on each agent's
environment:

```sh
export HACP_SECURE_STATE=/absolute/path/to/that-agents-private-state-directory
```

`HACP_SECURE_STATE` must live **outside the shared project** so receipts and
send-markers cannot be forged through the shared workspace. See
`docs/hacp-secure-local-demo.md` for a full worked walkthrough and
`docs/security-architecture.md` / `docs/trust-boundary.md` for the threat
model. The local demo runs the architecture's explicit **same-UID degraded
mode**; dedicated-UID process isolation must be validated separately before
claiming standard-mode isolation.

### 4. Optional demonstrators

- **Wasmer sandbox** (`infra/wasmer/`): separate Cargo workspace;
  `cargo test --locked` inside it. Does not affect the root crate.
- **Tenki deployment** (`infra/tenki/`): shell scripts provisioning VMs;
  start from `infra/tenki/README.md` and `docs/hacp-secure-tenki-demo.md`.

## Verification commands

```sh
# Existing project, unchanged surface
cargo build --locked
cargo test --locked
cargo run --locked --example bilateral

# Secure layer (key-free client/workflow surface)
cargo test --locked --test secure_workflow --test secure_envelope

# Full secure stack incl. guardian crypto/transport
cargo test --locked --all-features
```

Expected: the pre-existing suite (147 tests) passes on default features; the
new secure tests add coverage on top (`docs/hacp-secure-test-matrix.md` maps
test IDs to guarantees).

## Rollback

The layer is fully additive and feature-gated. Reverting the merge commit
restores `main` byte-for-byte except `.gitignore`; no persisted protocol
state, schema, or API depends on it. Secure sessions' private state lives in
`HACP_SECURE_STATE` directories and can be deleted independently.
