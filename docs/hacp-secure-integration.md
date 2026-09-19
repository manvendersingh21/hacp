# HACP Secure — Integration and Upgrade Guide

What merging `feat/hacp-secure` changes, and what operators must do.

## What ships

| Area | Path | Status |
| --- | --- | --- |
| Secure core | `src/secure/` (crypto, envelope, guardian, session, transport, client, workflow) | new, additive |
| CLIs | `src/bin/hacp-secure.rs` (agents), `src/bin/hacp-secure-guardian.rs` (operators) | new |
| Wire schema | `spec/schemas/secure-envelope.json` | new, frozen, hand-authored |
| Tests | `tests/secure_{envelope,transport,workflow}.rs` | new |
| Skill adapter | `integrations/hacp-skill/` (`secure.patch`, `source.json`) | applied to the external hacp-skill repo |
| Demonstrators | `infra/wasmer/`, `infra/tenki/`, `scripts/demo-*.py` | new, optional |
| Docs | `docs/hacp-secure.md` (spec), this guide, `docs/hacp-secure-demos.md` | new |

## Changes to files on `main` (all additive)

1. **`Cargo.toml`/`Cargo.lock`** — `base64` as a regular dep; all crypto
   crates optional behind the new `guardian` feature; a feature-gated `[[bin]]`;
   `static_assertions` dev-dep.
2. **`src/lib.rs`** — `pub mod secure;`.
3. **`src/v2/schema.rs`** — test-only: excludes the hand-authored
   `secure-envelope.json` from the schemars registry check.

Plus: `.hacp/` runtime state is untracked and `.hacp/`/`.hacp-history/` are
gitignored (this PR).

**Verdict: no breaking integration.** Default features, wire formats, schemas,
and public APIs are unchanged; `hacp = { git = ... }` consumers are unaffected
unless they opt into `features = ["guardian"]`.

## Required setup

**1. Guardian (required for any secure session)**

```sh
cargo build --locked --features guardian
hacp-secure-guardian init --store <dir> --agent <urn>          # per agent
hacp-secure-guardian pin --store <dir> --peer <urn> --pub <hex> --require-secure true
hacp-secure-guardian serve --store <dir> --project <dir> --socket <dir>/guardian.sock \
  --agent-uid <uid>            # or --degraded for same-uid, labeled mode
```

One daemon per agent, private socket dir owned by its UID, store outside the
project. Request budget defaults to 600/minute (`--rate-per-minute`, zero
refused). Agents need:

```sh
export HACP_SECURE_STATE=/absolute/path/to/private/state   # outside the shared project, 0700
```

**2. hacp-skill patch (skill users)**

```sh
git apply /path/to/hacp/integrations/hacp-skill/secure.patch   # at the commit in source.json
```

**3. Optional demonstrators** — `infra/wasmer/` (separate workspace) and
`infra/tenki/` (see their READMEs and demo docs).

## Verification

```sh
cargo test --locked                                        # existing suite, unchanged
cargo test --locked --test secure_workflow --test secure_envelope
cargo test --locked --all-features                         # full secure stack
```

## Rollback

Fully additive and feature-gated: revert the merge; only `.gitignore` differs
from pre-merge `main`. Secure sessions' private state lives in
`HACP_SECURE_STATE` dirs and can be deleted independently.
