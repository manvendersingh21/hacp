# Standalone validation — 2026-09-07

## What was tested

HACP revision `697eae62e950e862b64984ef8f0b2ee86f2aeb34`, fetched from the public
GitHub repository into a fresh temporary checkout on macOS. The clone disabled
Git credential helpers, demonstrating anonymous source access. Tests ran from
that checkout, not the former HIVE workspace or the maintainer's HACP build tree.

A second, independent Cargo application used the Git-pinned dependency block
and Rust source extracted directly from the README. Its manifest did not use
a local path, a HIVE workspace, or a patch override. Cargo metadata confirmed
that HACP came from the published Git revision and that no package beginning
with `hive` was in the resolved dependency graph.

## Results

| Check | Result |
|---|---|
| Fresh standalone build | Passed, no warnings |
| Default test suite | 146 passed, 0 failed, 0 ignored |
| Rust reference ↔ separate Python peer | Passed, included in the 146 tests |
| Full bilateral example | Settled; content, size, digest checked; session closed |
| Test-profile compilation | Passed, no warnings |
| API documentation build | Passed, no warnings |
| Clean isolated Cargo package verification | Passed |
| Tests from the unpacked Cargo package | 146 passed, 0 failed, 0 ignored |
| README application as a separate Git-dependency consumer | Compiled and ran |
| Cached offline example and consumer runs | Passed |
| Consumer dependency graph | Published HACP; no HIVE packages |

The source and package test totals describe the same suite run in two locations,
not 292 distinct tests. Coverage includes canonicalization, refusal cases,
schemas, golden transcripts, contracts, grants, permits, verification, escalation,
and the optional profile. Passing this finite suite is not a claim that every
possible input or real agent deployment has been tested.

## Reproduce the source/package checks

From a new clone of the HACP repository at the revision above:

```sh
cargo build --locked
cargo test --locked --no-run
cargo test --locked
cargo run --locked --example bilateral
cargo doc --locked --no-deps
cargo package --locked
cargo test --manifest-path target/package/hacp-1.1.0/Cargo.toml --locked
cargo run --locked --offline --example bilateral
```

The initial clone/build needs network access and Rust dependencies; the Python
interop test needs `python3`. Package verification was run on the clean public
clone, without `--allow-dirty`. The README edits are documentation-only.

To reproduce the consumer check, follow
[the README application instructions](../README.md#2-use-the-library-in-your-own-rust-application),
then run `cargo tree --locked` and `cargo run --locked --offline` from the new
application. The tested program prints:

```text
Frozen revision: 53a07af2ce669a36c71fd4e26c8efdb66bd5e92d507f55fc9c11ba6f211b1300
```

That program freezes an agreed contract only. The separate `bilateral` example
exercises submission, measured verification, and settlement. Neither launches
live model agents. No HIVE executable, daemon, configuration, database, SSH
host, or provider account was used; existing services were left untouched.
