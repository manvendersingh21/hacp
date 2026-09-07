# Contributing to HACP

HACP is a protocol and Rust library, not an agent host. Changes to scheduling,
process execution, model adapters, or deployment belong in a consuming runtime
such as [HIVE](https://github.com/manvendersingh21/HIVE).

## Development

Install stable Rust with Cargo and Python 3 (the interoperability peer uses only
the standard library). Clone this repository and run:

```sh
cargo build --locked
cargo test --locked --no-run
cargo test --locked
cargo run --locked --example bilateral
cargo doc --locked --no-deps
```

These checks need no model accounts, API keys, running services, or HIVE checkout.
The initial build downloads Rust dependencies. CI repeats the checks on Linux
and macOS. Build and test output should contain no warnings.

## Changes and compatibility

- Open an issue for substantial design changes before implementing them.
- Include a minimal reproduction and a regression test with a bug fix.
- Root modules implement frozen HACP/1.1; `hacp::v2` implements the separate
  HACP/2.0 draft. Cargo package versions and wire versions are different concepts.
- Do not introduce dependencies on a vendor, CLI, async runtime, database,
  transport client, or HIVE crate.
- Update the normative specification when changing wire semantics. Describe
  compatibility and migration consequences, including rejected old messages.
- Regenerate schemas with `cargo run --bin emit-schemas`, then run the tests.
  Do not hand-edit generated schemas to hide a failing drift check.
- Preserve the independent Python peer's information barrier: implement its
  behavior from specifications, schemas, and fixtures, not the Rust internals.
- Review golden transcript changes as protocol changes, not snapshot cleanup.
  Never claim a test passed if it was skipped or not executed.

Keep credentials, personal home paths, machine inventories, and live private
transcripts out of commits. Use neutral participant identities in examples.

## Pull requests and releases

Explain the problem, solution, compatibility impact, and exact checks performed.
Small, focused pull requests are easier to review. Include documentation when a
public API or behavior changes. Contributions are provided under the repository's
[Apache-2.0 license](LICENSE).

Maintainers can verify distributability using `cargo package --locked`; this
builds an isolated package but does not publish it. Registry publication and
release tags require an explicit maintainer decision.
