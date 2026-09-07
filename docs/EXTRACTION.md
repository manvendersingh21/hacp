# Standalone repository extraction — 2026-09-07

The protocol directory was extracted from HIVE commit
`87dd12251a6e2375d48d77f85b64aba58b4c3d19` using `git subtree split --prefix=hacp`.
The resulting protocol-history tip is
`a1bba96b6fd264411caafc1b9beabc50c7c4d756`. Original protocol commits and the
Apache-2.0 license are retained; HIVE runtime code is not part of this tree.

Repository paths and documentation links were updated, and the design decision,
historical adapter findings, and testing guide were copied with their context.
No protocol wire semantics or conformance assertions changed during extraction.
Cargo package version 1.1.0 and the separate HACP/2.0 draft namespace are retained.

Local verification on macOS:

```text
cargo build --locked --offline                  -> passed, no warnings
cargo test --locked --offline --no-run          -> passed, no warnings
cargo test --locked --offline                   -> 146 passed, 0 failed, 0 ignored
cargo run --locked --offline --example bilateral
  -> settled; content, size, digest verified; session closed
cargo doc --locked --offline --no-deps          -> passed, no warnings
cargo package --locked --offline --allow-dirty  -> isolated package build passed
relative Markdown file-link check              -> all targets resolve
git diff --check                               -> passed
```

`--allow-dirty` was used only to verify packaging before committing documentation.
The CI definition repeats build, tests, example, docs, and clean packaging on
Linux and macOS. CI configuration is not itself evidence those remote jobs passed.
No registry package or release tag was published by this extraction.
