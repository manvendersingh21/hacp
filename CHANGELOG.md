# Changelog

## Unreleased

- Add the optional HACP Secure layer: guardian-held key custody, secure
  envelope transport, signatures, and replay protection behind a `guardian`
  Cargo feature, plus the `hacp-secure` agent CLI and the frozen
  `spec/schemas/secure-envelope.json` schema. Default builds, wire formats,
  and existing APIs are unchanged.
- Enforce a rolling per-minute request budget in the guardian daemon
  (default 600 operations/minute, `--rate-per-minute` to override, zero
  refused). The budget spans all authorized connections, counts malformed
  and unknown-operation requests, and returns the fixed `RateLimited`
  error; transient socket accept failures no longer terminate the daemon.
- CI now builds the `guardian` feature and runs `cargo test --all-features`,
  covering the crypto, transport, and guardian suites on Linux and macOS.
- Add optional Wasmer sandbox execution and Tenki deployment demonstrators
  under `infra/`, and reproducible demo scripts under `scripts/`.
- Add the hacp-skill secure adapter patch under `integrations/hacp-skill/`.
- Stop tracking `.hacp/` runtime state; ignore `.hacp/` and `.hacp-history/`.
- Document integration, upgrade, and rollback in
  `docs/hacp-secure-integration.md`; add security architecture, trust
  boundary, threat model, module, test-matrix, and demo documentation.
- Add a documentation index (`docs/README.md`); document the secure layer's
  development workflow in `CONTRIBUTING.md` (guardian feature test matrix,
  frozen-schema and fixed-error rules, `SKIP(degraded)` convention), its
  boundaries and reporting scope in `SECURITY.md`, and its test entry points
  in `docs/TESTING-YOUR-PROTOCOL.md`.
- Consolidate and crisp the secure-layer documentation: the trust boundary and
  boundary rules move into `docs/security-architecture.md`; the non-goals move
  into `docs/hacp-secure-threat-model.md`; the hackathon scope and the
  bilateral integration-review narratives are dropped. All normative content
  (adversary model, handshake, key schedule, envelope, binding, replay,
  pipeline, error taxonomy, test matrix) is retained.

## 1.1.1

- Add regression coverage proving nested canonical contract content binds bilateral acceptance, frozen revision digests, and amendments; stale submissions are rejected after an amendment.
- Clarify that agreement fields hold pending votes, and that generic session closure does not certify successful completion.
- Document the boundary between runtime-neutral HACP and the coding workflow in hacp-skill.

Core runtime APIs, protocol schemas, HACP/2.0 lifecycle semantics, and the revision digest preimage `{contract_id, revision, content}` are unchanged.

Validation: 147 tests, the bilateral example, documentation build, and package verification passed. GitHub CI passed on Linux and macOS. Existing repository-wide formatting and strict Clippy issues are outside this documentation/test patch.

This is a GitHub source/package release; it does not indicate publication to crates.io.
