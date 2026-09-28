# Changelog

## Unreleased

- Fix V5: accept the last allowed amendment; refuse further proposals while preserving execution and the frozen revision.
- Fix V6: specify arbitrary-precision canonical integers and normalize `-0` to `0`, matching the independent Python peer.
- Fix V8: accept deployment charterers and profile capability slashes, preserve explicit null replies, and align verdict prose with `accept`/`reject` wire values.
- Fix S3: enforce the documented rolling 60-second guardian budget with independently expiring admissions.
- Fix S4: emit at most one rate-limit audit record per 60 seconds, including across temporary admission recovery.
- Fix S5: require even-length ciphertext hex in the schema and reject space-separated secure timestamps.
- Fix S6: document the ack signature's HACP context binding and separate derived secure session ID check.

- Fix V1: constrain preauthorized collaboration peers to the grantor's authority at issuance and admission; recursive-pairwise preauthorization additionally binds and enforces one named sibling peer. This adds `CapabilityGrant::peer` and makes the public `CollaborationPermit::by_preauthorization` and `HiveProfile::authorize_siblings` signatures breaking API changes.
- Fix V2: reject consecutive counters by one participant and preserve the current executing revision when a unilateral amendment exhausts its rounds or deadline.
- Fix V3: define LCA as the lowest common supervisor (never a party); escalation `raise` accepts direct parent/child disputes mediated by the parent's supervisor and rejects `a == b`.
- Fix V4: delegation contracts carry `grant_id`; contract formation validates the referenced grant is open, matches the two participants, and that `escalation_path` matches the grantor's declared org chain.
- Fix V7: add `ContractLimits.max_rework`; once rework is exhausted, further `rework` verdicts transition the contract to `Rejected`.
- Test V1: add a regression test showing that an unrestricted (`peer: None`) preauthorization reaches only peers inside the grantor's org chain. Issuance refuses peers on another branch, the root, and unknown agents, and admission refuses a forged permit. Tests only; no behavior change.
- Fix HACP Secure S1 hello amplification/livelock by answering each
  `(context, hello signature)` once through a bounded replay history that
  survives session eviction, and by scanning message directories after the
  handshake phase. Fix S2 guardian hangs on a hostile `.hacp/session.json` by
  opening it nonblocking without following symlinks and rejecting non-regular
  files as `ContractMismatch`.
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
- Reduce documentation to what is needed: one canonical spec
  (`docs/hacp-secure.md`: architecture, trust boundaries, threat model,
  non-goals, module interfaces, test matrix), one integration guide
  (`docs/hacp-secure-integration.md`), and one demos doc
  (`docs/hacp-secure-demos.md`). Drops the separate architecture/threat/
  modules/matrix/demo files, the docs index, and the extraction/validation
  narratives. All normative content and test/threat IDs are retained.
- Add Mermaid architecture diagrams across the spec and demos docs:
  deployment with trust zones, handshake sequence, verification pipeline,
  TIER-2 binding and replay-window decision flows, feature-gated module
  graph, skill adapter flow, and the Wasmer execution sequence.

## 1.1.1

- Add regression coverage proving nested canonical contract content binds bilateral acceptance, frozen revision digests, and amendments; stale submissions are rejected after an amendment.
- Clarify that agreement fields hold pending votes, and that generic session closure does not certify successful completion.
- Document the boundary between runtime-neutral HACP and the coding workflow in hacp-skill.

Core runtime APIs, protocol schemas, HACP/2.0 lifecycle semantics, and the revision digest preimage `{contract_id, revision, content}` are unchanged.

Validation: 147 tests, the bilateral example, documentation build, and package verification passed. GitHub CI passed on Linux and macOS. Existing repository-wide formatting and strict Clippy issues are outside this documentation/test patch.

This is a GitHub source/package release; it does not indicate publication to crates.io.
