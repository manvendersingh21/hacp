# Changelog

## 1.1.1

- Add regression coverage proving nested canonical contract content binds bilateral acceptance, frozen revision digests, and amendments; stale submissions are rejected after an amendment.
- Clarify that agreement fields hold pending votes, and that generic session closure does not certify successful completion.
- Document the boundary between runtime-neutral HACP and the coding workflow in hacp-skill.

Core runtime APIs, protocol schemas, HACP/2.0 lifecycle semantics, and the revision digest preimage `{contract_id, revision, content}` are unchanged.

Validation: 147 tests, the bilateral example, documentation build, and package verification passed. GitHub CI passed on Linux and macOS. Existing repository-wide formatting and strict Clippy issues are outside this documentation/test patch.

This is a GitHub source/package release; it does not indicate publication to crates.io.
