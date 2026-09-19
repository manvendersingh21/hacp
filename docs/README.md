# Documentation index

Three groups: protocol core, optional HACP Secure layer, and infrastructure
demonstrators. Start with the [README](../README.md), then follow the path
that matches what you are building.

## Protocol core

| Document | Purpose |
| --- | --- |
| [../spec/HACP.md](../spec/HACP.md) | Frozen HACP/1.1 specification |
| [../spec/HACP-2.0-draft.md](../spec/HACP-2.0-draft.md) | HACP/2.0 draft specification |
| [TESTING-YOUR-PROTOCOL.md](TESTING-YOUR-PROTOCOL.md) | Layered testing playbook (L0–L5) |
| [STANDALONE-VALIDATION.md](STANDALONE-VALIDATION.md) | Standalone extraction validation record |
| [EXTRACTION.md](EXTRACTION.md) | Extraction from HIVE with history preserved |
| [adr/](adr/), [findings/](findings/) | Decisions and recorded findings |
| [../CHANGELOG.md](../CHANGELOG.md), [../CONTRIBUTING.md](../CONTRIBUTING.md), [../SECURITY.md](../SECURITY.md) | Changes, workflow, reporting |

## HACP Secure layer (optional, feature-gated)

Reading order:

1. [hacp-secure-integration.md](hacp-secure-integration.md) — merge impact,
   required setup, verification, rollback. **Start here.**
2. [security-architecture.md](security-architecture.md) — normative design:
   adversary, trust boundaries, handshake, envelope, binding, replay,
   pipeline, errors, limits.
3. [hacp-secure-threat-model.md](hacp-secure-threat-model.md) — assets,
   adversaries, threats with test IDs, invariants, and non-goals.
4. [hacp-secure-modules.md](hacp-secure-modules.md) — module rules,
   inventory, CLI/socket interfaces, receive pipeline, error type.
5. [hacp-secure-test-matrix.md](hacp-secure-test-matrix.md) — test IDs mapped
   to guarantees; canary and `SKIP(degraded)` conventions.
6. Demos: [hacp-secure-local-demo.md](hacp-secure-local-demo.md) (local,
   degraded mode), [hacp-secure-tenki-demo.md](hacp-secure-tenki-demo.md)
   (two VMs).

## Infrastructure demonstrators (optional)

| Document | Purpose |
| --- | --- |
| [hacp-wasmer-integration.md](hacp-wasmer-integration.md) | Wasmer sandbox execution (`infra/wasmer/`) |
| [../infra/wasmer/README.md](../infra/wasmer/README.md), [../infra/tenki/README.md](../infra/tenki/README.md) | Quickstarts and policies |

## Conventions

- Documents are normative where they say so; everything else is explanatory.
- The frozen wire schema is
  [../spec/schemas/secure-envelope.json](../spec/schemas/secure-envelope.json);
  changes to it are protocol changes.
- Demo scripts live in `../scripts/` and exit non-zero on any failed assertion.
