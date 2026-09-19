# Documentation index

HACP documentation is split into three groups: the protocol core, the
optional HACP Secure layer, and infrastructure demonstrators. Start with the
[README](../README.md) for orientation, then follow the path that matches
what you are building.

## Protocol core

| Document | Purpose |
| --- | --- |
| [../README](../README.md) | Orientation, standalone usage, library consumption, integration trust boundaries |
| [../spec/HACP.md](../spec/HACP.md) | Frozen HACP/1.1 specification |
| [../spec/HACP-2.0-draft.md](../spec/HACP-2.0-draft.md) | HACP/2.0 draft specification |
| [TESTING-YOUR-PROTOCOL.md](TESTING-YOUR-PROTOCOL.md) | The layered testing playbook (L0–L5) used to build HACP/2.0 |
| [STANDALONE-VALIDATION.md](STANDALONE-VALIDATION.md) | Validation record for the standalone extraction |
| [EXTRACTION.md](EXTRACTION.md) | How HACP was extracted from HIVE with history preserved |
| [adr/](adr/) | Architecture decisions (bilateral core scope) |
| [findings/](findings/) | Recorded adapter and edge findings |
| [../CHANGELOG.md](../CHANGELOG.md) | Released and unreleased changes |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | Development workflow, compatibility rules, test requirements |
| [../SECURITY.md](../SECURITY.md) | Vulnerability reporting and integration boundaries |

## HACP Secure layer (optional, feature-gated)

Recommended reading order:

1. [hacp-secure-integration.md](hacp-secure-integration.md) — what merging the
   layer changes, required operator setup, verification commands, rollback.
   **Start here if you are reviewing or consuming the PR.**
2. [security-architecture.md](security-architecture.md) — the normative
   architecture: guardians, key schedule, pipeline stages, degraded mode.
3. [trust-boundary.md](trust-boundary.md) and
   [hacp-secure-threat-model.md](hacp-secure-threat-model.md) — what the layer
   does and does not defend against.
4. [hacp-secure-modules.md](hacp-secure-modules.md) — module map, crate
   layout, and the agent/operator CLI surfaces.
5. [hacp-secure-test-matrix.md](hacp-secure-test-matrix.md) — test IDs mapped
   to guarantees, including canary and `SKIP(degraded)` conventions.
6. [hacp-secure-non-goals.md](hacp-secure-non-goals.md) — explicit non-goals;
   read before proposing scope extensions.
7. Demos: [hacp-secure-local-demo.md](hacp-secure-local-demo.md) (local,
   same-UID degraded mode) and [hacp-secure-tenki-demo.md](hacp-secure-tenki-demo.md)
   (multi-VM deployment).
8. [hacp-secure-integration-review.md](hacp-secure-integration-review.md) —
   the recorded bilateral review of the integration session.

## Infrastructure demonstrators (optional)

| Document | Purpose |
| --- | --- |
| [hacp-wasmer-integration.md](hacp-wasmer-integration.md) | Wasmer sandbox execution of verified work (`infra/wasmer/`) |
| [hacp-secure-tenki-demo.md](hacp-secure-tenki-demo.md) | Tenki multi-VM edge deployment (`infra/tenki/`) |
| [../infra/wasmer/README.md](../infra/wasmer/README.md) | Sandbox workspace quickstart and policy examples |
| [../infra/tenki/README.md](../infra/tenki/README.md) | Deployment scripts and peer provisioning |

## Conventions

- Documents are normative where they say so; everything else is explanatory.
- The frozen wire schema for the secure layer is
  [../spec/schemas/secure-envelope.json](../spec/schemas/secure-envelope.json);
  changes to it are protocol changes, not editorial ones.
- Demo scripts referenced by these documents live in `../scripts/` and exit
  non-zero on any failed assertion.
