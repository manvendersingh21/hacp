# Security

HACP provides protocol objects, validation, and state transitions. It does not
authenticate a network connection, run acceptance commands, or sandbox agents.
Read the [integration trust boundaries](README.md#integration-trust-boundaries)
before building an adapter. A valid message or passing finite test corpus is not
a security certification.

## HACP Secure layer

The optional HACP Secure layer (the `guardian` Cargo feature, the
`hacp-secure-guardian` daemon, and the `hacp-secure` agent CLI) moves key
custody out of agent processes, but it does not change the statements above:

- Agents never hold keys; all cryptography runs inside the guardian daemon,
  and its socket exposes only the frozen verbs `session`, `seal`, `open`,
  `status`, and `fingerprint`. There is no raw-sign or key-export operation.
- Running the guardian under the same UID as an agent is an explicitly
  **degraded mode**: same-UID filesystem access can read guardian state, so
  process isolation must not be claimed in that mode. The guardian says so
  loudly at startup. Dedicated-UID isolation has not been validated; see
  [docs/hacp-secure.md](docs/hacp-secure.md).
- Secure-session private state (receipts, send markers) belongs in an
  operator-configured `HACP_SECURE_STATE` directory **outside the shared
  project**, never under the agent-visible workspace.
- Shared `.hacp` contract state remains cooperative: revision binding proves
  digest consistency, not bilateral consent against a writer who forges all
  control state consistently. Plaintext endpoint histories and model contexts
  are outside edge confidentiality.

The full threat model and non-goals are in
[docs/hacp-secure.md](docs/hacp-secure.md) §12–13.

For a suspected vulnerability, use GitHub's private vulnerability reporting
option on this repository's **Security** tab if available. If it is unavailable,
open an issue requesting a private reporting channel without including exploit
details, credentials, private transcripts, or sensitive affected-system data.
No response-time guarantee or commercial support is offered.

Include the affected commit, a minimal synthetic reproduction, expected versus
actual behavior, and the relevant trust boundary in a private report. Reports
against the secure layer should additionally name the mode (degraded
same-UID versus dedicated-UID) and the guardian socket operation involved.
Do not test systems you do not own or have permission to assess. The current
development branch is the maintenance target; older snapshots have no
promised support window.
