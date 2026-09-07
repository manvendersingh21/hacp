# Security

HACP provides protocol objects, validation, and state transitions. It does not
authenticate a network connection, run acceptance commands, or sandbox agents.
Read the [integration trust boundaries](README.md#integration-trust-boundaries)
before building an adapter. A valid message or passing finite test corpus is not
a security certification.

For a suspected vulnerability, use GitHub's private vulnerability reporting
option on this repository's **Security** tab if available. If it is unavailable,
open an issue requesting a private reporting channel without including exploit
details, credentials, private transcripts, or sensitive affected-system data.
No response-time guarantee or commercial support is offered.

Include the affected commit, a minimal synthetic reproduction, expected versus
actual behavior, and the relevant trust boundary in a private report. Do not
test systems you do not own or have permission to assess. The current development
branch is the maintenance target; older snapshots have no promised support window.
