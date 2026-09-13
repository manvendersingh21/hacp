# Tenki deployment

Based on `feat/tenki-infra`, updated for the completed HACP Secure CLI and the
Wasmer execution adapter. See [the reproducible demo](../../docs/hacp-secure-tenki-demo.md).

Run `infra/tenki/demo-e2e.sh --dry-run` for local syntax checks, then
`infra/tenki/demo-e2e.sh` for two real VMs and unconditional cleanup. An authenticated
Tenki CLI, SSH/rsync, jq, Python 3 and Bash are required on the operator machine.
Configuration defaults are in `tenki.env.example`; credentials belong in the CLI's
own configuration, never in a project file.

`create-peer.sh`, `bootstrap-peer.sh`, `deploy-hacp.sh`, and `guardian.sh` accept
peer `a` or `b`. `guardian.sh pin` accepts the other peer URN and the **raw public
key** from `guardian.sh public`; a fingerprint is not a pin. The store and socket
paths are passed explicitly to the real Guardian CLI.

`sync-edge.sh --once --from a` copies A's cooperative `.hacp` snapshot to B and
exchanges sealed edge files both ways. Use `--from b` after B writes the snapshot.
`sync-edge.sh --edge-only` runs the sealed transport loop while the execution
service owns inbound delivery. This serial snapshot discipline is required;
concurrent modifications to `.hacp/session.json` are unsupported.

`destroy-peer.sh all` terminates only IDs in this workflow's operator state,
not every sandbox with a similar tag. State and transcripts default to
`~/.local/state/hacp-tenki`, outside the repository. Deploy uses a source allowlist
and excludes the active local integration session, private caches and local config.
