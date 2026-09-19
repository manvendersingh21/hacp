# HACP Secure + Wasmer on two Tenki VMs

Run from the HACP repository:

```sh
infra/tenki/demo-e2e.sh --dry-run
infra/tenki/demo-e2e.sh
```

The second command creates two billable Tenki VMs, provisions dependencies,
builds locked HACP Secure with the guardian feature, builds the existing Wasmer
adapter unchanged, and builds hacp-skill from `integrations/hacp-skill/source.json`
plus `secure.patch`. Wasmer is pinned to 7.4.1; Python is pinned to
`python/python@3.13.20` and pre-warmed before execution timeouts apply.

Each VM has a non-sudo `hacp-agent` user for the skill/client/execution service,
a separate `hacp-guard` Guardian user, and `tenki` as the trusted operator.
The operator installs runtime binaries in `/usr/local/bin` and policy in
`/etc/hacp/exec-policy.json`, with root-owned parents and files. The policy path
and agent UID differ from the original Tenki proposal to prevent the agent from
using sudo or replacing a policy in its own writable home. No real agent
credentials are installed or required: the demo drives the agent-facing `/hacp`
CLI deterministically.

The private Guardian store is outside the project, mode 0700. Guardian startup
uses explicit `--store`, `--project`, `--socket`, and `--agent-uid`; it starts with
a 0700 socket parent, then grants group search (0710) and socket connect (0660).
The existing UID check remains enabled. Only public identities are exchanged.

The trusted operator relays the sealed file edge via SSH/sudo rsync, preserving
Guardian ownership and private modes. No Guardian key or session store is copied.
The cooperative `.hacp` snapshot has one writer per turn, then syncs to the other
VM. During execution only sealed edge files sync, and the service owns inbound
delivery until it stops. The demo does not poll the skill concurrently with it.

The workflow asserts secure question/answer; bilateral contract freezing;
Wasmer hello execution and secure return; filesystem/environment/network denial
with fake environment canaries and a real host loopback listener; timeout;
out-of-policy denial; normal skill submission and counterparty verification;
replay rejection on the same running Guardian; and tamper rejection before
execution. Attack mutation is operator-only and never prints envelope internals.

Cleanup runs on success or failure. `destroy-peer.sh all` terminates only the
recorded VM IDs, then the demo checks `tenki sandbox list --json` for their absence.
Operator state (`resources.json`, `results.json`, execution audit and sync logs)
lives outside the repository under `~/.local/state/hacp-tenki`. On interrupted
operator processes, run `infra/tenki/destroy-peer.sh all` using the same state path.

Limitations: trusted operator controls both VMs and the relay; the cooperative
snapshot requires serial writes. Agent B and its execution service share a UID,
so the agent can stop or replace its own service. Guardian replay state is
process-local; the demo does not claim restart-persistent replay protection.
Rust and OS package repositories are not image-pinned, and cold builds require
network access. The demo uses fresh disposable VM collaboration state and leaves
the existing local HACP integration session untouched.

Live execution evidence is recorded after running the workflow; static acceptance
alone does not establish cross-machine or Linux Wasmer isolation.
