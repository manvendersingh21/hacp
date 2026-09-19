# HACP Secure + Wasmer on Two Tenki VMs

```sh
infra/tenki/demo-e2e.sh --dry-run
infra/tenki/demo-e2e.sh
```

The second command creates two billable Tenki VMs, provisions dependencies,
builds locked HACP Secure (guardian feature), the Wasmer bridge, and the
patched hacp-skill. Wasmer is pinned to 7.4.1; Python to `python/python@3.13.20`
(pre-warmed). Cleanup runs on success or failure; on interruption run
`infra/tenki/destroy-peer.sh all` (operator state lives outside the repo under
`~/.local/state/hacp-tenki`).

## Layout

Each VM: `hacp-agent` (no sudo) runs the skill, `hacp-exec`, and the execution
service; `hacp-guard` runs the guardian; `tenki` is the trusted operator.
Binaries install to `/usr/local/bin`, policy to `/etc/hacp/exec-policy.json`
(root-owned) — paths chosen so the agent cannot sudo or replace policy. The
guardian store is 0700 outside the project; the socket dir starts 0700, then
gets group search (0710) and socket connect (0660) with the UID check still
admitting only `hacp-agent`. Only public identities are exchanged.

The operator relays the sealed edge via SSH/sudo rsync (guardian ownership and
modes preserved; no keys or session stores copied). The `.hacp` snapshot has
one writer per turn, then syncs. During execution only sealed edge files sync.

## Asserted outcomes

Secure question/answer; bilateral contract freeze; Wasmer hello execution and
secure return; filesystem/environment/network denial (fake canaries, real
loopback listener); timeout; out-of-policy denial; skill submit/verify
settlement; replay rejection on a running guardian; tamper rejection before
execution. Attack mutation is operator-only and never prints envelope
internals.

## Limits

Trusted operator controls both VMs and the relay; the snapshot needs serial
writes; agent B shares a UID with its execution service (it can stop/replace
it); guardian replay state is process-local (no restart-persistent claim);
repos are not image-pinned and cold builds need network. Live execution
evidence is recorded after running the workflow — static acceptance alone
does not establish cross-machine or Linux Wasmer isolation.
