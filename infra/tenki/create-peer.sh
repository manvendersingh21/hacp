#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/common.sh"

usage() { printf 'usage: create-peer.sh <a|b>\n' >&2; exit 2; }
[ $# -eq 1 ] || usage
peer="$1"
require_peer "$peer"
require_tenki
require_jq

[ -z "$(session_id "$peer")" ] || die "peer already recorded; destroy it first"
name="$(peer_name "$peer")"
tags="hacp,$(peer_tag "$peer")"

printf 'creating Tenki VM for peer %s (%s): cpu=%s mem=%sMB disk=%sGB idle-timeout=%s max-duration=%s\n' \
  "$peer" "$(peer_urn "$peer")" "$HACP_VM_CPU" "$HACP_VM_MEMORY_MB" "$HACP_VM_DISK_GB" "$HACP_VM_IDLE_TIMEOUT" "$HACP_VM_MAX_DURATION"

out="$(tenki sandbox create \
  --name "$name" \
  --cpu "$HACP_VM_CPU" \
  --memory-mb "$HACP_VM_MEMORY_MB" \
  --disk-size-gb "$HACP_VM_DISK_GB" \
  --idle-timeout "$HACP_VM_IDLE_TIMEOUT" \
  --max-duration "$HACP_VM_MAX_DURATION" \
  --allow-outbound \
  --tags "$tags" \
  --metadata "purpose=hacp-secure" \
  --metadata "peer_urn=$(peer_urn "$peer")" \
  --output json)"

printf '%s\n' "$out" > "$STATE_DIR/create-$peer.last.json"

sid="$(printf '%s' "$out" | jq -r '.session_id // .sessionId // .id // empty')"
[ -n "$sid" ] || die "could not parse session id from create output: $out"

save_session "$peer" "$sid" "$name"

tenki sandbox ssh config install >/dev/null 2>&1 || true

printf 'peer %s ready\n  session : %s\n  ssh     : %s\n  exec   : infra/tenki/exec.sh %s "uname -a"\n' \
  "$peer" "$sid" "$(ssh_alias_for "$sid")" "$peer"
