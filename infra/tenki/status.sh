#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/common.sh"

usage() { printf 'usage: status.sh [--vms|--guardians]\n' >&2; exit 2; }
require_tenki
require_jq

mode="${1:---vms}"

vm_row() {
  local peer="$1" s="$2"
  sid="$(printf '%s' "$s" | jq -r '.sessionId // .session_id // .id // "?"')"
  state="$(printf '%s' "$s" | jq -r '.state // .status // "?"')"
  name="$(printf '%s' "$s" | jq -r '.name // "?"')"
  printf '%-4s %-28s %-40s %-10s\n' "$peer" "$name" "$sid" "$state"
}

case "$mode" in
  --guardians)
    for peer in $PEERS; do
      sid="$(session_id "$peer")" || true
      if [ -n "$sid" ]; then
        printf '== peer %s (%s)\n' "$peer" "$sid"
        "$(dirname "$0")/guardian.sh" "$peer" status || true
      fi
    done
    ;;
  --vms|*)
    printf 'hacp Tenki sessions (tag: hacp)\n'
    list="$(tenki sandbox list --output json)"
    sessions="$(printf '%s' "$list" | jq -c '[.. | objects | select(.tags? // [] | index("hacp"))] | .[]')"
    for peer in $PEERS; do
      sid="$(session_id "$peer")"
      if [ -n "$sid" ]; then
        s="$(printf '%s' "$sessions" | jq -c "select(.sessionId // .session_id // .id == \"$sid\")" | head -1)"
        [ -n "$s" ] && vm_row "$peer" "$s" || printf '%-4s %-28s %-40s %-10s\n' "$peer" "$(peer_name "$peer")" "$sid" "(not listed)"
      fi
    done
    [ -n "$sessions" ] || printf '  none\n'
    ;;
esac
