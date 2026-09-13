#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/common.sh"
[ $# -eq 1 ] || die 'usage: destroy-peer.sh a|b|all'
case "$1" in a|b) peers="$1";; all) peers='a b';; *) die 'expected a|b|all';; esac
failed=0
for peer in $peers; do
 sid="$(session_id "$peer")"; [ -n "$sid" ] || continue
 if tenki sandbox terminate --session "$sid"; then
  printf 'CLEANUP terminated peer=%s session=%s\n' "$peer" "$sid"
  clear_session "$peer"
 else failed=1; fi
done
exit "$failed"
