#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/common.sh"
once=0; from=''; edge_only=0
while [ $# -gt 0 ]; do
 case "$1" in --once) once=1;; --from) from="$2"; require_peer "$from"; shift;; --edge-only) edge_only=1;; --interval) HACP_SYNC_INTERVAL="$2"; shift;; *) die 'usage: sync-edge.sh [--once] [--from a|b | --edge-only]';; esac; shift
done
[ "$edge_only" -eq 1 ] || [ -n "$from" ] || die 'choose cooperative snapshot writer with --from a|b, or --edge-only'
a="$(ssh_alias_for "$(require_session a)")"; b="$(ssh_alias_for "$(require_session b)")"
relay() {
 local src="$1" dst="$2" path="$3" stage="$STATE_DIR/relay-$1-$3"
 mkdir -p "$stage"
 # No --delete. --ignore-existing applies to immutable sealed edge frames only.
 # Plain string, not an array: bash 3.2 (macOS stock) treats "${arr[@]}" on an
 # empty array as unbound under set -u.
 local ignore_existing=''; [ "$path" = .hacp-secure ] && ignore_existing='--ignore-existing'
 rsync -rlt --quiet --rsync-path='sudo rsync' $ignore_existing --exclude lock --exclude '*.tmp' -e ssh "$src:$HACP_PROJECT_DIR/$path/" "$stage/"
 rsync -rlt --quiet --rsync-path='sudo rsync' $ignore_existing --exclude lock --exclude '*.tmp' -e ssh "$stage/" "$dst:$HACP_PROJECT_DIR/$path/"
 # Received edge belongs to the recipient guardian, not the agent or root.
 if [ "$path" = .hacp-secure ]; then
  ssh "$dst" "sudo chown -R $(quote "$HACP_GUARDIAN_USER") $(quote "$HACP_PROJECT_DIR/.hacp-secure")"
 else
  ssh "$dst" "sudo chown -R hacp-agent:hacp $(quote "$HACP_PROJECT_DIR/.hacp")"
 fi
 if [ "$path" = .hacp ]; then
  ssh "$dst" "sudo setfacl -R -m u:$(quote "$HACP_GUARDIAN_USER"):rX $(quote "$HACP_PROJECT_DIR/.hacp")"
 fi
}
pass() {
 if [ "$edge_only" -eq 0 ]; then
  if [ "$from" = a ]; then relay "$a" "$b" .hacp; else relay "$b" "$a" .hacp; fi
 fi
 relay "$a" "$b" .hacp-secure
 relay "$b" "$a" .hacp-secure
}
while true; do pass; [ "$once" -eq 1 ] && break; sleep "$HACP_SYNC_INTERVAL"; done
