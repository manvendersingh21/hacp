#!/usr/bin/env bash
set -euo pipefail
TENKI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${TENKI_ENV_FILE:-$TENKI_DIR/tenki.env}"
if [ -f "$ENV_FILE" ]; then . "$ENV_FILE"; fi
: "${HACP_STATE_DIR:=$HOME/.local/state/hacp-tenki}"
STATE_DIR="$HACP_STATE_DIR"
STATE_FILE="$STATE_DIR/sessions.json"
: "${HACP_PEER_A_URN:=urn:hacp:agent:a}"
: "${HACP_PEER_B_URN:=urn:hacp:agent:b}"
: "${HACP_VM_CPU:=4}"
: "${HACP_VM_MEMORY_MB:=8192}"
: "${HACP_VM_DISK_GB:=20}"
: "${HACP_VM_IDLE_TIMEOUT:=60m}"
: "${HACP_VM_MAX_DURATION:=4h}"
: "${HACP_VM_NAME_PREFIX:=hacp}"
: "${HACP_PROJECT_DIR:=/srv/hacp/project}"
: "${HACP_AGENT_HOME:=/home/hacp-agent}"
: "${HACP_GUARDIAN_USER:=hacp-guard}"
: "${HACP_GUARDIAN_HOME:=/home/$HACP_GUARDIAN_USER}"
: "${HACP_GUARDIAN_MODE:=standard}"
: "${HACP_SYNC_INTERVAL:=1}"
: "${HACP_WASMER_VERSION:=7.4.1}"
: "${HACP_WASMER_PACKAGE:=python/python@3.13.20}"
: "${HACP_EXEC_PEER:=b}"
: "${HACP_EXEC_WASMER_DIR:=$HACP_AGENT_HOME/.wasmer-exec}"
: "${HACP_EXEC_POLICY:=/etc/hacp/exec-policy.json}"
: "${HACP_EXEC_AUDIT:=$HACP_AGENT_HOME/exec-audit.jsonl}"
: "${HACP_EXEC_STAGING:=$HACP_AGENT_HOME/exec-staging}"
PEERS='a b'
umask 077
mkdir -p "$STATE_DIR"
[ -f "$STATE_FILE" ] || printf '{}\n' > "$STATE_FILE"
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
require_tenki() { command -v tenki >/dev/null || die 'tenki CLI not found'; }
require_jq() { command -v jq >/dev/null || die 'jq not found'; }
valid_peer() { case "$1" in a|b) return 0;; *) return 1;; esac; }
require_peer() { valid_peer "$1" || die 'expected peer a|b'; }
peer_urn() { require_peer "$1"; case "$1" in a) printf '%s' "$HACP_PEER_A_URN";; b) printf '%s' "$HACP_PEER_B_URN";; esac; }
peer_tag() { require_peer "$1"; printf 'peer-%s' "$1"; }
peer_name() { require_peer "$1"; printf '%s-peer-%s' "$HACP_VM_NAME_PREFIX" "$1"; }
session_id() { require_peer "$1"; jq -r --arg p "$1" '.[$p].session_id // empty' "$STATE_FILE"; }
require_session() { local sid; sid="$(session_id "$1")"; [ -n "$sid" ] || die "no recorded VM for peer $1"; printf '%s' "$sid"; }
save_session() { jq --arg p "$1" --arg s "$2" --arg n "$3" '.[$p]={session_id:$s,name:$n,created_at:(now|todateiso8601)}' "$STATE_FILE" > "$STATE_FILE.tmp"; mv "$STATE_FILE.tmp" "$STATE_FILE"; }
clear_session() { jq --arg p "$1" 'del(.[$p])' "$STATE_FILE" > "$STATE_FILE.tmp"; mv "$STATE_FILE.tmp" "$STATE_FILE"; }
ssh_alias_for() { printf 'sbx-%s' "$1"; }
# Quote each argument for a POSIX remote shell, including literal newlines.
quote() { python3 -c 'import shlex,sys;print(" ".join(map(shlex.quote,sys.argv[1:])))' "$@"; }
tk_exec() { local p="$1"; shift; tenki sandbox exec --session "$(require_session "$p")" "$@"; }
vm_run() {
  local peer="$1" out; shift
  out="$(tk_exec "$peer" --timeout "${TENKI_VM_RUN_TIMEOUT:-30m}" --json -c "$*")" || die "Tenki exec transport failed ($peer)"
  printf '%s' "$out" | jq -r '.stdout // ""'
  printf '%s' "$out" | jq -r '.stderr // ""' >&2
  printf '%s' "$out" | jq -e '.status == "SUCCEEDED" and ((.exit_code // 0) == 0)' >/dev/null || die "VM command failed ($peer)"
}
export HACP_STATE_DIR TENKI_DIR STATE_DIR STATE_FILE
