#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/common.sh"

usage() { printf 'usage: exec.sh <a|b> "<command>"\n' >&2; exit 2; }
[ $# -ge 2 ] || usage
peer="$1"
require_peer "$peer"
shift

printf '== peer %s ==\n' "$peer"
tk_exec "$peer" -c "$*"
