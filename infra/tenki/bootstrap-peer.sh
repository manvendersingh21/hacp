#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/common.sh"
[ $# -eq 1 ] || die 'usage: bootstrap-peer.sh a|b'
peer="$1"; require_peer "$peer"
sid="$(require_session "$peer")"
tenki sandbox write --session "$sid" --path /home/tenki/bootstrap-vm.sh --data-file "$TENKI_DIR/lib/bootstrap-vm.sh" >/dev/null
vm_run "$peer" "bash /home/tenki/bootstrap-vm.sh $(quote "$peer" "$HACP_PROJECT_DIR" "$HACP_GUARDIAN_USER" "$HACP_WASMER_VERSION" "$HACP_WASMER_PACKAGE" "$HACP_EXEC_WASMER_DIR" "$HACP_EXEC_STAGING")"
