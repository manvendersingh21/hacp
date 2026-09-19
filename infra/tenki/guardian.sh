#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/common.sh"
[ $# -ge 2 ] || die 'usage: guardian.sh a|b init|pin|public|start|stop|status'
peer="$1"; action="$2"; shift 2; require_peer "$peer"
[ "$HACP_GUARDIAN_MODE" = standard ] || die 'this deployment requires standard mode'
store="$HACP_GUARDIAN_HOME/.hacp-secure"
runtime="$HACP_GUARDIAN_HOME/runtime/$peer"
socket="$runtime/guardian.sock"
guard="sudo -u $(quote "$HACP_GUARDIAN_USER") -H /usr/local/bin/hacp-secure-guardian"
case "$action" in
 init) vm_run "$peer" "$guard init --store $(quote "$store") --agent $(quote "$(peer_urn "$peer")")";;
 pin) [ $# -eq 2 ] || die 'pin requires peer-urn raw-public-key'; [[ "$2" =~ ^[0-9a-f]{64}$ ]] || die 'expected raw 32-byte public key hex'; vm_run "$peer" "$guard pin --store $(quote "$store") --peer $(quote "$1") --pub $(quote "$2") --require-secure true";;
 public) vm_run "$peer" "sudo -u $(quote "$HACP_GUARDIAN_USER") cat $(quote "$store/identity.pub")";;
 start)
 vm_run "$peer" "sudo bash -s $(quote "$HACP_GUARDIAN_USER" "$store" "$HACP_PROJECT_DIR" "$runtime") <<'REMOTE'
set -euo pipefail
guard=\"\$1\"; store=\"\$2\"; project=\"\$3\"; runtime=\"\$4\"
if [ -f \"\$runtime/pid\" ] && kill -0 \"\$(cat \"\$runtime/pid\")\" 2>/dev/null; then echo 'guardian already running'; exit 1; fi
chmod 0700 \"\$runtime\"
rm -f \"\$runtime/guardian.sock\"
# Relay uses operator sudo; encrypted edge retains guardian-only modes.
chgrp hacp \"\$project\"; chmod 2770 \"\$project\"
runuser -u \"\$guard\" -- /usr/local/bin/hacp-secure-guardian serve --store \"\$store\" --project \"\$project\" --socket \"\$runtime/guardian.sock\" --agent-uid \"\$(id -u hacp-agent)\" >\"\$runtime/service.log\" 2>&1 </dev/null &
echo \$! > \"\$runtime/pid\"
for i in {1..100}; do [ -S \"\$runtime/guardian.sock\" ] && break; sleep .1; done
test -S \"\$runtime/guardian.sock\"
chgrp hacp \"\$runtime\" \"\$runtime/guardian.sock\"
chmod 0710 \"\$runtime\"
chmod 0660 \"\$runtime/guardian.sock\"
echo 'GUARDIAN STANDARD READY'
REMOTE";;
 stop) vm_run "$peer" "sudo pkill -u $(quote "$HACP_GUARDIAN_USER") -f '^/usr/local/bin/hacp-secure-guardian serve' || test \$? = 1";;
 status) vm_run "$peer" "sudo test -S $(quote "$socket") && sudo pgrep -u $(quote "$HACP_GUARDIAN_USER") -f '^/usr/local/bin/hacp-secure-guardian serve'";;
 *) die 'unknown guardian action';;
esac
