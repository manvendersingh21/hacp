#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/common.sh"
[ $# -eq 1 ] || die 'usage: deploy-hacp.sh a|b'
peer="$1"; require_peer "$peer"
alias="$(ssh_alias_for "$(require_session "$peer")")"
root="$(cd "$TENKI_DIR/../.." && pwd)"
# Allowlist tracked source plus this integration's outputs. No session, local
# config, credentials, ignored caches, or arbitrary untracked files are sent.
manifest="$STATE_DIR/deploy-files"
python3 - "$root" "$manifest" <<'PY'
import pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1]); files=set(subprocess.check_output(['git','ls-files','-z'],cwd=root).decode().split('\0'))
files={f for f in files if f and not any(p.startswith('.') for p in pathlib.Path(f).parts) and (root/f).is_file()}
for folder in ['infra/tenki','infra/wasmer']:
 for p in (root/folder).rglob('*'):
  rel=p.relative_to(root)
  if p.is_file() and not any(x.startswith('.') or x in ('target','state','node_modules','__pycache__') for x in rel.parts) and p.name!='tenki.env': files.add(str(rel))
files.update(['scripts/demo-hacp-wasmer.py','docs/hacp-wasmer-integration.md'])
pathlib.Path(sys.argv[2]).write_text('\n'.join(sorted(files))+'\n')
PY
rsync -rlt --files-from="$manifest" -e ssh "$root/" "$alias:$HACP_PROJECT_DIR/"
other=a; [ "$peer" = a ] && other=b
vm_run "$peer" "bash -s $(quote "$HACP_PROJECT_DIR" "$HACP_EXEC_POLICY" "$(peer_urn "$other")") <<'REMOTE'
set -euo pipefail
project=\"\$1\"; policy=\"\$2\"; requester=\"\$3\"
cd \"\$project\"
. \"\$HOME/.cargo/env\"
cargo build --locked --release --features guardian --bins
cargo build --locked --release --manifest-path infra/wasmer/Cargo.toml --bins
sudo install -m 0755 target/release/hacp-secure-guardian target/release/hacp-secure infra/wasmer/target/release/hacp-exec infra/wasmer/target/release/hacp-exec-guardian /usr/local/bin/
sudo install -d -m 0755 /etc/hacp
jq --arg p \"\$requester\" '.allowed_peers=[\$p]' infra/wasmer/exec-policy.example.json > /home/tenki/exec-policy.build.json
sudo install -o root -g root -m 0644 /home/tenki/exec-policy.build.json \"\$policy\"
rm /home/tenki/exec-policy.build.json
python3 - <<'PY'
import json,pathlib,subprocess
root=pathlib.Path.cwd(); source=json.loads((root/'integrations/hacp-skill/source.json').read_text())
checkout=pathlib.Path('/home/tenki/hacp-skill-build')
if not checkout.exists(): subprocess.run(['git','clone','--quiet',source['repository'],str(checkout)],check=True)
subprocess.run(['git','-C',str(checkout),'checkout','--force',source['commit']],check=True)
subprocess.run(['git','apply',str(root/'integrations/hacp-skill/secure.patch')],cwd=checkout,check=True)
p=checkout/'Cargo.toml';p.write_text('\\n'.join('hacp = { path = '+json.dumps(str(root))+' }' if line.startswith('hacp =') else line for line in p.read_text().splitlines())+'\\n')
subprocess.run(['cargo','build','--locked','--release'],cwd=checkout,check=True)
subprocess.run(['cargo','test','--locked'],cwd=checkout,check=True)
subprocess.run(['sudo','install','-m','0755',str(checkout/'target/release/hacp'),'/usr/local/bin/hacp'],check=True)
PY
sudo -u hacp-agent -H hacp --peer $peer --project \"\$project\" install --cli claude
sudo chown -R hacp-agent:hacp \"\$project/.hacp\" 2>/dev/null || true
printf 'DEPLOY PASS\\n'
REMOTE"
