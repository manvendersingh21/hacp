#!/usr/bin/env bash
set -euo pipefail
peer="${1:?peer}"; project="${2:?project}"; guard="${3:?guardian user}"
version="${4:-7.4.1}"; package="${5:-python/python@3.13.20}"
cache="${6:-/home/tenki/.wasmer-exec}"; staging="${7:-/home/tenki/exec-staging}"
umask 022
printf 'BOOTSTRAP architecture=%s agent_uid=%s\n' "$(uname -m)" "$(id -u)"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential pkg-config libssl-dev curl git jq rsync acl python3
if [ ! -x "$HOME/.cargo/bin/rustc" ]; then
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
fi
. "$HOME/.cargo/env"
getent group hacp >/dev/null || sudo groupadd hacp
id "$guard" >/dev/null 2>&1 || sudo useradd -m -s /bin/bash "$guard"
sudo usermod -aG hacp "$guard"
sudo usermod -aG hacp "$(id -un)"
id hacp-agent >/dev/null 2>&1 || sudo useradd -m -s /bin/bash hacp-agent
sudo usermod -aG hacp hacp-agent
sudo chmod 0750 /home/hacp-agent
sudo chgrp hacp /home/hacp-agent
guard_home="$(getent passwd "$guard" | cut -d: -f6)"
sudo chgrp hacp "$guard_home"
sudo chmod 0710 "$guard_home"
sudo install -d -o "$guard" -g hacp -m 0710 "$guard_home/runtime"
sudo install -d -o "$guard" -g hacp -m 0700 "$guard_home/runtime/$peer" "$guard_home/.hacp-secure"
# Parent (default /srv/hacp) stays root:root 0755 so hacp-agent/hacp-guard can
# traverse into it regardless of /home/tenki's own mode (Ubuntu 24.04 HOME_MODE).
sudo install -d -o root -g root -m 0755 "$(dirname "$project")"
sudo install -d -o hacp-agent -g hacp -m 2770 "$project"
sudo install -d -o "$guard" -g hacp -m 0700 "$project/.hacp-secure"
sudo install -d -o hacp-agent -g hacp -m 0700 "$cache" "$staging" /home/hacp-agent/.hacp-agent-state
if [ ! -x "$HOME/.wasmer/bin/wasmer" ]; then
  curl -fsSL https://get.wasmer.io | sh -s -- "v$version"
fi
"$HOME/.wasmer/bin/wasmer" --version | grep -F "wasmer $version"
sudo install -m 0755 "$HOME/.wasmer/bin/wasmer" /usr/local/bin/wasmer
sudo -u hacp-agent -H env WASMER_DIR="$cache" /usr/local/bin/wasmer run "$package" -- -c pass
# The pinned hacp-skill source + integrations/hacp-skill/secure.patch are built
# by deploy-hacp.sh after the project is available, never upstream tag v0.1.1.
printf 'BOOTSTRAP PASS (%s)\n' "$peer"
