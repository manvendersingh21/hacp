#!/usr/bin/env bash
# Build and run the HACP Wasmer sandbox PoC. Exits non-zero if any check fails.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -z "${HACP_WASMER_BIN:-}" ] && ! command -v wasmer >/dev/null 2>&1; then
  echo "wasmer CLI not found. Install it with one of:" >&2
  echo "  brew install wasmer" >&2
  echo "  curl https://get.wasmer.io -sSfL | sh" >&2
  exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found. Install Rust from https://rustup.rs" >&2
  exit 1
fi

# The first run downloads python/python from the Wasmer registry (host side only).
exec cargo run --quiet --manifest-path "$here/Cargo.toml" --bin hacp-wasmer-demo -- "$@"
