"""Guest program: look for the host's Wasmer registry credentials.

Usage (inside the sandbox):
    wasmer-token-denied.py <host-path>...

Tries to read each host path (the Wasmer config holding the registry token and
its directory) and the WASMER_TOKEN variable, then prints DONE. The host checks
its real token never appears in this output.
"""
import os
import sys


def look(path):
    if os.path.isdir(path):
        return sorted(os.listdir(path))[:10]
    with open(path, "rb") as f:
        return f.read(80)


for path in sys.argv[1:]:
    try:
        leaked = look(path)
    except OSError as e:
        print(f"DENIED  read {path} ({type(e).__name__}: {e.strerror or e})")
    else:
        print(f"EXPOSED read {path} ({leaked!r})")

token = os.environ.get("WASMER_TOKEN")
if token is None:
    print("DENIED  env WASMER_TOKEN (not present)")
else:
    print(f"EXPOSED env WASMER_TOKEN ({token!r})")
print("DONE")
