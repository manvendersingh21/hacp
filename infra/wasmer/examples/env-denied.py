"""Guest program: look for host secrets in the environment.

Usage (inside the sandbox):
    env-denied.py <explicitly-granted-var> <host-secret-var>...

Prints the guest's variable names (never values, unless one leaks), one line
per secret variable, then DONE.
"""
import os
import sys

granted, secret_names = sys.argv[1], sys.argv[2:]
print("GUEST_ENV_KEYS", sorted(os.environ))

if granted in os.environ:
    print(f"GRANTED {granted}={os.environ[granted]}")
else:
    print(f"MISSING_GRANT {granted}")

for name in secret_names:
    value = os.environ.get(name)
    if value is None:
        print(f"DENIED  env {name} (not present)")
    else:
        print(f"EXPOSED env {name} ({value!r})")

try:
    with open("/proc/self/environ", "rb") as f:
        data = f.read()
except OSError as e:
    print(f"DENIED  file /proc/self/environ ({type(e).__name__})")
else:
    print(f"INFO    /proc/self/environ readable: {data[:200]!r}")

print("DONE")
