"""Guest program: try to reach host paths that were never granted.

Usage (inside the sandbox):
    filesystem-denied.py <host-write-probe-path> <host-path>...

Prints one line per attempt, then DONE:
    DENIED  <what> <path> (<error>)
    EXPOSED <what> <path> (<what leaked>)

Nothing here is destructive: directory listings, reads, and an attempt to
create one brand-new probe file. The host decides the verdict itself; these
lines are only for humans.
"""
import os
import sys


def attempt(what, path, action):
    try:
        leaked = action(path)
    except OSError as e:
        print(f"DENIED  {what} {path} ({type(e).__name__}: {e.strerror or e})")
    else:
        print(f"EXPOSED {what} {path} ({leaked!r})")


def look(path):
    if os.path.isdir(path):
        return sorted(os.listdir(path))[:10]
    with open(path, "rb") as f:
        return f.read(80)


def create(path):
    with open(path, "x") as f:
        f.write("sandbox write probe\n")
    return "created"


def through_symlink(path):
    link = "/work/escape-link"
    os.symlink(path, link)
    return look(link)


write_probe, targets = sys.argv[1], sys.argv[2:]
print("GUEST_ROOT", sorted(os.listdir("/")))

for target in targets:
    attempt("read", target, look)

key_file = targets[0]
attempt("traverse", "/work/" + "../" * 16 + key_file.lstrip("/"), look)
attempt("symlink", key_file, through_symlink)
attempt("write", write_probe, create)
print("DONE")
