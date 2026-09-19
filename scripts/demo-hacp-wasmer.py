#!/usr/bin/env python3
"""HACP Secure x Wasmer: Agent A requests execution through its guardian, Agent B's
guardian side authorizes it, Wasmer runs it, and the result returns sealed.
Fails on any unmet assertion."""
import argparse
import base64
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
WASMER = ROOT / "infra/wasmer"
EXAMPLES = WASMER / "examples"
PACKAGE = "python/python@3.13.20"

# Reuse the HACP Secure demo's guardian pair and patched-skill build unchanged.
_spec = importlib.util.spec_from_file_location("demo_hacp_secure", ROOT / "scripts/demo-hacp-secure.py")
secure = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(secure)
URN, run, Pair = secure.URN, secure.run, secure.Pair

# Fake stand-ins planted in the execution service's own environment.
SECRET_ENV = ["HACP_GUARDIAN_PRIVATE_KEY", "HACP_SESSION_KEY", "WASMER_TOKEN"]
GRANT = ("SANDBOX_GREETING", "hello-from-agent-a")
POLICY = {
    "allowed_peers": [URN["a"]],
    "allowed_packages": [PACKAGE],
    "max_timeout_ms": 10000,
    "max_output_bytes": 65536,
    "max_args": 32,
    "max_files": 8,
    "max_total_file_bytes": 262144,
    "allowed_env": [GRANT[0]],
    "allowed_network": [],
}


class Listener:
    """Loopback listener that counts connections reaching the host."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.sock.settimeout(0.05)
        self.port = self.sock.getsockname()[1]
        self.count, self.stopping = 0, False
        self.thread = threading.Thread(target=self._accept, daemon=True)
        self.thread.start()

    def _accept(self):
        while not self.stopping:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            self.count += 1
            conn.close()

    def stop(self):
        time.sleep(0.1)
        self.stopping = True
        self.thread.join()
        self.sock.close()
        return self.count


class Execution:
    def __init__(self, work, pair, context, binding):
        self.work, self.pair, self.context, self.binding = work, pair, context, binding
        self.bin = WASMER / "target/debug"
        self.audit = work / "exec-audit.jsonl"
        self.policy = work / "exec-policy.json"
        self.policy.write_text(json.dumps(POLICY))
        self.staging = work / "exec-staging"
        self.staging.mkdir(mode=0o700)
        token = uuid.uuid4().hex
        self.secrets = {name: f"FAKE-{name}-{token}" for name in SECRET_ENV}
        self.service = None

    def service_command(self):
        cmd = [self.bin / "hacp-exec-guardian", "--socket", self.pair.sockets["b"], "--agent", URN["b"],
               "--context", self.context, "--policy", self.policy, "--audit", self.audit,
               "--staging-root", self.staging, "--poll-ms", "100"]
        env = os.environ.copy()
        env.update(self.secrets)
        env["FORWARD_HOST_ENV"] = "true"
        return [str(c) for c in cmd], env

    def start(self):
        cmd, env = self.service_command()
        log_path = self.work / "exec-service.log"
        with log_path.open("w") as log:
            self.service = subprocess.Popen(cmd, env=env, stdout=log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 30
        while "ready" not in log_path.read_text():
            assert self.service.poll() is None, log_path.read_text()
            assert time.monotonic() < deadline, "execution service startup failed"
            time.sleep(0.05)

    def once(self):
        cmd, env = self.service_command()
        r = subprocess.run(cmd + ["--once"], env=env, text=True, capture_output=True)
        assert r.returncode == 0, r.stderr
        return [json.loads(line) for line in r.stdout.splitlines()]

    def stop(self):
        if self.service:
            self.service.terminate()
            self.service.wait(timeout=10)
            self.service = None

    def request(self, *args, wait=True):
        cmd = [self.bin / "hacp-exec", "--socket", self.pair.sockets["a"], "--agent", URN["a"], "--peer", URN["b"],
               "--context", self.context, "--contract", self.binding, "--wait-secs", "180", *args]
        if not wait:
            cmd.append("--no-wait")
        r = subprocess.run([str(c) for c in cmd], text=True, capture_output=True)
        out = json.loads(r.stdout)
        assert r.returncode == 0 and out["ok"], f"{args}: {r.stdout} {r.stderr}"
        return out["returned"] if wait else out

    def python(self, script, *args, extra=(), wait=True):
        flags = ["--package", PACKAGE, "--file", f"{script.name}={script}", "--arg", f"/work/{script.name}"]
        for arg in args:
            flags += ["--arg", str(arg)]
        return self.request(*flags, *extra, wait=wait)

    def audited(self):
        return [json.loads(line) for line in self.audit.read_text().splitlines()] if self.audit.exists() else []


def stdout_lines(body):
    return body.get("stdout", "").splitlines()


def guest_finished(body):
    return body["status"] == "completed" and body["exit_code"] == 0 and "DONE" in stdout_lines(body)


def guest_exposed(body):
    return any(line.startswith("EXPOSED") for line in stdout_lines(body))


def negotiate(pair):
    """The existing patched /hacp workflow freezes the contract that authorizes execution."""
    pair.cli("a", "start", "request sandboxed execution", "--owns", "exec-result.json")
    pair.cli("b", "join", "authorize and run sandboxed execution", "--owns", "exec-review.txt")
    terms = pair.project / "a-terms.json"
    terms.write_text(json.dumps({"inputs": [], "outputs": ["exec-result.json"], "acceptance": ["test -s exec-result.json"]}))
    proposed = pair.cli("a", "propose", "--terms", terms)
    cid = proposed["contract"]["contract_id"]
    assert any(m["kind"] == "contract.proposed" for m in pair.cli("b", "poll")["messages"])
    frozen = pair.cli("b", "accept", cid, proposed["pending_digest"])
    revision = frozen["contract"]["revisions"][-1]["digest"]
    assert any(m["kind"] == "contract.frozen" for m in pair.cli("a", "poll")["messages"])
    context = json.loads((pair.project / ".hacp/session.json").read_text())["session"]["session_id"]
    binding = "sha256:" + revision.removeprefix("sha256:")
    print(f"EXECUTION CONTRACT: FROZEN ({cid})", flush=True)
    return cid, revision, context, binding


def scenarios(work, pair, ex):
    project = pair.project
    hello = ex.python(EXAMPLES / "hello.py")
    body = hello["body"]
    assert body["status"] == "completed" and body["exit_code"] == 0, hello
    assert body["stdout"].strip() == "HACP Wasmer sandbox works", hello
    assert hello["contract"] == ex.binding, hello
    hello_b64 = base64.b64encode((EXAMPLES / "hello.py").read_bytes())
    edge = [p.read_bytes() for p in (project / ".hacp-secure").rglob("*.json")]
    control = [p.read_bytes() for p in (project / ".hacp").rglob("*") if p.is_file()]
    assert edge, "no sealed frames on the edge"
    for needle in (b"HACP Wasmer sandbox works", hello_b64, b"sandbox.execution"):
        assert all(needle not in frame for frame in edge), f"plaintext {needle!r} on the encrypted edge"
        assert all(needle not in record for record in control), f"plaintext {needle!r} in shared .hacp state"
    assert any(e["message_id"] == hello["request_id"] and e["status"] == "executed" and e["replied"] for e in ex.audited())
    print("LEGITIMATE EXECUTION: PASS (request and result sealed; no plaintext on the edge)", flush=True)

    planted = work / "planted"
    (planted / "guardian/keys").mkdir(parents=True)
    canary = "FAKE-HACP-KEY-MATERIAL-" + uuid.uuid4().hex
    key_file = planted / "guardian/keys/guardian_ed25519.key"
    key_file.write_text(canary)
    (planted / "session-state.json").write_text(json.dumps({"session_key": canary}))
    probe = work / "guest-write-probe.txt"
    # The first target must be a file: the guest also tries traversal and a symlink to it.
    targets = [key_file, planted / "session-state.json", pair.base / "store-b/identity.key", pair.base / "store-b",
               pair.sockets["b"].parent, project / ".hacp-secure", project / ".hacp/session.json", ROOT,
               Path("/etc/passwd"), Path.home()]
    body = ex.python(EXAMPLES / "filesystem-denied.py", probe, *targets)["body"]
    assert guest_finished(body) and not guest_exposed(body), body
    assert canary not in json.dumps(body) and not probe.exists() and key_file.read_text() == canary, body
    print("HOST FILESYSTEM ACCESS: BLOCKED (guardian store, socket dir, edge, project, $HOME)", flush=True)

    body = ex.python(EXAMPLES / "env-denied.py", GRANT[0], *SECRET_ENV, extra=("--env", f"{GRANT[0]}={GRANT[1]}"))["body"]
    text = json.dumps(body)
    assert guest_finished(body) and not guest_exposed(body), body
    assert all(value not in text for value in ex.secrets.values()), body
    assert f"GRANTED {GRANT[0]}={GRANT[1]}" in stdout_lines(body), body
    print("HOST SECRET ACCESS: BLOCKED (HACP_* and WASMER_TOKEN absent; only the approved variable present)", flush=True)

    listener = Listener()
    body = ex.python(EXAMPLES / "network-denied.py", listener.port)["body"]
    widened = ex.python(EXAMPLES / "network-denied.py", listener.port,
                        extra=("--net", f"ipv4:allow=127.0.0.1:{listener.port}"))["body"]
    connections = listener.stop()
    assert guest_finished(body) and not guest_exposed(body) and connections == 0, (body, connections)
    assert widened["status"] == "denied" and widened["denial"]["code"] == "NetworkNotAllowed", widened
    print("UNAUTHORIZED NETWORK: BLOCKED (sandbox had no network; out-of-policy grant denied)", flush=True)

    returned = ex.request("--package", PACKAGE, "--arg", "-c", "--arg", "while True: pass", "--timeout-ms", "2000")
    body = returned["body"]
    assert body["status"] == "failed" and body["failure"]["kind"] == "TimedOut", body
    assert body["duration_ms"] < 10000, body
    print(f"TIMEOUT: ENFORCED (killed after {body['duration_ms']} ms)", flush=True)

    denied = {}
    for code, flags in [
        ("PackageNotAllowed", ("--package", "wasmer/bash", "--arg", "-c")),
        ("EnvNotAllowed", ("--package", PACKAGE, "--arg", "-c", "--arg", "pass", "--env", "HACP_SESSION_KEY=agent-supplied")),
        ("TimeoutOutOfPolicy", ("--package", PACKAGE, "--arg", "-c", "--arg", "pass", "--timeout-ms", "600000")),
    ]:
        returned = ex.request(*flags)
        assert returned["body"]["status"] == "denied" and returned["body"]["denial"]["code"] == code, returned
        denied[returned["request_id"]] = code
    for entry in ex.audited():
        if entry["message_id"] in denied:
            assert entry["status"] == "denied", entry
    print("UNAPPROVED EXECUTION DATA: DENIED BEFORE WASMER (package, HACP_* env, timeout)", flush=True)
    return hello


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skill-bin", type=Path, help="developer-only: use an already patched skill binary")
    args = parser.parse_args()
    run(["cargo", "build", "--locked", "--features", "guardian", "--bin", "hacp-secure-guardian", "--target-dir", ROOT / "target"])
    run(["cargo", "build", "--locked", "--manifest-path", WASMER / "Cargo.toml", "--bins"])
    # Warm Wasmer's package cache on the host so no run downloads inside its timeout.
    run([os.environ.get("HACP_WASMER_BIN", "wasmer"), "run", PACKAGE, "--", "-c", "pass"])
    guardian = ROOT / "target/debug/hacp-secure-guardian"
    with tempfile.TemporaryDirectory(prefix="hw-", dir="/tmp") as directory:
        work = Path(directory)
        skill = args.skill_bin or secure.build_skill(work)
        pair = Pair(work / "exec", guardian, skill)
        ex = None
        try:
            cid, revision, context, binding = negotiate(pair)
            ex = Execution(work, pair, context, binding)
            ex.start()
            hello = scenarios(work, pair, ex)
            ex.stop()

            # The execution service owns guardian delivery for this session while it
            # runs; with it stopped, the ordinary /hacp workflow continues unchanged.
            (pair.project / "exec-result.json").write_text(json.dumps(hello, indent=2) + "\n")
            pair.cli("a", "submit", cid, revision, "--claim", "Sandboxed result returned over HACP Secure")
            verified = pair.cli("b", "verify", cid)
            assert verified["contract"]["state"] == "settled", verified
            pair.cli("a", "poll")
            print("EXISTING HACP WORKFLOW: CONTRACT SETTLED", flush=True)

            sent = ex.python(EXAMPLES / "hello.py", wait=False)
            frames = [f for f in (pair.project / ".hacp-secure").rglob("*-a.json") if "handshakes" not in f.parts]
            frame = max(frames, key=lambda f: f.stat().st_mtime_ns)
            envelope = json.loads(frame.read_text())
            data = bytearray.fromhex(envelope["ct"])
            data[0] ^= 1
            envelope["ct"] = data.hex()
            frame.write_text(json.dumps(envelope))
            outcomes = ex.once()
            assert any(o["status"] == "rejected" for o in outcomes), outcomes
            assert all(o.get("message_id") != sent["request_id"] for o in outcomes), outcomes
            assert all(e.get("message_id") != sent["request_id"] for e in ex.audited())
            print("TAMPERED EXECUTION REQUEST: REJECTED BY GUARDIAN, NOT EXECUTED", flush=True)
        finally:
            if ex:
                ex.stop()
            pair.close()
    print("Mode: degraded (same UID); OS isolation between agent, guardian and execution service is not proven locally.")


if __name__ == "__main__":
    main()
