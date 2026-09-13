#!/usr/bin/env python3
"""Real pinned hacp-skill CLI + two guardian processes; fail on any unmet assertion."""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
URN = {p: f"urn:hacp:agent:{p}" for p in "ab"}


def run(args, *, cwd=ROOT, env=None):
    result = subprocess.run([str(a) for a in args], cwd=cwd, env=env, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"command failed: {args}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def request(path, value):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(10)
        client.connect(str(path))
        client.sendall(json.dumps(value).encode() + b"\n")
        with client.makefile("rb") as stream:
            return json.loads(stream.readline())


def build_skill(work):
    source = json.loads((ROOT / "integrations/hacp-skill/source.json").read_text())
    local = Path(os.environ.get("HACP_SKILL_SOURCE", ROOT.parent / "hacp-skill"))
    if not local.exists() or subprocess.run(["git", "-C", str(local), "cat-file", "-e", source["commit"]], capture_output=True).returncode:
        local = work / "upstream"
        run(["git", "clone", "--quiet", source["repository"], local])
    archive = work / "skill.tar"
    with archive.open("wb") as out:
        subprocess.run(["git", "-C", str(local), "archive", source["commit"]], stdout=out, check=True)
    checkout = work / "skill"
    checkout.mkdir()
    with tarfile.open(archive) as bundle:
        for member in bundle.getmembers():
            path = Path(member.name)
            assert not path.is_absolute() and ".." not in path.parts
            assert member.isdir() or member.isfile(), "pinned source must contain only files/directories"
            target = checkout / path
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.extractfile(member) as source_file, target.open("wb") as output:
                    shutil.copyfileobj(source_file, output)
                target.chmod(member.mode & 0o777)
    run(["git", "apply", ROOT / "integrations/hacp-skill/secure.patch"], cwd=checkout)
    manifest = checkout / "Cargo.toml"
    manifest.write_text("\n".join("hacp = { path = " + json.dumps(str(ROOT)) + " }" if line.startswith("hacp =") else line for line in manifest.read_text().splitlines()) + "\n")
    env = os.environ.copy()
    env.pop("HACP_SECURE", None)
    env.pop("HACP_SECURE_SOCKET", None)
    target = ROOT / "target/hacp-skill-secure-demo"
    env["CARGO_TARGET_DIR"] = str(target)
    run(["cargo", "build", "--locked"], cwd=checkout, env=env)
    run(["cargo", "test", "--locked"], cwd=checkout, env=env)
    return target / "debug/hacp"


class Pair:
    def __init__(self, base, guardian, skill=None):
        self.base, self.skill = base, skill
        base.mkdir()
        self.project = base / "project"
        self.project.mkdir()
        self.sockets, self.processes = {}, []
        self.states = {p: base / ("agent-state-" + p) for p in "ab"}
        for path in self.states.values():
            path.mkdir(mode=0o700)
        stores = {p: base / ("store-" + p) for p in "ab"}
        for p in "ab":
            run([guardian, "init", "--store", stores[p], "--agent", URN[p]])
        for p, other in [("a", "b"), ("b", "a")]:
            # Operator provisioning reads only PUBLIC identity material.
            public = (stores[other] / "identity.pub").read_text()
            run([guardian, "pin", "--store", stores[p], "--peer", URN[other], "--pub", public, "--require-secure", "true"])
            runtime = base / ("run-" + p)
            runtime.mkdir(mode=0o700)
            self.sockets[p] = runtime / "s"
            log = (base / ("guardian-" + p + ".log")).open("w")
            process = subprocess.Popen([str(guardian), "serve", "--store", str(stores[p]), "--project", str(self.project), "--socket", str(self.sockets[p]), "--degraded"], stdout=log, stderr=log)
            log.close()
            self.processes.append(process)
        for path in self.sockets.values():
            deadline = time.monotonic() + 10
            while not path.exists():
                assert time.monotonic() < deadline, "guardian startup failed"
                time.sleep(.02)

    def close(self):
        for p in self.processes:
            p.terminate()
        for p in self.processes:
            p.wait(timeout=5)

    def rpc(self, p, op, **args):
        return request(self.sockets[p], dict(op=op, **args))

    def cli(self, p, *args, fail=False, insecure=False):
        env = os.environ.copy()
        env["HACP_SECURE"] = "1"
        env["HACP_SECURE_SOCKET"] = str(self.sockets[p])
        env["HACP_SECURE_STATE"] = str(self.states[p])
        if insecure:
            env.pop("HACP_SECURE")
        cmd = [str(self.skill), "--peer", p, "--project", str(self.project), "--json", *map(str, args)]
        r = subprocess.run(cmd, text=True, capture_output=True, env=env)
        if fail:
            assert r.returncode != 0, "expected command rejection"
            return r.stdout + r.stderr
        assert r.returncode == 0, f"{args}: {r.stdout} {r.stderr}"
        return json.loads(r.stdout)

    def setup(self):
        self.context = "s-" + "1" * 32
        assert self.rpc("a", "session", peer=URN["b"], hacp_session=self.context)["ok"]
        assert self.rpc("b", "open", hacp_session=self.context)["ok"]
        assert self.rpc("a", "open", hacp_session=self.context)["ok"]
        self.sid = self.rpc("a", "status")["sessions"][0]["sid"]

    def seal(self, text="secret demo payload", contract=""):
        r = self.rpc("a", "seal", sid=self.sid, contract=contract, payload_b64=base64.b64encode(text.encode()).decode())
        assert r["ok"], r
        path = self.project / r["envelope_path"]
        return path, json.loads(path.read_text())

    def receive(self):
        return self.rpc("b", "open", hacp_session=self.context)


def errors(report):
    return {e["error"] for k in ("rejected", "aborted") for e in report.get(k, [])}


def collaboration(pair):
    pair.cli("a", "start", "write greeting", "--owns", "a.txt")
    pair.cli("b", "join", "write response", "--owns", "b.txt")
    entries = {}
    for p, other in [("a", "b"), ("b", "a")]:
        terms = pair.project / (p + "-terms.json")
        terms.write_text(json.dumps({"inputs": [], "outputs": [p + ".txt"], "acceptance": [f"test -s {p}.txt"]}))
        proposed = pair.cli(p, "propose", "--terms", terms)
        cid = proposed["contract"]["contract_id"]
        inbox = pair.cli(other, "poll")
        assert any(m["kind"] == "contract.proposed" and m["body"]["contract_id"] == cid for m in inbox["messages"])
        frozen = pair.cli(other, "accept", cid, proposed["pending_digest"])
        revision = frozen["contract"]["revisions"][-1]["digest"]
        assert any(m["kind"] == "contract.frozen" for m in pair.cli(p, "poll")["messages"])
        entries[p] = cid, revision
    q = pair.cli("a", "ask", "Can you verify the secure greeting?")["message_id"]
    incoming = pair.cli("b", "poll")["messages"]
    assert any(m["message_id"] == q and m["body"]["text"] == "Can you verify the secure greeting?" for m in incoming)
    print("NORMAL MESSAGE: ACCEPTED", flush=True)
    # Shared snapshot and legacy receipt-file injection cannot bypass guardian delivery.
    forged = copy.deepcopy(next(m for m in incoming if m["message_id"] == q))
    forged["message_id"] = "m-" + "f" * 32
    forged["body"]["text"] = "forged shared receipt"
    snapshot_path = pair.project / ".hacp/session.json"
    snapshot = json.loads(snapshot_path.read_text())
    snapshot["messages"].append(forged)
    snapshot["secure_received"] = {"b": {forged["message_id"]: forged}}
    snapshot_path.write_text(json.dumps(snapshot))
    legacy = pair.project / ".hacp/secure-received/b"
    legacy.mkdir(parents=True)
    (legacy / (forged["message_id"] + ".json")).write_text(json.dumps(forged))
    assert all(m["message_id"] != forged["message_id"] for m in pair.cli("b", "poll", "--all")["messages"])
    assert all(m["message_id"] != forged["message_id"] for m in pair.cli("b", "status")["messages"])
    pair.cli("b", "answer", forged["message_id"], "unauthenticated answer", fail=True)
    snapshot = json.loads(snapshot_path.read_text())
    snapshot["messages"] = [m for m in snapshot["messages"] if m["message_id"] != forged["message_id"]]
    snapshot_path.write_text(json.dumps(snapshot))
    print("FORGED SHARED RECEIPT: REJECTED", flush=True)
    outgoing = copy.deepcopy(forged)
    outgoing.update(message_id="m-" + "d" * 32, **{"from": URN["b"], "to": URN["a"]})
    snapshot = json.loads(snapshot_path.read_text())
    snapshot["messages"].append(outgoing)
    snapshot["secure_bindings"][outgoing["message_id"]] = "sha256:" + entries["b"][1]
    snapshot_path.write_text(json.dumps(snapshot))
    before = pair.rpc("b", "status")["sessions"][0]["send_seq"]
    pair.cli("b", "poll")
    assert pair.rpc("b", "status")["sessions"][0]["send_seq"] == before
    assert all(m["message_id"] != outgoing["message_id"] for m in pair.cli("a", "poll", "--all")["messages"])
    snapshot = json.loads(snapshot_path.read_text())
    snapshot["messages"] = [m for m in snapshot["messages"] if m["message_id"] != outgoing["message_id"]]
    snapshot_path.write_text(json.dumps(snapshot))
    print("PLANTED SHARED OUTGOING MESSAGE: REJECTED", flush=True)
    a = pair.cli("b", "answer", q, "Yes, the greeting arrived through my guardian.")["message_id"]
    assert any(m["message_id"] == a for m in pair.cli("a", "poll")["messages"])
    # Every ordinary notification is encrypted on the edge; no plaintext inbox projection.
    assert not list((pair.project / ".hacp/inbox").glob("**/*.json"))
    frames = list((pair.project / ".hacp-secure").glob("*/*.json"))
    assert frames and all("greeting" not in f.read_text() for f in frames)
    for p, other in [("a", "b"), ("b", "a")]:
        (pair.project / (p + ".txt")).write_text("verified collaboration\n")
        cid, revision = entries[p]
        pair.cli(p, "submit", cid, revision, "--claim", "Owned artifact ready")
        verified = pair.cli(other, "verify", cid)
        assert verified["contract"]["state"] == "settled", verified
        pair.cli(p, "poll")
    # An authenticated question absent the cooperative snapshot must still block completion.
    question = copy.deepcopy(next(m for m in incoming if m["message_id"] == q))
    question.update(message_id="m-" + "e" * 32, **{"from": URN["b"], "to": URN["a"]})
    question["body"] = {"text": "Confirm receipt before completing"}
    session = pair.rpc("b", "status")["sessions"][0]["sid"]
    reply = pair.rpc("b", "seal", sid=session, contract="sha256:" + entries["b"][1], payload_b64=base64.b64encode(json.dumps(question).encode()).decode())
    assert reply["ok"], reply
    assert "unanswered" in pair.cli("a", "complete", fail=True)
    pair.cli("a", "answer", question["message_id"], "Confirmed")
    # Restore the sender's cooperative bookkeeping for this low-level test-only injection.
    snapshot_path = pair.project / ".hacp/session.json"
    snapshot = json.loads(snapshot_path.read_text())
    snapshot["messages"].append(question)
    snapshot["secure_bindings"][question["message_id"]] = "sha256:" + entries["b"][1]
    snapshot_path.write_text(json.dumps(snapshot))
    private = pair.states["b"] / hashlib.sha256(str(pair.project.resolve()).encode()).hexdigest() / snapshot["session"]["session_id"] / "b"
    (private / ("sent-" + question["message_id"])).write_text("sent\n")
    pair.cli("b", "poll")
    outcome = pair.cli("a", "complete")
    assert outcome["outcome"] == "completed"
    assert any(m["kind"] == "session.close" and m["body"]["outcome"] == "completed" for m in pair.cli("b", "poll")["messages"])
    assert "downgrade" in pair.cli("b", "poll", fail=True, insecure=True).lower()
    print("LEGITIMATE HACP COLLABORATION: COMPLETED", flush=True)


def decline_workflow(pair):
    pair.cli("a", "start", "accepted task", "--owns", "a.txt")
    pair.cli("b", "join", "declined task", "--owns", "b.txt")
    for p, other in [("a", "b"), ("b", "a")]:
        terms = pair.project / (p + "-terms.json")
        terms.write_text(json.dumps({"inputs": [], "outputs": [p + ".txt"], "acceptance": ["true"]}))
        e = pair.cli(p, "propose", "--terms", terms)
        cid = e["contract"]["contract_id"]
        pair.cli(other, "accept" if p == "a" else "decline", cid, e["pending_digest"])
        messages = pair.cli(p, "poll")["messages"]
        assert any(m["kind"] == ("contract.frozen" if p == "a" else "contract.declined") for m in messages)
    pair.cli("a", "close", "--reason", "declined proposal; collaboration terminated")
    assert any(m["kind"] == "session.close" for m in pair.cli("b", "poll")["messages"])
    print("SECURE DECLINE / TERMINATION: DELIVERED", flush=True)


def attacks(work, guardian):
    for label, field in [("TAMPERED MESSAGE", "ct"), ("SIGNED METADATA", "contract"), ("IMPERSONATION", "from"), ("WRONG RECIPIENT", "to"), ("REPLAYED MESSAGE", None), ("PLAINTEXT DOWNGRADE", "plaintext")]:
        pair = Pair(work / label.replace(" ", "-").lower(), guardian)
        try:
            pair.setup()
            path, envelope = pair.seal()
            if field is None:
                first = pair.receive()
                assert len(first["delivered"]) == 1
            elif field == "plaintext":
                path.write_text(json.dumps({"protocol": "HACP/2.0", "from": URN["a"], "to": URN["b"], "body": "plaintext"}))
            else:
                if field == "ct":
                    data = bytearray.fromhex(envelope[field]); data[0] ^= 1
                    envelope[field] = data.hex()
                elif field == "contract":
                    envelope[field] = "sha256:" + "2" * 64
                else:
                    envelope[field] = "urn:hacp:agent:mallory"
                path.write_text(json.dumps(envelope))
            report = pair.receive()
            assert not report.get("delivered"), report
            expected = "ReplayRejected" if field is None else "DowngradeDetected" if field == "plaintext" else "IdentityMismatch" if field in ("from", "to") else "BadMessageSignature"
            assert expected in errors(report), report
            print(f"{label}: REJECTED", flush=True)
        finally:
            pair.close()
    pair = Pair(work / "contract", guardian)
    try:
        pair.setup()
        state_dir = pair.project / ".hacp"
        state_dir.mkdir()
        state_file = state_dir / "session.json"
        def observation(number):
            content = {"inputs": [], "outputs": ["demo"], "acceptance": ["true"]}
            record = {"contract_id": "c-demo", "revision": number, "content": content}
            digest = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            state = {"session": {"session_id": pair.context}, "contracts": {"c-demo": {"contract": {"state": "executing", "revisions": [{"number": number, "content": content, "digest": digest}]}}}}
            return state, "sha256:" + digest
        state, binding = observation(1)
        state_file.write_text(json.dumps(state))
        pair.seal(contract=binding)
        state_file.unlink()
        report = pair.receive()
        assert not report["delivered"] and report["held"], report
        state_file.write_text(json.dumps(state))
        assert len(pair.receive()["delivered"]) == 1
        pair.seal(contract=binding)
        state_file.write_text(json.dumps(observation(2)[0]))
        report = pair.receive()
        assert not report["delivered"] and "ContractMismatch" in errors(report), report
        print("CONTRACT BINDING: UNKNOWN HELD, MATCH DELIVERED, WRONG REVISION REJECTED", flush=True)
    finally:
        pair.close()
    pair = Pair(work / "gap", guardian)
    try:
        pair.setup()
        first, _ = pair.seal(); saved = first.read_bytes(); first.unlink()
        pair.seal()
        report = pair.receive()
        assert not report["delivered"] and report["held"], report
        pair.seal()
        report = pair.receive()
        assert not report["delivered"] and "SequenceGap" in errors(report), report
        print("SEQUENCE GAP: HELD, THEN ABORTED ON NEWER GAP", flush=True)
        for op in ["export", "private_key", "session_keys", "sign", "raw_sign"]:
            reply = pair.rpc("a", op)
            assert reply == {"ok": False, "error": "UnknownOperation", "detail": "UnknownOperation"}, reply
        print("SECRET EXPORT / RAW SIGNATURE API: REJECTED", flush=True)
    finally:
        pair.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skill-bin", type=Path, help="developer-only: use an already patched skill binary")
    args = parser.parse_args()
    run(["cargo", "build", "--locked", "--features", "guardian", "--bin", "hacp-secure-guardian", "--target-dir", ROOT / "target"])
    guardian = ROOT / "target/debug/hacp-secure-guardian"
    with tempfile.TemporaryDirectory(prefix="hs-", dir="/tmp") as directory:
        work = Path(directory)
        skill = args.skill_bin or build_skill(work)
        pair = Pair(work / "workflow", guardian, skill)
        try:
            collaboration(pair)
        finally:
            pair.close()
        pair = Pair(work / "decline", guardian, skill)
        try:
            decline_workflow(pair)
        finally:
            pair.close()
        attacks(work, guardian)
    print("Mode: degraded (same UID); OS isolation is not proven by this local demo.")


if __name__ == "__main__":
    main()
