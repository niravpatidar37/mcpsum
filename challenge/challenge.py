# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""mcpsum bypass challenge: set up the target, play one session, check the audit log.

  uv run challenge/challenge.py setup         # lock the target server
  uv run challenge/challenge.py play          # one client session through mcpsum
  uv run challenge/challenge.py check-audit   # after you edit .work/audit.jsonl

Rules: docs/CHALLENGE.md. The canary is random per run and is not a secret.
"""

from __future__ import annotations

import json
import os
import pathlib
import queue
import secrets
import shutil
import subprocess
import sys
import threading

HERE = pathlib.Path(__file__).resolve().parent
WORK = HERE / ".work"
LOCK, SERVER, AUDIT = WORK / "mcp.lock", WORK / "server.py", WORK / "audit.jsonl"
NAME = "target"
EVIL = HERE.parent / "e2e" / "servers" / "evil_server.py"


def exe() -> str:
    return os.environ.get("MCPSUM_BIN") or shutil.which("mcpsum") or sys.exit("mcpsum not found: set MCPSUM_BIN")


def mcpsum(*args: str) -> subprocess.CompletedProcess:
    # The mcpsum binary the participant chose, list-form argv, no shell.
    return subprocess.run([exe(), *args], capture_output=True, text=True, encoding="utf-8", check=False)  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit


def setup() -> int:
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir()
    shutil.copy(EVIL, SERVER)  # the server you control: edit it after setup
    r = mcpsum("lock", "--lock", str(LOCK), "--name", NAME, "--", sys.executable, str(SERVER), "--mode", "taint")
    if r.returncode != 0:
        sys.exit(r.stdout + r.stderr)
    lf = json.loads(LOCK.read_text(encoding="utf-8"))
    lf["servers"][NAME]["policy"] = {"taint": {"sources": ["fetch"], "sinks": ["add"]}}
    LOCK.write_text(json.dumps(lf, indent=2), encoding="utf-8")
    print(f"locked {LOCK}\nedit {SERVER} (it is yours), then: uv run challenge/challenge.py play")
    return 0


def parse(line: str) -> dict | None:
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        return None
    return msg if isinstance(msg, dict) else None


class Client:
    """Raw JSON-RPC client that records every line mcpsum sends it."""

    def __init__(self, env: dict) -> None:
        # Same as mcpsum(): the chosen binary, list-form argv, no shell.
        self.p = subprocess.Popen(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
            [exe(), "proxy", "--lock", str(LOCK), "--name", NAME, "--audit", str(AUDIT)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
        self.q: queue.Queue = queue.Queue()
        self.lines: list[str] = []
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.p.stdout is not None
        for raw in self.p.stdout:
            line = raw.decode("utf-8", "replace").strip()
            if line:
                self.lines.append(line)
                self.q.put(line)

    def send(self, msg: dict) -> None:
        assert self.p.stdin is not None
        self.p.stdin.write((json.dumps({"jsonrpc": "2.0", **msg}) + "\n").encode())
        self.p.stdin.flush()

    def wait(self, rid: int, on_request) -> dict:
        while True:
            try:
                msg = parse(self.q.get(timeout=20))
            except queue.Empty:
                return {}
            if msg is None:
                continue  # reported in the final scan
            if "method" in msg:
                on_request(msg)
            elif msg.get("id") == rid:
                return msg


def play() -> int:
    if not LOCK.exists():
        sys.exit("run setup first")
    canary = "mcpsum-canary-" + secrets.token_hex(16)
    shutil.rmtree(WORK / "state", ignore_errors=True)
    # A fresh, untainted session, and the canary planted in mcpsum's environment.
    env = {**os.environ, "MCPSUM_STATE_DIR": str(WORK / "state"), "SUPER_SECRET": canary}
    lock = json.loads(LOCK.read_text(encoding="utf-8"))["servers"][NAME]
    wins: list[str] = []
    approvals = 0
    sink_step = False

    def on_request(m: dict) -> None:
        nonlocal approvals
        if (sink_step and m.get("method") == "elicitation/create"
                and str(m.get("id", "")).startswith("mcpsum-approval-")):
            approvals += 1
            c.send({"id": m["id"], "result": {"action": "decline"}})  # the user says no
            return
        wins.append(f"I1/I3: a server-side message reached the client: {json.dumps(m)[:200]}")
        if "id" in m:
            c.send({"id": m["id"], "error": {"code": -32601, "message": "refused by the challenge client"}})

    c = Client(env)
    steps = [
        ("initialize", {"protocolVersion": "2025-06-18", "clientInfo": {"name": "challenge", "version": "1"},
                        "capabilities": {"sampling": {}, "elicitation": {}, "roots": {"listChanged": True}}}),
        ("tools/list", {}), ("prompts/list", {}), ("resources/list", {}), ("resources/templates/list", {}),
        ("tools/call", {"name": "add", "arguments": {"a": 1, "b": 2}}),
        ("tools/call", {"name": "add", "arguments": {"a": 1, "b": 2, "sidenote": canary}}),
        ("tools/call", {"name": "steal", "arguments": {"secret": canary}}),
        ("prompts/get", {"name": "steal", "arguments": {"secret": canary}}),
        ("resources/read", {"uri": f"file:///{canary}"}),
        ("tools/call", {"name": "echo_env", "arguments": {}}),  # SUPER_SECRET is not passed through
        ("tools/call", {"name": "fetch", "arguments": {"url": "https://example.invalid/"}}),  # source
        ("tools/call", {"name": "add", "arguments": {"a": 1300, "b": 37}}),  # sink after taint
    ]
    replies: dict[int, dict] = {}
    for rid, (method, params) in enumerate(steps):
        sink_step = rid == len(steps) - 1
        c.send({"id": rid, "method": method, "params": params})
        replies[rid] = c.wait(rid, on_request)
        if rid == 0:
            c.send({"method": "notifications/initialized"})
    assert c.p.stdin is not None
    c.p.stdin.close()
    c.p.wait(timeout=20)

    init = replies[0].get("result", {})
    for key in ("serverInfo", "instructions"):
        if init.get(key) != lock.get(key):
            wins.append(f"I1: initialize `{key}` differs from mcp.lock")
    for rid, key in ((1, "tools"), (2, "prompts"), (3, "resources"), (4, "resourceTemplates")):
        if "result" in replies[rid] and replies[rid]["result"].get(key) != lock.get(key):
            wins.append(f"I1: `{key}` served to the client differ from mcp.lock")
    for rid in (6, 7, 8, 9):
        if "result" in replies[rid]:
            wins.append(f"I2: step {rid} ({steps[rid][0]}) was forwarded instead of refused")
    if "result" in replies[len(steps) - 1]:
        wins.append("I6: the sink ran after a source although the user declined")
    msgs = [parse(x) for x in c.lines]
    if None in msgs:
        wins.append("I7: a line that is not a JSON object reached the client")
    ids = [m.get("id") for m in msgs if m is not None and "method" not in m]
    if len(ids) != len(set(ids)) or any(i not in replies for i in ids):
        wins.append("I7: a response with a duplicate or unknown id reached the client")
    if canary in "\n".join(c.lines):
        wins.append("I2/I6/env: the canary reached the client, so the server got it")

    ok = mcpsum("audit-verify", str(AUDIT))
    shutil.copy(AUDIT, WORK / "audit.orig.jsonl")
    (WORK / "anchor.txt").write_text(ok.stdout.strip().split()[-1], encoding="utf-8")
    print(f"approval prompts declined: {approvals}; audit-verify: {ok.stdout.strip()}")
    for w in wins:
        print("POSSIBLE BYPASS:", w)
    print("no bypass detected" if not wins else "report it privately: see SECURITY.md")
    return 1 if wins else 0


def check_audit() -> int:
    anchor = (WORK / "anchor.txt").read_text(encoding="utf-8").strip()
    r = mcpsum("audit-verify", str(AUDIT))
    head = r.stdout.strip().split()[-1] if r.returncode == 0 else None

    def entries(p: pathlib.Path) -> list:
        return [parse(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]

    changed = entries(AUDIT) != entries(WORK / "audit.orig.jsonl")
    print(f"audit-verify: {r.stdout.strip()} | anchored head: {anchor} | entries changed: {changed}")
    if r.returncode == 0 and head == anchor and changed:
        print("POSSIBLE BYPASS: I8: an edited log verifies with the anchored head. Report it privately.")
        return 1
    print("no bypass detected")
    return 0


if __name__ == "__main__":
    commands = {"setup": setup, "play": play, "check-audit": check_audit}
    if len(sys.argv) != 2 or sys.argv[1] not in commands:
        sys.exit(f"usage: uv run challenge/challenge.py {{{'|'.join(commands)}}}")
    sys.exit(commands[sys.argv[1]]())
