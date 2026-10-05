"""Shared helpers: build/locate the mcpsum binary and drive it over raw JSON-RPC."""

from __future__ import annotations

import json
import os
import pathlib
import queue
import subprocess
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXE = "mcpsum.exe" if os.name == "nt" else "mcpsum"
BIN = os.environ.get("MCPSUM_BIN") or str(ROOT / "target" / "debug" / EXE)
EVIL = str(ROOT / "e2e" / "servers" / "evil_server.py")

QUARANTINED = -32002
INVALID_PARAMS = -32602
METHOD_NOT_FOUND = -32601


def run(*args: str, timeout: int = 120, env: dict | None = None) -> subprocess.CompletedProcess:
    full_env = dict(os.environ)
    full_env.update(env or {})
    # Test harness: runs the mcpsum binary under test (BIN is set by our own CI)
    # with list-form argv and no shell, so nothing is shell-interpreted.
    return subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit, python.lang.security.audit.dangerous-subprocess-use-tainted-env-args
        [BIN, *args], capture_output=True, text=True, encoding="utf-8", timeout=timeout, env=full_env, shell=False
    )


def lock_evil(tmp: pathlib.Path, mode: str, *, poison_file: pathlib.Path | None = None,
              env_pass: tuple[str, ...] = (), extra: tuple[str, ...] = (), expect_rc: int = 0,
              env: dict | None = None) -> pathlib.Path:
    lockp = tmp / "mcp.lock"
    args = ["lock", "--lock", str(lockp), "--name", "evil", *extra]
    for e in env_pass:
        args += ["--env", e]
    args += ["--", sys.executable, EVIL, "--mode", mode]
    if poison_file is not None:
        args += ["--poison-file", str(poison_file)]
    r = run(*args, env=env)
    assert r.returncode == expect_rc, f"rc={r.returncode}\nstdout={r.stdout}\nstderr={r.stderr}"
    lock_evil.last = r  # type: ignore[attr-defined]
    return lockp


class Client:
    """A raw MCP client that talks to `mcpsum proxy` and records everything it receives."""

    def __init__(self, lockp: pathlib.Path, name: str = "evil", env: dict | None = None):
        full_env = dict(os.environ)
        full_env.update(env or {})
        self.audit = lockp.parent / "audit.jsonl"
        # Same justification as run(): binary under test, list-form argv, no shell.
        self.p = subprocess.Popen(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit, python.lang.security.audit.dangerous-subprocess-use-tainted-env-args
            [BIN, "proxy", "--lock", str(lockp), "--name", name, "--audit", str(self.audit)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=full_env, shell=False,
        )
        self.q: queue.Queue = queue.Queue()
        self.received: list[dict] = []
        self.unsolicited: list[dict] = []
        self.stderr_lines: list[str] = []
        threading.Thread(target=self._read_out, daemon=True).start()
        threading.Thread(target=self._read_err, daemon=True).start()

    def _read_out(self) -> None:
        for raw in self.p.stdout:  # type: ignore[union-attr]
            line = raw.decode("utf-8", "replace").strip()
            if line:
                msg = json.loads(line)
                self.received.append(msg)
                self.q.put(msg)

    def _read_err(self) -> None:
        for raw in self.p.stderr:  # type: ignore[union-attr]
            self.stderr_lines.append(raw.decode("utf-8", "replace").rstrip())

    @property
    def stderr(self) -> str:
        return "\n".join(self.stderr_lines)

    def send(self, msg: dict) -> None:
        self.p.stdin.write((json.dumps(msg) + "\n").encode())  # type: ignore[union-attr]
        self.p.stdin.flush()  # type: ignore[union-attr]

    def request(self, rid, method: str, params: dict | None = None, timeout: float = 20) -> dict:
        msg = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        self.send(msg)
        while True:
            got = self.q.get(timeout=timeout)
            if got.get("id") == rid and "method" not in got:
                return got
            self.unsolicited.append(got)

    def initialize(self, capabilities: dict | None = None) -> dict:
        if capabilities is None:
            capabilities = {"sampling": {}, "elicitation": {}, "roots": {"listChanged": True}}
        r = self.request(0, "initialize", {
            "protocolVersion": "2025-06-18",
            "capabilities": capabilities,
            "clientInfo": {"name": "e2e", "version": "1"},
        })
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return r

    def call(self, rid, name: str, args: dict) -> dict:
        return self.request(rid, "tools/call", {"name": name, "arguments": args})

    def next_request(self, method: str, timeout: float = 20) -> dict:
        """Wait for a request *to the client* (only mcpsum's own approval prompts)."""
        deadline = time.monotonic() + timeout
        for i, m in enumerate(self.unsolicited):
            if m.get("method") == method and "id" in m:
                return self.unsolicited.pop(i)
        while True:
            got = self.q.get(timeout=max(0.01, deadline - time.monotonic()))
            if got.get("method") == method and "id" in got:
                return got
            self.unsolicited.append(got)

    def wait_response(self, rid, timeout: float = 20) -> dict:
        deadline = time.monotonic() + timeout
        for i, m in enumerate(self.unsolicited):
            if m.get("id") == rid and "method" not in m:
                return self.unsolicited.pop(i)
        while True:
            got = self.q.get(timeout=max(0.01, deadline - time.monotonic()))
            if got.get("id") == rid and "method" not in got:
                return got
            self.unsolicited.append(got)

    def everything_received(self) -> str:
        return json.dumps(self.received, ensure_ascii=False)

    def close(self) -> None:
        try:
            self.p.stdin.close()  # type: ignore[union-attr]
        except OSError:
            pass
        try:
            self.p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.p.kill()
