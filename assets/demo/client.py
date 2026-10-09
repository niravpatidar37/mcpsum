"""The scripted MCP client in the README demo (not an agent).

It starts `mcpsum proxy --name weather` (lockfile ./mcp.lock, audit log at the
default .mcpsum-audit/weather.jsonl) and talks to it over stdio the way an MCP
client does: initialize, list tools, call `add`. It prints the description the
model would be shown and what happened to the call.

Usage (see demo.sh): python3 client.py [server name]
"""

from __future__ import annotations

import json
import subprocess
import sys

RED, RESET = "\x1b[1;31m", "\x1b[0m"


def printable(s: str) -> str:
    """Escape control characters so text from the wire can't drive the terminal."""
    return "".join(c if c.isprintable() else f"<U+{ord(c):04X}>" for c in s)


def main() -> int:
    name = sys.argv[1] if len(sys.argv) > 1 else "weather"
    # Fixed argv, no shell: starts the mcpsum binary on PATH.
    p = subprocess.Popen(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        ["mcpsum", "proxy", "--name", name],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=False,
    )
    assert p.stdin is not None and p.stdout is not None
    stdin, stdout = p.stdin, p.stdout

    def send(msg: dict) -> None:
        stdin.write((json.dumps(msg) + "\n").encode())
        stdin.flush()

    def request(rid: int, method: str, params: dict) -> dict:
        send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
        for raw in stdout:
            msg = json.loads(raw)
            if msg.get("id") == rid and "method" not in msg:
                return msg
        sys.exit("mcpsum exited")

    request(0, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                              "clientInfo": {"name": "demo-client", "version": "1"}})
    send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    for t in request(1, "tools/list", {})["result"]["tools"]:
        if t["name"] == "add":
            print(f"model sees  add: {json.dumps(t['description'])}   (served from mcp.lock)")

    r = request(2, "tools/call", {"name": "add", "arguments": {"a": 1, "b": 2}})
    if "error" in r:
        err = r["error"]
        print(f"call add -> {RED}refused{RESET} ({err['code']}): {printable(str(err['message']))}")
    else:
        print(f"call add -> {printable(str(r['result']['content'][0]['text']))}")

    stdin.close()
    p.wait(timeout=10)
    return 0


if __name__ == "__main__":
    sys.exit(main())
