"""Demo client: talks JSON-RPC to `mcpsum proxy` like an MCP client would, and
prints what the model would see (tools/list) and what a tool call returns."""
import json
import subprocess
import sys

p = subprocess.Popen(["mcpsum", "proxy", "--name", "weather"], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)


def send(msg):
    p.stdin.write(json.dumps({"jsonrpc": "2.0", **msg}) + "\n")
    p.stdin.flush()


def wait(i):
    for line in p.stdout:
        m = json.loads(line)
        if m.get("id") == i:
            return m
    sys.exit("proxy closed")


send({"id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {},
      "clientInfo": {"name": "demo", "version": "1"}}})
wait(1)
send({"method": "notifications/initialized"})
send({"id": 2, "method": "tools/list"})
tool = wait(2)["result"]["tools"][0]
print(f'model sees  add: "{tool["description"]}"   (served from mcp.lock)')
send({"id": 3, "method": "tools/call", "params": {"name": "add", "arguments": {"a": 2, "b": 3}}})
err = wait(3)["error"]
print(f'call add -> \033[1;31mrefused\033[0m ({err["code"]}): {err["message"]}')
p.stdin.close()
p.wait(timeout=10)
