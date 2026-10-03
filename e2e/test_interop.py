"""Interop: official MCP reference servers, driven through `mcpsum proxy` by the
official MCP Python SDK client.

These prove the monitor is transparent for honest traffic between real,
independently written implementations, while its guarantees still hold:
- tools/list through the proxy equals the reviewed lockfile
- valid calls work end to end; hidden extra arguments are rejected
- a real server's `get-env` tool cannot see secrets that were not passed through

Network required (uvx / npx fetch pinned versions). Marked `interop`.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import MCPError

from harness import BIN, run

pytestmark = pytest.mark.interop

TIME = ["uvx", "mcp-server-time==2026.8.18"]
EVERYTHING = ["npx", "-y", "@modelcontextprotocol/server-everything@2026.8.31"]


def lock(tmp, name, cmd, env=None):
    lockp = tmp / "mcp.lock"
    r = run("lock", "--lock", str(lockp), "--name", name, "--", *cmd, timeout=300, env=env)
    assert r.returncode == 0, r.stdout + r.stderr
    return lockp


async def with_session(lockp, name, fn, env=None):
    params = StdioServerParameters(
        command=BIN,
        args=["proxy", "--lock", str(lockp), "--name", name, "--audit", str(lockp.parent / f"{name}.jsonl")],
        env=env,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await fn(session)


def locked_tool_names(lockp, name):
    lf = json.loads(lockp.read_text(encoding="utf-8"))
    return sorted(t["name"] for t in lf["servers"][name]["tools"])


@pytest.mark.skipif(not shutil.which("uvx"), reason="uvx not available")
def test_official_sdk_through_proxy_to_official_time_server(tmp_path):
    lockp = lock(tmp_path, "time", TIME)

    async def go(s: ClientSession):
        listed = await s.list_tools()
        assert sorted(t.name for t in listed.tools) == locked_tool_names(lockp, "time")
        ok = await s.call_tool("get_current_time", {"timezone": "UTC"})
        assert not ok.is_error
        assert "UTC" in ok.content[0].text
        with pytest.raises(MCPError):
            await s.call_tool("get_current_time", {"timezone": "UTC", "sidenote": "exfil"})
        with pytest.raises(MCPError):
            await s.call_tool("not_a_tool", {})

    asyncio.run(with_session(lockp, "time", go))


@pytest.mark.skipif(not shutil.which("npx"), reason="npx not available")
def test_official_everything_server_cannot_read_unlisted_secrets(tmp_path):
    secret = "mcpsum-interop-s3cr3t-7d1f"
    env = {**os.environ, "MCPSUM_INTEROP_SECRET": secret}
    lockp = lock(tmp_path, "everything", EVERYTHING, env=env)

    async def go(s: ClientSession):
        listed = await s.list_tools()
        assert sorted(t.name for t in listed.tools) == locked_tool_names(lockp, "everything")
        echoed = await s.call_tool("echo", {"message": "hello through mcpsum"})
        assert "hello through mcpsum" in echoed.content[0].text
        dump = await s.call_tool("get-env", {})
        text = " ".join(getattr(c, "text", "") for c in dump.content)
        assert "PATH" in text.upper(), "get-env should work and show the allow-listed variables"
        assert secret not in text and "MCPSUM_INTEROP_SECRET" not in text

    asyncio.run(with_session(lockp, "everything", go, env=env))
