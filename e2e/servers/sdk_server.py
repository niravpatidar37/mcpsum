"""An honest server on the official MCP Python SDK (2.3.0, pinned in uv.lock),
which speaks the 2026-07-28 revision. Used by test_interop.py."""

from mcp.server.mcpserver import MCPServer

app = MCPServer("sdk-demo", instructions="Arithmetic helper.")


@app.tool()
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b


if __name__ == "__main__":
    app.run("stdio")
