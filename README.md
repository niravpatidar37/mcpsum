<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/brand/logo-dark.svg">
    <img alt="mcpsum" src="assets/brand/logo.svg" width="320">
  </picture>
</p>

<p align="center">
  <b>Stop MCP servers from rug-pulling your AI agent.</b><br>
  A lockfile + runtime reference monitor for MCP tools.
</p>

> **Status: pre-release, under active development. Do not rely on it yet.**

mcpsum is a reference monitor for the [Model Context Protocol](https://modelcontextprotocol.io).
It sits between an MCP client (Claude Code, Cursor, VS Code, ...) and an MCP server and:

- **serves tool definitions from a human-reviewed lockfile** (`mcp.lock`), so text a server
  writes after approval never reaches the model;
- **validates every call against the locked schema**, rejecting unapproved tools and hidden arguments;
- **denies server-initiated requests by default** (sampling, elicitation, roots);
- **fails closed** on drift, malformed or spoofed messages;
- **records every decision** in a hash-chained audit log.

Full documentation, guarantees and limitations will land with the first release.

## License

Apache-2.0. See [LICENSE](LICENSE). Brand assets and usage: [assets/brand](assets/brand/README.md).
