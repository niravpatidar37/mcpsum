# `mcp.lock` format (version 1)

`mcp.lock` is the reviewed, pinned MCP surface of each server. Commit it to
git and review changes to it the way you would review code. mcpsum writes it
with `mcpsum lock`, reads it in `proxy`, `verify` and `show`, and refuses to
use a lockfile whose digests do not match its contents.

## Example (abridged)

```json
{
  "lockfileVersion": 1,
  "generator": "mcpsum 0.1.0",
  "servers": {
    "time": {
      "command": ["uvx", "mcp-server-time==2026.8.18"],
      "envPassthrough": [],
      "protocolVersion": "2025-11-25",
      "serverInfo": { "name": "mcp-time", "version": "1.30.0" },
      "instructions": null,
      "capabilities": { "experimental": {}, "tools": { "listChanged": false } },
      "tools": [
        {
          "name": "get_current_time",
          "description": "Get current time in a specific timezone",
          "inputSchema": { "type": "object", "properties": { "timezone": { "type": "string", "description": "IANA timezone name …" } }, "required": ["timezone"] },
          "annotations": { "readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false }
        },
        { "name": "convert_time", "description": "Convert time between timezones", "…": "…" }
      ],
      "prompts": [],
      "resources": [],
      "resourceTemplates": [],
      "digests": {
        "surface": "sha256:…",
        "instructions": null,
        "tools": { "convert_time": "sha256:…", "get_current_time": "sha256:…" },
        "prompts": {},
        "resources": {},
        "resourceTemplates": {}
      }
    }
  }
}
```

## Fields

| Field | Meaning |
|---|---|
| `lockfileVersion` | Format version. Currently `1`. Unknown versions are rejected. |
| `generator` | The mcpsum version that wrote the file. Informational. |
| `servers.<name>` | One entry per server. `<name>` is what you pass to `--name` and use in your client config. |
| `command` | The exact argv the proxy runs. **The proxy never takes a command from the client config**, so the config and the lock cannot silently diverge. Pin package versions here (`pkg==1.2.3`, `pkg@1.2.3`). |
| `envPassthrough` | **Names** of environment variables passed to the server. Values are never stored. Everything else is withheld. |
| `protocolVersion`, `serverInfo`, `capabilities`, `instructions` | What the server reported at lock time. Served to the client from here. Changes count as *informational* drift, except `instructions`, which is definitional. |
| `tools`, `prompts`, `resources`, `resourceTemplates` | The full definitions as returned by the server (all pages), keyed by `name`, `name`, `uri` and `uriTemplate`. Served to the client from here. Capped at 1,000 items per kind. |
| `digests` | SHA-256 over the RFC 8785 canonical JSON of each item, plus one over the whole surface. mcpsum recomputes them on load and refuses a lockfile that does not match. |

## Drift classes

| Class | What changed | `verify` | `proxy` |
|---|---|---|---|
| Definitional | any tool, prompt, resource or template added, removed or changed; `instructions` | exit 1 | quarantine (`-32002` for every later request) |
| Informational | `serverInfo`, `capabilities`, `protocolVersion` | reported, exit 0 (exit 1 with `--strict`) | allowed; the client still sees the locked values |

## Integrity is not authenticity

The digests detect accidental or partial edits. They do **not** stop someone
who can write the file: they can recompute the digests. Protect `mcp.lock`
the same way you protect the rest of your repository (code review, branch
protection). Signed lockfiles and a public transparency log are on the
roadmap (M5).
