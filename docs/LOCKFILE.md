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
| `policy` | Optional, written by **you** (never by the server): taint labels ([I6](#policy-optional-i6)) and a sandbox ([I5](#sandbox-optional-i5)). Not covered by `digests`, and kept when the server is re-locked. |
| `digests` | SHA-256 over the RFC 8785 canonical JSON of each item, plus one over the whole surface. mcpsum recomputes them on load and refuses a lockfile that does not match. |

## Policy (optional, I6)

Add a `policy` section to a server entry to turn on taint tracking for it:

```json
"policy": {
  "taint": {
    "sources": ["fetch", "resources:*"],
    "sinks": ["fetch", "send_email"]
  }
}
```

| Key | Meaning |
|---|---|
| `taint.sources` | Tools whose **results** may contain text an attacker controls: web pages, emails, issues, documents. `resources:*` means every `resources/read`; `prompts:*` means every `prompts/get`. |
| `taint.sinks` | Tools whose **calls** have consequences or can carry data out: send, write, delete, create, pay. A tool that fetches a URL is both, because the URL itself can carry data out. |

After a source's result reaches the client, every call to a sink needs your
approval through mcpsum's prompt, or is refused if your client cannot show one.
This holds across every server of the same client session. See
[I6](GUARANTEES.md#i6--untrusted-results-cannot-silently-trigger-sinks-opt-in).

To get a starting point, run `mcpsum suggest-policy --name <server>`. It
labels tools from the server's own annotations, conservatively (a missing hint
counts as "may reach the outside world" and "may write"), and prints JSON for
you to review and paste. It never edits the lockfile.

After you have reviewed what a session read, clear it with
`mcpsum taint list` and `mcpsum taint reset <session>` (or `--all`), from a
terminal.

Rules:

- Every name must be a locked tool (or one of the two wildcards). A misspelled
  name is an error, so a typo cannot silently leave a tool unprotected. Unknown
  keys are errors too.
- Tool annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`) are
  hints written by the server. Use them to help you decide, but mcpsum never
  applies them on its own.
- When you re-lock a server, its policy is kept. Labels for tools that no
  longer exist are dropped and `lock` prints them. A renamed tool is **not**
  protected until you label it again.

## Sandbox (optional, I5)

Add `policy.sandbox` to a server entry to run it under an OS sandbox (Linux):

```json
"policy": {
  "sandbox": {
    "filesystem": { "read": ["~/notes"], "write": ["${TMP}/work"] },
    "network": { "allow": [] }
  }
}
```

| Key | Meaning |
|---|---|
| `filesystem.read` | Extra paths the server may read (recursively), beyond the runtime base. |
| `filesystem.write` | Paths it may read and write. Its private temporary directory (`${TMP}`, also in `TMPDIR`) is always writable. |
| `network.allow` | `[]`: no network at all. Or `host:port` entries (`"api.github.com:443"`, `"*.example.com:443"`, `"10.0.0.5:8080"`, `"[::1]:9000"`): the server reaches only these, over HTTPS through mcpsum's audited egress proxy (Linux, own network namespace). A name that resolves to a loopback, private or link-local address is refused unless that IP is listed too. |

Paths are absolute, `~/...` or `${TMP}/...`, without `..`, and must exist.
A write path that would cover `mcp.lock`, its directory, the audit log, the
taint state, the mcpsum binary or your home directory is refused. On macOS and
Windows a server with a sandbox policy does not start. See
[I5](GUARANTEES.md#i5--the-server-process-is-sandboxed-opt-in-linux)
(including the one-time AppArmor step on Ubuntu ≥ 23.10 for `network.allow`).

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
