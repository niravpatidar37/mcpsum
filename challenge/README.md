# Bypass challenge target

A local setup for the [bypass challenge](../docs/CHALLENGE.md). The rules,
win conditions and how to report are there; this page covers running it.

## What it sets up

- **The server you control:** `.work/server.py`, a copy of the repository's
  adversarial test server ([`e2e/servers/evil_server.py`](../e2e/servers/evil_server.py))
  in `taint` mode, with the tools `add`, `echo_env` and `fetch`.
- **The lockfile:** `.work/mcp.lock`, written by `mcpsum lock` against that
  server, with the taint policy `sources: [fetch]`, `sinks: [add]`. It is
  generated rather than committed because it holds absolute paths.
- **The client:** `challenge.py play`, a scripted MCP client. It advertises
  sampling, elicitation and roots, sends calls carrying a canary that mcpsum
  must refuse, reads `fetch`, then calls `add` and **declines** mcpsum's
  approval prompt. It records every line it receives and reports anything
  that should not have arrived.
- **The canary:** `mcpsum-canary-` plus 32 random hex characters, new on every
  run, also set as `SUPER_SECRET` in mcpsum's environment (it is not passed to
  the server). It is not a secret; never put real secrets in this setup.

## Run it

You need [uv](https://docs.astral.sh/uv/) and an `mcpsum` binary built from
this repository (`cargo build --locked`). The latest release, v0.1.1, predates
the taint policy (I6) that the target uses. From the repository root:

```sh
export MCPSUM_BIN=/path/to/mcpsum   # or put mcpsum on PATH
uv run challenge/challenge.py setup
uv run challenge/challenge.py play
```

With the unmodified server, `play` prints `no bypass detected`. Now edit
`.work/server.py`: it is your malicious server, and mcpsum will keep running
it under the locked command. Run `play` again after each change. `setup`
starts over (it deletes `.work/`).

For I8, run `play`, then edit `.work/audit.jsonl` and run:

```sh
uv run challenge/challenge.py check-audit
```

`play` exits 1 and prints `POSSIBLE BYPASS: ...` when one of its checks fires.
Check that it is real, then report it privately as described in
[SECURITY.md](../SECURITY.md). Don't post it publicly.

## Limits of this target

- Tested on Windows 11. It uses only the standard library and should run
  anywhere uv and mcpsum do.
- It does not set up the I5 sandbox (Linux) or test against real MCP clients.
  A bypass that needs a real client, or another scenario, is still in scope
  if it meets a win condition in the rules.
- Automatic checks are a convenience. A maintainer judges every report.
