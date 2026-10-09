# Demo recording

`demo.gif` is a real session (Linux), recorded with [asciinema](https://asciinema.org) 2.4.0,
rendered with [agg](https://github.com/asciinema/agg) 1.9.0 and framed with `frame.py` (Pillow).
The server is the adversarial test server, `e2e/servers/evil_server.py`, in `rugpull` mode;
`client.py` talks to `mcpsum proxy` the way an MCP client does. `demo.sh` sends stderr to
`/dev/null`, so neither the server's stderr nor mcpsum's own decision lines appear; the
refusal you see is the JSON-RPC error the client receives.
`demo.sh` prints only the amber comments and the prompt; every command and all of its output
are the tools' own.

The GIF was recorded with v0.1.1. Since then the refusal reads
`definition drift: tool "add" changed` instead of `Changed { kind: Tool, key: "add" }`;
everything else in the session is unchanged.

To re-record, copy `e2e/servers/evil_server.py` to `server.py` next to `demo.sh` and
`client.py`, put an `mcpsum` binary on `PATH`, then:

```sh
asciinema rec --cols 100 --rows 31 -c "bash demo.sh" demo.cast
agg --theme 0b0f14,f2f0ea,0b0f14,f47067,3fb950,f0b429,58a6ff,bc8cff,39c5cf,c9d1d9,484f58,ff7b72,56d364,f5c451,79c0ff,d2a8ff,56d4dd,f2f0ea \
    --font-size 20 --idle-time-limit 6.5 --last-frame-duration 5 demo.cast raw.gif
python3 frame.py raw.gif demo.gif "mcpsum  —  real session"
```

The theme is the brand palette (Ink `0b0f14` background, Snow `f2f0ea` text, Amber `f0b429`
for comments) with GitHub-dark ANSI colours; the window chrome is 28 px padding, a 48 px title
bar and 20 px rounded corners, transparent outside so the card sits on light and dark pages.
