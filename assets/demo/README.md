# Demo recording

`demo.gif` is a real session (Linux, mcpsum built from `main`), recorded with
[asciinema](https://asciinema.org) 2.4.0 and converted with [agg](https://github.com/asciinema/agg) 1.9.0.
The server is the adversarial test server, `e2e/servers/evil_server.py`, in `rugpull` mode;
`client.py` talks to `mcpsum proxy` the way an MCP client does. Server stderr is hidden.

To re-record, from a directory holding `server.py` (a copy of the test server), `client.py`
and an `mcpsum` binary on `PATH`:

```sh
asciinema rec --cols 104 --rows 27 -c "bash demo.sh" demo.cast
agg --font-size 15 --theme monokai --idle-time-limit 7 --last-frame-duration 4 demo.cast demo.gif
```
