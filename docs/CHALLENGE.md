# Bypass challenge

- **Status:** draft rules (issue #18). Not launched or announced; the owner
  decides when.
- **Target:** [`challenge/`](../challenge/README.md), a runnable setup for your
  own machine.

mcpsum makes specific, testable claims ([GUARANTEES.md](GUARANTEES.md)). This
challenge asks you to break them. You control a malicious MCP server; mcpsum
sits between it and a scripted client, enforcing a published lockfile and
policy. A valid bypass becomes a regression test and a credited advisory.

## Win conditions

Each one is a bypass of a guarantee as it is stated today. The target script
detects the ones marked **(auto)** and prints `POSSIBLE BYPASS`. Maintainers
confirm every claim by hand.

| Guarantee | You win if |
|---|---|
| **I1** definitions from the lock | Definition text you wrote after locking (tools, prompts, resources, templates, `instructions`, `serverInfo`) reaches the client **(auto)**, or a changed definition is served or used without the server being quarantined. |
| **I2** strict locked schemas | A call for an unlocked tool, prompt or resource, or with an argument the locked schema does not declare, reaches your server. Proof: the per-run canary that the client puts only in those calls comes back **(auto)**. |
| **I3** deny by default | A request from your server (`sampling/createMessage`, `elicitation/create`, `roots/list`, anything else) or a notification other than progress for a client token reaches the client **(auto)**; or your server learns that the client supports sampling, elicitation or roots. |
| **I5** sandbox (Linux, `policy.sandbox`) | A sandboxed server reads a canary file outside its grant (for example under `$HOME`), writes `mcp.lock`, the audit log or the taint state, or opens any network connection. The target script does not set up I5 yet; use the e2e test `test_I5_sandboxed_server_cannot_read_secrets_touch_mcpsum_files_or_reach_the_network` as the reference setup. |
| **I6** taint | After `fetch` (a source) has returned, `add` (a sink) runs without an explicit allow for exactly that call **(auto, the client declines)**; or the session's taint is cleared by anything other than the user's `mcpsum taint reset`. |
| **I7** fail closed | Something mcpsum must drop reaches the client: a non-JSON line, a batch, an oversize line, or a spoofed or duplicate response **(auto)**; or a call is forwarded before `initialize` completes. |
| **I8** audit log | You change, insert or delete an entry and `mcpsum audit-verify` still reports `ok` **with the head hash anchored after the session** (`check-audit`, **auto**). |
| Environment scrub | `SUPER_SECRET`, set in mcpsum's environment but not passed with `--env`, reaches the client through your server **(auto)**. Reading it from another process's memory or `/proc/<pid>/environ` doesn't count without a sandbox (see out of scope). |

I4 (credential broker) is not shipped and is out of scope until it is.

Crashes and hangs of the proxy are bugs and are welcome as reports. They count
as bypasses only if something gets through.

## Out of scope

- The documented limits in [GUARANTEES.md § Limits](GUARANTEES.md#limits):
  a definition that was poisoned when it was locked, prompt injection in
  results without a taint policy, a server not behind mcpsum, and anything an
  **unsandboxed** server does with your user's permissions (reading files or
  other processes, deleting the taint marker, editing files).
- Rewriting the whole audit log, or truncating it, without the anchored head.
  The log is tamper-evident, not tamper-proof.
- Denial of service by volume, social engineering of users or maintainers,
  Linux kernel 0-days, and bugs in MCP clients, models or third-party servers.
- Attacks that need write access to `mcp.lock`, the mcpsum binary or the policy
  (attacker A3 in the [threat model](THREAT-MODEL.md)).
- Anything against systems other than your own: the project's GitHub
  infrastructure, other users, or public MCP servers.

## Rules and safe harbor

- Test only on machines you own or are allowed to test, with the fake canary
  the script generates. Never use real secrets.
- Report privately first: see [SECURITY.md](../SECURITY.md) (GitHub private
  vulnerability reporting). Do not open a public issue or publish details
  until a fix is released or the maintainers agree.
- Research done in good faith under these rules is welcome, and the project
  will not treat it as a violation. *Owner to confirm the safe-harbor wording
  and the default disclosure window before launch.*

## How to submit

Through GitHub private vulnerability reporting, with:

1. the guarantee you bypassed and the win condition you met;
2. your `server.py` (or a diff against the copy `setup` made), and any other
   input you used;
3. the full output of `challenge.py play` or `check-audit`;
4. `mcpsum --version`, your OS and how you built mcpsum.

## What happens next

Each confirmed bypass gets a regression test in the adversarial suite, a fix, a
GitHub security advisory and credit (unless you prefer otherwise), as in
[SECURITY.md](../SECURITY.md). Rules may be clarified over time; a bypass is
judged by the rules in force when it was reported.

*Owner to decide: rewards.* There are no cash prizes or other rewards unless
the owner adds them here.

## Hall of fame

| Who | Guarantee | Advisory |
|---|---|---|
| *(none yet)* | | |
