# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may break).

## [Unreleased]

### Added
- I5 sandbox, opt-in, Linux (#14, design 0002). A `policy.sandbox` section in `mcp.lock`
  runs the server under Landlock (deny-by-default files: a runtime base, its own program
  and the listed paths; home directory not readable; mcpsum's files never writable) and
  seccomp (no network sockets, no `io_uring`, no namespaces, mounts, `bpf`, keyrings or
  `ptrace`). A policy that cannot be enforced, or that would expose mcpsum's files, stops
  the server from starting; macOS and Windows refuse sandboxed servers for now. Network
  allowlists by host come next.
- I6 taint tracking, opt-in and per server (preview, #16). A user-written `policy.taint`
  section in `mcp.lock` labels tools as sources and sinks. After a source's result (or
  error, or progress message) reaches the client, a sink call is held for the user's
  approval through mcpsum's own `elicitation/create` prompt and forwarded only on an
  explicit allow, or refused with `-32001` when the client cannot show prompts. Policies
  naming unlocked tools are rejected, and `lock` keeps the policy on re-lock. Design:
  `docs/design/0001-taint-tracking.md`.
- I6 taint is shared by every server of one client session (#16). The session is the MCP
  client process (or `--session` / `MCPSUM_SESSION`); its marker is written before the
  untrusted text is delivered, in a per-user directory, and an unreadable marker counts as
  tainted. Verified with Claude Code 2.1.284: content fetched by one server gated a call on
  another.
- `mcpsum taint list` and `mcpsum taint reset` (needs a person at a terminal).
- `mcpsum suggest-policy`: proposes labels from the server's own annotations, for review.
- `mcpsum show` prints a server's taint policy.
- Draft rules for a bypass challenge (`docs/CHALLENGE.md`, #18) and a local target
  (`challenge/`) that locks the adversarial test server and reports any message that
  should not have reached the client. Not launched yet.

## [0.1.1] - 2026-10-03

Security fixes found by testing v0.1.0 in real clients. Upgrading is recommended.

### Security
- Kill the whole server process tree, not just the direct child: process groups on Unix,
  Job Objects on Windows (assigned before the server can start anything). Grandchildren
  left by launchers like `npx`/`uvx` no longer outlive mcpsum (#7).
- Audit log stays one valid chain when several proxies for the same server run at once
  (VS Code runs servers in two processes). Appends take a cross-process lock, re-read the
  chain head and check its hash first; previously concurrent writes forked the chain and
  could even interleave half-lines (#29).

## [0.1.0] - 2026-10-03

First release. stdio transport only; see the limits in the README.

### Added
- Reference monitor (`src/monitor.rs`) enforcing I1 (definitions served from the
  lock), I2 (strict locked schemas), I3 (deny by default, both directions),
  I7 (fail closed) and I8 (audit events).
- `mcp.lock` format v1 with RFC 8785 canonical JSON and SHA-256 digests.
- CLI: `lock`, `verify` (`--strict`), `proxy`, `show`, `audit-verify`.
- Hash-chained audit log; argument values are recorded as digests only.
- Scrubbed server environment with explicit `--env NAME` passthrough.
- Escaped rendering of all server text (bidi, zero-width, tag characters, controls).
- Adversarial e2e suite against a malicious MCP server; interop tests with the
  official MCP Python SDK and official reference servers; property tests;
  four cargo-fuzz targets.
- Docs: guarantees, threat model, lockfile format, release verification.
- Release pipeline: 5 platforms, SHA256SUMS, CycloneDX SBOM, build-provenance and SBOM
  attestations (Sigstore), draft-release gate.

### Security
- Withhold server-authored `initialize` error text (I1 gap found by the property test, #4).
- Write audit entries before their effects, and stop if the log cannot be written (#3).
- A server that stops reading its input can no longer hang the proxy (#3).
- ReDoS guard: regexes in locked schemas run on a linear-time engine; backtracking-only
  patterns are refused at compile time, so the tool fails closed (#9).
- Relay server stderr escaped instead of raw, closing a terminal-injection path; drain it
  within a bounded grace period; never skip server shutdown on a fatal proxy error (#6).
