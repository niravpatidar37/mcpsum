# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may break).

## [Unreleased]

### Security
- I2: tool arguments are now checked against the locked `inputSchema` as written as
  well as its strict form. Before, only the strict rewrite was checked, and it could
  drop locked rules (`not`, `if`/`then`, `contains` with `maxContains`), so arguments
  the lock forbids reached the server. Undeclared properties are now also refused in
  nested objects typed `["object", "null"]` and in object schemas under
  `additionalProperties`/`unevaluatedProperties`. Affects 0.2.0 and earlier
  (GHSA-h84p-xpp4-jghw).

### Added
- `lock` and `verify` for servers that speak only MCP 2026-07-28 (#21). `lock` now
  detects a server's era the way the spec asks a dual-era client to on stdio:
  `server/discover` first, `initialize` after any other error or no answer, never after a
  2026-07-28 error (`-32021`, `-32022`). A 2026-07-28 entry records `supportedVersions`
  and needs `lockfileVersion: 2`; files without one stay at version 1, so older mcpsum
  still reads them, and versions other than 1 and 2 are refused. `verify` and a re-lock
  ask an existing entry in its own era first; a change of era is definitional drift.
- The proxy in front of servers that speak only MCP 2026-07-28 (#21). It never sends
  them `initialize`: it answers a legacy client's `initialize` from the lock, opens the
  server with its own `server/discover` (locked version in `_meta`, no client
  capabilities, mcpsum's `clientInfo`) and verifies the live version list, instructions
  and definitions before any call; drift quarantines. Every forwarded request carries
  only mcpsum's `_meta`, and multi round-trip input requests stay refused (`-32001`).

### Changed
- A fresh `lock` of a server that speaks both eras now records it as 2026-07-28.
  Existing entries keep their era.

### Fixed
- I8: client messages the proxy rejects before any routing (a `jsonrpc` other than
  `"2.0"`, an invalid id, neither `method` nor `id`, `initialize` without
  `protocolVersion`, a second `initialize`) are now audited. They got an error but no
  audit event. The reasons are fixed strings; no client value is logged.

## [0.2.0] - 2026-10-13

### Added
- Reproducible release binaries (#22). `scripts/release-build.sh` (used by the release
  workflow) remaps build paths and links with `/Brepro` (Windows) or `-S` (macOS); a new
  `reproducible` workflow builds each of the 5 release targets twice in different directories
  and homes and fails if the SHA-256 differs. `docs/RELEASING.md` shows how to rebuild a release and compare.
- 2026-07-28 clients (#21). A request with `io.modelcontextprotocol/protocolVersion`
  in `_meta` and no `initialize` starts a modern session: `server/discover` and the list
  methods are answered from `mcp.lock` (with `resultType`, `ttlMs: 0`,
  `cacheScope: "private"` and the locked `serverInfo`), and mcpsum opens a legacy session
  to the server itself, with no client capabilities, verifying it before any call. Other
  revisions get `-32022`. A result with `resultType` other than `complete` (a multi
  round-trip input request) is refused with `-32001` in every session. Servers that speak
  only 2026-07-28 are not supported yet.
- I5 network allowlist, Linux (#14, design 0002). `policy.sandbox.network.allow` with
  `host:port` entries now runs the server in its own user and network namespace whose
  only way out is mcpsum's egress proxy (`HTTPS_PROXY` and friends point at it). The proxy
  allows only `CONNECT` to listed destinations, resolves names itself once and refuses
  loopback, private and metadata addresses unless that IP is listed, bounds request size,
  time and connections, and audits every connection (`host:port` and the decision only)
  before opening it. seccomp still refuses UDP, DNS, raw sockets and IPv6. If the namespace
  cannot be set up the server does not start; on Ubuntu >= 23.10 the error prints a
  one-time AppArmor profile for mcpsum. TLS is not inspected.
- I5 sandbox, opt-in, Linux (#14, design 0002). A `policy.sandbox` section in `mcp.lock`
  runs the server under Landlock (deny-by-default files: a runtime base, its own program
  and the listed paths; home directory not readable; mcpsum's files never writable) and
  seccomp (no network sockets, no `io_uring`, no namespaces, mounts, `bpf`, keyrings or
  `ptrace`). A policy that cannot be enforced, or that would expose mcpsum's files, stops
  the server from starting; macOS and Windows refuse sandboxed servers for now. The
  per-host network allowlist is described above.
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
- README demo recording (`assets/demo/demo.gif`): a real asciinema session against the
  adversarial test server (lock, rug pull, `DRIFT`, refused call, audit log). The cast, the
  script, the client and the framing script are in `assets/demo/` to re-record it.

### Changed
- Proxy stderr is easier to read. Deny and quarantine lines now look like
  `mcpsum[calc]: Quarantine: definition drift: tool "add" changed` instead of Rust debug
  output. The method, tool name and reason are still escaped, so a server cannot write
  terminal escape sequences or bidi overrides to your terminal. The audit log format is unchanged.

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
