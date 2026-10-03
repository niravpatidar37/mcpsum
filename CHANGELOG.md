# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (pre-1.0: minor versions may break).

## [Unreleased]

### Security
- Kill the whole server process tree, not just the direct child: process groups on Unix,
  Job Objects on Windows (assigned before the server can start anything). Grandchildren
  left by launchers like `npx`/`uvx` no longer outlive mcpsum (#7).

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
