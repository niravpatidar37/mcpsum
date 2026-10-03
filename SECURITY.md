# Security policy

mcpsum is a security tool. Bypasses of its guarantees are the most valuable
bug reports we can receive.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability
reporting: **Security → Report a vulnerability** on this repository.

Include:

- which guarantee you bypassed (I1, I2, I3, I7, I8; see [docs/GUARANTEES.md](docs/GUARANTEES.md)),
- a minimal malicious server or message sequence that reproduces it,
- the mcpsum version (`mcpsum --version`) and OS.

We aim to acknowledge reports within 3 business days. Every confirmed bypass
gets a regression test in the adversarial suite and public credit (unless you
prefer otherwise).

## Scope

In scope: anything that lets server-authored definition text reach the client
after approval, lets a call through for an unapproved tool or argument, forwards
a server-initiated request to the client, makes the proxy fail open, or lets an
audit-log edit go undetected.

Known limitations (not vulnerabilities; see [docs/GUARANTEES.md § Limits](docs/GUARANTEES.md#limits)
and the [threat model](docs/THREAT-MODEL.md)): no sandbox yet, no credential
broker yet, tool *results* are passed through unfiltered, trust-on-first-use
at lock time, and stdio transport only.

## Supported versions

Pre-1.0: only the latest release receives fixes.
