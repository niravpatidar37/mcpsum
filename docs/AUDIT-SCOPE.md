# External security audit: draft scope

- **Status:** draft for discussion (issue #23, milestone M5). Nothing here is
  booked, funded or promised.
- **Date:** 2026-10-08
- **Timing:** after M2 lands (sandbox host allowlist and credential broker), so
  the audit covers the code that users will actually run.

## Why

mcpsum is a security tool whose value rests on its guarantees. Its own tests,
property tests and fuzzing were written by the people who wrote the code. An
independent review is the check those cannot provide. The project has said
from the start that it has not had one yet (README, status note).

## Assets and guarantees

The audit should try to break the guarantees in
[GUARANTEES.md](GUARANTEES.md) under the attackers in
[THREAT-MODEL.md](THREAT-MODEL.md):

| Guarantee | What a finding looks like |
|---|---|
| I1 | Server-written definition text reaches the client after approval |
| I2 | A call to an unlocked tool, or with an undeclared argument, reaches the server |
| I3 | A server request reaches the client; a client capability leaks to the server |
| I4 | (if shipped) a brokered secret reaches the server process |
| I5 | A sandboxed server reads outside its grant, writes mcpsum's files, or reaches the network |
| I6 | A sink runs after a source without an explicit allow for exactly that call |
| I7 | Any input makes the proxy forward, hang or crash instead of failing closed |
| I8 | An edited, inserted or deleted audit entry passes `audit-verify` |

## In scope

| Area | Code | Notes |
|---|---|---|
| Monitor | `src/monitor.rs` | Pure state machine; the core of I1–I3, I6, I7 |
| Proxy shell | `src/proxy.rs`, `src/framing.rs`, `src/process.rs`, `src/filelock.rs` | I/O, id rewriting, write-ahead audit, process-tree kill |
| Lockfile | `src/lock.rs`, `src/canon.rs` | Parsing, RFC 8785 digests, policy validation |
| Audit log | `src/audit.rs` | Hash chain, concurrent writers |
| Taint state | `src/taint.rs` | Session key, marker files, `taint reset` |
| Sandbox | `src/sandbox.rs`, `src/sandbox_linux.rs` | Landlock, seccomp, protected paths, egress proxy (when merged) |
| Rendering | `src/render.rs` | Escaping of all server text (terminal injection) |
| Release pipeline | `.github/workflows/release.yml`, `ci.yml`, `fuzz.yml` | Reproducibility, SBOM, attestations, pinned actions |
| Designs | `docs/design/0001` to `0003` | Is the design sound before the code is judged? |

About 7,100 lines of Rust in `src/` including unit tests (2026-10-08).

## Out of scope

- The limits already documented in [GUARANTEES.md § Limits](GUARANTEES.md#limits)
  (definitions poisoned before approval, prompt injection in results without a
  taint policy, servers not behind mcpsum), unless a finding shows a limit is
  worse than stated.
- MCP clients, models and third-party MCP servers.
- Linux kernel bugs in Landlock or seccomp.
- Volumetric denial of service. Making the proxy *fail open* or hang is in
  scope (I7).
- Streamable HTTP and the transparency log, unless they have shipped by then.

## What the project provides

- A frozen commit and tag, with build and test instructions that run offline.
- The threat model, guarantees, designs and the adversarial e2e server.
- A maintainer available during the engagement, and a private channel for
  findings (GitHub private vulnerability reporting, see [SECURITY.md](../SECURITY.md)).

## Deliverables we would ask for

- A report with each finding's severity, affected guarantee, reproduction and
  suggested fix.
- A retest of the fixes.
- Permission to publish the report in this repository after fixes ship (the
  issue asks for publication).
- Every confirmed finding becomes a regression test and an advisory, as for
  any reported bypass.

## Candidate routes (options, not commitments)

| Route | How it works | Fit for mcpsum |
|---|---|---|
| **OSTIF** | Scopes the audit, selects an audit team, manages it and publishes the report ([get an audit](https://ostif.org/get-an-audit)). It states that "initial audits could range anywhere from $30k to $200k" and that it helps projects find sponsors. | Good process fit. Funding is the open question. |
| **OpenSSF** | [Alpha-Omega](https://openssf.org/alpha-omega/) funds security work in critical open source projects; the OpenSSF TAC has funded community-driven audits. | Unlikely while mcpsum is young and small; worth asking once it has users. |
| **Paid firm, direct** | Contract an independent firm. | Fastest if funded. Cost unknown until scoped. |
| **Academic or community review** | Researchers in agent security review the design and code. | Cheap and useful for design flaws; not a substitute for a full code audit. |

The public bypass challenge (#18) complements an audit; it does not replace it.

## Open questions for the owner

1. Budget: is any funding available, or should we approach OSTIF for sponsors?
2. Timing: wait for I4 (credential broker), or audit once the I5 allowlist ships?
3. Should the release pipeline and supply chain be in the same engagement or a
   separate, smaller one?
4. Who is the maintainer contact during the engagement?
