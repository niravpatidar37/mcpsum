# Threat model

This document covers mcpsum v0.1: stdio transport, one proxy process per
server. It describes what mcpsum defends, against whom, and where it stops.
The per-guarantee statements and their tests are in [GUARANTEES.md](GUARANTEES.md).

## System

```
 ┌───────────── user's machine ─────────────────────────────────────────┐
 │                                                                      │
 │  MCP client ── stdio ──▶ mcpsum proxy ── stdio ──▶ MCP server process│
 │  (Claude Code,          ┌────────────┐            (third-party code) │
 │   Cursor, VS Code)      │  monitor   │ ◀── mcp.lock (reviewed, in git)
 │        ▲                │ (pure fn)  │ ──▶ audit log (hash chain)    │
 │        │                └────────────┘                               │
 │      model                                                           │
 └──────────────────────────────────────────────────────────────────────┘
```

## Assets

| Asset | Why it matters |
|---|---|
| The model's context (system prompt, tool definitions) | Whoever writes into it can steer the agent |
| Data reachable through *other* servers (email, chat, repos) | A cross-server *shadowing* attack exfiltrates it via a trusted tool ([Invariant Labs](https://invariantlabs.ai/blog/whatsapp-mcp-exploited)) |
| Secrets in the user's environment | Inherited by every server process unless scrubbed |
| The user's attention and approvals | Elicitation and forged output can social-engineer the user |
| Integrity of the record of what happened | Needed for incident response |

## Trust boundaries

1. **Server → mcpsum (untrusted → trusted).** Everything the server sends is
   untrusted, including its definitions, results, errors, notifications,
   requests, stderr and process exit.
2. **mcpsum → client.** mcpsum forwards server text only in the four places
   allowed by I1. Everything else comes from the lock or from mcpsum.
3. **Lockfile (trusted after human review).** The trust root. It is reviewed
   like code and committed to git.
4. **Client → mcpsum (trusted user, untrusted model).** The client is the
   user's agent, but the *model* choosing calls may already be manipulated. So
   calls are validated, not trusted.
5. **Server process ↔ OS (not mediated in v0.1).** The server runs as the user.

## Attacker models

| Attacker | Capability | In scope? |
|---|---|---|
| **A1 Malicious or compromised server publisher** | Ships any server code and changes it at any time, including after approval (rug pull) | Yes: the primary attacker |
| **A2 Content attacker** | Plants text in data that a tool returns (web page, issue, email) | Partially: see "Indirect injection" below |
| **A3 Local attacker with write access** | Edits the lockfile, the audit log or the binary | No (outside the trust model). Tamper-*evidence* only for the audit log |
| **A4 Network attacker** | — | N/A for stdio. Remote transports are not supported yet |

## Attack paths and mitigations

| # | Attack | Source | mcpsum mitigation | Status |
|---|---|---|---|---|
| 1 | **Tool poisoning**: instructions hidden in a tool description | [Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | `lock` flags hidden characters and injection markers; the human reviews the lockfile diff | Heuristic at lock time (TOFU) |
| 2 | **Rug pull**: definition changes after approval | [Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | I1: definitions served from the lock; live drift quarantines the server | **Enforced** |
| 3 | **Full-schema poisoning**: instructions in parameter names, defaults, enums, extra fields | [CyberArk](https://cyberark.com/resources/threat-research/poison-everywhere-no-output-from-your-mcp-server-is-safe) | I1 covers the *whole* surface digest, not just descriptions | **Enforced** |
| 4 | **Hidden exfiltration argument** (`sidenote`) | CyberArk / Invariant | I2: strict locked schemas reject undeclared properties | **Enforced** |
| 5 | **Shadowing**: one server's text reprograms how the agent uses another server | [Invariant Labs](https://invariantlabs.ai/blog/whatsapp-mcp-exploited) | I1 stops post-approval shadowing; `lock` flags cross-server name references | Enforced after lock; heuristic at lock |
| 6 | **Instructions / serverInfo poisoning** | MCP `initialize` result | I1: served from lock | **Enforced** |
| 7 | **Sampling abuse**: the server sends its own prompt to your model | MCP spec (sampling) | I3: capability withheld; requests refused | **Enforced** |
| 8 | **Elicitation phishing**: the server asks your user for secrets | MCP spec (elicitation) | I3: capability withheld; requests refused | **Enforced** |
| 9 | **Response spoofing / id confusion** | JSON-RPC | I7: id rewriting; responses must match an open request, at most once | **Enforced** |
| 10 | **Resource exhaustion** (huge lines, floods, a wedged pipe) | — | I7: 4 MiB line cap, pending/queue caps, write-ahead failure, wedged-server quarantine | **Enforced** |
| 11 | **Terminal injection** via definitions or stderr | Trojan Source, [CVE-2021-42574](https://nvd.nist.gov/vuln/detail/CVE-2021-42574) | All server text escaped before display; stderr relayed escaped and prefixed | **Enforced** |
| 12 | **Environment secret theft** | — | Scrubbed environment; explicit `--env NAME` passthrough; values never stored | **Enforced** (for env vars only) |
| 13 | **Malicious code behind unchanged definitions** (postmark-mcp BCC) | [Koi Security](https://www.koi.security/blog/postmark-mcp-npm-malicious-backdoor-email-theft) | Pin the package version in the locked command; audit trail. Sandbox and egress allowlist planned (I5) | **Not prevented** |
| 14 | **Indirect prompt injection in tool results** | [CaMeL](https://arxiv.org/abs/2503.18813), [design patterns](https://arxiv.org/abs/2506.08837) | Results pass through. Taint tracking planned (I6) | **Not prevented** |
| 15 | **Filesystem / network access outside MCP** | — | None in v0.1 (I5 planned) | **Not prevented** |
| 16 | **Bypass by configuring the server directly** | — | Out of mcpsum's control; use client allowlists or managed policies | **Not prevented** |

## Framework mapping

| Framework | Items addressed |
|---|---|
| OWASP Top 10 for LLM Applications (2025) | **LLM01** Prompt Injection (2–8, partial for 14), **LLM02** Sensitive Information Disclosure (4, 12), **LLM03** Supply Chain (2, 3, 13 partial), **LLM05** Improper Output Handling (11), **LLM06** Excessive Agency (4, 7, 8), **LLM10** Unbounded Consumption (10) |
| NIST AI RMF | MANAGE: the monitor, quarantine and kill path; MEASURE: test suite, fuzzing, audit log |
| Classic security principles | Reference monitor (complete mediation, tamper resistance, small enough to verify) as described by Anderson (1972); fail-safe defaults and least privilege (Saltzer & Schroeder, 1975) |

The OWASP Top 10 for LLM Applications is revised over time. Check the current
edition before relying on this mapping.

## Residual risk

These are the risks that remain, from highest to lowest:

1. **Malicious code behind honest definitions (13).** This is the most
   realistic remaining path, and it is how the first malicious MCP server
   found in the wild worked. Mitigation today: pin versions and review
   upgrades. Real fix: I5.
2. **Indirect injection through results (14).** Real fix: I6, plus application
   design that follows the design-patterns paper.
3. **Approval of an already-poisoned definition (1).** Heuristics plus human
   review. A public transparency log of definitions is planned (M5) so that
   many reviewers see the same bytes.
4. **Bugs in mcpsum itself.** Mitigated by the small core, Rust, property tests
   against an independent oracle, fuzzing and the security policy.

## Not yet assessed

- Remote transports (Streamable HTTP, OAuth).
- The 2026-07-28 protocol revision (`server/discover`); denied by default today.
- Every client's handling of a quarantined server (only Claude Code has been
  checked by hand).
- A formal model of the session state machine (TLA+ or Kani is on the roadmap).
