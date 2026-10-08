# Design 0004: Benchmarks for security, utility and overhead

- **Status:** proposed
- **Issue:** #17 (milestone M4)
- **Date:** 2026-10-08

## 1. Problem

mcpsum's claims are backed by tests that show each guarantee holds for crafted
messages. They do not say how much safer a real agent is with mcpsum in the
path, how often normal tasks break, or what it costs in latency. Those need
measurement with real models and published numbers.

## 2. Goals and non-goals

**Goals.** A harness anyone can rerun that reports, with and without mcpsum:

- **Security:** attack success rate (ASR) per attack class.
- **Utility:** task success on benign tasks, and under attack.
- **Overhead:** added latency per call (p50/p95/p99) and memory.

The harness, the configuration and the raw results are published.

**Non-goals:** ranking models; claiming mcpsum stops prompt injection in
general (it does not, see GUARANTEES Limits 3); tuning mcpsum to a benchmark.

## 3. Existing benchmarks

| Benchmark | What it measures | Runs real MCP? | Fit |
|---|---|---|---|
| **AgentDojo** ([arXiv:2406.13352](https://arxiv.org/abs/2406.13352), [repo](https://github.com/ethz-spylab/agentdojo), MIT) | Injections in tool *results*: 97 tasks, 629 security test cases. Reports benign utility, utility under attack and targeted ASR. | No: tools are Python functions in its own runtime; no MCP adapter found in the repo (checked 2026-10-08). | The metric design to copy. Exercises I6 (taint), not I1. Needs an adapter that serves each suite's tools as an MCP server. |
| **MCPTox** ([arXiv:2508.14925](https://arxiv.org/abs/2508.14925), [repo](https://github.com/zhiqiangwang4/MCPTox-Benchmark)) | Tool poisoning in definitions: 45 real servers, 353 tools, 1,348 malicious cases. | Built on live MCP servers. | Exercises I1/I2, but its poison is present *before* approval. mcpsum serves a poisoned lock faithfully (Limits 1), so most cases should show **no** change, plus `lock` heuristic findings. Useful as an honest negative result. |
| **MSB** ([arXiv:2510.15994](https://arxiv.org/abs/2510.15994), [repo](https://github.com/dongsenzhang/MSB), MIT) | 12 attack types across planning, invocation and response handling, run "via MCP rather than simulation"; Net Resilient Performance metric. | Yes. | Closest fit. Covers out-of-scope parameters (I2) and response attacks (I6). |

None of them covers the rug pull (a definition that changes **after**
approval), sampling or elicitation abuse, or protocol-level attacks (spoofed
ids, oversize frames). Those need our own suite.

## 4. Proposed design

Three suites, one harness (Python, uv, under `bench/`):

1. **`bench/mcpsum-attacks`: our own.** Each `e2e/servers/evil_server.py` mode
   becomes a scenario with a benign user task and an attacker goal: rug pull,
   inline rug pull, schema smuggling, poisoned instructions, sampling,
   elicitation, env theft, taint (inject then call a sink). The agent is a
   real model driving the official MCP SDK client. Success is decided by a
   deterministic check (a canary reached the server, a sink was called), never
   by an LLM judge.
2. **AgentDojo through an adapter.** Serve each AgentDojo suite's tools as a
   stdio MCP server, lock it, add a taint policy (`suggest-policy`, then
   reviewed) and run AgentDojo's own scoring. Compare no defence, mcpsum
   without policy, and mcpsum with policy.
3. **MSB** (and MCPTox as a TOFU control) behind mcpsum, if their harnesses can
   point at a wrapped server command. To be checked; may need upstream changes.

**Arms.** `direct` (client to server), `mcpsum` (lock, no policy), `mcpsum +
taint`, and on Linux `mcpsum + taint + sandbox`.

**Overhead.** A Rust micro-benchmark of the monitor alone, and an end-to-end
loop of `tools/call` against the clean server through the real binary,
reporting p50/p95/p99 and peak RSS, on the CI Linux and Windows runners.

**Reporting.** For every run: model and version, date, seeds, temperature,
number of trials, mcpsum commit, and per-scenario results with confidence
intervals. Raw transcripts are published only for synthetic data (no real
user data ever enters the harness).

## 5. Threats to validity

- **Model drift.** Hosted models change; results are dated and pinned to a
  model version string, and old numbers are never overwritten.
- **Benchmarks reward the defence they were tuned for.** The harness is frozen
  before mcpsum numbers are first published; changes are versioned.
- **Utility loss from approvals.** With taint, a sink after a source needs a
  person. The harness must report how often it asked, and decide each prompt
  by a fixed rule (always allow, always deny), stated with the numbers.
- **TOFU.** Attacks present at lock time are out of I1's reach by design; they
  are reported separately, not hidden.

## 6. Cost

Model API calls dominate. Estimate only, to be measured: AgentDojo's full run
is 629 security cases plus 97 benign tasks per model per arm, so four arms on
one model is roughly 2,900 agent episodes. A small model and a subset first.

## 7. Test plan

- The harness has its own tests: each deterministic success check fires on a
  recorded transcript where the attack succeeded and stays quiet on one where
  it did not.
- A dry-run mode with a scripted fake model runs in CI, so the harness cannot
  rot between real runs. Real-model runs are manual or scheduled, never on PRs.

## 8. Open questions for the owner

1. Budget: which models, how many trials, and who pays for API usage?
2. Should results live in this repo (`bench/results/`) or a separate repo?
3. Do we contribute the MCP adapter upstream to AgentDojo, or keep it here?
4. Approval rule for taint prompts in the benchmark: always deny, always allow,
   or report both?
