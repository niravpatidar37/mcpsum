# Guarantees

mcpsum is a **reference monitor**: one small, deterministic component that
mediates every message between an MCP client and one MCP server. The model is
never asked to enforce anything. Each guarantee below is a property of
`src/monitor.rs` (a pure state machine with no I/O), and each names the tests
that check it.

Three kinds of test back the guarantees:

- **Unit tests** (`src/monitor.rs`): one per behaviour, named `iN_...`.
- **Property tests** (`tests/properties.rs`): 6,000 random adversarial
  sessions per run, checked after every step against an *independent* oracle
  (written separately from the monitor, in the spirit of differential testing
  in Cedar's verification-guided development, [arXiv:2407.01688](https://arxiv.org/abs/2407.01688)).
- **End-to-end tests** (`e2e/`): the real binary against a real malicious MCP
  server (`e2e/servers/evil_server.py`), driven by the official MCP Python SDK,
  on Linux and Windows. `e2e/test_interop.py` repeats this against official MCP
  reference servers.

Fuzzing (`fuzz/`) runs four libFuzzer targets on every relevant PR and
nightly.

> **Scope.** These guarantees cover the *protocol channel* between client and
> server. They do not cover what the server does on its own machine, and they
> do not cover the truthfulness of tool *results*. See [Limits](#limits).

---

## I1 — Definitions are served from the lock

**Statement.** After approval, no definition text written by the server reaches
the client. `tools/list`, `prompts/list`, `resources/list`,
`resources/templates/list`, `serverInfo`, `instructions` and the advertised
capabilities are answered from `mcp.lock`. The live server is asked for its
definitions only to *compare* them with the lock. On any definitional
difference the server is quarantined, and every later request is refused with
`-32002`.

Server text reaches the client in exactly four places: the results of the
three pass-through methods (`tools/call`, `prompts/get`, `resources/read`) and
`notifications/progress` messages for a token the client issued.

**Why it matters.** It removes the *rug pull* (a server changes its tool
description after approval, [Invariant Labs](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks))
and *full-schema poisoning* (instructions hidden in any schema field, not just
`description`, [CyberArk](https://cyberark.com/resources/threat-research/poison-everywhere-no-output-from-your-mcp-server-is-safe)).
It removes them by construction: a scanner can miss a poisoned field, but the
monitor never forwards one.

**Tests.**
`i1_tools_list_is_served_from_lock_without_contacting_server`,
`i1_all_list_kinds_served_from_lock`,
`i1_initialize_returns_locked_instructions_and_server_info_even_if_server_lies`,
`i1_initialize_error_text_from_server_is_not_forwarded` (found by the property test),
`i1_tool_drift_during_verification_quarantines_and_poison_never_reaches_client`,
`i1_list_changed_is_not_forwarded_and_triggers_reverification`,
`i1_verification_follows_pagination`, `i1_verification_timeout_quarantines`,
`i1_method_not_found_on_verification_list_counts_as_empty`,
`i1_served_capabilities_never_advertise_list_changed_logging_or_completions`.
e2e: `test_I1_rugpull_between_sessions_never_reaches_model_and_quarantines`,
`test_I1_inline_rugpull_after_list_changed_quarantines`,
`test_I1_poisoned_instructions_never_reach_client`,
`test_I1_full_schema_poisoning_is_detected`.
Property: invariant I1 in `tests/properties.rs`.

## I2 — Calls are limited to locked items and strict locked schemas

**Statement.** `tools/call` is forwarded only for a locked tool, with
arguments that validate against the **locked** `inputSchema` under strict
rules. Any property the schema does not declare is rejected, unless the schema
explicitly sets `additionalProperties`. `prompts/get` is checked against the
locked prompt's argument names. `resources/read` is limited to locked URIs and
locked URI templates. Schemas with remote `$ref`s fail closed.

Denials return `-32602` and never echo the rejected values. The error names
only the schema path and instance path.

**Why it matters.** It blocks the hidden *exfiltration argument* (for example
a `sidenote` parameter that a poisoned description asks the model to fill
with `~/.ssh/id_rsa`). The call is refused before it reaches the server.

**Tests.** `i2_unapproved_tool_is_denied`, `i2_hidden_extra_argument_is_denied`,
`i2_extra_argument_denied_on_schema_without_properties`,
`i2_wrong_type_and_missing_required_are_denied`, `i2_remote_ref_schema_fails_closed`,
`i2_prompt_get_checks_name_and_argument_names`,
`i2_resource_read_limited_to_locked_uris_and_templates`,
`i2_valid_call_is_forwarded_with_rewritten_id_and_response_mapped_back`.
e2e: `test_I2_hidden_exfil_argument_is_blocked_before_reaching_server`;
interop: `test_official_sdk_through_proxy_to_official_time_server`.
Property: invariant I2, checked against a hand-written schema oracle.

## I3 — Deny by default, in both directions

**Statement.** Only the methods mcpsum understands are allowed. In addition
to the methods above, the client may send `initialize`,
`notifications/initialized`, `ping`, `logging/setLevel` and
`notifications/cancelled`. Everything else from the client is refused with
`-32601`.

From the server, **no request is ever forwarded** to the client:
`sampling/createMessage`, `elicitation/create`, `roots/list` and unknown
methods are refused, and `ping` is answered locally. The only server
notification forwarded is `notifications/progress`, for a token the client
issued. The client's `sampling`, `elicitation` and `roots` capabilities are
withheld from the server during `initialize`.

**Why it matters.** Sampling lets a server put its own prompt in front of
your model. Elicitation lets it ask your user for data directly. Roots reveal
your filesystem layout. A server that never learns the client supports them
cannot use them.

**Tests.** `i3_initialize_strips_sampling_elicitation_roots`,
`i3_server_sampling_and_elicitation_requests_are_refused_not_forwarded`,
`i3_server_ping_answered_locally`, `i3_progress_forwarded_only_for_known_token`,
`i3_unknown_client_method_denied_and_logging_notifications_dropped`.
e2e: `test_I3_server_initiated_requests_never_reach_client`,
`test_I3_modern_discover_is_denied_by_default`. Property: invariant I3.

## I7 — Fail closed

**Statement.** These are dropped or rejected, never passed on:

- malformed JSON
- JSON-RPC batches
- lines over 4 MiB
- calls sent before `initialize` completes
- duplicate in-flight client ids
- responses that do not match an open request, or that answer one twice
  (spoofed ids)

The client never sees server-side request ids, because mcpsum rewrites them.
If the audit log cannot be written, the proxy stops: audit entries are written
*before* their effects. A server that stops reading its input makes the proxy
quarantine it and exit, rather than hang.

**Tests.** `i7_garbage_oversize_and_batches_are_rejected`,
`i7_calls_before_initialize_are_not_forwarded`,
`i7_duplicate_pending_client_id_rejected`,
`i7_spoofed_and_duplicate_responses_are_dropped`,
`i7_client_cancel_is_translated_to_proxy_id`,
`i7_redos_patterns_in_locked_schemas_run_in_linear_time` (catastrophic regexes in locked
schemas run in linear time or fail closed at compile time),
`write_ahead_fails_closed_when_audit_cannot_be_written` (`src/proxy.rs`).
e2e: `test_I7_spoofed_and_duplicate_responses_are_dropped`,
`test_I7_garbage_oversize_and_log_injection_are_dropped`,
`test_I7_deaf_server_cannot_hang_proxy_shutdown`. Property: invariant I7.
Fuzz: `monitor_session`, `framing`, `lock_parse`.

## I8 — Tamper-evident audit trail

**Statement.** Every decision (allow, deny, rewrite, quarantine) is appended
to a JSON Lines log at `<lock dir>/.mcpsum-audit/<name>.jsonl`. Each entry
includes the SHA-256 of the previous one, starting from an all-zero genesis
hash. `mcpsum audit-verify` recomputes the chain and reports the first entry
that was edited, inserted or deleted.

Argument **values** are never logged. Only their canonical digest
(RFC 8785 JSON, SHA-256) is recorded.

The log is tamper-*evident*, not tamper-*proof*. An attacker with write access
can truncate the log, or rewrite all of it. To catch that, anchor the head
hash somewhere they cannot write.

**Tests.** `i8_allowed_calls_are_audited_with_args_digest_not_args`,
`i8_denied_argument_values_never_appear_in_audit_or_error`, `audit::tests::*`.
e2e: `test_I8_audit_log_verifies_and_detects_tampering`.

## Also enforced (outside the monitor)

- **Environment scrubbing.** Servers start with a minimal environment allow-list.
  Your shell's secrets are not inherited unless you name them with `--env NAME`.
  The lockfile records names only, never values. Tests:
  `test_env_secrets_are_not_inherited_unless_passed_through`, and
  `test_official_everything_server_cannot_read_unlisted_secrets` (against the
  official `server-everything`, whose `get-env` tool dumps every variable
  it can see).
- **Safe rendering.** Every server-authored string shown by `lock`, `verify`,
  `show`, or relayed from server stderr is escaped. Control characters,
  bidi overrides (Trojan Source, CVE-2021-42574), zero-width and Unicode
  tag characters are shown as `<U+XXXX>`. Tests: `render::tests::*`,
  `test_server_stderr_cannot_inject_terminal_escapes`.

## Planned (not yet implemented)

| ID | Guarantee | Milestone |
|----|-----------|-----------|
| I4 | Credential broker: servers receive scoped, short-lived credentials, never your raw secrets | M2 |
| I5 | Sandbox with a network egress allowlist per server | M2 |
| I6 | Taint tracking: data from untrusted results cannot flow into sensitive tool calls without approval | M3 |

## Limits

What mcpsum does **not** protect against today:

1. **A definition that was malicious when you approved it.** I1 faithfully
   serves whatever you locked. `lock` flags hidden characters, injection
   markers and cross-server shadowing, but this is a heuristic. Read the
   lockfile diff before committing it.
2. **Harm through allowed actions.** A locked tool can misuse its own API.
   `postmark-mcp` 1.0.16 BCC'd every email to its author through Postmark's
   legitimate API ([Koi Security](https://www.koi.security/blog/postmark-mcp-npm-malicious-backdoor-email-theft)).
   The server's code changed, but its tool definitions did not. Pin the
   package version in the locked command and keep it pinned. I5 (sandbox and
   egress allowlist) targets this.
3. **Prompt injection in tool results.** Results are passed through so tools
   keep working. An injected instruction in a web page or an email can still
   reach the model. I6 targets this; strong defenses need application design
   changes ([CaMeL, arXiv:2503.18813](https://arxiv.org/abs/2503.18813);
   [design patterns, arXiv:2506.08837](https://arxiv.org/abs/2506.08837)).
4. **No sandbox yet.** The server process runs with your user's permissions.
   It can read files and open network connections outside MCP.
5. **Servers not behind mcpsum.** If a server is configured in your client
   directly, mcpsum is not in the path.
6. **Bugs in mcpsum.** The trusted core is small, written in Rust, property
   tested and fuzzed. That reduces the risk; it does not eliminate it. Please
   report bypasses: see [SECURITY.md](../SECURITY.md).
7. **Remote (HTTP) transports and the 2026-07-28 protocol revision**
   (`server/discover`) are not supported yet. mcpsum speaks stdio, with
   protocol revisions up to 2025-11-25, and denies `server/discover`.
