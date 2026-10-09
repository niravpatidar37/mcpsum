# Guarantees

mcpsum is a **reference monitor**: one small, deterministic component that
mediates every message between an MCP client and one MCP server. The model is
never asked to enforce anything. Each guarantee below is a property of
`src/monitor.rs` (a pure state machine with no I/O), and each names the tests
that check it.

Three kinds of test back the guarantees:

- **Unit tests** (`src/monitor.rs`): one per behaviour, named `iN_...`.
- **Property tests** (`tests/properties.rs`): 9,000 random adversarial
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
capabilities are answered from `mcp.lock`. For a 2026-07-28 client (no
`initialize`, version in each request's `_meta`), so is `server/discover`,
and every result carries the locked `serverInfo`; the server's own
`server/discover` is never consulted. The live server is asked for its
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
`i1_served_capabilities_never_advertise_list_changed_logging_or_completions`,
`i1_modern_discover_served_from_lock_and_upstream_opened_legacy_without_client_caps`,
`i1_modern_call_waits_for_verification_and_result_is_rewritten`,
`i1_modern_session_quarantines_on_instruction_drift`.
e2e: `test_I1_modern_discover_served_from_lock_server_discover_never_consulted`,
`test_I1_modern_client_after_rugpull_is_quarantined`, `test_I1_rugpull_between_sessions_never_reaches_model_and_quarantines`,
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
`notifications/cancelled`, and a 2026-07-28 client `server/discover`.
Everything else from the client (including `subscriptions/listen` and the
tasks extension) is refused with `-32601`. A modern request for a revision
other than 2026-07-28 gets `-32022` (`UnsupportedProtocolVersionError`).

From the server, **no request is ever forwarded** to the client:
`sampling/createMessage`, `elicitation/create`, `roots/list` and unknown
methods are refused, and `ping` is answered locally. The only server
notification forwarded is `notifications/progress`, for a token the client
issued. The client's `sampling`, `elicitation` and `roots` capabilities are
withheld from the server during `initialize`; for a 2026-07-28 client mcpsum
opens the upstream session itself, with no client capabilities, and never
forwards per-request `_meta`. A 2026-07-28 *input request* (a result with
`resultType` other than `complete`, which carries elicitation, sampling or
roots requests) is refused with `-32001`.

**Why it matters.** Sampling lets a server put its own prompt in front of
your model. Elicitation lets it ask your user for data directly. Roots reveal
your filesystem layout. A server that never learns the client supports them
cannot use them.

**Tests.** `i3_initialize_strips_sampling_elicitation_roots`,
`i3_server_sampling_and_elicitation_requests_are_refused_not_forwarded`,
`i3_server_ping_answered_locally`, `i3_progress_forwarded_only_for_known_token`,
`i3_unknown_client_method_denied_and_logging_notifications_dropped`.
e2e: `test_I3_server_initiated_requests_never_reach_client`,
`test_I3_discover_without_modern_meta_is_denied_by_default`,
`test_I3_input_required_result_is_refused`;
unit: `i3_input_required_result_is_refused_not_forwarded`,
`i3_modern_discover_after_legacy_initialize_is_denied`,
`i7_modern_unsupported_or_missing_version_is_rejected_and_never_forwarded`.
Property: invariant I3, also from a session a modern client opened.

## I5 — The server process is sandboxed (opt-in, Linux, no network)

**Statement.** If the server's entry in `mcp.lock` has a `policy.sandbox`
section (see [LOCKFILE.md](LOCKFILE.md#sandbox-optional-i5)), mcpsum starts it
under OS-enforced, deny-by-default rules, and refuses to start it if they
cannot be enforced:

- **Files (Landlock).** It may read only a minimal runtime base (`/usr`,
  `/lib*`, `/bin`, `/sbin`, `/etc`, `/proc`, `/sys`, a few `/dev` files), its
  own program, absolute file arguments, and the paths the policy lists. It
  may write only the listed paths and a private temporary directory. **Your
  home directory is not readable** unless you list part of it, so `~/.ssh`
  and `~/.aws` are out of reach.
- **mcpsum's own files can never be made writable.** A policy whose write
  paths would cover `mcp.lock`, its directory, the audit log, the taint state,
  the mcpsum binary or your home directory is refused, because Landlock has no
  deny rules.
- **No network.** seccomp refuses `AF_INET`, `AF_INET6`, `AF_PACKET` and
  `AF_NETLINK` sockets (so no TCP, UDP or DNS on any kernel), and Landlock
  also denies TCP bind and connect on Linux ≥ 6.7. `io_uring` is refused,
  because it can create sockets without `socket(2)`.
- **No privilege building.** seccomp refuses new namespaces (`unshare`,
  `setns`, `clone` namespace flags; `clone3` returns `ENOSYS` so libc falls back
  to `clone`), mounts, `bpf`, keyrings, `ptrace` and `perf_event_open`.
  Landlock scopes signals and abstract Unix sockets on Linux ≥ 6.12.
- Re-locking and `verify` also run the server inside its sandbox. The audit
  log records the sandbox at start (Landlock ABI, path counts).

Design, options and threat model: [design 0002](design/0002-sandbox.md).

**Limits.**

- **Linux only.** On macOS and Windows a server with `policy.sandbox` does not
  start (fail closed). Network **allowlists** (`"api.github.com:443"`) are the
  next step; until then any `network.allow` entry is refused.
- **Abuse of an allowed API is not prevented** (the postmark-mcp case); that
  needs I4. A no-network sandbox suits local servers (files, git, databases on
  a socket you grant); servers that call web APIs need the allowlist.
- **Install first.** A sandboxed `npx`/`uvx` command cannot download
  packages. Install the server first and lock the installed command.
- **Filesystems need stable inodes.** Landlock cannot grant paths on 9p mounts
  such as WSL's `/mnt/c`; such a server fails to start. Keep it on the Linux
  filesystem.
- `/etc` and `/proc` are readable. Landlock's ptrace rules stop a sandboxed
  process from reading other processes' memory or environment, but command
  lines in `/proc/*/cmdline` are visible. File *existence* (`stat`) is not
  hidden.
- Before Landlock ABI 9 (Linux 7.1), connecting to a pathname Unix socket the
  user may write (for example `/run/docker.sock` for members of `docker`) is
  not controlled.
- Kernel bugs: Landlock and seccomp are kernel code.

**Tests.** e2e, against the real binary on Linux:
`test_I5_sandboxed_server_cannot_read_secrets_touch_mcpsum_files_or_reach_the_network`
(read `~/.ssh/id_rsa`, write `~/.bashrc`, `mcp.lock` and the audit log, TCP,
UDP and a user namespace are all denied; its temporary directory and running
programs still work) with the control
`test_I5_without_a_sandbox_the_probe_succeeds`;
`test_I5_policy_that_would_expose_mcpsum_files_is_refused`,
`test_I5_relock_and_verify_run_the_server_inside_its_sandbox`,
`test_I5_sandboxed_server_does_not_start_without_a_backend` (Windows).
Each network layer alone: `i5_seccomp_alone_blocks_tcp_and_udp`,
`i5_landlock_alone_blocks_tcp_where_the_kernel_supports_it`. Grant rules:
`i5_grant_is_deny_by_default_and_never_includes_home`,
`i5_writes_that_would_cover_mcpsum_files_or_home_are_refused`.
Mutation-checked: removing Landlock, seccomp, either network layer, the
namespace rules or the protected-path check each fails a test.

## I6 — Untrusted results cannot silently trigger sinks (opt-in)

**Statement.** If the server's entry in `mcp.lock` has a `policy.taint` section
(see [LOCKFILE.md](LOCKFILE.md#policy-optional-i6)), then once a result from a
**source** has been delivered to the client, a call to a **sink** is never
forwarded silently:

- If the client supports form prompts (`elicitation`), mcpsum holds the call and
  asks the user with **its own** prompt: the tool, the source that tainted the
  session, and the arguments, escaped and truncated. Only an explicit
  `accept` with `allow: true` forwards **exactly that call**, once. Decline,
  cancel, an error, anything malformed, or 60 s without an answer refuses it
  with `-32001`. A quarantine refuses every held call.
- Otherwise the call is refused with `-32001`.

The session is marked tainted **before** the untrusted text is delivered
(write-ahead), including error messages and progress messages from a source.
The taint is **shared by every server of one client session**: content fetched
by `web` gates `send_email` on `mail`. The session is the MCP client process that
started the proxies (override with `--session` or `MCPSUM_SESSION`), and its marker
lives in a per-user directory (owner-only on Unix). A marker that cannot be read
counts as tainted. Only the user clears it, with `mcpsum taint reset`, which
refuses to run without a person at a terminal. Labels come only from the user's policy, never from server-written
annotations (the MCP specification says not to trust those). A label that names
a tool which isn't locked is an error, so a typo cannot silently leave a tool
unprotected. Without a policy, behaviour is exactly as before.

This is the defence pattern from the prompt-injection literature: constrain what
may happen *after* untrusted data has been read, deterministically and outside
the model, instead of trying to detect injected text
([CaMeL](https://arxiv.org/abs/2503.18813), [FIDES](https://arxiv.org/abs/2505.23643),
[design patterns](https://arxiv.org/abs/2506.08837)). Design and alternatives:
[design 0001](design/0001-taint-tracking.md).

This covers flows inside one server, such as the GitHub MCP exploit where a
malicious public issue led the agent to leak private repositories through the
same server ([Invariant Labs](https://invariantlabs.ai/blog/mcp-github-vulnerability)),
and flows across servers. `mcpsum suggest-policy` proposes labels from the
server's annotations for you to review.

**Limits.**

- Coarse: after any source, every sink needs approval until you reset.
- Only as good as the policy and your decision (approval fatigue is real).
- **An agent with a shell tool that is not behind mcpsum can bypass it**: the
  shell is itself an unmediated sink (it can send data with `curl`, or delete
  the marker file). The terminal check on `taint reset` is defence in depth,
  not a boundary.
- Session grouping follows the process tree. VS Code starts servers from two
  processes, which form two sessions; use `--session` to join them. A reused
  process id makes a new session start tainted (fail safe).
- Integrity only: reading private data and sending it out *without* any
  injection is not covered yet (confidentiality labels, design 0001 §9).

**Tests.** `i6_source_result_taints_the_session_before_it_reaches_the_client`,
`i6_tainted_sink_is_held_and_forwarded_exactly_once_on_explicit_allow`,
`i6_anything_but_explicit_allow_denies_the_held_call`,
`i6_tainted_sink_is_refused_when_the_client_cannot_show_a_prompt`,
`i6_approval_prompt_names_tool_and_source_and_escapes_the_arguments`,
`i6_unanswered_approval_times_out_denies_and_withdraws_the_prompt`,
`i6_quarantine_denies_held_calls`,
`i6_progress_text_from_a_source_taints_before_it_is_delivered`,
`i6_policy_naming_an_unlocked_tool_is_rejected`,
`i6_marker_is_shared_by_every_store_of_a_session_and_cleared_only_by_reset`,
`i6_session_ids_cannot_escape_the_state_directory` and the other `i6_*` unit tests.
e2e: `test_I6_injected_result_cannot_trigger_a_sink_when_the_client_cannot_prompt`,
`test_I6_sink_after_injection_runs_only_when_the_user_allows_it`,
`test_I6_relock_keeps_the_user_policy`,
`test_I6_taint_crosses_servers_of_one_client_session`,
`test_I6_separate_sessions_do_not_share_taint`,
`test_I6_unreadable_taint_state_counts_as_tainted`,
`test_I6_taint_list_shows_the_session_and_reset_needs_a_person`.
Property: `i6_taint_invariants_hold_under_a_policy` (no sink after taint
without that step's explicit allow, for exactly the arguments shown; taint
recorded before delivery).

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

Several proxies may write the same log at once (VS Code runs MCP servers in two
processes): every append takes an exclusive cross-process lock, re-reads the chain
head and checks its hash, then writes one complete line, so the log stays a single
chain. A head that fails its hash check is never extended; the proxy fails closed.

Argument **values** are never logged. Only their canonical digest
(RFC 8785 JSON, SHA-256) is recorded.

The log is tamper-*evident*, not tamper-*proof*. An attacker with write access
can truncate the log, or rewrite all of it. To catch that, anchor the head
hash somewhere they cannot write.

**Tests.** `i8_allowed_calls_are_audited_with_args_digest_not_args`,
`i8_denied_argument_values_never_appear_in_audit_or_error`, `audit::tests::*`,
`concurrent_writers_keep_one_valid_chain` (8 writers × 50 appends).
e2e: `test_I8_audit_log_verifies_and_detects_tampering`,
`test_I8_two_proxies_for_one_server_keep_one_valid_chain`.

## Also enforced (outside the monitor)

- **Environment scrubbing.** Servers start with a minimal environment allow-list.
  Your shell's secrets are not inherited unless you name them with `--env NAME`.
  The lockfile records names only, never values. Tests:
  `test_env_secrets_are_not_inherited_unless_passed_through`, and
  `test_official_everything_server_cannot_read_unlisted_secrets` (against the
  official `server-everything`, whose `get-env` tool dumps every variable
  it can see).
- **Process lifetime.** Each server runs as the leader of its own process group (Unix)
  or inside a Job Object (Windows; assigned before the server can start anything), and
  mcpsum kills that whole tree on exit, so grandchildren cannot keep running
  unmediated. Limits: on Unix a process can leave its group with `setsid()`, and the
  tree is not killed if mcpsum itself is killed abruptly. Tests:
  `test_lock_kills_server_grandchildren`, `test_proxy_kills_server_grandchildren_on_shutdown`.
- **Safe rendering.** Every server-authored string shown by `lock`, `verify`,
  `show`, or relayed from server stderr is escaped. Control characters,
  bidi overrides (Trojan Source, CVE-2021-42574), zero-width and Unicode
  tag characters are shown as `<U+XXXX>`. Tests: `render::tests::*`,
  `test_server_stderr_cannot_inject_terminal_escapes`.

## Planned (not yet implemented)

| ID | Guarantee | Milestone |
|----|-----------|-----------|
| I4 | Credential broker: servers receive scoped, short-lived credentials, never your raw secrets | M2 |
| I5+ | Network egress allowlist by host (namespace + audited proxy); macOS and Windows backends | M2 |
| I6+ | Confidentiality labels (private data cannot reach public sinks) and per-argument rules | M3 |

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
   package version in the locked command and keep it pinned. The I5 sandbox
   stops it reaching *other* hosts or your files; abuse of the allowed API
   itself needs I4 (credential broker).
3. **Prompt injection in tool results.** Results are passed through so tools
   keep working. An injected instruction in a web page or an email can still
   reach the model. With a taint policy (I6, opt-in) it cannot silently trigger
   a sink, but it can still mislead the model's answers, the protection is
   only as good as the policy and the user's approval, and an agent with its
   own shell tool can bypass it. Strong defenses need application design
   changes ([CaMeL, arXiv:2503.18813](https://arxiv.org/abs/2503.18813);
   [design patterns, arXiv:2506.08837](https://arxiv.org/abs/2506.08837)).
4. **Sandbox is opt-in and Linux-only.** Without `policy.sandbox` (and on
   macOS and Windows) the server process runs with your user's permissions
   and can read files and open network connections outside MCP. Network
   allowlists by host are not available yet; see [I5](#i5--the-server-process-is-sandboxed-opt-in-linux-no-network).
5. **Servers not behind mcpsum.** If a server is configured in your client
   directly, mcpsum is not in the path.
6. **Bugs in mcpsum.** The trusted core is small, written in Rust, property
   tested and fuzzed. That reduces the risk; it does not eliminate it. Please
   report bypasses: see [SECURITY.md](../SECURITY.md).
7. **Protocol revisions.** mcpsum speaks stdio only (no HTTP transport).
   Clients may use revisions up to 2025-11-25 (`initialize`) or
   [2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
   (per-request `_meta`, [`server/discover`](https://modelcontextprotocol.io/specification/2026-07-28/server/discover)).
   Upstream, mcpsum always opens a legacy `initialize` session at the locked
   revision, so a server that speaks *only* 2026-07-28 cannot be locked or
   proxied yet. The new 2026-07-28 features are denied: multi round-trip
   input requests, `subscriptions/listen`, the tasks extension and
   capability `extensions`. mcpsum's approval prompt (I6) is a
   server-initiated request, which 2026-07-28 clients do not take, so a
   tainted sink call from such a client is refused, not held.
