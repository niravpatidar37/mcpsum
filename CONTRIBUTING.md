# Contributing to mcpsum

Thanks for helping. mcpsum is a security tool, so the bar for changes to the
enforcement core is high. In return, the process is predictable.

## Reporting a bypass

Do **not** open a public issue. Use private vulnerability reporting (see
[SECURITY.md](SECURITY.md)). A minimal malicious server or message sequence is
the most useful thing you can send.

## Development setup

- Rust **1.88.0** (pinned in `rust-toolchain.toml`; `rustup` picks it up automatically)
- [uv](https://docs.astral.sh/uv/) for the Python end-to-end suite (Python 3.12)
- Optional: nightly Rust + `cargo-fuzz` for fuzzing, `cargo-deny` for supply-chain checks

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked                       # unit + property tests

cargo build --locked
cd e2e
uv sync --frozen --python 3.12
uv run --frozen pytest -q -m "not interop"   # adversarial suite (offline)
uv run --frozen pytest -q -m interop         # official reference servers (network)
```

Fuzzing (nightly):

```sh
cargo +nightly fuzz run monitor_session -- -max_total_time=60
```

## Rules for changes

1. **Tests first.** For a bug, add a failing test that reproduces it (RED),
   then fix it (GREEN). For a bypass, the test goes in `src/monitor.rs` (unit)
   *and* `e2e/` (real binary vs. a malicious server) when that is feasible.
2. **`src/monitor.rs` stays pure.** No I/O, no clocks, no randomness. Time
   comes in through `on_tick`. This is what makes it testable and fuzzable.
3. **Never log or echo argument values, secrets or PII.** Not in the audit
   log, not in error messages, not in debug output. Log a digest instead.
4. **Render all server text through `render::escape_untrusted`.**
5. **Fail closed.** If you are unsure whether to forward something, don't.
6. **No new dependencies in the core without discussion.** Every crate must
   pass `cargo deny` (permissive licenses only, crates.io only).
7. **Conventional Commits**, and commit messages that explain *why*.

## Pull requests

- One feature or fix per PR. CI must be green: lint, tests on Linux and Windows,
  e2e on both, cargo-deny, gitleaks, zizmor.
- Fill in the PR template's **security impact** and **not checked** sections
  honestly. "No new attack surface, because…" is a fine answer when it is true.
- All review conversations must be resolved before merge (branch protection
  enforces this). PRs are squash-merged.

## Code of conduct

Be kind and assume good faith. Harassment is not tolerated; maintainers may
remove comments, close issues or block accounts that cross that line.
