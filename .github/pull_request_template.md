## What and why

<!-- One or two sentences. Link the issue / research it implements. -->

## Security impact

<!-- Required. Which guarantee (I1, I2, I3, I7, I8) does this touch? New attack surface?
     If none, say "no new attack surface" and why. -->

## How it was verified

- [ ] Tests written first and seen failing (RED) before the change
- [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` pass
- [ ] New/changed guarantees have a unit test **and** an adversarial e2e test
- [ ] No argument values, secrets or PII written to logs or the audit trail
- [ ] Untrusted server text rendered through `render::escape_untrusted`

## Not checked / needs human review

<!-- Be explicit about what this PR does not cover. -->
