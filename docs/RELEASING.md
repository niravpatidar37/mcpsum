# Releasing and verifying mcpsum

## Verify a release

Every release archive has a **build provenance attestation**. It is signed
through GitHub artifact attestations with a short-lived Sigstore certificate,
and states which workflow, commit and tag produced the file. Each release also
ships `SHA256SUMS` and a CycloneDX SBOM (`mcpsum.cdx.json`) with its own
attestation.

You need the [GitHub CLI](https://cli.github.com/) (`gh`).

```sh
# 1. Provenance: built by this repo's release workflow, unmodified since.
gh attestation verify mcpsum-x86_64-unknown-linux-musl.tar.gz \
  --repo niravpatidar37/mcpsum \
  --signer-workflow niravpatidar37/mcpsum/.github/workflows/release.yml

# 2. Checksum (the same digests the attestation covers).
sha256sum --ignore-missing -c SHA256SUMS

# 3. Optional: the SBOM attestation for the same archive.
gh attestation verify mcpsum-x86_64-unknown-linux-musl.tar.gz \
  --repo niravpatidar37/mcpsum \
  --predicate-type https://cyclonedx.org/bom
```

Do not run a binary that fails step 1. Please report it: see [SECURITY.md](../SECURITY.md).

| Archive | Platform |
|---|---|
| `mcpsum-x86_64-unknown-linux-musl.tar.gz` | Linux x86-64 (static) |
| `mcpsum-aarch64-unknown-linux-musl.tar.gz` | Linux ARM64 (static) |
| `mcpsum-x86_64-pc-windows-msvc.zip` | Windows x86-64 |
| `mcpsum-aarch64-apple-darwin.tar.gz` | macOS Apple silicon |
| `mcpsum-x86_64-apple-darwin.tar.gz` | macOS Intel (cross-compiled; not smoke-tested in CI) |

macOS binaries are not notarized yet, so Gatekeeper may block them. After
verifying and extracting, clear the quarantine flag:
`xattr -d com.apple.quarantine mcpsum-aarch64-apple-darwin/mcpsum` (use the directory
name of your archive).

### What this proves, and what it doesn't

The attestation proves the archive was built by
`.github/workflows/release.yml` in this repository, from the tagged commit,
on a GitHub-hosted runner, and was not modified afterwards. It does **not**
prove the source code is free of bugs or backdoors. It ties the binary to
public source that you (or anyone) can review. Because the binaries are
reproducible (next section), anyone can also check that the binary really is
what that source compiles to, without trusting GitHub's runners.

## Reproduce a release binary

Release binaries are built by [`scripts/release-build.sh`](../scripts/release-build.sh):
`cargo build --release --locked` with the pinned toolchain
(`rust-toolchain.toml`), the release profile in `Cargo.toml` (`lto`,
`codegen-units = 1`, `strip`), `--remap-path-prefix` for the checkout and
`CARGO_HOME` paths that panic messages embed
([rustc book](https://doc.rust-lang.org/rustc/remap-source-paths.html)),
`SOURCE_DATE_EPOCH` set to the commit time
([spec](https://reproducible-builds.org/specs/source-date-epoch/)), and on
Windows the linker's `/Brepro`, which replaces the link timestamp and PDB GUID
with a hash of the output. The `reproducible` workflow builds every target twice
on each PR and push to `main` (different checkout path, `HOME`/`CARGO_HOME`,
time zone and time) and fails if the SHA-256 differs.

To check a published binary, build the tag on the same OS and CPU architecture
as the release runner (Ubuntu 24.04 with `musl-tools` for Linux, Windows with
MSVC, macOS 15 with Xcode), then compare with the binary inside the verified
archive:

```sh
git clone https://github.com/niravpatidar37/mcpsum && cd mcpsum
git checkout vX.Y.Z   # releases after v0.1.1 use scripts/release-build.sh
rustup toolchain install && rustup target add x86_64-unknown-linux-musl
bash scripts/release-build.sh x86_64-unknown-linux-musl
shasum -a 256 target/x86_64-unknown-linux-musl/release/mcpsum
# Same digest as the binary in the release archive (verified above):
tar -xzf mcpsum-x86_64-unknown-linux-musl.tar.gz
shasum -a 256 mcpsum-x86_64-unknown-linux-musl/mcpsum
```

Limits: the archives (`.tar.gz`, `.zip`) store file times, so compare the
binary inside, not the archive. A different linker or SDK (another binutils,
MSVC or Xcode version) can change the bytes, and so can building on a
different host architecture
([cargo#8140](https://github.com/rust-lang/cargo/issues/8140)). CI proves
the build is deterministic on the release runner images; a mismatch on your
machine is worth reporting with both digests and your toolchain versions.

## Cutting a release (maintainers)

1. Make sure `main` is green, and that `CHANGELOG.md` has the new version's
   section with the date.
2. Bump `version` in `Cargo.toml`, then run `cargo build --locked` so
   `Cargo.lock` updates. Merge that via a PR.
3. Tag the merge commit and push the tag:
   ```sh
   git checkout main && git pull --ff-only
   git tag -a v0.1.0 -m "mcpsum v0.1.0"
   git push origin v0.1.0
   ```
4. The `release` workflow builds 5 targets, smoke-tests 4, generates the
   SBOM, checks that the tag matches `Cargo.toml`, writes `SHA256SUMS`,
   creates both attestations, and opens a **draft** release.
5. Review the draft: download one archive, run the verification steps above,
   check the notes. Then publish it by hand. Publishing is irreversible, so it
   stays a human step.

The workflow's write permissions (`contents`, `id-token`, `attestations`)
exist only in the final job. That job runs only for `v*` tag pushes, in the
`release` environment, which is restricted to `v*` tags.

### Rollback

A bad release cannot be "unpublished" from people who already downloaded it.

1. Mark the release as a pre-release and edit its notes to say why. Or delete
   it if no one could have used it yet.
2. Publish a fixed patch release (`vX.Y.Z+1`). Never move or reuse a tag.
3. If the issue is security-relevant, publish a GitHub security advisory.
