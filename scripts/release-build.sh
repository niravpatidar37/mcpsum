#!/usr/bin/env bash
# Build the release binary for one target, exactly as the release workflow does.
# Used by .github/workflows/release.yml and reproducible.yml, and by anyone
# reproducing a release (docs/RELEASING.md#reproduce-a-release-binary).
# The release profile (Cargo.toml) already sets lto, codegen-units = 1 and strip.
set -euo pipefail
target="${1:?usage: scripts/release-build.sh <target-triple>}"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
src="$PWD"
if command -v cygpath > /dev/null; then # Git Bash: rustc sees native Windows paths
  cargo_home="$(cygpath -w "$cargo_home")"
  src="$(cygpath -w "$src")"
fi
export CARGO_HOME="$cargo_home" # so cargo uses exactly the prefix remapped below
# Panic messages embed source paths (file!()); map the machine-specific prefixes
# (dependency sources under CARGO_HOME, and the checkout) to fixed names.
# https://doc.rust-lang.org/rustc/remap-source-paths.html
export RUSTFLAGS="--remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$src=/build"
# MSVC's linker otherwise writes the link time into the PE header and a random
# PDB GUID; /Brepro derives both from a hash of the output (IMAGE_DEBUG_TYPE_REPRO,
# https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#debug-type).
case "$target" in *-windows-msvc) RUSTFLAGS+=" -C link-arg=/Brepro" ;; esac
# Apple's linker otherwise gave a different LC_UUID per build directory (its debug
# map names object files by path); -S omits debug info, which strip drops anyway.
case "$target" in *-apple-darwin) RUSTFLAGS+=" -C link-arg=-Wl,-S" ;; esac
# Nothing in the build reads the clock today; if a build script ever does, it
# should use the commit time. https://reproducible-builds.org/specs/source-date-epoch/
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
cargo build --release --locked --target "$target"
