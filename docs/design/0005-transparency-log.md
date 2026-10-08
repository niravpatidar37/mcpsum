# Design 0005: Public transparency log of tool definitions

- **Status:** proposed
- **Issue:** #19 (milestone M5)
- **Date:** 2026-10-08

## 1. Problem

`mcp.lock` is trust on first use. If the definitions are already poisoned when
you lock them, I1 serves the poison faithfully (GUARANTEES, Limits 1). A
targeted attacker can also show poisoned definitions only to some users (by
client name, IP, time or environment) and clean ones to everyone who looks.
One reviewer cannot tell which case they are in.

Go solved the same problem for module downloads with a checksum database: a
public, append-only log of `module@version → hash`, where a correct download
is "the same code everyone else downloads"
([proposal](https://go.dev/design/25530-sumdb),
[reference](https://go.dev/ref/mod#checksum-database)).

## 2. Goals and non-goals

**Goals.**

- `mcpsum lock` can check that the surface it saw for a pinned server matches
  what everyone else recorded, and flags a mismatch before you commit.
- The log is append-only and publicly verifiable: anyone can check that an
  entry is included and that the log never rewrote history.
- Signed lockfiles, so a reviewed `mcp.lock` can be checked against its
  approver.

**Non-goals.** Deciding whether a definition is *malicious* (the log records,
it does not judge); unpinned commands (`npx pkg` without a version has no
stable key); private servers.

## 3. Background

- **Certificate Transparency** logs certificates in a Merkle tree with
  inclusion and consistency proofs ([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962.html);
  [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html), Experimental, obsoletes it).
- **Go's sumdb** serves `/lookup/M@V` with a signed tree head and the log as
  *tiles*, which "helps caching and proxying but also makes victim
  identification that much harder" ([proposal](https://go.dev/design/25530-sumdb)).
- **tlog-tiles** ([C2SP](https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md))
  serves a log as static files with RFC 6962 hashing, so it can sit on
  object storage. **Witnesses** ([tlog-witness](https://github.com/C2SP/C2SP/blob/main/tlog-witness.md))
  cosign checkpoints after verifying a consistency proof, which makes a
  split view (different logs for different users) detectable.
- **Sigstore Rekor** ([rekor.sigstore.dev](https://rekor.sigstore.dev/)) is a
  running public log for signed artifacts.

## 4. The hard part: what is the key, and who measures?

A Go module is a zip file; its hash does not depend on who downloads it. An
MCP server's definitions are what the *running process* reports, and they can
legitimately depend on arguments, environment and protocol version (some
servers enable tool sets by flag).

- **Key:** `(package ecosystem, name, version, normalised argv, protocol
  version)` → surface digest (the existing `digests.surface`). Environment
  *names* are part of the key; values never are.
- **Who measures:**

| Option | For | Against |
|---|---|---|
| **A. Users submit** what they locked | Cheap; catches split views (many independent observers) | Anyone can submit anything: needs rate limits and per-submitter counts; a first poisoned submission looks like any other |
| **B. Log operator measures** by running the server in a sandbox, as Go's proxy fetches modules itself | One authoritative answer per key | Running arbitrary third-party code at scale; a server can cloak against the operator's environment; expensive |
| **C. Both**: operator entries plus user observations, shown side by side | Disagreement is the signal the issue asks for | Most complex |

## 5. Proposed design

- **Start with A, on an existing log, before running our own.** `mcpsum
  publish` records a signed statement `(key, surface digest, mcpsum version)`
  in Rekor (or a tlog-tiles log); `mcpsum lock --check-log` looks up the key
  and prints "seen by N independent submitters, M distinct digests". A
  mismatch is a finding (exit 2 with `--deny-findings`), never a silent block.
- **Privacy.** Lookups reveal which servers a user locks. Mitigations from the
  Go design: look up by `SHA-256(key)`, fetch tiles instead of per-key proofs
  where possible, allow proxying, and an opt-out list like `GONOSUMDB`.
  Checking is opt-in in v1.
- **Signed lockfiles.** A detached signature over the canonical lockfile
  (Sigstore keyless or an SSH key), verified by `mcpsum verify --signed`.
- **Own log later** (option C), on tlog-tiles with at least two independent
  witnesses, if A shows real use.

## 6. Threat model

- **Attacker:** a server publisher showing different definitions to different
  users; a log operator who forks the log; a spammer submitting false digests.
- **Detected:** split views between users who check the log; a log fork, once
  witnesses cosign.
- **Not detected:** a poisoned definition shown identically to everyone (the
  log makes it *visible*, not safe); servers nobody else has locked.

## 7. Operating cost (estimate)

Static tiles on object storage plus a small sequencer. No figures yet; the
estimate needs expected entry volume. Option B adds sandboxed compute per new
version, which is likely the dominant cost.

## 8. Test plan

- Unit: key normalisation is stable across platforms (path separators,
  `uvx` vs `uv tool run`); the same lock yields the same key.
- Integration against a local tlog-tiles log: inclusion and consistency proofs
  verify; a forked checkpoint is rejected; a mismatch produces a finding.
- e2e: two locks of `evil_server.py --mode rugpull`, one poisoned, published
  under the same key, are reported as two distinct digests.

## 9. Open questions for the owner

1. Use Rekor (public, operated by Sigstore) for v1, or run a log from the start?
2. Is opt-in lookup acceptable, given the privacy trade-off, or should
   publishing be opt-in and lookups default-on?
3. Which ecosystems get keys first: npm and PyPI only?
4. Who would operate witnesses, and is operator measurement (option B) in
   scope at all?
