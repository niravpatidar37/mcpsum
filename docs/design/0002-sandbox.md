# Design 0002: Per-server sandbox with a network egress allowlist (I5)

- **Status:** accepted (owner decisions, 2026-10-07: build the Linux network part in mcpsum in Rust; refuse to start when the sandbox cannot be enforced)
- **Issue:** #14 (milestone M2)
- **Date:** 2026-10-07

## 1. Problem

mcpsum controls what a server *says* (I1–I3) and what the model may *do*
with it (I6). It does not control what the server process *does on its own
machine*: it runs with the user's full permissions. That is the most
realistic remaining attack path (THREAT-MODEL, residual risk 1):

- `postmark-mcp` 1.0.16 changed its code, not its definitions
  ([Koi Security](https://www.koi.security/blog/postmark-mcp-npm-malicious-backdoor-email-theft)).
- A malicious or compromised package can read `~/.ssh`, `~/.aws` and browser
  profiles, send them anywhere, or persist (`~/.bashrc`, autostart entries).
- A server can also attack mcpsum itself: rewrite `mcp.lock`, the audit log
  or the I6 taint markers.

## 2. Goal and non-goals

**Goal (I5).** A server with a `policy.sandbox` section in `mcp.lock` runs
under OS-enforced, deny-by-default rules:

- **Filesystem:** it may read and write only the paths the policy lists, plus
  a minimal read-only runtime base (§5.3).
- **Network:** either none, or only the listed `host:port` destinations,
  through an egress proxy run by mcpsum that audits every decision (I8).
- **mcpsum's own files** (`mcp.lock`, audit logs, taint state) are never
  writable by the server.
- If the sandbox cannot be enforced, the server does not start (I7).

**Non-goals:**

- **Abuse of an allowlisted API.** postmark-mcp BCC'd mail *through Postmark's
  own API*. A host allowlist that permits `api.postmarkapp.com` cannot stop
  that. It needs request inspection (TLS termination) or scoped credentials,
  which is I4 (#15). This design stops exfiltration to *other* hosts.
- Kernel exploits, hardware side channels. A microVM backend is M5.
- Servers compiled to Wasm (e.g. [wassette](https://github.com/microsoft/wassette))
  get strong isolation for free, but cover few servers today.

## 3. Threat model

- **Attacker:** the server's code (malicious package, compromised update or
  dependency), or a server exploited through its inputs.
- **Goals:** read secrets; send data to a host it chooses; persist; reach
  local services (`/run/docker.sock`, databases on `127.0.0.1`, cloud metadata
  `169.254.169.254`); tamper with mcpsum's state; escape the sandbox.
- **Trusted:** the kernel, mcpsum, the user's policy.

## 4. Options considered

| Option | Filesystem | Network by host | Unprivileged on Ubuntu 24.04 | Notes |
|---|---|---|---|---|
| **Landlock** ([docs](https://docs.kernel.org/userspace-api/landlock.html)) | Yes, allow-list only (ABI 1, Linux 5.13) | **No**: rules are per *port* (TCP since ABI 4 / 6.7, UDP since ABI 10) | Yes | No deny rules: cannot express "allow X except X/secret". |
| **seccomp-bpf** | No (cannot read path arguments) | No, but can forbid whole socket families | Yes | Good for "no network at all" and for closing kernel surface. |
| **User + network namespace** (own code or bubblewrap) | (mount ns) | Yes, with a proxy outside | **No**: needs a one-time root-installed AppArmor profile ([Ubuntu spec](https://discourse.ubuntu.com/t/spec-unprivileged-user-namespace-restrictions-via-apparmor-in-ubuntu-23-10/37626)) | Ubuntu deliberately ships no profile for `bwrap`, because it would let anyone get a user namespace ([LP#2035315](https://bugs.launchpad.net/ubuntu/+source/apparmor/+bug/2035315)). |
| **Anthropic sandbox-runtime (srt)** ([repo](https://github.com/anthropic-experimental/sandbox-runtime)) | Yes | Yes (proxies over a Unix socket; bwrap + socat on Linux) | Same AppArmor step | Mature and cross-platform (macOS Seatbelt; Windows via a dedicated account plus WFP, admin install). But it needs Node.js, bubblewrap, socat and ripgrep, and is a research preview. |
| Containers (Docker/Podman) | Yes | Yes | Needs a daemon or rootless setup | Heavy; servers run with `npx`/`uvx` against host runtimes. |
| Egress proxy via `HTTPS_PROXY` only | No | Advisory | Yes | Bypassable: the server can just ignore the variable. |

**Conclusion.** No single mechanism gives deny-by-default files *and* a host
allowlist without privileges. So, in layers:

1. **Landlock** for the filesystem (always, unprivileged).
2. **seccomp** to remove network families entirely when the policy allows no
   network, and to close kernel surface (nested namespaces, `bpf`, `keyctl`, ...).
3. **Network namespace plus mcpsum's own egress proxy** only when the policy
   allows some hosts. This needs a one-time AppArmor profile on Ubuntu ≥ 23.10;
   mcpsum detects that and prints the exact steps.

## 5. Design (Linux)

### 5.1 Policy

```json
"policy": {
  "sandbox": {
    "filesystem": { "read": ["~/notes"], "write": ["${TMP}/notes-mcp"] },
    "network": { "allow": ["api.github.com:443"] }
  }
}
```

- `network.allow: []` (or no `network`) means **no network**.
- Entries are `host:port` with an exact host or `*.suffix`; IP literals are
  allowed. No ports by range.
- Paths: absolute, or starting with `~` or `${TMP}`. They are canonicalised at
  start; a path that does not exist is an error (Landlock opens it).
- **Refused at load** (fail closed): write access covering `/`, `$HOME`, the
  directory of `mcp.lock`, the audit directory or the taint state directory.
  Landlock has no deny rules, so "write the project but not `mcp.lock`" cannot
  be expressed. Keep `mcp.lock` outside any directory a server may write.
- Like `policy.taint`, it is user-authored, outside the definition digests,
  and kept on re-lock.

### 5.2 Launch

mcpsum re-executes itself as a single-threaded helper
(`mcpsum __sandbox-exec <spec> -- <command>`). The helper applies everything
below, then `execve`s the server, so the server keeps the helper's PID and
stays inside mcpsum's process-tree control (#7). Doing this in a helper
instead of `pre_exec` avoids allocating after `fork()` in a multithreaded
parent.

The helper probes first and fails closed: no Landlock, a user namespace that
cannot be created, or a ruleset that cannot be applied all mean the server
does not start, with a message that says why and what to do.

### 5.3 Filesystem: Landlock

- Handle every filesystem right the kernel supports (best-effort *upgrade*,
  never below ABI 1). Record the effective ABI in the audit log.
- Allowed by default, **read and execute only**: the system runtime (`/usr`,
  `/lib*`, `/bin`, `/sbin` and all of `/etc`, because Landlock cannot
  exclude a subdirectory), the resolved server executable's install prefix, and the
  launcher caches (`~/.npm`, `~/.cache/uv`, ...) when the command uses `npx` or
  `uvx`. Plus `/dev/null`, `/dev/urandom` and `/proc/self`.
- Everything in the policy on top. **`$HOME` is not readable by default**, so
  `~/.ssh` and `~/.aws` are out of reach unless the user lists them.
- Writes: only the policy's `write` paths and a private temporary directory
  that mcpsum creates per server.

### 5.4 Network

**No network (`allow: []`).** seccomp makes `socket()` fail with `EACCES`
for `AF_INET`, `AF_INET6`, `AF_PACKET` and `AF_NETLINK`. On ABI ≥ 4 Landlock
also denies all TCP bind and connect. Works on every supported kernel, no
privileges, and no DNS, so no DNS exfiltration either.

**Allowlist.**

1. The helper unshares a user and a network namespace (mapping the user's own
   uid, so the server has no capabilities after `exec`) and brings up `lo`.
   Inside, there is no route anywhere.
2. A bridge in the helper listens on `127.0.0.1:<port>` inside the namespace
   and forwards to a Unix socket that mcpsum listens on outside. Pathname
   Unix sockets are filesystem objects, not network-namespaced.
3. mcpsum's **egress proxy** speaks HTTP `CONNECT` only (v1). It checks
   `host:port` against the allowlist, resolves DNS itself, and refuses
   loopback, link-local (cloud metadata), private and multicast addresses
   unless the user listed that IP literally (stops DNS rebinding to
   `127.0.0.1`). It audits every allow and deny.
4. The server gets `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY=` and
   `NODE_USE_ENV_PROXY=1` (Node's built-in fetch ignores the variables
   otherwise). A client that ignores the proxy has no network at all: fail
   closed, never fail open.

seccomp in both modes also blocks `unshare`, `clone`/`clone3` with namespace
flags (`clone3` gets `ENOSYS`, as in Docker and Flatpak, so libc falls back to
`clone`), `mount`, `pivot_root`, `bpf`, `keyctl`, `add_key`, `request_key` and
`ptrace`. A sandboxed server therefore cannot use the user namespace it runs
in to reach more kernel surface. That matters, because the AppArmor profile
makes `mcpsum` a way to get a user namespace (see §7).

### 5.5 Audit (I8)

- At start: `sandbox applied`, with the policy digest, mode, effective Landlock
  ABI and namespace use.
- Every proxy decision: allow or deny, with `host:port` (no paths, no
  payloads).
- Individual filesystem denials are seen by the kernel, not by mcpsum: the
  server just gets `EACCES`. Landlock audit records (ABI 7, Linux 6.15) can
  log them to the kernel audit subsystem when the administrator enables it.

### 5.6 Other platforms

Until a backend exists, a server with `policy.sandbox` **does not start** on
macOS or Windows (fail closed, clear error). Planned next: macOS with a
Seatbelt profile (`sandbox-exec` is deprecated but used by Chrome, Bazel and
srt) allowing only the proxy port; Windows with an AppContainer (files) and,
for host-level egress, WFP, which needs an administrator install.

## 6. Ubuntu ≥ 23.10 setup (allowlist mode only)

`kernel.apparmor_restrict_unprivileged_userns=1` lets an unconfined process
create a user namespace but gives it no capabilities, so `lo` cannot be
brought up. mcpsum detects this and prints a one-time profile for its own
resolved binary path:

```
abi <abi/4.0>,
include <tunables/global>
profile mcpsum /home/me/.cargo/bin/mcpsum flags=(unconfined) {
  userns,
}
```

It never changes system settings itself, and never suggests disabling the
restriction globally.

## 7. Limits

- **Allowlisted APIs can still be abused** (postmark-mcp). Needs I4 (#15).
- **TLS is not inspected.** Anything the allowed host serves is reachable,
  including domain fronting through shared CDNs. Allow narrow hostnames.
- **The AppArmor profile widens kernel surface:** any local process can run
  `mcpsum __sandbox-exec` to get a user namespace. The helper drops all
  capabilities and seccomp blocks namespace and `bpf` syscalls before running
  anything, which keeps that surface small, but not zero.
- **Unix sockets:** before Landlock ABI 9 (Linux 7.1), connecting to a
  pathname socket the user may write (for example `/run/docker.sock` when the
  user is in the `docker` group) is not controlled by Landlock. In no-network
  mode seccomp cannot filter it either. Mitigation now: none; documented.
  Abstract sockets are scoped from ABI 6 (Linux 6.12).
- `/etc` is readable (system runtime). Secrets belong in `$HOME` or a secret
  manager, not `/etc`.
- Kernel bugs: Landlock and seccomp are kernel code. M5's microVM backend is
  the stronger boundary.

## 8. Test plan

- **e2e evil modes:**
  - `steal-ssh`: read a planted `~/.ssh/id_rsa` in a fake `$HOME`.
  - `persist`: write `~/.bashrc`.
  - `tamper`: write `mcp.lock`, the audit log and the taint marker.
  - `exfil`: connect directly to a local "attacker" listener, and through the
    proxy to a non-allowlisted port; connect to the allowlisted one.
  Each must fail (or succeed for the allowlisted one) **and** be visible: the
  server reports the error, the proxy denial is audited.
- **Fail closed:** a policy on a system without Landlock (simulated by a test
  switch), and allowlist mode with user namespaces blocked, must not start
  the server.
- **Unit tests:** policy validation (refused write paths, path expansion,
  `host:port` syntax); allowlist matching (case, trailing dot, `*.` suffix,
  IDN, IPv4/IPv6 literals, private ranges).
- **Fuzzing:** a new target for the proxy's request parser.
- **CI:** Ubuntu 24.04 runners have Landlock; the allowlist job installs the
  AppArmor profile for the built binary with `sudo` (GitHub-hosted runners
  allow it), and one job checks the refusal path without it.
- **Real servers:** the official fetch server allowlisted to one domain; the
  filesystem server limited to one directory.

## 9. Rollout

1. This design.
2. `policy.sandbox` (schema, validation, kept on re-lock) plus Linux
   filesystem (Landlock) and no-network (seccomp) modes, the helper, the
   fail-closed probe, audit, and e2e. macOS and Windows refuse.
3. Egress proxy (pure, fuzzed), namespaces and bridge, allowlist mode, CI with
   the AppArmor profile.
4. Docs and real-server runs. Then macOS, then Windows.

## 10. Decisions (owner, 2026-10-07)

1. **The Linux network part is built into mcpsum in Rust**: one binary, no
   extra packages, and the namespace code is mcpsum's to test. bubblewrap and
   srt remain documented alternatives; srt's macOS and Windows approaches
   inform §5.6.
2. **Fail closed:** a server whose sandbox cannot be enforced does not start.
   No "run unsandboxed" switch; to run without a sandbox, remove the policy.
