# Design 0003: Credential broker (I4)

- **Status:** proposed
- **Issue:** #15 (milestone M2)
- **Date:** 2026-10-08

## 1. Problem

`mcpsum lock --env GITHUB_TOKEN` passes the raw secret to the server process.
mcpsum keeps the value out of the lockfile and the audit log, but the server
can still read it. A malicious or compromised server can then:

- send it to a host it chooses (blocked by the I5 sandbox, design 0002);
- send it out through an API it is allowed to call, for example by putting it in
  a gist or an issue (not blocked by I5);
- keep using it after the session ends, because it is long-lived.

The postmark-mcp case (GUARANTEES, Limits 2) is the second kind: harm done
through an allowed API with a credential the user handed over.

## 2. Goals and non-goals

**Goal (I4).** A server with a `policy.credentials` section never sees a
long-lived secret. It gets either a placeholder or a short-lived, narrowly
scoped token, and the real secret is only ever used on the allowlisted hosts.

**Non-goals:**

- Stopping abuse of the API *within* the granted scope. A token that may send
  mail can still send mail; I4 shrinks what a stolen credential is worth.
- Inspecting request bodies or enforcing per-call API policy (possible later on
  top of option A).
- macOS and Windows in v1: this depends on the I5 egress proxy, which is Linux
  only.

## 3. Threat model

- **Attacker:** the server's code, as in design 0002 §3.
- **Goals:** read the secret (environment, `/proc`, files, memory of its own
  process), make the broker reveal it (an endpoint that echoes request
  headers back, a redirect to another host, an error message), or use the
  secret outside the policy.
- **Trusted:** mcpsum, the kernel, the user's policy and the secret store.

## 4. Options

| Option | How | For | Against |
|---|---|---|---|
| **A. Placeholder + injection at the egress proxy** | The server gets `MCPSUM_PLACEHOLDER_<random>`. The I5 egress proxy terminates TLS for allowlisted hosts and replaces the placeholder with the real secret in one named header. The pattern of CyberArk's [Secretless Broker](https://github.com/cyberark/secretless-broker), which "relieves client applications of the need to directly handle secrets". | Works for any static API key. The server never holds the secret. Matches the issue's acceptance test. | TLS termination needs a local CA that only the sandboxed server trusts, and a much larger trusted core (HTTP/1.1 and HTTP/2 parsing). Servers that pin certificates break. |
| **B. Short-lived scoped tokens** | mcpsum mints a token per session with a provider API and passes it like `--env` today. GitHub App installation tokens can be limited to chosen repositories and permissions and "will expire after 1 hour" ([GitHub docs](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation)). OAuth token exchange ([RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html)) and cloud STS services do the same where they are offered. | No TLS interception. Small code per provider. Useful without the sandbox. | Provider-specific. The server *does* hold a working token for its lifetime, so it can still leak it through the allowed API. |
| **C. Secret store only** | Read `--env` values from the OS keychain or a secret manager instead of the shell. | Small. Secrets leave the shell environment. | The server still gets the raw secret. Hygiene, not a guarantee. |
| D. mcpsum calls the API itself | The server asks mcpsum to make the call. | Strongest. | Needs servers written for it. Not a proxy any more. |

## 5. Proposed design

Ship in layers, smallest first:

1. **C as the base.** Secrets come from the OS keychain (or a named secret
   manager), never from the lockfile, logs, audit log or error messages.
2. **B for providers that support it**, starting with GitHub App installation
   tokens: minted at proxy start, scoped by the policy, revoked on exit where
   the provider allows it.
3. **A for static API keys**, once the I5 allowlist (design 0002 §5.4) ships.

Policy sketch (user-authored, outside the digests, kept on re-lock like
`policy.taint` and `policy.sandbox`):

```json
"policy": {
  "credentials": {
    "GITHUB_TOKEN": { "github-app": { "repositories": ["org/repo"], "permissions": { "issues": "write" } } },
    "POSTMARK_TOKEN": { "inject": { "host": "api.postmarkapp.com:443", "header": "X-Postmark-Server-Token" } }
  }
}
```

Rules for option A:

- Inject only on a TLS connection to the listed host and port, only into the
  listed header, and only when the header value equals the placeholder
  exactly. Never in bodies, URLs or other headers.
- Do not follow redirects for the server, and never inject on a connection the
  server opened to any other host.
- The local CA key lives only in mcpsum's memory and is regenerated per proxy
  start; the CA certificate is passed through `SSL_CERT_FILE`,
  `NODE_EXTRA_CA_CERTS` and `REQUESTS_CA_BUNDLE`.
- Audit (I8): host, header name and allow/deny. Never the value.
- If the secret store, provider or proxy is unavailable, the server does not
  start (I7).

## 6. Limits

- **Reflection.** An allowlisted API that echoes request headers back (a debug
  endpoint, an error message that quotes the header) returns the real secret to
  the server. A and B both narrow this, neither removes it. List narrow hosts.
- **Scope is only as narrow as the provider allows.** Many APIs have no scoped
  or short-lived tokens; for them only A helps.
- **TLS termination is new trusted code.** It must be fuzzed like the monitor.
- Abuse of the granted scope is not prevented (§2).

## 7. Test plan

- e2e (Linux), the acceptance test from #15: an evil server mode dumps its
  environment and `/proc/self/environ` and calls an echo tool; neither contains
  the secret (a random canary generated at test time), while a call to an
  allowlisted local test API with the placeholder succeeds and the test API
  sees the real canary.
- Injection only on the listed host, header and exact placeholder; a redirect
  to another host carries the placeholder, not the secret.
- Unit: the secret never appears in audit entries, errors or `show` output.
- Fuzz the HTTP parsing in the egress proxy.
- Mutation checks: injecting on any host, or in any header, must fail a test.

## 8. Open questions for the owner

1. Order: B (GitHub tokens) first, or wait and ship A with the allowlist?
2. Is TLS termination inside mcpsum acceptable, given the larger trusted
   core, or should A run as a separate helper process?
3. Which secret stores in v1: OS keychain only, or also 1Password/Bitwarden
   CLIs and cloud secret managers?
4. Should a server with `policy.credentials` be required to also have
   `policy.sandbox` (otherwise the placeholder can be bypassed by reading the
   keychain directly)?
