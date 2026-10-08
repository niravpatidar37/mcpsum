# Design 0006: Streamable HTTP transport and its authorization

- **Status:** proposed
- **Issue:** #20 (milestone M5)
- **Date:** 2026-10-08

## 1. Problem

mcpsum speaks stdio only. Remote MCP servers use the Streamable HTTP
transport, usually with OAuth. Users of remote servers get none of I1–I8.

The monitor is already transport-agnostic (JSON-RPC in, JSON-RPC out). What
is missing is an HTTP shell, and the security work that comes with it: TLS, a
network attacker, OAuth tokens, and URLs supplied by the server.

## 2. Spec summary (what we must implement)

From the 2026-07-28 revision (citations are to modelcontextprotocol.io):

- **Transport** ([Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)):
  one MCP endpoint; every client message is a new HTTP POST carrying one
  JSON-RPC request or notification; the response is JSON or an SSE stream.
  Every POST carries `MCP-Protocol-Version`, plus `Mcp-Method` and (for
  `tools/call`, `resources/read`, `prompts/get`) `Mcp-Name`, which must match
  the body. Servers must validate `Origin` against DNS rebinding.
- **No sessions any more.** 2026-07-28 removed `Mcp-Session-Id`, the
  `initialize` handshake, SSE resumability and the GET stream
  ([changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)).
  Servers on 2025-11-25 still use them
  ([transport, 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)).
- **Authorization** ([spec](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)):
  OAuth 2.1 (draft) with Protected Resource Metadata ([RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728)),
  Authorization Server Metadata ([RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414)),
  Resource Indicators ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html)),
  PKCE (clients must refuse an authorization server that does not advertise
  it) and `iss` validation ([RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207)).
  Tokens go in the `Authorization` header, never in the query string.
  "MCP servers MUST NOT accept or transit any other tokens."
- **Known attacks** ([security best practices](https://modelcontextprotocol.io/docs/2026-07-28/tutorials/security/security_best_practices)):
  token passthrough, confused deputy, SSRF through `resource_metadata`,
  `authorization_servers` and endpoint URLs chosen by the server, mix-up
  attacks, and unsafe authorization URLs (`javascript:`, `file:`).

The protocol-level changes of 2026-07-28 (stateless requests,
`server/discover`, multi round-trip requests) belong to the monitor and are
tracked separately (#21). This design covers the transport and authorization.

## 3. Options

| Option | Shape | For | Against |
|---|---|---|---|
| **A. stdio in, HTTP out** | The client starts `mcpsum proxy --name remote` as today; mcpsum is the MCP client *and* the OAuth client of the remote server. | Client configs do not change. mcpsum opens no listening port, so no DNS rebinding or local auth surface. The client never sees the token, so there is no passthrough. | mcpsum must implement an OAuth client (browser flow, loopback redirect, refresh, client registration). |
| B. HTTP in, HTTP out | mcpsum listens on `127.0.0.1` and forwards to the remote server. | Works for clients that only speak HTTP. | The client's token is issued for the remote server, but would be presented to mcpsum and passed on: the passthrough pattern the spec forbids. mcpsum would have to rewrite metadata or run its own authorization server. Needs `Origin` checks and local auth. |
| C. HTTP in, stdio out | Expose a local stdio server over HTTP. | Remote use of local servers. | Different product; out of scope. |

## 4. Proposed design (option A)

- **Lockfile.** A server entry has either `command` or `url` (`https://` only;
  `http://` only for loopback). The URL is part of the definitional key, so
  changing it means re-locking. Definitions are served from the lock as for
  stdio (I1).
- **Shell.** One HTTP/1.1 and HTTP/2 client with rustls and platform roots. No
  redirects followed with a token. Response size, SSE event size and stream
  duration are capped as for stdio (I7). Legacy servers: mcpsum keeps
  `Mcp-Session-Id` itself; the client never sees it.
- **Headers.** mcpsum builds `MCP-Protocol-Version`, `Mcp-Method` and
  `Mcp-Name` from the message it forwards, never from the model, so they
  cannot disagree with the body.
- **OAuth.** Authorization code with PKCE (S256), the `resource` parameter set
  to the locked URL, recorded issuer checked against `iss`, client ID metadata
  document or dynamic registration. The browser is opened only for `https`
  authorization URLs, without a shell.
- **SSRF.** Every URL learned from the server or its metadata must be `https`,
  must not resolve to loopback, private, link-local (including
  `169.254.169.254`) or multicast addresses, and is resolved once and pinned
  for the connection. The allowed authorization servers are recorded in the
  lock at approval time; a new one is drift, not a silent change.
- **Tokens.** Stored in the OS keychain (shared with design 0003), keyed by
  issuer and resource URL, sent only to the locked URL's origin, never logged:
  audit (I8) records the host and outcome. A 401 after refresh quarantines the
  server instead of retrying in a loop.

## 5. Threat model additions

- **A4 network attacker:** TLS with certificate validation; no plaintext except
  loopback.
- **Malicious remote server:** SSRF (above), header injection through
  `Mcp-Name` (mcpsum encodes it as the spec requires), oversize or endless SSE
  streams (caps), token phishing through a new authorization server (drift).
- **Malicious authorization server:** mix-up (`iss` check), open redirect.
- **Not covered:** a remote server's code can change at any time and cannot be
  pinned or sandboxed by mcpsum. I1 still stops *definition* changes; I5 does
  not apply.

## 6. Test plan

- A Python test server (uv) that speaks Streamable HTTP and runs the existing
  evil modes over HTTP, plus a fake authorization server.
- e2e: I1/I2/I3/I7/I8 tests repeated over HTTP; token never appears in the
  audit log, stderr or anything sent to the client (random canary token);
  metadata pointing at `127.0.0.1` or `169.254.169.254` is refused; `iss`
  mismatch and missing PKCE refuse; a redirect does not carry the token;
  `http://` to a non-loopback host is refused.
- Interop with one public remote MCP server, manual at first.
- Fuzz the SSE parser.

## 7. Open questions for the owner

1. Option A only, or is HTTP-in (B) needed for a specific client?
2. Support legacy 2025-11-25 HTTP servers (sessions, GET stream), or modern
   2026-07-28 only?
3. Client registration: client ID metadata documents only (DCR is deprecated
   in 2026-07-28), or both? A metadata document needs an `https` URL that the
   project hosts.
4. Which HTTP stack (hyper directly vs. reqwest) given the trusted-core size?
