//! I5 egress proxy (design 0002 §5.4): the only way out of a sandboxed
//! server's network namespace when its policy lists hosts.
//!
//! The server sees `HTTPS_PROXY=http://127.0.0.1:3128`, a listening socket
//! that mcpsum owns. For each connection mcpsum reads **one** HTTP `CONNECT
//! host:port` request (bounded in size and time) and checks it against
//! `policy.sandbox.network.allow`. It resolves the name itself, **once**, and
//! drops loopback, private, link-local (cloud metadata) and other non-public
//! addresses unless the user listed that IP literally. It audits the decision
//! (`host:port` only, never headers or payloads) *before* connecting, and then
//! connects only to an address it checked, so a DNS answer cannot change
//! between check and use. After that it relays bytes. TLS is not inspected.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::monitor::{AuditEvent, Decision, Dir};

/// Size, time and concurrency limits for clients of the proxy.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Request line plus headers, including the final empty line.
    pub max_head: usize,
    pub max_request_line: usize,
    /// Total time to send the whole head (slow-header defence).
    pub head_timeout: Duration,
    pub connect_timeout: Duration,
    /// Open connections at once; more are refused with 503.
    pub max_connections: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_head: 8 * 1024,
            max_request_line: 1024,
            head_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(10),
            max_connections: 64,
        }
    }
}

/// A destination host, as requested or as listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// Lowercase ASCII DNS name without a trailing dot.
    Name(String),
    /// Canonical: IPv4-mapped IPv6 addresses become IPv4.
    Ip(IpAddr),
}

/// A validated `host:port` from a `CONNECT` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: Host,
    pub port: u16,
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Name(n) => write!(f, "{n}:{}", self.port),
            Host::Ip(ip) => write!(f, "{}", SocketAddr::new(*ip, self.port)),
        }
    }
}

/// Normalise a DNS name: one trailing dot dropped, lowercase, LDH labels of
/// 1-63 characters, at most 253 in total. Non-ASCII (use punycode) and names
/// whose last label is numeric (`127.1`, `2130706433`: resolvers read those
/// as IPv4 addresses) are refused.
fn normalize_name(h: &str) -> Option<String> {
    let h = h.strip_suffix('.').unwrap_or(h).to_ascii_lowercase();
    let label_ok = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    let last_numeric = h
        .rsplit('.')
        .next()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    (h.len() <= 253 && h.split('.').all(label_ok) && !last_numeric).then_some(h)
}

/// Parse `name:port`, `1.2.3.4:port` or `[v6]:port` (no zone IDs).
fn parse_authority(s: &str) -> Option<Target> {
    let (host, port) = match s.strip_prefix('[') {
        Some(rest) => {
            let (h, p) = rest.split_once("]:")?;
            (
                Host::Ip(h.parse::<IpAddr>().ok().filter(IpAddr::is_ipv6)?.to_canonical()),
                p,
            )
        }
        None => {
            let (h, p) = s.rsplit_once(':')?;
            match h.parse::<Ipv4Addr>() {
                Ok(ip) => (Host::Ip(IpAddr::V4(ip)), p),
                Err(_) => (Host::Name(normalize_name(h)?), p),
            }
        }
    };
    if !(1..=5).contains(&port.len()) || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
    Some(Target { host, port })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostRule {
    Exact(String),
    /// `*.example.com` stored as `.example.com`: subdomains only.
    Suffix(String),
    Ip(IpAddr),
}

/// The parsed `policy.sandbox.network.allow`.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    rules: Vec<(HostRule, u16)>,
}

impl Allowlist {
    pub fn parse(entries: &[String]) -> Result<Self> {
        let rules = entries
            .iter()
            .map(|e| {
                crate::lock::check_net_entry(e)?;
                let (wild, rest) = match e.strip_prefix("*.") {
                    Some(rest) => (true, rest),
                    None => (false, e.as_str()),
                };
                let t = parse_authority(rest)
                    .with_context(|| format!("network allow entry `{e}` is not a valid host:port"))?;
                let rule = match (t.host, wild) {
                    (Host::Name(n), false) => HostRule::Exact(n),
                    (Host::Name(n), true) => HostRule::Suffix(format!(".{n}")),
                    (Host::Ip(ip), false) => HostRule::Ip(ip),
                    (Host::Ip(_), true) => anyhow::bail!("network allow entry `{e}`: `*.` needs a host name"),
                };
                Ok((rule, t.port))
            })
            .collect::<Result<_>>()?;
        Ok(Self { rules })
    }

    fn allows_name(&self, name: &str, port: u16) -> bool {
        self.rules.iter().any(|(r, p)| {
            *p == port
                && match r {
                    HostRule::Exact(h) => h == name,
                    HostRule::Suffix(s) => name.ends_with(s.as_str()),
                    HostRule::Ip(_) => false,
                }
        })
    }

    fn allows_ip(&self, ip: IpAddr, port: u16) -> bool {
        let ip = ip.to_canonical();
        self.rules.iter().any(|(r, p)| *p == port && *r == HostRule::Ip(ip))
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(o[0] == 0 // "this network"
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local() // 169.254/16, cloud metadata
        || ip.is_multicast()
        || ip.is_documentation()
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 shared (CGNAT, some metadata services)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0/24 protocol assignments
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18/15 benchmarking
        || o[0] >= 240) // reserved and broadcast
}

/// True for addresses on the public internet. Everything a DNS answer could
/// use to reach this machine, its LAN or a cloud metadata service is false.
pub fn is_public(ip: IpAddr) -> bool {
    let v6 = match ip.to_canonical() {
        IpAddr::V4(v4) => return is_public_v4(v4),
        IpAddr::V6(v6) => v6,
    };
    let s = v6.segments();
    let embedded = |hi: u16, lo: u16| Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo));
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return is_public_v4(embedded(s[6], s[7])); // NAT64
    }
    if s[0] == 0x2002 {
        return is_public_v4(embedded(s[1], s[2])); // 6to4
    }
    if s[..6] == [0, 0, 0, 0, 0xffff, 0] {
        return is_public_v4(embedded(s[6], s[7])); // IPv4-translated (RFC 6145)
    }
    !(s[..6] == [0; 6] // ::, ::1 and IPv4-compatible
        || v6.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // unique local
        || (s[0] & 0xffc0) == 0xfe80 // link-local
        || (s[0] & 0xffc0) == 0xfec0 // site-local (deprecated)
        || (s[0] == 0x2001 && (s[1] == 0 || s[1] == 0xdb8)) // Teredo, documentation
        || s[..3] == [0x64, 0xff9b, 1] // local-use NAT64 (RFC 8215): may embed private IPv4
        || s[..4] == [0x100, 0, 0, 0]) // discard-only
}

/// Why a connection was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Malformed,
    NotConnect,
    TooLarge,
    Timeout,
    Busy,
    Policy(&'static str),
    Unresolved,
    Unreachable,
    AuditFailed,
}

impl Refusal {
    fn status(&self) -> &'static str {
        match self {
            Refusal::Malformed => "400 Bad Request",
            Refusal::NotConnect => "405 Method Not Allowed",
            Refusal::TooLarge => "431 Request Header Fields Too Large",
            Refusal::Timeout => "408 Request Timeout",
            Refusal::Busy => "503 Service Unavailable",
            Refusal::Policy(_) => "403 Forbidden",
            Refusal::Unresolved | Refusal::Unreachable => "502 Bad Gateway",
            Refusal::AuditFailed => "500 Internal Server Error",
        }
    }

    fn reason(&self) -> &'static str {
        match self {
            Refusal::Malformed => "malformed request",
            Refusal::NotConnect => "only CONNECT is supported (HTTPS through the proxy)",
            Refusal::TooLarge => "request head too large",
            Refusal::Timeout => "request head not received in time",
            Refusal::Busy => "too many open connections",
            Refusal::Policy(why) => why,
            Refusal::Unresolved => "name did not resolve",
            Refusal::Unreachable => "destination unreachable",
            Refusal::AuditFailed => "audit log write failed (fail closed)",
        }
    }
}

const NOT_LISTED: &str = "not listed in policy.sandbox.network.allow";
const IP_NOT_LISTED: &str = "IP address not listed literally in policy.sandbox.network.allow";
const NOT_PUBLIC: &str = "resolves only to loopback, private, link-local or other non-public addresses \
                          (list the IP literally to allow it)";

/// Parse a complete request head (ending in an empty line). Only
/// `CONNECT authority HTTP/1.x` passes; headers are checked for syntax and
/// otherwise ignored.
pub fn parse_head(head: &[u8], limits: &Limits) -> Result<Target, Refusal> {
    let text = std::str::from_utf8(head).map_err(|_| Refusal::Malformed)?;
    let body = text.strip_suffix("\r\n\r\n").ok_or(Refusal::Malformed)?;
    let mut lines = body.split("\r\n");
    let request = lines.next().unwrap_or_default();
    if request.len() > limits.max_request_line {
        return Err(Refusal::TooLarge);
    }
    let bad_char = |l: &str| l.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f);
    let mut parts = request.split(' ');
    let (Some(method), Some(authority), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Refusal::Malformed);
    };
    if bad_char(request) || !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Err(Refusal::Malformed);
    }
    if method != "CONNECT" {
        let token = !method.is_empty() && method.bytes().all(|b| b.is_ascii_uppercase());
        return Err(if token { Refusal::NotConnect } else { Refusal::Malformed });
    }
    for h in lines {
        if bad_char(h) || h.starts_with([' ', '\t']) || h.split_once(':').is_none_or(|(k, _)| k.is_empty()) {
            return Err(Refusal::Malformed);
        }
    }
    parse_authority(authority).ok_or(Refusal::Malformed)
}

/// Read the head up to and including the empty line, within the limits.
/// Returns the head and any bytes the client sent after it.
fn read_head(s: &mut TcpStream, limits: &Limits) -> Result<(Vec<u8>, Vec<u8>), Refusal> {
    let deadline = Instant::now() + limits.head_timeout;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Refusal::Timeout);
        }
        s.set_read_timeout(Some(left)).map_err(|_| Refusal::Malformed)?;
        let n = match s.read(&mut chunk) {
            Ok(0) => return Err(Refusal::Malformed),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                return Err(Refusal::Timeout)
            }
            Err(_) => return Err(Refusal::Malformed),
        };
        let from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf[from..].windows(4).position(|w| w == b"\r\n\r\n") {
            let end = from + pos + 4;
            if end > limits.max_head {
                return Err(Refusal::TooLarge);
            }
            let extra = buf.split_off(end);
            return Ok((buf, extra));
        }
        if buf.len() > limits.max_head {
            return Err(Refusal::TooLarge);
        }
    }
}

/// Writes one audit event; an error means "not recorded".
pub type AuditSink = Arc<dyn Fn(&AuditEvent) -> Result<()> + Send + Sync>;
/// Resolves a name to addresses. Injected so tests can map names.
pub type Resolver = Arc<dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync>;

/// The operating system's resolver (`getaddrinfo`).
pub fn system_resolver() -> Resolver {
    Arc::new(|host, port| Ok((host, port).to_socket_addrs()?.collect()))
}

fn event(target: Option<&Target>, decision: Decision, reason: String) -> AuditEvent {
    AuditEvent {
        dir: Dir::Internal,
        method: Some("egress/connect".into()),
        subject: target.map(Target::to_string),
        decision,
        reason,
        args_digest: None,
    }
}

/// The egress proxy for one server.
#[derive(Clone)]
pub struct Egress {
    pub allow: Arc<Allowlist>,
    pub audit: AuditSink,
    pub resolve: Resolver,
    pub limits: Limits,
}

impl Egress {
    /// The checked addresses `t` may be reached at, or why not. Resolves at
    /// most once; the caller connects only to what this returns.
    pub fn decide(&self, t: &Target) -> Result<Vec<SocketAddr>, Refusal> {
        let name = match &t.host {
            Host::Ip(ip) if self.allow.allows_ip(*ip, t.port) => return Ok(vec![SocketAddr::new(*ip, t.port)]),
            Host::Ip(_) => return Err(Refusal::Policy(IP_NOT_LISTED)),
            Host::Name(n) => n,
        };
        if !self.allow.allows_name(name, t.port) {
            return Err(Refusal::Policy(NOT_LISTED));
        }
        let addrs = (self.resolve)(name, t.port).map_err(|_| Refusal::Unresolved)?;
        let ok: Vec<SocketAddr> = addrs
            .into_iter()
            .map(|a| SocketAddr::new(a.ip().to_canonical(), t.port))
            .filter(|a| is_public(a.ip()) || self.allow.allows_ip(a.ip(), t.port))
            .collect();
        if ok.is_empty() {
            return Err(Refusal::Policy(NOT_PUBLIC));
        }
        Ok(ok)
    }

    /// Read and check one request, audit the decision, connect. Every
    /// connection is audited exactly once.
    fn admit(&self, client: &mut TcpStream) -> Result<(TcpStream, Vec<u8>), Refusal> {
        let deny = |t: Option<&Target>, r: Refusal| {
            // Denied either way; a failed write cannot widen anything.
            let _ = (self.audit)(&event(t, Decision::Deny, format!("egress denied: {}", r.reason())));
            r
        };
        let (head, extra) = read_head(client, &self.limits).map_err(|r| deny(None, r))?;
        let target = parse_head(&head, &self.limits).map_err(|r| deny(None, r))?;
        let addrs = self.decide(&target).map_err(|r| deny(Some(&target), r))?;
        // Write-ahead: no record, no connection.
        let allowed = event(
            Some(&target),
            Decision::Allow,
            "egress allowed by policy.sandbox.network.allow".into(),
        );
        (self.audit)(&allowed).map_err(|_| Refusal::AuditFailed)?;
        let upstream = addrs
            .iter()
            .find_map(|a| TcpStream::connect_timeout(a, self.limits.connect_timeout).ok())
            .ok_or(Refusal::Unreachable)?;
        Ok((upstream, extra))
    }

    fn handle(&self, mut client: TcpStream) {
        let _ = client.set_nonblocking(false);
        match self.admit(&mut client) {
            Ok((upstream, extra)) => tunnel(client, upstream, &extra),
            Err(r) => respond(&mut client, &r),
        }
    }

    /// Serve `listener` on a background thread until the handle is dropped.
    pub fn serve(self, listener: TcpListener) -> io::Result<EgressHandle> {
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let active = Arc::new(AtomicUsize::new(0));
        let thread = thread::Builder::new().name("mcpsum-egress".into()).spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                let Ok((mut client, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(20));
                    continue;
                };
                if active.fetch_add(1, Ordering::SeqCst) >= self.limits.max_connections {
                    active.fetch_sub(1, Ordering::SeqCst);
                    let _ = client.set_nonblocking(false);
                    let r = Refusal::Busy;
                    let _ = (self.audit)(&event(None, Decision::Deny, format!("egress denied: {}", r.reason())));
                    respond(&mut client, &r);
                    continue;
                }
                let me = self.clone();
                let guard = ActiveGuard(active.clone());
                let spawned = thread::Builder::new().spawn(move || {
                    let _guard = guard;
                    me.handle(client);
                });
                drop(spawned); // on failure the closure (and guard) is dropped: client closed
            }
        })?;
        Ok(EgressHandle {
            stop,
            thread: Some(thread),
        })
    }
}

struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Stops accepting new connections when dropped (open tunnels end when
/// either side closes).
pub struct EgressHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for EgressHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn respond(client: &mut TcpStream, r: &Refusal) {
    let body = format!("mcpsum egress: {}\n", r.reason());
    let msg = format!(
        "HTTP/1.1 {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        r.status(),
        body.len()
    );
    let _ = client.set_write_timeout(Some(Duration::from_secs(2)));
    let _ = client.write_all(msg.as_bytes());
    let _ = client.shutdown(Shutdown::Write);
    // Drain a little of what the client is still sending, so closing does not
    // reset the connection before it has read the answer.
    let _ = client.set_read_timeout(Some(Duration::from_millis(200)));
    let _ = io::copy(&mut client.take(64 * 1024), &mut io::sink());
}

fn tunnel(mut client: TcpStream, mut upstream: TcpStream, extra: &[u8]) {
    let _ = client.set_read_timeout(None);
    if client
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .is_err()
        || upstream.write_all(extra).is_err()
    {
        return;
    }
    let (Ok(mut c2), Ok(mut u2)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let up = thread::spawn(move || {
        let _ = io::copy(&mut c2, &mut u2);
        let _ = u2.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut upstream, &mut client);
    let _ = client.shutdown(Shutdown::Write);
    let _ = up.join();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn allow(entries: &[&str]) -> Allowlist {
        Allowlist::parse(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    fn target(s: &str) -> Target {
        parse_authority(s).unwrap_or_else(|| panic!("{s}"))
    }

    #[test]
    fn i5_allowlist_matches_exact_suffix_case_trailing_dot_and_port() {
        let a = allow(&["api.github.com:443", "*.example.com:443", "10.0.0.5:8080", "[::1]:9000"]);
        assert!(a.allows_name(&normalize_name("API.GitHub.com.").unwrap(), 443));
        assert!(!a.allows_name("api.github.com", 80), "port must match");
        assert!(!a.allows_name("github.com", 443) && !a.allows_name("evilapi.github.com", 443));
        assert!(a.allows_name("a.example.com", 443) && a.allows_name("a.b.example.com", 443));
        assert!(!a.allows_name("example.com", 443), "`*.` means subdomains only");
        assert!(!a.allows_name("badexample.com", 443));
        assert!(a.allows_ip("10.0.0.5".parse().unwrap(), 8080));
        assert!(
            a.allows_ip("::ffff:10.0.0.5".parse().unwrap(), 8080),
            "IPv4-mapped is the same IP"
        );
        assert!(!a.allows_ip("10.0.0.5".parse().unwrap(), 443));
        assert!(a.allows_ip("::1".parse().unwrap(), 9000));
        assert!(Allowlist::parse(&["*.1.2.3.4:443".into()]).is_err());
    }

    #[test]
    fn i5_connect_authority_is_strict() {
        assert_eq!(
            target("[::ffff:127.0.0.1]:80").host,
            Host::Ip("127.0.0.1".parse().unwrap())
        );
        assert_eq!(target("Example.COM.:443").to_string(), "example.com:443");
        assert_eq!(target("[2001:db8::1]:443").to_string(), "[2001:db8::1]:443");
        for bad in [
            "example.com",
            "example.com:0",
            "example.com:65536",
            "example.com:+443",
            "example.com:0443x",
            ":443",
            "[fe80::1%eth0]:443",
            "[1.2.3.4]:443",
            "127.1:80",
            "2130706433:80",
            "0x7f.0.0.1:80",
            "exa_mple.com:443",
            "b\u{fc}cher.de:443",
            "-a.com:443",
            "a..com:443",
            "user@example.com:443",
        ] {
            assert!(parse_authority(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn i5_only_connect_heads_parse() {
        let l = Limits::default();
        let ok = b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\nProxy-Authorization: x\r\n\r\n";
        assert_eq!(parse_head(ok, &l).unwrap().to_string(), "api.github.com:443");
        let cases: [(&[u8], Refusal); 9] = [
            (b"GET http://example.com/ HTTP/1.1\r\n\r\n", Refusal::NotConnect),
            (b"POST / HTTP/1.1\r\n\r\n", Refusal::NotConnect),
            (b"connect a.com:443 HTTP/1.1\r\n\r\n", Refusal::Malformed),
            (b"CONNECT a.com:443 HTTP/2\r\n\r\n", Refusal::Malformed),
            (b"CONNECT  a.com:443 HTTP/1.1\r\n\r\n", Refusal::Malformed),
            (b"CONNECT a.com:443 HTTP/1.1\r\nNoColon\r\n\r\n", Refusal::Malformed),
            (b"CONNECT a.com:443 HTTP/1.1\r\nX: a\nY: b\r\n\r\n", Refusal::Malformed),
            (b"CONNECT a.com:443 HTTP/1.1\r\n folded\r\n\r\n", Refusal::Malformed),
            (b"CONNECT \xff.com:443 HTTP/1.1\r\n\r\n", Refusal::Malformed),
        ];
        for (head, want) in cases {
            assert_eq!(parse_head(head, &l), Err(want), "{}", String::from_utf8_lossy(head));
        }
        let long = format!("CONNECT {}.com:443 HTTP/1.1\r\n\r\n", "a".repeat(2000));
        assert_eq!(parse_head(long.as_bytes(), &l), Err(Refusal::TooLarge));
    }

    #[test]
    fn i5_non_public_addresses_are_recognised() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.100.200",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "192.0.0.8",
            "198.18.0.1",
            "192.0.2.1",
            "::",
            "::1",
            "fe80::1",
            "fd00:ec2::254",
            "fc00::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::7f00:1",
            "2002:a9fe:a9fe::",
            "2001:db8::1",
            "2001::1",
            "::127.0.0.1",
            "::ffff:0:a00:1",     // IPv4-translated 10.0.0.1 (RFC 6145)
            "::ffff:0:a9fe:a9fe", // IPv4-translated 169.254.169.254
            "64:ff9b:1::a00:1",   // local-use NAT64 (RFC 8215)
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "140.82.112.3", "2606:4700:4700::1111", "64:ff9b::808:808"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    type Events = Arc<Mutex<Vec<AuditEvent>>>;

    fn egress(entries: &[&str], resolve: Resolver, limits: Limits) -> (Egress, Events) {
        let events: Events = Arc::default();
        let sink = events.clone();
        let audit: AuditSink = Arc::new(move |e: &AuditEvent| {
            sink.lock().unwrap().push(e.clone());
            Ok(())
        });
        let e = Egress {
            allow: Arc::new(allow(entries)),
            audit,
            resolve,
            limits,
        };
        (e, events)
    }

    /// Resolves `name` to the given addresses and counts lookups.
    fn fixed(answers: &'static [&'static str], count: Arc<AtomicUsize>) -> Resolver {
        Arc::new(move |_h, port| {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(answers
                .iter()
                .map(|a| SocketAddr::new(a.parse().unwrap(), port))
                .collect())
        })
    }

    #[test]
    fn i5_decide_refuses_raw_ips_and_names_resolving_inward() {
        let n = Arc::new(AtomicUsize::new(0));
        let (e, _) = egress(&["svc.test:443"], fixed(&["127.0.0.1"], n.clone()), Limits::default());
        assert_eq!(e.decide(&target("127.0.0.1:443")), Err(Refusal::Policy(IP_NOT_LISTED)));
        assert_eq!(e.decide(&target("svc.test:443")), Err(Refusal::Policy(NOT_PUBLIC)));
        assert_eq!(e.decide(&target("other.test:443")), Err(Refusal::Policy(NOT_LISTED)));
        assert_eq!(e.decide(&target("svc.test:444")), Err(Refusal::Policy(NOT_LISTED)));
        assert_eq!(n.load(Ordering::SeqCst), 1, "names not listed are never resolved");

        // Metadata, and a mixed answer: only the checked public address is used.
        let (e, _) = egress(
            &["svc.test:80"],
            fixed(&["169.254.169.254"], Arc::default()),
            Limits::default(),
        );
        assert_eq!(e.decide(&target("svc.test:80")), Err(Refusal::Policy(NOT_PUBLIC)));
        let (e, _) = egress(
            &["svc.test:80"],
            fixed(&["10.0.0.1", "8.8.8.8", "::1"], Arc::default()),
            Limits::default(),
        );
        assert_eq!(
            e.decide(&target("svc.test:80")),
            Ok(vec!["8.8.8.8:80".parse().unwrap()])
        );

        // Listing the IP literally allows it, by name and directly.
        let (e, _) = egress(
            &["svc.test:443", "127.0.0.1:443"],
            fixed(&["127.0.0.1"], Arc::default()),
            Limits::default(),
        );
        assert_eq!(
            e.decide(&target("svc.test:443")),
            Ok(vec!["127.0.0.1:443".parse().unwrap()])
        );
        assert_eq!(
            e.decide(&target("[::ffff:127.0.0.1]:443")),
            Ok(vec!["127.0.0.1:443".parse().unwrap()])
        );
    }

    // ---- the proxy over real sockets (an echo server stands in for the internet)

    fn echo_server() -> (u16, Arc<AtomicUsize>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let a = accepted.clone();
        thread::spawn(move || {
            for s in l.incoming().flatten() {
                a.fetch_add(1, Ordering::SeqCst);
                thread::spawn(move || {
                    let mut r = s.try_clone().unwrap();
                    let mut w = s;
                    let _ = io::copy(&mut r, &mut w);
                });
            }
        });
        (port, accepted)
    }

    struct Running {
        port: u16,
        events: Events,
        _h: EgressHandle,
    }

    fn start(entries: &[&str], limits: Limits) -> Running {
        let resolve: Resolver = Arc::new(|h, port| match h {
            "allowed.test" | "rebind.test" => Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))]),
            _ => Err(io::Error::other("no such host")),
        });
        let (e, events) = egress(entries, resolve, limits);
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        Running {
            port,
            events,
            _h: e.serve(l).unwrap(),
        }
    }

    fn connect(proxy: u16, head: &[u8]) -> (TcpStream, String) {
        let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.write_all(head).unwrap();
        let status = read_status(&mut s);
        (s, status)
    }

    fn read_status(s: &mut TcpStream) -> String {
        let mut got = Vec::new();
        let mut b = [0u8; 1];
        while !got.ends_with(b"\r\n\r\n") {
            match s.read(&mut b) {
                Ok(1) => got.push(b[0]),
                _ => break,
            }
        }
        String::from_utf8_lossy(&got)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    }

    fn wait_events(r: &Running, n: usize) -> Vec<AuditEvent> {
        let deadline = Instant::now() + Duration::from_secs(10);
        while r.events.lock().unwrap().len() < n && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        r.events.lock().unwrap().clone()
    }

    #[test]
    fn i5_proxy_tunnels_only_to_listed_destinations_and_audits_each() {
        let (up, accepted) = echo_server();
        let (listed, ip_listed) = (format!("allowed.test:{up}"), format!("127.0.0.1:{up}"));
        let r = start(&[&listed, &ip_listed, "rebind.test:443"], Limits::default());

        let head = format!("CONNECT allowed.test:{up} HTTP/1.1\r\nProxy-Authorization: Basic SECRETTOKEN\r\n\r\nearly");
        let (mut s, status) = connect(r.port, head.as_bytes());
        assert_eq!(status, "HTTP/1.1 200 Connection established");
        s.write_all(b"-ping").unwrap();
        let mut buf = [0u8; 10];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"early-ping", "bytes sent with the head are forwarded too");

        let denied = [
            (format!("CONNECT example.org:{up} HTTP/1.1\r\n\r\n"), "403"),
            (format!("CONNECT allowed.test:{} HTTP/1.1\r\n\r\n", up + 1), "403"),
            ("CONNECT rebind.test:443 HTTP/1.1\r\n\r\n".to_string(), "403"),
            (format!("CONNECT 127.0.0.2:{up} HTTP/1.1\r\n\r\n"), "403"),
            (
                format!("GET http://allowed.test:{up}/secret-path HTTP/1.1\r\n\r\n"),
                "405",
            ),
            ("garbage\r\n\r\n".to_string(), "400"),
        ];
        for (head, code) in &denied {
            let (_, status) = connect(r.port, head.as_bytes());
            assert!(status.starts_with(&format!("HTTP/1.1 {code}")), "{head:?}: {status}");
        }
        let events = wait_events(&r, 1 + denied.len());
        assert_eq!(
            events.len(),
            1 + denied.len(),
            "one audit event per connection: {events:?}"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "denied requests never reach the destination"
        );
        assert_eq!(events[0].decision, Decision::Allow);
        assert_eq!(events[0].subject.as_deref(), Some(listed.as_str()));
        let subjects: Vec<_> = events[1..].iter().map(|e| (e.decision, e.subject.clone())).collect();
        assert_eq!(subjects[0], (Decision::Deny, Some(format!("example.org:{up}"))));
        assert_eq!(subjects[3], (Decision::Deny, Some(format!("127.0.0.2:{up}"))));
        assert_eq!(subjects[4], (Decision::Deny, None), "no path or URL from a refused GET");
        let all = format!("{events:?}");
        assert!(!all.contains("SECRETTOKEN") && !all.contains("secret-path"), "{all}");
    }

    #[test]
    fn i5_proxy_bounds_head_size_time_and_connections() {
        let (up, _) = echo_server();
        let limits = Limits {
            head_timeout: Duration::from_millis(400),
            max_connections: 2,
            ..Limits::default()
        };
        let r = start(&[&format!("127.0.0.1:{up}")], limits);

        // Oversized, with and without an end: refused as soon as the limit is
        // passed, not after the timeout.
        for end in ["\r\n\r\n", ""] {
            let huge = format!("CONNECT 127.0.0.1:{up} HTTP/1.1\r\nX: {}{end}", "a".repeat(20_000));
            let (_, status) = connect(r.port, huge.as_bytes());
            assert!(status.starts_with("HTTP/1.1 431"), "{end:?}: {status}");
        }

        // Slow headers: a byte at a time, never finishing in time.
        let started = Instant::now();
        let mut slow = TcpStream::connect(("127.0.0.1", r.port)).unwrap();
        slow.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        for b in b"CONNECT 127.0.0.1" {
            if slow.write_all(&[*b]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert!(read_status(&mut slow).starts_with("HTTP/1.1 408"));
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(slow);
        thread::sleep(Duration::from_millis(500)); // refused handlers drain for up to 200 ms

        // Two idle connections fill the limit; the third is refused.
        let _a = TcpStream::connect(("127.0.0.1", r.port)).unwrap();
        let _b = TcpStream::connect(("127.0.0.1", r.port)).unwrap();
        thread::sleep(Duration::from_millis(100));
        let (_, status) = connect(r.port, format!("CONNECT 127.0.0.1:{up} HTTP/1.1\r\n\r\n").as_bytes());
        assert!(status.starts_with("HTTP/1.1 503"), "{status}");
        let events = wait_events(&r, 3);
        assert!(events.iter().all(|e| e.decision == Decision::Deny), "{events:?}");
    }

    #[test]
    fn i5_proxy_does_not_connect_when_the_audit_log_fails() {
        let (up, accepted) = echo_server();
        let resolve = system_resolver();
        let audit: AuditSink = Arc::new(|_| anyhow::bail!("disk full"));
        let e = Egress {
            allow: Arc::new(allow(&[&format!("127.0.0.1:{up}")])),
            audit,
            resolve,
            limits: Limits::default(),
        };
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let _h = e.serve(l).unwrap();
        let (_, status) = connect(port, format!("CONNECT 127.0.0.1:{up} HTTP/1.1\r\n\r\n").as_bytes());
        assert!(status.starts_with("HTTP/1.1 500"), "{status}");
        assert_eq!(accepted.load(Ordering::SeqCst), 0);
    }
}
