//! Probe a live MCP server: handshake, then capture its full surface
//! (tools, prompts, resources, resource templates, instructions).
//!
//! The probe runs the server with a scrubbed environment. It does NOT sandbox
//! it yet (milestone M2): the server's code runs on this host with the user's
//! filesystem permissions, exactly as it would under an MCP client.

use std::io::{BufReader, Write};
use std::process::ChildStdin;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

use crate::framing::{BoundedLines, Frame};
use crate::lock::{Surface, MAX_ITEMS_PER_KIND};
use crate::monitor::{modern_meta, META_SERVER_INFO, MODERN_VERSIONS};
use crate::process::{relay_stderr, spawn_server};

/// Newest `initialize` (legacy) revision we speak. The server's era is
/// detected first, per the 2026-07-28 stdio backward-compatibility rules.
pub const PROBE_PROTOCOL_VERSION: &str = "2025-11-25";
/// 2026-07-28 errors that identify a modern server (`MissingRequiredClientCapabilityError`,
/// `UnsupportedProtocolVersionError`): never a reason to fall back to `initialize`.
const MODERN_ERRORS: [i64; 2] = [-32021, -32022];
const MAX_PAGES: usize = 50;
/// Messages queued for a server that is not reading its stdin. Beyond this
/// the probe fails instead of waiting: a full pipe must not outlast the timeout.
const MAX_PENDING_WRITES: usize = 256;

#[derive(Debug, Clone)]
pub struct ProbeOptions {
    pub timeout: Duration,
    pub max_line_bytes: usize,
    /// I5: probe the server inside its sandbox (re-lock and verify).
    pub sandbox: Option<crate::sandbox::SandboxSpec>,
    /// The server is locked over `initialize`: try that era first (re-lock,
    /// verify), so a server that speaks both keeps the era it was locked in.
    pub prefer_legacy: bool,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_line_bytes: 4 * 1024 * 1024,
            sandbox: None,
            prefer_legacy: false,
        }
    }
}

struct Session {
    /// Lines for the writer thread (see `spawn_writer`).
    out: SyncSender<Vec<u8>>,
    rx: Receiver<std::io::Result<Frame>>,
    next_id: u64,
    timeout: Duration,
    /// 2026-07-28: `_meta` sent with every request (none for legacy servers).
    meta: Option<Value>,
}

impl Session {
    /// Never blocks: a server that stops reading stdin (a full pipe) would
    /// otherwise hang the probe past its timeout.
    fn write(&mut self, msg: &Value) -> Result<()> {
        let mut line = serde_json::to_vec(msg)?;
        line.push(b'\n');
        match self.out.try_send(line) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                bail!("the server is not reading its input ({MAX_PENDING_WRITES} messages pending)")
            }
            Err(TrySendError::Disconnected(_)) => bail!("writing to server: its input is closed"),
        }
    }

    /// Send a request and wait for its response. Server-initiated requests are
    /// refused (ping answered); notifications and unrelated messages ignored.
    fn request(&mut self, method: &str, params: Value) -> Result<std::result::Result<Value, Value>> {
        match self.request_or_timeout(method, params)? {
            Some(r) => Ok(r),
            None => bail!("timed out after {:?} waiting for `{method}`", self.timeout),
        }
    }

    /// Like `request`, but a timeout is `None` rather than an error.
    fn request_or_timeout(&mut self, method: &str, params: Value) -> Result<Option<std::result::Result<Value, Value>>> {
        let id = self.next_id;
        self.next_id += 1;
        let mut params = params;
        if let (Some(meta), Some(p)) = (&self.meta, params.as_object_mut()) {
            p.insert("_meta".into(), meta.clone());
        }
        self.write(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        let deadline = Instant::now() + self.timeout;
        loop {
            // Checked first: `recv_timeout` still returns queued messages
            // once the time is up, so a flooding server would never time out.
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            let frame = match self.rx.recv_timeout(left) {
                Ok(f) => f.context("reading from server")?,
                Err(RecvTimeoutError::Timeout) => return Ok(None),
                Err(RecvTimeoutError::Disconnected) => bail!("server exited before answering `{method}`"),
            };
            let Frame::Line(line) = frame else { continue };
            let Ok(msg) = serde_json::from_slice::<Value>(&line) else {
                continue;
            };
            let Some(obj) = msg.as_object() else { continue };
            match (obj.get("method").and_then(Value::as_str), obj.get("id")) {
                (Some("ping"), Some(sid)) => {
                    let sid = sid.clone();
                    self.write(&json!({"jsonrpc": "2.0", "id": sid, "result": {}}))?;
                }
                (Some(_), Some(sid)) => {
                    let sid = sid.clone();
                    self.write(&json!({"jsonrpc": "2.0", "id": sid, "error": {"code": -32601, "message": "denied by mcpsum probe"}}))?;
                }
                (None, Some(rid)) if rid.as_u64() == Some(id) => {
                    if let Some(e) = obj.get("error") {
                        return Ok(Some(Err(e.clone())));
                    }
                    return Ok(Some(Ok(obj.get("result").cloned().unwrap_or(Value::Null))));
                }
                _ => {}
            }
        }
    }

    fn list_all(&mut self, method: &str, field: &str) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let params = match &cursor {
                Some(c) => json!({"cursor": c}),
                None => json!({}),
            };
            let res = match self.request(method, params)? {
                Ok(r) => r,
                // Not implemented counts as empty, matching the monitor's verification.
                Err(e) if e.get("code").and_then(Value::as_i64) == Some(-32601) => return Ok(out),
                Err(e) => bail!("`{method}` failed: {}", crate::render::escape_untrusted(&e.to_string())),
            };
            let (items, next) = list_page(method, field, &res)?;
            out.extend(items.iter().cloned());
            if out.len() > MAX_ITEMS_PER_KIND {
                bail!("server returned more than {MAX_ITEMS_PER_KIND} items for `{method}`");
            }
            match next {
                Some(c) => cursor = Some(c),
                None => return Ok(out),
            }
        }
        bail!("`{method}` exceeded {MAX_PAGES} pages")
    }
}

/// One page of a list result: its items and the next cursor. A 2026-07-28
/// result that is not `complete` (an input request) is refused.
fn list_page<'a>(method: &str, field: &str, res: &'a Value) -> Result<(&'a Vec<Value>, Option<String>)> {
    if res.get("resultType").is_some_and(|t| t != "complete") {
        bail!("`{method}` did not complete (resultType is not \"complete\")");
    }
    let items = res
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("`{method}` result has no `{field}` array"))?;
    Ok((items, res.get("nextCursor").and_then(Value::as_str).map(str::to_string)))
}

/// The opening of a 2026-07-28 server (`DiscoverResult`), as an empty surface.
/// Untrusted input: anything ambiguous is rejected (fail closed).
pub fn discover_surface(res: &Value) -> Result<Surface> {
    if res.get("resultType").is_some_and(|t| t != "complete") {
        bail!("server/discover did not complete (resultType is not \"complete\")");
    }
    let mut versions = res
        .get("supportedVersions")
        .and_then(Value::as_array)
        .context("server/discover result has no supportedVersions array")?
        .iter()
        .map(|v| v.as_str().map(str::to_string))
        .collect::<Option<Vec<_>>>()
        .context("server/discover supportedVersions must be strings")?;
    versions.sort();
    versions.dedup();
    let Some(pv) = MODERN_VERSIONS.iter().find(|m| versions.iter().any(|v| v == *m)) else {
        bail!(
            "the server supports {} only; mcpsum speaks {}",
            crate::render::escape_untrusted(&versions.join(", ")),
            MODERN_VERSIONS.join(", ")
        );
    };
    let capabilities = res
        .get("capabilities")
        .cloned()
        .filter(Value::is_object)
        .context("server/discover result has no capabilities object")?;
    let server_info = res
        .get("_meta")
        .and_then(|m| m.get(META_SERVER_INFO))
        .cloned()
        .filter(Value::is_object)
        .context("server/discover result has no serverInfo in `_meta` (mcpsum needs it to serve legacy clients)")?;
    let instructions = match res.get("instructions") {
        None | Some(Value::Null) => None,
        Some(Value::String(i)) => Some(i.clone()),
        Some(_) => bail!("server/discover instructions is not a string"),
    };
    Ok(Surface {
        protocol_version: pv.to_string(),
        supported_versions: Some(versions),
        server_info,
        instructions,
        capabilities,
        tools: vec![],
        prompts: vec![],
        resources: vec![],
        resource_templates: vec![],
    })
}

fn legacy_surface(init: &Value) -> Result<Surface> {
    let protocol_version = init
        .get("protocolVersion")
        .and_then(Value::as_str)
        .context("initialize result has no protocolVersion")?
        .to_string();
    let capabilities = init
        .get("capabilities")
        .cloned()
        .filter(Value::is_object)
        .context("initialize result has no capabilities")?;
    let server_info = init
        .get("serverInfo")
        .cloned()
        .filter(Value::is_object)
        .context("initialize result has no serverInfo")?;
    let instructions = init.get("instructions").and_then(Value::as_str).map(str::to_string);
    Ok(Surface {
        protocol_version,
        supported_versions: None,
        server_info,
        instructions,
        capabilities,
        tools: vec![],
        prompts: vec![],
        resources: vec![],
        resource_templates: vec![],
    })
}

/// What a `server/discover` probe tells about the server's era (2026-07-28
/// stdio, backward compatibility): a `DiscoverResult` is modern, a recognized
/// modern error is modern but unusable (never fall back), anything else or no
/// answer (`None`) is legacy (`Ok(None)`).
pub fn classify_discover(reply: Option<std::result::Result<Value, Value>>) -> Result<Option<Surface>> {
    match reply {
        Some(Ok(res)) => discover_surface(&res).map(Some),
        Some(Err(e))
            if e.get("code")
                .and_then(Value::as_i64)
                .is_some_and(|c| MODERN_ERRORS.contains(&c)) =>
        {
            bail!(
                "the server speaks 2026-07-28 or later but refused mcpsum's {}: {}",
                MODERN_VERSIONS.join(", "),
                crate::render::escape_untrusted(&e.to_string())
            )
        }
        Some(Err(_)) | None => Ok(None),
    }
}

fn send_initialize(s: &mut Session) -> Result<std::result::Result<Value, Value>> {
    s.meta = None;
    s.request(
        "initialize",
        json!({
            "protocolVersion": PROBE_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcpsum-probe", "version": env!("CARGO_PKG_VERSION")},
        }),
    )
}

/// `server/discover` with mcpsum's preferred version, then the version it picked.
fn send_discover(s: &mut Session) -> Result<Option<Surface>> {
    s.meta = Some(modern_meta(MODERN_VERSIONS[0], "mcpsum-probe"));
    let surface = classify_discover(s.request_or_timeout("server/discover", json!({}))?)?;
    s.meta = surface
        .as_ref()
        .map(|m| modern_meta(&m.protocol_version, "mcpsum-probe"));
    Ok(surface)
}

/// Open the session and detect the server's era. Default order is the spec's
/// (stdio, backward compatibility): `server/discover` first, `initialize` on
/// any other error or no answer. A server locked over `initialize` is asked
/// that way first, and only a rejected `initialize` leads to `server/discover`.
fn open(s: &mut Session, prefer_legacy: bool) -> Result<Surface> {
    let escape = |e: &Value| crate::render::escape_untrusted(&e.to_string());
    let surface = if prefer_legacy {
        match send_initialize(s)? {
            Ok(init) => legacy_surface(&init)?,
            Err(e) => match send_discover(s).with_context(|| format!("initialize failed: {}", escape(&e)))? {
                Some(modern) => modern,
                None => bail!("initialize failed: {}; server/discover failed too", escape(&e)),
            },
        }
    } else {
        match send_discover(s)? {
            Some(modern) => modern,
            None => {
                let init = send_initialize(s)?.map_err(|e| {
                    anyhow!(
                        "server/discover and initialize both failed (initialize: {})",
                        escape(&e)
                    )
                })?;
                legacy_surface(&init)?
            }
        }
    };
    if surface.supported_versions.is_none() {
        s.write(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;
    }
    Ok(surface)
}

/// Write to the server's stdin on a thread of its own. It may block on a full
/// pipe, but only until the server's process tree is killed (the probe's
/// guard does that when it returns): the write then fails and the thread ends.
fn spawn_writer(mut stdin: ChildStdin) -> SyncSender<Vec<u8>> {
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(MAX_PENDING_WRITES);
    thread::spawn(move || {
        for line in rx {
            if stdin.write_all(&line).and_then(|()| stdin.flush()).is_err() {
                break;
            }
        }
    });
    tx
}

pub fn probe(argv: &[String], env_passthrough: &[String], opts: &ProbeOptions) -> Result<Surface> {
    let mut server = spawn_server(argv, env_passthrough, opts.sandbox.as_ref())?;
    // Declared before `server` is moved into the guard below, so it is dropped
    // *after* it: the tree is killed first, then buffered stderr gets a bounded
    // grace period to drain.
    let _relay = relay_stderr(&mut server, "server");
    // I5 allowlist mode: `lock` and `verify` have no audit log, so the egress
    // proxy reports its decisions on stderr.
    let _egress = match &opts.sandbox {
        Some(spec) => {
            let sink: crate::egress::AuditSink = std::sync::Arc::new(|ev: &crate::monitor::AuditEvent| {
                eprintln!(
                    "mcpsum: egress {:?} {}: {}",
                    ev.decision,
                    crate::render::escape_untrusted(ev.subject.as_deref().unwrap_or("-")),
                    ev.reason
                );
                Ok(())
            });
            crate::proxy::start_egress(&mut server, spec, sink)?
        }
        None => None,
    };
    let stdout = server.take_stdout().context("server stdout")?;
    let stdin = server.take_stdin().context("server stdin")?;
    let _guard = server; // ServerProcess kills the whole tree on drop
    let (tx, rx) = mpsc::channel();
    let max = opts.max_line_bytes;
    thread::spawn(move || {
        for f in BoundedLines::new(BufReader::new(stdout), max) {
            if tx.send(f).is_err() {
                break;
            }
        }
    });
    let mut s = Session {
        out: spawn_writer(stdin),
        rx,
        next_id: 1,
        timeout: opts.timeout,
        meta: None,
    };

    let mut surface = open(&mut s, opts.prefer_legacy)?;
    let capabilities = surface.capabilities.clone();
    if capabilities.get("tools").is_some() {
        surface.tools = s.list_all("tools/list", "tools")?;
    }
    if capabilities.get("prompts").is_some() {
        surface.prompts = s.list_all("prompts/list", "prompts")?;
    }
    if capabilities.get("resources").is_some() {
        surface.resources = s.list_all("resources/list", "resources")?;
        surface.resource_templates = s.list_all("resources/templates/list", "resourceTemplates")?;
    }
    surface.validate()?;
    Ok(surface)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discover() -> Value {
        json!({"resultType": "complete", "supportedVersions": ["2027-01-01", "2026-07-28", "2026-07-28"],
            "capabilities": {"tools": {}}, "instructions": "Arithmetic helper.", "ttlMs": 5, "cacheScope": "public",
            "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "demo", "version": "1"}}})
    }

    #[test]
    fn discover_result_is_recorded_with_the_version_mcpsum_speaks() {
        let s = discover_surface(&discover()).unwrap();
        assert_eq!(s.protocol_version, "2026-07-28");
        assert_eq!(
            s.supported_versions,
            Some(vec!["2026-07-28".into(), "2027-01-01".into()])
        );
        assert_eq!(s.server_info, json!({"name": "demo", "version": "1"}));
        assert_eq!(s.capabilities, json!({"tools": {}}));
        assert_eq!(s.instructions.as_deref(), Some("Arithmetic helper."));
        assert!(s.tools.is_empty());
    }

    #[test]
    fn ambiguous_or_unusable_discover_results_are_refused() {
        let mut cases = Vec::new();
        for (ptr, v) in [
            ("/supportedVersions", json!(["2027-01-01"])),
            ("/supportedVersions", json!(["2026-07-28", 7])),
            ("/supportedVersions", json!("2026-07-28")),
            ("/capabilities", json!([])),
            ("/resultType", json!("input_required")),
            ("/_meta", json!({})),
            ("/instructions", json!(["x"])),
        ] {
            let mut d = discover();
            *d.pointer_mut(ptr).unwrap() = v;
            cases.push(d);
        }
        let mut no_caps = discover();
        no_caps.as_object_mut().unwrap().remove("capabilities");
        cases.push(no_caps);
        for d in cases {
            assert!(discover_surface(&d).is_err(), "{d}");
        }
        // The error names what the server supports, escaped.
        let mut d = discover();
        d["supportedVersions"] = json!(["2027-01-01\u{202e}"]);
        let e = discover_surface(&d).unwrap_err().to_string();
        assert!(e.contains("2027-01-01") && !e.contains('\u{202e}'), "{e}");
    }

    #[test]
    fn list_pages_that_ask_for_input_are_refused() {
        let page = json!({"resultType": "complete", "tools": [{"name": "a"}], "nextCursor": "c"});
        let (items, next) = list_page("tools/list", "tools", &page).unwrap();
        assert_eq!((items.len(), next.as_deref()), (1, Some("c")));
        assert!(
            list_page("tools/list", "tools", &json!({"tools": []})).is_ok(),
            "legacy: no resultType"
        );
        let ask = json!({"resultType": "input_required", "tools": [{"name": "a"}], "inputRequests": {}});
        assert!(list_page("tools/list", "tools", &ask).is_err());
        assert!(list_page("tools/list", "tools", &json!({"resultType": "complete"})).is_err());
    }

    const FLOOD_ENV: &str = "MCPSUM_TEST_PING_FLOOD";

    /// Child-process helper for the test below; it does nothing unless
    /// re-executed with FLOOD_ENV set. A server that sends many `ping`
    /// requests, never reads its stdin and keeps stdout open.
    #[test]
    #[ignore = "helper process for probe_honours_its_timeout_when_the_server_never_reads_stdin"]
    fn ping_flood_server_helper() {
        if std::env::var_os(FLOOD_ENV).is_none() {
            return;
        }
        let mut out = std::io::BufWriter::new(std::io::stdout().lock());
        for i in 0..200_000u64 {
            // The probe stops reading once it gives up: then just exit.
            if writeln!(out, r#"{{"jsonrpc":"2.0","id":"s{i}","method":"ping"}}"#).is_err() {
                std::process::exit(0);
            }
        }
        let _ = out.flush();
        thread::sleep(Duration::from_secs(20));
    }

    /// `--timeout-secs` bounds the probe (LOCKFILE.md: "no answer within
    /// `--timeout-secs` means a legacy server"). A server that floods pings and
    /// never reads stdin fills the pipe with mcpsum's replies; a blocking write
    /// must not hang `lock`/`verify` past that.
    #[test]
    fn probe_honours_its_timeout_when_the_server_never_reads_stdin() {
        let me = std::env::current_exe().unwrap().to_string_lossy().into_owned();
        let argv: Vec<String> = [
            me.as_str(),
            "probe::tests::ping_flood_server_helper",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let opts = ProbeOptions {
            timeout: Duration::from_secs(2),
            ..ProbeOptions::default()
        };
        // SAFETY (edition 2021): test-only; the name is unique to this test.
        // It reaches the child through the scrubbed environment's passthrough.
        std::env::set_var(FLOOD_ENV, "1");
        let (tx, rx) = mpsc::channel();
        let start = Instant::now();
        thread::spawn(move || {
            let r = probe(&argv, &[FLOOD_ENV.to_string()], &opts);
            let _ = tx.send(r.map(|_| ()).map_err(|e| format!("{e:#}")));
        });
        let r = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("probe still blocked after 10 s although its timeout is 2 s");
        let err = r.expect_err("the flooding server never answers, so the probe fails");
        assert!(err.contains("not reading its input"), "{err}");
        assert!(start.elapsed() < Duration::from_secs(10), "{err}");
    }

    /// The deadline holds however fast the server sends: messages already
    /// queued when it passes are not read (a flood must not extend the wait).
    #[test]
    fn probe_deadline_holds_while_messages_keep_arriving() {
        let (out, _server_stdin) = mpsc::sync_channel(MAX_PENDING_WRITES);
        let (feed, rx) = mpsc::channel();
        let note = br#"{"jsonrpc":"2.0","method":"notifications/message","params":{}}"#;
        for _ in 0..1000 {
            feed.send(Ok(Frame::Line(note.to_vec()))).unwrap();
        }
        let mut s = Session {
            out,
            rx,
            next_id: 1,
            timeout: Duration::ZERO,
            meta: None,
        };
        assert!(s.request_or_timeout("tools/list", json!({})).unwrap().is_none());
        assert_eq!(s.rx.try_iter().count(), 1000, "messages were read after the deadline");
    }

    /// 2026-07-28 stdio backward compatibility: a recognized modern error
    /// means "modern, pick another version", never "fall back to initialize";
    /// any other error, or no answer, means legacy.
    #[test]
    fn discover_probe_falls_back_to_initialize_only_for_non_modern_errors() {
        assert!(classify_discover(Some(Ok(discover()))).unwrap().is_some());
        for code in [-32601, -32602, -32600, -32603, -32000, -32002] {
            let e = json!({"code": code, "message": "Received request before initialization was complete"});
            assert!(classify_discover(Some(Err(e))).unwrap().is_none(), "{code}");
        }
        assert!(classify_discover(Some(Err(json!({"message": "no code"}))))
            .unwrap()
            .is_none());
        assert!(
            classify_discover(None).unwrap().is_none(),
            "no answer within the timeout is legacy"
        );
        for code in [-32021, -32022] {
            let e = json!({"code": code, "message": "nope\u{1b}[2J", "data": {"supported": ["2099-01-01"], "requested": "2026-07-28"}});
            let err = classify_discover(Some(Err(e))).unwrap_err().to_string();
            assert!(err.contains("2099-01-01") && !err.contains('\u{1b}'), "{err}");
        }
    }
}
