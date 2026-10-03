//! Probe a live MCP server: handshake, then capture its full surface
//! (tools, prompts, resources, resource templates, instructions).
//!
//! The probe runs the server with a scrubbed environment. It does NOT sandbox
//! it yet (milestone M2): the server's code runs on this host with the user's
//! filesystem permissions, exactly as it would under an MCP client.

use std::io::{BufReader, Write};
use std::process::ChildStdin;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};

use crate::framing::{BoundedLines, Frame};
use crate::lock::{Surface, MAX_ITEMS_PER_KIND};
use crate::process::{relay_stderr, spawn_server};

/// Newest handshake protocol revision we speak. The 2026-07-28 "modern"
/// (server/discover) protocol is not supported yet.
pub const PROBE_PROTOCOL_VERSION: &str = "2025-11-25";
const MAX_PAGES: usize = 50;

pub struct ProbeOptions {
    pub timeout: Duration,
    pub max_line_bytes: usize,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_line_bytes: 4 * 1024 * 1024,
        }
    }
}

struct Session {
    stdin: ChildStdin,
    rx: Receiver<std::io::Result<Frame>>,
    next_id: u64,
    timeout: Duration,
}

impl Session {
    fn write(&mut self, msg: &Value) -> Result<()> {
        let mut line = serde_json::to_vec(msg)?;
        line.push(b'\n');
        self.stdin.write_all(&line).context("writing to server")?;
        self.stdin.flush().context("writing to server")
    }

    /// Send a request and wait for its response. Server-initiated requests are
    /// refused (ping answered); notifications and unrelated messages ignored.
    fn request(&mut self, method: &str, params: Value) -> Result<std::result::Result<Value, Value>> {
        let id = self.next_id;
        self.next_id += 1;
        self.write(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        let deadline = Instant::now() + self.timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let frame = match self.rx.recv_timeout(left) {
                Ok(f) => f.context("reading from server")?,
                Err(RecvTimeoutError::Timeout) => bail!("timed out after {:?} waiting for `{method}`", self.timeout),
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
                        return Ok(Err(e.clone()));
                    }
                    return Ok(Ok(obj.get("result").cloned().unwrap_or(Value::Null)));
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
            let items = res
                .get(field)
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("`{method}` result has no `{field}` array"))?;
            out.extend(items.iter().cloned());
            if out.len() > MAX_ITEMS_PER_KIND {
                bail!("server returned more than {MAX_ITEMS_PER_KIND} items for `{method}`");
            }
            match res.get("nextCursor").and_then(Value::as_str) {
                Some(c) => cursor = Some(c.to_string()),
                None => return Ok(out),
            }
        }
        bail!("`{method}` exceeded {MAX_PAGES} pages")
    }
}

pub fn probe(argv: &[String], env_passthrough: &[String], opts: &ProbeOptions) -> Result<Surface> {
    let mut server = spawn_server(argv, env_passthrough)?;
    // Declared before `server` is moved into the guard below, so it is dropped
    // *after* it: the tree is killed first, then buffered stderr gets a bounded
    // grace period to drain.
    let _relay = relay_stderr(&mut server, "server");
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
        stdin,
        rx,
        next_id: 1,
        timeout: opts.timeout,
    };

    let init = s
        .request(
            "initialize",
            json!({
                "protocolVersion": PROBE_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcpsum-probe", "version": env!("CARGO_PKG_VERSION")},
            }),
        )?
        .map_err(|e| anyhow!("initialize failed: {}", crate::render::escape_untrusted(&e.to_string())))?;
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
    s.write(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;

    let mut surface = Surface {
        protocol_version,
        server_info,
        instructions,
        capabilities: capabilities.clone(),
        tools: vec![],
        prompts: vec![],
        resources: vec![],
        resource_templates: vec![],
    };
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
