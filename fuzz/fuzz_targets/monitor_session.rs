//! Fuzz the monitor with arbitrary message sequences from both peers.
//!
//! Input format: lines separated by '\n'; the first byte of each line picks the
//! direction (even = client, odd = server), a byte of 0xFF advances the clock.
//! Beyond panic-freedom, every step checks the cheap invariants:
//!   - no server-initiated request ever reaches the client (I3)
//!   - the only notification the client ever receives is notifications/progress (I3)
//!   - every message sent to the server is a JSON-RPC 2.0 object (I7)
#![no_main]

use libfuzzer_sys::fuzz_target;
use mcpsum::lock::{ServerLock, Surface};
use mcpsum::monitor::{Action, Monitor, Policy};
use serde_json::{json, Value};
use std::sync::OnceLock;

fn lock() -> &'static ServerLock {
    static LOCK: OnceLock<ServerLock> = OnceLock::new();
    LOCK.get_or_init(|| {
        let surface = Surface {
            protocol_version: "2025-06-18".into(),
            server_info: json!({"name": "demo", "version": "1"}),
            instructions: Some("x".into()),
            capabilities: json!({"tools": {}, "prompts": {}, "resources": {}}),
            tools: vec![
                json!({"name": "add", "inputSchema": {"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}, "required": ["a", "b"]}}),
                json!({"name": "pat", "inputSchema": {"type": "object", "properties": {"s": {"type": "string", "pattern": "^(a+)+$"}}}}),
            ],
            prompts: vec![json!({"name": "greet", "arguments": [{"name": "who"}]})],
            resources: vec![json!({"uri": "file:///readme.md", "name": "r"})],
            resource_templates: vec![json!({"uriTemplate": "notes://{id}{?q}", "name": "n"})],
        };
        ServerLock::from_surface(vec!["demo".into()], vec![], surface).unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let mut m = Monitor::new(
        lock().clone(),
        Policy {
            max_line_bytes: 4096,
            ..Policy::default()
        },
    );
    let mut now = 0u64;
    for line in data.split(|b| *b == b'\n') {
        let Some((&sel, rest)) = line.split_first() else {
            continue;
        };
        let actions = if sel == 0xFF {
            now += u64::from(rest.first().copied().unwrap_or(1)) * 1000;
            m.on_tick(now)
        } else if sel % 2 == 0 {
            m.on_client_line(rest)
        } else {
            m.on_server_line(rest)
        };
        for a in actions {
            match a {
                Action::ToClient(v) => {
                    assert!(
                        !(v.get("method").is_some() && v.get("id").is_some()),
                        "request reached client"
                    );
                    if let Some(method) = v.get("method").and_then(Value::as_str) {
                        assert_eq!(method, "notifications/progress");
                    }
                }
                Action::ToServer(v) => {
                    assert_eq!(v.get("jsonrpc"), Some(&json!("2.0")));
                    assert!(v.is_object());
                }
                Action::Audit(_) => {}
            }
        }
    }
});
