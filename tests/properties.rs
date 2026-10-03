//! Property-based tests of the monitor's security invariants.
//!
//! Thousands of random sessions mix valid traffic with adversarial traffic:
//! poisoned server responses and notifications (every server string carries the
//! marker `§EVIL§`), forged ids, server-initiated requests, unknown methods,
//! malformed and random bytes. After every step the monitor's output is checked
//! against an independent oracle that does not reuse the monitor's own code.
//!
//! Invariants (docs/GUARANTEES.md):
//!   I1  server-authored text reaches the client only inside responses to
//!       forwarded tools/call, prompts/get, resources/read, or the message of a
//!       progress notification; never in list responses or initialize.
//!   I2  every forwarded tools/call names a locked tool and carries arguments
//!       valid under the strict locked schema (checked by a hand-written oracle).
//!   I3  no server-initiated request ever reaches the client; the only
//!       notification the client ever receives is notifications/progress.
//!   I7  every response the client receives answers a request it sent and has not
//!       yet had answered (no spoofed or duplicate responses); after quarantine,
//!       nothing is ever forwarded to the server again except replies to its pings
//!       and refusals of its requests.

use std::collections::{HashMap, HashSet};

use mcpsum::lock::{ServerLock, Surface};
use mcpsum::monitor::{Action, Monitor, Policy};
use proptest::prelude::*;
use serde_json::{json, Value};

const EVIL: &str = "§EVIL§";

fn surface() -> Surface {
    Surface {
        protocol_version: "2025-06-18".into(),
        server_info: json!({"name": "demo", "version": "1.0.0"}),
        instructions: Some("Arithmetic helper.".into()),
        capabilities: json!({"tools": {"listChanged": true}, "prompts": {}, "resources": {}}),
        tools: vec![
            json!({"name": "add", "description": "Add two numbers", "inputSchema": {"type": "object", "properties": {"a": {"type": "number"}, "b": {"type": "number"}}, "required": ["a", "b"]}}),
            json!({"name": "noargs", "description": "No arguments", "inputSchema": {"type": "object"}}),
        ],
        prompts: vec![json!({"name": "greet", "arguments": [{"name": "who"}]})],
        resources: vec![json!({"uri": "file:///readme.md", "name": "readme"})],
        resource_templates: vec![json!({"uriTemplate": "notes://{id}", "name": "note"})],
    }
}

fn lock() -> ServerLock {
    ServerLock::from_surface(vec!["demo".into()], vec![], surface()).unwrap()
}

/// Independent oracle for I2: what the strict locked schemas allow.
fn oracle_call_allowed(name: &str, args: &Value) -> bool {
    let Some(obj) = args.as_object() else { return false };
    match name {
        "add" => {
            obj.len() == 2 && obj.get("a").is_some_and(Value::is_number) && obj.get("b").is_some_and(Value::is_number)
        }
        "noargs" => obj.is_empty(),
        _ => false,
    }
}

// ----------------------------------------------------------------- generators

#[derive(Debug, Clone)]
enum Op {
    Client(ClientOp),
    Server(ServerOp),
    Tick(u64),
    RawClient(Vec<u8>),
    RawServer(Vec<u8>),
}

#[derive(Debug, Clone)]
enum ClientOp {
    Initialize,
    Initialized,
    List(&'static str),
    Call { name: String, args: Value },
    PromptGet { name: String, args: Value },
    Read(String),
    Unknown(String),
    Cancel(i64),
    Ping,
}

#[derive(Debug, Clone)]
enum ServerOp {
    /// Respond to the k-th outstanding request the monitor sent (mod len).
    Respond {
        k: usize,
        payload: Payload,
    },
    /// Response with an id the monitor never used.
    Forged {
        id: Value,
    },
    Request {
        method: &'static str,
    },
    ListChanged,
    Progress {
        token: Value,
    },
    Log,
}

#[derive(Debug, Clone)]
enum Payload {
    /// Mirror the lock exactly (clean verification / clean results).
    Clean,
    /// Everything poisoned.
    Poisoned,
    Error,
    Malformed,
}

fn arb_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(json!(1)),
        Just(json!(-2.5)),
        Just(json!("x")),
        Just(json!(EVIL)),
        Just(json!(null)),
        Just(json!(true)),
        Just(json!([1, 2])),
        Just(json!({"k": EVIL})),
    ]
}

fn arb_args() -> impl Strategy<Value = Value> {
    prop_oneof![
        3 => (arb_value(), arb_value()).prop_map(|(a, b)| json!({"a": a, "b": b})),
        2 => Just(json!({"a": 1, "b": 2})),
        1 => Just(json!({})),
        1 => Just(json!({"a": 1, "b": 2, "sidenote": "secret"})),
        1 => Just(json!({"a": 1})),
        1 => arb_value(),
    ]
}

fn arb_client() -> impl Strategy<Value = ClientOp> {
    prop_oneof![
        2 => Just(ClientOp::Initialize),
        2 => Just(ClientOp::Initialized),
        2 => prop_oneof![Just("tools/list"), Just("prompts/list"), Just("resources/list"), Just("resources/templates/list")].prop_map(ClientOp::List),
        6 => (prop_oneof![Just("add".to_string()), Just("noargs".to_string()), Just("exec".to_string()), Just(EVIL.to_string())], arb_args())
            .prop_map(|(name, args)| ClientOp::Call { name, args }),
        1 => (prop_oneof![Just("greet".to_string()), Just("nope".to_string())], prop_oneof![Just(json!({"who": "x"})), Just(json!({"who": 1})), Just(json!({"other": "y"}))])
            .prop_map(|(name, args)| ClientOp::PromptGet { name, args }),
        1 => prop_oneof![Just("file:///readme.md".to_string()), Just("notes://abc".to_string()), Just("file:///etc/passwd".to_string()), Just("notes://a/../b".to_string())].prop_map(ClientOp::Read),
        1 => prop_oneof![Just("completion/complete".to_string()), Just("server/discover".to_string()), Just("x/y".to_string())].prop_map(ClientOp::Unknown),
        1 => (0i64..40).prop_map(ClientOp::Cancel),
        1 => Just(ClientOp::Ping),
    ]
}

fn arb_payload() -> impl Strategy<Value = Payload> {
    prop_oneof![5 => Just(Payload::Clean), 2 => Just(Payload::Poisoned), 1 => Just(Payload::Error), 1 => Just(Payload::Malformed)]
}

fn arb_server() -> impl Strategy<Value = ServerOp> {
    prop_oneof![
        8 => (0usize..8, arb_payload()).prop_map(|(k, payload)| ServerOp::Respond { k, payload }),
        1 => prop_oneof![Just(json!(999_999)), Just(json!("1")), Just(json!(-1)), Just(json!(null))].prop_map(|id| ServerOp::Forged { id }),
        1 => prop_oneof![Just("sampling/createMessage"), Just("elicitation/create"), Just("roots/list"), Just("ping"), Just("made/up")].prop_map(|method| ServerOp::Request { method }),
        1 => Just(ServerOp::ListChanged),
        1 => prop_oneof![Just(json!("tok")), Just(json!("other")), Just(json!(7))].prop_map(|token| ServerOp::Progress { token }),
        1 => Just(ServerOp::Log),
    ]
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => arb_client().prop_map(Op::Client),
        8 => arb_server().prop_map(Op::Server),
        1 => (0u64..100_000).prop_map(Op::Tick),
        1 => proptest::collection::vec(any::<u8>(), 0..64).prop_map(Op::RawClient),
        1 => proptest::collection::vec(any::<u8>(), 0..64).prop_map(Op::RawServer),
    ]
}

// ----------------------------------------------------------------- harness

struct Harness {
    m: Monitor,
    next_client_id: i64,
    /// client id -> method, for requests the client sent and that are unanswered
    open: HashMap<String, String>,
    answered: HashSet<String>,
    /// requests the monitor sent to the server, oldest first: (id, method)
    server_pending: Vec<(Value, String)>,
    quarantined_seen: bool,
    now: u64,
}

fn key(id: &Value) -> String {
    id.to_string()
}

impl Harness {
    fn new() -> Self {
        Self {
            m: Monitor::new(lock(), Policy::default()),
            next_client_id: 1,
            open: HashMap::new(),
            answered: HashSet::new(),
            server_pending: Vec::new(),
            quarantined_seen: false,
            now: 0,
        }
    }

    fn client_request(&mut self, method: &str, params: Value) -> Vec<Action> {
        let id = json!(self.next_client_id);
        self.next_client_id += 1;
        self.open.insert(key(&id), method.to_string());
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.m.on_client_line(&serde_json::to_vec(&msg).unwrap())
    }

    fn poisoned_items(method: &str) -> Value {
        let item = match method {
            "tools/list" => {
                json!({"name": "add", "description": EVIL, "inputSchema": {"type": "object", "properties": {EVIL: {"type": "string"}}}})
            }
            "prompts/list" => json!({"name": "greet", "description": EVIL}),
            "resources/list" => json!({"uri": "file:///readme.md", "name": EVIL}),
            _ => json!({"uriTemplate": "notes://{id}", "name": EVIL}),
        };
        json!([item])
    }

    fn respond(&mut self, k: usize, payload: &Payload) -> Vec<Action> {
        if self.server_pending.is_empty() {
            return Vec::new();
        }
        let (id, method) = self.server_pending.remove(k % self.server_pending.len());
        let s = surface();
        let result = match (payload, method.as_str()) {
            (Payload::Error, _) => {
                return self.server(
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": EVIL, "data": EVIL}}),
                )
            }
            (Payload::Malformed, _) => json!(EVIL),
            (Payload::Clean, "initialize") => {
                json!({"protocolVersion": "2025-06-18", "capabilities": s.capabilities, "serverInfo": s.server_info, "instructions": s.instructions})
            }
            (Payload::Poisoned, "initialize") => {
                json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}, "experimental": EVIL}, "serverInfo": {"name": EVIL}, "instructions": EVIL})
            }
            (Payload::Clean, "tools/list") => json!({"tools": s.tools}),
            (Payload::Clean, "prompts/list") => json!({"prompts": s.prompts}),
            (Payload::Clean, "resources/list") => json!({"resources": s.resources}),
            (Payload::Clean, "resources/templates/list") => json!({"resourceTemplates": s.resource_templates}),
            (
                Payload::Poisoned,
                m @ ("tools/list" | "prompts/list" | "resources/list" | "resources/templates/list"),
            ) => {
                let field = match m {
                    "tools/list" => "tools",
                    "prompts/list" => "prompts",
                    "resources/list" => "resources",
                    _ => "resourceTemplates",
                };
                json!({field: Self::poisoned_items(m), "nextCursor": EVIL})
            }
            (Payload::Clean, _) => json!({"content": [{"type": "text", "text": "3"}]}),
            (Payload::Poisoned, _) => json!({"content": [{"type": "text", "text": EVIL}], "_meta": EVIL}),
        };
        self.server(json!({"jsonrpc": "2.0", "id": id, "result": result}))
    }

    fn server(&mut self, msg: Value) -> Vec<Action> {
        self.m.on_server_line(&serde_json::to_vec(&msg).unwrap())
    }

    fn apply(&mut self, op: &Op) -> Vec<Action> {
        match op {
            Op::Client(c) => match c {
                ClientOp::Initialize => self.client_request(
                    "initialize",
                    json!({"protocolVersion": "2025-06-18", "capabilities": {"sampling": {}, "elicitation": {}}, "clientInfo": {"name": "p", "version": "1"}}),
                ),
                ClientOp::Initialized => self.m.on_client_line(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
                ClientOp::List(m) => self.client_request(m, json!({})),
                ClientOp::Call { name, args } => {
                    let params = json!({"name": name, "arguments": args, "_meta": {"progressToken": "tok"}});
                    self.client_request("tools/call", params)
                }
                ClientOp::PromptGet { name, args } => self.client_request("prompts/get", json!({"name": name, "arguments": args})),
                ClientOp::Read(uri) => self.client_request("resources/read", json!({"uri": uri})),
                ClientOp::Unknown(m) => self.client_request(m, json!({})),
                ClientOp::Cancel(id) => {
                    let msg = json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": id}});
                    self.m.on_client_line(&serde_json::to_vec(&msg).unwrap())
                }
                ClientOp::Ping => self.client_request("ping", json!({})),
            },
            Op::Server(s) => match s {
                ServerOp::Respond { k, payload } => self.respond(*k, payload),
                ServerOp::Forged { id } => self.server(json!({"jsonrpc": "2.0", "id": id, "result": {"content": [{"type": "text", "text": EVIL}]}})),
                ServerOp::Request { method } => self.server(json!({"jsonrpc": "2.0", "id": "srv-1", "method": method, "params": {"messages": [EVIL]}})),
                ServerOp::ListChanged => self.server(json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})),
                ServerOp::Progress { token } => self.server(json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": token, "progress": 1, "message": EVIL, "extra": EVIL}})),
                ServerOp::Log => self.server(json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": EVIL}})),
            },
            Op::Tick(dt) => {
                self.now += dt;
                self.m.on_tick(self.now)
            }
            Op::RawClient(b) => self.m.on_client_line(b),
            Op::RawServer(b) => self.m.on_server_line(b),
        }
    }

    /// Check every invariant against one step's actions.
    fn check(&mut self, actions: &[Action]) -> Result<(), TestCaseError> {
        let was_quarantined = self.quarantined_seen;
        for a in actions {
            match a {
                Action::ToClient(v) => {
                    let text = v.to_string();
                    // I3: never a server-initiated request.
                    prop_assert!(
                        !(v.get("method").is_some() && v.get("id").is_some()),
                        "request reached client: {text}"
                    );
                    if let Some(method) = v.get("method").and_then(Value::as_str) {
                        prop_assert_eq!(method, "notifications/progress", "unexpected notification: {}", text);
                        let mut p = v["params"].clone();
                        p.as_object_mut().unwrap().remove("message");
                        prop_assert!(
                            !p.to_string().contains(EVIL),
                            "poison outside progress.message: {}",
                            text
                        );
                        continue;
                    }
                    // I7: responses only for open client requests, at most once.
                    let id = v.get("id").cloned().unwrap_or(Value::Null);
                    if id.is_null() {
                        // parse/invalid-request errors for garbage input carry id null
                        prop_assert!(v.get("error").is_some(), "null-id non-error: {text}");
                        prop_assert!(!text.contains(EVIL));
                        continue;
                    }
                    let k = key(&id);
                    prop_assert!(!self.answered.contains(&k), "duplicate response for {k}: {text}");
                    let method = self.open.remove(&k);
                    prop_assert!(method.is_some(), "response for unknown id {k}: {text}");
                    self.answered.insert(k);
                    let method = method.unwrap();
                    // I1: server text only in pass-through responses.
                    if !matches!(method.as_str(), "tools/call" | "prompts/get" | "resources/read") {
                        prop_assert!(!text.contains(EVIL), "server text in `{method}` response: {text}");
                    }
                    if method == "tools/list" && v.get("result").is_some() {
                        prop_assert_eq!(&v["result"]["tools"], &json!(lock().surface.tools));
                    }
                }
                Action::ToServer(v) => {
                    let method = v.get("method").and_then(Value::as_str).unwrap_or("");
                    let is_request = v.get("id").is_some() && !method.is_empty();
                    if was_quarantined && is_request {
                        prop_assert!(false, "request forwarded after quarantine: {v}");
                    }
                    if method == "tools/call" {
                        let name = v["params"]["name"].as_str().unwrap_or("");
                        prop_assert!(
                            oracle_call_allowed(name, &v["params"]["arguments"]),
                            "oracle rejects forwarded call: {v}"
                        );
                    }
                    if is_request {
                        self.server_pending.push((v["id"].clone(), method.to_string()));
                    }
                }
                Action::Audit(_) => {}
            }
        }
        if self.m.is_quarantined() {
            self.quarantined_seen = true;
        }
        Ok(())
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 3000, max_shrink_iters: 4000, ..ProptestConfig::default() })]

    #[test]
    fn invariants_hold_for_arbitrary_sessions(ops in proptest::collection::vec(arb_op(), 1..60)) {
        let mut h = Harness::new();
        for op in &ops {
            let actions = h.apply(op);
            h.check(&actions)?;
        }
    }

    /// Sessions that complete a clean handshake first, so the interesting
    /// Ready-state paths (forwarding, re-verification) are exercised heavily.
    #[test]
    fn invariants_hold_after_clean_handshake(ops in proptest::collection::vec(arb_op(), 1..60)) {
        let mut h = Harness::new();
        let mut script = vec![
            Op::Client(ClientOp::Initialize),
            Op::Server(ServerOp::Respond { k: 0, payload: Payload::Clean }),
            Op::Client(ClientOp::Initialized),
        ];
        for _ in 0..4 {
            script.push(Op::Server(ServerOp::Respond { k: 0, payload: Payload::Clean }));
        }
        for op in script.iter().chain(ops.iter()) {
            let actions = h.apply(op);
            h.check(&actions)?;
        }
    }
}

#[test]
fn oracle_matches_known_cases() {
    assert!(oracle_call_allowed("add", &json!({"a": 1, "b": 2})));
    assert!(!oracle_call_allowed("add", &json!({"a": 1, "b": 2, "c": 3})));
    assert!(!oracle_call_allowed("add", &json!({"a": "1", "b": 2})));
    assert!(oracle_call_allowed("noargs", &json!({})));
    assert!(!oracle_call_allowed("noargs", &json!({"x": 1})));
    assert!(!oracle_call_allowed("exec", &json!({})));
}
