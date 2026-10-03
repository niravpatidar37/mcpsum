//! The I/O shell around the pure `Monitor`: spawn the locked server, pump
//! newline-delimited JSON-RPC between our stdio and the server, execute the
//! monitor's actions, and append every decision to the audit log.
//!
//! Threads: one reader per peer plus one ticker feed a single bounded channel;
//! the main loop is the only place that touches the monitor, so decisions are
//! strictly ordered. Server writes go through a dedicated writer thread so a
//! server that stops reading cannot stall the client side.

use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::Value;

use crate::audit::{AppendAudit, AuditFile};
use crate::framing::{BoundedLines, Frame};
use crate::lock::LockFile;
use crate::monitor::{Action, AuditEvent, Decision, Dir, Monitor, Policy};
use crate::process::{relay_stderr, spawn_server};
use crate::render::escape_untrusted;

enum Event {
    Client(Frame),
    ClientEof,
    Server(Frame),
    ServerEof,
    Tick,
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Open (or resume) the audit chain. Safe to call from several processes for
/// the same log at once; see [`AuditFile`]. A log that fails verification is
/// moved aside, never appended to, so tampering stays visible.
pub fn open_audit(path: &Path, server: &str) -> Result<AuditFile> {
    AuditFile::open(path, server)
}

pub fn default_audit_path(lock_path: &Path, server: &str) -> PathBuf {
    let dir = lock_path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    dir.join(".mcpsum-audit").join(format!("{server}.jsonl"))
}

fn write_line(w: &mut impl Write, v: &Value) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(v)?;
    line.push(b'\n');
    w.write_all(&line)?;
    w.flush()
}

pub fn run_proxy(lock_path: &Path, name: &str, audit_path: Option<PathBuf>, policy: Policy) -> Result<i32> {
    let lockfile = LockFile::load(lock_path)?;
    let server = lockfile.server(name)?.clone();
    let audit_path = audit_path.unwrap_or_else(|| default_audit_path(lock_path, name));
    let mut audit = open_audit(&audit_path, name)?;
    let max = policy.max_line_bytes;
    let mut monitor = Monitor::new(server.clone(), policy);

    let mut child = spawn_server(&server.command, &server.env_passthrough)?;
    // Dropped at return, after the server tree is killed below: bounded drain.
    let _relay = relay_stderr(&mut child, name);
    let child_stdout = child.take_stdout().context("server stdout")?;
    let mut child_stdin = child.take_stdin().context("server stdin")?;

    let (tx, rx) = mpsc::sync_channel::<Event>(64);
    spawn_reader(tx.clone(), std::io::stdin(), max, Event::Client, Event::ClientEof);
    spawn_reader(tx.clone(), child_stdout, max, Event::Server, Event::ServerEof);
    let ticker = tx.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(250));
        if ticker.send(Event::Tick).is_err() {
            break;
        }
    });
    drop(tx);

    let (to_server, server_q) = mpsc::sync_channel::<Vec<u8>>(256);
    let writer = thread::spawn(move || {
        for line in server_q {
            if child_stdin.write_all(&line).and_then(|_| child_stdin.flush()).is_err() {
                break;
            }
        }
    });

    let start = Instant::now();
    let stdout = std::io::stdout();
    let mut exit_code = 0;
    // A fatal error still goes through the shutdown below, so the server is
    // never left running (an early `?` would skip the kill).
    let mut fatal: Option<anyhow::Error> = None;
    'events: for ev in rx {
        let actions = match ev {
            Event::Client(Frame::Line(l)) => monitor.on_client_line(&l),
            Event::Client(Frame::TooLong) => monitor.client_oversize(),
            Event::Server(Frame::Line(l)) => monitor.on_server_line(&l),
            Event::Server(Frame::TooLong) => monitor.server_oversize(),
            Event::Tick => monitor.on_tick(start.elapsed().as_millis() as u64),
            Event::ClientEof => break,
            Event::ServerEof => {
                eprintln!("mcpsum[{name}]: server exited");
                exit_code = 1;
                break;
            }
        };
        // Write-ahead audit (I8): every decision in this batch is appended to
        // the log before any of its effects happen. If the log cannot be
        // written, nothing in the batch is forwarded and the proxy stops.
        if let Err(e) = write_ahead(&mut audit, &actions, name) {
            fatal = Some(e);
            break 'events;
        }
        for a in actions {
            match a {
                Action::ToServer(v) => {
                    let mut line = match serde_json::to_vec(&v) {
                        Ok(l) => l,
                        Err(e) => {
                            fatal = Some(e.into());
                            break 'events;
                        }
                    };
                    line.push(b'\n');
                    match to_server.try_send(line) {
                        Ok(()) => {}
                        Err(TrySendError::Full(_)) => {
                            // The server has stopped reading its input. Fail closed
                            // rather than block the client side indefinitely.
                            let e = AuditEvent {
                                dir: Dir::Internal,
                                method: None,
                                subject: None,
                                decision: Decision::Quarantine,
                                reason: "server is not reading its input; proxy exiting".into(),
                                args_digest: None,
                            };
                            if let Err(e) = write_ahead(&mut audit, &[Action::Audit(e)], name) {
                                fatal = Some(e);
                            }
                            exit_code = 1;
                            break 'events;
                        }
                        Err(TrySendError::Disconnected(_)) => {
                            exit_code = 1;
                            break 'events;
                        }
                    }
                }
                Action::ToClient(v) => {
                    if write_line(&mut stdout.lock(), &v).is_err() {
                        break 'events; // client went away
                    }
                }
                Action::Audit(_) => {} // already written ahead
            }
        }
    }
    // Shutdown. Close the server's input, give it a moment to exit, then kill
    // the whole process tree (unconditionally: a server that exits cleanly may
    // still leave descendants). Only then join the writer: if the server
    // stopped reading, the writer is blocked in write_all and only a broken
    // pipe (the kill) releases it.
    drop(to_server);
    child.shutdown(Duration::from_secs(2));
    let _ = writer.join();
    match fatal {
        Some(e) => Err(e),
        None => Ok(exit_code),
    }
}

/// Append every audit event in `actions` before any effect is executed.
fn write_ahead<A: AppendAudit>(audit: &mut A, actions: &[Action], name: &str) -> Result<()> {
    for a in actions {
        if let Action::Audit(e) = a {
            if matches!(e.decision, Decision::Deny | Decision::Quarantine) {
                eprintln!(
                    "mcpsum[{name}]: {:?} {} {}: {}",
                    e.decision,
                    escape_untrusted(e.method.as_deref().unwrap_or("-")),
                    escape_untrusted(e.subject.as_deref().unwrap_or("")),
                    escape_untrusted(&e.reason)
                );
            }
            audit
                .append_event(e, unix_ms())
                .context("audit log write failed; refusing to forward (fail closed)")?;
        }
    }
    Ok(())
}

fn spawn_reader<R: std::io::Read + Send + 'static>(
    tx: SyncSender<Event>,
    r: R,
    max: usize,
    wrap: fn(Frame) -> Event,
    eof: Event,
) {
    thread::spawn(move || {
        for f in BoundedLines::new(BufReader::new(r), max) {
            match f {
                Ok(frame) => {
                    if tx.send(wrap(frame)).is_err() {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = tx.send(eof);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{verify_chain, AuditLog};

    /// A writer that fails, like a full disk.
    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("disk full"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("disk full"))
        }
    }

    #[test]
    fn write_ahead_fails_closed_when_audit_cannot_be_written() {
        let mut audit = AuditLog::new(FailingWriter, "s");
        let batch = vec![Action::ToClient(serde_json::json!({"x": 1})), Action::Audit(ev())];
        // The caller executes effects only after write_ahead returns Ok.
        assert!(write_ahead(&mut audit, &batch, "s").is_err());
    }

    #[test]
    fn write_ahead_logs_every_event_in_the_batch() {
        let mut buf = Vec::new();
        {
            let mut audit = AuditLog::new(&mut buf, "s");
            let batch = vec![
                Action::Audit(ev()),
                Action::ToServer(serde_json::json!({})),
                Action::Audit(ev()),
            ];
            write_ahead(&mut audit, &batch, "s").unwrap();
        }
        assert_eq!(verify_chain(&String::from_utf8(buf).unwrap()).unwrap().0, 2);
    }

    fn ev() -> AuditEvent {
        AuditEvent {
            dir: Dir::Internal,
            method: None,
            subject: None,
            decision: Decision::Allow,
            reason: "x".into(),
            args_digest: None,
        }
    }

    #[test]
    fn concurrent_writers_keep_one_valid_chain() {
        // Two MCP hosts (e.g. VS Code's extension host and Agent Host) run a
        // proxy for the same server at once, each with its own handle on one
        // log. Their appends must serialize into a single verifiable chain (#29).
        let dir = std::env::temp_dir().join(format!("mcpsum-audit-race-{}-{}", std::process::id(), unix_ms()));
        let path = dir.join("s.jsonl");
        let (writers, per) = (8u64, 50u64);
        let handles: Vec<_> = (0..writers)
            .map(|w| {
                let path = path.clone();
                thread::spawn(move || {
                    let mut a = open_audit(&path, "s").unwrap();
                    for i in 0..per {
                        a.append(&ev(), w * 1000 + i).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let (n, _) = verify_chain(&text).unwrap_or_else(|e| panic!("chain forked: {e}"));
        assert_eq!(n, writers * per);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_resumes_valid_chain_and_quarantines_tampered_one() {
        let dir = std::env::temp_dir().join(format!("mcpsum-audit-test-{}", unix_ms()));
        let path = dir.join("s.jsonl");
        {
            let mut a = open_audit(&path, "s").unwrap();
            a.append(&ev(), 1).unwrap();
        }
        {
            let mut a = open_audit(&path, "s").unwrap();
            a.append(&ev(), 2).unwrap();
        }
        assert_eq!(verify_chain(&std::fs::read_to_string(&path).unwrap()).unwrap().0, 2);
        let text = std::fs::read_to_string(&path).unwrap().replace("\"x\"", "\"y\"");
        std::fs::write(&path, text).unwrap();
        {
            let mut a = open_audit(&path, "s").unwrap();
            a.append(&ev(), 3).unwrap();
        }
        assert_eq!(verify_chain(&std::fs::read_to_string(&path).unwrap()).unwrap().0, 1);
        let aside = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| e.file_name().to_string_lossy().contains("corrupt-"));
        assert!(aside, "tampered log must be preserved, not appended to");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
