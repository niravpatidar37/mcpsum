//! The I/O shell around the pure `Monitor`: spawn the locked server, pump
//! newline-delimited JSON-RPC between our stdio and the server, execute the
//! monitor's actions, and append every decision to the audit log.
//!
//! Threads: one reader per peer plus one ticker feed a single bounded channel;
//! the main loop is the only place that touches the monitor, so decisions are
//! strictly ordered. Server writes go through a dedicated writer thread so a
//! server that stops reading cannot stall the client side.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, SyncSender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde_json::Value;

use crate::audit::{verify_chain, AuditLog};
use crate::framing::{BoundedLines, Frame};
use crate::lock::LockFile;
use crate::monitor::{Action, Decision, Monitor, Policy};
use crate::process::spawn_server;
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

/// Open (or resume) the audit chain. A log that fails verification is moved
/// aside, never appended to, so tampering stays visible.
pub fn open_audit(path: &Path, server: &str) -> Result<AuditLog<File>> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let (prev, seq) = match std::fs::read_to_string(path) {
        Ok(text) => match verify_chain(&text) {
            Ok((n, last)) => (Some(last), n),
            Err(e) => {
                let aside = path.with_extension(format!("corrupt-{}.jsonl", unix_ms()));
                std::fs::rename(path, &aside)?;
                eprintln!(
                    "mcpsum: audit log {} failed verification ({e}); moved to {} and starting a new chain",
                    path.display(),
                    aside.display()
                );
                (None, 0)
            }
        },
        Err(_) => (None, 0),
    };
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    Ok(match prev {
        Some(p) => AuditLog::resume(file, server, p, seq),
        None => AuditLog::new(file, server),
    })
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
    let child_stdout = child.stdout.take().context("server stdout")?;
    let mut child_stdin = child.stdin.take().context("server stdin")?;

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
    for ev in rx {
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
        for a in actions {
            match a {
                Action::ToServer(v) => {
                    let mut line = serde_json::to_vec(&v)?;
                    line.push(b'\n');
                    if to_server.send(line).is_err() {
                        exit_code = 1;
                    }
                }
                Action::ToClient(v) => {
                    if write_line(&mut stdout.lock(), &v).is_err() {
                        return Ok(0); // client went away
                    }
                }
                Action::Audit(e) => {
                    if matches!(e.decision, Decision::Deny | Decision::Quarantine) {
                        eprintln!(
                            "mcpsum[{name}]: {:?} {} {}: {}",
                            e.decision,
                            escape_untrusted(e.method.as_deref().unwrap_or("-")),
                            escape_untrusted(e.subject.as_deref().unwrap_or("")),
                            escape_untrusted(&e.reason)
                        );
                    }
                    audit.append(&e, unix_ms())?;
                }
            }
        }
    }
    drop(to_server);
    let _ = writer.join();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            return Ok(exit_code);
        }
        thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();
    Ok(exit_code)
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
    use crate::monitor::{AuditEvent, Dir};

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
