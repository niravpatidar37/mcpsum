//! Hash-chained, append-only audit log (JSON Lines).
//!
//! Each entry commits to the previous entry's hash, so deleting, reordering or
//! editing any line breaks verification. This is tamper-*evident*, not
//! tamper-proof: an attacker with write access can rewrite the whole chain.
//! Ship entries to an external sink (SIEM) for stronger guarantees.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::canon::{canonical_json, sha256_tagged};
use crate::filelock::lock_exclusive;
use crate::monitor::AuditEvent;

pub const GENESIS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Anything audit events can be appended to.
pub trait AppendAudit {
    fn append_event(&mut self, ev: &AuditEvent, ts_ms: u64) -> Result<()>;
}

/// Build one entry: its canonical JSON line (no newline) and its hash.
fn build_entry(server: &str, seq: u64, prev: &str, ev: &AuditEvent, ts_ms: u64) -> (String, String) {
    let mut entry = json!({
        "seq": seq,
        "ts": ts_ms,
        "server": server,
        "event": ev,
        "prev": prev,
    });
    let hash = entry_hash(&entry);
    entry["hash"] = json!(hash);
    (canonical_json(&entry), hash)
}

/// An in-memory or single-writer chain over any `Write`.
pub struct AuditLog<W: Write> {
    w: W,
    server: String,
    prev: String,
    seq: u64,
}

impl<W: Write> AuditLog<W> {
    pub fn new(w: W, server: &str) -> Self {
        Self::resume(w, server, GENESIS.to_string(), 0)
    }

    pub fn resume(w: W, server: &str, prev: String, seq: u64) -> Self {
        Self {
            w,
            server: server.to_string(),
            prev,
            seq,
        }
    }

    pub fn append(&mut self, ev: &AuditEvent, ts_ms: u64) -> Result<()> {
        let (line, hash) = build_entry(&self.server, self.seq + 1, &self.prev, ev, ts_ms);
        writeln!(self.w, "{line}")?;
        self.w.flush()?;
        self.seq += 1;
        self.prev = hash;
        Ok(())
    }
}

impl<W: Write> AppendAudit for AuditLog<W> {
    fn append_event(&mut self, ev: &AuditEvent, ts_ms: u64) -> Result<()> {
        self.append(ev, ts_ms)
    }
}

/// How long a writer waits for the log before failing closed.
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest last line we will read back (entries are small; this bounds a
/// malformed or hostile file).
const MAX_TAIL: u64 = 1024 * 1024;

/// An audit chain on disk that several processes may append to at once.
///
/// MCP hosts can run two proxies for the same server concurrently (VS Code
/// runs servers in both its extension host and its Agent Host, #29). Every
/// append therefore takes an exclusive OS lock, re-reads the chain head *under
/// the lock*, checks that head's own hash, and writes one complete line. The
/// lock lives on a sidecar file (`<log>.lock`) that is never renamed, so moving
/// a corrupt log aside cannot race with another writer.
pub struct AuditFile {
    path: PathBuf,
    lock: File,
    server: String,
}

impl AuditFile {
    /// Open the log, creating it if needed. A log that fails verification is
    /// moved aside (kept, never appended to) and a new chain starts.
    pub fn open(path: &Path, server: &str) -> Result<Self> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let mut lock_path = path.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("opening {}", Path::new(&lock_path).display()))?;
        let me = Self {
            path: path.to_path_buf(),
            lock,
            server: server.to_string(),
        };
        let _guard = lock_exclusive(&me.lock, LOCK_TIMEOUT).context("locking the audit log")?;
        match std::fs::read_to_string(path) {
            Ok(text) => {
                if let Err(e) = verify_chain(&text) {
                    let ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis())
                        .unwrap_or(0);
                    let aside = path.with_extension(format!("corrupt-{ms}.jsonl"));
                    std::fs::rename(path, &aside)?;
                    eprintln!(
                        "mcpsum: audit log {} failed verification ({e}); moved to {} and starting a new chain",
                        path.display(),
                        aside.display()
                    );
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        }
        drop(_guard);
        Ok(me)
    }

    pub fn append(&mut self, ev: &AuditEvent, ts_ms: u64) -> Result<()> {
        let _guard = lock_exclusive(&self.lock, LOCK_TIMEOUT).context("locking the audit log")?;
        let (seq, prev) = match last_line(&self.path)? {
            None => (0, GENESIS.to_string()),
            Some(line) => head_of(&line).context("audit log head is invalid; refusing to extend it")?,
        };
        let (line, _) = build_entry(&self.server, seq + 1, &prev, ev, ts_ms);
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("opening {}", self.path.display()))?;
        let mut bytes = line.into_bytes();
        bytes.push(b'\n');
        f.write_all(&bytes)?; // one write of one complete line, under the lock
        f.flush()?;
        Ok(())
    }
}

impl AppendAudit for AuditFile {
    fn append_event(&mut self, ev: &AuditEvent, ts_ms: u64) -> Result<()> {
        self.append(ev, ts_ms)
    }
}

/// (seq, hash) of an entry line, after checking the entry's own hash.
fn head_of(line: &str) -> Result<(u64, String)> {
    let mut entry: Value = serde_json::from_str(line).context("last entry is not JSON")?;
    let obj = entry.as_object_mut().context("last entry is not an object")?;
    let stored = obj
        .remove("hash")
        .and_then(|h| h.as_str().map(str::to_string))
        .context("last entry has no hash")?;
    let seq = obj
        .get("seq")
        .and_then(Value::as_u64)
        .context("last entry has no seq")?;
    if entry_hash(&entry) != stored {
        bail!("last entry does not match its hash (edited)");
    }
    Ok((seq, stored))
}

/// The last line of a file (without its newline), or None for a missing or
/// empty file. Reads backwards in chunks; a file that does not end in a newline
/// (a torn write) is an error.
fn last_line(path: &Path) -> Result<Option<String>> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let len = f.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    const CHUNK: u64 = 8192;
    let mut buf: Vec<u8> = Vec::new();
    let mut end = len;
    loop {
        let start = end.saturating_sub(CHUNK);
        let mut chunk = vec![0u8; (end - start) as usize];
        f.seek(SeekFrom::Start(start))?;
        f.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&buf);
        buf = chunk;
        if buf.last() != Some(&b'\n') {
            bail!("audit log does not end with a complete line");
        }
        let body = &buf[..buf.len() - 1];
        if let Some(pos) = body.iter().rposition(|&b| b == b'\n') {
            return Ok(Some(String::from_utf8_lossy(&body[pos + 1..]).into_owned()));
        }
        if start == 0 {
            return Ok(Some(String::from_utf8_lossy(body).into_owned()));
        }
        if buf.len() as u64 > MAX_TAIL {
            bail!("last audit entry is larger than {MAX_TAIL} bytes");
        }
        end = start;
    }
}

fn entry_hash(entry_without_hash: &Value) -> String {
    sha256_tagged(canonical_json(entry_without_hash).as_bytes())
}

/// Verify a whole log. Returns (entries, last hash).
pub fn verify_chain(text: &str) -> Result<(u64, String)> {
    let mut prev = GENESIS.to_string();
    let mut seq = 0u64;
    for (i, line) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        let mut entry: Value = serde_json::from_str(line).with_context(|| format!("line {}: not JSON", i + 1))?;
        let obj = entry
            .as_object_mut()
            .with_context(|| format!("line {}: not an object", i + 1))?;
        let stored = obj
            .remove("hash")
            .and_then(|h| h.as_str().map(str::to_string))
            .with_context(|| format!("line {}: missing hash", i + 1))?;
        if obj.get("prev").and_then(Value::as_str) != Some(prev.as_str()) {
            bail!(
                "line {}: chain broken (prev hash mismatch: entry deleted, reordered or inserted)",
                i + 1
            );
        }
        if obj.get("seq").and_then(Value::as_u64) != Some(seq + 1) {
            bail!("line {}: sequence gap", i + 1);
        }
        if entry_hash(&entry) != stored {
            bail!("line {}: entry content does not match its hash (edited)", i + 1);
        }
        prev = stored;
        seq += 1;
    }
    Ok((seq, prev))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::{Decision, Dir};

    fn ev(reason: &str) -> AuditEvent {
        AuditEvent {
            dir: Dir::ClientToServer,
            method: Some("tools/call".into()),
            subject: Some("add".into()),
            decision: Decision::Allow,
            reason: reason.into(),
            args_digest: None,
        }
    }

    fn log3() -> String {
        let mut buf = Vec::new();
        {
            let mut log = AuditLog::new(&mut buf, "demo");
            log.append(&ev("one"), 1).unwrap();
            log.append(&ev("two"), 2).unwrap();
            log.append(&ev("three"), 3).unwrap();
        }
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn valid_chain_verifies() {
        let (n, last) = verify_chain(&log3()).unwrap();
        assert_eq!(n, 3);
        assert!(last.starts_with("sha256:"));
    }

    #[test]
    fn edited_entry_is_detected() {
        assert!(verify_chain(&log3().replacen("\"two\"", "\"TWO\"", 1)).is_err());
    }

    #[test]
    fn deleted_entry_is_detected() {
        let full = log3();
        let lines: Vec<&str> = full.lines().collect();
        let tampered = format!("{}\n{}\n", lines[0], lines[2]);
        assert!(verify_chain(&tampered).is_err());
    }

    #[test]
    fn reordered_entries_are_detected() {
        let full = log3();
        let lines: Vec<&str> = full.lines().collect();
        let tampered = format!("{}\n{}\n{}\n", lines[1], lines[0], lines[2]);
        assert!(verify_chain(&tampered).is_err());
    }

    #[test]
    fn resume_continues_the_chain() {
        let first = log3();
        let (n, last) = verify_chain(&first).unwrap();
        let mut buf = first.clone().into_bytes();
        {
            let mut log = AuditLog::resume(&mut buf, "demo", last, n);
            log.append(&ev("four"), 4).unwrap();
        }
        assert_eq!(verify_chain(&String::from_utf8(buf).unwrap()).unwrap().0, 4);
    }
}
