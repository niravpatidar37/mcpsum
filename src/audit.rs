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
    /// Open the log, creating it if needed. A log that fails verification, or
    /// that [`append`](Self::append) could not extend (not UTF-8, no final
    /// newline, a blank or oversized last line: torn writes), is moved aside
    /// unchanged (kept, never appended to) and a new chain starts.
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
        match std::fs::read(path) {
            Ok(bytes) => {
                if let Err(e) = check_extendable(path, &bytes) {
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
        let mut bytes = line.into_bytes();
        bytes.push(b'\n');
        // Never write a head that the next append could not read back.
        if bytes.len() as u64 > MAX_TAIL {
            bail!(
                "audit entry of {} bytes is larger than {MAX_TAIL}; refusing to write it",
                bytes.len()
            );
        }
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("opening {}", self.path.display()))?;
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

/// Fails unless the whole log verifies and `append` can read its head back,
/// so a log `open` keeps is one that `append` extends.
fn check_extendable(path: &Path, bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("not valid UTF-8")?;
    verify_chain(text)?;
    if let Some(line) = last_line(path)? {
        head_of(&line)?;
    }
    Ok(())
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

    fn scratch_log(tag: &str) -> (PathBuf, PathBuf) {
        let d = std::env::temp_dir().join(format!("mcpsum-audit-size-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let path = d.join("s.jsonl");
        (d, path)
    }

    /// An event whose entry line, newline included, is `bytes` long.
    fn event_of_size(bytes: usize, seq: u64, prev: &str) -> AuditEvent {
        let mut e = ev("sized");
        e.subject = Some(String::new());
        let base = build_entry("demo", seq, prev, &e, 1).0.len() + 1;
        e.subject = Some("a".repeat(bytes - base));
        assert_eq!(build_entry("demo", seq, prev, &e, 1).0.len() + 1, bytes);
        e
    }

    #[test]
    fn append_refuses_an_entry_it_could_not_read_back() {
        let (d, path) = scratch_log("over");
        let mut a = AuditFile::open(&path, "demo").unwrap();
        a.append(&ev("one"), 1).unwrap();
        let before = std::fs::read(&path).unwrap();
        let (_, prev) = verify_chain(std::str::from_utf8(&before).unwrap()).unwrap();
        let refused = a.append(&event_of_size(MAX_TAIL as usize + 1, 2, &prev), 1);
        let after = std::fs::read(&path).unwrap();
        let next = a.append(&ev("two"), 3);
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_dir_all(&d);
        assert!(refused.is_err(), "an entry over MAX_TAIL must be refused");
        assert_eq!(after, before, "a refused entry writes nothing");
        next.unwrap();
        assert_eq!(verify_chain(&text).unwrap().0, 2);
    }

    #[test]
    fn append_extends_an_entry_of_exactly_max_tail_bytes() {
        let (d, path) = scratch_log("exact");
        let mut a = AuditFile::open(&path, "demo").unwrap();
        a.append(&ev("one"), 1).unwrap();
        let (_, prev) = verify_chain(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let wrote = a.append(&event_of_size(MAX_TAIL as usize, 2, &prev), 1);
        let next = a.append(&ev("three"), 3);
        let text = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_dir_all(&d);
        wrote.unwrap();
        next.unwrap();
        assert_eq!(verify_chain(&text).unwrap().0, 3);
    }

    #[test]
    fn append_can_extend_every_entry_it_wrote() {
        // Before the bound, a 2 MiB entry was written and then refused as a
        // head by every later append: one entry blocked the log for good.
        let (d, path) = scratch_log("big");
        let mut a = AuditFile::open(&path, "demo").unwrap();
        let mut big = ev("big");
        big.subject = Some("a".repeat(2 * MAX_TAIL as usize));
        let _ = a.append(&big, 1);
        let next = a.append(&ev("next"), 2);
        let _ = std::fs::remove_dir_all(&d);
        next.unwrap_or_else(|e| panic!("append after an oversized entry failed: {e:#}"));
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mcpsum-audit-open-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Open a log holding `bytes`, append one entry, and return what was moved
    /// aside (if anything) and the live log afterwards.
    fn open_then_append(tag: &str, bytes: &[u8]) -> (Option<Vec<u8>>, String) {
        let d = scratch(tag);
        let path = d.join("s.jsonl");
        std::fs::write(&path, bytes).unwrap();
        let mut a = AuditFile::open(&path, "demo").unwrap_or_else(|e| panic!("open failed: {e:#}"));
        let appended = a.append(&ev("next"), 9);
        let aside: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("corrupt-"))
            .map(|e| std::fs::read(e.path()).unwrap())
            .collect();
        let live = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_dir_all(&d);
        appended.unwrap_or_else(|e| panic!("append after open failed: {e:#}"));
        assert!(aside.len() <= 1);
        (aside.into_iter().next(), live)
    }

    /// A log `append` cannot extend is moved aside byte for byte (never
    /// truncated or repaired) and a new chain starts.
    fn assert_moved_aside(tag: &str, bytes: &[u8]) {
        let (aside, live) = open_then_append(tag, bytes);
        assert_eq!(
            aside.as_deref(),
            Some(bytes),
            "the old log must be kept aside unchanged"
        );
        assert_eq!(verify_chain(&live).unwrap().0, 1, "a new chain starts");
    }

    #[test]
    fn open_resumes_a_log_append_can_extend() {
        let (aside, live) = open_then_append("ok", log3().as_bytes());
        assert!(aside.is_none());
        assert_eq!(verify_chain(&live).unwrap().0, 4);
    }

    #[test]
    fn open_moves_aside_a_log_with_an_edited_entry_below_an_intact_head() {
        assert_moved_aside("edited", log3().replacen("\"two\"", "\"TWO\"", 1).as_bytes());
    }

    #[test]
    fn open_moves_aside_a_log_missing_its_final_newline() {
        // A write torn just before its `\n` leaves a verifiable chain that
        // `append` can never extend.
        assert_moved_aside("nonl", log3().trim_end_matches('\n').as_bytes());
    }

    #[test]
    fn open_moves_aside_a_log_with_a_trailing_blank_line() {
        assert_moved_aside("blank", format!("{}\n", log3()).as_bytes());
    }

    #[test]
    fn open_moves_aside_a_log_of_blank_lines() {
        assert_moved_aside("blanks", b"\n\n");
    }

    #[test]
    fn open_moves_aside_a_log_torn_inside_a_utf8_character() {
        // Entries carry raw UTF-8; a write cut after the first byte of `€`.
        let mut bytes = log3().into_bytes();
        bytes.extend_from_slice(b"{\"event\":{\"reason\":\"\xE2");
        assert_moved_aside("utf8", &bytes);
    }

    #[test]
    fn open_moves_aside_invalid_utf8_even_where_lossy_decoding_would_verify() {
        // Swapping an entry's U+FFFD for a raw invalid byte keeps the lossy
        // text (and so every hash) the same: only a strict decode catches it.
        let mut buf = Vec::new();
        AuditLog::new(&mut buf, "demo").append(&ev("\u{FFFD}"), 1).unwrap();
        let text = String::from_utf8(buf).unwrap().replace('\u{FFFD}', "\u{1}");
        let bytes: Vec<u8> = text.bytes().map(|b| if b == 1 { 0xFF } else { b }).collect();
        assert!(verify_chain(&String::from_utf8_lossy(&bytes)).is_ok());
        assert_moved_aside("lossy", &bytes);
    }

    #[test]
    fn open_moves_aside_a_log_whose_head_is_too_large_to_read_back() {
        let mut buf = Vec::new();
        let mut big = ev("big");
        big.subject = Some("a".repeat(2 * MAX_TAIL as usize));
        let mut log = AuditLog::new(&mut buf, "demo");
        log.append(&ev("small"), 1).unwrap();
        log.append(&big, 2).unwrap();
        assert_eq!(verify_chain(std::str::from_utf8(&buf).unwrap()).unwrap().0, 2);
        assert_moved_aside("big", &buf);
    }
}
