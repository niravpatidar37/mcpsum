//! Hash-chained, append-only audit log (JSON Lines).
//!
//! Each entry commits to the previous entry's hash, so deleting, reordering or
//! editing any line breaks verification. This is tamper-*evident*, not
//! tamper-proof: an attacker with write access can rewrite the whole chain.
//! Ship entries to an external sink (SIEM) for stronger guarantees.

use std::io::Write;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use crate::canon::{canonical_json, sha256_tagged};
use crate::monitor::AuditEvent;

pub const GENESIS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

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
        self.seq += 1;
        let mut entry = json!({
            "seq": self.seq,
            "ts": ts_ms,
            "server": self.server,
            "event": ev,
            "prev": self.prev,
        });
        let hash = entry_hash(&entry);
        entry["hash"] = json!(hash);
        writeln!(self.w, "{}", canonical_json(&entry))?;
        self.w.flush()?;
        self.prev = hash;
        Ok(())
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
