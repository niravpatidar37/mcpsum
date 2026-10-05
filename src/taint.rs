//! Shared taint state for one client session (I6, design 0001 §4.4).
//!
//! mcpsum runs one proxy per server, but the important flows cross servers:
//! a page fetched by `web` steers `send_email` on `mail`. So every proxy that
//! serves the same client session shares one marker file:
//!
//! - **Session key:** the proxy's parent process (the MCP client that spawned
//!   it), or `--session` / `MCPSUM_SESSION` where that grouping is wrong.
//! - **Location:** a per-user directory (`$XDG_RUNTIME_DIR/mcpsum/sessions`,
//!   `~/.cache/mcpsum/sessions`, `%LOCALAPPDATA%\mcpsum\sessions`), owner-only
//!   on Unix; `MCPSUM_STATE_DIR` overrides it.
//! - **Fail safe:** a marker that exists but cannot be read counts as tainted;
//!   a stale marker whose process id was reused makes a new session start
//!   tainted (more prompts, never fewer). Markers are never pruned
//!   automatically; only `mcpsum taint reset` removes them.
//!
//! Writes are atomic (temporary file, then rename), so readers see either no
//! marker or a complete one. The first source to taint a session is kept.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

const MARKER_EXT: &str = "taint";
const MAX_SESSION_LEN: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marker {
    /// `<server>:<policy label>` that tainted the session.
    pub source: String,
    /// Unix time in milliseconds.
    pub at_ms: u64,
}

/// A session id is used as a file name: allow a small safe alphabet only.
pub fn validate_session(s: &str) -> Result<()> {
    if s.is_empty()
        || s.len() > MAX_SESSION_LEN
        || s.starts_with('.')
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("invalid session id (use 1-{MAX_SESSION_LEN} characters from A-Z a-z 0-9 . _ -, not starting with `.`)");
    }
    Ok(())
}

/// The default session: the MCP client process that spawned this proxy.
pub fn default_session() -> Result<String> {
    let ppid = parent_pid().context("cannot determine the parent process (pass --session)")?;
    Ok(format!("ppid-{ppid}"))
}

#[cfg(unix)]
pub fn parent_pid() -> Option<u32> {
    Some(std::os::unix::process::parent_id())
}

#[cfg(windows)]
pub fn parent_pid() -> Option<u32> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    let me = std::process::id();
    // SAFETY: the snapshot handle is checked before use and closed exactly
    // once; PROCESSENTRY32W is plain data with dwSize set as the API requires.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        let mut ok = Process32FirstW(snap, &mut e);
        while ok != 0 {
            if e.th32ProcessID == me {
                found = Some(e.th32ParentProcessID);
                break;
            }
            ok = Process32NextW(snap, &mut e);
        }
        CloseHandle(snap);
        found
    }
}

/// Per-user directory for session markers.
pub fn default_state_dir() -> Result<PathBuf> {
    if let Some(d) = std::env::var_os("MCPSUM_STATE_DIR").filter(|d| !d.is_empty()) {
        return Ok(PathBuf::from(d));
    }
    #[cfg(unix)]
    {
        if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
            return Ok(PathBuf::from(d).join("mcpsum").join("sessions"));
        }
        let home = std::env::var_os("HOME")
            .filter(|d| !d.is_empty())
            .context("HOME is not set")?;
        Ok(PathBuf::from(home).join(".cache").join("mcpsum").join("sessions"))
    }
    #[cfg(windows)]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .filter(|d| !d.is_empty())
            .context("LOCALAPPDATA is not set")?;
        Ok(PathBuf::from(base).join("mcpsum").join("sessions"))
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn ensure_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {}", dir.display()))?;
    }
    Ok(())
}

/// The taint marker of one session.
#[derive(Debug, Clone)]
pub struct TaintStore {
    dir: PathBuf,
    session: String,
}

impl TaintStore {
    pub fn open(dir: &Path, session: &str) -> Result<Self> {
        validate_session(session)?;
        ensure_dir(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            session: session.to_string(),
        })
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    fn path(&self) -> PathBuf {
        marker_path(&self.dir, &self.session)
    }

    /// The source that tainted this session, if any. A marker that exists but
    /// cannot be read or parsed is an error: callers must treat it as tainted.
    pub fn read(&self) -> Result<Option<String>> {
        read_marker(&self.path()).map(|m| m.map(|m| m.source))
    }

    /// Record that `source` tainted the session (kept if one is already
    /// recorded). Errors must stop the caller before it delivers the text.
    pub fn mark(&self, source: &str) -> Result<()> {
        if matches!(self.read(), Ok(Some(_))) {
            return Ok(());
        }
        let m = Marker {
            source: source.to_string(),
            at_ms: unix_ms(),
        };
        let tmp = self.dir.join(format!(".{}.{}.tmp", self.session, std::process::id()));
        {
            let mut opts = fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
            f.write_all(&serde_json::to_vec(&m)?)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, self.path()).with_context(|| format!("recording taint in {}", self.path().display()))?;
        Ok(())
    }
}

fn marker_path(dir: &Path, session: &str) -> PathBuf {
    dir.join(format!("{session}.{MARKER_EXT}"))
}

fn read_marker(path: &Path) -> Result<Option<Marker>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .with_context(|| format!("unreadable taint marker {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Every tainted session in `dir`: (session, marker or the reason it is unreadable).
pub fn list(dir: &Path) -> Result<Vec<(String, Result<Marker, String>)>> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some(MARKER_EXT) {
            continue;
        }
        let Some(session) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if validate_session(session).is_err() {
            continue;
        }
        let m = match read_marker(&path) {
            Ok(Some(m)) => Ok(m),
            Ok(None) => continue,
            Err(e) => Err(format!("{e:#}")),
        };
        out.push((session.to_string(), m));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Remove a session's marker. Returns whether there was one.
pub fn clear(dir: &Path, session: &str) -> Result<bool> {
    validate_session(session)?;
    match fs::remove_file(marker_path(dir, session)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("clearing session {session}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mcpsum-taint-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn i6_marker_is_shared_by_every_store_of_a_session_and_cleared_only_by_reset() {
        let d = dir("share");
        let web = TaintStore::open(&d, "ppid-42").unwrap();
        let mail = TaintStore::open(&d, "ppid-42").unwrap();
        let other = TaintStore::open(&d, "ppid-43").unwrap();
        assert_eq!(mail.read().unwrap(), None);
        web.mark("web:fetch").unwrap();
        assert_eq!(mail.read().unwrap().as_deref(), Some("web:fetch"));
        assert_eq!(other.read().unwrap(), None, "sessions are isolated");
        mail.mark("mail:read_inbox").unwrap();
        assert_eq!(
            web.read().unwrap().as_deref(),
            Some("web:fetch"),
            "first source is kept"
        );
        let l = list(&d).unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].0, "ppid-42");
        assert!(clear(&d, "ppid-42").unwrap());
        assert!(!clear(&d, "ppid-42").unwrap());
        assert_eq!(mail.read().unwrap(), None);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn i6_unreadable_marker_is_an_error_so_callers_fail_safe() {
        let d = dir("corrupt");
        let s = TaintStore::open(&d, "s1").unwrap();
        fs::write(d.join("s1.taint"), b"{not json").unwrap();
        assert!(s.read().is_err());
        assert!(list(&d).unwrap()[0].1.is_err());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn i6_session_ids_cannot_escape_the_state_directory() {
        for bad in [
            "",
            "..",
            "../x",
            "a/b",
            "a\\b",
            ".hidden",
            "a b",
            "x:y",
            &"a".repeat(65),
        ] {
            assert!(validate_session(bad).is_err(), "{bad:?}");
            assert!(TaintStore::open(&dir("bad"), bad).is_err());
        }
        for good in ["ppid-123", "claude.main_1", "A-z_0.9"] {
            validate_session(good).unwrap();
        }
    }

    #[test]
    fn i6_parent_pid_is_found() {
        let p = parent_pid().expect("parent pid");
        assert_ne!(p, std::process::id());
        #[cfg(unix)]
        assert_eq!(p, std::os::unix::process::parent_id());
        assert!(default_session().unwrap().starts_with("ppid-"));
    }

    #[cfg(unix)]
    #[test]
    fn i6_state_is_owner_only_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("perm");
        TaintStore::open(&d, "s").unwrap().mark("a:b").unwrap();
        assert_eq!(fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(d.join("s.taint")).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(&d);
    }
}
