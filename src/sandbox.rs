//! I5: turn a server's `policy.sandbox` into a concrete, checked grant
//! (design 0002). Enforcement lives in `sandbox_linux` (Landlock + seccomp);
//! every other platform refuses to start a sandboxed server (fail closed).
//!
//! The grant is **deny by default**: the server may read only a minimal
//! runtime base, its own program, and what the policy lists; it may write
//! only the listed paths and a private temporary directory. mcpsum's own
//! files (`mcp.lock`, audit logs, taint state, the mcpsum binary) and the home
//! directory can never be made writable, because Landlock has no deny rules:
//! granting a parent would grant them too.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::lock::{SandboxPolicy, TMP_VAR};

/// What the helper enforces. Paths are absolute and canonical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxSpec {
    /// Read and execute, recursively.
    pub read: Vec<PathBuf>,
    /// Read and write, recursively.
    pub write: Vec<PathBuf>,
    /// The server's private temporary directory (also in `write`).
    pub tmp: PathBuf,
    /// No network at all. (Allowlists come with the egress proxy.)
    pub no_network: bool,
}

/// Inputs to [`resolve`], gathered by [`prepare`]; separate so the checks are
/// testable without touching the real home directory.
#[derive(Debug, Clone)]
pub struct GrantInputs {
    pub home: Option<PathBuf>,
    pub tmp: PathBuf,
    /// Files and directories that must never become writable.
    pub protected: Vec<PathBuf>,
    /// Always-readable runtime base (system libraries, `/etc`, ...).
    pub base_read: Vec<PathBuf>,
    /// Always-writable device files (`/dev/null`).
    pub base_write: Vec<PathBuf>,
}

/// Expand `~` and `${TMP}`; reject anything else that is not absolute.
pub fn expand(p: &str, home: Option<&Path>, tmp: &Path) -> Result<PathBuf> {
    crate::lock::check_sandbox_path(p)?;
    let out = if p == "~" || p.starts_with("~/") {
        let home = home.context("`~` used in a sandbox path but HOME is not set")?;
        home.join(p.trim_start_matches('~').trim_start_matches('/'))
    } else if let Some(rest) = p.strip_prefix(TMP_VAR) {
        tmp.join(rest.trim_start_matches('/'))
    } else {
        PathBuf::from(p)
    };
    Ok(out)
}

/// Canonicalise the longest existing prefix of `p` and append the rest, so a
/// path that does not exist yet (an audit log) can still be compared.
pub fn canonical_lenient(p: &Path) -> PathBuf {
    let mut existing = p.to_path_buf();
    let mut rest = Vec::new();
    loop {
        if let Ok(c) = existing.canonicalize() {
            let mut out = c;
            for r in rest.iter().rev() {
                out.push(r);
            }
            return out;
        }
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_os_string());
                existing = parent.to_path_buf();
            }
            _ => return p.to_path_buf(),
        }
    }
}

/// The directory a program is installed under (`.../bin/prog` -> `...`), unless
/// that would be `/` or would contain the home directory; then just the
/// program's own directory, or only the file.
fn install_prefix(prog: &Path, home: Option<&Path>) -> PathBuf {
    let too_broad = |p: &Path| p.parent().is_none() || home.is_some_and(|h| h.starts_with(p));
    let dir = prog.parent().unwrap_or(prog);
    let prefix = dir.parent().unwrap_or(dir);
    if !too_broad(prefix) {
        return prefix.to_path_buf();
    }
    if !too_broad(dir) {
        return dir.to_path_buf();
    }
    prog.to_path_buf()
}

/// Build the concrete grant for `argv` (whose first element is already
/// resolved through PATH). Fails closed on anything unsafe or missing.
pub fn resolve(policy: &SandboxPolicy, argv: &[PathBuf], ctx: &GrantInputs) -> Result<SandboxSpec> {
    if !policy.network.allow.is_empty() {
        bail!(
            "policy.sandbox.network.allow is not supported yet (the egress proxy is the next step of design 0002); \
             use `\"allow\": []` for no network, or remove policy.sandbox"
        );
    }
    let home = ctx.home.as_deref();
    let canon = |raw: &str| -> Result<PathBuf> {
        let p = expand(raw, home, &ctx.tmp)?;
        p.canonicalize()
            .with_context(|| format!("sandbox path `{raw}` ({}) does not exist", p.display()))
    };
    let mut read: Vec<PathBuf> = ctx.base_read.iter().filter(|p| p.exists()).cloned().collect();
    // The program and its install prefix, both as given and as resolved
    // through symlinks (a venv's `bin/python` links to the system Python).
    if let Some(prog) = argv.first() {
        for p in [Some(prog.clone()), prog.canonicalize().ok()].into_iter().flatten() {
            read.push(install_prefix(&p, home));
        }
    }
    // Absolute file arguments (`python /path/server.py`): that file only.
    for a in argv.iter().skip(1) {
        if a.is_absolute() && a.is_file() {
            read.push(a.canonicalize()?);
        }
    }
    for r in &policy.filesystem.read {
        read.push(canon(r)?);
    }
    let mut write = vec![ctx.tmp.canonicalize().context("sandbox temporary directory")?];
    write.extend(ctx.base_write.iter().filter(|p| p.exists()).cloned());
    for w in &policy.filesystem.write {
        let p = canon(w)?;
        let protected = ctx
            .protected
            .iter()
            .map(|x| canonical_lenient(x))
            .chain(home.map(canonical_lenient));
        for x in protected {
            if x.starts_with(&p) {
                bail!(
                    "policy.sandbox.filesystem.write `{w}` would let the server modify `{}` \
                     (Landlock cannot exclude it from a writable parent); grant a narrower directory",
                    x.display()
                );
            }
        }
        if p.parent().is_none() {
            bail!("policy.sandbox.filesystem.write `{w}` grants the whole filesystem");
        }
        write.push(p);
    }
    read.sort();
    read.dedup();
    write.sort();
    write.dedup();
    Ok(SandboxSpec {
        read,
        write,
        tmp: ctx.tmp.canonicalize()?,
        no_network: true,
    })
}

/// The runtime base for Linux: what a typical interpreter needs to start.
/// `/proc` is readable, but Landlock's ptrace restrictions stop a sandboxed
/// process from reading other processes' memory or environment through it.
pub fn linux_base() -> (Vec<PathBuf>, Vec<PathBuf>) {
    let read = [
        "/usr",
        "/lib",
        "/lib64",
        "/lib32",
        "/bin",
        "/sbin",
        "/etc",
        "/proc",
        "/sys",
        "/dev/zero",
        "/dev/urandom",
        "/dev/random",
        "/dev/null",
    ];
    let write = ["/dev/null"];
    (
        read.iter().map(PathBuf::from).collect(),
        write.iter().map(PathBuf::from).collect(),
    )
}

/// A prepared sandbox: the grant plus its private temporary directory, which
/// is removed when this is dropped.
#[derive(Debug)]
pub struct PreparedSandbox {
    pub spec: SandboxSpec,
}

impl Drop for PreparedSandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.spec.tmp);
    }
}

/// Everything mcpsum must keep out of a server's reach.
pub fn protected_paths(lock_path: &Path, audit_path: Option<&Path>) -> Vec<PathBuf> {
    let mut v = vec![lock_path.to_path_buf()];
    if let Some(d) = lock_path.parent().filter(|d| !d.as_os_str().is_empty()) {
        v.push(d.to_path_buf());
    } else {
        v.push(PathBuf::from("."));
    }
    if let Some(a) = audit_path {
        v.push(a.to_path_buf());
        if let Some(d) = a.parent() {
            v.push(d.to_path_buf());
        }
    }
    if let Ok(d) = crate::taint::default_state_dir() {
        v.push(d);
    }
    if let Ok(exe) = std::env::current_exe() {
        v.push(exe.clone());
        if let Some(d) = exe.parent() {
            v.push(d.to_path_buf());
        }
    }
    v
}

/// Resolve and check a server's sandbox before it is started. On platforms
/// without a backend this refuses (fail closed, owner decision in design 0002).
pub fn prepare(
    name: &str,
    policy: &SandboxPolicy,
    argv: &[PathBuf],
    lock_path: &Path,
    audit_path: Option<&Path>,
) -> Result<PreparedSandbox> {
    if !cfg!(target_os = "linux") {
        bail!(
            "server `{name}` has a sandbox policy, but sandboxes are enforced on Linux only so far \
             (design 0002); it will not start. Remove policy.sandbox to run it unsandboxed."
        );
    }
    let tmp = make_private_tmp(name)?;
    let (base_read, base_write) = linux_base();
    let ctx = GrantInputs {
        home: std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from),
        tmp: tmp.clone(),
        protected: protected_paths(lock_path, audit_path),
        base_read,
        base_write,
    };
    match resolve(policy, argv, &ctx) {
        Ok(spec) => Ok(PreparedSandbox { spec }),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            Err(e.context(format!("server `{name}`: sandbox policy refused")))
        }
    }
}

fn make_private_tmp(name: &str) -> Result<PathBuf> {
    let safe: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(32)
        .collect();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("mcpsum-{safe}-{}-{nanos}", std::process::id()));
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut b = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    // `create` (not `create_all`) fails if it already exists: no pre-planted dir.
    b.create(&dir)
        .with_context(|| format!("creating sandbox temporary directory {}", dir.display()))?;
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::{FsPolicy, NetPolicy};

    struct Fixture {
        root: PathBuf,
        ctx: GrantInputs,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn fixture(tag: &str) -> Fixture {
        let root = std::env::temp_dir().join(format!("mcpsum-sbx-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for d in ["home/.ssh", "home/notes", "home/project/sub", "tmp", "base/usr", "bin"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        std::fs::write(root.join("home/project/mcp.lock"), "{}").unwrap();
        std::fs::write(root.join("bin/server.py"), "").unwrap();
        let root = root.canonicalize().unwrap();
        let ctx = GrantInputs {
            home: Some(root.join("home")),
            tmp: root.join("tmp"),
            protected: vec![root.join("home/project/mcp.lock"), root.join("home/project")],
            base_read: vec![root.join("base/usr"), root.join("base/missing")],
            base_write: vec![],
        };
        Fixture { root, ctx }
    }

    fn policy(read: &[&str], write: &[&str]) -> SandboxPolicy {
        SandboxPolicy {
            filesystem: FsPolicy {
                read: read.iter().map(|s| s.to_string()).collect(),
                write: write.iter().map(|s| s.to_string()).collect(),
            },
            network: NetPolicy::default(),
        }
    }

    #[test]
    fn i5_grant_is_deny_by_default_and_never_includes_home() {
        let f = fixture("default");
        let prog = f.root.join("bin/python");
        std::fs::write(&prog, "").unwrap();
        let spec = resolve(&policy(&[], &[]), &[prog, f.root.join("bin/server.py")], &f.ctx).unwrap();
        assert!(spec.no_network);
        assert!(spec.read.contains(&f.root.join("base/usr")));
        assert!(
            !spec.read.iter().any(|p| p.ends_with("missing")),
            "missing base paths are skipped"
        );
        assert!(
            spec.read.contains(&f.root.join("bin/server.py")),
            "absolute file argument"
        );
        let home = f.root.join("home");
        for p in spec.read.iter().chain(&spec.write) {
            assert!(!home.starts_with(p), "{} would expose the home directory", p.display());
        }
        assert_eq!(spec.write, vec![f.root.join("tmp")]);
    }

    #[test]
    fn i5_listed_paths_are_expanded_and_canonical() {
        let f = fixture("expand");
        let spec = resolve(&policy(&["~/notes"], &["${TMP}"]), &[], &f.ctx).unwrap();
        assert!(spec.read.contains(&f.root.join("home/notes")));
        assert!(spec.write.contains(&f.root.join("tmp")));
    }

    #[test]
    fn i5_writes_that_would_cover_mcpsum_files_or_home_are_refused() {
        let f = fixture("refuse");
        for w in ["~", "~/project", "/"] {
            let err = resolve(&policy(&[], &[w]), &[], &f.ctx).unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("would let the server modify") || msg.contains("whole filesystem"),
                "{w}: {msg}"
            );
        }
        // A sibling inside home is fine; a subdirectory of the project is fine too.
        resolve(&policy(&[], &["~/notes", "~/project/sub"]), &[], &f.ctx).unwrap();
    }

    #[test]
    fn i5_missing_paths_and_allowlists_fail_closed() {
        let f = fixture("missing");
        assert!(resolve(&policy(&["~/nope"], &[]), &[], &f.ctx).is_err());
        let mut p = policy(&[], &[]);
        p.network.allow = vec!["api.github.com:443".into()];
        assert!(format!("{:#}", resolve(&p, &[], &f.ctx).unwrap_err()).contains("not supported yet"));
    }

    #[test]
    fn i5_program_prefix_never_widens_to_root_or_home() {
        let home = Path::new("/home/u");
        assert_eq!(
            install_prefix(Path::new("/usr/bin/python3"), Some(home)),
            PathBuf::from("/usr")
        );
        assert_eq!(install_prefix(Path::new("/bin/sh"), Some(home)), PathBuf::from("/bin"));
        assert_eq!(
            install_prefix(Path::new("/home/u/.venv/bin/python"), Some(home)),
            PathBuf::from("/home/u/.venv")
        );
        assert_eq!(
            install_prefix(Path::new("/home/u/server"), Some(home)),
            PathBuf::from("/home/u/server")
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn i5_other_platforms_refuse_sandboxed_servers() {
        let err = prepare("x", &SandboxPolicy::default(), &[], Path::new("mcp.lock"), None).unwrap_err();
        assert!(format!("{err:#}").contains("will not start"));
    }
}
