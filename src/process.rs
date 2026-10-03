//! Spawning MCP servers with a scrubbed environment.
//!
//! The server inherits only a small allow-list of variables needed to run at
//! all (PATH, temp dirs, locale, Windows system paths) plus the variables the
//! lockfile explicitly names. Everything else, including API keys sitting in
//! the user's shell, is withheld.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use anyhow::{bail, Context, Result};

/// Variables every server may see. None of these should hold secrets.
pub const BASE_ENV: &[&str] = &[
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
];

fn same_name(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

/// Validate names given with `--env`.
pub fn validate_env_names(names: &[String]) -> Result<()> {
    for n in names {
        if n.is_empty() || n.contains('=') || n.contains('\0') {
            bail!("invalid environment variable name `{n}`");
        }
    }
    Ok(())
}

/// The environment a server process receives.
pub fn scrubbed_env(passthrough: &[String]) -> Vec<(OsString, OsString)> {
    std::env::vars_os()
        .filter(|(k, _)| {
            k.to_str().is_some_and(|k| {
                BASE_ENV.iter().any(|a| same_name(a, k)) || passthrough.iter().any(|p| same_name(p, k))
            })
        })
        .collect()
}

/// Resolve a bare program name through PATH (and PATHEXT on Windows), so that
/// `npx` finds `npx.cmd`. Paths are returned unchanged.
pub fn resolve_program(prog: &str) -> PathBuf {
    let p = Path::new(prog);
    if p.is_absolute() || p.components().count() > 1 {
        return p.to_path_buf();
    }
    let Some(path) = std::env::var_os("PATH") else {
        return p.to_path_buf();
    };
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
            .split(';')
            .filter(|e| !e.is_empty())
            .map(str::to_ascii_lowercase)
            .collect()
    } else {
        Vec::new()
    };
    for dir in std::env::split_paths(&path) {
        let direct = dir.join(prog);
        if (!cfg!(windows) || p.extension().is_some()) && direct.is_file() {
            return direct;
        }
        for e in &exts {
            let c = dir.join(format!("{prog}{e}"));
            if c.is_file() {
                return c;
            }
        }
    }
    p.to_path_buf()
}

/// Spawn a server with piped stdio and a scrubbed environment. stderr is
/// inherited so server diagnostics stay visible to the user.
pub fn spawn_server(argv: &[String], passthrough: &[String]) -> Result<Child> {
    let (prog, args) = argv.split_first().context("empty server command")?;
    validate_env_names(passthrough)?;
    let resolved = resolve_program(prog);
    Command::new(&resolved)
        .args(args)
        .env_clear()
        .envs(scrubbed_env(passthrough))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to start MCP server `{}`", resolved.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_withheld_unless_passed_through() {
        // SAFETY (edition 2021): test-only; the variable name is unique to this test.
        std::env::set_var("MCPSUM_TEST_SECRET_7F3A", "hunter2");
        let env = scrubbed_env(&[]);
        assert!(!env.iter().any(|(k, _)| k == "MCPSUM_TEST_SECRET_7F3A"));
        let env = scrubbed_env(&["MCPSUM_TEST_SECRET_7F3A".into()]);
        assert!(env
            .iter()
            .any(|(k, v)| k == "MCPSUM_TEST_SECRET_7F3A" && v == "hunter2"));
    }

    #[test]
    fn path_is_kept_so_servers_can_run() {
        assert!(scrubbed_env(&[])
            .iter()
            .any(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case("PATH")));
    }

    #[test]
    fn invalid_env_names_are_rejected() {
        assert!(validate_env_names(&["A=B".into()]).is_err());
        assert!(validate_env_names(&["".into()]).is_err());
        assert!(validate_env_names(&["GITHUB_TOKEN".into()]).is_ok());
    }

    #[test]
    fn resolves_programs_on_path() {
        let cargo = resolve_program("cargo");
        assert!(cargo.is_absolute() && cargo.is_file(), "{}", cargo.display());
        assert_eq!(resolve_program("./x/y"), PathBuf::from("./x/y"));
    }
}
