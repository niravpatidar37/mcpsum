//! Spawning MCP servers with a scrubbed environment.
//!
//! The server inherits only a small allow-list of variables needed to run at
//! all (PATH, temp dirs, locale, Windows system paths) plus the variables the
//! lockfile explicitly names. Everything else, including API keys sitting in
//! the user's shell, is withheld.

use std::ffi::OsString;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};

use crate::framing::{BoundedLines, Frame};
use crate::render::escape_untrusted;

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
/// piped too: it is server-authored text, so it is relayed through
/// [`relay_stderr`] rather than inherited (raw bytes could carry terminal
/// escape sequences that hide or forge mcpsum's own output).
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
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to start MCP server `{}`", resolved.display()))
}

/// Longest server stderr line relayed; the rest is dropped (flood control).
pub const MAX_STDERR_LINE: usize = 4096;

/// Render one line of server stderr for display: lossy UTF-8, every control
/// and invisible character escaped (no ESC/CSI/OSC reaches the terminal),
/// length-capped, and prefixed so it cannot pass for mcpsum's own output.
pub fn render_stderr_line(name: &str, frame: &Frame) -> String {
    match frame {
        Frame::Line(bytes) => {
            let text = String::from_utf8_lossy(bytes);
            format!("[{name} stderr] {}", escape_untrusted(text.trim_end_matches('\r')))
        }
        Frame::TooLong => format!("[{name} stderr] <line over {MAX_STDERR_LINE} bytes dropped>"),
    }
}

/// Relay a child's stderr to ours on a background thread, line by line,
/// through [`render_stderr_line`].
pub fn relay_stderr(child: &mut Child, name: &str) -> Option<JoinHandle<()>> {
    let stderr = child.stderr.take()?;
    let name = escape_untrusted(name);
    Some(thread::spawn(move || {
        for frame in BoundedLines::new(BufReader::new(stderr), MAX_STDERR_LINE) {
            let Ok(frame) = frame else { break };
            if writeln!(std::io::stderr().lock(), "{}", render_stderr_line(&name, &frame)).is_err() {
                break;
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stderr_terminal_escapes_are_neutralised() {
        // CSI clear-screen + cursor-home, OSC 52 clipboard write, BEL, a fake
        // "OK" line via carriage return, and a bidi override.
        let evil = b"\x1b[2J\x1b[H\x1b]52;c;ZWNobyBwd25lZA==\x07all good\rOK  weather\xe2\x80\xae".to_vec();
        let out = render_stderr_line("weather", &Frame::Line(evil));
        assert!(out.starts_with("[weather stderr] "), "{out}");
        assert!(
            !out.chars().any(|c| c.is_control()),
            "raw control char survived: {out:?}"
        );
        assert!(
            out.contains("<U+001B>") && out.contains("<U+0007>") && out.contains("<U+202E>"),
            "{out}"
        );
        assert!(out.contains("\\r"), "{out}");
    }

    #[test]
    fn stderr_invalid_utf8_and_oversize_lines_are_safe() {
        let out = render_stderr_line("s", &Frame::Line(vec![0xff, 0xfe, b'x']));
        assert!(out.ends_with('x') && !out.chars().any(|c| c.is_control()), "{out:?}");
        let out = render_stderr_line("s", &Frame::TooLong);
        assert!(out.contains("dropped"), "{out}");
    }

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
