//! Spawning MCP servers with a scrubbed environment.
//!
//! The server inherits only a small allow-list of variables needed to run at
//! all (PATH, temp dirs, locale, Windows system paths) plus the variables the
//! lockfile explicitly names. Everything else, including API keys sitting in
//! the user's shell, is withheld.

use std::ffi::OsString;
use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, ChildStdin, ChildStdout, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(windows)]
use process_wrap::std::JobObject;
#[cfg(unix)]
use process_wrap::std::ProcessGroup;
use process_wrap::std::{ChildWrapper, CommandWrap};

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

/// A running MCP server **and every process it starts**.
///
/// On Unix the server leads a new process group; on Windows it runs in a Job
/// Object (it is created suspended and only resumed once assigned, so nothing
/// it starts can escape the job). Killing therefore reaches grandchildren that
/// launchers such as `npx`/`uvx` leave behind, which would otherwise keep
/// running unmediated and keep our stderr pipe open.
///
/// Limits: on Unix a process can leave the group with `setsid()`/`setpgid()`;
/// containing that needs the sandbox (PID namespaces or cgroups, issue #14).
/// The tree is killed on every normal exit, error and panic of mcpsum, but not
/// if mcpsum itself is killed abruptly (SIGKILL, TerminateProcess). The server's
/// stdin then closes, and well-behaved servers exit on their own.
pub struct ServerProcess {
    child: Box<dyn ChildWrapper>,
    done: bool,
}

/// How long to wait for the tree to be gone after it has been killed.
const REAP_TIMEOUT: Duration = Duration::from_secs(2);

impl ServerProcess {
    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin().take()
    }

    pub fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout().take()
    }

    pub fn take_stderr(&mut self) -> Option<ChildStderr> {
        self.child.stderr().take()
    }

    /// Give the server up to `grace` to exit on its own (call this after its
    /// stdin has been closed), then kill the whole tree. The kill is
    /// unconditional: a server that exits cleanly may still leave descendants.
    /// Every wait is bounded, so this never hangs on a process that refuses to die.
    pub fn shutdown(&mut self, grace: Duration) {
        if self.done {
            return;
        }
        self.done = true;
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(None) => thread::sleep(Duration::from_millis(50)),
                _ => break,
            }
        }
        let _ = self.child.start_kill();
        let deadline = Instant::now() + REAP_TIMEOUT;
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                _ => break,
            }
        }
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        self.shutdown(Duration::ZERO);
    }
}

/// Spawn a server with piped stdio and a scrubbed environment, as the leader of
/// its own process tree (see [`ServerProcess`]). stderr is piped too: it is
/// server-authored text, so it is relayed through [`relay_stderr`] rather than
/// inherited (raw bytes could carry terminal escape sequences that hide or
/// forge mcpsum's own output).
pub fn spawn_server(argv: &[String], passthrough: &[String]) -> Result<ServerProcess> {
    let (prog, args) = argv.split_first().context("empty server command")?;
    validate_env_names(passthrough)?;
    let resolved = resolve_program(prog);
    let env = scrubbed_env(passthrough);
    let mut cmd = CommandWrap::with_new(&resolved, |c| {
        c.args(args)
            .env_clear()
            .envs(env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    });
    #[cfg(unix)]
    cmd.wrap(ProcessGroup::leader());
    #[cfg(windows)]
    cmd.wrap(JobObject);
    let child = cmd
        .spawn()
        .with_context(|| format!("failed to start MCP server `{}`", resolved.display()))?;
    Ok(ServerProcess { child, done: false })
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

/// How long to wait, after the server is gone, for already-buffered stderr to
/// be relayed before giving up.
pub const STDERR_DRAIN_GRACE: Duration = Duration::from_millis(500);

/// Owns the stderr relay thread. Dropping it waits up to `grace` for the
/// thread to drain and finish, then detaches it. The wait is bounded because
/// a launcher's grandchild (npx, uvx) can hold the pipe open indefinitely;
/// an unbounded join would hang mcpsum. Drop this *after* the server has been
/// killed, so the pipe normally reaches EOF within the grace period.
pub struct StderrRelay {
    handle: Option<JoinHandle<()>>,
    grace: Duration,
}

impl StderrRelay {
    /// Wait up to `grace` for the relay to finish. Returns true if it finished.
    pub fn finish(&mut self) -> bool {
        let Some(h) = self.handle.take() else { return true };
        let deadline = Instant::now() + self.grace;
        while !h.is_finished() {
            if Instant::now() >= deadline {
                return false; // detached: a descendant still holds the pipe
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = h.join();
        true
    }
}

impl Drop for StderrRelay {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Relay a server's stderr to ours on a background thread, line by line,
/// through [`render_stderr_line`].
pub fn relay_stderr(server: &mut ServerProcess, name: &str) -> StderrRelay {
    relay_to(server.take_stderr(), name, STDERR_DRAIN_GRACE, std::io::stderr)
}

fn relay_to<R, W, F>(src: Option<R>, name: &str, grace: Duration, sink: F) -> StderrRelay
where
    R: std::io::Read + Send + 'static,
    W: Write,
    F: Fn() -> W + Send + 'static,
{
    let name = escape_untrusted(name);
    let handle = src.map(|src| {
        thread::spawn(move || {
            for frame in BoundedLines::new(BufReader::new(src), MAX_STDERR_LINE) {
                let Ok(frame) = frame else { break };
                if writeln!(sink(), "{}", render_stderr_line(&name, &frame)).is_err() {
                    break;
                }
            }
        })
    });
    StderrRelay { handle, grace }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_drains_buffered_lines_before_finishing() {
        use std::sync::{Arc, Mutex};
        #[derive(Clone, Default)]
        struct Sink(Arc<Mutex<Vec<u8>>>);
        impl Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let sink = Sink::default();
        let s2 = sink.clone();
        let src = std::io::Cursor::new(b"one\ntwo\nlast line before exit".to_vec());
        let mut relay = relay_to(Some(src), "srv", Duration::from_secs(5), move || s2.clone());
        assert!(relay.finish());
        let out = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            out,
            "[srv stderr] one\n[srv stderr] two\n[srv stderr] last line before exit\n"
        );
    }

    #[test]
    fn relay_finish_is_bounded_when_pipe_never_closes() {
        /// A reader that blocks forever, like a pipe held open by a grandchild.
        struct Never;
        impl std::io::Read for Never {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                loop {
                    thread::sleep(Duration::from_secs(3600));
                }
            }
        }
        let mut relay = relay_to(Some(Never), "srv", Duration::from_millis(100), std::io::sink);
        let t = Instant::now();
        assert!(!relay.finish());
        assert!(
            t.elapsed() < Duration::from_secs(2),
            "finish blocked: {:?}",
            t.elapsed()
        );
    }

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
