use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use mcpsum::audit::verify_chain;
use mcpsum::lock::{suggest_taint_policy, Change, LockFile, ServerLock};
use mcpsum::monitor::Policy;
use mcpsum::probe::{probe, ProbeOptions};
use mcpsum::process::validate_env_names;
use mcpsum::proxy::{run_proxy, sandbox_argv};
use mcpsum::render::escape_untrusted;
use mcpsum::report::{findings, render_changes};
use mcpsum::sandbox::{prepare, SandboxSpec};
use mcpsum::taint;

/// Exit codes are part of the CLI contract (CI depends on them).
const EXIT_OK: u8 = 0;
const EXIT_DRIFT: u8 = 1;
const EXIT_FINDINGS: u8 = 2;
const EXIT_ERROR: u8 = 3;

#[derive(Parser)]
#[command(
    name = "mcpsum",
    version,
    about = "Lock what your AI agent's MCP tools say. Enforce it at runtime."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Probe a server and pin its definitions into the lockfile.
    Lock {
        #[arg(long, default_value = "mcp.lock")]
        lock: PathBuf,
        /// Name of this server in the lockfile (and in your MCP client config).
        #[arg(long)]
        name: String,
        /// Environment variable NAME to pass through to the server (repeatable). Values are never stored.
        #[arg(long = "env", value_name = "NAME")]
        env: Vec<String>,
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
        /// Exit 2 and do not write the lockfile when the heuristic scan has findings.
        #[arg(long)]
        deny_findings: bool,
        /// Server command, after `--`.
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// Re-probe locked servers and report drift. Exit 1 on definitional drift
    /// (tools, prompts, resources, instructions); informational changes
    /// (serverInfo, capabilities, protocol version) are reported but exit 0
    /// unless --strict, matching what the runtime proxy quarantines.
    Verify {
        #[arg(long, default_value = "mcp.lock")]
        lock: PathBuf,
        /// Only verify this server.
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value_t = 30)]
        timeout_secs: u64,
        /// Also exit 1 on informational changes.
        #[arg(long)]
        strict: bool,
    },
    /// Run a locked server behind the reference monitor (use this as the command in your MCP client config).
    Proxy {
        #[arg(long, default_value = "mcp.lock")]
        lock: PathBuf,
        #[arg(long)]
        name: String,
        /// Audit log path (default: <lock dir>/.mcpsum-audit/<name>.jsonl).
        #[arg(long)]
        audit: Option<PathBuf>,
        /// Taint session shared with other proxies (default: the MCP client's
        /// process id; also MCPSUM_SESSION). Only used with a taint policy.
        #[arg(long)]
        session: Option<String>,
    },
    /// Print the locked definitions with hidden characters made visible.
    Show {
        #[arg(long, default_value = "mcp.lock")]
        lock: PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
    /// Verify the hash chain of an audit log.
    AuditVerify { path: PathBuf },
    /// Print a suggested taint policy (I6) for a locked server, from its own
    /// annotations. Review it, then paste it into the server's entry; it is
    /// never applied automatically.
    SuggestPolicy {
        #[arg(long, default_value = "mcp.lock")]
        lock: PathBuf,
        #[arg(long)]
        name: String,
    },
    /// Internal: apply a sandbox and exec the server (used by mcpsum itself).
    #[command(name = "__sandbox-exec", hide = true)]
    SandboxExec {
        #[arg(long)]
        spec: String,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Inspect or reset tainted client sessions (I6).
    Taint {
        #[command(subcommand)]
        cmd: TaintCmd,
    },
}

#[derive(Subcommand)]
enum TaintCmd {
    /// List sessions that have read untrusted content.
    List,
    /// Clear a session's taint after you have reviewed it. Needs a person at a
    /// terminal, so an agent with a shell tool cannot clear its own taint.
    Reset {
        /// Session id (from `mcpsum taint list`).
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        session: Option<String>,
        /// Reset every session.
        #[arg(long)]
        all: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Lock {
            lock,
            name,
            env,
            timeout_secs,
            deny_findings,
            command,
        } => cmd_lock(&lock, &name, env, timeout_secs, deny_findings, command),
        Cmd::Verify {
            lock,
            name,
            timeout_secs,
            strict,
        } => cmd_verify(&lock, name.as_deref(), timeout_secs, strict),
        Cmd::Proxy {
            lock,
            name,
            audit,
            session,
        } => {
            let session = session.or_else(|| std::env::var("MCPSUM_SESSION").ok().filter(|s| !s.is_empty()));
            run_proxy(&lock, &name, audit, session, Policy::default())
                .map(|c| if c == 0 { EXIT_OK } else { EXIT_DRIFT })
        }
        Cmd::Show { lock, name } => cmd_show(&lock, name.as_deref()),
        Cmd::AuditVerify { path } => cmd_audit_verify(&path),
        Cmd::SuggestPolicy { lock, name } => cmd_suggest_policy(&lock, &name),
        Cmd::SandboxExec { spec, command } => cmd_sandbox_exec(&spec, &command),
        Cmd::Taint { cmd } => match cmd {
            TaintCmd::List => cmd_taint_list(),
            TaintCmd::Reset { session, all } => cmd_taint_reset(session.as_deref(), all),
        },
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("mcpsum: error: {}", escape_untrusted(&format!("{e:#}")));
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn load_or_new(path: &Path) -> Result<LockFile> {
    if path.exists() {
        LockFile::load(path)
    } else {
        Ok(LockFile::new())
    }
}

/// Write via a temp file + rename so a crash never leaves a half-written lock.
fn write_lock(path: &Path, lf: &LockFile) -> Result<()> {
    let tmp = path.with_extension("lock.tmp");
    std::fs::write(&tmp, lf.to_pretty()?).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

fn cmd_lock(
    lock: &Path,
    name: &str,
    env: Vec<String>,
    timeout_secs: u64,
    deny_findings: bool,
    command: Vec<String>,
) -> Result<u8> {
    validate_env_names(&env)?;
    if name.is_empty() || name.chars().any(|c| c.is_control()) {
        bail!("invalid server name");
    }
    let mut lf = load_or_new(lock)?;
    eprintln!(
        "mcpsum: probing `{}` (scrubbed environment; no sandbox yet)",
        escape_untrusted(&command.join(" "))
    );
    let opts = ProbeOptions {
        timeout: Duration::from_secs(timeout_secs),
        ..ProbeOptions::default()
    };
    // Re-locking a sandboxed server probes it inside its sandbox too.
    let old_sandbox = lf
        .servers
        .get(name)
        .and_then(|s| s.policy.as_ref())
        .and_then(|p| p.sandbox.clone());
    let prepared = match &old_sandbox {
        Some(sb) => Some(prepare(name, sb, &sandbox_argv(&command), lock, None)?),
        None => None,
    };
    let opts = ProbeOptions {
        sandbox: prepared.as_ref().map(|p| p.spec.clone()),
        ..opts
    };
    let surface = probe(&command, &env, &opts)?;
    let mut entry = ServerLock::from_surface(command, env, surface)?;
    // The policy is the user's decision, not the server's: keep it on re-lock.
    if let Some(old) = lf.servers.get(name) {
        for label in entry.carry_policy_from(old) {
            println!(
                "policy: dropped `{}` (that tool is gone; relabel it if it was renamed)",
                escape_untrusted(&label)
            );
        }
    }

    let others: Vec<(&str, &mcpsum::lock::Surface)> = lf
        .servers
        .iter()
        .filter(|(n, _)| n.as_str() != name)
        .map(|(n, s)| (n.as_str(), &s.surface))
        .collect();
    let found = findings(&entry.surface, &others);

    if let Some(old) = lf.servers.get(name) {
        let changes = old.surface.compare(&entry.surface)?;
        if changes.is_empty() {
            println!("server `{}`: unchanged", escape_untrusted(name));
        } else {
            println!("server `{}`: changes since the previous lock:", escape_untrusted(name));
            print!("{}", render_changes(&old.surface, &entry.surface, &changes));
        }
    }
    let s = &entry.surface;
    println!(
        "locked `{}`: {} tools, {} prompts, {} resources, {} resource templates",
        escape_untrusted(name),
        s.tools.len(),
        s.prompts.len(),
        s.resources.len(),
        s.resource_templates.len()
    );
    if !found.is_empty() {
        println!("\nfindings (heuristic; review before approving):");
        for f in &found {
            println!("  ! {f}");
        }
    }
    if deny_findings && !found.is_empty() {
        println!("\nnot written: --deny-findings is set");
        return Ok(EXIT_FINDINGS);
    }
    lf.servers.insert(name.to_string(), entry);
    write_lock(lock, &lf)?;
    println!("\nwrote {}. Review the diff before committing it.", lock.display());
    Ok(EXIT_OK)
}

fn cmd_verify(lock: &Path, name: Option<&str>, timeout_secs: u64, strict: bool) -> Result<u8> {
    let lf = LockFile::load(lock)?;
    let opts = ProbeOptions {
        timeout: Duration::from_secs(timeout_secs),
        ..ProbeOptions::default()
    };
    let names: Vec<&String> = match name {
        Some(n) => vec![
            lf.servers
                .get_key_value(n)
                .with_context(|| format!("server `{n}` is not in the lockfile"))?
                .0,
        ],
        None => lf.servers.keys().collect(),
    };
    let mut drift = false;
    for n in names {
        let entry = &lf.servers[n];
        let prepared = match entry.policy.as_ref().and_then(|p| p.sandbox.as_ref()) {
            Some(sb) => Some(prepare(n, sb, &sandbox_argv(&entry.command), lock, None)?),
            None => None,
        };
        let opts = ProbeOptions {
            sandbox: prepared.as_ref().map(|p| p.spec.clone()),
            ..opts.clone()
        };
        let live = probe(&entry.command, &entry.env_passthrough, &opts).with_context(|| format!("server `{n}`"))?;
        let changes = entry.surface.compare(&live)?;
        if changes.is_empty() {
            println!("ok     {}", escape_untrusted(n));
        } else {
            let definitional = changes.iter().any(Change::is_definitional);
            // Definitional drift always fails; informational changes only with --strict.
            if definitional || strict {
                drift = true;
            }
            println!(
                "{} {}",
                if definitional { "DRIFT " } else { "info  " },
                escape_untrusted(n)
            );
            print!("{}", render_changes(&entry.surface, &live, &changes));
        }
    }
    Ok(if drift { EXIT_DRIFT } else { EXIT_OK })
}

fn cmd_show(lock: &Path, name: Option<&str>) -> Result<u8> {
    let lf = LockFile::load(lock)?;
    for (n, entry) in &lf.servers {
        if name.is_some_and(|x| x != n) {
            continue;
        }
        println!(
            "server `{}`  command: {}",
            escape_untrusted(n),
            escape_untrusted(&entry.command.join(" "))
        );
        if let Some(i) = &entry.surface.instructions {
            println!("  instructions: {}", escape_untrusted(i));
        }
        for t in &entry.surface.tools {
            let tn = t.get("name").and_then(|v| v.as_str()).unwrap_or("?");
            let d = t.get("description").and_then(|v| v.as_str()).unwrap_or("");
            println!("  tool {}: {}", escape_untrusted(tn), escape_untrusted(d));
        }
        if let Some(tp) = entry.policy.as_ref().and_then(|p| p.taint.as_ref()) {
            let join = |s: &std::collections::BTreeSet<String>| {
                s.iter().map(|x| escape_untrusted(x)).collect::<Vec<_>>().join(", ")
            };
            println!(
                "  taint policy: sources [{}], sinks [{}]",
                join(&tp.sources),
                join(&tp.sinks)
            );
        }
        for f in findings(&entry.surface, &[]) {
            println!("  ! {f}");
        }
    }
    Ok(EXIT_OK)
}

fn cmd_audit_verify(path: &Path) -> Result<u8> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    match verify_chain(&text) {
        Ok((n, last)) => {
            println!("ok: {n} entries, head {last}");
            Ok(EXIT_OK)
        }
        Err(e) => {
            println!("TAMPERED: {e}");
            Ok(EXIT_DRIFT)
        }
    }
}

fn cmd_suggest_policy(lock: &Path, name: &str) -> Result<u8> {
    let lf = LockFile::load(lock)?;
    let entry = lf.server(name)?;
    let snippet = serde_json::json!({"policy": {"taint": suggest_taint_policy(&entry.surface)}});
    println!(
        "Suggested taint policy for `{}`, from the server's own annotations.",
        escape_untrusted(name)
    );
    println!("Annotations are claims made by the server: check every label, then paste");
    println!(
        "this into the server's entry in {}. mcpsum never applies it on its own.\n",
        lock.display()
    );
    // Tool names are server-written: escape each line for the terminal.
    for line in serde_json::to_string_pretty(&snippet)?.lines() {
        println!("{}", escape_untrusted(line));
    }
    Ok(EXIT_OK)
}

fn cmd_taint_list() -> Result<u8> {
    let dir = taint::default_state_dir()?;
    let sessions = taint::list(&dir)?;
    if sessions.is_empty() {
        println!("no tainted sessions ({})", dir.display());
    }
    for (session, m) in sessions {
        match m {
            Ok(m) => println!(
                "{session}  tainted by {}  at {} (unix ms)",
                escape_untrusted(&m.source),
                m.at_ms
            ),
            Err(e) => println!("{session}  UNREADABLE (treated as tainted): {}", escape_untrusted(&e)),
        }
    }
    Ok(EXIT_OK)
}

fn cmd_taint_reset(session: Option<&str>, all: bool) -> Result<u8> {
    use std::io::{BufRead, IsTerminal};
    // Defence in depth: an agent with a shell tool usually has no terminal.
    // (It could still delete the marker file itself; see GUARANTEES I6.)
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        bail!("refusing: `taint reset` must be run by a person in a terminal");
    }
    let dir = taint::default_state_dir()?;
    let targets: Vec<String> = if all {
        taint::list(&dir)?.into_iter().map(|(s, _)| s).collect()
    } else {
        vec![session.unwrap_or_default().to_string()]
    };
    if targets.is_empty() {
        println!("no tainted sessions");
        return Ok(EXIT_OK);
    }
    eprintln!(
        "Reset taint for {}? Only do this if you have reviewed what the agent read. Type `reset` to confirm:",
        targets.join(", ")
    );
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    if answer.trim() != "reset" {
        println!("not reset");
        return Ok(EXIT_ERROR);
    }
    for s in targets {
        if taint::clear(&dir, &s)? {
            println!("reset {s}");
        } else {
            println!("{s} was not tainted");
        }
    }
    Ok(EXIT_OK)
}

fn cmd_sandbox_exec(spec: &str, command: &[String]) -> Result<u8> {
    let spec: SandboxSpec = serde_json::from_str(spec).context("invalid sandbox spec")?;
    #[cfg(target_os = "linux")]
    {
        match mcpsum::sandbox_linux::exec(&spec, command)? {}
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (spec, command);
        bail!("sandboxes are enforced on Linux only so far; refusing to start the server")
    }
}
