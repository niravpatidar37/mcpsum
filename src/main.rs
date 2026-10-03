use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};

use mcpsum::audit::verify_chain;
use mcpsum::lock::{Change, LockFile, ServerLock};
use mcpsum::monitor::Policy;
use mcpsum::probe::{probe, ProbeOptions};
use mcpsum::process::validate_env_names;
use mcpsum::proxy::run_proxy;
use mcpsum::render::escape_untrusted;
use mcpsum::report::{findings, render_changes};

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
        Cmd::Proxy { lock, name, audit } => {
            run_proxy(&lock, &name, audit, Policy::default()).map(|c| if c == 0 { EXIT_OK } else { EXIT_DRIFT })
        }
        Cmd::Show { lock, name } => cmd_show(&lock, name.as_deref()),
        Cmd::AuditVerify { path } => cmd_audit_verify(&path),
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
    let surface = probe(&command, &env, &opts)?;
    let entry = ServerLock::from_surface(command, env, surface)?;

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
