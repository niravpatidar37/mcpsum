//! Linux enforcement of a [`SandboxSpec`] (design 0002, §5.3–5.4).
//!
//! Runs in the single-threaded `mcpsum __sandbox-exec` helper, immediately
//! before it `execve`s the server, so the server keeps the helper's PID (and
//! therefore stays inside mcpsum's process-tree control, #7).
//!
//! 1. **Landlock**: deny-by-default filesystem rules, TCP bind/connect denied
//!    (ABI ≥ 4), and scoping of signals and abstract Unix sockets (ABI ≥ 6).
//!    Best effort *upwards* only: Landlock must at least enforce filesystem
//!    rules, or the helper refuses (fail closed).
//! 2. **seccomp**: no `AF_INET`/`AF_INET6`/`AF_PACKET`/`AF_NETLINK` sockets
//!    (no network on any kernel, no DNS), no `io_uring` (it can create sockets
//!    without `socket(2)`), and none of the syscalls that would let the server
//!    build more privilege: namespaces, mounts, `bpf`, keyrings, `ptrace`,
//!    `perf_event_open`. `clone3` gets `ENOSYS` so libc falls back to `clone`,
//!    whose namespace flags *can* be filtered (as Docker and Flatpak do).

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{bail, Context, Result};
use landlock::{
    path_beneath_rules, Access, AccessFs, AccessNet, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
    ABI,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule, TargetArch,
};

use crate::sandbox::SandboxSpec;

/// Highest ABI this build knows; older kernels get the subset they support.
const ABI_TARGET: ABI = ABI::V9;

/// The running kernel's Landlock ABI (0 or negative: unavailable).
pub fn landlock_abi() -> i64 {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    // SAFETY: documented probe call: null attr, size 0, version flag. It only
    // returns a number and touches no memory.
    unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    }
}

fn apply_landlock(spec: &SandboxSpec) -> Result<RulesetStatus> {
    let status = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI_TARGET))?
        .handle_access(AccessNet::from_all(ABI_TARGET))?
        .scope(Scope::from_all(ABI_TARGET))?
        .create()?
        .add_rules(path_beneath_rules(&spec.read, AccessFs::from_read(ABI_TARGET)))?
        .add_rules(path_beneath_rules(&spec.write, AccessFs::from_all(ABI_TARGET)))?
        .restrict_self()
        .context("applying the Landlock ruleset")?;
    if status.ruleset == RulesetStatus::NotEnforced {
        bail!("Landlock is not available in this kernel (needs Linux >= 5.13 with Landlock enabled)");
    }
    if !status.no_new_privs {
        bail!("could not set no_new_privs");
    }
    Ok(status.ruleset)
}

fn arch() -> Result<TargetArch> {
    if cfg!(target_arch = "x86_64") {
        Ok(TargetArch::x86_64)
    } else if cfg!(target_arch = "aarch64") {
        Ok(TargetArch::aarch64)
    } else {
        bail!("seccomp filter not built for this architecture")
    }
}

fn arg0_eq(v: u64) -> Result<SeccompRule> {
    Ok(SeccompRule::new(vec![SeccompCondition::new(
        0,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        v,
    )?])?)
}

fn arg0_has_flag(flag: u64) -> Result<SeccompRule> {
    Ok(SeccompRule::new(vec![SeccompCondition::new(
        0,
        SeccompCmpArgLen::Qword,
        SeccompCmpOp::MaskedEq(flag),
        flag,
    )?])?)
}

/// Syscalls refused with `EPERM`, with optional argument conditions
/// (an empty rule list means "always").
fn denied_syscalls(no_network: bool) -> Result<BTreeMap<i64, Vec<SeccompRule>>> {
    let mut m: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for nr in [
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_fsopen,
        libc::SYS_fsmount,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_bpf,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_ptrace,
        libc::SYS_perf_event_open,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ] {
        m.insert(nr, vec![]);
    }
    let ns_flags = [
        libc::CLONE_NEWNS,
        libc::CLONE_NEWCGROUP,
        libc::CLONE_NEWUTS,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWNET,
    ];
    m.insert(
        libc::SYS_clone,
        ns_flags
            .iter()
            .map(|f| arg0_has_flag(*f as u64))
            .collect::<Result<_>>()?,
    );
    if no_network {
        m.insert(
            libc::SYS_socket,
            [libc::AF_INET, libc::AF_INET6, libc::AF_PACKET, libc::AF_NETLINK]
                .iter()
                .map(|d| arg0_eq(*d as u64))
                .collect::<Result<_>>()?,
        );
    }
    Ok(m)
}

fn apply_seccomp(no_network: bool) -> Result<()> {
    let arch = arch()?;
    let deny: BpfProgram = SeccompFilter::new(
        denied_syscalls(no_network)?,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )?
    .try_into()?;
    let mut clone3 = BTreeMap::new();
    clone3.insert(libc::SYS_clone3, vec![]);
    let enosys: BpfProgram = SeccompFilter::new(
        clone3,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )?
    .try_into()?;
    seccompiler::apply_filter(&deny).context("installing the seccomp filter")?;
    seccompiler::apply_filter(&enosys).context("installing the seccomp filter")?;
    Ok(())
}

/// Apply everything. Any failure is fatal: the caller must not run the server.
pub fn enforce(spec: &SandboxSpec) -> Result<RulesetStatus> {
    if !spec.no_network {
        bail!("network allowlists are not supported yet");
    }
    let status = apply_landlock(spec)?;
    apply_seccomp(spec.no_network)?;
    Ok(status)
}

/// The `__sandbox-exec` helper: enforce, then replace this process with the
/// server. Returns only on failure.
pub fn exec(spec: &SandboxSpec, argv: &[String]) -> Result<Infallible> {
    let (prog, args) = argv.split_first().context("empty server command")?;
    enforce(spec).context("mcpsum sandbox: refusing to start the server")?;
    let err = Command::new(prog).args(args).exec();
    Err(err).with_context(|| format!("mcpsum sandbox: cannot execute `{prog}`"))
}

#[cfg(test)]
mod tests {
    //! Each layer must hold on its own: Landlock has no UDP rules before ABI 10
    //! and no TCP rules before ABI 4 (Linux 6.7), and seccomp cannot see paths.
    //! So each test re-runs this test binary as a child that applies exactly
    //! one layer and reports what still works.
    use super::*;
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::process::Command;

    const CHILD: &str = "MCPSUM_SANDBOX_LAYER_CHILD";

    fn spec(read: Vec<std::path::PathBuf>) -> SandboxSpec {
        let tmp = std::env::temp_dir();
        SandboxSpec {
            read,
            write: vec![],
            tmp,
            no_network: true,
        }
    }

    /// In the child: apply one layer, then try TCP and UDP to `port`.
    fn child_body(layer: &str, port: u16) -> String {
        match layer {
            "landlock" => {
                apply_landlock(&spec(vec![])).unwrap();
            }
            "seccomp" => apply_seccomp(true).unwrap(),
            _ => unreachable!(),
        }
        let tcp = TcpStream::connect(("127.0.0.1", port))
            .map(|_| ())
            .map_err(|e| e.kind());
        let udp = UdpSocket::bind(("127.0.0.1", 0))
            .and_then(|u| u.send_to(b"x", ("127.0.0.1", port)))
            .map(|_| ())
            .map_err(|e| e.kind());
        format!("tcp={tcp:?} udp={udp:?}")
    }

    /// Run `test_name` in a child with `layer`; return its report line.
    fn run_child(test_name: &str, layer: &str) -> String {
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = l.local_addr().unwrap().port();
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
            .env(CHILD, format!("{layer}:{port}"))
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        stdout
            .lines()
            .find_map(|l| l.split_once("LAYER-REPORT ").map(|(_, r)| r))
            .unwrap_or_else(|| panic!("child failed: {stdout} {}", String::from_utf8_lossy(&out.stderr)))
            .to_string()
    }

    fn maybe_child() -> bool {
        let Ok(v) = std::env::var(CHILD) else { return false };
        let (layer, port) = v.split_once(':').unwrap();
        println!("LAYER-REPORT {}", child_body(layer, port.parse().unwrap()));
        true
    }

    #[test]
    fn i5_seccomp_alone_blocks_tcp_and_udp() {
        if maybe_child() {
            return;
        }
        let r = run_child("sandbox_linux::tests::i5_seccomp_alone_blocks_tcp_and_udp", "seccomp");
        assert_eq!(r, "tcp=Err(PermissionDenied) udp=Err(PermissionDenied)", "{r}");
    }

    #[test]
    fn i5_landlock_alone_blocks_tcp_where_the_kernel_supports_it() {
        if maybe_child() {
            return;
        }
        if landlock_abi() < 4 {
            eprintln!("skipped: Landlock ABI {} has no TCP rules", landlock_abi());
            return;
        }
        let r = run_child(
            "sandbox_linux::tests::i5_landlock_alone_blocks_tcp_where_the_kernel_supports_it",
            "landlock",
        );
        assert!(r.starts_with("tcp=Err(PermissionDenied)"), "{r}");
    }

    #[test]
    fn i5_landlock_is_available_on_this_kernel() {
        // CI and the supported platforms have Landlock; if this fails, every
        // sandboxed server would refuse to start (fail closed), which is right,
        // but the e2e results would then prove nothing.
        assert!(landlock_abi() >= 1, "Landlock ABI {}", landlock_abi());
    }
}
