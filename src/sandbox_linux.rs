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
//! 3. **Allowlist mode** (`network.allow` not empty): first, a new user and
//!    network namespace with only `lo`. The helper binds the egress proxy's
//!    port there and hands the listening socket to mcpsum, which runs the
//!    proxy outside (`crate::egress`). Landlock then allows TCP connect to
//!    that port only, and seccomp allows `AF_INET` stream sockets only (no
//!    UDP, raw or other protocols, no `AF_INET6`).

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io;
use std::net::{Ipv4Addr, TcpListener};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{bail, Context, Result};
use landlock::{
    path_beneath_rules, Access, AccessFs, AccessNet, NetPort, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    Scope, ABI,
};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule, TargetArch,
};

use crate::sandbox::{SandboxSpec, EGRESS_FD, PROXY_PORT};

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
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI_TARGET))?
        .handle_access(AccessNet::from_all(ABI_TARGET))?
        .scope(Scope::from_all(ABI_TARGET))?
        .create()?
        .add_rules(path_beneath_rules(&spec.read, AccessFs::from_read(ABI_TARGET)))?
        .add_rules(path_beneath_rules(&spec.write, AccessFs::from_all(ABI_TARGET)))?;
    if !spec.no_network() {
        // Allowlist mode: TCP connect to the egress proxy port only.
        ruleset = ruleset.add_rule(NetPort::new(PROXY_PORT, AccessNet::ConnectTcp))?;
    }
    let status = ruleset.restrict_self().context("applying the Landlock ruleset")?;
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
    let mut families = vec![libc::AF_INET6, libc::AF_PACKET, libc::AF_NETLINK];
    let mut socket_rules = vec![];
    if no_network {
        families.push(libc::AF_INET);
    } else {
        // Allowlist mode: the only way out is TCP to the egress proxy on `lo`
        // (the namespace has no route, Landlock allows that one port). Refuse
        // every other AF_INET socket: UDP (DNS), raw, SCTP, MPTCP, ...
        let inet = || SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, libc::AF_INET as u64);
        for ty in (0..16u64).filter(|t| *t != libc::SOCK_STREAM as u64) {
            let ty = SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::MaskedEq(0xf), ty);
            socket_rules.push(SeccompRule::new(vec![inet()?, ty?])?);
        }
        let proto_ne = |v: u64| SeccompCondition::new(2, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, v);
        socket_rules.push(SeccompRule::new(vec![
            inet()?,
            proto_ne(0)?,
            proto_ne(libc::IPPROTO_TCP as u64)?,
        ])?);
    }
    for d in families {
        socket_rules.push(arg0_eq(d as u64)?);
    }
    m.insert(libc::SYS_socket, socket_rules);
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

/// Why a user namespace could not be set up, and what to do about it.
fn userns_help(what: &str) -> String {
    let read = |p: &str| std::fs::read_to_string(p).map(|s| s.trim().to_string()).ok();
    let exe = std::env::current_exe().map_or_else(|_| "/path/to/mcpsum".into(), |p| p.display().to_string());
    let why = if read("/proc/sys/kernel/apparmor_restrict_unprivileged_userns").as_deref() == Some("1") {
        format!(
            "AppArmor restricts unprivileged user namespaces on this system \
             (kernel.apparmor_restrict_unprivileged_userns=1, the Ubuntu >= 23.10 default). \
             To allow mcpsum only, save this profile as /etc/apparmor.d/mcpsum and run \
             `sudo apparmor_parser -r /etc/apparmor.d/mcpsum`:\n\
             abi <abi/4.0>,\ninclude <tunables/global>\nprofile mcpsum {exe} flags=(unconfined) {{\n  userns,\n}}\n"
        )
    } else if read("/proc/sys/kernel/unprivileged_userns_clone").as_deref() == Some("0") {
        "unprivileged user namespaces are disabled (kernel.unprivileged_userns_clone=0)".into()
    } else if read("/proc/sys/user/max_user_namespaces").as_deref() == Some("0") {
        "user namespaces are disabled (user.max_user_namespaces=0)".into()
    } else {
        "user namespaces are not available here (a container or seccomp policy may block them)".into()
    };
    format!(
        "{what}: {why}\npolicy.sandbox.network.allow needs an unprivileged user and network namespace, \
         so the server will not start. Without the allow list it runs with no network."
    )
}

/// Enter a new user and network namespace (our own uid and gid mapped, so
/// the server has no capabilities after `execve`) and bring up `lo`.
fn enter_network_namespace() -> Result<()> {
    // SAFETY: plain syscalls in the single-threaded helper; no memory shared.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    // SAFETY: as above; unshare only changes this process's namespaces.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
        return Err(io::Error::last_os_error()).context(userns_help("cannot create a user and network namespace"));
    }
    for (file, map) in [
        ("/proc/self/setgroups", "deny".to_string()),
        ("/proc/self/uid_map", format!("{uid} {uid} 1\n")),
        ("/proc/self/gid_map", format!("{gid} {gid} 1\n")),
    ] {
        std::fs::write(file, map).with_context(|| userns_help(&format!("cannot write {file}")))?;
    }
    loopback_up().context(userns_help("cannot bring up the loopback interface"))
}

fn loopback_up() -> io::Result<()> {
    // SAFETY: socket(2) returns a new descriptor or -1; we own it on success.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, valid descriptor that nothing else owns.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: ifreq is plain old data; all-zero is a valid value.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_name[0] = b'l' as libc::c_char;
    ifr.ifr_name[1] = b'o' as libc::c_char;
    // SAFETY: SIOCGIFFLAGS/SIOCSIFFLAGS read and write `ifr`, which lives
    // across both calls; the union field written is the one the ioctl uses.
    unsafe {
        if libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFFLAGS as _, &mut ifr) < 0 {
            return Err(io::Error::last_os_error());
        }
        ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        if libc::ioctl(sock.as_raw_fd(), libc::SIOCSIFFLAGS as _, &ifr) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Bind the proxy port inside the namespace and give the listening socket to
/// mcpsum over [`EGRESS_FD`]. Both are closed here, so the server inherits
/// neither.
fn hand_over_proxy_listener() -> Result<()> {
    // SAFETY: F_GETFD only inspects the descriptor table.
    if unsafe { libc::fcntl(EGRESS_FD, libc::F_GETFD) } < 0 {
        bail!("mcpsum did not pass the egress channel (fd {EGRESS_FD})");
    }
    // SAFETY: fd 3 is open (checked above) and was set up by mcpsum for this
    // helper alone; we take ownership and close it when done.
    let chan = unsafe { OwnedFd::from_raw_fd(EGRESS_FD) };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, PROXY_PORT))
        .context("binding the egress proxy port in the namespace")?;
    send_fd(chan.as_fd(), listener.as_fd()).context("handing the egress socket to mcpsum")
}

/// Room for one descriptor's control message (CMSG_SPACE(4) is 16 or 24).
type CmsgBuf = [u64; 4];

/// Send `fd` over the Unix socket `chan` (SCM_RIGHTS).
pub fn send_fd(chan: BorrowedFd<'_>, fd: BorrowedFd<'_>) -> io::Result<()> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut cmsg: CmsgBuf = [0; 4];
    // SAFETY: msghdr is plain old data; every pointer set below points into
    // locals that outlive the sendmsg call, and the control buffer is large
    // and aligned enough for one SCM_RIGHTS header with one descriptor.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(c).cast::<RawFd>(), fd.as_raw_fd());
        if libc::sendmsg(chan.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Receive one descriptor sent with [`send_fd`] (honours the socket's read
/// timeout). EOF means the sender exited without sending.
pub fn recv_fd(chan: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut cmsg: CmsgBuf = [0; 4];
    // SAFETY: as in send_fd; the kernel writes at most msg_controllen bytes
    // into `cmsg`, and we read a descriptor only from a complete SCM_RIGHTS
    // header it filled in (MSG_CTRUNC rejected).
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of::<CmsgBuf>() as _;
        let n = libc::recvmsg(chan.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let c = libc::CMSG_FIRSTHDR(&msg);
        if n == 0 || c.is_null() || msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "no descriptor received"));
        }
        if (*c).cmsg_level != libc::SOL_SOCKET
            || (*c).cmsg_type != libc::SCM_RIGHTS
            || (*c).cmsg_len as usize != libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize
        {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected control message"));
        }
        Ok(OwnedFd::from_raw_fd(std::ptr::read_unaligned(
            libc::CMSG_DATA(c).cast::<RawFd>(),
        )))
    }
}

/// Apply everything. Any failure is fatal: the caller must not run the server.
pub fn enforce(spec: &SandboxSpec) -> Result<RulesetStatus> {
    if !spec.no_network() {
        enter_network_namespace()?;
        hand_over_proxy_listener()?;
    }
    let status = apply_landlock(spec)?;
    apply_seccomp(spec.no_network())?;
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
    use std::io::{Read, Write};
    use std::net::{TcpStream, UdpSocket};
    use std::os::unix::net::UnixStream;
    use std::process::Command;
    use std::time::Duration;

    const CHILD: &str = "MCPSUM_SANDBOX_LAYER_CHILD";

    fn spec(read: Vec<std::path::PathBuf>) -> SandboxSpec {
        let tmp = std::env::temp_dir();
        SandboxSpec {
            read,
            write: vec![],
            tmp,
            net_allow: vec![],
        }
    }

    /// errno of `socket(domain, ty, proto)`, or "ok".
    fn socket_errno(domain: i32, ty: i32, proto: i32) -> String {
        // SAFETY: socket(2) returns a new descriptor or -1; we close it at once.
        let fd = unsafe { libc::socket(domain, ty, proto) };
        if fd < 0 {
            return format!("{:?}", io::Error::last_os_error().kind());
        }
        // SAFETY: `fd` is a fresh descriptor we own.
        drop(unsafe { OwnedFd::from_raw_fd(fd) });
        "ok".into()
    }

    /// In the child: apply one layer, then try TCP and UDP to `port`.
    fn child_body(layer: &str, port: u16) -> String {
        let mut extra = String::new();
        match layer {
            "landlock" => {
                apply_landlock(&spec(vec![])).unwrap();
            }
            "seccomp" => apply_seccomp(true).unwrap(),
            "seccomp-allowlist" => {
                apply_seccomp(false).unwrap();
                let (inet, v6) = (libc::AF_INET, libc::AF_INET6);
                let flags = libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;
                extra = format!(
                    " v6={} dgram_flags={} seqpacket={} sctp={}",
                    socket_errno(v6, libc::SOCK_STREAM, 0),
                    socket_errno(inet, libc::SOCK_DGRAM | flags, 0),
                    socket_errno(inet, libc::SOCK_SEQPACKET, 0),
                    socket_errno(inet, libc::SOCK_STREAM, libc::IPPROTO_SCTP),
                );
            }
            "netns" => return in_forked_child(|| netns_body(port)),
            _ => unreachable!(),
        }
        format!("{}{extra}", tcp_udp(port))
    }

    fn tcp_udp(port: u16) -> String {
        let tcp = TcpStream::connect(("127.0.0.1", port))
            .map(|_| ())
            .map_err(|e| e.kind());
        let udp = UdpSocket::bind(("127.0.0.1", 0))
            .and_then(|u| u.send_to(b"x", ("127.0.0.1", port)))
            .map(|_| ())
            .map_err(|e| e.kind());
        format!("tcp={tcp:?} udp={udp:?}")
    }

    /// unshare(CLONE_NEWUSER) needs a single-threaded process and libtest
    /// has threads, so run `f` in a forked child and return what it reports.
    fn in_forked_child(f: impl FnOnce() -> String) -> String {
        let (mut rx, mut tx) = UnixStream::pair().unwrap();
        // SAFETY: test-only. The child runs `f`, writes the result and
        // `_exit`s without running the parent's destructors.
        match unsafe { libc::fork() } {
            0 => {
                drop(rx);
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or_else(|_| "panic".into());
                let _ = tx.write_all(r.as_bytes());
                // SAFETY: see above.
                unsafe { libc::_exit(0) }
            }
            pid if pid > 0 => {
                drop(tx);
                let mut out = String::new();
                rx.read_to_string(&mut out).unwrap();
                // SAFETY: reaps the child forked above.
                unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
                out
            }
            _ => panic!("fork failed"),
        }
    }

    fn netns_body(port: u16) -> String {
        enter_network_namespace().unwrap();
        let inner = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let inner_ok = TcpStream::connect(inner.local_addr().unwrap()).map(|_| ());
        let outside = TcpStream::connect_timeout(&"192.0.2.1:80".parse().unwrap(), Duration::from_secs(2));
        format!(
            "{} lo={:?} outside={:?}",
            tcp_udp(port),
            inner_ok.map_err(|e| e.kind()),
            outside.map(|_| ()).map_err(|e| e.kind())
        )
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
    fn i5_seccomp_allowlist_mode_allows_only_tcp_streams() {
        if maybe_child() {
            return;
        }
        let r = run_child(
            "sandbox_linux::tests::i5_seccomp_allowlist_mode_allows_only_tcp_streams",
            "seccomp-allowlist",
        );
        assert_eq!(
            r,
            "tcp=Ok(()) udp=Err(PermissionDenied) v6=PermissionDenied dgram_flags=PermissionDenied \
             seqpacket=PermissionDenied sctp=PermissionDenied",
            "{r}"
        );
    }

    #[test]
    fn i5_namespace_alone_has_only_loopback() {
        if maybe_child() {
            return;
        }
        // Ubuntu >= 23.10 withholds the capabilities a new user namespace
        // needs, so allowlist mode refuses to start there (the e2e suite checks
        // that). CI lifts the restriction for this job (ci.yml), so this runs.
        let restricted = std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns");
        if restricted.is_ok_and(|s| s.trim() == "1") {
            eprintln!("skipped: AppArmor restricts unprivileged user namespaces here");
            return;
        }
        let r = run_child("sandbox_linux::tests::i5_namespace_alone_has_only_loopback", "netns");
        // The host's listener is unreachable from the namespace's own `lo`, and
        // there is no route anywhere else.
        assert_eq!(
            r, "tcp=Err(ConnectionRefused) udp=Ok(()) lo=Ok(()) outside=Err(NetworkUnreachable)",
            "{r}"
        );
    }

    #[test]
    fn i5_listening_socket_crosses_a_unix_socket() {
        let (a, b) = UnixStream::pair().unwrap();
        let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = l.local_addr().unwrap();
        send_fd(a.as_fd(), l.as_fd()).unwrap();
        drop(l);
        let got = TcpListener::from(recv_fd(b.as_fd()).unwrap());
        let _c = TcpStream::connect(addr).unwrap();
        assert!(got.accept().is_ok());
        drop(a);
        assert_eq!(recv_fd(b.as_fd()).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn i5_landlock_is_available_on_this_kernel() {
        // CI and the supported platforms have Landlock; if this fails, every
        // sandboxed server would refuse to start (fail closed), which is right,
        // but the e2e results would then prove nothing.
        assert!(landlock_abi() >= 1, "Landlock ABI {}", landlock_abi());
    }
}
