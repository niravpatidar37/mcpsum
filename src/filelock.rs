//! Cross-process exclusive file locks, used to serialize audit-log appends
//! between proxies that run concurrently for the same server (#29).
//!
//! Unix: `flock(2)` via `nix`. Windows: `LockFileEx` via `windows-sys`. Both
//! locks belong to an open file description / handle, so two handles opened
//! separately conflict even inside one process, and the OS releases them if
//! the holder dies.
//!
//! TODO: when the MSRV reaches 1.89, replace this module with
//! `std::fs::File::try_lock` (stabilized in Rust 1.89).

use std::fs::File;
use std::io;
use std::thread;
use std::time::{Duration, Instant};

/// Holds an exclusive lock until dropped.
pub struct LockGuard {
    #[cfg(unix)]
    _flock: nix::fcntl::Flock<File>,
    #[cfg(windows)]
    file: File,
}

/// Take an exclusive lock on `file`, retrying until `timeout`. On timeout this
/// returns an error rather than blocking forever: a writer that cannot get the
/// lock must fail closed, not hang the proxy.
pub fn lock_exclusive(file: &File, timeout: Duration) -> io::Result<LockGuard> {
    let deadline = Instant::now() + timeout;
    loop {
        match try_lock(file)? {
            Some(guard) => return Ok(guard),
            None if Instant::now() >= deadline => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("could not lock the audit log within {timeout:?}"),
                ))
            }
            None => thread::sleep(Duration::from_millis(2)),
        }
    }
}

#[cfg(unix)]
fn try_lock(file: &File) -> io::Result<Option<LockGuard>> {
    use nix::errno::Errno;
    use nix::fcntl::{Flock, FlockArg};
    // try_clone() dup()s the descriptor: same open file description, so the
    // lock taken through the clone is this handle's lock.
    match Flock::lock(file.try_clone()?, FlockArg::LockExclusiveNonblock) {
        Ok(flock) => Ok(Some(LockGuard { _flock: flock })),
        Err((_, Errno::EWOULDBLOCK)) => Ok(None),
        Err((_, e)) => Err(io::Error::from(e)),
    }
}

#[cfg(windows)]
fn try_lock(file: &File) -> io::Result<Option<LockGuard>> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY};
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let file = file.try_clone()?;
    // SAFETY: OVERLAPPED is plain data; all-zero means "lock from offset 0".
    let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
    // SAFETY: `file` is a valid, open handle for the duration of the call, and
    // `ov` outlives it (the call is synchronous with LOCKFILE_FAIL_IMMEDIATELY).
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle() as _,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut ov,
        )
    };
    if ok != 0 {
        return Ok(Some(LockGuard { file }));
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
        Ok(None)
    } else {
        Err(err)
    }
}

#[cfg(windows)]
impl Drop for LockGuard {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
        use windows_sys::Win32::System::IO::OVERLAPPED;
        // SAFETY: as in try_lock. Closing the handle would also release the
        // lock, but only "eventually"; unlock explicitly so the next writer
        // does not wait.
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        unsafe {
            UnlockFileEx(self.file.as_raw_handle() as _, 0, u32::MAX, u32::MAX, &mut ov);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(tag: &str) -> (std::path::PathBuf, File) {
        let p = std::env::temp_dir().join(format!("mcpsum-lock-{tag}-{}", std::process::id()));
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&p)
            .unwrap();
        (p, f)
    }

    #[test]
    fn second_handle_waits_and_times_out_while_first_holds_the_lock() {
        let (p, a) = temp_file("hold");
        let b = std::fs::OpenOptions::new().read(true).write(true).open(&p).unwrap();
        let held = lock_exclusive(&a, Duration::from_secs(1)).unwrap();
        let t = Instant::now();
        let err = lock_exclusive(&b, Duration::from_millis(100))
            .err()
            .expect("must not get the lock");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(t.elapsed() < Duration::from_secs(2));
        drop(held);
        assert!(
            lock_exclusive(&b, Duration::from_secs(1)).is_ok(),
            "lock must be free after drop"
        );
        let _ = std::fs::remove_file(&p);
    }
}
