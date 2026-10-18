//! I7: framing buffers at most one line, so a peer that never sends a
//! newline cannot make the proxy hold unbounded memory. Its own test binary
//! because it counts every heap allocation of the process.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{BufReader, Read};
use std::sync::atomic::{AtomicUsize, Ordering};

use mcpsum::framing::{BoundedLines, Frame};

struct Counting;
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let now = CURRENT.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
        PEAK.fetch_max(now, Ordering::SeqCst);
        // SAFETY: forwards the caller's layout to the system allocator.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
        // SAFETY: `ptr` was allocated by `alloc` above with this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[test]
fn i7_framing_buffers_at_most_one_line() {
    const MAX: usize = 64 * 1024;
    const STREAM: u64 = 32 * 1024 * 1024; // no newline at all
    for ending in [&b""[..], b"\r\n"] {
        let input = std::io::repeat(b'x').take(STREAM).chain(ending);
        let base = CURRENT.load(Ordering::SeqCst);
        PEAK.store(base, Ordering::SeqCst);
        let frames: Vec<Frame> = BoundedLines::new(BufReader::new(input), MAX)
            .map(Result::unwrap)
            .collect();
        let peak = PEAK.load(Ordering::SeqCst) - base;
        assert_eq!(frames, vec![Frame::TooLong]);
        // The line buffer (<= MAX + 1 bytes, doubled by Vec growth) plus the
        // reader's buffer; far below the 32 MiB the peer sent.
        assert!(peak < 4 * MAX, "framing held {peak} bytes for a {MAX}-byte limit");
    }
}
