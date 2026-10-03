//! Framing must never panic, never yield a line above the limit, and never
//! yield a line containing a newline.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mcpsum::framing::{BoundedLines, Frame};
use std::io::{BufReader, Cursor};

fuzz_target!(|data: &[u8]| {
    let Some((&cap, rest)) = data.split_first() else { return };
    let max = 1 + usize::from(cap % 64);
    let reader = BufReader::with_capacity(1 + usize::from(cap % 7), Cursor::new(rest.to_vec()));
    for frame in BoundedLines::new(reader, max) {
        if let Frame::Line(l) = frame.expect("cursor reads cannot fail") {
            assert!(l.len() <= max);
            assert!(!l.contains(&b'\n'));
            assert!(!l.is_empty());
        }
    }
});
