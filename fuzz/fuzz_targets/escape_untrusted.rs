//! Escaped untrusted text must contain no suspicious character and no raw
//! newline, whatever the input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mcpsum::render::{escape_untrusted, is_suspicious};

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let out = escape_untrusted(&s);
    assert!(!out.chars().any(is_suspicious), "suspicious char survived escaping");
    assert!(!out.contains('\n') && !out.contains('\r'));
});
