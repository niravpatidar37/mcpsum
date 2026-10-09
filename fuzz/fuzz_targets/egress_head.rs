//! The egress proxy's request parser (I5) must never panic, and anything it
//! accepts must be a CONNECT whose target prints back as plain `host:port`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mcpsum::egress::{parse_head, Host, Limits};

fuzz_target!(|data: &[u8]| {
    if let Ok(t) = parse_head(data, &Limits::default()) {
        assert!(data.starts_with(b"CONNECT "));
        assert!(t.port != 0);
        let shown = t.to_string();
        assert!(shown.bytes().all(|b| b.is_ascii_graphic()), "{shown:?}");
        if let Host::Name(n) = &t.host {
            assert!(!n.is_empty() && n.len() <= 253 && !n.ends_with('.'));
            assert!(n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'));
        }
    }
});
