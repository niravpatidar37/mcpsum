//! Parsing an attacker-supplied lockfile must never panic; anything that
//! parses must pass its own integrity check and survive a round trip.
#![no_main]

use libfuzzer_sys::fuzz_target;
use mcpsum::lock::LockFile;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(lf) = LockFile::parse(text) {
        for s in lf.servers.values() {
            s.check_integrity().expect("parsed lock must be internally consistent");
        }
        let again = LockFile::parse(&lf.to_pretty().unwrap()).expect("round trip");
        // mcpsum writes the lowest lockfileVersion that fits (docs/LOCKFILE.md):
        // 2 only when an entry records supportedVersions. Everything else
        // survives the round trip unchanged.
        let modern = lf.servers.values().any(|s| s.surface.supported_versions.is_some());
        assert_eq!(again.lockfile_version, if modern { 2 } else { 1 });
        let mut expected = lf;
        expected.lockfile_version = again.lockfile_version;
        assert_eq!(again, expected);
    }
});
