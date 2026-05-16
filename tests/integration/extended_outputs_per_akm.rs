//! Integration test: per-AKM extended output flags emit only the expected prefixes.
//!
//! Drives `wpawolf` against an in-memory WPA2-PSK pcap (built by
//! `common::multi_handshake_wpa2_psk_pcap`) and asserts that:
//!
//! * `--22000-out` (legacy hashcat mode 22000) produces only `WPA*01*` (PMKID) and
//!   `WPA*02*` (EAPOL) prefixes -- the legacy 4-prefix scheme.
//! * `--wpa2-out` (extended types 2 + 3) produces only `WPA*02*` (PMKID) and
//!   `WPA*03*` (EAPOL) prefixes from the 11-type extended in `ARCHITECTURE.md §2`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs,
    unused_crate_dependencies,
    reason = "integration test module -- strict lints relaxed"
)]

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

/// Returns the set of `WPA*NN*` prefix codes (the second `*`-separated field) seen on
/// every non-empty line of the file. Empty file returns an empty set.
fn prefix_codes(path: &Path) -> BTreeSet<String> {
    let text = fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            // Lines have the shape "WPA*NN*..." -- the prefix code is field index 1.
            let mut parts = l.splitn(3, '*');
            let _ = parts.next()?; // "WPA"
            parts.next().map(str::to_owned)
        })
        .collect()
}

#[test]
fn per_akm_flags_emit_expected_prefixes_only() {
    // Generate a 3-handshake WPA2-PSK pcap in /tmp; no checked-in binary needed.
    let pcap_path = common::write_temp_pcap("extended_per_akm.pcap", &common::multi_handshake_wpa2_psk_pcap(3));
    let legacy_out = "/tmp/wpawolf_extended_legacy.22000";
    let wpa2_out = "/tmp/wpawolf_extended_wpa2.taxo";
    let _ = fs::remove_file(legacy_out);
    let _ = fs::remove_file(wpa2_out);

    let status = Command::new(common::binary_path())
        .args(["--22000-out", legacy_out, "--wpa2-out", wpa2_out])
        .arg(&pcap_path)
        .status()
        .expect("failed to spawn wpawolf");
    assert!(status.success(), "wpawolf exited non-zero: {status}");

    let legacy_codes = prefix_codes(Path::new(legacy_out));
    let wpa2_codes = prefix_codes(Path::new(wpa2_out));

    // Generated pcap is pure WPA2-PSK -- no FT, no SHA-256/SHA-384.
    // Legacy sink: only WPA*01* (PMKID) and/or WPA*02* (EAPOL).
    let legacy_allowed: BTreeSet<&str> = ["01", "02"].into_iter().collect();
    for code in &legacy_codes {
        assert!(
            legacy_allowed.contains(code.as_str()),
            "--22000-out emitted unexpected prefix WPA*{code}*; allowed: {legacy_allowed:?}; got {legacy_codes:?}",
        );
    }
    assert!(!legacy_codes.is_empty(), "--22000-out produced no hash lines for {pcap_path:?}");

    // Taxonomy --wpa2-out: only WPA*02* (PMKID) and/or WPA*03* (EAPOL) per ARCHITECTURE.md §2.
    let wpa2_allowed: BTreeSet<&str> = ["02", "03"].into_iter().collect();
    for code in &wpa2_codes {
        assert!(
            wpa2_allowed.contains(code.as_str()),
            "--wpa2-out emitted unexpected prefix WPA*{code}*; allowed: {wpa2_allowed:?}; got {wpa2_codes:?}",
        );
    }
    assert!(!wpa2_codes.is_empty(), "--wpa2-out produced no hash lines for {pcap_path:?}");
}
