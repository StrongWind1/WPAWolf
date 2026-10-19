//! Integration test: per-type output flags emit only the expected prefixes.
//!
//! Drives `wpawolf` against an in-memory WPA2-PSK pcap (built by
//! `common::multi_handshake_wpa2_psk_pcap`) and asserts that:
//!
//! * `-o` (combined) produces only `WPA*01*` (PMKID) and `WPA*02*` (EAPOL) prefixes.
//! * `--wpa2-eapol` (type 3 only) produces only `WPA*02*` (EAPOL) prefixes.

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
            let mut parts = l.splitn(3, '*');
            let _ = parts.next()?; // "WPA"
            parts.next().map(str::to_owned)
        })
        .collect()
}

#[test]
fn per_type_flags_emit_expected_prefixes_only() {
    let pcap_path = common::write_temp_pcap("extended_per_akm.pcap", &common::multi_handshake_wpa2_psk_pcap(3));
    let combined_out = "/tmp/wpawolf_extended_combined.22000";
    let eapol_out = "/tmp/wpawolf_extended_wpa2_eapol.22000";
    let _ = fs::remove_file(combined_out);
    let _ = fs::remove_file(eapol_out);

    let status = Command::new(common::binary_path())
        .args(["-o", combined_out, "--wpa2-eapol", eapol_out])
        .arg(&pcap_path)
        .status()
        .expect("failed to spawn wpawolf");
    assert!(status.success(), "wpawolf exited non-zero: {status}");

    let combined_codes = prefix_codes(Path::new(combined_out));
    let eapol_codes = prefix_codes(Path::new(eapol_out));

    // Generated pcap is pure WPA2-PSK -- no FT, no SHA-256/SHA-384.
    // Combined: only WPA*01* (PMKID) and/or WPA*02* (EAPOL).
    let combined_allowed: BTreeSet<&str> = ["01", "02"].into_iter().collect();
    for code in &combined_codes {
        assert!(
            combined_allowed.contains(code.as_str()),
            "-o emitted unexpected prefix WPA*{code}*; allowed: {combined_allowed:?}; got {combined_codes:?}",
        );
    }
    assert!(!combined_codes.is_empty(), "-o produced no hash lines for {pcap_path:?}");

    // --wpa2-eapol: only WPA*02* (EAPOL) -- this sink only receives type 3 (WPA2-PSK EAPOL).
    let eapol_allowed: BTreeSet<&str> = std::iter::once("02").collect();
    for code in &eapol_codes {
        assert!(
            eapol_allowed.contains(code.as_str()),
            "--wpa2-eapol emitted unexpected prefix WPA*{code}*; allowed: {eapol_allowed:?}; got {eapol_codes:?}",
        );
    }
    assert!(!eapol_codes.is_empty(), "--wpa2-eapol produced no hash lines for {pcap_path:?}");
}
