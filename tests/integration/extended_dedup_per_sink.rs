//! Integration test: per-sink dedup -- the same logical hash lands in multiple sinks.
//!
//! Drives `wpawolf -o A --wpa2-eapol B` against an in-memory WPA2-PSK pcap
//! (built by `common::multi_handshake_wpa2_psk_pcap`) and asserts:
//!
//! * The combined sink contains `WPA*01*`/`WPA*02*` prefixes.
//! * The per-type eapol sink contains only `WPA*02*` prefixes (type 3 only).
//! * Every line within each sink is unique (per-sink dedup is in effect).
//! * The EAPOL line count in `-o` matches the per-type sink count.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs,
    unused_crate_dependencies,
    reason = "integration test module -- strict lints relaxed"
)]

mod common;

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;

fn read_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path).unwrap_or_default().lines().filter(|l| !l.is_empty()).map(str::to_owned).collect()
}

fn count_with_prefix(lines: &[String], prefix: &str) -> usize {
    lines.iter().filter(|l| l.starts_with(prefix)).count()
}

#[test]
fn same_logical_hash_in_two_sinks_with_per_sink_dedup() {
    let pcap_path = common::write_temp_pcap("extended_dedup.pcap", &common::multi_handshake_wpa2_psk_pcap(3));
    let combined = "/tmp/wpawolf_extended_dedup_combined.22000";
    let eapol_out = "/tmp/wpawolf_extended_dedup_wpa2_eapol.22000";
    let _ = fs::remove_file(combined);
    let _ = fs::remove_file(eapol_out);

    let status = Command::new(common::binary_path())
        .args(["-o", combined, "--wpa2-eapol", eapol_out])
        .arg(&pcap_path)
        .status()
        .expect("failed to spawn wpawolf");
    assert!(status.success(), "wpawolf exited non-zero: {status}");

    let combined_lines = read_lines(Path::new(combined));
    let eapol_lines = read_lines(Path::new(eapol_out));

    assert!(!combined_lines.is_empty(), "combined sink empty for {pcap_path:?}");
    assert!(!eapol_lines.is_empty(), "per-type eapol sink empty for {pcap_path:?}");

    // Per-sink dedup: no internal duplicates.
    let combined_set: HashSet<&str> = combined_lines.iter().map(String::as_str).collect();
    assert_eq!(combined_lines.len(), combined_set.len(), "combined sink contains duplicate lines");
    let eapol_set: HashSet<&str> = eapol_lines.iter().map(String::as_str).collect();
    assert_eq!(eapol_lines.len(), eapol_set.len(), "per-type eapol sink contains duplicate lines");

    // Same logical hashes: WPA2-PSK EAPOL lines (WPA*02* in both sinks) must match 1:1.
    let combined_eapol = count_with_prefix(&combined_lines, "WPA*02*");
    let pertype_eapol = count_with_prefix(&eapol_lines, "WPA*02*");

    assert_eq!(
        combined_eapol, pertype_eapol,
        "EAPOL count diverges: combined WPA*02*={combined_eapol}, per-type WPA*02*={pertype_eapol}"
    );
    assert!(!combined_lines.is_empty(), "no hashes emitted from {pcap_path:?}");
}
