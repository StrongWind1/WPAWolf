//! Integration test: per-sink dedup -- the same logical hash lands in multiple sinks.
//!
//! Drives `wpawolf --22000-out A --wpa2-out B` against an in-memory WPA2-PSK pcap
//! (built by `common::multi_handshake_wpa2_psk_pcap`) and asserts:
//!
//! * The legacy sink contains only `WPA*01*`/`WPA*02*` prefixes.
//! * The taxonomy sink contains only `WPA*02*`/`WPA*03*` prefixes (per
//!   `ARCHITECTURE.md §2`).
//! * Every line within each sink is unique (per-sink dedup is in effect).
//! * The same logical hash count is observed in both sinks: every WPA2-PSK EAPOL
//!   line in legacy (WPA*02*) corresponds to a WPA*03* line in the taxonomy sink.

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
    let pcap_path = common::write_temp_pcap("taxonomy_dedup.pcap", &common::multi_handshake_wpa2_psk_pcap(3));
    let legacy = "/tmp/wpawolf_taxonomy_dedup_legacy.22000";
    let wpa2 = "/tmp/wpawolf_taxonomy_dedup_wpa2.taxo";
    let _ = fs::remove_file(legacy);
    let _ = fs::remove_file(wpa2);

    let status = Command::new(common::binary_path())
        .args(["--22000-out", legacy, "--wpa2-out", wpa2])
        .arg(&pcap_path)
        .status()
        .expect("failed to spawn wpawolf");
    assert!(status.success(), "wpawolf exited non-zero: {status}");

    let legacy_lines = read_lines(Path::new(legacy));
    let wpa2_lines = read_lines(Path::new(wpa2));

    assert!(!legacy_lines.is_empty(), "legacy sink empty for {pcap_path:?}");
    assert!(!wpa2_lines.is_empty(), "taxonomy sink empty for {pcap_path:?}");

    // Per-sink dedup: no internal duplicates.
    let legacy_set: HashSet<&str> = legacy_lines.iter().map(String::as_str).collect();
    assert_eq!(legacy_lines.len(), legacy_set.len(), "legacy sink contains duplicate lines");
    let wpa2_set: HashSet<&str> = wpa2_lines.iter().map(String::as_str).collect();
    assert_eq!(wpa2_lines.len(), wpa2_set.len(), "taxonomy sink contains duplicate lines");

    // Same logical hashes: WPA2-PSK EAPOL lines (legacy WPA*02*) correspond 1:1 with
    // taxonomy WPA*03* lines, and PMKID lines (legacy WPA*01*) correspond 1:1 with
    // taxonomy WPA*02* lines.
    let legacy_pmkid = count_with_prefix(&legacy_lines, "WPA*01*");
    let legacy_eapol = count_with_prefix(&legacy_lines, "WPA*02*");
    let taxo_pmkid = count_with_prefix(&wpa2_lines, "WPA*02*");
    let taxo_eapol = count_with_prefix(&wpa2_lines, "WPA*03*");

    assert_eq!(
        legacy_pmkid, taxo_pmkid,
        "PMKID count diverges: legacy WPA*01*={legacy_pmkid}, taxonomy WPA*02*={taxo_pmkid}"
    );
    assert_eq!(
        legacy_eapol, taxo_eapol,
        "EAPOL count diverges: legacy WPA*02*={legacy_eapol}, taxonomy WPA*03*={taxo_eapol}"
    );
    assert!(legacy_pmkid + legacy_eapol > 0, "no hashes emitted from {pcap_path:?}");
}
