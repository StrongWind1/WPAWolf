//! Integration test: combined `-o` extended output sink.
//!
//! Drives `wpawolf -o <FILE>` against an in-memory WPA2-PSK pcap (built by
//! `common::multi_handshake_wpa2_psk_pcap`) and asserts:
//!
//! * Every line begins with `WPA*NN*` where `NN` is one of the eleven 2-digit type
//!   codes from `ARCHITECTURE.md §2` (01-11).
//! * Each line has the correct field count: 8 for non-FT (codes 01-05, 08-09) or
//!   11 for FT (codes 06-07, 10-11). FT lines append MDID + R0KH-ID + R1KH-ID.

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
use std::process::Command;

#[test]
fn combined_o_emits_only_eleven_extended_prefixes() {
    let pcap_path = common::write_temp_pcap("extended_combined.pcap", &common::multi_handshake_wpa2_psk_pcap(3));
    let combined = "/tmp/wpawolf_extended_combined.taxo";
    let _ = fs::remove_file(combined);

    let status = Command::new(common::binary_path())
        .args(["-o", combined])
        .arg(&pcap_path)
        .status()
        .expect("failed to spawn wpawolf");
    assert!(status.success(), "wpawolf exited non-zero: {status}");

    let text = fs::read_to_string(combined).expect("combined output file missing");
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    assert!(!lines.is_empty(), "combined sink produced no lines for {pcap_path:?}");

    let valid_codes: BTreeSet<&str> =
        ["01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11"].into_iter().collect();
    let ft_codes: BTreeSet<&str> = ["06", "07", "10", "11"].into_iter().collect();

    for line in &lines {
        let parts: Vec<&str> = line.split('*').collect();
        // Layout: ["WPA", "NN", ...payload...]. Non-FT has 8 hash fields after the WPA*NN*
        // prefix (PMKID/MIC, ap, sta, essid, nonce, eapol, msgpair) -- so split on '*'
        // yields 9 parts for the WPA*02* shape (line ends with msgpair, no trailing *).
        // For FT lines, three FT extras (mdid, r0khid, r1khid) push that to 12 parts.
        assert!(parts.len() >= 2, "malformed line: {line}");
        assert_eq!(parts[0], "WPA", "non-WPA prefix in line: {line}");
        let code = parts[1];
        assert!(valid_codes.contains(code), "unknown extended code WPA*{code}* in line: {line}");

        let expected = if ft_codes.contains(code) { 12 } else { 9 };
        assert_eq!(parts.len(), expected, "WPA*{code}* line has {} fields, expected {expected}: {line}", parts.len());
    }
}
