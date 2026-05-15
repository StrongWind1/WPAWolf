//! Integration test: `--wordlist-scan-ies FILE` standalone output.
//!
//! Builds a crafted Beacon frame carrying a vendor-specific IE whose body
//! contains an ASCII firmware string surrounded by binary padding. Runs
//! `wpawolf` three times to validate the **separation contract**: the IE-scan
//! strand goes only to `--wordlist-scan-ies FILE` and is never folded into
//! `-W`.
//!
//! - Run A: no `--wordlist-scan-ies` flag -- `-W` carries only the SSID, the
//!   IE-scan strand is silent (no scan happens).
//! - Run B: `--wordlist-scan-ies SCAN_FILE` and `-W WORD_FILE` configured to
//!   different paths -- the firmware string lands in `SCAN_FILE` only, `-W`
//!   stays clean.
//!
//! The 5-byte "short" run must be filtered out in every case (8-byte
//! `WORDLIST_SCAN_IES_MIN_RUN` floor).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs,
    unused_crate_dependencies,
    clippy::cast_possible_truncation,
    reason = "integration test module -- strict lints relaxed"
)]

use std::fs;
use std::path::Path;
use std::process::Command;

// --- Pcap byte builders (mirrors pmkid_coverage.rs) ---

fn pcap_global_header(link_type: u32) -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&0xA1B2_C3D4_u32.to_le_bytes());
    h[4..6].copy_from_slice(&2_u16.to_le_bytes());
    h[6..8].copy_from_slice(&4_u16.to_le_bytes());
    h[16..20].copy_from_slice(&65535_u32.to_le_bytes());
    h[20..24].copy_from_slice(&link_type.to_le_bytes());
    h
}

fn pcap_packet_record(ts_sec: u32, data: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(16 + data.len());
    r.extend_from_slice(&ts_sec.to_le_bytes());
    r.extend_from_slice(&0_u32.to_le_bytes());
    let len = data.len() as u32;
    r.extend_from_slice(&len.to_le_bytes());
    r.extend_from_slice(&len.to_le_bytes());
    r.extend_from_slice(data);
    r
}

fn mgmt_header(subtype: u8, addr1: [u8; 6], addr2: [u8; 6], addr3: [u8; 6]) -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0] = subtype << 4;
    h[1] = 0x00;
    h[4..10].copy_from_slice(&addr1);
    h[10..16].copy_from_slice(&addr2);
    h[16..22].copy_from_slice(&addr3);
    h
}

/// Beacon body: fixed (12) + SSID IE + a vendor-specific IE (tag 221) whose body
/// contains an ASCII firmware string surrounded by binary padding.
///
/// The vendor IE uses OUI `AA:BB:CC` (not wolf's known `00:50:F2` / `00:13:92` /
/// `00:17:F2` / etc.), guaranteeing wolf has no structured parser for it. The
/// only way the firmware string reaches `-W` is via `--wordlist-scan-ies`.
fn beacon_with_vendor_firmware_ie(ap: [u8; 6], ssid: &[u8], firmware: &[u8]) -> Vec<u8> {
    // subtype=8 (Beacon)
    let mut frame: Vec<u8> = mgmt_header(8, [0xFF; 6], ap, ap).to_vec();
    // Beacon fixed fields: Timestamp(8) + BeaconInterval(2) + Capability(2) = 12 bytes.
    frame.extend_from_slice(&[0u8; 12]);
    // SSID IE (tag 0).
    let ssid_len = u8::try_from(ssid.len()).expect("ssid too long");
    frame.push(0);
    frame.push(ssid_len);
    frame.extend_from_slice(ssid);
    // Vendor-specific IE (tag 221): [OUI (3)] [Type (1)] [binary padding] [firmware string] [binary padding].
    // The "short5" prefix below is 5 bytes, which MUST be filtered out by the
    // min_run=8 floor. Only the firmware string survives the scan.
    let mut ie_val = Vec::new();
    ie_val.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // unknown OUI
    ie_val.push(0x01); // vendor type
    ie_val.extend_from_slice(b"short"); // 5-byte run: below 8-byte floor
    ie_val.extend_from_slice(&[0x00, 0x01, 0xFF]); // binary separator
    ie_val.extend_from_slice(firmware); // the long ASCII run
    ie_val.extend_from_slice(&[0x00, 0x02, 0xFE]); // trailing binary padding
    let ie_len = u8::try_from(ie_val.len()).expect("vendor IE too long");
    frame.push(221);
    frame.push(ie_len);
    frame.extend_from_slice(&ie_val);
    frame
}

fn build_fixture_pcap(ssid: &[u8], firmware: &[u8]) -> Vec<u8> {
    let ap_mac = [0x00_u8, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&pcap_global_header(105)); // DLT_IEEE802_11
    let frame = beacon_with_vendor_firmware_ie(ap_mac, ssid, firmware);
    pcap.extend_from_slice(&pcap_packet_record(1000, &frame));
    pcap
}

fn read_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path).unwrap_or_default().lines().filter(|l| !l.is_empty()).map(String::from).collect()
}

/// Asserts that `needle` appears as an exact line in `lines`. Output is autohex
/// so pure-ASCII `needle` strings appear verbatim.
fn assert_contains(lines: &[String], needle: &str) {
    assert!(lines.iter().any(|l| l == needle), "expected {needle:?} in output; got: {lines:?}");
}

fn assert_not_contains(lines: &[String], needle: &str) {
    assert!(!lines.iter().any(|l| l == needle), "expected {needle:?} NOT in output; got: {lines:?}");
}

#[test]
fn wordlist_scan_subtracts_e_r_w_entries() {
    let pcap_path = "/tmp/wpawolf_t22_scan_fixture.pcap";
    let scan_path = "/tmp/wpawolf_t22_scan.scan";
    let essid_path = "/tmp/wpawolf_t22_scan.essids";
    let wordlist_path = "/tmp/wpawolf_t22_scan.wordlist";
    let dummy_hash = "/tmp/wpawolf_t22_scan.22000";

    let ssid = b"TestSSID";
    let firmware = b"VendorFirmware-1.2.3";

    fs::write(pcap_path, build_fixture_pcap(ssid, firmware)).expect("write fixture pcap");

    for p in [scan_path, essid_path, wordlist_path] {
        let _ = fs::remove_file(p);
    }

    let status = Command::new(env!("CARGO_BIN_EXE_wpawolf"))
        .args([
            "--22000-out",
            dummy_hash,
            "-E",
            essid_path,
            "-W",
            wordlist_path,
            "--wordlist-scan",
            scan_path,
            pcap_path,
        ])
        .status()
        .expect("failed to spawn wpawolf");
    assert!(status.success(), "wpawolf exited non-zero: {status}");

    let lines_e = read_lines(Path::new(essid_path));
    let lines_w = read_lines(Path::new(wordlist_path));
    let lines_scan = read_lines(Path::new(scan_path));

    // -E and -W both contain the SSID.
    assert_contains(&lines_e, "TestSSID");
    assert_contains(&lines_w, "TestSSID");
    // --wordlist-scan subtracts entries already in -E / -W, so SSID must NOT
    // appear. The firmware string is only reachable via the IE scanner.
    assert_not_contains(&lines_scan, "TestSSID");
    assert_contains(&lines_scan, "VendorFirmware-1.2.3");
    // 5-byte "short" run is still filtered by the 8-byte minimum.
    assert_not_contains(&lines_scan, "short");
}

#[test]
fn wordlist_scan_works_without_dash_w() {
    // Without -W configured the WordlistStore component is empty, but EssidSet
    // is always populated during extraction. The SSID "TestSSID" still gets
    // subtracted because it lives in EssidSet regardless of whether -E is
    // configured as a file output.
    let pcap_path = "/tmp/wpawolf_t22_scan_no_w_fixture.pcap";
    let scan_path = "/tmp/wpawolf_t22_scan_no_w.scan";
    let dummy_hash = "/tmp/wpawolf_t22_scan_no_w.22000";
    let _ = fs::remove_file(scan_path);

    let ssid = b"TestSSID";
    let firmware = b"VendorFirmware-1.2.3";
    fs::write(pcap_path, build_fixture_pcap(ssid, firmware)).expect("write fixture pcap");

    let status = Command::new(env!("CARGO_BIN_EXE_wpawolf"))
        .args(["--22000-out", dummy_hash, "--wordlist-scan", scan_path, pcap_path])
        .status()
        .expect("failed to spawn wpawolf");
    assert!(status.success(), "wpawolf without -W exited non-zero: {status}");
    let lines_scan = read_lines(Path::new(scan_path));
    // Firmware string survives (not in any store).
    assert_contains(&lines_scan, "VendorFirmware-1.2.3");
    // SSID is subtracted even without -E configured -- EssidSet is always populated.
    assert_not_contains(&lines_scan, "TestSSID");
}
