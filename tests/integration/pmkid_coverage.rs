//! Integration test: PMKID source coverage and output format validation validation.
//!
//! Builds a minimal crafted pcap in memory containing two frames:
//!   1. Assoc Request (S3) with a PSK PMKID in the RSN IE -> WPA\*01\* in 22000 output
//!   2. FT Auth seq=1 (S5) with an FT-PSK PMKID, MDE, and FTE (R0KH-ID) -> WPA\*03\* in 37100 output
//!
//! Assertions:
//!   - At least one WPA\*01\* line produced for the PSK PMKID
//!   - At least one WPA\*03\* line produced for the FT-PSK PMKID
//!   - No duplicate lines in either output file
//!   - Every WPA\*01\* line has exactly 9 `*`-separated fields
//!   - Every WPA\*03\* line has exactly 12 `*`-separated fields

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs,
    unused_crate_dependencies,
    clippy::cast_possible_truncation,
    reason = "integration test module -- strict lints relaxed"
)]

use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;

// --- Pcap byte builders ---

/// Write a standard classic pcap global header (24 bytes).
///
/// Magic `0xA1B2C3D4` (microsecond, LE). `LinkType`: `DLT_IEEE802_11` = 105.
fn pcap_global_header(link_type: u32) -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&0xA1B2_C3D4_u32.to_le_bytes()); // magic
    h[4..6].copy_from_slice(&2_u16.to_le_bytes()); // major
    h[6..8].copy_from_slice(&4_u16.to_le_bytes()); // minor
    // bytes 8-11: thiszone = 0; bytes 12-15: sigfigs = 0 (already 0)
    h[16..20].copy_from_slice(&65535_u32.to_le_bytes()); // snaplen
    h[20..24].copy_from_slice(&link_type.to_le_bytes()); // linktype
    h
}

/// Wrap `data` in a classic pcap packet record (16-byte header + data).
fn pcap_packet_record(ts_sec: u32, data: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(16 + data.len());
    r.extend_from_slice(&ts_sec.to_le_bytes()); // ts_sec
    r.extend_from_slice(&0_u32.to_le_bytes()); // ts_usec
    let len = data.len() as u32;
    r.extend_from_slice(&len.to_le_bytes()); // caplen
    r.extend_from_slice(&len.to_le_bytes()); // orig_len
    r.extend_from_slice(data);
    r
}

/// Build the 24-byte 802.11 management frame header.
///
/// For management frames (type=0) with ToDS=0, FromDS=0:
///   Addr1=DA, Addr2=SA, Addr3=BSSID -> `frame::parse` sets AP=Addr3, STA=Addr2.
/// [IEEE 802.11-2024] §9.3.3.1
fn mgmt_header(subtype: u8, addr1: [u8; 6], addr2: [u8; 6], addr3: [u8; 6]) -> [u8; 24] {
    let mut h = [0u8; 24];
    // Frame Control byte 0: bits 7-4 = subtype, bits 3-2 = type (0=mgmt), bits 1-0 = version
    h[0] = subtype << 4;
    h[1] = 0x00; // no flags (ToDS=0, FromDS=0, Protected=0, ...)
    // Duration field (bytes 2-3): zero for crafted test frames
    h[4..10].copy_from_slice(&addr1); // Addr1 (DA / BSSID for downlink / AP for mgmt)
    h[10..16].copy_from_slice(&addr2); // Addr2 (SA / STA)
    h[16..22].copy_from_slice(&addr3); // Addr3 (BSSID)
    // Sequence Control (bytes 22-23): zero
    h
}

/// Build a minimal RSN IE tagged parameter block with the given AKM type and one PMKID.
///
/// Structure: Version(2) + GroupCipher(4) + PairwiseCount(2)+Suite(4) + `AkmCount`(2)+Suite(4)
///            + `RsnCaps`(2) + `PmkidCount`(2) + Pmkid(16). Total value = 38 bytes.
/// [IEEE 802.11-2024] §9.4.2.24
fn rsn_ie_with_pmkid(akm_type: u8, pmkid: &[u8; 16]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x01, 0x00]); // Version = 1
    v.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // Group cipher: CCMP
    v.extend_from_slice(&[0x01, 0x00]); // Pairwise count = 1
    v.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // CCMP pairwise
    v.extend_from_slice(&[0x01, 0x00]); // AKM count = 1
    v.extend_from_slice(&[0x00, 0x0F, 0xAC, akm_type]); // AKM suite
    v.extend_from_slice(&[0x00, 0x00]); // RSN Capabilities
    v.extend_from_slice(&[0x01, 0x00]); // PMKID Count = 1
    v.extend_from_slice(pmkid); // PMKID
    let ie_len = u8::try_from(v.len()).expect("RSN IE value too long for u8");
    let mut ie = vec![48u8, ie_len]; // tag=48, length
    ie.extend_from_slice(&v);
    ie
}

/// Build an 802.11 Association Request frame (subtype=0) containing a PSK PMKID.
///
/// Fixed fields (4 bytes): Capability Info + Listen Interval.
/// Tagged params: RSN IE (AKM=2, PSK) with one PMKID + SSID IE.
/// Per `frame::parse` IBSS/mgmt convention: AP=Addr3, STA=Addr2.
fn assoc_req_frame(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<u8> {
    // subtype=0 (assoc req): FC[0] = 0x00 << 4 = 0x00
    let mut frame: Vec<u8> = mgmt_header(0, ap, sta, ap).to_vec();
    // Fixed fields: Capability Info (2 bytes) + Listen Interval (2 bytes)
    frame.extend_from_slice(&[0x11, 0x00, 0x0A, 0x00]);
    // SSID IE (tag=0, len=7, "testnet")
    frame.extend_from_slice(&[0u8, 7]);
    frame.extend_from_slice(b"testnet");
    // RSN IE with PSK PMKID (AKM type 2)
    frame.extend_from_slice(&rsn_ie_with_pmkid(2, pmkid));
    frame
}

/// Build an 802.11 FT Authentication frame (subtype=11, algo=2, seq=1) with FT-PSK PMKID.
///
/// Includes MDE (tag 54) and FTE (tag 55) with R0KH-ID subelement so that
/// `ft.r0khid_len > 0` and the entry is routed to 37100 output.
/// Per `frame::parse` mgmt convention: AP=Addr3, STA=Addr2.
/// [IEEE 802.11-2024] §13.8.3, §9.4.2.45 (MDE), §9.4.2.46 (FTE)
fn ft_auth_frame(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<u8> {
    // subtype=11 (auth): FC[0] = 0x0B << 4 = 0xB0
    let mut frame: Vec<u8> = mgmt_header(11, ap, sta, ap).to_vec();
    // Auth fixed: Algorithm=2 (FBT) + Sequence=1 + Status=0
    frame.extend_from_slice(&[0x02, 0x00]); // algo = 2 (FT)
    frame.extend_from_slice(&[0x01, 0x00]); // seq = 1
    frame.extend_from_slice(&[0x00, 0x00]); // status = 0 (success)
    // RSN IE with FT-PSK PMKID (AKM=4 = FT-PSK). [§13.8.3]
    frame.extend_from_slice(&rsn_ie_with_pmkid(4, pmkid));
    // MDE: tag=54, len=3, MDID=[0x12,0x34], FT-Capability=0x00. [§9.4.2.45]
    frame.extend_from_slice(&[54, 3, 0x12, 0x34, 0x00]);
    // FTE: tag=55, 82-byte fixed body (MIC ctrl + MIC + ANonce + SNonce) + subelements.
    // R0KH-ID subelement (type=3, len=4) required for r0khid_len>0. [§9.4.2.46]
    // R1KH-ID subelement (type=1, len=6).
    let mut fte_val = vec![0u8; 82]; // MIC ctrl(2) + MIC(16) + ANonce(32) + SNonce(32)
    fte_val.extend_from_slice(&[3, 4, 0xAA, 0xBB, 0xCC, 0xDD]); // R0KH-ID
    fte_val.extend_from_slice(&[1, 6, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // R1KH-ID
    let fte_len = u8::try_from(fte_val.len()).expect("FTE value too long for u8");
    frame.push(55);
    frame.push(fte_len);
    frame.extend_from_slice(&fte_val);
    frame
}

/// Assemble the complete crafted fixture pcap.
fn build_fixture_pcap() -> Vec<u8> {
    let ap_mac = [0x00_u8, 0x11, 0x22, 0x33, 0x44, 0x55];
    let sta_mac = [0xAA_u8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    // Distinct non-zero PMKIDs so dedup doesn't collapse them.
    let psk_pmkid = [0x01_u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
    let ft_pmkid = [0x11_u8, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20];

    let mut pcap = Vec::new();
    pcap.extend_from_slice(&pcap_global_header(105)); // DLT_IEEE802_11

    // Packet 1: Assoc Request with PSK PMKID -> S3 -> WPA*01* in 22000
    let frame1 = assoc_req_frame(ap_mac, sta_mac, &psk_pmkid);
    pcap.extend_from_slice(&pcap_packet_record(1000, &frame1));

    // Packet 2: FT Auth seq=1 with FT-PSK PMKID + MDE + FTE -> S5 -> WPA*03* in 37100
    let frame2 = ft_auth_frame(ap_mac, sta_mac, &ft_pmkid);
    pcap.extend_from_slice(&pcap_packet_record(1001, &frame2));

    pcap
}

// --- Test runner ---

fn read_nonempty_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path).unwrap_or_default().lines().filter(|l| !l.is_empty()).map(String::from).collect()
}

#[test]
fn pmkid_coverage_format_and_dedup() {
    // Write fixture pcap to a temp path.
    let pcap_path = "/tmp/wpawolf_t1311_fixture.pcap";
    let out22_path = "/tmp/wpawolf_t1311.22000";
    let out37_path = "/tmp/wpawolf_t1311.37100";

    fs::write(pcap_path, build_fixture_pcap()).expect("write fixture pcap");

    // Run wpawolf with both output modes.
    let status = Command::new(env!("CARGO_BIN_EXE_wpawolf"))
        .args(["--22000-out", out22_path, "--37100-out", out37_path, pcap_path])
        .status()
        .expect("failed to spawn wpawolf");
    assert!(status.success(), "wpawolf exited non-zero: {status}");

    let lines22 = read_nonempty_lines(Path::new(out22_path));
    let lines37 = read_nonempty_lines(Path::new(out37_path));

    // --- Dedup: no duplicate lines in either output ---
    let set22: HashSet<&str> = lines22.iter().map(String::as_str).collect();
    assert_eq!(lines22.len(), set22.len(), "duplicate lines in 22000 output");
    let set37: HashSet<&str> = lines37.iter().map(String::as_str).collect();
    assert_eq!(lines37.len(), set37.len(), "duplicate lines in 37100 output");

    // --- At least one line of each expected type ---
    assert!(
        lines22.iter().any(|l| l.starts_with("WPA*01*")),
        "expected at least one WPA*01* line in 22000 output; got: {lines22:?}"
    );
    assert!(
        lines37.iter().any(|l| l.starts_with("WPA*03*")),
        "expected at least one WPA*03* line in 37100 output; got: {lines37:?}"
    );

    // --- Field counts: WPA*01* must have 9 fields, WPA*03* must have 12 fields ---
    // Format: WPA*{type}*{pmkid}*{ap}*{sta}*{essid}***{mp}         (9 fields)
    //         WPA*{type}*{pmkid}*{ap}*{sta}*{essid}***{mp}*{mdid}*{r0khid}*{r1khid} (12 fields)
    for line in &lines22 {
        if line.starts_with("WPA*01*") {
            let count = line.split('*').count();
            assert_eq!(count, 9, "WPA*01* line has wrong field count (expected 9): {line}");
        }
    }
    for line in &lines37 {
        if line.starts_with("WPA*03*") || line.starts_with("WPA*04*") {
            let count = line.split('*').count();
            assert_eq!(count, 12, "WPA*03*/04* line has wrong field count (expected 12): {line}");
        }
    }
}
