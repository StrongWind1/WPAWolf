//! Integration test: 802.11 MSDU fragmentation reassembly through the full binary.
//!
//! Builds a pcap containing two fragments of one Data MSDU sharing Sequence Number
//! 42 (frag 0 with `MoreFrag=1`, frag 1 with `MoreFrag=0`). After running the
//! binary, the Phase 2 stats summary must show:
//!
//! * `fragments seen (non-final, buffered): 1`
//! * `reassembled MSDUs:                    1`
//!
//! This exercises the wiring in `extract::data::process_data` and the
//! `store::fragments::FragmentStore`. Whether or not the reassembled body
//! contained a valid EAPOL-Key is irrelevant for this test -- we are guarding
//! the reassembly machinery itself, not the EAPOL parser.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    missing_docs,
    unused_crate_dependencies,
    clippy::cast_possible_truncation,
    reason = "integration test module -- strict lints relaxed"
)]

use std::fs;
use std::process::Command;

// --- Pcap byte builders ---

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

/// Builds a 24-byte 802.11 Data frame header with the given Sequence Control
/// (Sequence Number << 4 | Fragment Number) and More Fragments flag (FC bit B10).
/// ToDS=1, FromDS=0 (uplink). FC[0]=0x08 (Type=Data), FC[1] varies for `MoreFrag`.
fn data_frame_uplink(ap: [u8; 6], sta: [u8; 6], seq_num: u16, frag_num: u8, more_frag: bool, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; 24];
    frame[0] = 0x08; // Type=Data, Subtype=0
    let mut fc1: u8 = 0x01; // ToDS=1
    if more_frag {
        fc1 |= 0x04; // B10 of FC -> bit 2 of byte 1
    }
    frame[1] = fc1;
    // Address1 = AP (BSSID for uplink), Address2 = STA (SA), Address3 = DA (= AP).
    frame[4..10].copy_from_slice(&ap);
    frame[10..16].copy_from_slice(&sta);
    frame[16..22].copy_from_slice(&ap);
    // Sequence Control (offset 22, LE u16): SeqNum << 4 | FragNum (low 4 bits).
    let seq_ctrl = (seq_num << 4) | u16::from(frag_num & 0x0F);
    frame[22..24].copy_from_slice(&seq_ctrl.to_le_bytes());
    frame.extend_from_slice(body);
    frame
}

fn run_capture(pcap_path: &str) -> String {
    let out_path = format!("{pcap_path}.22000");
    let log_path = format!("{pcap_path}.log");
    let stderr_path = format!("{pcap_path}.stderr");
    let _ = fs::remove_file(&out_path);
    let _ = fs::remove_file(&log_path);
    let _ = fs::remove_file(&stderr_path);
    let stderr_file = fs::File::create(&stderr_path).unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_wpawolf"))
        .args(["--22000-out", &out_path, "--log", &log_path, pcap_path])
        .stderr(stderr_file)
        .status()
        .unwrap();
    assert!(status.success(), "wpawolf exit {status}");
    fs::read_to_string(&stderr_path).unwrap()
}

#[test]
fn two_fragment_msdu_reassembles_through_binary() {
    let pcap = "/tmp/wpawolf_fragmsdu.pcap";

    let ap = [0x02, 0, 0, 0, 0, 0xAA];
    let sta = [0x02, 0, 0, 0, 0, 0xBB];
    let part0 = b"AAAAAAAAAA"; // 10 bytes
    let part1 = b"BBBBBBBBBB"; // 10 bytes
    let f0 = data_frame_uplink(ap, sta, 42, 0, true, part0);
    let f1 = data_frame_uplink(ap, sta, 42, 1, false, part1);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pcap_global_header(105));
    bytes.extend_from_slice(&pcap_packet_record(1000, &f0));
    bytes.extend_from_slice(&pcap_packet_record(1001, &f1));
    fs::write(pcap, &bytes).unwrap();

    let stderr = run_capture(pcap);

    assert!(stderr.contains("fragments seen"), "expected fragment stats in Phase 2 summary; stderr:\n{stderr}");
    assert!(stderr.contains("reassembled MSDUs"), "expected reassembled MSDUs counter; stderr:\n{stderr}");

    // Counts should be exactly 1 each.
    let line = stderr.lines().find(|l| l.contains("fragments seen")).expect("fragments seen line");
    assert!(line.contains(": 1"), "expected count=1 in: {line}");
    let line = stderr.lines().find(|l| l.contains("reassembled MSDUs")).expect("reassembled MSDUs line");
    assert!(line.contains(": 1"), "expected count=1 in: {line}");
}

#[test]
fn orphan_final_fragment_does_not_reassemble() {
    // A final fragment (FragNum=1, MoreFrag=0) arrives without a preceding FragNum=0.
    // Reassembly must fail; counter `fragments dropped (out of order)` increments.
    let pcap = "/tmp/wpawolf_fragorphan.pcap";

    let ap = [0x02, 0, 0, 0, 0, 0xCC];
    let sta = [0x02, 0, 0, 0, 0, 0xDD];
    let f1 = data_frame_uplink(ap, sta, 99, 1, false, b"orphaned");

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pcap_global_header(105));
    bytes.extend_from_slice(&pcap_packet_record(1000, &f1));
    fs::write(pcap, &bytes).unwrap();

    let stderr = run_capture(pcap);

    // No reassembled MSDUs counter should appear (the line only prints when > 0).
    assert!(!stderr.contains("reassembled MSDUs"), "expected no reassembled MSDUs; stderr:\n{stderr}");
    // But the disorder counter should fire.
    assert!(stderr.contains("fragments dropped (out of order"), "expected disorder counter; stderr:\n{stderr}");
}

#[test]
fn unfragmented_frames_do_not_touch_fragment_store() {
    // Sanity baseline: a pcap with no fragmentation must produce zero fragment
    // counters in the Phase 2 summary (the `nz!` macro suppresses the lines).
    let pcap = "/tmp/wpawolf_fragnone.pcap";

    let ap = [0x02, 0, 0, 0, 0, 0xEE];
    let sta = [0x02, 0, 0, 0, 0, 0xFF];
    let f = data_frame_uplink(ap, sta, 1, 0, false, b"hello world");

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pcap_global_header(105));
    bytes.extend_from_slice(&pcap_packet_record(1000, &f));
    fs::write(pcap, &bytes).unwrap();

    let stderr = run_capture(pcap);

    assert!(!stderr.contains("fragments seen"), "no fragment counters expected; stderr:\n{stderr}");
    assert!(!stderr.contains("reassembled MSDUs"), "no reassembly expected; stderr:\n{stderr}");
}
