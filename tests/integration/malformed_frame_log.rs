//! Integration test: `--log` emits `[malformed_frame]` entries for truncated MAC headers.
//!
//! Asserts that when a packet is shorter than the 24-byte 802.11 MAC header minimum,
//! wpawolf bumps `stats.malformed_mac_hdr` AND writes a `[malformed_frame]` line to
//! the log file configured via `--log`. Regression test for the advertised but
//! previously unwired log category.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs,
    unused_crate_dependencies,
    clippy::cast_possible_truncation,
    reason = "integration test module -- strict lints relaxed"
)]

use std::fs;
use std::process::Command;

// --- Pcap byte builders (duplicated from pmkid_coverage.rs to keep tests independent) ---

/// Classic pcap global header, 24 bytes, microsecond resolution, `DLT_IEEE802_11` = 105.
fn pcap_global_header(link_type: u32) -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&0xA1B2_C3D4_u32.to_le_bytes());
    h[4..6].copy_from_slice(&2_u16.to_le_bytes());
    h[6..8].copy_from_slice(&4_u16.to_le_bytes());
    h[16..20].copy_from_slice(&65535_u32.to_le_bytes());
    h[20..24].copy_from_slice(&link_type.to_le_bytes());
    h
}

/// Classic pcap packet record: 16-byte header + data.
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

#[test]
fn malformed_frame_logged_on_truncated_mac_header() {
    let pcap_path = "/tmp/wpawolf_t4_malformed.pcap";
    let log_path = "/tmp/wpawolf_t4_malformed.log";
    // Pre-clean so a prior run does not contaminate the assertion.
    let _ = fs::remove_file(log_path);

    // Build a pcap with one frame too short for the 24-byte MAC header minimum.
    // frame::parse rejects this, bumping malformed_mac_hdr and emitting the log line.
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&pcap_global_header(105));
    let tiny_frame = [0u8; 8]; // 8 bytes -- well below the 24-byte MAC header minimum
    pcap.extend_from_slice(&pcap_packet_record(1000, &tiny_frame));
    fs::write(pcap_path, &pcap).expect("write fixture pcap");

    // wpawolf requires at least one output flag; the fixture yields no hashes, so the
    // output file is legitimately empty. We only care about the --log side effect here.
    let out_path = "/tmp/wpawolf_t4_malformed.22000";
    let _ = fs::remove_file(out_path);
    let status = Command::new(env!("CARGO_BIN_EXE_wpawolf"))
        .args(["--log", log_path, "--22000-out", out_path, pcap_path])
        .status()
        .expect("failed to spawn wpawolf");
    assert!(status.success(), "wpawolf exited non-zero: {status}");

    let log_contents = fs::read_to_string(log_path).expect("log file not created");
    let malformed_lines: Vec<&str> = log_contents.lines().filter(|l| l.starts_with("[malformed_frame]")).collect();
    assert_eq!(
        malformed_lines.len(),
        1,
        "expected exactly one [malformed_frame] summary line; got {}:\n{log_contents}",
        malformed_lines.len(),
    );
    assert!(
        malformed_lines[0].contains("truncated 802.11 MAC header") && malformed_lines[0].contains("count=1"),
        "summary line missing expected reason or count: {}",
        malformed_lines[0],
    );
}
