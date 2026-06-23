//! Integration test: `[progress]` stdout lines and the `--quiet` escape hatch.
//!
//! Cadence is hybrid (every 5 s or every 2 000 000 packets, whichever first).
//! A test capture cannot reach 2 M packets in a reasonable time and we don't
//! want to sleep 5 s, so we lean on the "always print one line at end of
//! Phase 1" behaviour: every run -- even a 1-packet capture -- emits exactly
//! one `[progress]` line just before the closing banner. That is the contract
//! we test here.
//!
//! Two assertions:
//!   1) default run -> stdout contains a `[progress]` line with the expected
//!      `key=value` fields, plus the closing Phase 1-5 banner.
//!   2) `--quiet` run -> stdout contains the closing banner but no `[progress]`
//!      line.

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

/// Tiny LE-microsecond pcap with one trivial packet (so Phase 1 visits the
/// progress reporter at least once via `print_now`).
fn minimal_pcap() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0xA1B2_C3D4_u32.to_le_bytes()); // magic
    v.extend_from_slice(&2_u16.to_le_bytes()); // version_major
    v.extend_from_slice(&4_u16.to_le_bytes()); // version_minor
    v.extend_from_slice(&0_i32.to_le_bytes()); // thiszone
    v.extend_from_slice(&0_u32.to_le_bytes()); // sigfigs
    v.extend_from_slice(&65535_u32.to_le_bytes()); // snaplen
    v.extend_from_slice(&127_u32.to_le_bytes()); // DLT_IEEE802_11_RADIO
    // One packet: a tiny radiotap header (8 bytes, no fields).
    let frame = [
        0x00, 0x00, // version + pad
        0x08, 0x00, // it_len = 8
        0x00, 0x00, 0x00, 0x00, // it_present = 0
    ];
    v.extend_from_slice(&1_u32.to_le_bytes()); // ts_sec
    v.extend_from_slice(&0_u32.to_le_bytes()); // ts_usec
    v.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // incl_len
    v.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // orig_len
    v.extend_from_slice(&frame);
    v
}

#[test]
fn default_run_prints_at_least_one_progress_line() {
    let pcap = "/tmp/wpawolf_progress_default.pcap";
    let out = "/tmp/wpawolf_progress_default.22000";
    let stdout_path = "/tmp/wpawolf_progress_default.stdout";
    let _ = fs::remove_file(out);
    let _ = fs::remove_file(stdout_path);
    fs::write(pcap, minimal_pcap()).unwrap();

    let stdout_file = fs::File::create(stdout_path).unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_wpawolf"))
        .args(["--22000-out", out, pcap])
        .stdout(stdout_file)
        .status()
        .unwrap();
    assert!(status.success(), "wpawolf must exit 0");

    let stdout_contents = fs::read_to_string(stdout_path).unwrap();

    let progress_lines: Vec<&str> = stdout_contents.lines().filter(|l| l.starts_with("[progress]")).collect();
    assert!(
        !progress_lines.is_empty(),
        "expected at least one [progress] line on default stdout; got:\n{stdout_contents}"
    );
    let line = progress_lines[0];
    // Greppability + key fields. RSS is omitted on non-Linux platforms; we
    // don't assert on it here.
    assert!(line.contains("elapsed="), "missing elapsed= field: {line}");
    assert!(line.contains("files="), "missing files= field: {line}");
    assert!(line.contains("packets="), "missing packets= field: {line}");
    assert!(line.contains("eapol="), "missing eapol= field: {line}");
    assert!(line.contains("pmkids="), "missing pmkids= field: {line}");

    // Closing Phase 1 banner is still present.
    assert!(stdout_contents.contains("=== Phase 1: Ingest"), "expected Phase 1 banner; got:\n{stdout_contents}");
}

#[test]
fn quiet_flag_suppresses_progress_lines_but_keeps_banner() {
    let pcap = "/tmp/wpawolf_progress_quiet.pcap";
    let out = "/tmp/wpawolf_progress_quiet.22000";
    let stdout_path = "/tmp/wpawolf_progress_quiet.stdout";
    let _ = fs::remove_file(out);
    let _ = fs::remove_file(stdout_path);
    fs::write(pcap, minimal_pcap()).unwrap();

    let stdout_file = fs::File::create(stdout_path).unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_wpawolf"))
        .args(["--22000-out", out, "--quiet", pcap])
        .stdout(stdout_file)
        .status()
        .unwrap();
    assert!(status.success(), "wpawolf must exit 0");

    let stdout_contents = fs::read_to_string(stdout_path).unwrap();
    assert!(
        !stdout_contents.lines().any(|l| l.starts_with("[progress]")),
        "--quiet must suppress every [progress] line; got:\n{stdout_contents}"
    );
    // Closing banner is still required.
    assert!(
        stdout_contents.contains("=== Phase 1: Ingest"),
        "even with --quiet the closing banner must be intact; got:\n{stdout_contents}"
    );
}
