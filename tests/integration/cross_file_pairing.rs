//! Integration test: handshake stitching across multiple input files.
//!
//! Generates a 3-handshake WPA2-PSK pcap in memory (via
//! `common::multi_handshake_wpa2_psk_pcap`), splits it at the midpoint into two
//! files, drops them in a temp directory, and runs wpawolf against the
//! directory. The shared `MessageStore` and the single `pair_all_groups` pass
//! at the end of Phase 1 mean the M1/M2/M3/M4 frames must reunite even when
//! they live in different files. This test pins that contract.
//!
//! Without cross-file stitching, splitting M1 into one file and M2/M3/M4 into
//! another would produce *fewer* hashes than the baseline -- the N1E2/N1E4
//! combos that require an M1 nonce would never pair. We therefore assert
//! both that the directory run matches the single-file baseline AND that
//! the solo runs over each half each yield strictly fewer hashes (proving
//! the test fixture actually exercises cross-file pairing rather than
//! lucking into both halves containing complete handshakes).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::similar_names,
    missing_docs,
    unused_crate_dependencies,
    clippy::cast_possible_truncation,
    reason = "integration test module -- strict lints relaxed"
)]

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

/// Parses a pcap byte stream into `(global_header, packet_records)`. Each packet
/// record is the full 16-byte per-packet header concatenated with the captured
/// frame payload, ready to write back into another pcap.
fn split_pcap(pcap_bytes: &[u8]) -> ([u8; 24], Vec<Vec<u8>>) {
    let mut hdr = [0u8; 24];
    hdr.copy_from_slice(&pcap_bytes[..24]);

    let mut records = Vec::new();
    let mut pos = 24;
    while pos + 16 <= pcap_bytes.len() {
        let incl_len = u32::from_le_bytes(pcap_bytes[pos + 8..pos + 12].try_into().unwrap()) as usize;
        let total = 16 + incl_len;
        if pos + total > pcap_bytes.len() {
            break;
        }
        records.push(pcap_bytes[pos..pos + total].to_vec());
        pos += total;
    }
    (hdr, records)
}

fn build_pcap(global_hdr: &[u8; 24], records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(global_hdr);
    for r in records {
        out.extend_from_slice(r);
    }
    out
}

/// Runs wpawolf with `-o <out>` on `input_path` and returns the number of
/// emitted hash lines (line count of the taxonomy output file).
fn run_and_count_hashes(input_path: &Path, out_path: &str) -> usize {
    let _ = fs::remove_file(out_path);
    let status = Command::new(common::binary_path())
        .args(["-o", out_path])
        .arg(input_path)
        .stderr(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "wpawolf exit {status} for input {}", input_path.display());
    let body = fs::read_to_string(out_path).unwrap_or_default();
    body.lines().filter(|l| !l.is_empty()).count()
}

#[test]
fn handshake_split_across_two_files_still_emits_baseline_hashes() {
    // Step 1: generate the canonical 3-handshake WPA2-PSK pcap and write it to /tmp.
    // Three handshakes (5 packets each = 15 packets total) gives the midpoint
    // split a high probability of cleaving at least one M1..M4 across the
    // boundary, which is what the cross-file pairing test relies on.
    let bytes = common::multi_handshake_wpa2_psk_pcap(3);
    let baseline_path = common::write_temp_pcap("xfile_base.pcap", &bytes);
    let baseline = run_and_count_hashes(&baseline_path, "/tmp/wpawolf_xfile_base.tax");
    assert!(baseline >= 4, "baseline must yield several hashes; got {baseline}");

    // Step 2: parse and split the fixture into two halves at the midpoint.
    let (gh, records) = split_pcap(&bytes);
    assert!(records.len() >= 4, "fixture must have plenty of packets to split; got {}", records.len());
    let mid = records.len() / 2;
    let file_a_bytes = build_pcap(&gh, &records[..mid]);
    let file_b_bytes = build_pcap(&gh, &records[mid..]);

    // Step 3: write the two halves into a fresh temp directory.
    let tmp_dir = "/tmp/wpawolf_xfile_dir";
    let _ = fs::remove_dir_all(tmp_dir);
    fs::create_dir_all(tmp_dir).unwrap();
    let path_a = format!("{tmp_dir}/half_a.pcap");
    let path_b = format!("{tmp_dir}/half_b.pcap");
    fs::write(&path_a, &file_a_bytes).unwrap();
    fs::write(&path_b, &file_b_bytes).unwrap();

    // Step 4: solo runs each yield strictly fewer hashes than the baseline.
    // (If neither solo run loses hashes, the split is degenerate -- M1..M4
    // all ended up in one half -- and the directory test below proves
    // nothing useful. We require the split to actually break a handshake.)
    let solo_a = run_and_count_hashes(Path::new(&path_a), "/tmp/wpawolf_xfile_a.tax");
    let solo_b = run_and_count_hashes(Path::new(&path_b), "/tmp/wpawolf_xfile_b.tax");
    assert!(
        solo_a < baseline || solo_b < baseline,
        "split must break at least one solo run below baseline (a={solo_a}, b={solo_b}, base={baseline}); \
         otherwise the test does not exercise cross-file stitching"
    );

    // Step 5: running on the directory must recover the full baseline count.
    // This is the contract -- shared MessageStore + single end-of-Phase-1
    // pair_all_groups call means M1 in half_a stitches with M2/M3/M4 in
    // half_b. Anything below baseline means stitching is broken.
    let combined = run_and_count_hashes(Path::new(tmp_dir), "/tmp/wpawolf_xfile_combined.tax");
    assert_eq!(combined, baseline, "directory run must equal single-file baseline; cross-file stitching regression");
}
