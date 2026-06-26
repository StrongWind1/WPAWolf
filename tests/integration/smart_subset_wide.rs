//! Integration test: wpawolf `--smart` output is a never-miss subset of WIDE.
//!
//! `--smart` (handshake-instance attribution) prunes only provably-uncrackable
//! cross-instance candidate lines, so two invariants must hold for any capture:
//! (1) every smart-emitted line also appears in WIDE (subset -- smart never
//! invents a line), and (2) every distinct MIC / PMKID present in the WIDE output
//! is still present in the smart output -- smart never drops a crackable
//! handshake. Invariant (2) is the cardinal never-miss rule of
//! `docs/smart-pairing-design.md` (`smart-crackable >= ... ` is enforced at the
//! MIC level here). A regression is a P0 never-miss bug in the smart selector.
//!
//! On a clean multi-handshake fixture (distinct AP/STA per handshake) smart is a
//! no-op, so this gate primarily guards that the binary smart path does not
//! corrupt or drop lines on ordinary captures; the prune path is exercised by the
//! `pair::combos` unit tests and the developer-local corpus regression.

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
use std::path::{Path, PathBuf};
use std::process::Command;

/// Run wpawolf with the given extra flags, capturing 22000 + 37100 output, and
/// return the union of non-empty output lines.
fn run_and_collect(input: &Path, out22: &Path, out37: &Path, extra: &[&str]) -> Vec<String> {
    let _ = fs::remove_file(out22);
    let _ = fs::remove_file(out37);
    let mut cmd = Command::new(common::binary_path());
    cmd.args(["--22000-out", out22.to_str().unwrap(), "--37100-out", out37.to_str().unwrap()]);
    for f in extra {
        cmd.arg(f);
    }
    cmd.arg(input);
    let status = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("failed to spawn wpawolf");
    assert!(status.success(), "wpawolf exited non-zero: {status} (flags: {extra:?})");
    let mut lines = read_lines(out22);
    lines.extend(read_lines(out37));
    lines
}

fn read_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path).unwrap_or_default().lines().filter(|l| !l.is_empty()).map(String::from).collect()
}

/// Extracts the MIC / PMKID (field index 2 in `WPA*TYPE*HASH*...`) from each line.
fn hashes(lines: &[String]) -> HashSet<String> {
    lines.iter().filter_map(|l| l.split('*').nth(2).map(String::from)).collect()
}

fn assert_smart_never_misses(label: &str, capture_bytes: &[u8], ext: &str) {
    let dir = common::temp_dir("wpawolf_smart_subset");
    let cap_path: PathBuf = dir.join(format!("{label}_{ext}.{ext}"));
    fs::write(&cap_path, capture_bytes).unwrap();

    let wide_lines = run_and_collect(
        &cap_path,
        &dir.join(format!("{label}_{ext}_wide.22000")),
        &dir.join(format!("{label}_{ext}_wide.37100")),
        &[],
    );
    let smart_lines = run_and_collect(
        &cap_path,
        &dir.join(format!("{label}_{ext}_smart.22000")),
        &dir.join(format!("{label}_{ext}_smart.37100")),
        &["--smart"],
    );

    // Non-degenerate fixture: WIDE must emit something or the checks are vacuous.
    assert!(!wide_lines.is_empty(), "WIDE produced no lines for {label}.{ext}; fixture is degenerate");

    // (1) subset: every smart line is a WIDE line.
    let wide_set: HashSet<&str> = wide_lines.iter().map(String::as_str).collect();
    for line in &smart_lines {
        assert!(
            wide_set.contains(line.as_str()),
            "--smart emitted a line WIDE did not (not a subset) for {label}.{ext}:\n  {line}"
        );
    }

    // (2) never-miss: every distinct WIDE MIC/PMKID survives under --smart.
    let smart_hashes = hashes(&smart_lines);
    for h in hashes(&wide_lines) {
        assert!(
            smart_hashes.contains(&h),
            "--smart dropped a crackable MIC/PMKID present in WIDE for {label}.{ext}: {h}"
        );
    }

    // --smart output carries no duplicate lines of its own.
    let smart_set: HashSet<&str> = smart_lines.iter().map(String::as_str).collect();
    assert_eq!(smart_lines.len(), smart_set.len(), "duplicate lines in --smart output for {label}.{ext}");
}

#[test]
fn smart_never_misses_pcap_three_handshakes() {
    let bytes = common::multi_handshake_wpa2_psk_pcap(3);
    assert_smart_never_misses("three_handshakes", &bytes, "pcap");
}

#[test]
fn smart_never_misses_pcapng_three_handshakes() {
    let bytes = common::multi_handshake_wpa2_psk_pcapng(3);
    assert_smart_never_misses("three_handshakes", &bytes, "pcapng");
}
