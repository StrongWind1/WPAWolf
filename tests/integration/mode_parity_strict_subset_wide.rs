//! Integration test: wpawolf STRICT output must be a subset of WIDE output.
//!
//! STRICT mode is composed of pure subset-filters layered on top of WIDE:
//! `--eapoltimeout` drops messages outside a time window, `--rc-drift` drops
//! pairs whose replay-counter delta is too large, and `--dedup-hash-combos`
//! collapses N#E# equivalence classes. None of those can synthesize an output
//! line the underlying WIDE pipeline did not already produce -- so for any
//! capture, every line in the STRICT output must also appear in the WIDE
//! output. This is the P0 invariant the cross-version corpus harness pins
//! across the corpus; this test pins it on a generated fixture so the gate
//! still fires in CI where the corpus is not available.
//!
//! A regression here means a STRICT-mode code path is producing output that
//! the WIDE path does not -- almost certainly a logic bug in the filter
//! (wrong predicate, wrong scope, late mutation of shared state).

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

/// Run wpawolf with the given extra flags, capturing 22000 + 37100 output to
/// the two given files. Returns the union of non-empty lines read back from
/// both files.
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
    assert!(status.success(), "wpawolf exited with non-zero status: {status} (flags: {extra:?})");
    let mut lines = read_lines(out22);
    lines.extend(read_lines(out37));
    lines
}

fn read_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path).unwrap_or_default().lines().filter(|l| !l.is_empty()).map(String::from).collect()
}

fn assert_strict_subset_of_wide(label: &str, capture_bytes: &[u8], ext: &str) {
    let dir = common::temp_dir("wpawolf_mode_parity");
    let cap_path: PathBuf = dir.join(format!("{label}_{ext}.{ext}"));
    fs::write(&cap_path, capture_bytes).unwrap();

    let wide_22 = dir.join(format!("{label}_{ext}_wide.22000"));
    let wide_37 = dir.join(format!("{label}_{ext}_wide.37100"));
    let strict_22 = dir.join(format!("{label}_{ext}_strict.22000"));
    let strict_37 = dir.join(format!("{label}_{ext}_strict.37100"));

    let wide_lines = run_and_collect(&cap_path, &wide_22, &wide_37, &[]);
    let strict_lines = run_and_collect(&cap_path, &strict_22, &strict_37, &["--strict"]);

    // The fixture is non-degenerate: WIDE must produce at least one line, or
    // the subset check below is vacuously true and would hide a real regression.
    assert!(!wide_lines.is_empty(), "WIDE produced no lines for {label}.{ext}; fixture is degenerate");

    let wide_set: HashSet<&str> = wide_lines.iter().map(String::as_str).collect();
    for line in &strict_lines {
        assert!(
            wide_set.contains(line.as_str()),
            "STRICT output not a subset of WIDE for {label}.{ext}: line present in STRICT but missing from WIDE:\n  {line}"
        );
    }
    // STRICT must also have no duplicates of its own.
    let strict_set: HashSet<&str> = strict_lines.iter().map(String::as_str).collect();
    assert_eq!(strict_lines.len(), strict_set.len(), "duplicate lines in STRICT output for {label}.{ext}");
}

#[test]
fn strict_subset_of_wide_pcap_three_handshakes() {
    let bytes = common::multi_handshake_wpa2_psk_pcap(3);
    assert_strict_subset_of_wide("three_handshakes", &bytes, "pcap");
}

#[test]
fn strict_subset_of_wide_pcapng_three_handshakes() {
    let bytes = common::multi_handshake_wpa2_psk_pcapng(3);
    assert_strict_subset_of_wide("three_handshakes", &bytes, "pcapng");
}
