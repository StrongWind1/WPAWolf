//! Integration test: wpawolf output must be a superset of hcxpcapngtool output.
//!
//! Generates pcap and pcapng captures in memory via `common::*` (no checked-in
//! binary fixtures), runs the upstream `hcxpcapngtool` reference at test time
//! to produce the oracle output, runs `wpawolf` in wide mode (all 6 N#E#
//! combinations, no rc-drift filter, no collapse), and asserts that every line
//! emitted by `hcxpcapngtool` also appears verbatim in the wpawolf output --
//! plus an internal-no-duplicates check on the wpawolf side.
//!
//! If the upstream `hcxpcapngtool` binary is not on `PATH`, each test logs a
//! skip notice and exits successfully (so contributors without the C tool
//! installed can still run the suite). CI environments that pin the regression
//! oracle should ensure `hcxpcapngtool` is installed.

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

/// `true` iff `hcxpcapngtool --version` runs and exits successfully. We probe
/// instead of hard-failing so the test suite stays runnable without the C
/// reference binary; CI is responsible for installing it.
fn hcxpcapngtool_available() -> bool {
    Command::new("hcxpcapngtool")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Run `hcxpcapngtool -o <out> <input>`, returning the path the caller can read
/// non-empty hash lines from. Stdout / stderr are discarded -- only the file
/// matters here.
fn run_hcxpcapngtool(input: &Path, output: &Path) {
    let _ = fs::remove_file(output);
    let status = Command::new("hcxpcapngtool")
        .arg("-o")
        .arg(output)
        .arg(input)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("failed to spawn hcxpcapngtool");
    assert!(status.success(), "hcxpcapngtool exited with non-zero status: {status}");
}

/// Run wpawolf in wide mode, writing legacy 22000 hash lines to `output`.
fn run_wpawolf(input: &Path, output: &Path) {
    let _ = fs::remove_file(output);
    let status = Command::new(common::binary_path())
        .args(["--22000-out", output.to_str().unwrap()])
        .arg(input)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("failed to spawn wpawolf");
    assert!(status.success(), "wpawolf exited with non-zero status: {status}");
}

/// Read non-empty lines into a Vec. Missing file returns an empty Vec so a
/// failing assert points at the real superset / dedup violation.
fn read_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path).unwrap_or_default().lines().filter(|l| !l.is_empty()).map(String::from).collect()
}

/// Core superset oracle. Wraps the four steps both tests share:
///   1. write `capture_bytes` to `<tmp>/<label>.<ext>`
///   2. run hcxpcapngtool against it
///   3. run wpawolf against it
///   4. assert wpawolf output is a superset of hcxpcapngtool output AND wpawolf output has no duplicates
fn assert_wpawolf_supersets_hcxpcapngtool(label: &str, ext: &str, capture_bytes: &[u8]) {
    if !hcxpcapngtool_available() {
        eprintln!("skipping superset_{label}: hcxpcapngtool not on PATH");
        return;
    }
    let dir = common::temp_dir("wpawolf_superset");
    // Embed `ext` in every per-test filename so the pcap and pcapng tests can
    // run in parallel without overwriting each other's oracle / actual files.
    let cap_path: PathBuf = dir.join(format!("{label}_{ext}.{ext}"));
    fs::write(&cap_path, capture_bytes).unwrap();

    let oracle_path = dir.join(format!("{label}_{ext}_oracle.22000"));
    let actual_path = dir.join(format!("{label}_{ext}_actual.22000"));
    run_hcxpcapngtool(&cap_path, &oracle_path);
    run_wpawolf(&cap_path, &actual_path);

    let actual_lines = read_lines(&actual_path);
    let actual_set: HashSet<&str> = actual_lines.iter().map(String::as_str).collect();
    let oracle_lines = read_lines(&oracle_path);

    // hcxpcapngtool must produce at least one line on the generated fixture --
    // otherwise the superset assertion below is vacuously true and the test
    // proves nothing about wpawolf's parity.
    assert!(!oracle_lines.is_empty(), "hcxpcapngtool emitted no lines for {label}.{ext}; oracle is degenerate");

    for line in &oracle_lines {
        assert!(
            actual_set.contains(line.as_str()),
            "superset check failed for {label}.{ext}: oracle line missing from wpawolf output:\n  {line}"
        );
    }

    // Internal dedup invariant: wpawolf must not emit the same line twice.
    assert_eq!(actual_lines.len(), actual_set.len(), "duplicate lines in wpawolf output for {label}.{ext}");
}

#[test]
fn superset_pcap_three_handshakes() {
    let bytes = common::multi_handshake_wpa2_psk_pcap(3);
    assert_wpawolf_supersets_hcxpcapngtool("three_handshakes", "pcap", &bytes);
}

#[test]
fn superset_pcapng_three_handshakes() {
    let bytes = common::multi_handshake_wpa2_psk_pcapng(3);
    assert_wpawolf_supersets_hcxpcapngtool("three_handshakes", "pcapng", &bytes);
}
