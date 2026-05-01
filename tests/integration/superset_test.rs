//! Integration test: wpawolf output must be a superset of hcxpcapngtool output.
//!
//! Generates pcap and pcapng captures in memory via `common::*` (no checked-in
//! binary fixtures), runs the upstream `hcxpcapngtool` reference at test time
//! to produce the oracle output, runs `wpawolf` in wide mode (all 6 N#E#
//! combinations, no rc-drift filter, no collapse), and asserts that every line
//! emitted by `hcxpcapngtool` also appears verbatim in the wpawolf output --
//! plus an internal-no-duplicates check on the wpawolf side.
//!
//! ## Oracle version requirement
//!
//! wpawolf claims superset parity against `hcxpcapngtool >= 7.0.1`. Older
//! releases emit a different `WPA*01*` / `WPA*02*` trailer format and select a
//! different canonical EAPOL frame; the parity claim is undefined against them.
//! `MIN_HCXPCAPNGTOOL = (7, 0, 1)` is enforced here so a stale apt-installed
//! oracle (Ubuntu/Debian still ship 6.2.x) cannot silently produce false
//! mismatches.
//!
//! ## Skip behaviour
//!
//! When the binary is missing or too old:
//!   * In CI (`CI=true` or `CI=1` in env) the test panics so the parity gate
//!     can never be silently no-op'd by a forgotten install step.
//!   * Outside CI the test is skipped via `#[ignore]`-style early return with
//!     a loud `eprintln!` so contributors without hcxtools installed can still
//!     run the rest of the suite. Locally, run `make check-parity` (which
//!     hard-fails on a missing oracle) before relying on the parity claim.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs,
    unused_crate_dependencies,
    reason = "integration test module -- strict lints relaxed"
)]

mod common;

use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Minimum hcxpcapngtool version wpawolf claims superset parity against.
///
/// Pre-7.0.1 oracles diverge on `WPA*02*` canonical-frame selection (the M2
/// vs. M3 frame swap that landed in 7.0.1) and pre-6.3.1 oracles also lack
/// the `WPA*01*` PMKID status-byte trailer. Comparing wpawolf against any
/// older version is meaningless and produces noisy false-positive mismatches.
const MIN_HCXPCAPNGTOOL: (u32, u32, u32) = (7, 0, 1);

/// Result of probing for a usable hcxpcapngtool oracle.
enum OracleProbe {
    /// Binary on PATH and version >= `MIN_HCXPCAPNGTOOL`.
    Ok,
    /// Binary not on PATH, or `--version` failed to spawn.
    Missing,
    /// Binary on PATH but reports a version older than `MIN_HCXPCAPNGTOOL`.
    TooOld(String),
}

/// `true` iff the harness is running under a CI pipeline. CI must never
/// silently skip the parity test; without this flag a missing oracle would
/// turn the gate into a no-op (the original failure mode that masked Alex's
/// 6.2.7 breakage). Both `CI=true` and `CI=1` are recognised; that covers
/// `GitHub` Actions, `GitLab`, `CircleCI`, and most other vendors.
fn is_ci() -> bool {
    matches!(env::var("CI").as_deref(), Ok("true" | "1" | "TRUE"))
}

/// Parse `hcxpcapngtool 7.1.2 (C) 2026 ZeroBeat` -> `Some((7, 1, 2))`.
fn parse_version(line: &str) -> Option<(u32, u32, u32)> {
    let token = line.split_whitespace().nth(1)?;
    let mut parts = token.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    // Patch may carry trailing -gXXXXX from a git-described build; strip it.
    let patch_token = parts.next()?;
    let patch = patch_token.split('-').next()?.parse().ok()?;
    Some((major, minor, patch))
}

/// Probe whether the oracle is present and recent enough to use as ground truth.
fn probe_oracle() -> OracleProbe {
    let output = Command::new("hcxpcapngtool").arg("--version").output();
    let Ok(out) = output else { return OracleProbe::Missing };
    if !out.status.success() {
        return OracleProbe::Missing;
    }
    // hcxpcapngtool prints the version banner on stdout in 7.x and stderr in
    // older releases; check both so the version gate works against the full
    // matrix the project actually has to defend against.
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let first = stdout.lines().chain(stderr.lines()).find(|l| l.contains("hcxpcapngtool"));
    let Some(line) = first else { return OracleProbe::TooOld("<unparseable banner>".into()) };
    match parse_version(line) {
        Some(v) if v >= MIN_HCXPCAPNGTOOL => OracleProbe::Ok,
        Some(v) => OracleProbe::TooOld(format!("{}.{}.{}", v.0, v.1, v.2)),
        None => OracleProbe::TooOld(line.to_owned()),
    }
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
    match probe_oracle() {
        OracleProbe::Ok => {},
        OracleProbe::Missing => {
            let msg = format!(
                "hcxpcapngtool not on PATH; install >= {}.{}.{} (build from \
                 https://github.com/ZerBea/hcxtools, distro packages are too old)",
                MIN_HCXPCAPNGTOOL.0, MIN_HCXPCAPNGTOOL.1, MIN_HCXPCAPNGTOOL.2,
            );
            assert!(!is_ci(), "CI parity gate: {msg}");
            eprintln!("skipping superset_{label}: {msg}");
            return;
        },
        OracleProbe::TooOld(found) => {
            let msg = format!(
                "hcxpcapngtool {found} is older than the minimum supported \
                 oracle {}.{}.{}; pre-7.0.1 emits a different WPA*01*/WPA*02* \
                 format and is not a valid parity reference",
                MIN_HCXPCAPNGTOOL.0, MIN_HCXPCAPNGTOOL.1, MIN_HCXPCAPNGTOOL.2,
            );
            assert!(!is_ci(), "CI parity gate: {msg}");
            eprintln!("skipping superset_{label}: {msg}");
            return;
        },
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

// --- Version-banner parser unit tests ---
//
// The probe relies on `parse_version` to compare against MIN_HCXPCAPNGTOOL.
// Cover the banner shapes hcxpcapngtool has emitted across the 6.3.x and 7.x
// releases, plus the git-described patch (`7.1.2-56-gec90972`) the build
// system stamps when compiling between tags.

#[test]
fn parse_version_handles_release_banner() {
    assert_eq!(parse_version("hcxpcapngtool 7.1.2 (C) 2026 ZeroBeat"), Some((7, 1, 2)));
    assert_eq!(parse_version("hcxpcapngtool 7.0.1 (C) 2025 ZeroBeat"), Some((7, 0, 1)));
    assert_eq!(parse_version("hcxpcapngtool 6.3.5 (C) 2024 ZeroBeat"), Some((6, 3, 5)));
}

#[test]
fn parse_version_strips_git_described_suffix() {
    // Built from a commit between 7.1.2 and the next tag; banner reads
    // `7.1.2-56-gec90972`. Patch number must still parse to 2.
    assert_eq!(parse_version("hcxpcapngtool 7.1.2-56-gec90972 (C) 2026 ZeroBeat"), Some((7, 1, 2)));
}

#[test]
fn parse_version_rejects_garbage() {
    assert_eq!(parse_version(""), None);
    assert_eq!(parse_version("nothing parseable here"), None);
    assert_eq!(parse_version("hcxpcapngtool"), None);
    assert_eq!(parse_version("hcxpcapngtool x.y.z"), None);
}

#[test]
fn min_oracle_threshold_is_satisfied_by_known_good_versions() {
    // Documented compatibility line: any version >= 7.0.1 is accepted, and
    // every version < 7.0.1 is rejected. If the threshold ever moves, this
    // test pins the boundary so reviewers see the expected break.
    assert!((7, 0, 1) >= MIN_HCXPCAPNGTOOL);
    assert!((7, 0, 0) < MIN_HCXPCAPNGTOOL);
    assert!((6, 3, 5) < MIN_HCXPCAPNGTOOL);
    assert!((7, 1, 2) >= MIN_HCXPCAPNGTOOL);
}
