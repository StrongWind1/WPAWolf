//! Integration test: walks the generated fixture corpus produced by
//! `wpawolf-fixturegen` and asserts wpawolf parses every file without
//! crashing and emits at least one hash line for the type-N fixtures.
//!
//! Corpus location: `tests/fixtures/generated/`. Regenerate with:
//!
//! ```sh
//! cargo run --release -p wpawolf-fixturegen -- all --out tests/fixtures/generated/
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::too_many_lines,
    missing_docs,
    unused_crate_dependencies,
    reason = "integration test module -- strict lints relaxed"
)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CORPUS_ROOT: &str = "tests/fixtures/generated";

fn binary_path() -> PathBuf {
    let env = std::env::var("CARGO_BIN_EXE_wpawolf");
    if let Ok(p) = env {
        return PathBuf::from(p);
    }
    // Fallback for `cargo test` invocations that don't set the env var
    // (e.g. outside the wpawolf package).
    let target = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(target).join("target").join("release").join("wpawolf")
}

/// Run wpawolf with the combined `-o` sink so every taxonomy type
/// (including PSK-SHA256, FT, and SHA-384 families that bypass `--22000-out`)
/// is captured.
fn run_wpawolf(input: &Path) -> String {
    let bin = binary_path();
    let combined =
        std::env::temp_dir().join(format!("wpawolf-test-{}-{}.combined", std::process::id(), nanos_unique()));
    let _ = fs::remove_file(&combined);
    let status = Command::new(&bin).arg("-o").arg(&combined).arg(input).status().expect("spawn wpawolf");
    assert!(status.success(), "wpawolf failed on {}", input.display());
    fs::read_to_string(&combined).unwrap_or_default()
}

/// Run wpawolf over multiple input files in a single invocation.
fn run_wpawolf_multi(inputs: &[&Path]) -> String {
    let bin = binary_path();
    let combined =
        std::env::temp_dir().join(format!("wpawolf-test-{}-{}.combined", std::process::id(), nanos_unique()));
    let _ = fs::remove_file(&combined);
    let mut cmd = Command::new(&bin);
    cmd.arg("-o").arg(&combined);
    for p in inputs {
        cmd.arg(p);
    }
    let status = cmd.status().expect("spawn wpawolf");
    assert!(status.success(), "wpawolf failed on {inputs:?}");
    fs::read_to_string(&combined).unwrap_or_default()
}

/// Per-call nanosecond suffix so parallel test threads don't share temp paths.
fn nanos_unique() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos())
}

/// Capture wpawolf's stderr (where the stats summary is printed) for one
/// fixture. The combined `-o` sink swallows the hash output; we just want the
/// human-readable counters here.
fn run_wpawolf_capture_stats(input: &Path) -> String {
    let bin = binary_path();
    let combined =
        std::env::temp_dir().join(format!("wpawolf-test-{}-{}.combined", std::process::id(), nanos_unique()));
    let _ = fs::remove_file(&combined);
    let output = Command::new(&bin).arg("-o").arg(&combined).arg(input).output().expect("spawn wpawolf");
    assert!(output.status.success(), "wpawolf failed on {}", input.display());
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn corpus_root_exists() {
    let root = Path::new(CORPUS_ROOT);
    assert!(root.exists(), "missing corpus root -- run wpawolf-fixturegen first");
}

#[test]
fn manifest_is_present() {
    let manifest = Path::new(CORPUS_ROOT).join("ground_truth/manifest.toml");
    assert!(manifest.exists(), "missing ground_truth/manifest.toml");
    let body = fs::read_to_string(&manifest).expect("read manifest");
    assert!(body.contains("[[fixture]]"), "manifest empty");
}

#[test]
fn every_type_fixture_emits_at_least_one_22000_line() {
    let dir = Path::new(CORPUS_ROOT).join("11_types");
    if !dir.exists() {
        return; // Corpus not generated; sibling test catches that.
    }
    for entry in fs::read_dir(&dir).expect("readdir") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|e| e != "pcap" && e != "pcapng") {
            continue;
        }
        let lines = run_wpawolf(&path);
        assert!(!lines.is_empty(), "{} produced no combined-sink output", path.display());
        assert!(lines.contains("WPA*"), "{} output missing WPA*NN* prefix", path.display());
    }
}

#[test]
fn pmkid_site_fixtures_parse_without_crash() {
    let dir = Path::new(CORPUS_ROOT).join("20_pmkid_sites");
    if !dir.exists() {
        return;
    }
    for entry in fs::read_dir(&dir).expect("readdir") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|e| e != "pcap") {
            continue;
        }
        // Just confirm the parser does not crash; PMKID-only fixtures may or
        // may not emit hashes depending on whether the site is currently
        // wired up. Crash-free parsing is the contract here.
        let _ = run_wpawolf(&path);
    }
}

#[test]
fn combo_fixtures_parse_without_crash() {
    let dir = Path::new(CORPUS_ROOT).join("6_combos");
    if !dir.exists() {
        return;
    }
    for entry in fs::read_dir(&dir).expect("readdir") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|e| e != "pcap") {
            continue;
        }
        let _ = run_wpawolf(&path);
    }
}

#[test]
fn edge_fixtures_parse_without_crash() {
    walk_dir_no_crash("edge");
}

#[test]
fn link_layer_fixtures_parse_without_crash() {
    walk_dir_no_crash("link_layers");
}

#[test]
fn container_fixtures_parse_without_crash() {
    walk_dir_no_crash("containers");
}

#[test]
fn link_layer_fixtures_emit_consistent_output() {
    // The link-layer directory carries the same payload wrapped in seven
    // different headers. wpawolf should produce identical hash output for
    // every variant -- any drift is a bug in src/link/{...}.
    let dir = Path::new(CORPUS_ROOT).join("link_layers");
    if !dir.exists() {
        return;
    }
    let outputs: Vec<String> = fs::read_dir(&dir)
        .expect("readdir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pcap"))
        .map(|p| run_wpawolf(&p))
        .collect();
    if outputs.len() < 2 {
        return;
    }
    let baseline = &outputs[0];
    for o in &outputs[1..] {
        assert_eq!(o, baseline, "link-layer outputs diverge -- regression in src/link/*");
    }
}

#[test]
fn container_fixtures_emit_consistent_output() {
    let dir = Path::new(CORPUS_ROOT).join("containers");
    if !dir.exists() {
        return;
    }
    let outputs: Vec<String> = fs::read_dir(&dir)
        .expect("readdir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
            matches!(ext, "pcap" | "pcapng" | "gz")
        })
        .map(|p| run_wpawolf(&p))
        .collect();
    if outputs.len() < 2 {
        return;
    }
    let baseline = &outputs[0];
    for o in &outputs[1..] {
        assert_eq!(o, baseline, "container outputs diverge -- regression in src/input/*");
    }
}

fn walk_dir_no_crash(rel: &str) {
    let dir = Path::new(CORPUS_ROOT).join(rel);
    if !dir.exists() {
        return;
    }
    for entry in fs::read_dir(&dir).expect("readdir") {
        let path = entry.expect("entry").path();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "pcap" | "pcapng" | "gz") {
            continue;
        }
        let _ = run_wpawolf(&path);
    }
}

/// One entry parsed out of `ground_truth/manifest.toml` -- positive +
/// negative emission oracles for a single fixture.
struct ManifestFixture {
    path: PathBuf,
    expected: Vec<String>,
    forbidden: Vec<String>,
}

/// Which TOML array (if any) the manifest parser is currently inside.
enum ManifestSection {
    None,
    Expected,
    Forbidden,
}

/// Hand-rolled TOML fragment iterator: each `[[fixture]]` block in
/// `ground_truth/manifest.toml` is parsed into a `ManifestFixture`.
/// Paired with the manifest writer in `tools/fixturegen/src/main.rs::write_manifest`.
fn parse_manifest_fixtures() -> Vec<ManifestFixture> {
    let path = Path::new(CORPUS_ROOT).join("ground_truth/manifest.toml");
    let Ok(body) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut fixtures = Vec::new();
    let mut current_path: Option<PathBuf> = None;
    let mut current_expected: Vec<String> = Vec::new();
    let mut current_forbidden: Vec<String> = Vec::new();
    let mut section = ManifestSection::None;
    let push =
        |fixtures: &mut Vec<ManifestFixture>, cp: &mut Option<PathBuf>, ce: &mut Vec<String>, cf: &mut Vec<String>| {
            if let Some(p) = cp.take() {
                fixtures.push(ManifestFixture { path: p, expected: std::mem::take(ce), forbidden: std::mem::take(cf) });
            }
        };
    for line in body.lines() {
        let l = line.trim();
        if l == "[[fixture]]" {
            push(&mut fixtures, &mut current_path, &mut current_expected, &mut current_forbidden);
            section = ManifestSection::None;
        } else if let Some(rest) = l.strip_prefix("path = \"") {
            current_path = Some(PathBuf::from(rest.trim_end_matches('"')));
        } else if l.starts_with("expected_hashes") {
            section = ManifestSection::Expected;
        } else if l.starts_with("forbidden_hashes") {
            section = ManifestSection::Forbidden;
        } else if l == "]" {
            section = ManifestSection::None;
        } else if let Some(rest) = l.strip_prefix('"')
            && let Some(prefix) = rest.strip_suffix("\",")
        {
            match section {
                ManifestSection::Expected => current_expected.push(prefix.to_owned()),
                ManifestSection::Forbidden => current_forbidden.push(prefix.to_owned()),
                ManifestSection::None => {},
            }
        }
    }
    push(&mut fixtures, &mut current_path, &mut current_expected, &mut current_forbidden);
    fixtures
}

/// Sentinel-rejection edge fixtures (NULL or all-`0xFF` nonces / PMKIDs / MICs)
/// emit no hash lines by FR-CLI-INVALID-NONCE / FR-CLI-INVALID-PMKID. The
/// existing crash-free oracle (`edge_fixtures_parse_without_crash`) only
/// proves the parser does not panic; it does not prove wpawolf actually
/// recognised the sentinel and incremented the right rejection counter.
/// This test asserts the per-kind rejection counter (`null_nonce_rejected`,
/// `ff_nonce_rejected`, `null_pmkid_rejected`, `ff_pmkid_rejected`) shows
/// up in the stats output for the matching fixture, AND that no hash lines
/// land in the combined sink. Together those two checks make sentinel
/// regressions impossible to slip past CI silently.
#[test]
fn sentinel_rejection_fixtures_increment_their_counter_and_emit_nothing() {
    let cases: &[(&str, &str)] = &[
        ("edge/null_nonce_m1.pcap", "NULL nonce rejected (frame dropped"),
        ("edge/ff_nonce_m1.pcap", "0xFF nonce rejected (frame dropped"),
        ("edge/null_pmkid_kde.pcap", "NULL PMKID rejected (placeholder; PMKID dropped"),
        ("edge/ff_pmkid_kde.pcap", "0xFF PMKID rejected (PMKID dropped"),
    ];

    for (rel, label) in cases {
        let abs = Path::new(CORPUS_ROOT).join(rel);
        if !abs.exists() {
            continue;
        }
        // Combined-sink output must be empty: the sentinel should be rejected
        // before any hash line is written.
        let combined = run_wpawolf(&abs);
        assert!(!combined.contains("WPA*"), "{rel}: sentinel fixture leaked a hash line\n--- combined ---\n{combined}");
        // And the matching rejection counter must increment >= 1.
        let stderr = run_wpawolf_capture_stats(&abs);
        let has_counter = stderr
            .lines()
            .filter(|l| l.contains(label))
            .any(|l| l.split(':').nth(1).is_some_and(|tail| tail.trim().parse::<u64>().unwrap_or(0) >= 1));
        assert!(has_counter, "{rel}: rejection counter `{label}` did not fire\n--- stderr ---\n{stderr}");
    }
}

/// FILS / Mesh PMKIDs do not flow into a hash line because their AKMs are
/// out of wpawolf's PSK-cracking scope (FILS AKMs 14-17 are not in
/// `AkmType`; Mesh entries are stored with `AkmType::Unknown` and dropped
/// by the FR-OUT-3 emit gate). The parser still walks every byte and
/// increments the source-tagged counter (`pmkid_fils_auth`, `pmkid_mesh`
/// in `src/stats.rs`). This test asserts that the matching stats line
/// appears in wpawolf's stderr summary for each non-emitting S-site, which
/// proves the parse path is exercised end-to-end. Without this oracle a
/// regression that silently skipped these frames would only be visible if
/// someone ran the binary by hand.
#[test]
fn non_emitting_s_sites_increment_their_stats_counter() {
    let cases: &[(&str, &str)] = &[
        ("20_pmkid_sites/s07_fils_auth_seq1.pcap", "FILS Authentication (S7/S8, algo=4/5)"),
        ("20_pmkid_sites/s08_fils_auth_seq2.pcap", "FILS Authentication (S7/S8, algo=4/5)"),
        ("20_pmkid_sites/s18_mesh_peering_open.pcap", "Mesh Peering AMPE (S18/S19)"),
        ("20_pmkid_sites/s19_mesh_peering_confirm.pcap", "Mesh Peering AMPE (S18/S19)"),
        // S9 / S10 (PASN) emit a hash line (algo=7 dispatches through
        // `process_auth_pasn` since the §12.13.1 fix), and S20 (OSEN)
        // now emits via beacon-AKM promotion since the OSEN-IE-as-RSN-IE
        // layout fix -- both are covered by the manifest expected-hashes
        // oracle instead.
    ];

    for (rel, label) in cases {
        let abs = Path::new(CORPUS_ROOT).join(rel);
        if !abs.exists() {
            continue;
        }
        let stderr = run_wpawolf_capture_stats(&abs);
        // The label is followed by `: <count>`; both >=1 and any padding
        // amount of dots in between, so we assert on substring presence
        // and a non-zero numeric tail.
        let has_counter = stderr
            .lines()
            .filter(|l| l.contains(label))
            .any(|l| l.split(':').nth(1).is_some_and(|tail| tail.trim().parse::<u64>().unwrap_or(0) >= 1));
        assert!(has_counter, "{rel}: stats counter `{label}` did not increment\n--- stderr ---\n{stderr}");
    }
}

/// `multi_file_a.pcap` carries the Beacon + M1; `multi_file_b.pcap` carries
/// M2 + M3 + M4. Both share the same `(AP, STA)` MAC pair (`IDX_EDGE_MULTI_FILE`
/// in `tools/fixturegen/src/catalog.rs`). When wpawolf processes both files in
/// one invocation, `MessageStore` accumulates all four messages under the same
/// `MacPair` key and Phase 4 pairing fires the full set of N#E# combos --
/// exercising FR-PAIR-CROSS-FILE in `ARCHITECTURE.md §8`.
///
/// File B alone has no Beacon/Probe Response, so the AP's SSID is unresolved
/// and wpawolf drops every uncrackable hash (logging the AP under
/// `[essid_not_found_summary]` in --log instead). The joint A+B run resolves
/// the SSID from file A's Beacon and emits both the M1 PMKID line (`WPA*02*`)
/// and the EAPOL pair line (`WPA*03*`).
#[test]
fn multi_file_pairing_resolves_across_files() {
    let path_a = Path::new(CORPUS_ROOT).join("edge/multi_file_a.pcap");
    let path_b = Path::new(CORPUS_ROOT).join("edge/multi_file_b.pcap");
    if !path_a.exists() || !path_b.exists() {
        return; // Corpus not generated; sibling test catches that.
    }

    let out_alone_a = run_wpawolf(&path_a);
    let out_alone_b = run_wpawolf(&path_b);
    let out_joint = run_wpawolf_multi(&[&path_a, &path_b]);

    // File A in isolation: Beacon supplies the SSID and the M1 carries a PMKID;
    // emit the M1 PMKID line. No EAPOL pair (no M2/M3/M4 in this file).
    assert!(out_alone_a.contains("WPA*02*"), "file A alone should emit the M1 PMKID line");
    assert!(!out_alone_a.contains("WPA*03*"), "file A alone has no M2/M3/M4 -- no EAPOL pair should emit");

    // File B in isolation: no Beacon means no SSID; uncrackable hashes are
    // dropped, so no `WPA*` lines should appear. The cross-file branch below
    // is what makes this AP's hashes recoverable.
    let count_lines = |s: &str| -> usize { s.lines().filter(|l| l.starts_with("WPA*")).count() };
    assert_eq!(
        count_lines(&out_alone_b),
        0,
        "file B alone has no SSID -- every emission must be dropped, not shipped with a NULL ESSID"
    );

    // Joint run: file A's Beacon resolves the SSID for file B's frames, so
    // both the M1 PMKID line and the EAPOL pair line ship.
    assert!(out_joint.contains("WPA*02*"), "joint run missing the M1 PMKID line (cross-file PMKID resolution broke)");
    assert!(out_joint.contains("WPA*03*"), "joint run missing the EAPOL pair line (cross-file pairing broke)");

    // Joint run must produce strictly more lines than file A alone (file B
    // alone produces zero).
    let n_alone_a = count_lines(&out_alone_a);
    let n_joint = count_lines(&out_joint);
    assert!(
        n_joint > n_alone_a,
        "joint run produced {n_joint} lines but file A alone had {n_alone_a}; cross-file pairing should add at least the EAPOL pair line"
    );
}

/// For every fixture whose manifest entry declares `expected_hashes`, run
/// wpawolf in isolation and assert (a) every declared `expected_hashes`
/// prefix appears at least once in the combined-sink output, and (b) every
/// declared `forbidden_hashes` prefix is absent. The first half catches
/// regressions where a classifier drops a type prefix; the second half
/// catches regressions where a sentinel-rejection check is removed or a
/// pairing path leaks a hash from an incomplete fixture (e.g. M1-only).
#[test]
fn manifest_expected_hashes_present_per_fixture() {
    let fixtures = parse_manifest_fixtures();
    if fixtures.is_empty() {
        return; // Corpus not generated; sibling test catches that.
    }
    let mut failures: Vec<String> = Vec::new();
    for f in fixtures {
        if f.expected.is_empty() && f.forbidden.is_empty() {
            continue;
        }
        let abs = Path::new(CORPUS_ROOT).join(&f.path);
        if !abs.exists() {
            continue;
        }
        let out = run_wpawolf(&abs);
        for prefix in &f.expected {
            if !out.contains(prefix) {
                failures.push(format!("{}: missing expected {prefix}", f.path.display()));
            }
        }
        for prefix in &f.forbidden {
            if out.contains(prefix) {
                failures.push(format!("{}: forbidden {prefix} appeared", f.path.display()));
            }
        }
    }
    assert!(failures.is_empty(), "manifest oracle regressions:\n{}", failures.join("\n"));
}
