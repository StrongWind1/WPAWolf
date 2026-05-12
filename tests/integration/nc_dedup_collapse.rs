//! Integration test: `--nc-dedup` collapses a 26-element near-identical-nonce cluster.
//!
//! Synthesises a WPA2-PSK fixture mimicking the shape Mike reported on the
//! hcxtools mailing list: many WPA*02* lines for one (AP, STA) that share the
//! same EAPOL frame and MIC and differ only in the trailing byte of the
//! `ANonce`. 26 M1 frames are emitted (each carrying a distinct trailing-byte
//! `ANonce` 0x4D..=0x66) followed by a single M2 that pairs with all of them.
//! The pairing engine produces 26 N1E2 lines without `--nc-dedup`; with
//! `--nc-dedup` the clustering pass collapses the 26 to exactly 3 survivors
//! (cluster sizes 9, 9, 8 at the default `--nc-tolerance=8`).
//!
//! Three assertions pin the contract:
//!   * Default (no flag) -> 26 lines, byte-for-byte regression-proofs the
//!     opt-in.
//!   * `--nc-dedup` -> 3 lines with `FLAG_NC` set on each survivor.
//!   * `--nc-dedup --nc-tolerance=4` -> 6 lines (the tighter span forces more
//!     cluster splits), confirming the tolerance knob takes effect.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::similar_names,
    clippy::cast_possible_truncation,
    clippy::fn_params_excessive_bools,
    missing_docs,
    unused_crate_dependencies,
    reason = "integration test module -- strict lints relaxed; eapol_key_body mirrors the 4-bool EAPOL Key Info layout"
)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

// --- Inline 802.11 frame builders (mirror the private helpers in common.rs) ---

const TYPE_MGMT: u8 = 0;
const TYPE_DATA: u8 = 2;
const SUBTYPE_BEACON: u8 = 8;
const SUBTYPE_DATA: u8 = 0;
const BCAST: [u8; 6] = [0xFF; 6];

/// Builds a 24-byte 3-address 802.11 MAC header.
fn mac_hdr_3addr(ftype: u8, subtype: u8, to_ds: bool, from_ds: bool, a1: [u8; 6], a2: [u8; 6], a3: [u8; 6]) -> Vec<u8> {
    let mut fc = [0u8; 2];
    fc[0] = (subtype << 4) | (ftype << 2);
    if to_ds {
        fc[1] |= 0x01;
    }
    if from_ds {
        fc[1] |= 0x02;
    }
    let mut h = Vec::with_capacity(24);
    h.extend_from_slice(&fc);
    h.extend_from_slice(&[0u8; 2]); // Duration
    h.extend_from_slice(&a1);
    h.extend_from_slice(&a2);
    h.extend_from_slice(&a3);
    h.extend_from_slice(&[0u8; 2]); // Sequence Control
    h
}

/// Beacon body advertising AKM 2 (WPA2-PSK) with a single SSID + CCMP.
fn beacon_wpa2_psk(ssid: &[u8], ap: [u8; 6]) -> Vec<u8> {
    let mut frame = mac_hdr_3addr(TYPE_MGMT, SUBTYPE_BEACON, false, false, BCAST, ap, ap);
    frame.extend_from_slice(&[0u8; 8]); // Timestamp
    frame.extend_from_slice(&100_u16.to_le_bytes()); // Beacon interval
    frame.extend_from_slice(&0x0011_u16.to_le_bytes()); // Capability info
    // SSID (tag 0)
    frame.push(0);
    frame.push(ssid.len() as u8);
    frame.extend_from_slice(ssid);
    // Supported Rates (tag 1)
    frame.extend_from_slice(&[1u8, 4, 0x82, 0x84, 0x8B, 0x96]);
    // DS Parameter Set (tag 3) channel 6
    frame.extend_from_slice(&[3u8, 1, 6]);
    // RSN IE (tag 48) AKM 2 + CCMP.
    frame.push(48);
    let mut rsn: Vec<u8> = Vec::new();
    rsn.extend_from_slice(&1_u16.to_le_bytes());
    rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // group: CCMP
    rsn.extend_from_slice(&1_u16.to_le_bytes());
    rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // pairwise: CCMP
    rsn.extend_from_slice(&1_u16.to_le_bytes());
    rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x02]); // AKM 2 = WPA2-PSK
    rsn.extend_from_slice(&[0x00, 0x00]); // RSN caps
    frame.push(rsn.len() as u8);
    frame.extend_from_slice(&rsn);
    frame
}

/// LLC/SNAP + EAPOL-Key body for WPA2-PSK (KDV=2, 16-byte MIC).
fn eapol_key_body(
    key_ack: bool,
    install: bool,
    mic_flag: bool,
    secure: bool,
    nonce: [u8; 32],
    mic: [u8; 16],
) -> Vec<u8> {
    let mut body = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];
    body.push(0x02); // EAPOL proto ver
    body.push(0x03); // Packet Type: EAPOL-Key
    body.extend_from_slice(&95u16.to_be_bytes()); // body length (no Key Data)
    body.push(0x02); // descriptor type: RSN
    let mut ki = 2u16; // KDV=2 = HMAC-SHA1 (WPA2-PSK)
    if install {
        ki |= 1 << 6;
    }
    if key_ack {
        ki |= 1 << 7;
    }
    if mic_flag {
        ki |= 1 << 8;
    }
    if secure {
        ki |= 1 << 9;
    }
    body.extend_from_slice(&ki.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x10]); // Key Length
    body.extend_from_slice(&[0u8; 8]); // Replay Counter
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&[0u8; 16]); // Key IV
    body.extend_from_slice(&[0u8; 8]); // Key RSC
    body.extend_from_slice(&[0u8; 8]); // Reserved
    body.extend_from_slice(&mic);
    body.extend_from_slice(&[0u8, 0u8]); // Key Data Length = 0
    body
}

/// Downlink data frame (AP -> STA): To DS=0, From DS=1.
fn data_frame_dl(ap: [u8; 6], sta: [u8; 6], body: &[u8]) -> Vec<u8> {
    let mut frame = mac_hdr_3addr(TYPE_DATA, SUBTYPE_DATA, false, true, sta, ap, ap);
    frame.extend_from_slice(body);
    frame
}

/// Uplink data frame (STA -> AP): To DS=1, From DS=0.
fn data_frame_ul(ap: [u8; 6], sta: [u8; 6], body: &[u8]) -> Vec<u8> {
    let mut frame = mac_hdr_3addr(TYPE_DATA, SUBTYPE_DATA, true, false, ap, sta, ap);
    frame.extend_from_slice(body);
    frame
}

/// Per Mike's reported shape: 26 M1 frames where the `ANonce` trailing byte
/// cycles 0x4D..=0x66 (26 values, all sharing the first 28 bytes), followed
/// by a single M2 with a fixed `SNonce`. Spans 26 -> three clusters of sizes
/// 9, 9, 8 at default `--nc-tolerance=8`.
fn build_nc_cluster_pcap() -> Vec<u8> {
    let ap: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let sta: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let ssid = b"WolfClusterNet";

    // ANonce: 28 fixed bytes (varied for entropy so it isn't garbage-rejected) +
    // [0x00, 0x00, 0x00, tail_byte]. Trailing-byte sweep = the cluster axis.
    let anonce_prefix: [u8; 28] = [
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1,
        0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB,
    ];
    let snonce: [u8; 32] = [
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1,
        0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
    ];
    let mic = [0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F];

    let mut buf = common::pcap_global_header().to_vec();
    let mut ts: u32 = 1_000_000;

    // Beacon: AP advertises the SSID so wpawolf can resolve it for hash output.
    buf.extend_from_slice(&common::pcap_packet(ts, &beacon_wpa2_psk(ssid, ap)));
    ts += 1;

    // 26 M1 variants with cycling trailing nonce byte.
    for tail in 0x4Du8..=0x66 {
        let mut nonce = [0u8; 32];
        nonce[..28].copy_from_slice(&anonce_prefix);
        nonce[28] = 0x00;
        nonce[29] = 0x00;
        nonce[30] = 0x00;
        nonce[31] = tail;
        let m1_body = eapol_key_body(true, false, false, false, nonce, [0u8; 16]);
        let m1 = data_frame_dl(ap, sta, &m1_body);
        buf.extend_from_slice(&common::pcap_packet(ts, &m1));
        ts += 1;
    }

    // One M2 to produce N1E2 pairs.
    let m2_body = eapol_key_body(false, false, true, false, snonce, mic);
    let m2 = data_frame_ul(ap, sta, &m2_body);
    buf.extend_from_slice(&common::pcap_packet(ts, &m2));

    buf
}

/// Runs wpawolf on `input_path` with `extra_args` and returns the number of
/// non-empty lines in the produced `--22000-out` file.
fn run_and_count(input_path: &Path, out_path: &Path, extra_args: &[&str]) -> usize {
    let _ = fs::remove_file(out_path);
    let mut args: Vec<&str> = vec!["--22000-out", out_path.to_str().unwrap()];
    args.extend_from_slice(extra_args);
    let input_str = input_path.to_str().unwrap();
    args.push(input_str);
    let status = Command::new(common::binary_path()).args(&args).status().expect("spawn wpawolf");
    assert!(status.success(), "wpawolf exited non-zero with args {extra_args:?}");
    fs::read_to_string(out_path).expect("read 22000 output").lines().filter(|l| !l.is_empty()).count()
}

fn fixture_paths(name: &str) -> (PathBuf, PathBuf) {
    let dir = common::temp_dir("wpawolf_nc_dedup_collapse");
    (dir.join(format!("{name}.pcap")), dir.join(format!("{name}.22000")))
}

#[test]
fn nc_dedup_off_emits_every_observed_nonce() {
    let (pcap, out) = fixture_paths("default");
    fs::write(&pcap, build_nc_cluster_pcap()).unwrap();
    let lines = run_and_count(&pcap, &out, &[]);
    assert_eq!(lines, 26, "26 distinct nonces must yield 26 N1E2 lines without --nc-dedup");
}

#[test]
fn nc_dedup_collapses_26_nonces_to_three_survivors() {
    let (pcap, out) = fixture_paths("with_flag");
    fs::write(&pcap, build_nc_cluster_pcap()).unwrap();
    let lines = run_and_count(&pcap, &out, &["--nc-dedup"]);
    assert_eq!(lines, 3, "26 sequential nonces span 0x19 -> three clusters of 9, 9, 8 at tolerance=8");

    // Each survivor must carry FLAG_NC (0x80) | FLAG_LE (0x20) in the
    // message_pair byte (field 9 of the WPA*02* line).
    let text = fs::read_to_string(&out).unwrap();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let fields: Vec<&str> = line.split('*').collect();
        let mp_hex = fields.get(8).expect("WPA*02*line has at least 9 *-separated fields");
        let mp_byte = u8::from_str_radix(mp_hex, 16).expect("message_pair is two hex digits");
        assert_eq!(mp_byte & 0x80, 0x80, "every nc-dedup survivor must carry FLAG_NC: {line}");
        assert_eq!(mp_byte & 0x20, 0x20, "every nc-dedup survivor must carry FLAG_LE: {line}");
    }
}

#[test]
fn nc_tolerance_tighter_value_splits_into_more_clusters() {
    // Tolerance=4 forces each cluster's max-min span to <= 4 instead of <= 8.
    // 26 elements 0x4D..=0x66 (span 0x19=25) split into clusters of 5 (start
    // 0x4D, 0x52, 0x57, 0x5C, 0x61) plus a 6th of 2 elements (0x66, but with
    // span tolerance 4 only 0x62..=0x66 fits in a single tail cluster). The
    // exact count depends on the greedy split: starting at 0x4D, clusters
    // of 5 form at 0x4D-0x51, 0x52-0x56, 0x57-0x5B, 0x5C-0x60, 0x61-0x65,
    // singleton 0x66 -- 5 survivors + 1 singleton = 6 lines.
    let (pcap, out) = fixture_paths("tolerance_4");
    fs::write(&pcap, build_nc_cluster_pcap()).unwrap();
    let lines = run_and_count(&pcap, &out, &["--nc-dedup", "--nc-tolerance=4"]);
    assert_eq!(lines, 6, "tolerance=4 produces 5 cluster survivors + 1 isolated singleton");
}
