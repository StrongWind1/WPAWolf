//! Integration test: per-HashType pcapng fixtures.
//!
//! Builds an in-memory pcap (DLT 105 = raw IEEE 802.11) for each of the 11 hash
//! types in `ARCHITECTURE.md §2`, runs wpawolf against the fixture, and asserts
//! the expected `WPA*NN*` line appears in the corresponding taxonomy sink with
//! the correct prefix, MIC width, and ESSID round-trip. The PMKID and MIC
//! values are deterministic non-zero patterns -- wpawolf is a parser, not a
//! verifier, so cryptographic validity is not required to exercise the
//! emission path. The 24-byte MIC tests (types 9 and 11) are the regression
//! oracle for the SHA-384 EAPOL parser fix in `src/ieee80211/eapol.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::fn_params_excessive_bools,
    clippy::doc_markdown,
    clippy::unnecessary_debug_formatting,
    clippy::needless_pass_by_value,
    clippy::redundant_pub_crate,
    clippy::format_push_string,
    missing_docs,
    unused_crate_dependencies,
    reason = "integration test module -- strict lints relaxed"
)]

use std::fs;
use std::path::Path;
use std::process::Command;

// --- Pcap byte builders (DLT 105 raw IEEE 802.11) ---

const DLT_IEEE_802_11: u32 = 105;

fn pcap_global_header() -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&0xA1B2_C3D4_u32.to_le_bytes());
    h[4..6].copy_from_slice(&2_u16.to_le_bytes());
    h[6..8].copy_from_slice(&4_u16.to_le_bytes());
    h[16..20].copy_from_slice(&65535_u32.to_le_bytes());
    h[20..24].copy_from_slice(&DLT_IEEE_802_11.to_le_bytes());
    h
}

fn pcap_packet(ts_sec: u32, ts_usec: u32, data: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(16 + data.len());
    r.extend_from_slice(&ts_sec.to_le_bytes());
    r.extend_from_slice(&ts_usec.to_le_bytes());
    let len = data.len() as u32;
    r.extend_from_slice(&len.to_le_bytes());
    r.extend_from_slice(&len.to_le_bytes());
    r.extend_from_slice(data);
    r
}

// --- 802.11 frame builders ---

const SUBTYPE_BEACON: u8 = 8;
const SUBTYPE_ASSOC_REQ: u8 = 0;
const TYPE_MGMT: u8 = 0;
const TYPE_DATA: u8 = 2;

const AP: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const STA: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

/// Builds a 24-byte 802.11 MAC header for a 3-address frame.
fn mac_hdr(
    ftype: u8,
    subtype: u8,
    to_ds: bool,
    from_ds: bool,
    addr1: [u8; 6],
    addr2: [u8; 6],
    addr3: [u8; 6],
) -> [u8; 24] {
    let mut h = [0u8; 24];
    let mut fc0 = (subtype << 4) | (ftype << 2);
    let _ = &mut fc0;
    h[0] = fc0;
    let mut fc1 = 0u8;
    if to_ds {
        fc1 |= 0x01;
    }
    if from_ds {
        fc1 |= 0x02;
    }
    h[1] = fc1;
    h[4..10].copy_from_slice(&addr1);
    h[10..16].copy_from_slice(&addr2);
    h[16..22].copy_from_slice(&addr3);
    h
}

/// Builds a Beacon frame body containing fixed fields + SSID + RSN IE (or WPA1 vendor IE).
///
/// `akm_byte` is the AKM-suite low byte in the `00:0F:AC` namespace (e.g. 2 for
/// WPA2-PSK, 6 for PSK-SHA256). When `wpa1` is true, omits RSN IE and emits
/// the WPA legacy vendor IE (OUI `00:50:F2` type 1) for type 1 fixtures.
fn build_beacon(ssid: &[u8], akm_byte: u8, wpa1: bool, ft: bool) -> Vec<u8> {
    let mut frame = mac_hdr(TYPE_MGMT, SUBTYPE_BEACON, false, false, [0xFF; 6], AP, AP).to_vec();
    // Fixed fields: Timestamp(8) + BeaconInterval(2) + Capability(2)
    frame.extend_from_slice(&[0u8; 8]);
    frame.extend_from_slice(&100u16.to_le_bytes());
    frame.extend_from_slice(&0x0011u16.to_le_bytes());
    // SSID IE
    frame.push(0); // tag 0
    frame.push(ssid.len() as u8);
    frame.extend_from_slice(ssid);
    // Supported Rates IE (mandatory presence; arbitrary values)
    frame.extend_from_slice(&[1u8, 4, 0x82, 0x84, 0x8B, 0x96]);
    // DS Parameter Set (channel 6)
    frame.extend_from_slice(&[3u8, 1, 6]);
    if ft {
        // MDE (tag 54): 2-byte MDID + 1-byte FT Capability and Policy.
        // [IEEE 802.11-2024] §9.4.2.45
        frame.extend_from_slice(&[54u8, 3, 0x12, 0x34, 0x00]);
    }
    if wpa1 {
        // WPA legacy vendor IE: OUI 00:50:F2 type 1 with PSK AKM.
        // Body: OUI(3) + type(1) + version(2 LE) + GroupCipher(4) + PwCount(2 LE)+Suite(4) +
        //       AkmCount(2 LE)+Suite(4)
        let mut wpa_body: Vec<u8> = Vec::new();
        wpa_body.extend_from_slice(&[0x00, 0x50, 0xF2, 0x01]); // OUI + type
        wpa_body.extend_from_slice(&1u16.to_le_bytes()); // WPA version
        wpa_body.extend_from_slice(&[0x00, 0x50, 0xF2, 0x02]); // group: TKIP
        wpa_body.extend_from_slice(&1u16.to_le_bytes());
        wpa_body.extend_from_slice(&[0x00, 0x50, 0xF2, 0x02]); // pairwise: TKIP
        wpa_body.extend_from_slice(&1u16.to_le_bytes());
        wpa_body.extend_from_slice(&[0x00, 0x50, 0xF2, 0x02]); // AKM: PSK (WPA1)
        frame.push(221); // tag 221 vendor
        frame.push(wpa_body.len() as u8);
        frame.extend_from_slice(&wpa_body);
    } else {
        // RSN IE (tag 48) with the requested AKM byte.
        // Version(2) + GroupCipher(4) + PwCount(2)+Suite(4) + AkmCount(2)+Suite(4) + RsnCaps(2)
        let mut rsn: Vec<u8> = Vec::new();
        rsn.extend_from_slice(&1u16.to_le_bytes()); // version
        rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // group: CCMP
        rsn.extend_from_slice(&1u16.to_le_bytes());
        rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // pairwise CCMP
        rsn.extend_from_slice(&1u16.to_le_bytes());
        rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, akm_byte]); // AKM
        rsn.extend_from_slice(&[0x00, 0x00]); // RSN caps
        frame.push(48u8);
        frame.push(rsn.len() as u8);
        frame.extend_from_slice(&rsn);
    }
    frame
}

/// Builds an LLC/SNAP + EAPOL-Key frame body with 16-byte MIC.
///
/// `key_ack`/`install`/`mic_flag`/`secure` set the corresponding Key Information bits.
/// `kdv` is the Key Descriptor Version (1, 2, 3, or 0 for AKM-defined).
fn eapol_key_16(
    kdv: u8,
    key_ack: bool,
    install: bool,
    mic_flag: bool,
    secure: bool,
    nonce: [u8; 32],
    mic: [u8; 16],
    key_data_extra: &[u8],
) -> Vec<u8> {
    let mut body = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];
    body.push(0x02); // proto ver
    body.push(0x03); // EAPOL-Key
    let kd_len = key_data_extra.len() as u16;
    body.extend_from_slice(&(95u16 + kd_len).to_be_bytes()); // body length
    body.push(0x02); // RSN descriptor
    let mut ki = u16::from(kdv);
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
    body.extend_from_slice(&kd_len.to_be_bytes());
    body.extend_from_slice(key_data_extra);
    body
}

/// Builds an LLC/SNAP + EAPOL-Key frame body with 24-byte MIC (SHA-384 family).
fn eapol_key_24(
    kdv: u8,
    key_ack: bool,
    install: bool,
    mic_flag: bool,
    secure: bool,
    nonce: [u8; 32],
    mic: [u8; 24],
    key_data_extra: &[u8],
) -> Vec<u8> {
    let mut body = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];
    body.push(0x02);
    body.push(0x03);
    let kd_len = key_data_extra.len() as u16;
    body.extend_from_slice(&(103u16 + kd_len).to_be_bytes()); // 95 + 8 (extra MIC bytes) + kd_len
    body.push(0x02);
    let mut ki = u16::from(kdv);
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
    body.extend_from_slice(&[0x00, 0x10]);
    body.extend_from_slice(&[0u8; 8]);
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&[0u8; 16]);
    body.extend_from_slice(&[0u8; 8]);
    body.extend_from_slice(&[0u8; 8]);
    body.extend_from_slice(&mic);
    body.extend_from_slice(&kd_len.to_be_bytes());
    body.extend_from_slice(key_data_extra);
    body
}

/// Wraps an LLC/SNAP+EAPOL-Key body in an 802.11 Data frame from STA->AP (uplink).
fn data_frame_uplink(body: &[u8]) -> Vec<u8> {
    let mut frame = mac_hdr(TYPE_DATA, 0, true, false, AP, STA, AP).to_vec();
    frame.extend_from_slice(body);
    frame
}

/// Wraps an LLC/SNAP+EAPOL-Key body in an 802.11 Data frame from AP->STA (downlink).
fn data_frame_downlink(body: &[u8]) -> Vec<u8> {
    let mut frame = mac_hdr(TYPE_DATA, 0, false, true, STA, AP, AP).to_vec();
    frame.extend_from_slice(body);
    frame
}

/// PMKID KDE: type=0xDD, len=0x14, OUI 00:0F:AC, sub-type 0x04, 16-byte PMKID.
fn pmkid_kde(pmkid: &[u8; 16]) -> Vec<u8> {
    let mut kde = vec![0xDD, 0x14, 0x00, 0x0F, 0xAC, 0x04];
    kde.extend_from_slice(pmkid);
    kde
}

/// RSN IE bytes for inclusion in M2 Key Data, with the requested AKM and one PMKID.
fn rsn_ie_m2(akm_byte: u8, pmkid: Option<&[u8; 16]>) -> Vec<u8> {
    let mut value: Vec<u8> = Vec::new();
    value.extend_from_slice(&1u16.to_le_bytes());
    value.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]);
    value.extend_from_slice(&1u16.to_le_bytes());
    value.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]);
    value.extend_from_slice(&1u16.to_le_bytes());
    value.extend_from_slice(&[0x00, 0x0F, 0xAC, akm_byte]);
    value.extend_from_slice(&[0x00, 0x00]); // RSN caps
    if let Some(p) = pmkid {
        value.extend_from_slice(&1u16.to_le_bytes()); // PMKID Count
        value.extend_from_slice(p);
    }
    let mut ie = vec![48u8, value.len() as u8];
    ie.extend_from_slice(&value);
    ie
}

/// Builds an Association Request frame body with RSN IE (carrying one PMKID), MDE, and FTE.
///
/// Used for the FT-PSK PMKID fixtures (types 6 and 10): the AssocReq frame is the
/// canonical S3 PMKID source, and `extract/assoc.rs` attaches the parsed FT fields
/// (MDID + R0KH-ID + R1KH-ID) to the stored `PmkidEntry` so the WPA*06*/WPA*10*
/// emission gates pass.
fn build_assoc_req(akm_byte: u8) -> Vec<u8> {
    // Mgmt Assoc Request: ToDS=0, FromDS=0, BSSID=Addr3=AP, SA=Addr2=STA, DA=Addr1=AP.
    let mut frame = mac_hdr(TYPE_MGMT, SUBTYPE_ASSOC_REQ, false, false, AP, STA, AP).to_vec();
    // Fixed fields: Capability(2) + ListenInterval(2)
    frame.extend_from_slice(&0x0011u16.to_le_bytes());
    frame.extend_from_slice(&100u16.to_le_bytes());
    // SSID IE
    frame.push(0);
    frame.push(SSID.len() as u8);
    frame.extend_from_slice(SSID);
    // RSN IE with PMKID
    frame.extend_from_slice(&rsn_ie_m2(akm_byte, Some(&PMKID)));
    // MDE + FTE
    frame.extend_from_slice(&mde_fte());
    frame
}

/// MDE + FTE (with R0KH-ID and R1KH-ID subelements) for FT M2 Key Data.
fn mde_fte() -> Vec<u8> {
    // MDE tag 54: MDID(2) + FT Capability(1)
    let mut out = vec![54u8, 3, 0x12, 0x34, 0x00];
    // FTE tag 55: minimal valid FTE with R1KH-ID subelement (id=1, len=6) and
    // R0KH-ID subelement (id=3, len=N). Per [IEEE 802.11-2024] §9.4.2.46 the
    // FTE has a fixed 82/90-byte header followed by subelements; we synthesise
    // the minimum: MIC Control(2) + MIC(16 or 24) + ANonce(32) + SNonce(32) + subes.
    let mut fte = Vec::new();
    fte.extend_from_slice(&[0u8; 2]); // MIC Control
    fte.extend_from_slice(&[0u8; 16]); // MIC (16-byte form for simplicity)
    fte.extend_from_slice(&[0u8; 32]); // ANonce
    fte.extend_from_slice(&[0u8; 32]); // SNonce
    // R1KH-ID subelement: id=1, len=6, 6 bytes
    fte.extend_from_slice(&[1u8, 6]);
    fte.extend_from_slice(&AP);
    // R0KH-ID subelement: id=3, len=8 ASCII
    fte.extend_from_slice(&[3u8, 8]);
    fte.extend_from_slice(b"r0khtest");
    out.push(55);
    out.push(fte.len() as u8);
    out.extend_from_slice(&fte);
    out
}

// --- Test runner ---

fn write_pcap(path: &Path, frames: &[Vec<u8>]) {
    let mut buf = pcap_global_header().to_vec();
    for (i, f) in frames.iter().enumerate() {
        buf.extend_from_slice(&pcap_packet(1_000_000 + i as u32, 0, f));
    }
    fs::write(path, &buf).expect("write fixture pcap");
}

fn binary_path() -> std::path::PathBuf {
    // CARGO_BIN_EXE_wpawolf is set by cargo when integration tests build the bin.
    let p = std::env::var("CARGO_BIN_EXE_wpawolf").expect("CARGO_BIN_EXE_wpawolf");
    std::path::PathBuf::from(p)
}

/// Runs wpawolf against `pcap_path` with the given output flags and returns the
/// contents of the file specified by `out_flag`.
fn run_wpawolf(pcap_path: &Path, out_flag: &str, out_path: &Path) -> String {
    let status = Command::new(binary_path()).arg(out_flag).arg(out_path).arg(pcap_path).status().expect("run wpawolf");
    assert!(status.success(), "wpawolf exited non-zero on {pcap_path:?}");
    fs::read_to_string(out_path).expect("read output")
}

const SSID: &[u8] = b"WPAWolfFixture";
const PMKID: [u8; 16] =
    [0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0];
// Non-uniform fixtures: the EAPOL parser rejects uniform-byte nonces and MICs
// (`[0xB0; 32]` flags as `repeat_1`). Real wire bytes are HMAC outputs / random
// nonces; the per-element fixtures below mirror that shape while keeping each
// side identifiable by its leading byte.
const NONCE_AP: [u8; 32] = [
    0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xA0, 0xA1, 0xA2,
    0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
];
const NONCE_STA: [u8; 32] = [
    0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2,
    0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
];
const MIC16: [u8; 16] =
    [0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F];
const MIC24: [u8; 24] = [
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2,
    0xF3, 0xF4, 0xF5, 0xF6, 0xF7,
];

/// Builds the M1+M2+M3+M4 sequence with a 16-byte MIC for the given KDV.
fn handshake_4_way_16(kdv: u8, m2_key_data: &[u8]) -> Vec<Vec<u8>> {
    let m1 = data_frame_downlink(&eapol_key_16(kdv, true, false, false, false, NONCE_AP, [0u8; 16], &[]));
    let m2 = data_frame_uplink(&eapol_key_16(kdv, false, false, true, false, NONCE_STA, MIC16, m2_key_data));
    let m3 = data_frame_downlink(&eapol_key_16(kdv, true, true, true, true, NONCE_AP, MIC16, &[]));
    let m4 = data_frame_uplink(&eapol_key_16(kdv, false, false, true, true, NONCE_STA, MIC16, &[]));
    vec![m1, m2, m3, m4]
}

/// Builds the M1+M2+M3+M4 sequence with a 24-byte MIC (SHA-384 family).
fn handshake_4_way_24(m2_key_data: &[u8]) -> Vec<Vec<u8>> {
    // SHA-384 family uses KDV=0 (AKM-defined). [IEEE 802.11-2024] Table 12-9
    let m1 = data_frame_downlink(&eapol_key_24(0, true, false, false, false, NONCE_AP, [0u8; 24], &[]));
    let m2 = data_frame_uplink(&eapol_key_24(0, false, false, true, false, NONCE_STA, MIC24, m2_key_data));
    let m3 = data_frame_downlink(&eapol_key_24(0, true, true, true, true, NONCE_AP, MIC24, &[]));
    let m4 = data_frame_uplink(&eapol_key_24(0, false, false, true, true, NONCE_STA, MIC24, &[]));
    vec![m1, m2, m3, m4]
}

fn temp_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("wpawolf_per_type_fixtures");
    fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

/// Convenience: builds a fixture, runs wpawolf, asserts at least one line with the expected prefix.
fn assert_fixture_emits(test_name: &str, frames: Vec<Vec<u8>>, out_flag: &str, expected_prefix: &str) -> String {
    let pcap = temp_path(&format!("{test_name}.pcap"));
    let out = temp_path(&format!("{test_name}.out"));
    write_pcap(&pcap, &frames);
    let contents = run_wpawolf(&pcap, out_flag, &out);
    assert!(
        contents.lines().any(|l| l.starts_with(expected_prefix)),
        "no line starting with {expected_prefix:?} in {out_flag} output for {test_name}; got:\n{contents}"
    );
    contents
}

// --- Type 1: WPA1-PSK-EAPOL ---

#[test]
fn type_01_wpa1_psk_eapol() {
    let beacon = build_beacon(SSID, 2 /* ignored */, true, false);
    let mut frames = vec![beacon];
    frames.extend(handshake_4_way_16(1, &[]));
    let contents = assert_fixture_emits("type_01", frames, "--wpa1-out", "WPA*01*");
    let line = contents.lines().find(|l| l.starts_with("WPA*01*")).unwrap();
    let fields: Vec<&str> = line.split('*').collect();
    // WPA*01* + MIC + AP + STA + ESSID + NONCE + EAPOL + MP = 9 fields.
    assert_eq!(fields.len(), 9, "type 1 line must have 9 fields: {line}");
    assert_eq!(fields[2].len(), 32, "type 1 MIC must be 16 B = 32 hex chars");
    assert_eq!(fields[5], hex::encode_essid(SSID));
}

// --- Type 2: WPA2-PSK-PMKID ---

#[test]
fn type_02_wpa2_psk_pmkid() {
    let beacon = build_beacon(SSID, 2, false, false);
    // M1 with PMKID KDE; AKM detected from beacon RSN IE = AKM 2 -> Wpa2Psk.
    let m1 = data_frame_downlink(&eapol_key_16(2, true, false, false, false, NONCE_AP, [0u8; 16], &pmkid_kde(&PMKID)));
    let frames = vec![beacon, m1];
    let contents = assert_fixture_emits("type_02", frames, "--wpa2-out", "WPA*02*");
    let line = contents.lines().find(|l| l.starts_with("WPA*02*")).unwrap();
    let fields: Vec<&str> = line.split('*').collect();
    assert!(fields.len() >= 6);
    assert_eq!(fields[2].len(), 32, "PMKID is 16 B = 32 hex chars");
    assert!(fields[2].chars().all(|c| c.is_ascii_hexdigit()));
}

// --- Type 3: WPA2-PSK-EAPOL ---

#[test]
fn type_03_wpa2_psk_eapol() {
    let beacon = build_beacon(SSID, 2, false, false);
    let mut frames = vec![beacon];
    frames.extend(handshake_4_way_16(2, &rsn_ie_m2(2, None)));
    let _ = assert_fixture_emits("type_03", frames, "--wpa2-out", "WPA*03*");
}

// --- Type 4: PSK-SHA256-PMKID ---

#[test]
fn type_04_psk_sha256_pmkid() {
    let beacon = build_beacon(SSID, 6, false, false);
    let m1 = data_frame_downlink(&eapol_key_16(3, true, false, false, false, NONCE_AP, [0u8; 16], &pmkid_kde(&PMKID)));
    let frames = vec![beacon, m1];
    let _ = assert_fixture_emits("type_04", frames, "--psk-sha256-out", "WPA*04*");
}

// --- Type 5: PSK-SHA256-EAPOL ---

#[test]
fn type_05_psk_sha256_eapol() {
    let beacon = build_beacon(SSID, 6, false, false);
    let mut frames = vec![beacon];
    frames.extend(handshake_4_way_16(3, &rsn_ie_m2(6, None)));
    let _ = assert_fixture_emits("type_05", frames, "--psk-sha256-out", "WPA*05*");
}

// --- Type 6: FT-PSK-PMKID ---

#[test]
fn type_06_ft_psk_pmkid() {
    // Beacon advertises FT-PSK (AKM 4) so the AKM map carries FtPsk for the AP.
    // AssocReq carries PMKID + MDE + FTE in tagged params (S3 source); the
    // PmkidEntry is stored with FT context attached, satisfying the FR-OUT-3
    // emission gate (MDID + R0KH-ID + R1KH-ID required).
    let beacon = build_beacon(SSID, 4, false, true);
    let assoc = build_assoc_req(4);
    let frames = vec![beacon, assoc];
    let _ = assert_fixture_emits("type_06", frames, "--ft-out", "WPA*06*");
}

// --- Type 7: FT-PSK-EAPOL ---

#[test]
fn type_07_ft_psk_eapol() {
    let beacon = build_beacon(SSID, 4, false, true);
    let mut m2_kd = rsn_ie_m2(4, None);
    m2_kd.extend_from_slice(&mde_fte());
    let m1 = data_frame_downlink(&eapol_key_16(2, true, false, false, false, NONCE_AP, [0u8; 16], &mde_fte()));
    let m2 = data_frame_uplink(&eapol_key_16(2, false, false, true, false, NONCE_STA, MIC16, &m2_kd));
    let m3 = data_frame_downlink(&eapol_key_16(2, true, true, true, true, NONCE_AP, MIC16, &[]));
    let m4 = data_frame_uplink(&eapol_key_16(2, false, false, true, true, NONCE_STA, MIC16, &[]));
    let frames = vec![beacon, m1, m2, m3, m4];
    let _ = assert_fixture_emits("type_07", frames, "--ft-out", "WPA*07*");
}

// --- Type 8: PSK-SHA384-PMKID ---

#[test]
fn type_08_psk_sha384_pmkid() {
    let beacon = build_beacon(SSID, 20, false, false);
    // M1 with 24-B MIC (SHA-384), KDV=0, plus PMKID KDE.
    let m1 = data_frame_downlink(&eapol_key_24(0, true, false, false, false, NONCE_AP, [0u8; 24], &pmkid_kde(&PMKID)));
    let frames = vec![beacon, m1];
    let _ = assert_fixture_emits("type_08", frames, "--psk-sha384-out", "WPA*08*");
}

// --- Type 9: PSK-SHA384-EAPOL (the SHA-384 24-B MIC fix regression oracle) ---

#[test]
fn type_09_psk_sha384_eapol() {
    let beacon = build_beacon(SSID, 20, false, false);
    let mut frames = vec![beacon];
    frames.extend(handshake_4_way_24(&rsn_ie_m2(20, None)));
    let contents = assert_fixture_emits("type_09", frames, "--psk-sha384-out", "WPA*09*");
    let line = contents.lines().find(|l| l.starts_with("WPA*09*")).unwrap();
    let fields: Vec<&str> = line.split('*').collect();
    // For SHA-384 the MIC field must be 48 hex chars (24 B). This is the headline
    // regression: pre-fix the parser truncated to 16 B and emitted 32 hex chars.
    assert_eq!(fields[2].len(), 48, "SHA-384 MIC must be 24 B = 48 hex chars: {line}");
    // And the EAPOL frame field's MIC window must be all-zero across 24 B (offset
    // 162..210 in hex) -- not just 32 chars.
    let eapol_hex = fields[7];
    assert!(
        eapol_hex.len() >= 210,
        "SHA-384 EAPOL frame must be at least 105 bytes = 210 hex chars: got {} chars",
        eapol_hex.len()
    );
    let mic_window = &eapol_hex[162..210];
    assert!(mic_window.chars().all(|c| c == '0'), "24-B MIC window in EAPOL field must be zeroed");
}

// --- Type 10: FT-PSK-SHA384-PMKID ---

#[test]
fn type_10_ft_psk_sha384_pmkid() {
    // Same shape as type 6, with AKM 19 (FT-PSK-SHA384) on the beacon and AssocReq.
    let beacon = build_beacon(SSID, 19, false, true);
    let assoc = build_assoc_req(19);
    let frames = vec![beacon, assoc];
    let _ = assert_fixture_emits("type_10", frames, "--ft-psk-sha384-out", "WPA*10*");
}

// --- Type 11: FT-PSK-SHA384-EAPOL ---

#[test]
fn type_11_ft_psk_sha384_eapol() {
    let beacon = build_beacon(SSID, 19, false, true);
    let mut m2_kd = rsn_ie_m2(19, None);
    m2_kd.extend_from_slice(&mde_fte());
    let m1 = data_frame_downlink(&eapol_key_24(0, true, false, false, false, NONCE_AP, [0u8; 24], &mde_fte()));
    let m2 = data_frame_uplink(&eapol_key_24(0, false, false, true, false, NONCE_STA, MIC24, &m2_kd));
    let m3 = data_frame_downlink(&eapol_key_24(0, true, true, true, true, NONCE_AP, MIC24, &[]));
    let m4 = data_frame_uplink(&eapol_key_24(0, false, false, true, true, NONCE_STA, MIC24, &[]));
    let frames = vec![beacon, m1, m2, m3, m4];
    let contents = assert_fixture_emits("type_11", frames, "--ft-psk-sha384-out", "WPA*11*");
    let line = contents.lines().find(|l| l.starts_with("WPA*11*")).unwrap();
    let fields: Vec<&str> = line.split('*').collect();
    assert_eq!(fields[2].len(), 48, "FT SHA-384 MIC must be 24 B = 48 hex chars: {line}");
}

// --- Helpers ---

mod hex {
    pub(super) fn encode_essid(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}
