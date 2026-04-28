//! Integration test: every plaintext extraction surface is exercised end-to-end.
//!
//! Builds a single in-memory DLT 105 pcap whose lone Beacon frame carries every
//! supported plaintext IE listed in `ARCHITECTURE.md §9.3` "Plaintext extraction
//! surfaces": SSID, SSID List (tag 84), Mesh ID (tag 114), Country (tag 7), Time
//! Zone (tag 98), WPS device info (OUI `00:50:F2` type 4), OWE Transition SSID
//! (OUI `50:6F:9A` type 28), Cisco CCX1 AP name (tag 133), Aruba vendor AP name
//! (tag 221, OUI `00:0B:86` subtype 3), Multiple BSSID profile (tag 71), Reduced
//! Neighbor Report BSSID (tag 201), and Wi-Fi Direct (P2P) device name (OUI
//! `50:6F:9A` type 9). Runs wpawolf with `-E`, `-W`, `-D` pointed at temp paths
//! and asserts each expected string lands in the correct sink. This is the
//! regression oracle that pins all 12 IE-driven plaintext surfaces against
//! silent removal during refactors.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::format_push_string,
    clippy::format_collect,
    missing_docs,
    unused_crate_dependencies,
    reason = "integration test module -- strict lints relaxed"
)]

use std::fs;
use std::path::Path;
use std::process::Command;

// --- DLT 105 pcap byte builders ---

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

fn pcap_packet(ts_sec: u32, data: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(16 + data.len());
    r.extend_from_slice(&ts_sec.to_le_bytes());
    r.extend_from_slice(&0_u32.to_le_bytes());
    let len = data.len() as u32;
    r.extend_from_slice(&len.to_le_bytes());
    r.extend_from_slice(&len.to_le_bytes());
    r.extend_from_slice(data);
    r
}

// --- 802.11 Beacon builder with the kitchen-sink IE set ---

const SUBTYPE_BEACON: u8 = 8;
const TYPE_MGMT: u8 = 0;
const AP: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const BCAST: [u8; 6] = [0xFF; 6];

const SSID: &[u8] = b"WolfPrimary";
const SSID_LIST_ENTRY: &[u8] = b"WolfListed";
const MESH_ID: &[u8] = b"MeshHomestead";
const COUNTRY: [u8; 2] = *b"DE";
const TIME_ZONE: &[u8] = b"CET-1CEST,M3.5.0,M10.5.0/3";
const WPS_MANUFACTURER: &[u8] = b"AcmeRouters";
const WPS_MODEL_NAME: &[u8] = b"AC-9000X";
const WPS_MODEL_NUMBER: &[u8] = b"v3.2";
const WPS_SERIAL: &[u8] = b"SN-99-XYZ";
const WPS_DEVICE_NAME: &[u8] = b"AcmeAP-Lobby";
const OWE_OPEN_SSID: &[u8] = b"WolfOpen";
const CCX1_NAME: &[u8] = b"CCXLab-AP-07";
const ARUBA_AP_NAME: &[u8] = b"aruba-ap-edge";
const SUB_SSID: &[u8] = b"WolfSubGuest";
const RNR_BSSID: [u8; 6] = [0x06, 0x99, 0x77, 0x55, 0x33, 0x11];
const P2P_DEVICE_NAME: &[u8] = b"AndroidPhonePixel";

fn mac_hdr(ftype: u8, subtype: u8, addr1: [u8; 6], addr2: [u8; 6], addr3: [u8; 6]) -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0] = (subtype << 4) | (ftype << 2);
    h[4..10].copy_from_slice(&addr1);
    h[10..16].copy_from_slice(&addr2);
    h[16..22].copy_from_slice(&addr3);
    h
}

/// Builds a Beacon body whose tagged-parameters region carries every IE listed
/// in `ARCHITECTURE.md §9.3` "Plaintext extraction surfaces". Order does not
/// matter for any of the parsers under test; we use a roughly numerical IE-tag
/// order to keep the byte stream readable in `xxd` dumps when the test fails.
fn enriched_beacon() -> Vec<u8> {
    let mut frame = mac_hdr(TYPE_MGMT, SUBTYPE_BEACON, BCAST, AP, AP).to_vec();
    // Fixed fields: Timestamp(8) + BeaconInterval(2) + Capability(2)
    frame.extend_from_slice(&[0u8; 8]);
    frame.extend_from_slice(&100_u16.to_le_bytes());
    frame.extend_from_slice(&0x0011_u16.to_le_bytes());
    // SSID (tag 0)
    push_tlv(&mut frame, 0, SSID);
    // Supported Rates (tag 1) -- presence required by some clients.
    push_tlv(&mut frame, 1, &[0x82, 0x84, 0x8B, 0x96]);
    // DS Parameter Set (tag 3) channel 6
    push_tlv(&mut frame, 3, &[6]);
    // Country (tag 7) -- 2-letter ISO 3166-1 + Environment byte (' ' = any).
    push_tlv(&mut frame, 7, &[COUNTRY[0], COUNTRY[1], b' ']);
    // RSN (tag 48) WPA2-PSK so the beacon is otherwise spec-conformant.
    push_tlv(&mut frame, 48, &rsn_wpa2_psk());
    // Multiple BSSID (tag 71) -- one nontransmitted profile with sub-SSID.
    push_tlv(&mut frame, 71, &multiple_bssid_body());
    // SSID List (tag 84) -- one nested SSID element.
    push_tlv(&mut frame, 84, &ssid_list_body());
    // Time Zone (tag 98) -- POSIX TZ string.
    push_tlv(&mut frame, 98, TIME_ZONE);
    // Mesh ID (tag 114).
    push_tlv(&mut frame, 114, MESH_ID);
    // Cisco CCX1 (tag 133) -- 16-byte null-padded AP name at body offset 10.
    push_tlv(&mut frame, 133, &ccx1_body());
    // Reduced Neighbor Report (tag 201) -- one neighbor with BSSID at offset 1.
    push_tlv(&mut frame, 201, &rnr_body());
    // WPS vendor IE (tag 221, OUI 00:50:F2, type 4).
    push_tlv(&mut frame, 221, &wps_vendor_body());
    // OWE Transition vendor IE (tag 221, OUI 50:6F:9A, type 28).
    push_tlv(&mut frame, 221, &owe_transition_body());
    // P2P (Wi-Fi Direct) vendor IE (tag 221, OUI 50:6F:9A, type 9).
    push_tlv(&mut frame, 221, &p2p_vendor_body());
    // Aruba vendor AP-name IE (tag 221, OUI 00:0B:86, subtype 3).
    push_tlv(&mut frame, 221, &aruba_vendor_body());
    frame
}

fn push_tlv(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    out.push(body.len() as u8);
    out.extend_from_slice(body);
}

fn rsn_wpa2_psk() -> Vec<u8> {
    let mut rsn: Vec<u8> = Vec::new();
    rsn.extend_from_slice(&1_u16.to_le_bytes()); // version
    rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // group: CCMP
    rsn.extend_from_slice(&1_u16.to_le_bytes());
    rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // pairwise: CCMP
    rsn.extend_from_slice(&1_u16.to_le_bytes());
    rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x02]); // AKM: PSK
    rsn.extend_from_slice(&[0x00, 0x00]); // RSN caps
    rsn
}

fn ssid_list_body() -> Vec<u8> {
    // SSID List (tag 84) body is a stream of nested SSID elements (tag 0).
    let mut out = Vec::new();
    push_tlv(&mut out, 0, SSID_LIST_ENTRY);
    out
}

fn ccx1_body() -> Vec<u8> {
    // Cisco CCX1 layout: 10-byte preamble + 16-byte null-padded AP name.
    let mut body = vec![0u8; 10];
    let mut name = [0u8; 16];
    let n = CCX1_NAME.len().min(16);
    name[..n].copy_from_slice(&CCX1_NAME[..n]);
    body.extend_from_slice(&name);
    body
}

fn rnr_body() -> Vec<u8> {
    // One Neighbor AP Information block: TBTT Info Header (LE u16) +
    // Op Class (1) + Channel (1) + one TBTT Information field of length 8.
    // Length 8 layout: TBTT Offset(1) + BSSID(6) + BSS Params(1) -- BSSID is
    // at offset 1 within the entry. Header bits: count=N+1=1 (N=0 in bits 4-7),
    // length=8 in bits 8-15.
    let hdr: u16 = 8 << 8; // count_field = 0 (=> 1 entry), length = 8
    let mut body = Vec::new();
    body.extend_from_slice(&hdr.to_le_bytes());
    body.push(81); // operating class (2.4 GHz)
    body.push(6); // channel
    body.push(0); // TBTT Offset
    body.extend_from_slice(&RNR_BSSID); // BSSID at offset 1 of the TBTT entry
    body.push(0); // BSS Parameters
    body
}

fn wps_attr(out: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    // WPS attribute TLV: Type(2 BE) + Length(2 BE) + Value.
    out.extend_from_slice(&attr_type.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

fn wps_vendor_body() -> Vec<u8> {
    // Vendor IE prefix: OUI(3) + Type(1) + WPS attribute TLV stream.
    let mut body = vec![0x00, 0x50, 0xF2, 0x04]; // OUI 00:50:F2, type 4 (WPS)
    wps_attr(&mut body, 0x1021, WPS_MANUFACTURER);
    wps_attr(&mut body, 0x1023, WPS_MODEL_NAME);
    wps_attr(&mut body, 0x1024, WPS_MODEL_NUMBER);
    wps_attr(&mut body, 0x1042, WPS_SERIAL);
    wps_attr(&mut body, 0x1011, WPS_DEVICE_NAME);
    body
}

fn owe_transition_body() -> Vec<u8> {
    // Vendor IE: OUI 50:6F:9A + type 28 + BSSID(6) + SSID_Len(1) + SSID(n).
    let mut body = vec![0x50, 0x6F, 0x9A, 28];
    body.extend_from_slice(&[0x06, 0x88, 0x77, 0x66, 0x55, 0x44]); // open BSSID
    body.push(OWE_OPEN_SSID.len() as u8);
    body.extend_from_slice(OWE_OPEN_SSID);
    body
}

fn p2p_vendor_body() -> Vec<u8> {
    // Vendor IE: OUI 50:6F:9A + type 9 + P2P attribute TLV stream.
    // Each attribute: id(u8) + len(u16 LE) + value.
    let mut device_info: Vec<u8> = Vec::new();
    device_info.extend_from_slice(&[0u8; 6]); // P2P Device Address
    device_info.extend_from_slice(&[0u8; 2]); // Config Methods
    device_info.extend_from_slice(&[0u8; 8]); // Primary Device Type
    device_info.push(0); // Number of Secondary Device Types
    // Device Name TLV: id 0x1011 BE + len BE + name.
    device_info.extend_from_slice(&0x1011_u16.to_be_bytes());
    device_info.extend_from_slice(&(P2P_DEVICE_NAME.len() as u16).to_be_bytes());
    device_info.extend_from_slice(P2P_DEVICE_NAME);

    let mut body = vec![0x50, 0x6F, 0x9A, 9];
    body.push(13); // attribute id: P2P Device Info
    body.extend_from_slice(&(device_info.len() as u16).to_le_bytes());
    body.extend_from_slice(&device_info);
    body
}

fn aruba_vendor_body() -> Vec<u8> {
    // Vendor IE: OUI 00:0B:86 + Type(1, arbitrary) + Subtype(1=3 -> AP name) + name.
    let mut body = vec![0x00, 0x0B, 0x86, 0x01, 0x03];
    body.extend_from_slice(ARUBA_AP_NAME);
    body
}

fn multiple_bssid_body() -> Vec<u8> {
    // MaxBSSID Indicator (1) + Subelement(0=Nontransmitted Profile).
    // Profile body carries nested SSID (tag 0) + Multiple BSSID-Index (tag 83).
    let mut profile: Vec<u8> = Vec::new();
    push_tlv(&mut profile, 0, SUB_SSID);
    push_tlv(&mut profile, 83, &[1u8]); // sub-BSSID index 1

    let mut body: Vec<u8> = Vec::new();
    body.push(2); // MaxBSSID Indicator (=> mask = 0b11)
    body.push(0); // subelement id = Nontransmitted Profile
    body.push(profile.len() as u8);
    body.extend_from_slice(&profile);
    body
}

// --- Test harness ---

fn write_pcap(path: &Path, frames: &[Vec<u8>]) {
    let mut buf = pcap_global_header().to_vec();
    for (i, f) in frames.iter().enumerate() {
        buf.extend_from_slice(&pcap_packet(1_000_000 + i as u32, f));
    }
    fs::write(path, &buf).expect("write fixture pcap");
}

fn binary_path() -> std::path::PathBuf {
    let p = std::env::var("CARGO_BIN_EXE_wpawolf").expect("CARGO_BIN_EXE_wpawolf");
    std::path::PathBuf::from(p)
}

fn temp_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("wpawolf_extraction_coverage");
    fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn assert_contains(haystack: &str, needle: &str, label: &str) {
    assert!(haystack.lines().any(|l| l == needle), "{label}: missing line {needle:?} in:\n{haystack}");
}

fn assert_word(wordlist: &str, word: &[u8], label: &str) {
    let s = std::str::from_utf8(word).expect("test word ASCII");
    assert_contains(wordlist, s, label);
}

#[test]
fn beacon_emits_every_plaintext_surface() {
    let pcap = temp_path("beacon.pcap");
    let essid_out = temp_path("essid.list");
    let wordlist_out = temp_path("wordlist");
    let device_out = temp_path("device.info");
    write_pcap(&pcap, &[enriched_beacon()]);

    let status = Command::new(binary_path())
        .arg("-E")
        .arg(&essid_out)
        .arg("-W")
        .arg(&wordlist_out)
        .arg("-D")
        .arg(&device_out)
        .arg(&pcap)
        .status()
        .expect("run wpawolf");
    assert!(status.success(), "wpawolf exited non-zero on enriched beacon");

    let essid = fs::read_to_string(&essid_out).expect("read essid output");
    let wordlist = fs::read_to_string(&wordlist_out).expect("read wordlist output");
    let device = fs::read_to_string(&device_out).expect("read device-info output");

    // ESSID list (-E) must contain the primary SSID, the nested SSID-List entry,
    // the Mesh ID (mesh BSS shares ESSID semantics), the Multiple BSSID sub-SSID,
    // and the OWE Transition open-SSID.
    for (label, ssid) in [
        ("primary SSID", SSID),
        ("SSID List entry", SSID_LIST_ENTRY),
        ("Mesh ID", MESH_ID),
        ("Multiple BSSID sub-SSID", SUB_SSID),
        ("OWE Transition SSID", OWE_OPEN_SSID),
    ] {
        let s = std::str::from_utf8(ssid).expect("test ESSID ASCII");
        assert_contains(&essid, s, label);
    }

    // Wordlist (-W) must contain every plaintext IE-derived string.
    assert_word(&wordlist, SSID, "SSID");
    assert_word(&wordlist, SSID_LIST_ENTRY, "SSID List entry");
    assert_word(&wordlist, MESH_ID, "Mesh ID");
    assert_word(&wordlist, &COUNTRY, "Country code");
    assert_word(&wordlist, TIME_ZONE, "Time Zone");
    assert_word(&wordlist, WPS_MANUFACTURER, "WPS manufacturer");
    assert_word(&wordlist, WPS_MODEL_NAME, "WPS model name");
    assert_word(&wordlist, WPS_MODEL_NUMBER, "WPS model number");
    assert_word(&wordlist, WPS_SERIAL, "WPS serial number");
    assert_word(&wordlist, WPS_DEVICE_NAME, "WPS device name");
    assert_word(&wordlist, OWE_OPEN_SSID, "OWE Transition SSID");
    assert_word(&wordlist, CCX1_NAME, "Cisco CCX1 AP name");
    assert_word(&wordlist, ARUBA_AP_NAME, "Aruba vendor AP name");
    assert_word(&wordlist, P2P_DEVICE_NAME, "P2P device name");

    // RNR BSSIDs are emitted to the wordlist as lowercase hex (no separators).
    let rnr_hex: String = RNR_BSSID.iter().map(|b| format!("{b:02x}")).collect();
    assert_contains(&wordlist, &rnr_hex, "RNR BSSID hex");

    // Device-info (-D) output must include the WPS-derived AP profile.
    let device_lc = device.to_ascii_lowercase();
    assert!(
        device_lc.contains(&String::from_utf8_lossy(WPS_MANUFACTURER).to_ascii_lowercase()),
        "device info missing WPS manufacturer; got:\n{device}"
    );
    assert!(
        device_lc.contains(&String::from_utf8_lossy(WPS_DEVICE_NAME).to_ascii_lowercase()),
        "device info missing WPS device name; got:\n{device}"
    );
}
