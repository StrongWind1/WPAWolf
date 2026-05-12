//! Shared test helpers for integration tests that need a generated WPA2-PSK
//! capture instead of a checked-in binary fixture.
//!
//! Each integration test in `tests/integration/` is registered in `Cargo.toml`
//! as its own `[[test]]` crate. This file is **not** registered, so cargo
//! treats it as a plain module that any test crate can include via
//! `mod common;`. The file is compiled once per including crate.
//!
//! Helpers fall in four layers:
//!
//! * **DLT-105 pcap framing** -- `pcap_global_header`, `pcap_packet`.
//! * **pcapng block framing** -- `pcapng_shb`, `pcapng_idb`, `pcapng_epb`
//!   per draft-ietf-opsawg-pcapng-05 §4.{1,2,3}.
//! * **802.11 frame builders** -- minimal Beacon + 4-way handshake construction
//!   for WPA2-PSK (AKM 2). PMKID KDE is included on every M1 so both the
//!   PMKID line (`WPA*01*`) and the EAPOL line (`WPA*02*`) reach the output
//!   sinks.
//! * **High-level capture generators** --
//!   `multi_handshake_wpa2_psk_pcap(n)` and `multi_handshake_wpa2_psk_pcapng(n)`
//!   return a complete byte stream with `n` distinct handshakes (each its own
//!   AP MAC, STA MAC, ESSID, and PMKID), 5 frames per handshake (Beacon +
//!   M1 + M2 + M3 + M4). Both wrap the same underlying frame stream so any
//!   parser-format-specific bug shows up as a per-format test failure.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::redundant_pub_crate,
    clippy::fn_params_excessive_bools,
    clippy::doc_markdown,
    missing_docs,
    reason = "shared test helpers; not every including crate uses every helper, and the unreachable_pub / redundant_pub_crate pair is contradictory in a private test-only module"
)]

use std::fs;
use std::path::PathBuf;

// --- DLT 105 pcap framing ---

/// libpcap DLT for raw IEEE 802.11 frames.
const DLT_IEEE_802_11: u32 = 105;

/// 24-byte classic-pcap global header in microsecond-resolution little-endian.
#[must_use]
pub(crate) fn pcap_global_header() -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&0xA1B2_C3D4_u32.to_le_bytes());
    h[4..6].copy_from_slice(&2_u16.to_le_bytes()); // version major
    h[6..8].copy_from_slice(&4_u16.to_le_bytes()); // version minor
    h[16..20].copy_from_slice(&65535_u32.to_le_bytes()); // snaplen
    h[20..24].copy_from_slice(&DLT_IEEE_802_11.to_le_bytes());
    h
}

/// 16-byte per-packet header (`ts_sec`/`ts_usec`/`incl_len`/`orig_len`) followed by the payload.
#[must_use]
pub(crate) fn pcap_packet(ts_sec: u32, data: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(16 + data.len());
    r.extend_from_slice(&ts_sec.to_le_bytes());
    r.extend_from_slice(&0_u32.to_le_bytes());
    let len = data.len() as u32;
    r.extend_from_slice(&len.to_le_bytes());
    r.extend_from_slice(&len.to_le_bytes());
    r.extend_from_slice(data);
    r
}

// --- pcapng block framing ([draft-ietf-opsawg-pcapng-05] §4) ---

/// Section Header Block, 28 bytes total. Little-endian byte order
/// (BOM = `0x1A2B3C4D` stored LE), version 1.0, section length unspecified.
/// [draft-ietf-opsawg-pcapng-05] §4.1
#[must_use]
pub(crate) fn pcapng_shb() -> [u8; 28] {
    let mut b = [0u8; 28];
    b[0..4].copy_from_slice(&0x0A0D_0D0Au32.to_le_bytes()); // block type
    b[4..8].copy_from_slice(&28u32.to_le_bytes()); // total length
    b[8..12].copy_from_slice(&[0x4D, 0x3C, 0x2B, 0x1A]); // BOM little-endian
    b[12..14].copy_from_slice(&1u16.to_le_bytes()); // major
    b[14..16].copy_from_slice(&0u16.to_le_bytes()); // minor
    b[16..24].copy_from_slice(&(-1i64).to_le_bytes()); // section_length unspecified
    b[24..28].copy_from_slice(&28u32.to_le_bytes()); // trailing total length
    b
}

/// Interface Description Block, 20 bytes total. Declares one DLT-105 interface
/// with snaplen 65535 and no options. EPBs reference this with `interface_id=0`.
/// [draft-ietf-opsawg-pcapng-05] §4.2
#[must_use]
pub(crate) fn pcapng_idb() -> [u8; 20] {
    let mut b = [0u8; 20];
    b[0..4].copy_from_slice(&0x0000_0001u32.to_le_bytes()); // block type IDB
    b[4..8].copy_from_slice(&20u32.to_le_bytes()); // total length
    b[8..10].copy_from_slice(&(DLT_IEEE_802_11 as u16).to_le_bytes()); // LinkType
    b[10..12].copy_from_slice(&0u16.to_le_bytes()); // reserved
    b[12..16].copy_from_slice(&65535u32.to_le_bytes()); // snaplen
    b[16..20].copy_from_slice(&20u32.to_le_bytes()); // trailing total length
    b
}

/// Enhanced Packet Block referencing `interface_id=0`. Default timestamp
/// resolution is microseconds (no `if_tsresol` option), so `ts_us` is the
/// 32-bit low word of the us-since-epoch timestamp. Packet payload is padded
/// to a 4-byte boundary per spec.
/// [draft-ietf-opsawg-pcapng-05] §4.3
#[must_use]
pub(crate) fn pcapng_epb(ts_us: u32, data: &[u8]) -> Vec<u8> {
    let captured_len = data.len() as u32;
    let pad = (4 - (data.len() % 4)) % 4;
    let total_len = (32 + data.len() + pad) as u32;

    let mut b = Vec::with_capacity(total_len as usize);
    b.extend_from_slice(&0x0000_0006u32.to_le_bytes()); // block type EPB
    b.extend_from_slice(&total_len.to_le_bytes()); // total length
    b.extend_from_slice(&0u32.to_le_bytes()); // interface_id
    b.extend_from_slice(&0u32.to_le_bytes()); // ts_high (always 0 for these fixtures)
    b.extend_from_slice(&ts_us.to_le_bytes()); // ts_low
    b.extend_from_slice(&captured_len.to_le_bytes()); // captured_length
    b.extend_from_slice(&captured_len.to_le_bytes()); // original_length
    b.extend_from_slice(data);
    b.resize(b.len() + pad, 0u8); // 4-byte alignment padding
    b.extend_from_slice(&total_len.to_le_bytes()); // trailing total length
    b
}

// --- 802.11 frame builders ---

const TYPE_MGMT: u8 = 0;
const TYPE_DATA: u8 = 2;
const SUBTYPE_BEACON: u8 = 8;
const SUBTYPE_DATA: u8 = 0;
const BCAST: [u8; 6] = [0xFF; 6];

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

/// Builds a Beacon body advertising AKM 2 (WPA2-PSK) with a single SSID and CCMP.
fn build_beacon_wpa2_psk(ssid: &[u8], ap: [u8; 6]) -> Vec<u8> {
    let mut frame = mac_hdr_3addr(TYPE_MGMT, SUBTYPE_BEACON, false, false, BCAST, ap, ap);
    // Fixed fields: Timestamp(8) + BeaconInterval(2) + Capability(2)
    frame.extend_from_slice(&[0u8; 8]);
    frame.extend_from_slice(&100_u16.to_le_bytes());
    frame.extend_from_slice(&0x0011_u16.to_le_bytes());
    // SSID (tag 0)
    frame.push(0);
    frame.push(ssid.len() as u8);
    frame.extend_from_slice(ssid);
    // Supported Rates (tag 1) -- mandatory presence
    frame.extend_from_slice(&[1u8, 4, 0x82, 0x84, 0x8B, 0x96]);
    // DS Parameter Set (tag 3) channel 6
    frame.extend_from_slice(&[3u8, 1, 6]);
    // RSN IE (tag 48) advertising AKM 2 = WPA2-PSK with CCMP group + pairwise.
    frame.push(48);
    let mut rsn: Vec<u8> = Vec::new();
    rsn.extend_from_slice(&1_u16.to_le_bytes()); // version
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

// Non-uniform fixtures: the garbage-pattern check rejects uniform-byte nonces
// and MICs (`[0xB0; 32]` flagged as `repeat_1`), so the pre-fix `[0xB0; 32]` /
// `[0xC0; 32]` / `[0xD0; 16]` constants would now zero the test corpus. These
// arrays mirror the random shape of real wire bytes while keeping a stable
// per-side identity (every nonce byte is unique within its array).
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

/// PMKID KDE per [IEEE 802.11-2024] §12.7.2: type=0xDD, len=0x14, OUI 00:0F:AC,
/// sub-type 0x04, 16-byte PMKID. Goes inside an M1 Key Data field.
fn pmkid_kde(pmkid: &[u8; 16]) -> Vec<u8> {
    let mut kde = vec![0xDD, 0x14, 0x00, 0x0F, 0xAC, 0x04];
    kde.extend_from_slice(pmkid);
    kde
}

/// LLC/SNAP + EAPOL-Key body for WPA2-PSK (KDV=2, 16-byte MIC).
fn eapol_key_body(
    key_ack: bool,
    install: bool,
    mic_flag: bool,
    secure: bool,
    nonce: [u8; 32],
    mic: [u8; 16],
    key_data: &[u8],
) -> Vec<u8> {
    let mut body = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];
    body.push(0x02); // EAPOL proto ver
    body.push(0x03); // Packet Type: EAPOL-Key
    let kd_len = key_data.len() as u16;
    body.extend_from_slice(&(95u16 + kd_len).to_be_bytes());
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
    body.extend_from_slice(&kd_len.to_be_bytes());
    body.extend_from_slice(key_data);
    body
}

fn data_frame_downlink(ap: [u8; 6], sta: [u8; 6], body: &[u8]) -> Vec<u8> {
    // ToDS=0, FromDS=1: addr1=DA(STA), addr2=BSSID(AP), addr3=SA(AP).
    let mut frame = mac_hdr_3addr(TYPE_DATA, SUBTYPE_DATA, false, true, sta, ap, ap);
    frame.extend_from_slice(body);
    frame
}

fn data_frame_uplink(ap: [u8; 6], sta: [u8; 6], body: &[u8]) -> Vec<u8> {
    // ToDS=1, FromDS=0: addr1=BSSID(AP), addr2=SA(STA), addr3=DA(AP).
    let mut frame = mac_hdr_3addr(TYPE_DATA, SUBTYPE_DATA, true, false, ap, sta, ap);
    frame.extend_from_slice(body);
    frame
}

/// Builds the four EAPOL-Key data frames of a WPA2-PSK 4-way handshake.
///
/// M1 carries a PMKID KDE so both `WPA*01*` (PMKID line) and `WPA*02*` (EAPOL
/// pair line) reach the legacy `--22000-out` sink. M4 carries the same SNonce
/// as M2 (matches non-conforming firmware that copies M2's SNonce into M4 per
/// [IEEE 802.11-2024] §12.7.6.5 NOTE 9). The spec-mandated all-zero M4 Key
/// Nonce is dropped at extract because the resulting hash line is
/// mathematically uncrackable -- the live PTK depends on M2's SNonce, which
/// the M4 frame does not carry. See parse() in src/ieee80211/eapol.rs.
fn build_handshake(ap: [u8; 6], sta: [u8; 6], pmkid: [u8; 16]) -> [Vec<u8>; 4] {
    let m1 = data_frame_downlink(
        ap,
        sta,
        &eapol_key_body(true, false, false, false, NONCE_AP, [0u8; 16], &pmkid_kde(&pmkid)),
    );
    let m2 = data_frame_uplink(ap, sta, &eapol_key_body(false, false, true, false, NONCE_STA, MIC16, &[]));
    let m3 = data_frame_downlink(ap, sta, &eapol_key_body(true, true, true, true, NONCE_AP, MIC16, &[]));
    let m4 = data_frame_uplink(ap, sta, &eapol_key_body(false, false, true, true, NONCE_STA, MIC16, &[]));
    [m1, m2, m3, m4]
}

// --- High-level generators ---

/// Returns the ordered `(timestamp_us, 802.11 frame)` stream for `n` WPA2-PSK
/// handshakes. Both the pcap and the pcapng generator wrap this same stream so
/// any per-format bug shows up as a one-format-only test failure.
///
/// Per handshake: Beacon, then M1 (with PMKID KDE) / M2 / M3 / M4. AP/STA MACs,
/// ESSID, and PMKID are derived from the loop index so every handshake is
/// independently identifiable in the output.
fn wpa2_psk_handshake_packets(n: usize) -> Vec<(u32, Vec<u8>)> {
    let mut packets: Vec<(u32, Vec<u8>)> = Vec::with_capacity(n * 5);
    let mut ts: u32 = 1_000_000;
    for i in 0..n {
        let i_u8 = u8::try_from(i).expect("at most 256 handshakes per fixture");
        let ap = [0x02, 0x11, 0x22, 0x33, 0x44, i_u8];
        let sta = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, i_u8];
        let ssid = format!("WolfNet{i:02}");
        let mut pmkid = [0x55u8; 16];
        pmkid[0] = 0xA0 ^ i_u8;

        packets.push((ts, build_beacon_wpa2_psk(ssid.as_bytes(), ap)));
        ts += 1;
        for f in build_handshake(ap, sta, pmkid) {
            packets.push((ts, f));
            ts += 1;
        }
    }
    packets
}

/// Generates a DLT-105 classic pcap with `n` distinct WPA2-PSK handshakes
/// (5 frames each: Beacon + M1 + M2 + M3 + M4). Returns the complete byte
/// stream ready to write to a file or pipe to `wpawolf`.
#[must_use]
pub(crate) fn multi_handshake_wpa2_psk_pcap(n: usize) -> Vec<u8> {
    let mut buf = pcap_global_header().to_vec();
    for (ts, frame) in wpa2_psk_handshake_packets(n) {
        buf.extend_from_slice(&pcap_packet(ts, &frame));
    }
    buf
}

/// Generates a DLT-105 pcapng with `n` distinct WPA2-PSK handshakes.
///
/// Layout: SHB, then a single IDB declaring the DLT-105 interface, then one
/// EPB per frame referencing `interface_id=0`. Same underlying frame stream as
/// `multi_handshake_wpa2_psk_pcap`, so a divergence between the two test
/// outputs isolates a bug to the pcapng parser.
#[must_use]
pub(crate) fn multi_handshake_wpa2_psk_pcapng(n: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&pcapng_shb());
    buf.extend_from_slice(&pcapng_idb());
    for (ts, frame) in wpa2_psk_handshake_packets(n) {
        buf.extend_from_slice(&pcapng_epb(ts, &frame));
    }
    buf
}

// --- Test plumbing ---

/// Returns a fresh per-test temp directory under the system temp root.
#[must_use]
pub(crate) fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(name);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Writes `bytes` to a file inside a shared temp dir and returns the path.
#[must_use]
pub(crate) fn write_temp_pcap(filename: &str, bytes: &[u8]) -> PathBuf {
    let path = temp_dir("wpawolf_common_fixtures").join(filename);
    fs::write(&path, bytes).unwrap();
    path
}

/// Path to the wpawolf binary cargo built for this test crate.
#[must_use]
pub(crate) fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wpawolf"))
}
