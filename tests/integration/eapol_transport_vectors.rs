//! Integration test: every non-trivial EAPOL transport vector survives end-to-end.
//!
//! This is the regression oracle for `ARCHITECTURE.md §3.3` "EAPOL transport-vector
//! inventory". A periodic external audit (`/tmp/eapol_vectors_report.txt`) was
//! authored against a stale snapshot of wpawolf and reported items 5 (Mesh Control
//! header skip), 9 (Mesh Peering Open AMPE PMKID), and 10 (preauth EtherType
//! `0x88C7`) as missing. They are all implemented; this test pins each one against
//! silent regression by exercising the full pipeline (parse -> store -> hashcat
//! emission).
//!
//! Three fixtures, each a single in-memory DLT-105 pcap:
//!   1. `mesh_control_skip_recovers_eapol_handshake`
//!      Beacon (RSN-PSK) + a 4-way handshake whose data frames carry a Mesh
//!      Control header per [IEEE 802.11-2024] §9.2.4.8.3. wpawolf must skip the
//!      6-byte Mesh Control header and recover the inner LLC/SNAP+EAPOL, emitting
//!      a `WPA*02*` line.
//!   2. `preauth_ethertype_88c7_emits_handshake`
//!      Beacon + 4-way handshake whose LLC/SNAP carries `EtherType 0x88C7` (IEEE
//!      preauthentication, §12.3.2) instead of `0x888E`. wpawolf must accept the
//!      preauth EtherType and emit a `WPA*02*` line.
//!   3. `mesh_peering_open_emits_ampe_pmkid`
//!      Beacon + a Mesh Peering Open self-protected action frame (category 15,
//!      action 1) with an AMPE element whose last 16 bytes are the chosen PMK
//!      identifier. wpawolf must extract the PMKID (S18) and emit a `WPA*01*` line.

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

// --- 802.11 helpers ---

const TYPE_MGMT: u8 = 0;
const TYPE_DATA: u8 = 2;
const SUBTYPE_BEACON: u8 = 8;
const SUBTYPE_QOS_DATA: u8 = 8; // type=2 + subtype=8 = QoS Data (needed for Mesh Control bit)
const SUBTYPE_DATA: u8 = 0; // type=2 + subtype=0 = plain Data
const SUBTYPE_ACTION: u8 = 13;

const AP: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
const STA: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
const BCAST: [u8; 6] = [0xFF; 6];

const fn fc(ftype: u8, subtype: u8, to_ds: bool, from_ds: bool) -> [u8; 2] {
    let mut f = [0u8; 2];
    f[0] = (subtype << 4) | (ftype << 2);
    if to_ds {
        f[1] |= 0x01;
    }
    if from_ds {
        f[1] |= 0x02;
    }
    f
}

/// Builds a 24-byte 3-address MAC header.
fn mac_hdr_3addr(ftype: u8, subtype: u8, to_ds: bool, from_ds: bool, a1: [u8; 6], a2: [u8; 6], a3: [u8; 6]) -> Vec<u8> {
    let mut h = Vec::with_capacity(24);
    h.extend_from_slice(&fc(ftype, subtype, to_ds, from_ds));
    h.extend_from_slice(&[0u8; 2]); // Duration
    h.extend_from_slice(&a1);
    h.extend_from_slice(&a2);
    h.extend_from_slice(&a3);
    h.extend_from_slice(&[0u8; 2]); // Sequence Control
    h
}

/// Builds a 32-byte QoS Data MAC header (4-address + 2-byte QoS Control).
///
/// Mesh BSS data frames use 4-address format per [IEEE 802.11-2024] §9.3.2.1.
/// `mesh_control_present` sets bit B0 of the LE-high byte of QoS Control per
/// [IEEE 802.11-2024] §9.2.4.5.7 -- this subfield is defined for QoS Data
/// frames "transmitted between mesh STAs" only, and wpawolf only honors it on
/// 4-address frames.
fn mac_hdr_qos_mesh(a1: [u8; 6], a2: [u8; 6], a3: [u8; 6], a4: [u8; 6], mesh_control_present: bool) -> Vec<u8> {
    // Mesh data frames are 4-address: ToDS=1 AND FromDS=1.
    let mut h = mac_hdr_3addr(TYPE_DATA, SUBTYPE_QOS_DATA, true, true, a1, a2, a3);
    h.extend_from_slice(&a4); // Address 4
    let qos_high = u8::from(mesh_control_present);
    h.push(0); // QoS Control LE-low byte (TID + EOSP + Ack Policy)
    h.push(qos_high); // QoS Control LE-high byte; bit B0 = Mesh Control Present
    h
}

// --- Beacon (advertise PSK so the AKM map gets seeded) ---

fn build_beacon(ssid: &[u8], akm_byte: u8) -> Vec<u8> {
    let mut frame = mac_hdr_3addr(TYPE_MGMT, SUBTYPE_BEACON, false, false, BCAST, AP, AP);
    // Fixed fields: Timestamp(8) + BeaconInterval(2) + Capability(2)
    frame.extend_from_slice(&[0u8; 8]);
    frame.extend_from_slice(&100_u16.to_le_bytes());
    frame.extend_from_slice(&0x0011_u16.to_le_bytes());
    // SSID
    frame.push(0);
    frame.push(ssid.len() as u8);
    frame.extend_from_slice(ssid);
    // Supported Rates
    frame.extend_from_slice(&[1u8, 4, 0x82, 0x84, 0x8B, 0x96]);
    // DS Parameter Set
    frame.extend_from_slice(&[3u8, 1, 6]);
    // RSN IE with the requested AKM
    frame.push(48);
    let mut rsn: Vec<u8> = Vec::new();
    rsn.extend_from_slice(&1_u16.to_le_bytes()); // version
    rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // group: CCMP
    rsn.extend_from_slice(&1_u16.to_le_bytes());
    rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // pairwise: CCMP
    rsn.extend_from_slice(&1_u16.to_le_bytes());
    rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, akm_byte]); // AKM
    rsn.extend_from_slice(&[0x00, 0x00]); // RSN caps
    frame.push(rsn.len() as u8);
    frame.extend_from_slice(&rsn);
    frame
}

// --- EAPOL-Key body builder (16-byte MIC, parametrised EtherType) ---

// Non-uniform fixtures: the garbage-pattern check at the EAPOL parser rejects
// uniform-byte nonces and MICs (formerly `[0xB0; 32]` / `[0xC0; 32]` / `[0xD0; 16]`
// would now flag as `repeat_1`). Real wire bytes are HMAC outputs / random nonces;
// these fixtures mirror that shape.
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

/// Builds an LLC/SNAP+EAPOL-Key frame body. `ethertype` selects between
/// 0x888E (standard EAPOL) and 0x88C7 (preauthentication).
fn eapol_key_body(
    ethertype: u16,
    kdv: u8,
    key_ack: bool,
    install: bool,
    mic_flag: bool,
    secure: bool,
    nonce: [u8; 32],
    mic: [u8; 16],
    key_data_extra: &[u8],
) -> Vec<u8> {
    let et = ethertype.to_be_bytes();
    let mut body = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, et[0], et[1]];
    body.push(0x02); // EAPOL proto ver
    body.push(0x03); // Packet Type: EAPOL-Key
    let kd_len = key_data_extra.len() as u16;
    body.extend_from_slice(&(95u16 + kd_len).to_be_bytes());
    body.push(0x02); // descriptor type: RSN
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

// --- Frame builders for each test ---

fn data_frame_downlink_eapol(ethertype: u16, eapol_body: &[u8]) -> Vec<u8> {
    // ToDS=0, FromDS=1: addr1=DA(STA), addr2=BSSID(AP), addr3=SA(AP).
    let mut frame = mac_hdr_3addr(TYPE_DATA, SUBTYPE_DATA, false, true, STA, AP, AP);
    let _ = ethertype;
    frame.extend_from_slice(eapol_body);
    frame
}

fn data_frame_uplink_eapol(ethertype: u16, eapol_body: &[u8]) -> Vec<u8> {
    // ToDS=1, FromDS=0: addr1=BSSID(AP), addr2=SA(STA), addr3=DA(AP).
    let mut frame = mac_hdr_3addr(TYPE_DATA, SUBTYPE_DATA, true, false, AP, STA, AP);
    let _ = ethertype;
    frame.extend_from_slice(eapol_body);
    frame
}

/// Builds a Mesh Data QoS frame (downlink) with a 6-byte Mesh Control header
/// followed by the EAPOL body. Mesh Address Extension Mode is `00` (no Address
/// Extension), so total Mesh Control length is 6 bytes. Mesh BSS data frames
/// are 4-address per [IEEE 802.11-2024] §9.3.2.1 (mesh STAs as both transmitter
/// and receiver of forwarded MSDUs).
fn mesh_data_frame_downlink_eapol(eapol_body: &[u8]) -> Vec<u8> {
    // Address mapping for a 4-addr mesh frame: addr1=RA, addr2=TA, addr3=DA, addr4=SA.
    let mut frame = mac_hdr_qos_mesh(STA, AP, STA, AP, true);
    // Mesh Control: Flags(1) + TTL(1) + Sequence(4) -> Address Extension Mode = 00.
    frame.extend_from_slice(&[0x00, 0x20, 0x01, 0x02, 0x03, 0x04]);
    frame.extend_from_slice(eapol_body);
    frame
}

fn mesh_data_frame_uplink_eapol(eapol_body: &[u8]) -> Vec<u8> {
    let mut frame = mac_hdr_qos_mesh(AP, STA, AP, STA, true);
    frame.extend_from_slice(&[0x00, 0x20, 0x05, 0x06, 0x07, 0x08]);
    frame.extend_from_slice(eapol_body);
    frame
}

/// Builds a Mesh Peering Open self-protected action frame (category 15, action 1)
/// whose AMPE element body ends with the given 16-byte PMKID. wpawolf reads the
/// last 16 bytes of the AMPE body as the chosen PMK identifier per
/// [IEEE 802.11-2024] §14.3.5 Figure 14-16.
fn mesh_peering_open_with_pmkid(pmkid: [u8; 16]) -> Vec<u8> {
    // Self-protected action frames are management frames; addr1 = STA, addr2 = AP,
    // addr3 = AP (BSSID).
    let mut frame = mac_hdr_3addr(TYPE_MGMT, SUBTYPE_ACTION, false, false, STA, AP, AP);
    // Action body: Category(1) + Action(1) + Capability(2) + (optional) IEs.
    frame.push(15); // Self-Protected Action
    frame.push(1); // Mesh Peering Open
    frame.extend_from_slice(&[0x00, 0x00]); // Capability Info
    // AMPE element (id 139). Body must be at least 16 bytes; final 16 bytes
    // are the chosen PMK identifier per §14.3.5. Pad the front with 16 bytes
    // of zeros so the decoder's "last 16 bytes" rule selects our PMKID.
    frame.push(139);
    frame.push(32); // AMPE body length
    frame.extend_from_slice(&[0u8; 16]); // selected pairwise / AKM filler
    frame.extend_from_slice(&pmkid);
    frame
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
    let dir = std::env::temp_dir().join("wpawolf_eapol_transport_vectors");
    fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

/// Runs wpawolf with `--22000-out FILE PCAP` and returns `(stdout, output_contents)`.
fn run_wpawolf_22000(pcap: &Path, out: &Path) -> (String, String) {
    let result = Command::new(binary_path()).arg("--22000-out").arg(out).arg(pcap).output().expect("run wpawolf");
    assert!(result.status.success(), "wpawolf exited non-zero on {pcap:?}");
    let log = String::from_utf8_lossy(&result.stdout).into_owned();
    let contents = fs::read_to_string(out).unwrap_or_default();
    (log, contents)
}

// --- Tests ---

#[test]
fn mesh_control_skip_recovers_eapol_handshake() {
    let beacon = build_beacon(b"WolfMesh", 2);
    let m1 =
        mesh_data_frame_downlink_eapol(&eapol_key_body(0x888E, 2, true, false, false, false, NONCE_AP, [0u8; 16], &[]));
    let m2 = mesh_data_frame_uplink_eapol(&eapol_key_body(0x888E, 2, false, false, true, false, NONCE_STA, MIC16, &[]));
    let m3 = mesh_data_frame_downlink_eapol(&eapol_key_body(0x888E, 2, true, true, true, true, NONCE_AP, MIC16, &[]));
    let m4 = mesh_data_frame_uplink_eapol(&eapol_key_body(0x888E, 2, false, false, true, true, NONCE_STA, MIC16, &[]));
    let pcap = temp_path("mesh_control.pcap");
    let out = temp_path("mesh_control.22000");
    write_pcap(&pcap, &[beacon, m1, m2, m3, m4]);
    let (log, contents) = run_wpawolf_22000(&pcap, &out);

    // Stats banner must show that the Mesh Control header was actually unwrapped.
    assert!(
        log.contains("Mesh Data frames recovered"),
        "stats banner missing mesh_control_frames line; full log:\n{log}"
    );
    // Hash output must contain at least one WPA*02* (EAPOL) line.
    assert!(
        contents.lines().any(|l| l.starts_with("WPA*02*")),
        "expected WPA*02* line for the recovered handshake; output was:\n{contents}"
    );
}

#[test]
fn preauth_ethertype_88c7_emits_handshake() {
    let beacon = build_beacon(b"WolfPreauth", 2);
    let m1 = data_frame_downlink_eapol(
        0x88C7,
        &eapol_key_body(0x88C7, 2, true, false, false, false, NONCE_AP, [0u8; 16], &[]),
    );
    let m2 =
        data_frame_uplink_eapol(0x88C7, &eapol_key_body(0x88C7, 2, false, false, true, false, NONCE_STA, MIC16, &[]));
    let m3 =
        data_frame_downlink_eapol(0x88C7, &eapol_key_body(0x88C7, 2, true, true, true, true, NONCE_AP, MIC16, &[]));
    let m4 =
        data_frame_uplink_eapol(0x88C7, &eapol_key_body(0x88C7, 2, false, false, true, true, NONCE_STA, MIC16, &[]));
    let pcap = temp_path("preauth.pcap");
    let out = temp_path("preauth.22000");
    write_pcap(&pcap, &[beacon, m1, m2, m3, m4]);
    let (log, contents) = run_wpawolf_22000(&pcap, &out);

    // Stats banner must surface the preauthentication EtherType line as non-zero.
    let preauth_count = log
        .lines()
        .find(|l| l.contains("preauthentication frames (EtherType 0x88C7)"))
        .and_then(|l| l.rsplit_once(':').map(|(_, v)| v.trim().parse::<u32>().ok()))
        .flatten()
        .unwrap_or(0);
    assert!(preauth_count >= 4, "preauth_ethertype counter should reflect M1..M4; full log:\n{log}");
    assert!(
        contents.lines().any(|l| l.starts_with("WPA*02*")),
        "expected WPA*02* line for the preauth handshake; output was:\n{contents}"
    );
}

#[test]
fn mesh_peering_open_emits_ampe_pmkid_when_beacon_is_psk() {
    // AMPE PMKID extraction stores entry.akm = Unknown because the AMPE element
    // itself carries no AKM context. The output pipeline falls back on
    // akm_map.get_best(ap, sta), which is seeded from the Beacon's RSN IE. With
    // a PSK Beacon the PMKID resolves to WPA2-PSK and emits as WPA*02*. This
    // is the "all PSK PMKIDs are crackable" guarantee in action -- without the
    // fallback the PMKID would parse and count in stats but never reach a
    // hashcat line.
    let beacon = build_beacon(b"WolfMeshPeer", 2); // AKM 2 = WPA2-PSK
    let pmkid: [u8; 16] =
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00];
    let action = mesh_peering_open_with_pmkid(pmkid);
    let pcap = temp_path("mesh_peering.pcap");
    let out = temp_path("mesh_peering.22000");
    write_pcap(&pcap, &[beacon, action]);
    let (log, contents) = run_wpawolf_22000(&pcap, &out);

    // Per-source S18 stat must increment so the extraction surface is visible
    // in the operator-facing summary.
    assert!(
        log.contains("Mesh Peering AMPE (S18/S19)"),
        "stats banner missing Mesh Peering AMPE PMKID source line; full log:\n{log}"
    );
    // The AMPE PMKID must reach a hashcat line. The hashcat 22000 PMKID prefix
    // is the literal `WPA*01*`; the extended type (2 for WPA2-PSK) only shows
    // up in the per-type sinks (--wpa2-out etc.). The 16 chosen-PMK bytes
    // appear lowercase-hex right after the prefix.
    let pmkid_hex: String = pmkid.iter().fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    });
    assert!(
        contents.lines().any(|l| l.starts_with("WPA*01*") && l.contains(&pmkid_hex)),
        "expected WPA*01* line containing PMKID {pmkid_hex}; output was:\n{contents}"
    );
}
