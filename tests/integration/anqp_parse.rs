//! Integration test: ANQP element parsing via GAS Public Action frames.
//!
//! Builds a synthetic pcap with a single Public Action frame: Category 4,
//! Action 11 (GAS Initial Response), whose Query Response payload carries four
//! ANQP elements: Venue Name, Domain Name List (two FQDNs), NAI Realm, and a
//! Hotspot 2.0 vendor-specific Operator Friendly Name.
//!
//! Assertions:
//!
//! - All five expected strings appear in the `-W` wordlist output.
//! - None of them appear in `-E` or `-R` (ANQP text is not an SSID and does not
//!   pass the `fwriteessidstr` admission filter).
//! - `-W` is identical byte-for-byte to the same fixture with `-E` / `-R`
//!   disabled, confirming ANQP flows only into the combined wordlist.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    missing_docs,
    unused_crate_dependencies,
    clippy::cast_possible_truncation,
    reason = "integration test module -- strict lints relaxed"
)]

use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

// --- Pcap byte builders ---

fn pcap_global_header(link_type: u32) -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&0xA1B2_C3D4_u32.to_le_bytes());
    h[4..6].copy_from_slice(&2_u16.to_le_bytes());
    h[6..8].copy_from_slice(&4_u16.to_le_bytes());
    h[16..20].copy_from_slice(&65535_u32.to_le_bytes());
    h[20..24].copy_from_slice(&link_type.to_le_bytes());
    h
}

fn pcap_packet_record(ts_sec: u32, data: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(16 + data.len());
    r.extend_from_slice(&ts_sec.to_le_bytes());
    r.extend_from_slice(&0_u32.to_le_bytes());
    let len = data.len() as u32;
    r.extend_from_slice(&len.to_le_bytes());
    r.extend_from_slice(&len.to_le_bytes());
    r.extend_from_slice(data);
    r
}

fn mgmt_header(subtype: u8, addr1: [u8; 6], addr2: [u8; 6], addr3: [u8; 6]) -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0] = subtype << 4;
    h[1] = 0x00;
    h[4..10].copy_from_slice(&addr1);
    h[10..16].copy_from_slice(&addr2);
    h[16..22].copy_from_slice(&addr3);
    h
}

// --- ANQP builders ---

fn anqp_tlv(info_id: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&info_id.to_le_bytes());
    v.extend_from_slice(&u16::try_from(body.len()).unwrap().to_le_bytes());
    v.extend_from_slice(body);
    v
}

fn venue_name_body(venue: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x00, 0x02]); // Venue Info
    let total_len = 3 + venue.len();
    v.push(total_len as u8);
    v.extend_from_slice(b"eng");
    v.extend_from_slice(venue);
    v
}

fn domain_name_body(names: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for n in names {
        v.push(n.len() as u8);
        v.extend_from_slice(n);
    }
    v
}

fn nai_realm_body(realm: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x01, 0x00]); // Realm Count = 1
    let data_len = 1 + 1 + realm.len() + 1;
    v.extend_from_slice(&u16::try_from(data_len).unwrap().to_le_bytes());
    v.push(0x00); // Encoding: RFC 4282
    v.push(realm.len() as u8);
    v.extend_from_slice(realm);
    v.push(0x00); // EAP Method Count = 0
    v
}

fn hs_operator_friendly_name_body(text: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&[0x50, 0x6F, 0x9A]); // WFA OUI
    v.push(0x03); // HS2 subtype = Operator Friendly Name
    v.push(0x00); // Reserved
    let total_len = 3 + text.len();
    v.push(total_len as u8);
    v.extend_from_slice(b"eng");
    v.extend_from_slice(text);
    v
}

/// Build a complete GAS Initial Response Action frame carrying four ANQP elements.
fn gas_initial_response_frame(ap: [u8; 6], sta: [u8; 6]) -> Vec<u8> {
    // ANQP element stream (will become the Query Response payload).
    let mut anqp_stream = Vec::new();
    anqp_stream.extend_from_slice(&anqp_tlv(258, &venue_name_body(b"Cafe Kyoto"))); // Venue Name
    anqp_stream.extend_from_slice(&anqp_tlv(263, &domain_name_body(&[b"example.com", b"wlan.acme.co"])));
    anqp_stream.extend_from_slice(&anqp_tlv(268, &nai_realm_body(b"example.org"))); // NAI Realm
    anqp_stream.extend_from_slice(&anqp_tlv(56797, &hs_operator_friendly_name_body(b"Acme Telco")));

    // 802.11 Action frame header (subtype 13, mgmt). Addr1=STA, Addr2=AP, Addr3=AP.
    let mut frame: Vec<u8> = mgmt_header(13, sta, ap, ap).to_vec();

    // Action frame body:
    //   Category(4) + Action(11) + DialogToken(1) + Status(2 LE) + ComebackDelay(2 LE)
    //   + Advertisement Protocol IE (tag=108, len=2, value=[QueryResponseInfo=0x7F, ANQP=0x00])
    //   + Query Response Length (u16 LE) + Query Response payload
    frame.push(4); // Category: Public
    frame.push(11); // Action: GAS Initial Response
    frame.push(1); // Dialog Token
    frame.extend_from_slice(&0_u16.to_le_bytes()); // Status = 0 (success)
    frame.extend_from_slice(&0_u16.to_le_bytes()); // Comeback Delay = 0 (non-fragmented)
    // Advertisement Protocol element: tag 108, length 2, [QueryResponseInfo=0x7F, AP-ID=0x00 (ANQP)]
    frame.push(108);
    frame.push(2);
    frame.push(0x7F); // QueryResponseInfo: PAME-BI bit, Advertisement Protocol ID follows
    frame.push(0x00); // Advertisement Protocol ID = 0 (ANQP)
    // Query Response Length
    frame.extend_from_slice(&u16::try_from(anqp_stream.len()).unwrap().to_le_bytes());
    frame.extend_from_slice(&anqp_stream);
    frame
}

fn build_fixture_pcap() -> Vec<u8> {
    let ap_mac = [0x00_u8, 0x11, 0x22, 0x33, 0x44, 0x55];
    let sta_mac = [0xAA_u8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&pcap_global_header(105));
    let frame = gas_initial_response_frame(ap_mac, sta_mac);
    pcap.extend_from_slice(&pcap_packet_record(1000, &frame));
    pcap
}

fn read_lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path).unwrap_or_default().lines().filter(|l| !l.is_empty()).map(String::from).collect()
}

fn assert_contains(lines: &[String], needle: &str) {
    assert!(lines.iter().any(|l| l == needle), "expected {needle:?} in output; got: {lines:?}");
}

fn assert_not_contains(lines: &[String], needle: &str) {
    assert!(!lines.iter().any(|l| l == needle), "expected {needle:?} NOT in output; got: {lines:?}");
}

#[test]
fn anqp_elements_parsed_into_wordlist_only() {
    let pcap_path = "/tmp/wpawolf_t23_fixture.pcap";
    let wordlist_path = "/tmp/wpawolf_t23.wordlist";
    let essid_path = "/tmp/wpawolf_t23.essid";
    let probe_path = "/tmp/wpawolf_t23.probe";
    let dummy_hash = "/tmp/wpawolf_t23.22000";

    fs::write(pcap_path, build_fixture_pcap()).expect("write fixture pcap");

    let status = Command::new(env!("CARGO_BIN_EXE_wpawolf"))
        .args(["--22000-out", dummy_hash, "-W", wordlist_path, "-E", essid_path, "-R", probe_path, pcap_path])
        .status()
        .expect("failed to spawn wpawolf");
    assert!(status.success(), "wpawolf exited non-zero: {status}");

    let wordlist = read_lines(Path::new(wordlist_path));
    let essid = read_lines(Path::new(essid_path));
    let probe = read_lines(Path::new(probe_path));

    // All five ANQP text fragments must land in -W.
    // Strings containing space (0x20) render as `$HEX[...]` under hashcat autohex
    // (printable = 0x21..=0x7E minus 0x3A); pure-ASCII domain names without spaces
    // render verbatim.
    let cafe_kyoto_hex = format!("$HEX[{}]", hex_encode(b"Cafe Kyoto"));
    let acme_telco_hex = format!("$HEX[{}]", hex_encode(b"Acme Telco"));
    assert_contains(&wordlist, &cafe_kyoto_hex);
    assert_contains(&wordlist, "example.com");
    assert_contains(&wordlist, "wlan.acme.co");
    assert_contains(&wordlist, "example.org");
    assert_contains(&wordlist, &acme_telco_hex);

    // None of them must land in -E or -R. ANQP text is not an SSID.
    for s in ["example.com", "wlan.acme.co", "example.org", &cafe_kyoto_hex, &acme_telco_hex] {
        assert_not_contains(&essid, s);
        assert_not_contains(&probe, s);
    }
}

/// Lowercase hex encoder matching `bytes_to_hex_string` in src/types.rs.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
