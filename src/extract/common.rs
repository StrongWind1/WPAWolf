//! Phase 3 -- Extract: shared helpers and wire constants used by multiple frame handlers. See ARCHITECTURE.md §3.3.

use crate::ieee80211::{
    eapol,
    ft::extract_ft_fields,
    ie::iter_ies,
    rsn::{detect_akm, parse_rsn_ie},
};
use crate::log::Logger;
use crate::stats::Stats;
use crate::store::{
    AkmMap,
    essid::EssidMap,
    messages::{EapolMessage, MessageStore},
    pmkid::{PmkidEntry, PmkidStore},
};
use crate::types::{AkmType, MacAddr, MsgType, PmkidSource};

// --- ESSID admission with control-byte warning ---

/// Inserts `essid` into `essid_map` for `ap`, warning the operator when the
/// SSID contains any ASCII C0 control byte (`0x00..=0x1F`, NUL through US).
///
/// Two stages:
///   1. **Spec-driven discard.** [IEEE 802.11-2024] §9.4.2.2 caps SSID length at
///      32 octets; longer bodies are bit-flipped IE Length parses with no
///      salt value. Length-zero is the spec wildcard and first-byte-zero is the
///      hcx-mirrored hidden-network sentinel. All three are filtered silently
///      inside `EssidMap::insert` -- they have dedicated upstream counters
///      (`beacon_ssid_wildcard`, `beacon_ssid_oversized`, `beacon_ssid_zeroed`)
///      and surface there.
///   2. **Control-byte warning.** SSIDs that pass the spec gate but contain any
///      byte in the ASCII C0 control range `0x00..=0x1F` (NUL through US --
///      every control character) are stored and emitted as-is -- the cracker
///      may still recover the right PMK -- but a `[essid_control_bytes]` log
///      line is emitted with the SSID rendered in lowercase hex so the
///      operator can audit the source frame. The `essid_control_bytes_warned`
///      stats counter ticks on each warning; output behaviour is unchanged.
///
/// Wraps `EssidMap::insert` so every SSID-extract site (Beacon, Probe Request /
/// Response, Association / Reassociation Request, Action Measurement,
/// OWE Transition Mode) raises the warning uniformly.
pub fn insert_essid(
    essid_map: &mut EssidMap,
    ap: MacAddr,
    essid: &[u8],
    timestamp_us: u64,
    stats: &mut Stats,
    logger: &mut Logger,
) {
    // Warn before insert so the warning fires whether or not the SSID gates
    // through (the gate at length 0 / >32 / first byte 0 is already covered
    // by upstream counters; we only warn for SSIDs that survive the gate).
    // To stay aligned with what actually lands in the map, reproduce the
    // gate here -- a one-line check, cheap enough to repeat.
    let passes_gate = !essid.is_empty() && essid.len() <= 32 && essid.first() != Some(&0);
    if passes_gate && essid.iter().any(|&b| b <= 0x1F) {
        stats.essid_control_bytes_warned = stats.essid_control_bytes_warned.saturating_add(1);
        logger.log_essid_control_bytes(timestamp_us, ap.hex_lower(), essid);
    }
    essid_map.insert(ap, essid, timestamp_us);
}

// --- Management frame subtype constants ---
// [IEEE 802.11-2024] §9.2.4.1.3, Table 9-1

/// Association Request subtype (STA -> AP). [IEEE 802.11-2024] §9.3.3.5
pub const SUBTYPE_ASSOC_REQ: u8 = 0;
/// Association Response subtype (AP -> STA). [IEEE 802.11-2024] §9.3.3.6
pub const SUBTYPE_ASSOC_RESP: u8 = 1;
/// Reassociation Request subtype (STA -> AP). [IEEE 802.11-2024] §9.3.3.7
pub const SUBTYPE_REASSOC_REQ: u8 = 2;
/// Reassociation Response subtype (AP -> STA). [IEEE 802.11-2024] §9.3.3.8
pub const SUBTYPE_REASSOC_RESP: u8 = 3;
/// Probe Request subtype (STA -> AP/broadcast). [IEEE 802.11-2024] §9.3.3.9
pub const SUBTYPE_PROBE_REQ: u8 = 4;
/// Probe Response subtype (AP -> STA). [IEEE 802.11-2024] §9.3.3.10
pub const SUBTYPE_PROBE_RESP: u8 = 5;
/// Measurement Pilot subtype. [IEEE 802.11-2024] §9.3.3 (wireshark: `MGT_MEASUREMENT_PILOT`)
pub const SUBTYPE_MEASUREMENT_PILOT: u8 = 6;
/// Beacon subtype (AP periodic). [IEEE 802.11-2024] §9.3.3.2
pub const SUBTYPE_BEACON: u8 = 8;
/// ATIM subtype (null body, IBSS power management). [IEEE 802.11-2024] §9.3.3.3
pub const SUBTYPE_ATIM: u8 = 9;
/// Disassociation subtype. [IEEE 802.11-2024] §9.3.3.4
pub const SUBTYPE_DISASSOC: u8 = 10;
/// Authentication subtype. [IEEE 802.11-2024] §9.3.3.11
pub const SUBTYPE_AUTH: u8 = 11;
/// Deauthentication subtype. [IEEE 802.11-2024] §9.3.3.12
pub const SUBTYPE_DEAUTH: u8 = 12;
/// Action subtype. [IEEE 802.11-2024] §9.3.3.13
pub const SUBTYPE_ACTION: u8 = 13;
/// Action No Ack subtype. [IEEE 802.11-2024] §9.3.3.14
pub const SUBTYPE_ACTION_NO_ACK: u8 = 14;
/// Timing Advertisement subtype. [IEEE 802.11-2024] §9.3.3.15
pub const SUBTYPE_TIMING_ADVERT: u8 = 15;

// Fixed-field byte counts before the tagged parameters section.
/// Beacon/ProbeResponse fixed fields: Timestamp(8) + BeaconInterval(2) + Capability(2).
/// [IEEE 802.11-2024] §9.3.3.2
pub const BEACON_FIXED: usize = 12;
/// `AssocRequest` fixed fields: Capability(2) + ListenInterval(2).
/// [IEEE 802.11-2024] §9.3.3.5
pub const ASSOC_REQ_FIXED: usize = 4;
/// `ReassocRequest` fixed fields: Capability(2) + ListenInterval(2) + CurrentAP(6).
/// [IEEE 802.11-2024] §9.3.3.7
pub const REASSOC_REQ_FIXED: usize = 10;

/// Broadcast MAC address for detecting undirected Probe Requests.
pub const BROADCAST_MAC: [u8; 6] = [0xff; 6];

/// Decodes the length of a Mesh Control header at the start of a Mesh Data MSDU body.
///
/// Per [IEEE 802.11-2024] §9.2.4.8.3, the Mesh Control field is `Mesh Flags (1) +
/// Mesh TTL (1) + Mesh Sequence Number (4)` followed by an optional Mesh Address
/// Extension whose width is encoded in bits B0-B1 of Mesh Flags ("Address Extension Mode"):
///   `00` -> no extension          (total length 6)
///   `01` -> Address 4 only        (total length 12)
///   `10` -> Address 5 + Address 6 (total length 18)
///   `11` -> reserved              (return None and skip the frame)
///
/// Returns `None` when the body is too short to read Mesh Flags or Address Extension
/// Mode is the reserved value `11`.
#[must_use]
pub fn mesh_control_len(body: &[u8]) -> Option<usize> {
    let flags = *body.first()?;
    match flags & 0x03 {
        0b00 => Some(6),
        0b01 => Some(12),
        0b10 => Some(18),
        _ => None, // reserved
    }
}

/// Returns true if `body` starts with an LLC/SNAP header for the IEEE 802.11
/// preauthentication carrier (`EtherType` `0x88C7`).
///
/// Used to distinguish preauth frames from regular EAPOL (`0x888E`) for the
/// `stats.eapol_preauth_frames` counter; both `EtherType` values carry an identical
/// EAPOL-Key payload so the parse path is shared.
/// [IEEE 802.11-2024] §12.3.2
#[must_use]
pub fn is_preauth_llc(body: &[u8]) -> bool {
    body.len() >= 8
        && body.first() == Some(&0xAA)  // DSAP
        && body.get(1) == Some(&0xAA)   // SSAP
        && body.get(2) == Some(&0x03)   // Control (UI)
        && body.get(6) == Some(&0x88)
        && body.get(7) == Some(&0xC7)
}

/// Returns true if `body` starts with an LLC/SNAP header for EAPOL (`EtherType` `0x888E`)
/// or for the IEEE 802.11 preauthentication carrier (`EtherType` `0x88C7`).
///
/// Used for quick pre-screening of WDS data frames before deferring to Phase 1.5.
/// Preauthentication ([IEEE 802.11-2024] §12.3.2) tunnels EAPOL through the DS prior to
/// roaming using `0x88C7`; the encapsulated payload is identical to the `0x888E` case.
/// [IEEE 802.11-2012 Annex P, Table P-2]
#[must_use]
pub fn is_eapol_llc(body: &[u8]) -> bool {
    let llc_ok = body.len() >= 8
        && body.first() == Some(&0xAA)  // DSAP
        && body.get(1) == Some(&0xAA)   // SSAP
        && body.get(2) == Some(&0x03); // Control (UI)
    let et_high = body.get(6);
    let et_low = body.get(7);
    let eapol = et_high == Some(&0x88) && et_low == Some(&0x8E);
    let preauth = et_high == Some(&0x88) && et_low == Some(&0xC7);
    llc_ok && (eapol || preauth)
}

/// Returns true if `body` starts with an LLC/SNAP EAPOL header AND the EAPOL
/// Packet Type byte (offset 9) is 3 (EAPOL-Key).
///
/// Used to gate the `stats.eapol_llc_invalid` counter so legitimate EAP-Packet
/// (type 0), EAPOL-Start (1), and EAPOL-Logoff (2) frames are not miscounted as
/// invalid key frames. Per [IEEE 802.11-2024] §12.6.3 the Packet Type byte is at
/// EAPOL offset 1, which lands at MSDU offset 8 + 1 = 9 after the LLC/SNAP header.
#[must_use]
pub fn is_eapol_key_packet(body: &[u8]) -> bool {
    is_eapol_llc(body) && body.get(9) == Some(&3) // 3 = EAPOL-Key per §12.6.3
}

/// Extracts the ACK flag (Key Information bit B7) from raw EAPOL frame body.
///
/// Parses just enough of the LLC/SNAP + EAPOL header to read the Key Information field.
/// Returns `None` if the body is too short. Used during Phase 1.5 WDS resolution.
#[must_use]
pub fn extract_ack_flag(body: &[u8]) -> Option<bool> {
    // LLC/SNAP (8 bytes) + EAPOL header (4 bytes) + Descriptor Type (1 byte) + Key Info (2 bytes)
    // Key Info starts at EAPOL offset 5, which is body offset 8 + 5 = 13.
    let ki_bytes: [u8; 2] = body.get(13..15)?.try_into().ok()?;
    let ki = u16::from_be_bytes(ki_bytes); // big-endian per §12.7.2
    Some((ki >> 7) & 1 != 0) // bit B7 = ACK
}

/// Stores a parsed EAPOL-Key into the message store with PMKID extraction.
///
/// Shared by the immediate classification path (Phase 1) and deferred WDS resolution
/// (Phase 1.5). Handles M1 PMKID KDE extraction, M2 RSN IE PMKID extraction,
/// per-message-type counters, and auth-length tracking.
pub fn store_eapol_key(
    key: eapol::EapolKey,
    ap: MacAddr,
    sta: MacAddr,
    timestamp_us: u64,
    akm_map: &mut AkmMap,
    message_store: &mut MessageStore,
    pmkid_store: &mut PmkidStore,
    stats: &mut Stats,
    logger: &mut Logger,
    cross_file_dedup: Option<&mut crate::output::dedup::CrossFileDedup>,
) {
    // Extract FT fields (MDIE + FTIE subelements) from the EAPOL Key Data field.
    // Applies to M1/M2 for FT-PSK; M3 Key Data is encrypted so the IE iterator
    // returns None harmlessly. [IEEE 802.11-2024] §9.4.2.45-46; hcxpcapngtool gettags():3517
    let ft = extract_ft_fields(&key.key_data).map(Box::new);

    // Determine the AKM for this handshake from observed wire evidence rather than
    // trusting the AP's advertised AKM list. Priority:
    //   1. FT fields observed in Key Data (MDIE + FTIE) -> FT-PSK. This is definitive:
    //      only an FT handshake includes FTIE in M1/M2 Key Data. [IEEE 802.11-2024] §13.5.2
    //   2. Declared AKM from the M2 Key Data: RSN IE for WPA2/WPA3, WPA1 vendor IE for
    //      legacy WPA1. `detect_akm` walks both with the right priority (RSN > WPA1).
    //      [IEEE 802.11-2024] §12.7.2; Wi-Fi Alliance WPA legacy spec
    // Both signals, when present, are recorded per-(ap, sta) so that later pairings
    // built from M3/M4 on the same session inherit the right AKM.
    if ft.is_some() {
        // FT-PSK family: pick the SHA-256 vs SHA-384 variant from wire evidence rather
        // than defaulting to FtPsk. Without this, FT-PSK-SHA384 (AKM 19) handshakes
        // whose AssocReq was not captured fall through to FtPsk and get misrouted to
        // types 6/7 instead of 10/11. Sources, in priority order:
        //   1. M2's Key Data RSN IE (`detect_akm`)
        //   2. The AP's beacon RSN IE (already in `akm_map.get(ap)`)
        //   3. Default to FtPsk
        // [IEEE 802.11-2024] §9.4.2.24, Table 9-190
        let ft_akm = match (key.msg_type, detect_akm(&key.key_data)) {
            (MsgType::M2, AkmType::FtPskSha384) => AkmType::FtPskSha384,
            (MsgType::M2, _) => AkmType::FtPsk,
            (_, _) => match akm_map.get(&ap) {
                AkmType::FtPskSha384 => AkmType::FtPskSha384,
                _ => AkmType::FtPsk,
            },
        };
        akm_map.insert_sta(ap, sta, ft_akm);
    } else if key.msg_type == MsgType::M2 {
        let m2_akm = detect_akm(&key.key_data);
        if m2_akm != AkmType::Unknown {
            akm_map.insert_sta(ap, sta, m2_akm);
        }
    }
    // AKM determination is layered, with the wire-level Key Descriptor Version
    // consulted FIRST and the AKM map (beacon/assoc RSN IEs) used only to refine
    // within a KDV class:
    //
    //   KDV=1 = HMAC-MD5     -> Wpa1 only (no FT, no SHA-256/384 variants exist)
    //   KDV=2 = HMAC-SHA1    -> SHA-1 family: Wpa2Psk or FtPsk
    //   KDV=3 = AES-CMAC     -> CMAC family: PskSha256 or FtPsk
    //   KDV=0 = AKM-defined  -> trust akm_map verbatim (FT, SAE, SHA-384 AKMs)
    //
    // The proposed hashcat type prefix (Type 1 vs 3 vs 5/7/9/11) tells the cracker
    // which MIC kernel to run; legacy mode 22000 auto-detects via the keyver byte
    // but the new prefix-trusting modules will silently fail on a mismatched line.
    // Mixed-mode beacons (RSN + WPA1 vendor IE; PSK + PSK-SHA256 simultaneously)
    // regularly produce an akm_map that disagrees with the actual wire bytes, so
    // KDV is the only signal we can stake the type prefix on. The FT family is
    // preserved across KDV=2/3 because FT-PSK can legitimately use either MIC
    // depending on the underlying cipher suite. [IEEE 802.11-2024] §12.7.3
    let mut akm = akm_map.get_best(&ap, &sta);
    match key.key_version {
        1 => akm = AkmType::Wpa1,
        2 => match akm {
            // SHA-1 MIC family: FT preserved, everything else collapses to Wpa2Psk.
            // PskSha256/PskSha384 with KDV=2 is a wire-bytes-vs-AKM-IE mismatch;
            // KDV wins because that is what hashcat verifies against.
            AkmType::FtPsk | AkmType::FtPskSha384 => {},
            _ => akm = AkmType::Wpa2Psk,
        },
        3 => match akm {
            // AES-CMAC family: FT preserved, everything else collapses to
            // PskSha256. The AKM-IE-says-Wpa2Psk-but-wire-says-CMAC case (the
            // 11-line edge from the corpus audit) lands here and is corrected.
            AkmType::FtPsk | AkmType::FtPskSha384 => {},
            _ => akm = AkmType::PskSha256,
        },
        // KDV=0 is "derived from AKM" per Table 12-9 -- used by the FT and SAE
        // families. Reserved KDV values (4-7) are non-standard; trust akm_map and
        // let the output stage decide whether the resulting AKM is emittable.
        _ => {},
    }

    // RSN vs WPA (legacy) descriptor type counter. [IEEE 802.11-2024] §12.7.2
    if key.is_rsn {
        stats.eapol_rsn += 1;
    } else {
        stats.eapol_wpa += 1;
    }

    // EAPOL time gap: update max gap between any two messages for this (AP, STA) session.
    // [hcxpcapngtool EAPOLTIME; stored in us, displayed in ms]
    stats.update_eapol_time_gap(ap, sta, timestamp_us);

    // PMKID classification is independent of the EAPOL MIC family. WPA1 has no PMKID
    // in spec, but various consumer router firmware regularly emits an M1
    // with KDV=1 (HMAC-MD5 MIC) AND a PMKID KDE in Key Data: a vendor quirk where
    // the descriptor type is RSN (0x02) but the wire-level MIC algorithm is the
    // legacy WPA1 one. The PMKID itself is still computed with the AKM-defined PRF
    // (HMAC-SHA1 for AKM 2 = Wpa2Psk), not HMAC-MD5, so it remains crackable as
    // a normal Wpa2-PSK PMKID. Promote `Wpa1` -> `Wpa2Psk` for the PMKID-only path
    // so `HashType::from_akm_and_attack(_, is_pmkid=true)` does not drop the line.
    let pmkid_akm = if akm == AkmType::Wpa1 { AkmType::Wpa2Psk } else { akm };

    // M1 PMKID from Key Data KDE. [IEEE 802.11-2024] §12.7.2
    if let Some(pmkid) = key.pmkid {
        if let Some(kind) = stats.check_pmkid_invalid(&pmkid) {
            logger.log_invalid_pmkid(timestamp_us, ap.hex_lower(), sta.hex_lower(), kind, &pmkid);
        }
        if pmkid_store.add(PmkidEntry {
            timestamp: timestamp_us,
            ap,
            sta,
            pmkid,
            source: PmkidSource::M1KeyData,
            akm: pmkid_akm,
            ft: ft.clone(),
        }) {
            stats.pmkids_found += 1;
            if pmkid_akm.is_ft() {
                stats.pmkid_ft_psk += 1;
            } else {
                stats.pmkid_wpa2_psk += 1;
            }
            stats.pmkid_m1 += 1;
        }
    }

    // M2 PMKID from embedded RSN IE in Key Data. [IEEE 802.11-2024] §12.7.2
    if key.msg_type == MsgType::M2 {
        for ie in iter_ies(&key.key_data) {
            if ie.id == 48
                && let Some(rsn) = parse_rsn_ie(ie.value)
            {
                for pmkid in rsn.pmkids {
                    if let Some(kind) = stats.check_pmkid_invalid(&pmkid) {
                        logger.log_invalid_pmkid(timestamp_us, ap.hex_lower(), sta.hex_lower(), kind, &pmkid);
                    }
                    if pmkid_store.add(PmkidEntry {
                        timestamp: timestamp_us,
                        ap,
                        sta,
                        pmkid,
                        source: PmkidSource::M2RsnIe,
                        akm: pmkid_akm,
                        ft: ft.clone(),
                    }) {
                        stats.pmkids_found += 1;
                        if pmkid_akm.is_ft() {
                            stats.pmkid_ft_psk += 1;
                        } else {
                            stats.pmkid_wpa2_psk += 1;
                        }
                        stats.pmkid_m2 += 1;
                    }
                }
            }
        }
    }

    // Per-message-type counters and auth-length maximum.
    let auth_len = key.eapol_frame.len();
    let msg_type = key.msg_type; // save before key is consumed by from_eapol_key
    match msg_type {
        MsgType::M1 => stats.eapol_m1 += 1,
        MsgType::M2 => stats.eapol_m2 += 1,
        MsgType::M3 => stats.eapol_m3 += 1,
        MsgType::M4 => stats.eapol_m4 += 1,
    }
    stats.update_auth_len(msg_type, u16::try_from(auth_len).unwrap_or(u16::MAX));
    // Key Descriptor Version breakdown. [IEEE 802.11-2024] §12.7.2, Key Info bits 0-2.
    stats.record_key_descriptor_version(key.key_version);

    let msg = EapolMessage::from_eapol_key(key, timestamp_us, akm, ft);
    if let Some(cfd) = cross_file_dedup
        && !cfd.check_message(ap, sta, msg.msg_type, msg.akm, &msg.eapol_frame)
    {
        stats.cross_file_dedup_skipped += 1;
        return;
    }
    message_store.add(ap, sta, msg);
}

// --- Unit tests ---

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        missing_docs,
        clippy::wildcard_imports,
        reason = "test module"
    )]

    use super::*;
    use crate::ieee80211::eapol;
    use crate::types::MicBytes;

    // --- mesh_control_len ---

    #[test]
    fn mesh_control_len_no_extension() {
        // Mesh Flags Address Extension Mode = 00 -> 6-byte mesh control header.
        assert_eq!(mesh_control_len(&[0b0000_0000, 0xAA, 0, 0, 0, 0]), Some(6));
    }

    #[test]
    fn mesh_control_len_addr4_extension() {
        // Mode = 01 -> 12-byte header (extra Address 4).
        assert_eq!(mesh_control_len(&[0b0000_0001]), Some(12));
    }

    #[test]
    fn mesh_control_len_addr5_addr6_extension() {
        // Mode = 10 -> 18-byte header (extra Address 5 and Address 6).
        assert_eq!(mesh_control_len(&[0b0000_0010]), Some(18));
    }

    #[test]
    fn mesh_control_len_reserved_returns_none() {
        // Mode = 11 is reserved; caller must skip the frame.
        assert_eq!(mesh_control_len(&[0b0000_0011]), None);
    }

    #[test]
    fn mesh_control_len_empty_body_returns_none() {
        assert_eq!(mesh_control_len(&[]), None);
    }

    // --- is_eapol_llc / is_preauth_llc ---

    #[test]
    fn is_eapol_llc_accepts_888e() {
        let llc = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];
        assert!(is_eapol_llc(&llc));
        assert!(!is_preauth_llc(&llc));
    }

    #[test]
    fn is_eapol_llc_accepts_88c7_preauth() {
        let llc = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0xC7];
        assert!(is_eapol_llc(&llc), "preauth EtherType must pass the EAPOL LLC gate");
        assert!(is_preauth_llc(&llc), "preauth gate must specifically detect 0x88C7");
    }

    #[test]
    fn is_eapol_llc_rejects_other_ethertype() {
        let llc = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]; // IPv4
        assert!(!is_eapol_llc(&llc));
        assert!(!is_preauth_llc(&llc));
    }

    #[test]
    fn is_eapol_llc_rejects_short_body() {
        assert!(!is_eapol_llc(&[0xAA, 0xAA]));
    }

    // --- is_eapol_key_packet (EAPOL Packet Type discriminator) ---

    /// Builds an LLC/SNAP EAPOL header followed by a 1-byte protocol-version field
    /// and the given EAPOL Packet Type byte at MSDU offset 9 (= LLC 8 + EAPOL byte 1).
    fn llc_eapol_with_packet_type(packet_type: u8) -> Vec<u8> {
        vec![
            0xAA,
            0xAA,
            0x03,
            0x00,
            0x00,
            0x00,
            0x88,
            0x8E,        // LLC/SNAP EAPOL
            0x02,        // EAPOL protocol version
            packet_type, // EAPOL Packet Type
            0x00,
            0x00, // Body Length placeholder
        ]
    }

    #[test]
    fn is_eapol_key_packet_accepts_type_3() {
        // EAPOL-Key (type 3) is the only Packet Type that should pass the gate.
        let body = llc_eapol_with_packet_type(3);
        assert!(is_eapol_key_packet(&body));
    }

    #[test]
    fn is_eapol_key_packet_rejects_type_0_eap_packet() {
        // EAP-Packet (type 0) is a legitimate EAPOL frame carrying EAP messages but
        // is not an EAPOL-Key frame; the gate must reject it so EAP-Identity /
        // Success / Failure traffic does not inflate eapol_llc_invalid.
        let body = llc_eapol_with_packet_type(0);
        assert!(!is_eapol_key_packet(&body));
    }

    #[test]
    fn is_eapol_key_packet_rejects_type_1_start_and_type_2_logoff() {
        // EAPOL-Start (1) and EAPOL-Logoff (2) are also legitimate non-key frames.
        assert!(!is_eapol_key_packet(&llc_eapol_with_packet_type(1)));
        assert!(!is_eapol_key_packet(&llc_eapol_with_packet_type(2)));
    }

    #[test]
    fn is_eapol_key_packet_rejects_non_eapol_ethertype() {
        // Wrong EtherType (IPv4) -- gate fails on the LLC check before reading the type.
        let body = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x03];
        assert!(!is_eapol_key_packet(&body));
    }

    #[test]
    fn is_eapol_key_packet_rejects_short_body() {
        // Truncated before the Packet Type byte at offset 9.
        let body = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E, 0x02];
        assert!(!is_eapol_key_packet(&body));
    }

    // --- store_eapol_key: KDV-driven AKM reconciliation ---

    /// Non-uniform 16-byte MIC fixture for tests. The garbage-pattern detector
    /// rejects uniform-byte MICs (`[0xAB, 0xBA, 0x89, 0x98, 0xEF, 0xFE, 0xCD, 0xDC, 0x23, 0x32, 0x01, 0x10, 0x67, 0x76, 0x45, 0x54]` would flag as `repeat_1`); real
    /// MICs are HMAC outputs (uniformly random), so the fixture mirrors that.
    const MIC16_FIXTURE: [u8; 16] =
        [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    /// Non-uniform 24-byte MIC fixture for SHA-384-family tests. Same rationale
    /// as `MIC16_FIXTURE`.
    const MIC24_FIXTURE: [u8; 24] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x12,
        0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
    ];

    fn mac(b: u8) -> MacAddr {
        MacAddr::from_bytes([b; 6])
    }

    /// Builds a minimal EAPOL-Key frame with the given KDV and key data, without LLC/SNAP.
    /// Returns the parsed `EapolKey`.
    fn make_key(kdv: u8, key_ack: bool, install: bool, mic_bytes: [u8; 16], key_data_extra: &[u8]) -> eapol::EapolKey {
        let mut frame = Vec::with_capacity(8 + 99 + key_data_extra.len());
        frame.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);
        frame.push(0x02); // proto ver
        frame.push(0x03); // EAPOL-Key
        let kd_len = key_data_extra.len() as u16;
        frame.extend_from_slice(&(95u16 + kd_len).to_be_bytes());
        frame.push(0x02); // descriptor type RSN
        let mut ki = u16::from(kdv);
        if install {
            ki |= 1 << 6;
        }
        if key_ack {
            ki |= 1 << 7;
        }
        if !key_ack {
            ki |= 1 << 8; // M2/M3/M4 carry MIC
        }
        frame.extend_from_slice(&ki.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x10]);
        frame.extend_from_slice(&[0u8; 8]); // replay
        let mut nonce = [0u8; 32];
        nonce[0] = 0xA5;
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&[0u8; 16]); // IV
        frame.extend_from_slice(&[0u8; 8]); // RSC
        frame.extend_from_slice(&[0u8; 8]); // reserved
        frame.extend_from_slice(&mic_bytes);
        frame.extend_from_slice(&kd_len.to_be_bytes());
        frame.extend_from_slice(key_data_extra);
        eapol::parse(&frame, None).expect("test EAPOL frame must parse")
    }

    // --- insert_essid: control-byte warning ---

    #[test]
    fn insert_essid_clean_ssid_no_warning() {
        // A printable SSID must store and emit no warning.
        let mut essid_map = EssidMap::new();
        let mut stats = Stats::default();
        let mut logger = Logger::new(None).expect("null logger");
        insert_essid(&mut essid_map, mac(0x11), b"WolfNet", 1000, &mut stats, &mut logger);
        assert_eq!(essid_map.resolve(&mac(0x11), 1000), Some(b"WolfNet".as_slice()));
        assert_eq!(stats.essid_control_bytes_warned, 0);
    }

    #[test]
    fn insert_essid_control_byte_in_body_warns_but_stores() {
        // SSID with an embedded control byte (any byte 0x00..=0x1F) must:
        //   1. still be stored (the cracker may recover the right PMK),
        //   2. bump `essid_control_bytes_warned`.
        // First-byte 0 is a separate hidden-network discard and never reaches
        // the warning path; we exercise an embedded control byte.
        let mut essid_map = EssidMap::new();
        let mut stats = Stats::default();
        let mut logger = Logger::new(None).expect("null logger");
        let essid = vec![b'W', b'o', b'l', 0x07, b'f', b'N', b'e', b't']; // BEL byte at index 3
        insert_essid(&mut essid_map, mac(0x12), &essid, 2000, &mut stats, &mut logger);
        assert_eq!(essid_map.resolve(&mac(0x12), 2000), Some(essid.as_slice()), "SSID must still be stored");
        assert_eq!(stats.essid_control_bytes_warned, 1, "warning counter must tick once");
    }

    #[test]
    fn insert_essid_us_byte_is_top_of_control_range_warns() {
        // 0x1F (US, Unit Separator) is the highest byte in the C0 control
        // range; pin the upper bound of the warning gate.
        let mut essid_map = EssidMap::new();
        let mut stats = Stats::default();
        let mut logger = Logger::new(None).expect("null logger");
        let essid = vec![b'A', 0x1F, b'B'];
        insert_essid(&mut essid_map, mac(0x15), &essid, 5000, &mut stats, &mut logger);
        assert_eq!(stats.essid_control_bytes_warned, 1, "0x1F must trip the warning");
    }

    #[test]
    fn insert_essid_space_byte_just_above_control_range_no_warning() {
        // 0x20 (space) is the first printable byte and must NOT trigger.
        let mut essid_map = EssidMap::new();
        let mut stats = Stats::default();
        let mut logger = Logger::new(None).expect("null logger");
        let essid = vec![b'M', b'y', 0x20, b'A', b'P'];
        insert_essid(&mut essid_map, mac(0x16), &essid, 6000, &mut stats, &mut logger);
        assert_eq!(stats.essid_control_bytes_warned, 0, "0x20 (space) is printable; no warning");
    }

    #[test]
    fn insert_essid_short_uniform_no_warning() {
        // A 4-byte all-`0x55` SSID has no control bytes and must NOT warn --
        // the previous garbage-pattern rejection has been retired.
        let mut essid_map = EssidMap::new();
        let mut stats = Stats::default();
        let mut logger = Logger::new(None).expect("null logger");
        insert_essid(&mut essid_map, mac(0x13), &[0x55u8; 4], 3000, &mut stats, &mut logger);
        assert_eq!(essid_map.resolve(&mac(0x13), 3000), Some([0x55u8; 4].as_slice()));
        assert_eq!(stats.essid_control_bytes_warned, 0);
    }

    #[test]
    fn insert_essid_oversized_discarded_no_warning() {
        // 33-byte SSID is > spec max -- discarded by the legacy gate. The
        // control-byte warning path must NOT fire for SSIDs the gate drops.
        let mut essid_map = EssidMap::new();
        let mut stats = Stats::default();
        let mut logger = Logger::new(None).expect("null logger");
        let oversized: Vec<u8> = (0..33u8).map(|i| b'A' + (i % 26)).collect();
        insert_essid(&mut essid_map, mac(0x14), &oversized, 4000, &mut stats, &mut logger);
        assert_eq!(essid_map.resolve(&mac(0x14), 4000), None, "oversized SSID must be discarded");
        assert_eq!(stats.essid_control_bytes_warned, 0);
    }

    #[test]
    fn store_eapol_key_kdv1_routes_to_wpa1() {
        // KDV=1 (HMAC-MD5) MUST collapse to Wpa1 regardless of any AKM-IE map state.
        let key = make_key(1, true, false, [0u8; 16], &[]); // M1, KDV=1
        let mut akm_map = AkmMap::new();
        let mut messages = MessageStore::new();
        let mut pmkids = PmkidStore::new();
        let mut stats = Stats::default();
        let mut logger = Logger::new(None).expect("null logger");
        store_eapol_key(
            key,
            mac(0x11),
            mac(0x22),
            1000,
            &mut akm_map,
            &mut messages,
            &mut pmkids,
            &mut stats,
            &mut logger,
            None,
        );
        let stored = messages.groups().next().unwrap().1;
        assert_eq!(stored[0].akm, AkmType::Wpa1, "KDV=1 must route to Wpa1");
    }

    #[test]
    fn store_eapol_key_kdv2_collapses_to_wpa2psk() {
        // KDV=2 (HMAC-SHA1) collapses any non-FT AKM to Wpa2Psk.
        // RSN IE (tag 48) with PSK AKM (00:0F:AC:02) in M2 Key Data so detect_akm fires.
        let rsn_ie = [
            48u8, 20, // tag 48, len 20
            0x01, 0x00, // RSN version
            0x00, 0x0F, 0xAC, 0x04, // group: CCMP
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, // pairwise: 1x CCMP
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, // AKM: 1x PSK (AKM 2)
            0x00, 0x00, // RSN caps
        ];
        // Varied MIC bytes: a uniform [0xAB, 0xBA, 0x89, 0x98, 0xEF, 0xFE, 0xCD, 0xDC, 0x23, 0x32, 0x01, 0x10, 0x67, 0x76, 0x45, 0x54] would now flag as `repeat_1`
        // garbage and be rejected by the parser. Real MICs are HMAC outputs
        // (uniformly random); the test fixture mirrors that property.
        let mic = MIC16_FIXTURE;
        let key = make_key(2, false, false, mic, &rsn_ie); // M2, KDV=2
        let mut akm_map = AkmMap::new();
        let mut messages = MessageStore::new();
        let mut pmkids = PmkidStore::new();
        let mut stats = Stats::default();
        let mut logger = Logger::new(None).unwrap();
        store_eapol_key(
            key,
            mac(0x11),
            mac(0x22),
            1000,
            &mut akm_map,
            &mut messages,
            &mut pmkids,
            &mut stats,
            &mut logger,
            None,
        );
        let stored = messages.groups().next().unwrap().1;
        assert_eq!(stored[0].akm, AkmType::Wpa2Psk);
    }

    #[test]
    fn store_eapol_key_kdv3_with_psk_sha256_akm_routes_correctly() {
        // KDV=3 (AES-CMAC) with explicit PskSha256 AKM in M2 RSN IE.
        let rsn_ie = [
            48u8, 20, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F,
            0xAC, 0x06, // AKM: PSK-SHA256 (AKM 6)
            0x00, 0x00,
        ];
        let key = make_key(3, false, false, MIC16_FIXTURE, &rsn_ie);
        let mut akm_map = AkmMap::new();
        let mut messages = MessageStore::new();
        let mut pmkids = PmkidStore::new();
        let mut stats = Stats::default();
        let mut logger = Logger::new(None).unwrap();
        store_eapol_key(
            key,
            mac(0x11),
            mac(0x22),
            1000,
            &mut akm_map,
            &mut messages,
            &mut pmkids,
            &mut stats,
            &mut logger,
            None,
        );
        let stored = messages.groups().next().unwrap().1;
        assert_eq!(stored[0].akm, AkmType::PskSha256, "KDV=3 with AKM 6 in IE must route to PskSha256");
    }

    #[test]
    fn store_eapol_key_m1_pmkid_kde_extracted() {
        // M1 with PMKID KDE in Key Data: PMKID must be added to pmkid_store as M1KeyData.
        let pmkid_val: [u8; 16] =
            [0xAB, 0xBA, 0x89, 0x98, 0xEF, 0xFE, 0xCD, 0xDC, 0x23, 0x32, 0x01, 0x10, 0x67, 0x76, 0x45, 0x54];
        let mut kde = vec![0xDD, 0x14, 0x00, 0x0F, 0xAC, 0x04];
        kde.extend_from_slice(&pmkid_val);
        let key = make_key(2, true, false, [0u8; 16], &kde); // M1, KDV=2 + PMKID KDE
        let mut akm_map = AkmMap::new();
        let mut messages = MessageStore::new();
        let mut pmkids = PmkidStore::new();
        let mut stats = Stats::default();
        let mut logger = Logger::new(None).unwrap();
        store_eapol_key(
            key,
            mac(0x11),
            mac(0x22),
            1000,
            &mut akm_map,
            &mut messages,
            &mut pmkids,
            &mut stats,
            &mut logger,
            None,
        );
        assert_eq!(pmkids.total_count(), 1, "M1 PMKID KDE must be stored");
        let entry = pmkids.iter().next().unwrap();
        assert_eq!(entry.pmkid, pmkid_val);
        assert_eq!(entry.source, PmkidSource::M1KeyData);
    }

    #[test]
    fn store_eapol_key_kdv1_with_pmkid_kde_promotes_to_wpa2_for_pmkid_only() {
        // Consumer-router firmware quirk: M1 with KDV=1 (legacy WPA1 MIC) AND a PMKID KDE.
        // The EAPOL must route as Wpa1 (HMAC-MD5 MIC) but the PMKID is computed with
        // HMAC-SHA1 (AKM 2), so the stored PMKID's akm field MUST be Wpa2Psk so it
        // emits as a Type 2 PMKID line. The promotion lives in `store_eapol_key`
        // above (`pmkid_akm = if akm == AkmType::Wpa1 { AkmType::Wpa2Psk } else { akm }`).
        let pmkid_val: [u8; 16] =
            [0xAB, 0xBA, 0x89, 0x98, 0xEF, 0xFE, 0xCD, 0xDC, 0x23, 0x32, 0x01, 0x10, 0x67, 0x76, 0x45, 0x54];
        let mut kde = vec![0xDD, 0x14, 0x00, 0x0F, 0xAC, 0x04];
        kde.extend_from_slice(&pmkid_val);
        let key = make_key(1, true, false, [0u8; 16], &kde);
        let mut akm_map = AkmMap::new();
        let mut messages = MessageStore::new();
        let mut pmkids = PmkidStore::new();
        let mut stats = Stats::default();
        let mut logger = Logger::new(None).unwrap();
        store_eapol_key(
            key,
            mac(0x11),
            mac(0x22),
            1000,
            &mut akm_map,
            &mut messages,
            &mut pmkids,
            &mut stats,
            &mut logger,
            None,
        );
        let stored = messages.groups().next().unwrap().1;
        assert_eq!(stored[0].akm, AkmType::Wpa1, "EAPOL still routes as Wpa1 (KDV=1)");
        let entry = pmkids.iter().next().unwrap();
        assert_eq!(entry.akm, AkmType::Wpa2Psk, "PMKID promoted to Wpa2Psk for Type 2 emission");
    }

    #[test]
    fn store_eapol_key_increments_per_message_counter() {
        let key = make_key(2, true, false, [0u8; 16], &[]); // M1
        let mut akm_map = AkmMap::new();
        let mut messages = MessageStore::new();
        let mut pmkids = PmkidStore::new();
        let mut stats = Stats::default();
        let mut logger = Logger::new(None).unwrap();
        store_eapol_key(
            key,
            mac(0x11),
            mac(0x22),
            1000,
            &mut akm_map,
            &mut messages,
            &mut pmkids,
            &mut stats,
            &mut logger,
            None,
        );
        assert_eq!(stats.eapol_m1, 1);
        assert_eq!(stats.eapol_m2, 0);
    }

    #[test]
    fn store_eapol_key_records_kdv_histogram() {
        let key = make_key(2, true, false, [0u8; 16], &[]);
        let mut akm_map = AkmMap::new();
        let mut messages = MessageStore::new();
        let mut pmkids = PmkidStore::new();
        let mut stats = Stats::default();
        let mut logger = Logger::new(None).unwrap();
        store_eapol_key(
            key,
            mac(0x11),
            mac(0x22),
            1000,
            &mut akm_map,
            &mut messages,
            &mut pmkids,
            &mut stats,
            &mut logger,
            None,
        );
        assert_eq!(stats.eapol_kdv2, 1, "KDV=2 must increment kdv2 counter");
    }

    #[test]
    fn store_eapol_key_preserves_24_byte_mic() {
        // SHA-384 family: 24-B MIC must be carried through to the message store
        // unchanged. Verifies the wire MIC is not silently truncated.
        // Build a 24-B-MIC frame manually because make_key only supports 16-B.
        let mic24: [u8; 24] = MIC24_FIXTURE;
        let mut frame = Vec::with_capacity(8 + 107);
        frame.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);
        frame.push(0x02);
        frame.push(0x03);
        // KDV=0 (SHA-384 family), key_ack=0, mic=1 (M2 path), no key data
        let mut ki: u16 = 0;
        ki |= 1 << 8;
        // For 24-B M2 we need at least 1 byte of key data so the parser routes M2 not M4.
        let key_data_extra = [0x30u8, 0x01, 0xFF];
        let kd_len = key_data_extra.len() as u16;
        // body_len for 24-B MIC = 103 + kd_len
        frame.extend_from_slice(&(103u16 + kd_len).to_be_bytes());
        frame.push(0x02);
        frame.extend_from_slice(&ki.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x10]);
        frame.extend_from_slice(&[0u8; 8]);
        let mut nonce = [0u8; 32];
        nonce[0] = 0xA5;
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&[0u8; 16]);
        frame.extend_from_slice(&[0u8; 8]);
        frame.extend_from_slice(&[0u8; 8]);
        frame.extend_from_slice(&mic24);
        frame.extend_from_slice(&kd_len.to_be_bytes());
        frame.extend_from_slice(&key_data_extra);
        let key = eapol::parse(&frame, None).expect("SHA-384 M2 must parse");
        assert_eq!(key.mic.len(), 24);

        let mut akm_map = AkmMap::new();
        let mut messages = MessageStore::new();
        let mut pmkids = PmkidStore::new();
        let mut stats = Stats::default();
        let mut logger = Logger::new(None).unwrap();
        store_eapol_key(
            key,
            mac(0x11),
            mac(0x22),
            1000,
            &mut akm_map,
            &mut messages,
            &mut pmkids,
            &mut stats,
            &mut logger,
            None,
        );
        let stored = messages.groups().next().unwrap().1;
        assert_eq!(stored[0].mic, MicBytes::from_24(mic24), "24-B MIC must be carried into the store unchanged");
    }
}
