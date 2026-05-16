//! Phase 3 -- Extract: Action frame handler (FT, Mesh Peering, FILS Discovery, GAS/ANQP). See ARCHITECTURE.md §3.3 + §6.

use crate::ieee80211::{
    anqp, frame,
    ft::extract_ft_fields,
    ie::{IE_MESH_ID, iter_ies},
    rsn::extract_pmkids,
};
use crate::log::Logger;
use crate::stats::Stats;
use crate::store::{
    auxiliary::{EssidSet, ProbeEssidSet, WordlistStore},
    essid::EssidMap,
    pmkid::{PmkidEntry, PmkidStore},
};
use crate::types::{AkmType, MacAddr, PmkidSource};

use super::common::insert_essid;

// Action frame constants
/// Action Category: Radio Measurement. [IEEE 802.11-2024] §9.6.6, Table 9-81
const ACTION_CAT_RADIO_MEAS: u8 = 5;
/// Radio Measurement Action: Neighbor Report Request. [IEEE 802.11-2024] §9.6.6.6
const ACTION_NR_REQ: u8 = 4;
/// Neighbor Report Request fixed fields: Category(1) + Action(1) + DialogToken(1).
const ACTION_NR_REQ_FIXED: usize = 3;

/// Action Category: Public Action. [IEEE 802.11-2024] §9.6.7, Table 9-81
const ACTION_CAT_PUBLIC: u8 = 4;
/// Public Action: FILS Discovery. [IEEE 802.11-2024] §9.6.7.36
const ACTION_PUBLIC_FILS_DISCOVERY: u8 = 34;

/// Public Action: GAS Initial Request. [IEEE 802.11-2024] §9.6.7.13
const ACTION_PUBLIC_GAS_INITIAL_REQUEST: u8 = 10;
/// Public Action: GAS Initial Response. [IEEE 802.11-2024] §9.6.7.14
const ACTION_PUBLIC_GAS_INITIAL_RESPONSE: u8 = 11;
/// Public Action: GAS Comeback Request. [IEEE 802.11-2024] §9.6.7.15
const ACTION_PUBLIC_GAS_COMEBACK_REQUEST: u8 = 12;
/// Public Action: GAS Comeback Response. [IEEE 802.11-2024] §9.6.7.16
const ACTION_PUBLIC_GAS_COMEBACK_RESPONSE: u8 = 13;
/// Byte offset of FILS Discovery Frame Control within `body`:
/// Category(1) + Action(1) = 2 bytes. [IEEE 802.11-2024] §9.6.7.36
const FILS_DISCOVERY_FC_OFFSET: usize = 2;
/// Byte offset where SSID/Short SSID starts within `body`:
/// Category(1) + Action(1) + FrameControl(2) + Timestamp(8) + BeaconInterval(2) = 14.
/// [IEEE 802.11-2024] §9.6.7.36
const FILS_DISCOVERY_SSID_OFFSET: usize = 14;
/// Short SSID Indicator: bit 6 of FILS Discovery Frame Control. [IEEE 802.11-2024] §9.6.7.36
const FILS_DISCOVERY_FC_SHORT_SSID: u16 = 0x0040;
/// SSID Length mask: bits 0-4 of FILS Discovery Frame Control. Value is (`actual_length` - 1).
/// [IEEE 802.11-2024] §9.6.7.36
const FILS_DISCOVERY_FC_SSID_LEN_MASK: u16 = 0x001F;

/// Action Category: Fast BSS Transition (FT). [IEEE 802.11-2024] §9.6.7, Table 9-81
const ACTION_CAT_FT: u8 = 6;
/// FT Action: FT Request. [IEEE 802.11-2024] §9.6.7.3
const ACTION_FT_REQUEST: u8 = 1;
/// FT Action: FT Response. [IEEE 802.11-2024] §9.6.7.4
const ACTION_FT_RESPONSE: u8 = 2;
/// FT Action: FT Confirm. [IEEE 802.11-2024] §9.6.7.5
const ACTION_FT_CONFIRM: u8 = 3;
/// Byte count of the fixed header before IEs in FT Request/Confirm bodies:
/// Category(1) + Action(1) + STA Address(6) + Target AP Address(6) = 14.
const ACTION_FT_FIXED: usize = 14;
/// Byte count of the fixed header before IEs in FT Response bodies:
/// Category(1) + Action(1) + STA Address(6) + Target AP Address(6) + Status Code(2) = 16.
const ACTION_FT_RESPONSE_FIXED: usize = 16;

/// Action Category: Self-Protected (Mesh). [IEEE 802.11-2024] §9.6.15, Table 9-81
const ACTION_CAT_SELF_PROTECTED: u8 = 15;
/// Self-Protected Action: Mesh Peering Open. [IEEE 802.11-2024] §9.6.15.2
const ACTION_MESH_PEER_OPEN: u8 = 1;
/// Self-Protected Action: Mesh Peering Confirm. [IEEE 802.11-2024] §9.6.15.3
const ACTION_MESH_PEER_CONFIRM: u8 = 2;
/// AMPE element ID: Authenticated Mesh Peering Exchange. [IEEE 802.11-2024] §9.4.2.113
pub const IE_AMPE: u8 = 139;

/// Processes an Action management frame body.
///
/// Handles SSID-bearing and PMKID-bearing Action frame categories:
/// - Category 5 (Radio Measurement), Action 4 (Neighbor Report Request): SSID.
///   [IEEE 802.11-2024] §9.6.6.6
/// - Category 4 (Public Action), Action 34 (FILS Discovery): SSID.
///   [IEEE 802.11-2024] §9.6.7.36
/// - Category 6 (Fast BSS Transition), Actions 1/2/3: PMKID from RSN IE.
///   [IEEE 802.11-2024] §13.8.5, §9.6.7.3-5
/// - Category 15 (Self-Protected), Actions 1/2 (Mesh Peering Open/Confirm):
///   PMKID from AMPE element "Chosen PMK" field. [IEEE 802.11-2024] §9.6.15.2-3, §14.3.5
///
/// Other categories are counted but not extracted from.
pub fn process_action(
    mac_hdr: &frame::MacHeader,
    body: &[u8],
    timestamp_us: u64,
    essid_map: &mut EssidMap,
    essid_set: &mut EssidSet,
    probe_essid_set: &mut ProbeEssidSet,
    wordlist_store: &mut WordlistStore,
    populate_wordlist: bool,
    pmkid_store: &mut PmkidStore,
    stats: &mut Stats,
    logger: &mut Logger,
) {
    stats.action_frames += 1;
    if body.len() < 2 {
        return;
    }
    let Some(&category) = body.first() else { return };
    let Some(&action_code) = body.get(1) else { return };

    // --- FT Action frames (category 6) -- PMKID from RSN IE (S11-S13) ---
    // [IEEE 802.11-2024] §13.8.5, §9.6.7.3 (Request), §9.6.7.4 (Response), §9.6.7.5 (Confirm)
    if category == ACTION_CAT_FT
        && (action_code == ACTION_FT_REQUEST || action_code == ACTION_FT_RESPONSE || action_code == ACTION_FT_CONFIRM)
    {
        stats.action_ft_frames += 1;
        if body.len() < ACTION_FT_FIXED {
            return;
        }
        // body[2..8] = STA Address, body[8..14] = Target AP Address.
        let sta_addr_bytes: [u8; 6] = body.get(2..8).and_then(|s| s.try_into().ok()).unwrap_or([0u8; 6]);
        let target_ap_bytes: [u8; 6] = body.get(8..14).and_then(|s| s.try_into().ok()).unwrap_or([0u8; 6]);
        let sta_addr = MacAddr::from_bytes(sta_addr_bytes);
        let target_ap = MacAddr::from_bytes(target_ap_bytes);
        // The embedded STA / Target AP MACs are not seeded into -W: MAC
        // addresses are device identifiers, not password-equivalent text.
        // They are still used below as the (ap, sta) pair for PMKID storage.
        // FT Response has a 2-byte Status Code after the fixed 14-byte header.
        let ie_offset = if action_code == ACTION_FT_RESPONSE { ACTION_FT_RESPONSE_FIXED } else { ACTION_FT_FIXED };
        let ies = body.get(ie_offset..).unwrap_or(&[]);
        let pmkids = extract_pmkids(ies);
        if !pmkids.is_empty() {
            let ft = extract_ft_fields(ies);
            let (ap, sta, source) = match action_code {
                ACTION_FT_REQUEST => (target_ap, sta_addr, PmkidSource::FtActionRequest),
                ACTION_FT_RESPONSE => (mac_hdr.ap, sta_addr, PmkidSource::FtActionResponse),
                _ /* ACTION_FT_CONFIRM */ => (target_ap, sta_addr, PmkidSource::FtActionConfirm),
            };
            for pmkid in pmkids {
                if let Some(kind) = stats.check_pmkid_invalid(&pmkid) {
                    logger.log_invalid_pmkid(timestamp_us, ap.hex_lower(), sta.hex_lower(), kind, &pmkid);
                }
                if pmkid_store.add(PmkidEntry {
                    timestamp: timestamp_us,
                    ap,
                    sta,
                    pmkid,
                    source,
                    akm: AkmType::FtPsk,
                    ft,
                }) {
                    stats.pmkids_found += 1;
                    stats.pmkid_ft_psk += 1;
                    stats.pmkid_ft_action += 1;
                }
            }
        }
        return;
    }

    // --- Mesh Peering Open/Confirm (category 15) ---
    // Extracts Mesh ID (tag 114) for -E/-W wordlist and PMKID from AMPE element (S18-S19).
    // [IEEE 802.11-2024] §9.6.15.2-3, §9.4.2.39, §14.3.5, Figure 14-16
    if category == ACTION_CAT_SELF_PROTECTED
        && (action_code == ACTION_MESH_PEER_OPEN || action_code == ACTION_MESH_PEER_CONFIRM)
    {
        stats.action_mesh_peering += 1;
        // IEs start at body[2..] (Category + Action = 2 bytes).
        let ies = body.get(2..).unwrap_or(&[]);
        for ie in iter_ies(ies) {
            if ie.id == IE_MESH_ID && !ie.value.is_empty() {
                // Mesh ID is the network name for this mesh BSS. Goes to -E (essid_set)
                // and -W (wordlist). Not in -R (client-side). [IEEE 802.11-2024] §9.4.2.39
                insert_essid(essid_map, mac_hdr.ap, ie.value, timestamp_us, stats, logger);
                essid_set.insert(ie.value);
                if populate_wordlist {
                    wordlist_store.insert(ie.value.to_vec());
                }
                stats.mesh_ids_extracted += 1;
            } else if ie.id == IE_AMPE && ie.value.len() >= 16 {
                // "Chosen PMK" = last 16 bytes of AMPE body. [§14.3.5, Figure 14-16]
                // Wireshark: `if (tag_len - offset == 16)` after fixed fields.
                // [packet-ieee80211.c:36270]
                let pmkid_bytes: [u8; 16] =
                    ie.value.get(ie.value.len() - 16..).and_then(|s| s.try_into().ok()).unwrap_or([0u8; 16]);
                let source = if action_code == ACTION_MESH_PEER_OPEN {
                    PmkidSource::MeshPeeringOpen
                } else {
                    PmkidSource::MeshPeeringConfirm
                };
                if let Some(kind) = stats.check_pmkid_invalid(&pmkid_bytes) {
                    logger.log_invalid_pmkid(
                        timestamp_us,
                        mac_hdr.ap.hex_lower(),
                        mac_hdr.sta.hex_lower(),
                        kind,
                        &pmkid_bytes,
                    );
                }
                if pmkid_store.add(PmkidEntry {
                    timestamp: timestamp_us,
                    ap: mac_hdr.ap,
                    sta: mac_hdr.sta,
                    pmkid: pmkid_bytes,
                    source,
                    akm: AkmType::Unknown,
                    ft: None,
                }) {
                    stats.pmkids_found += 1;
                    stats.pmkid_wpa2_psk += 1;
                    stats.pmkid_mesh += 1;
                }
                break; // Only one AMPE element per frame.
            }
        }
        return;
    }

    if category == ACTION_CAT_RADIO_MEAS && action_code == ACTION_NR_REQ {
        // Category 5 = Radio Measurement, Action 4 = Neighbor Report Request.
        // The NR Request carries an optional SSID element identifying the network
        // the STA wants neighbor information for. [IEEE 802.11-2024] §9.6.6.6
        if body.len() < ACTION_NR_REQ_FIXED {
            return;
        }
        let ies = body.get(ACTION_NR_REQ_FIXED..).unwrap_or(&[]);
        for ie in iter_ies(ies) {
            if ie.id == 0 && !ie.value.is_empty() {
                // NR Request is client-side -- the STA names the network it wants neighbors for.
                // Goes to probe_essid_set (-R), not essid_set (-E).
                insert_essid(essid_map, mac_hdr.ap, ie.value, timestamp_us, stats, logger);
                probe_essid_set.insert(ie.value);
                if populate_wordlist {
                    wordlist_store.insert(ie.value.to_vec());
                }
                stats.action_nr_req_ssids += 1;
                break;
            }
        }
    } else if category == ACTION_CAT_PUBLIC
        && (action_code == ACTION_PUBLIC_GAS_INITIAL_REQUEST
            || action_code == ACTION_PUBLIC_GAS_INITIAL_RESPONSE
            || action_code == ACTION_PUBLIC_GAS_COMEBACK_REQUEST
            || action_code == ACTION_PUBLIC_GAS_COMEBACK_RESPONSE)
    {
        // GAS / ANQP Public Action frames. The Query Response payload on GAS
        // Initial Response carries ANQP TLVs: Venue Name, Domain Name List, NAI Realm,
        // and Hotspot 2.0 vendor-specific Operator Friendly Name. Only the Initial
        // Response yields a usable single-shot payload; Comeback frames carry
        // fragmented data we do not reassemble in v1.
        // [IEEE 802.11-2024] §9.6.7.13-16
        stats.anqp_gas_frames += 1;
        if action_code == ACTION_PUBLIC_GAS_INITIAL_RESPONSE {
            if anqp::is_fragmented_response(body) {
                stats.anqp_fragmented_skipped += 1;
            } else if let Some(qr) = anqp::strip_gas_fixed_fields(body) {
                let (fragments, counts) = anqp::parse_query_response(qr);
                stats.anqp_venue_name += counts.venue_name;
                stats.anqp_domain_name += counts.domain_name;
                stats.anqp_nai_realm += counts.nai_realm;
                stats.anqp_hs_operator_friendly_name += counts.hs_operator_friendly_name;
                stats.anqp_unknown_info_id += counts.unknown_info_id;
                if populate_wordlist {
                    for entry in fragments.wordlist_entries {
                        wordlist_store.insert(entry);
                    }
                }
            }
        } else if action_code == ACTION_PUBLIC_GAS_COMEBACK_RESPONSE {
            // Fragmented payload arriving as a continuation -- not reassembled in v1.
            stats.anqp_fragmented_skipped += 1;
        }
        // Initial/Comeback Request frames carry a query, not a response -- the
        // query IDs are not useful wordlist input, so we only count the frame.
    } else if category == ACTION_CAT_PUBLIC && action_code == ACTION_PUBLIC_FILS_DISCOVERY {
        // FILS Discovery: AP-transmitted Public Action frame carrying either a full SSID
        // or a 4-byte Short SSID (CRC32). We only extract full SSIDs -- Short SSIDs are
        // not crackable. [IEEE 802.11-2024] §9.6.7.36
        //
        // Body layout:
        //   [0]      Category (4)
        //   [1]      Public Action (34)
        //   [2..4]   FILS Discovery Frame Control (u16 LE)
        //   [4..12]  Timestamp (8 bytes)
        //   [12..14] Beacon Interval (2 bytes)
        //   [14..]   SSID (variable) or Short SSID (4 bytes)
        if body.len() < FILS_DISCOVERY_SSID_OFFSET {
            return;
        }
        // Frame Control: 2 bytes, little-endian. [IEEE 802.11-2024] §9.6.7.36, Figure 9-1017
        let Some(&fc_lo) = body.get(FILS_DISCOVERY_FC_OFFSET) else { return };
        let Some(&fc_hi) = body.get(FILS_DISCOVERY_FC_OFFSET + 1) else { return };
        let fc = u16::from_le_bytes([fc_lo, fc_hi]);
        if fc & FILS_DISCOVERY_FC_SHORT_SSID != 0 {
            // Short SSID (CRC32, 4 bytes) -- not a crackable full SSID, skip.
            return;
        }
        // SSID Length field (bits 0-4) encodes (actual_length - 1), giving range 1..=32.
        // [IEEE 802.11-2024] §9.6.7.36
        let ssid_len = usize::from((fc & FILS_DISCOVERY_FC_SSID_LEN_MASK) + 1);
        let ssid_end = FILS_DISCOVERY_SSID_OFFSET + ssid_len;
        if body.len() < ssid_end {
            return;
        }
        let Some(ssid_bytes) = body.get(FILS_DISCOVERY_SSID_OFFSET..ssid_end) else { return };
        let ssid = ssid_bytes.to_vec();
        // The AP transmits FILS Discovery -- its BSSID is in Address 3 (mac_hdr.ap).
        insert_essid(essid_map, mac_hdr.ap, &ssid, timestamp_us, stats, logger);
        essid_set.insert(&ssid);
        if populate_wordlist {
            wordlist_store.insert(ssid);
        }
        stats.fils_discovery_ssids += 1;
    } else if category == 127 {
        // Category 127 = Vendor Specific. Apple AWDL uses OUI 00:17:F2.
        // [Apple AWDL Protocol; hcxpcapngtool AWDL detection]
        if body.get(2..5) == Some(&[0x00, 0x17, 0xF2]) {
            stats.awdl_frames += 1;
        }
    }
}

// --- Unit tests ---

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::missing_docs_in_private_items,
        clippy::wildcard_imports,
        reason = "relaxed lints for test code"
    )]
    use super::super::common::SUBTYPE_AUTH;
    use super::*;
    use crate::log::Logger;
    use crate::store::pmkid::PmkidStore;
    use crate::types::MacAddr;

    // Helper: build a minimal RSN IE tagged parameter block with one PMKID.
    fn rsn_ie_tagged(pmkid: [u8; 16]) -> Vec<u8> {
        let mut rsn = Vec::new();
        rsn.extend_from_slice(&[0x01, 0x00]); // version=1
        rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // group cipher CCMP
        rsn.extend_from_slice(&[0x01, 0x00]); // pairwise count=1
        rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // CCMP pairwise
        rsn.extend_from_slice(&[0x01, 0x00]); // AKM count=1
        rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x02]); // AKM PSK
        rsn.extend_from_slice(&[0x00, 0x00]); // RSN capabilities
        rsn.extend_from_slice(&[0x01, 0x00]); // PMKID count=1
        rsn.extend_from_slice(&pmkid);
        let mut tagged = vec![48u8, rsn.len() as u8];
        tagged.extend_from_slice(&rsn);
        tagged
    }

    fn dummy_mac_hdr(ap: [u8; 6], sta: [u8; 6]) -> frame::MacHeader {
        frame::MacHeader {
            ap: MacAddr::from_bytes(ap),
            sta: MacAddr::from_bytes(sta),
            frame_type: frame::TYPE_MANAGEMENT,
            subtype: SUBTYPE_AUTH,
            protected: false,
            body_offset: 24,
            direction: frame::FrameDirection::Ibss,
            more_fragments: false,
            sequence_number: 0,
            fragment_number: 0,
            is_amsdu: false,
            mesh_control_present: false,
        }
    }

    // S11 -- FT Action Request (cat=6, action=1) extracts FtActionRequest.
    #[test]
    fn t13_10f_ft_action_request_pmkid_extracted() {
        let pmkid = [0x11, 0x00, 0x33, 0x22, 0x55, 0x44, 0x77, 0x66, 0x99, 0x88, 0xBB, 0xAA, 0xDD, 0xCC, 0xFF, 0xEE];
        let sta = [0xAAu8; 6];
        let target_ap = [0xBBu8; 6];
        let mut body = Vec::new();
        body.push(6); // category=6 FT
        body.push(1); // action=1 FT Request
        body.extend_from_slice(&sta);
        body.extend_from_slice(&target_ap);
        body.extend_from_slice(&rsn_ie_tagged(pmkid));

        let mac_hdr = dummy_mac_hdr([0x33; 6], [0xAA; 6]);
        let mut store = PmkidStore::new();
        let mut stats = Stats::new();

        let mut essid_map = EssidMap::new();
        let mut essid_set = EssidSet::new();
        let mut wl = WordlistStore::new();
        let mut probe_essid_set_test = ProbeEssidSet::new();
        let mut logger = Logger::new(None).unwrap();
        process_action(
            &mac_hdr,
            &body,
            0,
            &mut essid_map,
            &mut essid_set,
            &mut probe_essid_set_test,
            &mut wl,
            false,
            &mut store,
            &mut stats,
            &mut logger,
        );

        assert_eq!(store.total_count(), 1);
        let entry = store.iter().next().unwrap();
        assert_eq!(entry.source, PmkidSource::FtActionRequest);
        assert_eq!(entry.ap.0, target_ap);
        assert_eq!(entry.sta.0, sta);
        assert_eq!(stats.action_ft_frames, 1);
        assert_eq!(stats.pmkid_ft_action, 1);
    }

    // S12 -- FT Action Response (cat=6, action=2) with Status Code.
    #[test]
    fn t13_10g_ft_action_response_pmkid_extracted() {
        let pmkid = [0x12, 0x03, 0x30, 0x21, 0x56, 0x47, 0x74, 0x65, 0x9A, 0x8B, 0xB8, 0xA9, 0xDE, 0xCF, 0xFC, 0xED];
        let sta = [0xCCu8; 6];
        let target_ap = [0xDDu8; 6];
        let mut body = Vec::new();
        body.push(6);
        body.push(2);
        body.extend_from_slice(&sta);
        body.extend_from_slice(&target_ap);
        body.extend_from_slice(&0u16.to_le_bytes()); // status=0
        body.extend_from_slice(&rsn_ie_tagged(pmkid));

        let mac_hdr = dummy_mac_hdr([0x33; 6], [0xCC; 6]);
        let mut store = PmkidStore::new();
        let mut stats = Stats::new();
        let mut essid_map = EssidMap::new();
        let mut essid_set = EssidSet::new();
        let mut wl = WordlistStore::new();
        let mut probe_essid_set_test = ProbeEssidSet::new();
        let mut logger = Logger::new(None).unwrap();
        process_action(
            &mac_hdr,
            &body,
            0,
            &mut essid_map,
            &mut essid_set,
            &mut probe_essid_set_test,
            &mut wl,
            false,
            &mut store,
            &mut stats,
            &mut logger,
        );

        assert_eq!(store.total_count(), 1);
        let entry = store.iter().next().unwrap();
        assert_eq!(entry.source, PmkidSource::FtActionResponse);
        assert_eq!(entry.ap.0, [0x33; 6]); // mac_hdr.ap for FT Response
    }

    // S13 -- FT Action Confirm (cat=6, action=3).
    #[test]
    fn t13_10h_ft_action_confirm_pmkid_extracted() {
        let pmkid = [0x13, 0x02, 0x31, 0x20, 0x57, 0x46, 0x75, 0x64, 0x9B, 0x8A, 0xB9, 0xA8, 0xDF, 0xCE, 0xFD, 0xEC];
        let sta = [0xEEu8; 6];
        let target_ap = [0xFFu8; 6];
        let mut body = Vec::new();
        body.push(6);
        body.push(3);
        body.extend_from_slice(&sta);
        body.extend_from_slice(&target_ap);
        body.extend_from_slice(&rsn_ie_tagged(pmkid));

        let mac_hdr = dummy_mac_hdr([0x33; 6], [0xEE; 6]);
        let mut store = PmkidStore::new();
        let mut stats = Stats::new();
        let mut essid_map = EssidMap::new();
        let mut essid_set = EssidSet::new();
        let mut wl = WordlistStore::new();
        let mut probe_essid_set_test = ProbeEssidSet::new();
        let mut logger = Logger::new(None).unwrap();
        process_action(
            &mac_hdr,
            &body,
            0,
            &mut essid_map,
            &mut essid_set,
            &mut probe_essid_set_test,
            &mut wl,
            false,
            &mut store,
            &mut stats,
            &mut logger,
        );

        assert_eq!(store.total_count(), 1);
        assert_eq!(store.iter().next().unwrap().source, PmkidSource::FtActionConfirm);
    }

    // S18 -- Mesh Peering Open (cat=15, action=1) with AMPE element.
    #[test]
    fn t13_10n_mesh_peering_open_pmkid_extracted() {
        let chosen_pmk =
            [0x18, 0x09, 0x3A, 0x2B, 0x5C, 0x4D, 0x7E, 0x6F, 0x90, 0x81, 0xB2, 0xA3, 0xD4, 0xC5, 0xF6, 0xE7];
        let ampe_val: Vec<u8> = [0xDEu8, 0xAD, 0xBE, 0xEF].iter().copied().chain(chosen_pmk).collect();
        let mut body = vec![15u8, 1u8];
        body.push(IE_AMPE);
        body.push(ampe_val.len() as u8);
        body.extend_from_slice(&ampe_val);

        let mac_hdr = dummy_mac_hdr([0x11; 6], [0x22; 6]);
        let mut store = PmkidStore::new();
        let mut stats = Stats::new();
        let mut essid_map = EssidMap::new();
        let mut essid_set = EssidSet::new();
        let mut wl = WordlistStore::new();

        let mut probe_essid_set_test = ProbeEssidSet::new();
        let mut logger = Logger::new(None).unwrap();
        process_action(
            &mac_hdr,
            &body,
            0,
            &mut essid_map,
            &mut essid_set,
            &mut probe_essid_set_test,
            &mut wl,
            false,
            &mut store,
            &mut stats,
            &mut logger,
        );

        assert_eq!(store.total_count(), 1);
        let entry = store.iter().next().unwrap();
        assert_eq!(entry.source, PmkidSource::MeshPeeringOpen);
        assert_eq!(entry.pmkid, chosen_pmk);
        assert_eq!(stats.pmkid_mesh, 1);
        assert_eq!(stats.action_mesh_peering, 1);
    }

    // S19 -- Mesh Peering Confirm (cat=15, action=2).
    #[test]
    fn t13_10o_mesh_peering_confirm_pmkid_extracted() {
        let chosen_pmk =
            [0x19, 0x08, 0x3B, 0x2A, 0x5D, 0x4C, 0x7F, 0x6E, 0x91, 0x80, 0xB3, 0xA2, 0xD5, 0xC4, 0xF7, 0xE6];
        let ampe_val: Vec<u8> = [0xABu8, 0xCD].iter().copied().chain(chosen_pmk).collect();
        let mut body = vec![15u8, 2u8];
        body.push(IE_AMPE);
        body.push(ampe_val.len() as u8);
        body.extend_from_slice(&ampe_val);

        let mac_hdr = dummy_mac_hdr([0x11; 6], [0x22; 6]);
        let mut store = PmkidStore::new();
        let mut stats = Stats::new();
        let mut essid_map = EssidMap::new();
        let mut essid_set = EssidSet::new();
        let mut wl = WordlistStore::new();

        let mut probe_essid_set_test = ProbeEssidSet::new();
        let mut logger = Logger::new(None).unwrap();
        process_action(
            &mac_hdr,
            &body,
            0,
            &mut essid_map,
            &mut essid_set,
            &mut probe_essid_set_test,
            &mut wl,
            false,
            &mut store,
            &mut stats,
            &mut logger,
        );

        assert_eq!(store.total_count(), 1);
        assert_eq!(store.iter().next().unwrap().source, PmkidSource::MeshPeeringConfirm);
    }

    // FT Action body carries embedded STA Address and Target AP Address
    // (body[2..14]). Neither is seeded into -W: MAC addresses are device
    // identifiers, not password-equivalent text. The (ap, sta) pair is still
    // used internally for PMKID storage.
    #[test]
    fn ft_action_request_mac_addresses_not_in_wordlist() {
        let pmkid = [0x44, 0x55, 0x66, 0x77, 0x00, 0x11, 0x22, 0x33, 0xCC, 0xDD, 0xEE, 0xFF, 0x88, 0x99, 0xAA, 0xBB];
        let sta = [0x12u8, 0x34, 0x56, 0x78, 0x9A, 0xBC];
        let target_ap = [0xDEu8, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let mut body = Vec::new();
        body.push(6); // category=6 FT
        body.push(1); // action=1 FT Request
        body.extend_from_slice(&sta);
        body.extend_from_slice(&target_ap);
        body.extend_from_slice(&rsn_ie_tagged(pmkid));

        let mac_hdr = dummy_mac_hdr([0x33; 6], [0x44; 6]);
        let mut store = PmkidStore::new();
        let mut stats = Stats::new();
        let mut essid_map = EssidMap::new();
        let mut essid_set = EssidSet::new();
        let mut wl = WordlistStore::new();
        let mut probe_essid_set_test = ProbeEssidSet::new();
        let mut logger = Logger::new(None).unwrap();
        process_action(
            &mac_hdr,
            &body,
            0,
            &mut essid_map,
            &mut essid_set,
            &mut probe_essid_set_test,
            &mut wl,
            true, // populate_wordlist on
            &mut store,
            &mut stats,
            &mut logger,
        );

        let entries: Vec<&[u8]> = wl.iter().map(Vec::as_slice).collect();
        assert!(!entries.iter().any(|e| *e == b"123456789abc"), "STA MAC must not be in -W: {entries:?}");
        assert!(!entries.iter().any(|e| *e == b"deadbeefcafe"), "Target AP MAC must not be in -W: {entries:?}");
        // PMKID extraction still happens; the embedded MACs are used internally
        // as the (ap, sta) pair for the PmkidEntry but not seeded into -W.
        assert_eq!(stats.pmkids_found, 1);
    }

    // The same body with -W off must not populate the wordlist even though
    // PMKID extraction still happens.
    #[test]
    fn ft_action_request_no_wordlist_when_flag_off() {
        let pmkid = [0x55, 0x44, 0x77, 0x66, 0x11, 0x00, 0x33, 0x22, 0xDD, 0xCC, 0xFF, 0xEE, 0x99, 0x88, 0xBB, 0xAA];
        let mut body = Vec::new();
        body.push(6);
        body.push(1);
        body.extend_from_slice(&[0xAAu8; 6]); // sta
        body.extend_from_slice(&[0xBBu8; 6]); // target_ap
        body.extend_from_slice(&rsn_ie_tagged(pmkid));

        let mac_hdr = dummy_mac_hdr([0x33; 6], [0x44; 6]);
        let mut store = PmkidStore::new();
        let mut stats = Stats::new();
        let mut essid_map = EssidMap::new();
        let mut essid_set = EssidSet::new();
        let mut wl = WordlistStore::new();
        let mut probe_essid_set_test = ProbeEssidSet::new();
        let mut logger = Logger::new(None).unwrap();
        process_action(
            &mac_hdr,
            &body,
            0,
            &mut essid_map,
            &mut essid_set,
            &mut probe_essid_set_test,
            &mut wl,
            false,
            &mut store,
            &mut stats,
            &mut logger,
        );

        assert!(wl.is_empty(), "-W off must not populate wordlist");
        assert_eq!(store.total_count(), 1);
    }

    // S18 -- AMPE element < 16 bytes -> skipped, no extraction.
    #[test]
    fn t13_10p_ampe_too_short_no_extraction() {
        let mut body = vec![15u8, 1u8];
        body.push(IE_AMPE);
        body.push(15); // only 15 bytes -- not enough for 16-byte Chosen PMK
        body.extend_from_slice(&[0xFFu8; 15]);

        let mac_hdr = dummy_mac_hdr([0x11; 6], [0x22; 6]);
        let mut store = PmkidStore::new();
        let mut stats = Stats::new();
        let mut essid_map = EssidMap::new();
        let mut essid_set = EssidSet::new();
        let mut wl = WordlistStore::new();

        let mut probe_essid_set_test = ProbeEssidSet::new();
        let mut logger = Logger::new(None).unwrap();
        process_action(
            &mac_hdr,
            &body,
            0,
            &mut essid_map,
            &mut essid_set,
            &mut probe_essid_set_test,
            &mut wl,
            false,
            &mut store,
            &mut stats,
            &mut logger,
        );
        assert_eq!(store.total_count(), 0);
    }
}
