//! Phase 3 -- Extract: Probe Request handler (probe-ESSID set, WPS, S14/S15 PMKID). See ARCHITECTURE.md §3.3 + §6.

use crate::ieee80211::{
    frame,
    ft::extract_ft_fields,
    ie::{IE_SSID_LIST, extract_ssid_list, extract_wps_info, iter_ies},
    rsn::extract_pmkids,
};
use crate::log::Logger;
use crate::stats::Stats;
use crate::store::{
    AkmMap,
    auxiliary::{EssidSet, ProbeEssidSet, WordlistStore},
    essid::EssidMap,
    pmkid::{PmkidEntry, PmkidStore},
};
use crate::types::PmkidSource;

use super::common::{BROADCAST_MAC, insert_essid};

/// Processes a Probe Request management frame body.
///
/// Extracts SSIDs (IE id=0 and SSID List IE), WPS device metadata, and (S14/S15)
/// PMKIDs from any RSN IE PMKID List. IEs start at `body[0]` (no fixed fields).
/// Directed probe requests (non-broadcast DA) update the ESSID map; broadcast probes
/// only update the global ESSID set. See `ARCHITECTURE.md §8 FR-MGMT-*`.
pub fn process_probe_req(
    mac_hdr: &frame::MacHeader,
    body: &[u8],
    timestamp_us: u64,
    essid_map: &mut EssidMap,
    essid_set: &mut EssidSet,
    probe_essid_set: &mut ProbeEssidSet,
    akm_map: &AkmMap,
    pmkid_store: &mut PmkidStore,
    wordlist_store: &mut WordlistStore,
    stats: &mut Stats,
    logger: &mut Logger,
    populate_wordlist: bool,
) {
    let is_directed = mac_hdr.ap.0 != BROADCAST_MAC;
    if is_directed {
        stats.probe_req_directed += 1;
    } else {
        stats.probe_req_undirected += 1;
    }

    // IEs start immediately in Probe Request (no fixed fields). [IEEE 802.11-2024] §9.3.3.9
    // Probe Request SSIDs populate both `probe_essid_set` (-R) and `essid_set` (-E) --
    // hcxpcapngtool's -E output is every entry in its internal AP list, which
    // includes all probe-request SSIDs (see `hcxtools/hcxpcapngtool.c:1204`
    // vs the `ST_PROBE_REQ` branch at line 1205); matching that inventory makes
    // wpawolf's -E a superset of hcx's. Directed probes additionally update
    // `essid_map` for PMK derivation at hash-line emit time.
    for ie in iter_ies(body) {
        if ie.id == 0 && !ie.value.is_empty() {
            // Directed Probe Requests: BSSID (addr3) in mac_hdr.ap identifies the target AP.
            // [IEEE 802.11-2024] §9.3.3.9
            if is_directed {
                insert_essid(essid_map, mac_hdr.ap, ie.value, timestamp_us, stats, logger);
            }
            essid_set.insert(ie.value);
            probe_essid_set.insert(ie.value);
            if populate_wordlist {
                wordlist_store.insert(ie.value.to_vec());
            }
            break;
        }
    }

    // Extract SSID List IE (tag 84) entries. [IEEE 802.11-2024] §9.4.2.71
    for ie in iter_ies(body) {
        if ie.id == IE_SSID_LIST {
            for ssid in extract_ssid_list(ie.value) {
                if is_directed {
                    insert_essid(essid_map, mac_hdr.ap, &ssid, timestamp_us, stats, logger);
                }
                essid_set.insert(&ssid);
                probe_essid_set.insert(&ssid);
                if populate_wordlist {
                    wordlist_store.insert(ssid);
                }
                stats.ssid_list_entries += 1;
            }
        }
    }

    // WPS metadata from Probe Requests -- client device names/models.
    // Probe Request WPS IEs describe the *sending STA*, not the AP, so the
    // row never lands in -D. The text-bearing WPS columns plus UUID-E (hex)
    // are routed to -W. The STA MAC itself is *not* seeded -- it is a device
    // identifier, not password-equivalent text.
    if populate_wordlist && let Some(wps) = extract_wps_info(body) {
        for field in [&wps.manufacturer, &wps.model_name, &wps.model_number, &wps.serial_number, &wps.device_name] {
            if !field.is_empty() {
                wordlist_store.insert(field.clone());
            }
        }
        if let Some(uuid) = wps.uuid_e.as_ref() {
            wordlist_store.insert(crate::types::bytes_to_hex_string(uuid).into_bytes());
        }
        // Every other text- or credential-bearing WPS attribute observed
        // in this Probe Request body -- including any leaked Network Key
        // / OOB Device Password / Credential bundle. See `parse_wps_body`.
        for value in &wps.wordlist_values {
            wordlist_store.insert(value.clone());
        }
        stats.wps_probe_req_extracted += 1;
    }

    // RSN IE PMKID extraction (S14/S15): rare but spec-valid when STA offers a
    // cached PMKSA in a directed Probe Request. Broadcast probes with RSN IE are
    // stored with ap=BROADCAST_MAC (no ESSID match, still valid for cracking).
    // [IEEE 802.11-2024] §9.4.2.24.5 Note, §12.6.8.3
    let pmkids = extract_pmkids(body);
    if !pmkids.is_empty() {
        let akm = akm_map.get(&mac_hdr.ap);
        let ft = extract_ft_fields(body).map(Box::new);
        for pmkid in pmkids {
            if let Some(kind) = stats.check_pmkid_invalid(&pmkid)
                && kind != "null"
            {
                logger.log_invalid_pmkid(mac_hdr.ap.hex_lower(), mac_hdr.sta.hex_lower(), kind, &pmkid);
            }
            if pmkid_store.add(PmkidEntry {
                timestamp: timestamp_us,
                ap: mac_hdr.ap,
                sta: mac_hdr.sta,
                pmkid,
                source: PmkidSource::ProbeRequest,
                akm,
                ft: if akm.is_ft() { ft.clone() } else { None },
            }) {
                stats.pmkids_found += 1;
                if akm.is_ft() {
                    stats.pmkid_ft_psk += 1;
                } else {
                    stats.pmkid_wpa2_psk += 1;
                }
                stats.pmkid_probe_req += 1;
            }
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
    use crate::ieee80211::rsn::extract_pmkids_from_osen;
    use crate::log::Logger;
    use crate::store::pmkid::PmkidStore;
    use crate::types::MacAddr;

    fn rsn_ie_tagged(pmkid: [u8; 16]) -> Vec<u8> {
        let mut rsn = Vec::new();
        rsn.extend_from_slice(&[0x01, 0x00]);
        rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]);
        rsn.extend_from_slice(&[0x01, 0x00]);
        rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]);
        rsn.extend_from_slice(&[0x01, 0x00]);
        rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x02]);
        rsn.extend_from_slice(&[0x00, 0x00]);
        rsn.extend_from_slice(&[0x01, 0x00]);
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

    // S14 -- Probe Request with RSN IE PMKID Count=1 extracts ProbeRequest.
    #[test]
    fn t13_10i_probe_req_pmkid_extracted() {
        let pmkid = [0x14, 0x05, 0x36, 0x27, 0x50, 0x41, 0x72, 0x63, 0x9C, 0x8D, 0xBE, 0xAF, 0xD8, 0xC9, 0xFA, 0xEB];
        let body = rsn_ie_tagged(pmkid);

        let mac_hdr = dummy_mac_hdr([0x11; 6], [0x22; 6]);
        let mut store = PmkidStore::new();
        let akm_map = AkmMap::new();
        let mut essid_map = EssidMap::new();
        let mut essid_set = EssidSet::new();
        let mut probe_essid_set = ProbeEssidSet::new();
        let mut wl = WordlistStore::new();
        let mut stats = Stats::new();
        let mut logger = Logger::new(None).unwrap();

        process_probe_req(
            &mac_hdr,
            &body,
            0,
            &mut essid_map,
            &mut essid_set,
            &mut probe_essid_set,
            &akm_map,
            &mut store,
            &mut wl,
            &mut stats,
            &mut logger,
            false,
        );

        assert_eq!(store.total_count(), 1);
        let entry = store.iter().next().unwrap();
        assert_eq!(entry.source, PmkidSource::ProbeRequest);
        assert_eq!(entry.pmkid, pmkid);
        assert_eq!(stats.pmkid_probe_req, 1);
    }

    // S15 -- Probe Request with RSN IE PMKID Count=0 -> zero entries.
    #[test]
    fn t13_10j_probe_req_no_pmkid_zero_entries() {
        let mut rsn = Vec::new();
        rsn.extend_from_slice(&[0x01, 0x00]);
        rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]);
        rsn.extend_from_slice(&[0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04]);
        rsn.extend_from_slice(&[0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02]);
        rsn.extend_from_slice(&[0x00, 0x00]);
        rsn.extend_from_slice(&[0x00, 0x00]); // PMKID count=0
        let mut body = vec![48u8, rsn.len() as u8];
        body.extend_from_slice(&rsn);

        let mac_hdr = dummy_mac_hdr([0x11; 6], [0x22; 6]);
        let mut store = PmkidStore::new();
        let akm_map = AkmMap::new();
        let mut essid_map = EssidMap::new();
        let mut essid_set = EssidSet::new();
        let mut probe_essid_set = ProbeEssidSet::new();
        let mut wl = WordlistStore::new();
        let mut stats = Stats::new();
        let mut logger = Logger::new(None).unwrap();

        process_probe_req(
            &mac_hdr,
            &body,
            0,
            &mut essid_map,
            &mut essid_set,
            &mut probe_essid_set,
            &akm_map,
            &mut store,
            &mut wl,
            &mut stats,
            &mut logger,
            false,
        );
        assert_eq!(store.total_count(), 0);
    }

    fn wps_ie_tagged(manufacturer: &[u8], uuid_e: Option<[u8; 16]>) -> Vec<u8> {
        // WPS vendor IE: tag 221, OUI 00:50:F2, type 0x04, then BE TLV attrs.
        let mut body = vec![0x00, 0x50, 0xF2, 0x04];
        body.extend_from_slice(&0x1021u16.to_be_bytes());
        body.extend_from_slice(&(manufacturer.len() as u16).to_be_bytes());
        body.extend_from_slice(manufacturer);
        if let Some(uuid) = uuid_e {
            body.extend_from_slice(&0x1047u16.to_be_bytes());
            body.extend_from_slice(&16u16.to_be_bytes());
            body.extend_from_slice(&uuid);
        }
        let mut tagged = vec![221u8, body.len() as u8];
        tagged.extend_from_slice(&body);
        tagged
    }

    // STA-side WPS in a Probe Request: text columns and UUID-E (hex) must
    // reach -W. The STA MAC itself is intentionally *not* seeded -- it is a
    // device identifier, not password-equivalent text. No -D row is written
    // for probe-side WPS (it describes the client, not an AP).
    #[test]
    fn probe_req_wps_wordlist_includes_uuid_hex_but_not_sta_mac() {
        let uuid: [u8; 16] =
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        let body = wps_ie_tagged(b"AcmeSTA", Some(uuid));

        let mac_hdr = dummy_mac_hdr([0xFF; 6], [0xCD; 6]); // broadcast probe; STA = 0xCD
        let mut store = PmkidStore::new();
        let akm_map = AkmMap::new();
        let mut essid_map = EssidMap::new();
        let mut essid_set = EssidSet::new();
        let mut probe_essid_set = ProbeEssidSet::new();
        let mut wl = WordlistStore::new();
        let mut stats = Stats::new();
        let mut logger = Logger::new(None).unwrap();

        process_probe_req(
            &mac_hdr,
            &body,
            0,
            &mut essid_map,
            &mut essid_set,
            &mut probe_essid_set,
            &akm_map,
            &mut store,
            &mut wl,
            &mut stats,
            &mut logger,
            true,
        );

        let entries: Vec<&[u8]> = wl.iter().map(Vec::as_slice).collect();
        assert!(entries.iter().any(|e| *e == b"AcmeSTA"), "manufacturer in wordlist: {entries:?}");
        assert!(!entries.iter().any(|e| *e == b"cdcdcdcdcdcd"), "STA MAC must not be in wordlist: {entries:?}");
        assert!(
            entries.iter().any(|e| *e == b"0123456789abcdeffedcba9876543210"),
            "UUID-E hex in wordlist: {entries:?}"
        );
        assert_eq!(stats.wps_probe_req_extracted, 1);
    }

    // S20 -- Assoc Request with OSEN IE containing PMKID -> OsenIe (helper test).
    #[test]
    fn t13_10q_osen_ie_pmkid_extracted() {
        let pmkid = [0x20, 0x31, 0x02, 0x13, 0x64, 0x75, 0x46, 0x57, 0xA8, 0xB9, 0x8A, 0x9B, 0xEC, 0xFD, 0xCE, 0xDF];
        let mut rsn_body = Vec::new();
        rsn_body.extend_from_slice(&[0x01, 0x00]);
        rsn_body.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]);
        rsn_body.extend_from_slice(&[0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04]);
        rsn_body.extend_from_slice(&[0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02]);
        rsn_body.extend_from_slice(&[0x00, 0x00]);
        rsn_body.extend_from_slice(&[0x01, 0x00]);
        rsn_body.extend_from_slice(&pmkid);
        let mut osen_value = vec![0x50, 0x6F, 0x9A, 0x12];
        osen_value.extend_from_slice(&rsn_body);

        let pmkids = extract_pmkids_from_osen(&osen_value);
        assert_eq!(pmkids.len(), 1);
        assert_eq!(pmkids[0], pmkid);
    }

    // S20 -- OSEN IE with wrong OUI -> no extraction.
    #[test]
    fn t13_10r_osen_ie_wrong_oui_no_extraction() {
        let osen_value = vec![0x50, 0x6F, 0x9B, 0x12, 0x01, 0x00];
        assert!(extract_pmkids_from_osen(&osen_value).is_empty());
    }
}
