//! Phase 3 -- Extract: Beacon / Probe Response handler (ESSID, AKM, RSN/MLE/RNR/WPS, beacon channel). See ARCHITECTURE.md §3.3.

use crate::ieee80211::{
    frame,
    ie::{
        IE_CISCO_CCX1, IE_COUNTRY, IE_MESH_ID, IE_MULTIPLE_BSSID, IE_REDUCED_NEIGHBOR_REPORT, IE_SSID_LIST,
        IE_TIME_ZONE, OUI_WFA_NEW, WFA_OWE_TRANSITION_TYPE, extract_ccx1_ap_name, extract_country_code,
        extract_ds_channel, extract_mle_basic, extract_owe_transition_ssid, extract_p2p_device_name,
        extract_rnr_bssids, extract_ssid_list, extract_vendor_ap_name, extract_wps_info, iter_ies,
        parse_multiple_bssid, parse_rnr, rnr_is_6ghz_class, vendor_ie_body,
    },
    rsn::{detect_akm, extract_pmkids, extract_rsnxe},
};
use crate::log::Logger;
use crate::stats::Stats;
use crate::store::{
    AkmMap, MldStore,
    auxiliary::{DeviceInfoEntry, DeviceInfoStore, EssidSet, WordlistStore},
    essid::EssidMap,
    pmkid::{PmkidEntry, PmkidStore},
};
use crate::types::{AkmType, MacAddr, PmkidSource};

use super::common::{BEACON_FIXED, SUBTYPE_BEACON};

/// Processes a Beacon or Probe Response management frame body.
///
/// Extracts SSIDs, AKM types, SSID List entries, Country codes, WPS device metadata,
/// Mesh IDs, vendor AP names, OWE Transition SSIDs, Cisco CCX1 AP names, Time Zone
/// strings, and (S16/S17) any non-zero PMKID from the RSN IE PMKID List (vendor
/// firmware deviation). See `ARCHITECTURE.md §8 FR-MGMT-*`.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "beacon handler aggregates many per-call sinks and walks the IE chain multiple times"
)]
pub fn process_beacon_or_probe_resp(
    mac_hdr: &frame::MacHeader,
    body: &[u8],
    timestamp_us: u64,
    essid_map: &mut EssidMap,
    essid_set: &mut EssidSet,
    akm_map: &mut AkmMap,
    mld_store: &mut MldStore,
    pmkid_store: &mut PmkidStore,
    wordlist_store: &mut WordlistStore,
    device_store: &mut DeviceInfoStore,
    stats: &mut Stats,
    logger: &mut Logger,
    populate_wordlist: bool,
    populate_device: bool,
) {
    if mac_hdr.subtype == SUBTYPE_BEACON {
        stats.beacon_frames += 1;
    } else {
        stats.probe_resp_frames += 1;
    }

    // Tagged parameters begin after the fixed fields.
    let ies = body.get(BEACON_FIXED..).unwrap_or(&[]);

    // Beacon channel distribution: DS Parameter Set IE (tag 3) gives the primary channel.
    // Populated for Beacons only (ProbeResp may have a different DS channel). [§9.4.2.4]
    if mac_hdr.subtype == SUBTYPE_BEACON {
        if let Some(ch) = extract_ds_channel(ies) {
            *stats.beacon_channels.entry(ch).or_insert(0) += 1;
        }
    }

    // Extract SSID from IE id=0. [IEEE 802.11-2024] §9.4.2.3
    for ie in iter_ies(ies) {
        if ie.id == 0 {
            // Beacon SSID quality counters (hidden/zeroed/malformed).
            if mac_hdr.subtype == SUBTYPE_BEACON {
                if ie.value.is_empty() {
                    stats.beacon_ssid_wildcard += 1;
                } else if ie.value.len() > 32 {
                    stats.beacon_ssid_oversized += 1;
                } else if ie.value.iter().all(|&b| b == 0) {
                    stats.beacon_ssid_zeroed += 1;
                }
            }
            if !ie.value.is_empty() {
                essid_map.insert(mac_hdr.ap, ie.value.to_vec(), timestamp_us);
                essid_set.insert(ie.value);
                if populate_wordlist {
                    wordlist_store.insert(ie.value.to_vec());
                }
            }
            break;
        }
    }

    // Detect AKM from RSN IE: FT-PSK routes output to mode 37100 (-f). [IEEE 802.11-2024] §12.6.1
    let akm = detect_akm(ies);
    if akm != AkmType::Unknown {
        akm_map.insert(mac_hdr.ap, akm);
    }

    // RSN Extension IE (tag 244) -- diagnostic capability flags. [§9.4.2.241]
    if let Some(rsnxe) = extract_rsnxe(ies) {
        if rsnxe.sae_h2e {
            stats.rsnxe_sae_h2e += 1;
        }
        if rsnxe.sae_pk {
            stats.rsnxe_sae_pk += 1;
        }
        if rsnxe.secure_ltf {
            stats.rsnxe_secure_ltf += 1;
        }
        if rsnxe.protected_twt {
            stats.rsnxe_protected_twt += 1;
        }
    }

    // Reduced Neighbor Report IE (tag 201) -- advertises co-located / neighboring BSSIDs
    // and (commonly) 6 GHz partners for legacy-band beacons. [IEEE 802.11-2024] §9.4.2.170
    for ie in iter_ies(ies) {
        if ie.id == IE_REDUCED_NEIGHBOR_REPORT {
            for info in parse_rnr(ie.value) {
                stats.rnr_blocks_parsed += 1;
                if rnr_is_6ghz_class(info.operating_class) {
                    stats.rnr_6ghz_colocated += 1;
                }
            }
            // Harvest each TBTT Information field's BSSID. The list is metadata only;
            // SSIDs for the neighbors are not advertised inline (a separate Beacon
            // probe is required to learn each neighbor's SSID), so we record presence
            // for visibility / wordlist seeding without claiming an ESSID mapping.
            let bssids = extract_rnr_bssids(ie.value);
            for bssid in &bssids {
                let mac = MacAddr::from_bytes(*bssid);
                if populate_wordlist {
                    wordlist_store.insert(mac.to_hex_lower().into_bytes());
                }
            }
            stats.rnr_bssids_extracted += bssids.len() as u64;
            break; // RNR may appear once per frame.
        }
    }

    // Multi-Link Element (ext tag 107) -- learn link_addr -> MLD_addr mapping so that
    // a client cycling link addresses across 2.4 / 5 / 6 GHz does not splinter into
    // unrelated (AP, STA) groups. [IEEE 802.11be] §9.4.2.321.
    if let Some(mle) = extract_mle_basic(ies) {
        stats.mle_basic_seen += 1;
        let mld_addr = MacAddr::from_bytes(mle.mld_mac);
        if mac_hdr.ap != mld_addr {
            // Only count a new mapping if we actually learned something new.
            let before = mld_store.len();
            mld_store.record(mac_hdr.ap, mld_addr);
            if mld_store.len() > before {
                stats.mle_mld_addrs_learned += 1;
            }
        }
    }

    // Extract SSID List IE (tag 84) entries. [IEEE 802.11-2024] §9.4.2.71
    for ie in iter_ies(ies) {
        if ie.id == IE_SSID_LIST {
            for ssid in extract_ssid_list(ie.value) {
                essid_map.insert(mac_hdr.ap, ssid.clone(), timestamp_us);
                essid_set.insert(&ssid);
                if populate_wordlist {
                    wordlist_store.insert(ssid);
                }
                stats.ssid_list_entries += 1;
            }
        }
    }

    // Extract Country code from IE tag 7. [IEEE 802.11-2024] §9.4.2.9
    if populate_wordlist {
        for ie in iter_ies(ies) {
            if ie.id == IE_COUNTRY {
                if let Some(cc) = extract_country_code(ie.value) {
                    wordlist_store.insert(cc.to_vec());
                    stats.country_codes_extracted += 1;
                }
                break;
            }
        }
    }

    // WPS device metadata extraction for -D and -W.
    if populate_device || populate_wordlist {
        if let Some(wps) = extract_wps_info(ies) {
            // Insert WPS text fields into wordlist for -W output.
            if populate_wordlist {
                for field in
                    [&wps.manufacturer, &wps.model_name, &wps.model_number, &wps.serial_number, &wps.device_name]
                {
                    if !field.is_empty() {
                        wordlist_store.insert(field.clone());
                    }
                }
            }
            // WPS device info for -D output.
            if populate_device {
                let essid = essid_map.resolve(&mac_hdr.ap, timestamp_us).unwrap_or(&[]).to_vec();
                device_store.push(DeviceInfoEntry {
                    mac: mac_hdr.ap,
                    manufacturer: wps.manufacturer,
                    model_name: wps.model_name,
                    model_number: wps.model_number,
                    serial_number: wps.serial_number,
                    device_name: wps.device_name,
                    uuid_e: wps.uuid_e,
                    essid,
                });
            }
        }
    }

    // Mesh ID (IE tag 114) -- network identifier for mesh APs, same semantics as SSID.
    // Goes to essid_map + essid_set + wordlist_store. [IEEE 802.11-2024] §9.4.2.97
    for ie in iter_ies(ies) {
        if ie.id == IE_MESH_ID && !ie.value.is_empty() {
            essid_map.insert(mac_hdr.ap, ie.value.to_vec(), timestamp_us);
            essid_set.insert(ie.value);
            if populate_wordlist {
                wordlist_store.insert(ie.value.to_vec());
            }
            stats.mesh_ids_extracted += 1;
            break;
        }
    }

    // Vendor-specific AP names from enterprise AP vendors (IE 221 with known OUIs).
    // Extracts admin-configured AP hostnames. [Wireshark packet-ieee80211.c]
    if populate_wordlist {
        for ie in iter_ies(ies) {
            if ie.id == 221 {
                if let Some(name) = extract_vendor_ap_name(ie.value) {
                    wordlist_store.insert(name);
                    stats.vendor_ap_names_extracted += 1;
                }
            }
        }
    }

    // OWE Transition Mode SSID -- paired open-network SSID.
    // OUI 50:6F:9A, type 28. [Wi-Fi Alliance OWE Specification §4]
    for ie in iter_ies(ies) {
        if let Some(body) = vendor_ie_body(&ie, OUI_WFA_NEW, WFA_OWE_TRANSITION_TYPE) {
            if let Some(ssid) = extract_owe_transition_ssid(body) {
                essid_map.insert(mac_hdr.ap, ssid.clone(), timestamp_us);
                essid_set.insert(&ssid);
                if populate_wordlist {
                    wordlist_store.insert(ssid);
                }
                stats.owe_transition_ssids += 1;
            }
            break;
        }
    }

    // Cisco CCX1 AP Name (IE tag 133/0x85) -- 16-byte null-padded AP name.
    // [Cisco CCX v1 Specification] §A.3
    if populate_wordlist {
        for ie in iter_ies(ies) {
            if ie.id == IE_CISCO_CCX1 {
                if let Some(name) = extract_ccx1_ap_name(ie.value) {
                    wordlist_store.insert(name);
                    stats.ccx1_ap_names_extracted += 1;
                }
                break;
            }
        }
    }

    // Time Zone IE (tag 98) -- ASCII POSIX timezone string.
    // [IEEE 802.11-2024] §9.4.2.85
    if populate_wordlist {
        for ie in iter_ies(ies) {
            if ie.id == IE_TIME_ZONE && !ie.value.is_empty() {
                wordlist_store.insert(ie.value.to_vec());
                stats.time_zones_extracted += 1;
                break;
            }
        }
    }

    // Multiple BSSID element (tag 71): a transmitted-BSSID Beacon advertises one or
    // more nontransmitted-BSSID profiles. Each profile carries its own SSID and the
    // sub-BSSID is synthesized from MaxBSSID Indicator + Multiple BSSID-Index per
    // [IEEE 802.11-2024] §35.2.2. Register the (sub_bssid, sub_ssid) pair into the
    // ESSID map so handshakes captured against the sub-BSSID resolve to the right
    // SSID at hash-emission time.
    for ie in iter_ies(ies) {
        if ie.id == IE_MULTIPLE_BSSID {
            let profiles = parse_multiple_bssid(ie.value, mac_hdr.ap.0);
            for profile in profiles {
                let sub_mac = MacAddr::from_bytes(profile.bssid);
                if !profile.ssid.is_empty() {
                    essid_map.insert(sub_mac, profile.ssid.clone(), timestamp_us);
                    essid_set.insert(&profile.ssid);
                    if populate_wordlist {
                        wordlist_store.insert(profile.ssid.clone());
                    }
                }
                stats.multiple_bssid_profiles += 1;
            }
            break;
        }
    }

    // P2P (Wi-Fi Direct) Device Name from WFA vendor IE (OUI 50:6F:9A type 9).
    // [Wi-Fi Alliance Wi-Fi Direct Specification, P2P IE attribute 3]
    if populate_wordlist {
        for ie in iter_ies(ies) {
            if let Some(name) = extract_p2p_device_name(&ie) {
                wordlist_store.insert(name);
                stats.p2p_device_names_extracted += 1;
            }
        }
    }

    // RSN IE PMKID extraction (S16/S17): per [IEEE 802.11-2024] §9.4.2.24.5, PMKID Count
    // should be 0 in AP-originated frames, but some vendor firmware emits non-zero values.
    // Capture all non-zero PMKIDs without filtering.
    let pmkids = extract_pmkids(ies);
    if !pmkids.is_empty() {
        let akm = akm_map.get(&mac_hdr.ap);
        let source =
            if mac_hdr.subtype == SUBTYPE_BEACON { PmkidSource::BeaconRsnIe } else { PmkidSource::ProbeRespRsnIe };
        for pmkid in pmkids {
            if let Some(kind) = stats.check_pmkid_invalid(&pmkid) {
                logger.log_invalid_pmkid(timestamp_us, &mac_hdr.ap.to_hex_lower(), &mac_hdr.sta.to_hex_lower(), kind);
            }
            pmkid_store.add(PmkidEntry {
                timestamp: timestamp_us,
                ap: mac_hdr.ap,
                sta: mac_hdr.sta, // typically broadcast for Beacon; directed for ProbeResp
                pmkid,
                source,
                akm,
                ft: None,
            });
            stats.pmkids_found += 1;
            if akm.is_ft() {
                stats.pmkid_ft_psk += 1;
            } else {
                stats.pmkid_wpa2_psk += 1;
            }
            if mac_hdr.subtype == SUBTYPE_BEACON {
                stats.pmkid_beacon += 1;
            } else {
                stats.pmkid_probe_resp += 1;
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
    use super::super::common::SUBTYPE_PROBE_RESP;
    use super::*;
    use crate::log::Logger;
    use crate::store::pmkid::PmkidStore;

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

    // S16 -- Beacon with RSN IE PMKID Count=1, non-zero PMKID -> BeaconRsnIe.
    #[test]
    fn t13_10k_beacon_rsn_pmkid_extracted() {
        let pmkid = [0x16u8; 16];
        let mut body = vec![0u8; 12];
        body.extend_from_slice(&rsn_ie_tagged(pmkid));

        let mac_hdr = frame::MacHeader {
            ap: MacAddr::from_bytes([0x11; 6]),
            sta: MacAddr::from_bytes([0xFF; 6]),
            frame_type: frame::TYPE_MANAGEMENT,
            subtype: SUBTYPE_BEACON,
            protected: false,
            body_offset: 24,
            direction: frame::FrameDirection::Ibss,
            more_fragments: false,
            sequence_number: 0,
            fragment_number: 0,
            is_amsdu: false,
            mesh_control_present: false,
        };

        let mut store = PmkidStore::new();
        let mut akm_map = AkmMap::new();
        let mut mld_store = MldStore::new();
        let mut essid_map = EssidMap::new();
        let mut essid_set = EssidSet::new();
        let mut wl = WordlistStore::new();
        let mut device_store = DeviceInfoStore::new();
        let mut stats = Stats::new();
        let mut logger = Logger::new(None).unwrap();

        process_beacon_or_probe_resp(
            &mac_hdr,
            &body,
            0,
            &mut essid_map,
            &mut essid_set,
            &mut akm_map,
            &mut mld_store,
            &mut store,
            &mut wl,
            &mut device_store,
            &mut stats,
            &mut logger,
            false,
            false,
        );

        assert_eq!(store.total_count(), 1);
        assert_eq!(store.iter().next().unwrap().source, PmkidSource::BeaconRsnIe);
        assert_eq!(stats.pmkid_beacon, 1);
    }

    // S16 -- Beacon with all-zero PMKID -> rejected by store.
    #[test]
    fn t13_10l_beacon_rsn_zero_pmkid_rejected() {
        let pmkid = [0u8; 16];
        let mut body = vec![0u8; 12];
        body.extend_from_slice(&rsn_ie_tagged(pmkid));

        let mac_hdr = frame::MacHeader {
            ap: MacAddr::from_bytes([0x11; 6]),
            sta: MacAddr::from_bytes([0xFF; 6]),
            frame_type: frame::TYPE_MANAGEMENT,
            subtype: SUBTYPE_BEACON,
            protected: false,
            body_offset: 24,
            direction: frame::FrameDirection::Ibss,
            more_fragments: false,
            sequence_number: 0,
            fragment_number: 0,
            is_amsdu: false,
            mesh_control_present: false,
        };

        let mut store = PmkidStore::new();
        let mut akm_map = AkmMap::new();
        let mut mld_store = MldStore::new();
        let mut essid_map = EssidMap::new();
        let mut essid_set = EssidSet::new();
        let mut wl = WordlistStore::new();
        let mut device_store = DeviceInfoStore::new();
        let mut stats = Stats::new();
        let mut logger = Logger::new(None).unwrap();

        process_beacon_or_probe_resp(
            &mac_hdr,
            &body,
            0,
            &mut essid_map,
            &mut essid_set,
            &mut akm_map,
            &mut mld_store,
            &mut store,
            &mut wl,
            &mut device_store,
            &mut stats,
            &mut logger,
            false,
            false,
        );

        assert_eq!(store.total_count(), 0);
    }

    // S17 -- Probe Response with PMKID Count=1 -> ProbeRespRsnIe.
    #[test]
    fn t13_10m_probe_resp_rsn_pmkid_extracted() {
        let pmkid = [0x17u8; 16];
        let mut body = vec![0u8; 12];
        body.extend_from_slice(&rsn_ie_tagged(pmkid));

        let mac_hdr = frame::MacHeader {
            ap: MacAddr::from_bytes([0x11; 6]),
            sta: MacAddr::from_bytes([0x22; 6]),
            frame_type: frame::TYPE_MANAGEMENT,
            subtype: SUBTYPE_PROBE_RESP,
            protected: false,
            body_offset: 24,
            direction: frame::FrameDirection::Ibss,
            more_fragments: false,
            sequence_number: 0,
            fragment_number: 0,
            is_amsdu: false,
            mesh_control_present: false,
        };

        let mut store = PmkidStore::new();
        let mut akm_map = AkmMap::new();
        let mut mld_store = MldStore::new();
        let mut essid_map = EssidMap::new();
        let mut essid_set = EssidSet::new();
        let mut wl = WordlistStore::new();
        let mut device_store = DeviceInfoStore::new();
        let mut stats = Stats::new();
        let mut logger = Logger::new(None).unwrap();

        process_beacon_or_probe_resp(
            &mac_hdr,
            &body,
            0,
            &mut essid_map,
            &mut essid_set,
            &mut akm_map,
            &mut mld_store,
            &mut store,
            &mut wl,
            &mut device_store,
            &mut stats,
            &mut logger,
            false,
            false,
        );

        assert_eq!(store.total_count(), 1);
        assert_eq!(store.iter().next().unwrap().source, PmkidSource::ProbeRespRsnIe);
        assert_eq!(stats.pmkid_probe_resp, 1);
    }
}
