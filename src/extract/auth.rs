//! Phase 3 -- Extract: Authentication handler (FT / FILS / PASN); S5-S10 PMKID extraction. See ARCHITECTURE.md §3.3 + §6.

use crate::ieee80211::{frame, ft::extract_ft_fields, rsn::extract_pmkids};
use crate::log::Logger;
use crate::stats::Stats;
use crate::store::{
    AkmMap,
    pmkid::{PmkidEntry, PmkidStore},
};
use crate::types::{AkmType, PmkidSource};

/// Extracts PMKIDs from a Fast BSS Transition Authentication frame body (algo=2).
///
/// Called for Authentication frames where `algo == 2` (FBT). Parses the IE list
/// starting at `body[6..]` (past the 6-byte fixed header) for RSN IE (PMKID List),
/// MDE (tag 54), and FTE (tag 55). FT-PSK PMKIDs with FT context are stored with
/// `AkmType::FtPsk`; direction is determined by the sequence number.
/// Per [IEEE 802.11-2024] §13.8.3, §9.4.2.45 (MDE), §9.4.2.46 (FTE).
#[allow(clippy::too_many_arguments, reason = "auth handler aggregates pmkid sinks plus structured log")]
pub fn process_auth_ft(
    mac_hdr: &frame::MacHeader,
    seq: u16,
    body: &[u8],
    timestamp_us: u64,
    pmkid_store: &mut PmkidStore,
    akm_map: &AkmMap,
    stats: &mut Stats,
    logger: &mut Logger,
) {
    if body.len() < 6 {
        return;
    }
    // Fixed header: algo(2) + seq(2) + status(2) = 6 bytes; IEs follow.
    let ies = body.get(6..).unwrap_or(&[]);
    let pmkids = extract_pmkids(ies);
    if pmkids.is_empty() {
        return;
    }
    let ft = extract_ft_fields(ies);
    // seq=1: STA->AP, mac_hdr.ap = BSSID = AP, mac_hdr.sta = addr2 = STA. [§13.8.3]
    // seq=2: AP->STA, mac_hdr.ap = BSSID = AP, mac_hdr.sta = addr2 = AP (not the STA).
    let (ap, sta, source) = if seq == 1 {
        (mac_hdr.ap, mac_hdr.sta, PmkidSource::FtAuthStaToAp)
    } else {
        (mac_hdr.ap, mac_hdr.sta, PmkidSource::FtAuthApToSta)
    };
    // Use beacon-detected AKM or fall back to FtPsk since algo=2 implies FT.
    let akm = {
        let a = akm_map.get(&ap);
        if a == AkmType::Unknown { AkmType::FtPsk } else { a }
    };
    for pmkid in pmkids {
        if let Some(kind) = stats.check_pmkid_invalid(&pmkid) {
            logger.log_invalid_pmkid(timestamp_us, ap.hex_lower(), sta.hex_lower(), kind);
        }
        pmkid_store.add(PmkidEntry { timestamp: timestamp_us, ap, sta, pmkid, source, akm, ft });
        stats.pmkids_found += 1;
        stats.pmkid_ft_psk += 1;
        stats.pmkid_ft_auth += 1;
    }
}

/// Extracts PMKIDs from a FILS Authentication frame body (algo=4/5/6).
///
/// Called for Authentication frames where `algo` is 4, 5, or 6 (FILS variants).
/// Parses the IE list for RSN IE PMKID List. FILS PMKIDs are not PSK-crackable
/// but are captured for completeness. Per [IEEE 802.11-2024] §12.11.2.3.2-3.4.
#[allow(clippy::too_many_arguments, reason = "auth handler aggregates pmkid sinks plus structured log")]
pub fn process_auth_fils(
    mac_hdr: &frame::MacHeader,
    seq: u16,
    body: &[u8],
    timestamp_us: u64,
    pmkid_store: &mut PmkidStore,
    akm_map: &AkmMap,
    stats: &mut Stats,
    logger: &mut Logger,
) {
    if body.len() < 6 {
        return;
    }
    let ies = body.get(6..).unwrap_or(&[]);
    let pmkids = extract_pmkids(ies);
    if pmkids.is_empty() {
        return;
    }
    let (ap, sta, source) = if seq == 1 {
        (mac_hdr.ap, mac_hdr.sta, PmkidSource::FilsAuthStaToAp)
    } else {
        (mac_hdr.ap, mac_hdr.sta, PmkidSource::FilsAuthApToSta)
    };
    let akm = akm_map.get(&ap);
    for pmkid in pmkids {
        if let Some(kind) = stats.check_pmkid_invalid(&pmkid) {
            logger.log_invalid_pmkid(timestamp_us, ap.hex_lower(), sta.hex_lower(), kind);
        }
        pmkid_store.add(PmkidEntry { timestamp: timestamp_us, ap, sta, pmkid, source, akm, ft: None });
        stats.pmkids_found += 1;
        if akm.is_ft() {
            stats.pmkid_ft_psk += 1;
        } else {
            stats.pmkid_wpa2_psk += 1;
        }
        stats.pmkid_fils_auth += 1;
    }
}

/// Extracts PMKIDs from a PASN Authentication frame body (unknown algorithm).
///
/// Called for Authentication frames with algorithm values not matching any known
/// type. All such values may be PASN base-AKMP values. Per [IEEE 802.11-2024] §12.13.1-2.
#[allow(clippy::too_many_arguments, reason = "auth handler aggregates pmkid sinks plus structured log")]
pub fn process_auth_pasn(
    mac_hdr: &frame::MacHeader,
    seq: u16,
    body: &[u8],
    timestamp_us: u64,
    pmkid_store: &mut PmkidStore,
    akm_map: &AkmMap,
    stats: &mut Stats,
    logger: &mut Logger,
) {
    if body.len() < 6 {
        return;
    }
    let ies = body.get(6..).unwrap_or(&[]);
    let pmkids = extract_pmkids(ies);
    if pmkids.is_empty() {
        return;
    }
    let (ap, sta, source) = if seq == 1 {
        (mac_hdr.ap, mac_hdr.sta, PmkidSource::PasnAuthStaToAp)
    } else {
        (mac_hdr.ap, mac_hdr.sta, PmkidSource::PasnAuthApToSta)
    };
    let akm = akm_map.get(&ap);
    for pmkid in pmkids {
        if let Some(kind) = stats.check_pmkid_invalid(&pmkid) {
            logger.log_invalid_pmkid(timestamp_us, ap.hex_lower(), sta.hex_lower(), kind);
        }
        pmkid_store.add(PmkidEntry { timestamp: timestamp_us, ap, sta, pmkid, source, akm, ft: None });
        stats.pmkids_found += 1;
        if akm.is_ft() {
            stats.pmkid_ft_psk += 1;
        } else {
            stats.pmkid_wpa2_psk += 1;
        }
        stats.pmkid_pasn_auth += 1;
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

    fn ft_auth_body(seq: u16, pmkid: [u8; 16]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&2u16.to_le_bytes()); // algo=2 FBT
        body.extend_from_slice(&seq.to_le_bytes()); // seq number
        body.extend_from_slice(&0u16.to_le_bytes()); // status=0
        body.extend_from_slice(&rsn_ie_tagged(pmkid));
        // MDE: id=54, len=3, MDID=[0x12,0x34], FT-cap=0x00
        body.extend_from_slice(&[54, 3, 0x12, 0x34, 0x00]);
        // FTE: id=55, minimal 82 bytes (MIC ctrl + MIC + ANonce + SNonce)
        let mut fte_val = vec![0u8; 82];
        fte_val.extend_from_slice(&[3, 4, 0xAA, 0xBB, 0xCC, 0xDD]);
        fte_val.extend_from_slice(&[1, 6, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        body.push(55);
        body.push(fte_val.len() as u8);
        body.extend_from_slice(&fte_val);
        body
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

    // S5 -- FT Auth seq=1 (STA->AP) with RSN PMKID, MDE, FTE.
    #[test]
    fn t13_10a_ft_auth_seq1_pmkid_extracted() {
        let pmkid = [0xABu8; 16];
        let ap = [0x11u8; 6];
        let sta = [0x22u8; 6];
        let mac_hdr = dummy_mac_hdr(ap, sta);
        let body = ft_auth_body(1, pmkid);
        let mut store = PmkidStore::new();
        let akm_map = AkmMap::new();
        let mut stats = Stats::new();

        let mut logger = Logger::new(None).unwrap();
        process_auth_ft(&mac_hdr, 1, &body, 0, &mut store, &akm_map, &mut stats, &mut logger);

        assert_eq!(store.total_count(), 1);
        let entry = store.iter().next().unwrap();
        assert_eq!(entry.pmkid, pmkid);
        assert_eq!(entry.source, PmkidSource::FtAuthStaToAp);
        assert!(entry.ft.is_some());
        assert_eq!(entry.ft.unwrap().mdid, [0x12, 0x34]);
        assert_eq!(stats.pmkid_ft_auth, 1);
    }

    // S6 -- FT Auth seq=2 (AP->STA) extracts FtAuthApToSta.
    #[test]
    fn t13_10b_ft_auth_seq2_source_ap_to_sta() {
        let pmkid = [0xCDu8; 16];
        let mac_hdr = dummy_mac_hdr([0x11; 6], [0x22; 6]);
        let body = ft_auth_body(2, pmkid);
        let mut store = PmkidStore::new();
        let akm_map = AkmMap::new();
        let mut stats = Stats::new();

        let mut logger = Logger::new(None).unwrap();
        process_auth_ft(&mac_hdr, 2, &body, 0, &mut store, &akm_map, &mut stats, &mut logger);

        assert_eq!(store.total_count(), 1);
        let entry = store.iter().next().unwrap();
        assert_eq!(entry.source, PmkidSource::FtAuthApToSta);
        assert!(entry.ft.is_some());
    }

    // S7 -- FILS Auth seq=1 with 2 PMKIDs.
    #[test]
    fn t13_10c_fils_auth_seq1_two_pmkids() {
        let mut rsn = Vec::new();
        rsn.extend_from_slice(&[0x01, 0x00]); // version=1
        rsn.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // group cipher
        rsn.extend_from_slice(&[0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04]); // pairwise
        rsn.extend_from_slice(&[0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02]); // AKM PSK
        rsn.extend_from_slice(&[0x00, 0x00]); // RSN capabilities
        rsn.extend_from_slice(&[0x02, 0x00]); // PMKID count=2
        rsn.extend_from_slice(&[0x01u8; 16]);
        rsn.extend_from_slice(&[0x02u8; 16]);
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_le_bytes()); // algo=4 FILS
        body.extend_from_slice(&1u16.to_le_bytes()); // seq=1
        body.extend_from_slice(&0u16.to_le_bytes()); // status=0
        body.push(48u8);
        body.push(rsn.len() as u8);
        body.extend_from_slice(&rsn);

        let mac_hdr = dummy_mac_hdr([0x11; 6], [0x22; 6]);
        let mut store = PmkidStore::new();
        let akm_map = AkmMap::new();
        let mut stats = Stats::new();

        let mut logger = Logger::new(None).unwrap();
        process_auth_fils(&mac_hdr, 1, &body, 0, &mut store, &akm_map, &mut stats, &mut logger);

        assert_eq!(store.total_count(), 2);
        assert!(store.iter().all(|e| e.source == PmkidSource::FilsAuthStaToAp));
        assert_eq!(stats.pmkid_fils_auth, 2);
    }

    // S8 -- FILS Auth seq=2 gives FilsAuthApToSta.
    #[test]
    fn t13_10d_fils_auth_seq2_source_ap_to_sta() {
        let pmkid = [0x05u8; 16];
        let mut body = Vec::new();
        body.extend_from_slice(&5u16.to_le_bytes()); // algo=5 FILS+PFS
        body.extend_from_slice(&2u16.to_le_bytes()); // seq=2
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&rsn_ie_tagged(pmkid));

        let mac_hdr = dummy_mac_hdr([0x11; 6], [0x22; 6]);
        let mut store = PmkidStore::new();
        let akm_map = AkmMap::new();
        let mut stats = Stats::new();

        let mut logger = Logger::new(None).unwrap();
        process_auth_fils(&mac_hdr, 2, &body, 0, &mut store, &akm_map, &mut stats, &mut logger);

        assert_eq!(store.total_count(), 1);
        assert_eq!(store.iter().next().unwrap().source, PmkidSource::FilsAuthApToSta);
    }

    // S9 -- PASN Auth seq=1 extracts PasnAuthStaToAp.
    #[test]
    fn t13_10e_pasn_auth_seq1_pmkid_extracted() {
        let pmkid = [0x09u8; 16];
        let mut body = Vec::new();
        body.extend_from_slice(&255u16.to_le_bytes()); // algo=255 (unknown/PASN)
        body.extend_from_slice(&1u16.to_le_bytes()); // seq=1
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&rsn_ie_tagged(pmkid));

        let mac_hdr = dummy_mac_hdr([0x11; 6], [0x22; 6]);
        let mut store = PmkidStore::new();
        let akm_map = AkmMap::new();
        let mut stats = Stats::new();

        let mut logger = Logger::new(None).unwrap();
        process_auth_pasn(&mac_hdr, 1, &body, 0, &mut store, &akm_map, &mut stats, &mut logger);

        assert_eq!(store.total_count(), 1);
        assert_eq!(store.iter().next().unwrap().source, PmkidSource::PasnAuthStaToAp);
        assert_eq!(stats.pmkid_pasn_auth, 1);
    }

    // Truncated FT auth body -> zero entries, no panic.
    #[test]
    fn ft_auth_truncated_body_no_panic() {
        let mac_hdr = dummy_mac_hdr([0x11; 6], [0x22; 6]);
        let mut store = PmkidStore::new();
        let akm_map = AkmMap::new();
        let mut stats = Stats::new();
        let mut logger = Logger::new(None).unwrap();
        process_auth_ft(&mac_hdr, 1, &[0x02, 0x00], 0, &mut store, &akm_map, &mut stats, &mut logger);
        assert_eq!(store.total_count(), 0);
    }
}
