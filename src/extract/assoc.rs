//! Phase 3 -- Extract: Association / Reassociation Request handler (per-AKM counters, PMKID, FT IEs). See ARCHITECTURE.md §3.3 + §6.

use crate::ieee80211::{
    frame,
    ft::extract_ft_fields,
    ie::{extract_mle_basic, iter_ies},
    rsn::{detect_assoc_akm_flags, extract_pmkids, extract_pmkids_from_osen},
};
use crate::log::Logger;
use crate::stats::Stats;
use crate::store::{
    AkmMap, MldStore,
    auxiliary::{EssidSet, WordlistStore},
    essid::EssidMap,
    pmkid::{PmkidEntry, PmkidStore},
};
use crate::types::{AkmType, MacAddr, PmkidSource};

use super::common::{ASSOC_REQ_FIXED, REASSOC_REQ_FIXED, SUBTYPE_ASSOC_REQ};

/// Handles a single Association Request or Reassociation Request management frame.
///
/// Increments frame/AKM counters, extracts SSIDs and PMKIDs from RSN and OSEN IEs.
/// Fixed-field offsets: `AssocReq` = 4 bytes, `ReassocReq` = 10 bytes.
/// [IEEE 802.11-2024] §9.3.3.6 (`AssocReq`), §9.3.3.8 (`ReassocReq`).
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "assoc handler mirrors process_probe_req pattern; large per-AKM counter switch is unavoidable"
)]
pub fn process_assoc_or_reassoc_req(
    mac_hdr: &frame::MacHeader,
    body: &[u8],
    timestamp_us: u64,
    essid_map: &mut EssidMap,
    essid_set: &mut EssidSet,
    akm_map: &mut AkmMap,
    mld_store: &mut MldStore,
    pmkid_store: &mut PmkidStore,
    wordlist_store: &mut WordlistStore,
    stats: &mut Stats,
    logger: &mut Logger,
    populate_wordlist: bool,
) {
    let is_assoc = mac_hdr.subtype == SUBTYPE_ASSOC_REQ;
    if is_assoc {
        stats.assoc_req_frames += 1;
    } else {
        stats.reassoc_req_frames += 1;
    }

    // Skip past fixed fields to reach the tagged parameters.
    let fixed = if is_assoc { ASSOC_REQ_FIXED } else { REASSOC_REQ_FIXED };
    let ies = body.get(fixed..).unwrap_or(&[]);

    // Per-AKM breakdown from the RSN IE in this frame. A single frame may advertise
    // multiple AKMs (e.g., PSK + FT-PSK). [IEEE 802.11-2024] §9.4.2.24.3
    let akm_flags = detect_assoc_akm_flags(ies);

    // Surface any AKM byte outside Table 9-190 to the structured log so an operator
    // can see novel / vendor / future AKMs without grepping the wire. The summary
    // counter `assoc_req_akm_unknown` (or its reassoc twin) is incremented below.
    if let Some(byte) = akm_flags.first_unknown_akm {
        logger.log_unknown_akm(byte);
    }

    // Determine the STA's negotiated AKM. Prefer observed-in-frame evidence over the
    // declared AKM-suite list, because the declared list can include AKMs the client
    // will not actually use, and APs supporting both PSK and FT-PSK commonly advertise
    // PSK first -- routing to mode 22000 even when the client does FT-PSK.
    //
    // Priority:
    //   1. FT fields observed (MDIE tag 54 + FTIE tag 55 both present) -> FT-PSK.
    //      This is the wire-level evidence that the handshake is FT; it is stronger
    //      than the declared AKM list. [IEEE 802.11-2024] §9.4.2.45-46
    //   2. Declared AKM from RSN IE. FT-PSK-SHA384 > FT-PSK > PSK-SHA384 > PSK-SHA256
    //      > WPA2-PSK. SAE / OWE / Unknown fall through and do not update. The
    //      SHA-384 variants are kept distinct from their SHA-256 siblings so that
    //      `HashType::from_akm_and_attack` can pin each handshake to one of the
    //      eleven hash-type rows in `ARCHITECTURE.md §2`.
    //
    // Parsing FT fields once here avoids a second walk below in the PMKID branch.
    let ft = extract_ft_fields(ies);
    let chosen_akm = if akm_flags.ft_psk_sha384 {
        AkmType::FtPskSha384
    } else if ft.is_some() || akm_flags.ft_psk {
        AkmType::FtPsk
    } else if akm_flags.psk_sha384 {
        AkmType::PskSha384
    } else if akm_flags.psk_sha256_only {
        AkmType::PskSha256
    } else if akm_flags.psk {
        AkmType::Wpa2Psk
    } else if akm_flags.wpa1 {
        // WPA1 vendor IE only (no RSN IE). Mixed-mode APs whose beacon advertises both
        // RSN and WPA1 still set akm_map[ap] = WPA2-PSK from the beacon path; this arm
        // overrides that for the per-pair entry when the STA itself committed to WPA1.
        // Without this, the WPA1 EAPOL exchange that follows is misclassified as
        // WPA2-PSK-EAPOL (type 3) instead of WPA1-PSK-EAPOL (type 1).
        AkmType::Wpa1
    } else {
        AkmType::Unknown
    };
    if chosen_akm != AkmType::Unknown {
        akm_map.insert_sta(mac_hdr.ap, mac_hdr.sta, chosen_akm);
    }

    // Multi-Link Element (ext tag 107) -- if the STA advertises its MLD MAC in an
    // Association Request, record link_addr -> MLD mapping so Phase 2 can canonicalize
    // pairs and avoid splitting a single client into multiple (AP, STA) groups.
    // [IEEE 802.11be] §9.4.2.321
    if let Some(mle) = extract_mle_basic(ies) {
        stats.mle_basic_seen += 1;
        let mld_addr = MacAddr::from_bytes(mle.mld_mac);
        if mac_hdr.sta != mld_addr {
            let before = mld_store.len();
            mld_store.record(mac_hdr.sta, mld_addr);
            if mld_store.len() > before {
                stats.mle_mld_addrs_learned += 1;
            }
        }
    }

    if is_assoc {
        if akm_flags.psk {
            stats.assoc_req_wpa2_psk += 1;
        }
        // Fine-grained FT family: AKM 4 vs AKM 19. The union flag `ft_psk` is preserved
        // for output routing but stats emit separate rows per hash-size variant.
        if akm_flags.ft_psk_sha256 {
            stats.assoc_req_ft_psk += 1;
        }
        if akm_flags.ft_psk_sha384 {
            stats.assoc_req_ft_psk_sha384 += 1;
        }
        // Fine-grained PSK-SHA: AKM 6 vs AKM 20.
        if akm_flags.psk_sha256_only {
            stats.assoc_req_psk_sha256 += 1;
        }
        if akm_flags.psk_sha384 {
            stats.assoc_req_psk_sha384 += 1;
        }
        if akm_flags.sae {
            stats.assoc_req_sae += 1;
        }
        if akm_flags.owe {
            stats.assoc_req_owe += 1;
        }
        if akm_flags.fils {
            stats.assoc_req_fils += 1;
        }
        if akm_flags.pasn {
            stats.assoc_req_pasn += 1;
        }
        if akm_flags.enterprise_sha1 {
            stats.assoc_req_enterprise_sha1 += 1;
        }
        if akm_flags.enterprise_sha256 {
            stats.assoc_req_enterprise_sha256 += 1;
        }
        if akm_flags.enterprise_sha384 {
            stats.assoc_req_enterprise_sha384 += 1;
        }
        if akm_flags.tdls {
            stats.assoc_req_tdls += 1;
        }
        if akm_flags.appeerkey {
            stats.assoc_req_appeerkey += 1;
        }
        if akm_flags.akm_unknown {
            stats.assoc_req_akm_unknown += 1;
        }
        if akm_flags.wpa1 {
            stats.assoc_req_wpa1 += 1;
        }
    } else {
        if akm_flags.psk {
            stats.reassoc_req_wpa2_psk += 1;
        }
        if akm_flags.ft_psk_sha256 {
            stats.reassoc_req_ft_psk += 1;
        }
        if akm_flags.ft_psk_sha384 {
            stats.reassoc_req_ft_psk_sha384 += 1;
        }
        if akm_flags.psk_sha256_only {
            stats.reassoc_req_psk_sha256 += 1;
        }
        if akm_flags.psk_sha384 {
            stats.reassoc_req_psk_sha384 += 1;
        }
        if akm_flags.sae {
            stats.reassoc_req_sae += 1;
        }
        if akm_flags.owe {
            stats.reassoc_req_owe += 1;
        }
        if akm_flags.fils {
            stats.reassoc_req_fils += 1;
        }
        if akm_flags.pasn {
            stats.reassoc_req_pasn += 1;
        }
        if akm_flags.enterprise_sha1 {
            stats.reassoc_req_enterprise_sha1 += 1;
        }
        if akm_flags.enterprise_sha256 {
            stats.reassoc_req_enterprise_sha256 += 1;
        }
        if akm_flags.enterprise_sha384 {
            stats.reassoc_req_enterprise_sha384 += 1;
        }
        if akm_flags.tdls {
            stats.reassoc_req_tdls += 1;
        }
        if akm_flags.appeerkey {
            stats.reassoc_req_appeerkey += 1;
        }
        if akm_flags.akm_unknown {
            stats.reassoc_req_akm_unknown += 1;
        }
        if akm_flags.wpa1 {
            stats.reassoc_req_wpa1 += 1;
        }
    }

    // Extract SSID from IE id=0. [IEEE 802.11-2024] §9.4.2.3
    for ie in iter_ies(ies) {
        if ie.id == 0 && !ie.value.is_empty() {
            essid_map.insert(mac_hdr.ap, ie.value.to_vec(), timestamp_us);
            essid_set.insert(ie.value);
            if populate_wordlist {
                wordlist_store.insert(ie.value.to_vec());
            }
            break;
        }
    }

    // Extract PMKIDs from the RSN IE PMKID List. [IEEE 802.11-2024] §9.4.2.24
    let pmkids = extract_pmkids(ies);
    if !pmkids.is_empty() {
        // Use the best-known AKM for this (AP, STA) -- prefers the per-pair override
        // just installed from the frame's observed FT fields or declared AKM over the
        // Beacon's AP-wide default. `ft` was parsed above to drive chosen_akm.
        let akm = akm_map.get_best(&mac_hdr.ap, &mac_hdr.sta);
        let source = if is_assoc { PmkidSource::AssocRequest } else { PmkidSource::ReassocRequest };
        for pmkid in pmkids {
            if let Some(kind) = stats.check_pmkid_invalid(&pmkid) {
                logger.log_invalid_pmkid(timestamp_us, mac_hdr.ap.hex_lower(), mac_hdr.sta.hex_lower(), kind);
            }
            pmkid_store.add(PmkidEntry {
                timestamp: timestamp_us,
                ap: mac_hdr.ap,
                sta: mac_hdr.sta,
                pmkid,
                source,
                akm,
                ft,
            });
            stats.pmkids_found += 1;
            if akm.is_ft() {
                stats.pmkid_ft_psk += 1;
            } else {
                stats.pmkid_wpa2_psk += 1;
            }
            if is_assoc {
                stats.pmkid_assoc_req += 1;
            } else {
                stats.pmkid_reassoc_req += 1;
            }
        }
    }

    // S20: OSEN IE PMKID in Association Request. Vendor tag 221, OUI 50:6F:9A,
    // type 0x12. Inner body is identical to RSN IE. [Hotspot 2.0 / OSEN spec;
    // packet-ieee80211.c:20494]
    if is_assoc {
        for ie in iter_ies(ies) {
            if ie.id == 221 {
                for pmkid in extract_pmkids_from_osen(ie.value) {
                    if let Some(kind) = stats.check_pmkid_invalid(&pmkid) {
                        logger.log_invalid_pmkid(timestamp_us, mac_hdr.ap.hex_lower(), mac_hdr.sta.hex_lower(), kind);
                    }
                    pmkid_store.add(PmkidEntry {
                        timestamp: timestamp_us,
                        ap: mac_hdr.ap,
                        sta: mac_hdr.sta,
                        pmkid,
                        source: PmkidSource::OsenIe,
                        akm: AkmType::Unknown,
                        ft: None,
                    });
                    stats.pmkids_found += 1;
                    stats.pmkid_wpa2_psk += 1;
                    stats.pmkid_osen += 1;
                }
            }
        }
    }
}
