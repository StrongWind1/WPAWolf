//! Phase 3 -- Extract: top-level management-frame dispatcher (fans out to subtype handlers). See ARCHITECTURE.md §3.3.

use crate::ieee80211::{frame, ie::iter_ies};
use crate::log::Logger;
use crate::stats::Stats;
use crate::store::{
    AkmMap, MldStore,
    auxiliary::{DeviceInfoStore, EssidSet, ProbeEssidSet, WordlistStore},
    essid::EssidMap,
    pmkid::PmkidStore,
};
use crate::strings_scan::extract_ascii_runs;

use super::ExtractConfig;
use super::action::process_action;
use super::assoc::process_assoc_or_reassoc_req;
use super::auth::{process_auth_fils, process_auth_ft, process_auth_pasn};
use super::beacon::process_beacon_or_probe_resp;
use super::common::{
    ASSOC_REQ_FIXED, BEACON_FIXED, REASSOC_REQ_FIXED, SUBTYPE_ACTION, SUBTYPE_ACTION_NO_ACK, SUBTYPE_ASSOC_REQ,
    SUBTYPE_ASSOC_RESP, SUBTYPE_ATIM, SUBTYPE_AUTH, SUBTYPE_BEACON, SUBTYPE_DEAUTH, SUBTYPE_DISASSOC,
    SUBTYPE_MEASUREMENT_PILOT, SUBTYPE_PROBE_REQ, SUBTYPE_PROBE_RESP, SUBTYPE_REASSOC_REQ, SUBTYPE_REASSOC_RESP,
    SUBTYPE_TIMING_ADVERT,
};
use super::probe::process_probe_req;

/// Minimum run length for `--wordlist-scan-ies` IE-body printable-ASCII sweep.
///
/// Tuned up from `strings(1)`'s default of 4 to suppress short-run noise from IE
/// length fields, vendor OUIs, and capability-byte patterns that happen to fall in
/// the printable band. See `ARCHITECTURE.md §9`.
const WORDLIST_SCAN_IES_MIN_RUN: usize = 8;

/// Scans the IE tagged-parameter block `ies` for printable-ASCII runs of length
/// `>= WORDLIST_SCAN_IES_MIN_RUN` and inserts each run into `wordlist_store`.
///
/// Called from `process_mgmt` when `--wordlist-scan-ies` is set and the frame is
/// plaintext. Iterates IEs via `iter_ies` so the scan looks at element *values*
/// only -- fixed management-body fields and the 2-byte IE TLV header never enter
/// the scan, matching the design contract in `ARCHITECTURE.md §9` that the
/// sweep is "IE body only, not the fixed fields themselves."
fn scan_ies_for_wordlist(ies: &[u8], wordlist_store: &mut WordlistStore, stats: &mut Stats) {
    for ie in iter_ies(ies) {
        for run in extract_ascii_runs(ie.value, WORDLIST_SCAN_IES_MIN_RUN) {
            wordlist_store.insert(run.to_vec());
            stats.wordlist_scan_ie_runs += 1;
        }
    }
}

/// Processes a single IEEE 802.11 management frame.
///
/// Dispatches on subtype to extract: SSIDs and AKM types from Beacons/ProbeResponses,
/// PMKIDs from AssocRequest/ReassocRequest RSN IEs, SSIDs from Probe Requests and
/// Action Neighbor Report Requests, WPS device metadata, country codes, and SSID
/// List entries. Unhandled subtypes increment counters for visibility.
/// See `ARCHITECTURE.md §8 FR-MGMT-*`.
#[allow(clippy::too_many_arguments, reason = "dispatcher aggregates all management-frame sinks")]
pub fn process_mgmt(
    mac_hdr: &frame::MacHeader,
    body: &[u8],
    timestamp_us: u64,
    cfg: &ExtractConfig,
    essid_map: &mut EssidMap,
    essid_set: &mut EssidSet,
    probe_essid_set: &mut ProbeEssidSet,
    akm_map: &mut AkmMap,
    mld_store: &mut MldStore,
    pmkid_store: &mut PmkidStore,
    wordlist_store: &mut WordlistStore,
    device_store: &mut DeviceInfoStore,
    stats: &mut Stats,
    logger: &mut Logger,
) {
    let populate_wordlist = cfg.populate_wordlist;
    let populate_device = cfg.populate_device;

    // PMF (Protected Management Frame, 802.11w): the body is CCMP/GCMP-encrypted
    // and we have no PTK to decrypt it. Walking the ciphertext as IEs would
    // produce garbage tag/length pairs that occasionally match RSN IE (id=48)
    // by chance, polluting the PMKID store. Count and short-circuit Action
    // frames -- the only management subtype we body-parse that is spec-allowed
    // to be PMF-protected. Beacon/ProbeResp/ProbeReq/Auth and AssocReq/
    // ReassocReq are spec-excluded from PMF [§11.13]; an unexpected Protected
    // bit on those is treated as a hardware glitch and parsed normally.
    if mac_hdr.protected {
        stats.mgmt_protected_frames += 1;
        if mac_hdr.subtype == SUBTYPE_ACTION {
            stats.action_frames += 1;
            stats.mgmt_protected_action_skipped += 1;
            return;
        }
    }

    // Optional `--wordlist-scan-ies` sweep (wordlist IE-scan): scan plaintext management-frame
    // IE bodies for printable-ASCII runs. See `ARCHITECTURE.md §9`. The per-subtype
    // fixed-field length determines where the tagged parameter block begins; subtypes
    // without a stable IE section (AUTH, ATIM, Measurement Pilot, Timing Advertisement)
    // are skipped.
    if cfg.scan_ies && populate_wordlist && !mac_hdr.protected {
        let fixed = match mac_hdr.subtype {
            SUBTYPE_BEACON | SUBTYPE_PROBE_RESP => Some(BEACON_FIXED),
            SUBTYPE_PROBE_REQ => Some(0),
            SUBTYPE_ASSOC_REQ => Some(ASSOC_REQ_FIXED),
            SUBTYPE_REASSOC_REQ => Some(REASSOC_REQ_FIXED),
            // Action frame IEs begin after Category(1) + Action(1). Per-category fixed
            // fields (e.g. FT Action's 14-byte header) are skipped by `iter_ies`
            // naturally once a non-TLV byte pair appears, but they can also be short
            // enough to contribute a 1-2 byte slice; the min_run=8 filter suppresses
            // that noise. [IEEE 802.11-2024] §9.3.3.14
            SUBTYPE_ACTION => Some(2),
            _ => None,
        };
        if let Some(offset) = fixed {
            if let Some(ies_bytes) = body.get(offset..) {
                scan_ies_for_wordlist(ies_bytes, wordlist_store, stats);
            }
        }
    }

    match mac_hdr.subtype {
        SUBTYPE_BEACON | SUBTYPE_PROBE_RESP => {
            process_beacon_or_probe_resp(
                mac_hdr,
                body,
                timestamp_us,
                essid_map,
                essid_set,
                akm_map,
                mld_store,
                pmkid_store,
                wordlist_store,
                device_store,
                stats,
                logger,
                populate_wordlist,
                populate_device,
            );
        },
        SUBTYPE_PROBE_REQ => {
            process_probe_req(
                mac_hdr,
                body,
                timestamp_us,
                essid_map,
                essid_set,
                probe_essid_set,
                akm_map,
                pmkid_store,
                wordlist_store,
                stats,
                logger,
                populate_wordlist,
            );
        },
        SUBTYPE_ASSOC_REQ | SUBTYPE_REASSOC_REQ => {
            process_assoc_or_reassoc_req(
                mac_hdr,
                body,
                timestamp_us,
                essid_map,
                essid_set,
                akm_map,
                mld_store,
                pmkid_store,
                wordlist_store,
                stats,
                logger,
                populate_wordlist,
            );
        },
        SUBTYPE_ACTION => {
            process_action(
                mac_hdr,
                body,
                timestamp_us,
                essid_map,
                essid_set,
                probe_essid_set,
                wordlist_store,
                populate_wordlist,
                pmkid_store,
                stats,
                logger,
            );
        },
        // Counting stubs for subtypes we don't extract data from (yet).
        SUBTYPE_ASSOC_RESP => {
            stats.assoc_resp_frames += 1;
        },
        SUBTYPE_REASSOC_RESP => {
            stats.reassoc_resp_frames += 1;
        },
        SUBTYPE_MEASUREMENT_PILOT => {
            stats.measurement_pilot_frames += 1;
        },
        SUBTYPE_ATIM => {
            stats.atim_frames += 1;
        },
        SUBTYPE_DISASSOC => {
            stats.disassoc_frames += 1;
        },
        SUBTYPE_AUTH => {
            stats.auth_frames += 1;
            // Authentication Algorithm Number: LE u16 at body[0..2].
            // Authentication Transaction Sequence Number: LE u16 at body[2..4].
            // [IEEE 802.11-2024] §9.4.1.1, Table 9-41; §9.3.3.11
            let Some(&algo_lo) = body.first() else { return };
            let Some(&algo_hi) = body.get(1) else { return };
            let algo = u16::from_le_bytes([algo_lo, algo_hi]);

            // Count algorithm type before extracting sequence number. Per
            // `[IEEE 802.11-2024]` Table 9-43 algo=7 is PASN
            // (Pre-Association Security Negotiation), not EPPKE.
            match algo {
                0 => stats.auth_open_system += 1,
                1 => stats.auth_shared_key += 1,
                2 => stats.auth_fbt += 1,
                3 => stats.auth_sae += 1,
                4..=6 => stats.auth_fils += 1,
                128 => stats.auth_network_eap += 1,
                // algo=7 PASN, plus any unrecognised value (§12.13.1 reserves
                // these for future PASN base-AKMP additions).
                _ => stats.auth_pasn += 1,
            }

            // Seq number required for PMKID extraction; abort on truncated body.
            let Some(&seq_lo) = body.get(2) else { return };
            let Some(&seq_hi) = body.get(3) else { return };
            let seq = u16::from_le_bytes([seq_lo, seq_hi]);

            // PMKID extraction dispatched by algorithm number.
            match algo {
                2 => process_auth_ft(mac_hdr, seq, body, timestamp_us, pmkid_store, akm_map, stats, logger),
                4..=6 => process_auth_fils(mac_hdr, seq, body, timestamp_us, pmkid_store, akm_map, stats, logger),
                // Algo 0 (Open), 1 (Shared Key), 3 (SAE), 128 (LEAP): no PMKID.
                0 | 1 | 3 | 128 => {},
                // algo=7 PASN per `[IEEE 802.11-2024]` §12.13.1, plus any
                // unrecognised value (PASN base-AKMP reservation).
                _ => process_auth_pasn(mac_hdr, seq, body, timestamp_us, pmkid_store, akm_map, stats, logger),
            }
        },
        SUBTYPE_DEAUTH => {
            stats.deauth_frames += 1;
        },
        SUBTYPE_ACTION_NO_ACK => {
            stats.action_no_ack_frames += 1;
        },
        SUBTYPE_TIMING_ADVERT => {
            stats.timing_advert_frames += 1;
        },
        _ => {}, // subtypes 7 (reserved) and >15
    }
}

// --- Unit tests ---

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        missing_docs,
        clippy::wildcard_imports,
        reason = "test module"
    )]

    use super::*;
    use crate::stats::Stats;
    use crate::store::AkmMap;
    use crate::types::MacAddr;

    /// Bundle of every store + stats + logger that `process_mgmt` writes through.
    struct MgmtWorld {
        essid_map: EssidMap,
        essid_set: EssidSet,
        probe_essid_set: ProbeEssidSet,
        akm_map: AkmMap,
        mld_store: MldStore,
        pmkid_store: PmkidStore,
        wordlist_store: WordlistStore,
        device_store: DeviceInfoStore,
        stats: Stats,
        logger: Logger,
    }

    impl MgmtWorld {
        fn new() -> Self {
            Self {
                essid_map: EssidMap::new(),
                essid_set: EssidSet::new(),
                probe_essid_set: ProbeEssidSet::new(),
                akm_map: AkmMap::new(),
                mld_store: MldStore::new(),
                pmkid_store: PmkidStore::new(),
                wordlist_store: WordlistStore::new(),
                device_store: DeviceInfoStore::new(),
                stats: Stats::new(),
                logger: Logger::new(None).unwrap(),
            }
        }
    }

    fn mgmt_hdr(subtype: u8, protected: bool) -> frame::MacHeader {
        frame::MacHeader {
            ap: MacAddr::from_bytes([0xAA; 6]),
            sta: MacAddr::from_bytes([0xBB; 6]),
            frame_type: frame::TYPE_MANAGEMENT,
            subtype,
            protected,
            body_offset: 24,
            direction: frame::FrameDirection::Ibss,
            more_fragments: false,
            sequence_number: 0,
            fragment_number: 0,
            is_amsdu: false,
            mesh_control_present: false,
        }
    }

    fn cfg_off() -> ExtractConfig {
        ExtractConfig {
            populate_wordlist: false,
            populate_device: false,
            populate_identity: false,
            populate_username: false,
            scan_ies: false,
        }
    }

    fn run_mgmt(world: &mut MgmtWorld, hdr: &frame::MacHeader, body: &[u8]) {
        process_mgmt(
            hdr,
            body,
            0,
            &cfg_off(),
            &mut world.essid_map,
            &mut world.essid_set,
            &mut world.probe_essid_set,
            &mut world.akm_map,
            &mut world.mld_store,
            &mut world.pmkid_store,
            &mut world.wordlist_store,
            &mut world.device_store,
            &mut world.stats,
            &mut world.logger,
        );
    }

    #[test]
    fn dispatcher_counts_deauth() {
        // Deauth (subtype 12) is a counting-only stub: the dispatcher must bump
        // exactly `deauth_frames` and touch nothing else.
        let mut world = MgmtWorld::new();
        let hdr = mgmt_hdr(SUBTYPE_DEAUTH, false);
        run_mgmt(&mut world, &hdr, &[]);
        assert_eq!(world.stats.deauth_frames, 1);
        assert_eq!(world.stats.disassoc_frames, 0);
        assert_eq!(world.stats.atim_frames, 0);
    }

    #[test]
    fn dispatcher_counts_disassoc_atim_action_no_ack_timing_advert() {
        // Each counting-only subtype gets one frame; the dispatcher should bump
        // exactly the matching counter for each. Catches a regression where a
        // `match` arm's body got copy-pasted to the wrong counter.
        let cases: &[(u8, fn(&Stats) -> u64)] = &[
            (SUBTYPE_DISASSOC, |s| s.disassoc_frames),
            (SUBTYPE_ATIM, |s| s.atim_frames),
            (SUBTYPE_ACTION_NO_ACK, |s| s.action_no_ack_frames),
            (SUBTYPE_TIMING_ADVERT, |s| s.timing_advert_frames),
            (SUBTYPE_MEASUREMENT_PILOT, |s| s.measurement_pilot_frames),
        ];
        for &(subtype, getter) in cases {
            let mut world = MgmtWorld::new();
            let hdr = mgmt_hdr(subtype, false);
            run_mgmt(&mut world, &hdr, &[]);
            assert_eq!(getter(&world.stats), 1, "subtype {subtype} should bump its counter");
        }
    }

    #[test]
    fn protected_action_short_circuits_with_skip_counter() {
        // PMF-encrypted Action frames (only management subtype permitted to
        // carry PMF) increment both `mgmt_protected_frames` and the
        // skip-specific `mgmt_protected_action_skipped`. The body is encrypted
        // ciphertext and walking it as IEs would pollute the PMKID store, so
        // the dispatcher must early-return; `action_frames` still counts the
        // frame for arrival statistics.
        let mut world = MgmtWorld::new();
        let hdr = mgmt_hdr(SUBTYPE_ACTION, true);
        run_mgmt(&mut world, &hdr, &[]);
        assert_eq!(world.stats.mgmt_protected_frames, 1);
        assert_eq!(world.stats.mgmt_protected_action_skipped, 1);
        assert_eq!(world.stats.action_frames, 1);
        assert_eq!(world.pmkid_store.total_count(), 0);
    }

    #[test]
    fn protected_non_action_still_parses() {
        // PMF Beacon / ProbeResp / Auth / Assoc are spec-excluded -- a
        // "protected" bit on those is treated as a hardware glitch and parsed.
        // The protected counter still bumps but the early-return is NOT taken.
        let mut world = MgmtWorld::new();
        let hdr = mgmt_hdr(SUBTYPE_BEACON, true);
        run_mgmt(&mut world, &hdr, &[]);
        assert_eq!(world.stats.mgmt_protected_frames, 1);
        assert_eq!(world.stats.mgmt_protected_action_skipped, 0);
    }

    #[test]
    fn auth_dispatcher_classifies_by_algo() {
        // Auth frame with algo=0 (Open System) should bump `auth_frames` and
        // `auth_open_system` and leave `auth_fbt` / `auth_pasn` untouched.
        // Body layout: algo (LE u16) + transaction sequence (LE u16) + status.
        let mut world = MgmtWorld::new();
        let hdr = mgmt_hdr(SUBTYPE_AUTH, false);
        let body = vec![0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        run_mgmt(&mut world, &hdr, &body);
        assert_eq!(world.stats.auth_frames, 1);
        assert_eq!(world.stats.auth_open_system, 1);
        assert_eq!(world.stats.auth_fbt, 0);
        assert_eq!(world.stats.auth_pasn, 0);
    }

    #[test]
    fn auth_truncated_body_does_not_panic() {
        // A truncated auth body (under 4 bytes) must not panic; the algo-byte
        // read short-circuits the rest of the dispatch.
        let mut world = MgmtWorld::new();
        let hdr = mgmt_hdr(SUBTYPE_AUTH, false);
        run_mgmt(&mut world, &hdr, &[]);
        // No algo byte read -> auth_frames still counted (the bump precedes the
        // body read), but no algo classifier bumped.
        assert_eq!(world.stats.auth_frames, 1);
        assert_eq!(world.stats.auth_open_system, 0);
    }
}
