//! Phase 3 -- Extract: data frame handler (EAPOL-Key / EAP via LLC/SNAP). See ARCHITECTURE.md §3.3 + §5.

use crate::ieee80211::{amsdu, eap, eapol, frame};
use crate::log::Logger;
use crate::stats::Stats;
use crate::store::{
    AkmMap,
    auxiliary::{IdentitySet, UsernameSet, WordlistStore},
    essid::EssidMap,
    fragments::FragmentStore,
    messages::{MessageStore, PendingEapol},
    pmkid::PmkidStore,
};

use super::ExtractConfig;
use super::common::{is_eapol_key_packet, is_eapol_llc, is_preauth_llc, mesh_control_len, store_eapol_key};

/// Processes a single IEEE 802.11 data frame body.
///
/// For standard BSS frames (ToDS/FromDS unambiguous), classifies EAPOL immediately
/// using the direction-based tree (Tier 1). For WDS relay frames (ToDS=1, FromDS=1),
/// defers EAPOL classification to Phase 1.5 by storing in `pending_eapol`.
/// Falls back to EAP parsing for identity/username extraction when the corresponding
/// output flags are set. See `ARCHITECTURE.md §8 FR-DATA-*`.
pub fn process_data(
    mac_hdr: &frame::MacHeader,
    body: &[u8],
    timestamp_us: u64,
    cfg: &ExtractConfig,
    message_store: &mut MessageStore,
    pmkid_store: &mut PmkidStore,
    essid_map: &EssidMap,
    akm_map: &mut AkmMap,
    identity_set: &mut IdentitySet,
    username_set: &mut UsernameSet,
    wordlist_store: &mut WordlistStore,
    stats: &mut Stats,
    pending_eapol: &mut Vec<PendingEapol>,
    fragment_store: &mut FragmentStore,
    logger: &mut Logger,
) {
    // Count encrypted data frames (Protected Frame bit set), split WEP vs
    // WPA-family on the ExtIV bit: byte 3 of the protected body is the KeyID
    // octet, and bit 5 (0x20) is Extended IV -- 0 for WEP ([IEEE 802.11-2024]
    // §12.3.4.2), 1 for TKIP/CCMP/GCMP ([IEEE 802.11-2024] §12.5.2.2). Bodies
    // too short to carry the KeyID octet stay in the WPA bucket (wire-bit
    // driven, no guessing beyond the flag-defined octet).
    // [IEEE 802.11-2024] §9.2.4.1.1 bit B14
    if mac_hdr.protected {
        if let Some(&key_id_byte) = body.get(3)
            && key_id_byte & 0x20 == 0
        {
            stats.wep_encrypted_data += 1;
        } else {
            stats.wpa_encrypted_data += 1;
        }
    }

    // --- 802.11 MSDU fragmentation reassembly ---
    //
    // Most EAPOL traffic is short (M1=99 B, M2/M3<200 B, M4=95 B) and fits in one
    // MPDU; fragmented EAPOL is rare in WPA2 but can occur for FT-PSK M2 with
    // extended IEs that exceed the radio MTU. The store buffers per-(SA, RA,
    // SeqNum) until the final fragment arrives, then returns the concatenated
    // MSDU body for normal EAPOL processing. See store::fragments.
    //
    // Address mapping per [§9.3.2.1 Table 9-60]:
    //   uplink   (ToDS=1, FromDS=0): SA=addr2 (sta),  RA=addr1 (ap)
    //   downlink (ToDS=0, FromDS=1): SA=addr2 (ap),   RA=addr1 (sta)
    //   IBSS     (ToDS=0, FromDS=0): SA=addr2 (sta),  RA=addr1 (= addr3 for mgmt)
    //   WDS                          handled in the WDS branch below; fragmentation
    //                                of relay frames is out of scope for v1.
    // The (SA, RA) tuple identifying a fragmented MSDU per [§9.2.4.4]. After
    // collapsing the FrameDirection cases, the spec rule is uniform: SA = the
    // STA when uplink/IBSS, AP otherwise; RA flips with it. Using `frame::parse`'s
    // pre-resolved (ap, sta) lets us write that as one expression per direction.
    let (sa, ra) = if mac_hdr.direction == frame::FrameDirection::FromAp {
        (mac_hdr.ap, mac_hdr.sta) // downlink: AP is the source
    } else {
        // STA->AP uplink, IBSS, or WDS: STA address is the source for fragmentation
        // keying. WDS frames take the early-return path below before we ever query
        // the FragmentStore, so this fallback is exercised only by uplink/IBSS.
        (mac_hdr.sta, mac_hdr.ap)
    };

    // Reassembly storage. Lives for the rest of the function so the shadowed
    // `body` slice below can borrow into it. The unfragmented hot path leaves
    // it `None` and `body` keeps pointing at the original frame slice.
    //
    // Every branch falls through to the normal EAPOL/EAP pipeline below, even
    // non-final fragments and orphan final fragments. Hardware glitches
    // occasionally set MoreFrag=1 or FragNum>0 on what is actually a complete
    // single-MPDU EAPOL frame; the pre-fragmentation pipeline emitted hashes
    // for those, and removing that fallback caused a measurable hash
    // regression in corpus testing. True multi-fragment first or middle
    // pieces fail EAPOL parse on length / LLC mismatch, so the fall-through
    // is safe; the global SipHash dedup suppresses any double-emit when
    // reassembly later succeeds and the reconstructed MSDU parses too.
    let reassembled: Option<Vec<u8>> = if mac_hdr.fragment_number == 0 && !mac_hdr.more_fragments {
        None // unfragmented frame: nothing to reassemble
    } else {
        // Fragmented frame (MoreFrag=1 or FragNum>0): buffer for out-of-order
        // reassembly. Returns Some(full_msdu) when all fragments 0..=N are
        // present, None otherwise. The original body still flows through to
        // the EAPOL parser on None so glitched-bit complete frames (MoreFrag
        // set on a single-MPDU EAPOL) are preserved; SipHash dedup suppresses
        // double-emit when reassembly later succeeds.
        let mut frag_stats = stats.fragment_stats;
        let full = fragment_store.insert_fragment(
            sa,
            ra,
            mac_hdr.sequence_number,
            mac_hdr.fragment_number,
            mac_hdr.more_fragments,
            body,
            timestamp_us,
            &mut frag_stats,
        );
        stats.fragment_stats = frag_stats;
        full
    };
    let body: &[u8] = reassembled.as_deref().unwrap_or(body);

    // --- Mesh Control header skip ---
    // Mesh BSS Data frames carry a 6/12/18-byte Mesh Control header at the start of
    // the body before the LLC/SNAP. The QoS Control "Mesh Control Present" bit is
    // the only signal. Reserved Address Extension Mode (`11`) returns None and the
    // frame is dropped silently. [IEEE 802.11-2024] §9.2.4.8.3
    let mesh_skipped: Option<Vec<u8>> = if mac_hdr.mesh_control_present {
        let mc_len = mesh_control_len(body);
        match mc_len {
            Some(n) if body.len() > n => {
                stats.mesh_control_frames += 1;
                Some(body.get(n..).unwrap_or(&[]).to_vec())
            },
            // Reserved Address Extension Mode (11) or a body shorter than the
            // Mesh Control header: the inner MSDU is unrecoverable. Counted as a
            // drop instead of vanishing silently. [IEEE 802.11-2024] §9.2.4.8.3
            _ => {
                stats.mesh_control_malformed += 1;
                None
            },
        }
    } else {
        None
    };
    let body: &[u8] = mesh_skipped.as_deref().unwrap_or(body);

    // --- WDS EAPOL deferral ---
    // WDS relay frames (ToDS=1, FromDS=1) have ambiguous direction: the transmitter
    // address (addr2) could be the AP or a relay node. Defer EAPOL classification
    // until the essid_map is fully populated (Phase 1.5).
    //
    // WDS + A-MSDU is technically valid but rare; per-subframe attribution under
    // ambiguous outer addresses is unreliable, so we treat the WDS body as a
    // single MSDU even when the A-MSDU bit is set.
    if mac_hdr.direction == frame::FrameDirection::Wds {
        if is_eapol_llc(body) {
            pending_eapol.push(PendingEapol {
                body: body.to_vec(),
                addr_ta: mac_hdr.ap,  // frame.rs: ap=addr2=TA for WDS
                addr_ra: mac_hdr.sta, // frame.rs: sta=addr1=RA for WDS
                timestamp: timestamp_us,
            });
            stats.relay_frames += 1;
        }
        return;
    }

    // essid_map is read-only in this path; the EAP identity/username branch does
    // not need it but the parameter is kept for signature consistency.
    let _ = essid_map;

    // --- A-MSDU vs single-MSDU dispatch ---
    // Always process the outer body as a single MSDU first. For true A-MSDU
    // frames the outer body starts with subframe headers (not LLC/SNAP) so
    // `eapol::parse` rejects it harmlessly. For frames with the A-MSDU bit
    // glitched on what is actually a complete single-MPDU EAPOL frame, this
    // single pass recovers the hash that subframe iteration would otherwise
    // lose (single-frame hash regression observed in corpus testing before
    // this dual path was added; same pattern as the fragmentation fallback
    // in store::fragments).
    //
    // Then, when the A-MSDU bit is set, also iterate subframes. Each subframe
    // payload is its own LLC/SNAP+MSDU; EAPOL hidden in subframes 2..N would
    // be invisible without this loop. Subframe DA/SA are discarded -- the
    // outer (`ap`, `sta`) is the authoritative session key, and re-keying on
    // inner addresses would split a single (AP, STA) handshake across
    // multiple `MessageStore` groups. The global SipHash dedup suppresses
    // any double-emit if both the outer pass and a subframe pass somehow
    // produce identical hashes.
    process_msdu_payload(
        mac_hdr,
        body,
        timestamp_us,
        *cfg,
        message_store,
        pmkid_store,
        akm_map,
        identity_set,
        username_set,
        wordlist_store,
        stats,
        logger,
    );
    if mac_hdr.is_amsdu {
        stats.amsdu_frames_seen += 1;
        for subframe in amsdu::AmsduIter::new(body) {
            stats.amsdu_subframes_total += 1;
            process_msdu_payload(
                mac_hdr,
                subframe,
                timestamp_us,
                *cfg,
                message_store,
                pmkid_store,
                akm_map,
                identity_set,
                username_set,
                wordlist_store,
                stats,
                logger,
            );
        }
    }
}
/// Processes a single MSDU payload (LLC/SNAP+payload) for EAPOL-Key / EAP.
///
/// Called once per Data frame for non-aggregated MSDUs and once per subframe
/// for A-MSDU aggregated frames. The `(ap, sta)` keying always uses the outer
/// frame's MAC header so a multi-subframe session lands in one `MessageStore`
/// group.
fn process_msdu_payload(
    mac_hdr: &frame::MacHeader,
    body: &[u8],
    timestamp_us: u64,
    cfg: ExtractConfig,
    message_store: &mut MessageStore,
    pmkid_store: &mut PmkidStore,
    akm_map: &mut AkmMap,
    identity_set: &mut IdentitySet,
    username_set: &mut UsernameSet,
    wordlist_store: &mut WordlistStore,
    stats: &mut Stats,
    logger: &mut Logger,
) {
    // --- Standard BSS EAPOL-Key path (Tier 1: direction-based) ---
    // Pre-check for invalid nonce/MIC values before full parse so stats can count them
    // and emit a structured log line. `check_invalid_fields` only runs when the
    // LLC/SNAP EtherType is 0x888E or 0x88C7 (preauth).
    {
        let t = eapol::check_invalid_fields(body);
        // The MAC hex wrappers are zero-allocation `Display` views; the hot path
        // (most frames trigger no sentinel) builds no `String` at all, and a
        // firing branch only allocates the single log-line `String` inside the
        // logger.
        if let Some((kind, nonce)) = t.nonce_garbage {
            stats.record_invalid_nonce(kind, t.msg_type);
            if kind != "null" {
                logger.log_invalid_nonce(mac_hdr.ap.hex_lower(), mac_hdr.sta.hex_lower(), t.msg_type, kind, &nonce);
            }
        }
        if let Some((kind, mic)) = t.mic_garbage {
            stats.record_invalid_mic(kind);
            if kind != "null" {
                logger.log_invalid_mic(
                    mac_hdr.ap.hex_lower(),
                    mac_hdr.sta.hex_lower(),
                    t.msg_type,
                    kind,
                    mic.as_slice(),
                );
            }
        }
    }
    // Surface the preauth EtherType (0x88C7) separately from regular EAPOL (0x888E)
    // so operators can spot inter-AP preauth traffic in the stats summary.
    // [IEEE 802.11-2024] §12.3.2
    if is_preauth_llc(body) {
        stats.eapol_preauth_frames += 1;
    }
    if let Some(key) = eapol::parse(body, Some(mac_hdr.direction)) {
        // ACK cross-check: direction from MAC header should agree with ACK flag.
        // AP-sent frames (M1/M3) should have ACK=1; STA-sent (M2/M4) should have ACK=0.
        // Mismatch is diagnostic only -- direction from ToDS/FromDS is authoritative.
        let expected_ack = mac_hdr.direction == frame::FrameDirection::FromAp;
        if expected_ack != key.key_ack {
            stats.eapol_ack_mismatches += 1;
        }
        stats.eapol_tier1_direction += 1;

        store_eapol_key(key, mac_hdr.ap, mac_hdr.sta, timestamp_us, akm_map, message_store, pmkid_store, stats, logger);
        return;
    }
    // LLC/SNAP gate said EAPOL/preauth EtherType AND the EAPOL Packet Type byte
    // was 3 (EAPOL-Key), but the EAPOL-Key parser bailed (truncated body, bad
    // descriptor, sentinel-rejected MIC/nonce). Count the silent drop so it
    // surfaces in the Phase 3 report rather than vanishing. EAPOL Packet Types
    // 0/1/2 (EAP-Packet, EAPOL-Start, EAPOL-Logoff) are not malformed key
    // frames and must NOT increment this counter.
    if is_eapol_key_packet(body) {
        stats.eapol_llc_invalid += 1;
        // Garbage nonce/MIC are already logged by [invalid_nonce] / [invalid_mic].
        // Only emit [eapol_key_rejected] for the remainder so the operator can see
        // the exact structural reason (truncation, bad descriptor, bad KDV, etc.)
        // without noise from the already-explained garbage-pattern drops.
        let reason = eapol::parse_rejection_reason(body);
        if reason != "garbage_nonce" && reason != "garbage_mic" {
            logger.log_eapol_key_rejected(mac_hdr.ap.hex_lower(), mac_hdr.sta.hex_lower(), reason, body);
        }
    }

    // --- EAP identity/username/outcome path ---
    // Always parse to drive the EAP-Success/Failure stat counters; identity and
    // username sets are only populated when -I / -U / -W was requested.
    if let Some(eap_info) = eap::parse(body) {
        // RFC 3748 §4.2 outcome counters -- stats-only; carry no identity data.
        match eap_info.outcome {
            Some(eap::EapOutcome::Success) => stats.eap_success_frames += 1,
            Some(eap::EapOutcome::Failure) => stats.eap_failure_frames += 1,
            None => {},
        }
        if cfg.populate_identity || cfg.populate_username || cfg.populate_wordlist {
            // -I (identity) / -W (wordlist): Request/Identity prompts and
            // Response/Identity claims both count.
            if let Some(identity_bytes) = eap_info.identity {
                if cfg.populate_wordlist && !identity_bytes.is_empty() {
                    wordlist_store.insert(identity_bytes.clone());
                }
                if let Ok(s) = String::from_utf8(identity_bytes)
                    && !s.is_empty()
                {
                    identity_set.insert(s);
                }
            }
            // -U (username) / -W (wordlist): only Response/Identity yields a
            // username. The username strand of the wordlist mirrors the
            // identity strand above so `-W` remains a strict superset of the
            // text columns written to `-I` / `-U`.
            if let Some(username_bytes) = eap_info.username {
                if cfg.populate_wordlist && !username_bytes.is_empty() {
                    wordlist_store.insert(username_bytes.clone());
                }
                if let Ok(s) = String::from_utf8(username_bytes)
                    && !s.is_empty()
                {
                    username_set.insert(s);
                }
            }
        }
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
    use crate::ieee80211::frame;
    use crate::stats::Stats;
    use crate::store::messages::PendingEapol;
    use crate::types::MacAddr;

    /// Bundle of every store + stats + logger that `process_data` writes through.
    /// Test helper only; exists so each test can build a fresh world without 16
    /// `let mut` lines per case.
    struct DataWorld {
        message_store: MessageStore,
        pmkid_store: PmkidStore,
        essid_map: EssidMap,
        akm_map: AkmMap,
        identity_set: IdentitySet,
        username_set: UsernameSet,
        wordlist_store: WordlistStore,
        stats: Stats,
        pending_eapol: Vec<PendingEapol>,
        fragment_store: FragmentStore,
        logger: Logger,
    }

    impl DataWorld {
        fn new() -> Self {
            Self {
                message_store: MessageStore::new(),
                pmkid_store: PmkidStore::new(),
                essid_map: EssidMap::new(),
                akm_map: AkmMap::new(),
                identity_set: IdentitySet::new(),
                username_set: UsernameSet::new(),
                wordlist_store: WordlistStore::new(),
                stats: Stats::new(),
                pending_eapol: Vec::new(),
                fragment_store: FragmentStore::new(),
                logger: Logger::new(None).unwrap(),
            }
        }
    }

    fn data_mac_hdr(direction: frame::FrameDirection, ap: [u8; 6], sta: [u8; 6]) -> frame::MacHeader {
        frame::MacHeader {
            ap: MacAddr::from_bytes(ap),
            sta: MacAddr::from_bytes(sta),
            frame_type: frame::TYPE_DATA,
            subtype: 0, // Data
            protected: false,
            body_offset: 24,
            direction,
            more_fragments: false,
            sequence_number: 0,
            fragment_number: 0,
            is_amsdu: false,
            mesh_control_present: false,
        }
    }

    fn run_data(world: &mut DataWorld, mac_hdr: &frame::MacHeader, body: &[u8], cfg: ExtractConfig) {
        process_data(
            mac_hdr,
            body,
            0,
            &cfg,
            &mut world.message_store,
            &mut world.pmkid_store,
            &world.essid_map,
            &mut world.akm_map,
            &mut world.identity_set,
            &mut world.username_set,
            &mut world.wordlist_store,
            &mut world.stats,
            &mut world.pending_eapol,
            &mut world.fragment_store,
            &mut world.logger,
        );
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

    #[test]
    fn empty_body_does_not_panic_or_bump_eapol_llc_invalid() {
        // A zero-byte body fails the LLC/SNAP gate; nothing should reach the
        // EAPOL parser and `eapol_llc_invalid` (the silent-drop counter) must
        // stay at zero. Guards against a regression where an empty body was
        // ever fed past the gate.
        let mut world = DataWorld::new();
        let hdr = data_mac_hdr(frame::FrameDirection::FromSta, [0xAA; 6], [0xBB; 6]);
        run_data(&mut world, &hdr, &[], cfg_off());
        assert_eq!(world.stats.eapol_llc_invalid, 0);
        assert_eq!(world.stats.eapol_tier1_direction, 0);
        assert_eq!(world.message_store.group_count(), 0);
        assert!(world.pending_eapol.is_empty());
    }

    #[test]
    fn wds_eapol_defers_to_pending_eapol() {
        // WDS (4-address) data frames have ambiguous transmitter role, so
        // EAPOL classification is deferred to Phase 1.5. Confirm the LLC/SNAP
        // EAPOL EtherType triggers the deferral path: `pending_eapol` gains an
        // entry and `relay_frames` is bumped. The frame must NOT take the
        // standard tier-1 path (`eapol_tier1_direction` stays at 0).
        let mut world = DataWorld::new();
        let hdr = data_mac_hdr(frame::FrameDirection::Wds, [0xAA; 6], [0xBB; 6]);
        // 8-byte LLC/SNAP with EAPOL EtherType `0x888E`. Body content does not
        // matter for the deferral path -- only the EtherType.
        let body = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E, 0x02, 0x03, 0x00, 0x00];
        run_data(&mut world, &hdr, &body, cfg_off());
        assert_eq!(world.pending_eapol.len(), 1, "WDS EAPOL must be deferred");
        assert_eq!(world.stats.relay_frames, 1);
        assert_eq!(world.stats.eapol_tier1_direction, 0, "WDS must skip tier-1 fast path");
    }

    #[test]
    fn wds_non_eapol_body_is_silently_skipped() {
        // WDS frames whose body is not EAPOL must not be deferred -- the
        // pending list stays empty. Guards against a regression where every
        // WDS data frame was queued regardless of content.
        let mut world = DataWorld::new();
        let hdr = data_mac_hdr(frame::FrameDirection::Wds, [0xAA; 6], [0xBB; 6]);
        // 8-byte LLC/SNAP with an arbitrary non-EAPOL EtherType (`0x0800` IPv4).
        let body = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        run_data(&mut world, &hdr, &body, cfg_off());
        assert!(world.pending_eapol.is_empty(), "non-EAPOL WDS must not defer");
        assert_eq!(world.stats.relay_frames, 0);
    }

    #[test]
    fn protected_data_frame_bumps_wpa_encrypted_counter() {
        // Protected data frames (B14 set) increment `wpa_encrypted_data` even
        // when the body is empty -- the counter is wire-bit-driven.
        let mut world = DataWorld::new();
        let mut hdr = data_mac_hdr(frame::FrameDirection::FromSta, [0xAA; 6], [0xBB; 6]);
        hdr.protected = true;
        run_data(&mut world, &hdr, &[], cfg_off());
        assert_eq!(world.stats.wpa_encrypted_data, 1);
    }
}
