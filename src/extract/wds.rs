//! Phase 3 -- Extract: deferred-WDS EAPOL resolution (Tier 1b/2/3). See ARCHITECTURE.md §3.3 + §4.

use crate::ieee80211::{eapol, frame};
use crate::log::Logger;
use crate::stats::Stats;
use crate::store::{
    AkmMap,
    essid::EssidMap,
    messages::{MessageStore, PendingEapol},
    pmkid::PmkidStore,
};
use crate::types::MacAddr;

use super::common::{extract_ack_flag, store_eapol_key};

/// Phase 1.5: resolves deferred WDS EAPOL frames after the `essid_map` is fully populated.
///
/// Three-tier resolution:
///   Tier 1b -- `essid_map` lookup: check if either MAC (TA or RA) is a known AP.
///   Tier 2  -- ACK-based AP discovery: ACK=1 means the transmitter is an AP.
///   Tier 3  -- Flag-based fallback: use the hcxpcapngtool-compatible decision tree.
///
/// When Tier 1b or Tier 2 reveals that the RA (not the TA) is the AP, the AP/STA
/// assignment from `frame::parse` is swapped for correct `message_store` grouping.
pub fn resolve_wds_eapol(
    pending: &[PendingEapol],
    essid_map: &EssidMap,
    akm_map: &mut AkmMap,
    message_store: &mut MessageStore,
    pmkid_store: &mut PmkidStore,
    stats: &mut Stats,
    logger: &mut Logger,
) {
    use std::collections::HashSet;

    let mut discovered_aps: HashSet<MacAddr> = HashSet::new();

    // Annotate each pending frame with its resolved direction (None = unresolved).
    let mut directions: Vec<Option<frame::FrameDirection>> = Vec::with_capacity(pending.len());

    // --- Tier 1b: essid_map lookup ---
    for p in pending {
        if essid_map.contains_ap(&p.addr_ta) {
            directions.push(Some(frame::FrameDirection::FromAp));
        } else if essid_map.contains_ap(&p.addr_ra) {
            directions.push(Some(frame::FrameDirection::FromSta));
        } else {
            directions.push(None);
        }
    }

    // --- Tier 2: ACK-based AP discovery ---
    // First pass: find ACK=1 frames among unresolved to discover AP MACs.
    for (p, dir) in pending.iter().zip(directions.iter()) {
        if dir.is_none() && extract_ack_flag(&p.body) == Some(true) {
            discovered_aps.insert(p.addr_ta);
        }
    }

    // Second pass: use discovered_aps to resolve remaining.
    for (p, dir) in pending.iter().zip(directions.iter_mut()) {
        if dir.is_some() {
            continue;
        }
        if discovered_aps.contains(&p.addr_ta) {
            *dir = Some(frame::FrameDirection::FromAp);
        } else if discovered_aps.contains(&p.addr_ra) {
            *dir = Some(frame::FrameDirection::FromSta);
        }
    }

    // --- Classify and store all resolved + fallback frames ---
    for (p, dir) in pending.iter().zip(directions.iter()) {
        // Determine the resolved direction and which tier it came from.
        let (resolved_dir, is_tier1b) = match dir {
            Some(d @ (frame::FrameDirection::FromAp | frame::FrameDirection::FromSta)) => {
                let from_essid = essid_map.contains_ap(&p.addr_ta) || essid_map.contains_ap(&p.addr_ra);
                (Some(*d), from_essid)
            },
            _ => (None, false),
        };

        // For FromSta direction, the real AP is addr_ra (swap the assignment from frame.rs).
        let (ap, sta) = if resolved_dir == Some(frame::FrameDirection::FromSta) {
            (p.addr_ra, p.addr_ta)
        } else {
            (p.addr_ta, p.addr_ra)
        };

        // Pre-check for invalid nonce/MIC values before full parse (WDS deferred path).
        // Logs each rejection so the structured-log audit trail is identical to the
        // non-WDS path in process_msdu_payload. The MAC hex wrappers are
        // zero-allocation `Display` views; nothing is built unless a check fires.
        {
            let t = eapol::check_invalid_fields(&p.body);
            if let Some((kind, nonce)) = t.nonce_garbage {
                stats.record_invalid_nonce(kind, t.msg_type);
                if kind != "null" {
                    logger.log_invalid_nonce(p.timestamp, ap.hex_lower(), sta.hex_lower(), t.msg_type, kind, &nonce);
                }
            }
            if let Some((kind, mic)) = t.mic_garbage {
                stats.record_invalid_mic(kind);
                if kind != "null" {
                    logger.log_invalid_mic(
                        p.timestamp,
                        ap.hex_lower(),
                        sta.hex_lower(),
                        t.msg_type,
                        kind,
                        mic.as_slice(),
                    );
                }
            }
        }
        if let Some(key) = eapol::parse(&p.body, resolved_dir) {
            store_eapol_key(key, ap, sta, p.timestamp, akm_map, message_store, pmkid_store, stats, logger);
            match (resolved_dir, is_tier1b) {
                (Some(_), true) => stats.eapol_tier1b_essid += 1,
                (Some(_), false) => stats.eapol_tier2_ack_discovery += 1,
                _ => stats.eapol_tier3_flag_fallback += 1,
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
    use super::*;
    use crate::log::Logger;
    use crate::store::messages::PendingEapol;
    use crate::types::MacAddr;

    // --- Test EAPOL frame builder ---

    /// Builds a minimal LLC/SNAP + EAPOL-Key frame for testing.
    ///
    /// `ack` / `install` / `secure` map to Key Information bits B7 / B6 / B9.
    /// `mic_flag` maps to bit B8. MIC bytes are always set to `mic`.
    /// `key_data_extra` is appended after the fixed 99-byte EAPOL body.
    fn make_eapol_frame(
        ack: bool,
        install: bool,
        secure: bool,
        mic_flag: bool,
        nonce: [u8; 32],
        mic: [u8; 16],
        key_data_extra: &[u8],
    ) -> Vec<u8> {
        let mut ki: u16 = 0x0002; // Key Descriptor Version = 2 (HMAC-SHA1/AES)
        ki |= 1 << 3; // Key Type = Pairwise (bit B3)
        if install {
            ki |= 1 << 6;
        }
        if ack {
            ki |= 1 << 7;
        }
        if mic_flag {
            ki |= 1 << 8;
        }
        if secure {
            ki |= 1 << 9;
        }

        let kd_len = key_data_extra.len() as u16;
        let mut frame = Vec::with_capacity(8 + 99 + key_data_extra.len());

        // LLC/SNAP header (8 bytes)
        frame.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);
        // EAPOL header (4 bytes)
        frame.push(0x02); // Protocol Version
        frame.push(0x03); // Packet Type = EAPOL-Key
        let body_len = (95u16 + kd_len).to_be_bytes();
        frame.extend_from_slice(&body_len);
        // EAPOL-Key body
        frame.push(0x02); // Descriptor Type = RSN
        frame.extend_from_slice(&ki.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x10]); // Key Length
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // RC
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&[0u8; 16]); // Key IV
        frame.extend_from_slice(&[0u8; 8]); // Key RSC
        frame.extend_from_slice(&[0u8; 8]); // Reserved
        frame.extend_from_slice(&mic);
        frame.extend_from_slice(&kd_len.to_be_bytes());
        frame.extend_from_slice(key_data_extra);
        frame
    }

    fn nonce_nonzero() -> [u8; 32] {
        let mut n = [0u8; 32];
        n[0] = 0xA5;
        n[31] = 0x5A;
        n
    }

    fn mic_nonzero() -> [u8; 16] {
        let mut m = [0u8; 16];
        m[0] = 0xDE;
        m[15] = 0xAD;
        m
    }

    fn mac(id: u8) -> MacAddr {
        MacAddr([id, id, id, id, id, id])
    }

    #[test]
    fn resolve_wds_tier1b_essid_lookup() {
        // AP is addr_ta (known in essid_map) -> FromAp direction.
        let ap = mac(0xAA);
        let sta = mac(0xBB);
        let mut essid_map = EssidMap::new();
        essid_map.insert(ap, b"TestNet", 1000);
        let mut akm_map = AkmMap::new();
        let mut msg_store = MessageStore::new();
        let mut pmkid_store = PmkidStore::new();
        let mut stats = Stats::new();

        // Build an M1 frame (ACK=1, Install=0, nonce non-zero).
        let body = make_eapol_frame(true, false, false, false, nonce_nonzero(), [0u8; 16], &[]);
        let pending = vec![PendingEapol { body, addr_ta: ap, addr_ra: sta, timestamp: 1000 }];

        let mut logger = Logger::new(None).unwrap();
        resolve_wds_eapol(
            &pending,
            &essid_map,
            &mut akm_map,
            &mut msg_store,
            &mut pmkid_store,
            &mut stats,
            &mut logger,
        );

        assert_eq!(stats.eapol_tier1b_essid, 1);
        assert_eq!(stats.eapol_m1, 1);
        assert_eq!(msg_store.total_count(), 1, "M1 should be stored in message_store");
    }

    #[test]
    fn resolve_wds_tier1b_swaps_ap_sta() {
        // AP is addr_ra (not addr_ta) -> FromSta direction, swap AP/STA.
        let ap = mac(0xAA);
        let sta = mac(0xBB);
        let mut essid_map = EssidMap::new();
        essid_map.insert(ap, b"TestNet", 1000);
        let mut akm_map = AkmMap::new();
        let mut msg_store = MessageStore::new();
        let mut pmkid_store = PmkidStore::new();
        let mut stats = Stats::new();

        // M2 from STA: ACK=0, MIC=1, key_data present. addr_ta=STA, addr_ra=AP.
        let fake_ie = [0x30u8, 0x01, 0xFF];
        let body = make_eapol_frame(false, true, false, false, nonce_nonzero(), mic_nonzero(), &fake_ie);
        let pending = vec![PendingEapol { body, addr_ta: sta, addr_ra: ap, timestamp: 1000 }];

        let mut logger = Logger::new(None).unwrap();
        resolve_wds_eapol(
            &pending,
            &essid_map,
            &mut akm_map,
            &mut msg_store,
            &mut pmkid_store,
            &mut stats,
            &mut logger,
        );

        assert_eq!(stats.eapol_tier1b_essid, 1);
        assert_eq!(stats.eapol_m2, 1);
        // Verify it was stored under (AP, STA), not (STA, AP).
        let pair = crate::types::MacPair { ap, sta };
        let group: Vec<_> = msg_store.groups().filter(|(k, _)| **k == pair).collect();
        assert_eq!(group.len(), 1, "message must be stored under (AP, STA)");
        assert_eq!(group[0].1.len(), 1);
    }

    #[test]
    fn resolve_wds_tier2_ack_discovery() {
        // Neither MAC is known in essid_map. But one frame has ACK=1 from addr_ta=AP.
        // Second pass should discover AP and resolve the non-ACK frame too.
        let ap = mac(0xAA);
        let sta = mac(0xBB);
        let essid_map = EssidMap::new(); // empty
        let mut akm_map = AkmMap::new();
        let mut msg_store = MessageStore::new();
        let mut pmkid_store = PmkidStore::new();
        let mut stats = Stats::new();

        // M1 from AP (ACK=1, addr_ta=AP).
        let m1_body = make_eapol_frame(true, false, false, false, nonce_nonzero(), [0u8; 16], &[]);
        // M2 from STA (ACK=0, addr_ta=STA, addr_ra=AP).
        let fake_ie = [0x30u8, 0x01, 0xFF];
        let m2_body = make_eapol_frame(false, true, false, false, nonce_nonzero(), mic_nonzero(), &fake_ie);

        let pending = vec![
            PendingEapol { body: m1_body, addr_ta: ap, addr_ra: sta, timestamp: 1000 },
            PendingEapol { body: m2_body, addr_ta: sta, addr_ra: ap, timestamp: 1001 },
        ];

        let mut logger = Logger::new(None).unwrap();
        resolve_wds_eapol(
            &pending,
            &essid_map,
            &mut akm_map,
            &mut msg_store,
            &mut pmkid_store,
            &mut stats,
            &mut logger,
        );

        // M1: discovered via ACK=1 in first pass -> tier 2.
        // M2: discovered via addr_ra=AP in second pass -> tier 2.
        assert_eq!(stats.eapol_tier2_ack_discovery, 2);
        assert_eq!(stats.eapol_m1, 1);
        assert_eq!(stats.eapol_m2, 1);
        assert_eq!(msg_store.total_count(), 2);
    }

    #[test]
    fn resolve_wds_tier3_flag_fallback() {
        // Neither MAC is known, no ACK-based discovery possible (no ACK=1 frames).
        // All frames fall through to Tier 3 flag-based.
        let ta = mac(0xAA);
        let ra = mac(0xBB);
        let essid_map = EssidMap::new();
        let mut akm_map = AkmMap::new();
        let mut msg_store = MessageStore::new();
        let mut pmkid_store = PmkidStore::new();
        let mut stats = Stats::new();

        // M2 from STA (ACK=0, MIC_flag=1, Secure=0, body > 95 -> flag-based M2).
        let fake_ie = [0x30u8, 0x01, 0xFF];
        let body = make_eapol_frame(false, false, false, true, nonce_nonzero(), mic_nonzero(), &fake_ie);
        let pending = vec![PendingEapol { body, addr_ta: ta, addr_ra: ra, timestamp: 1000 }];

        let mut logger = Logger::new(None).unwrap();
        resolve_wds_eapol(
            &pending,
            &essid_map,
            &mut akm_map,
            &mut msg_store,
            &mut pmkid_store,
            &mut stats,
            &mut logger,
        );

        assert_eq!(stats.eapol_tier3_flag_fallback, 1);
        assert_eq!(stats.eapol_m2, 1);
        assert_eq!(msg_store.total_count(), 1);
    }

    #[test]
    fn resolve_wds_empty_pending_is_noop() {
        let essid_map = EssidMap::new();
        let mut akm_map = AkmMap::new();
        let mut msg_store = MessageStore::new();
        let mut pmkid_store = PmkidStore::new();
        let mut stats = Stats::new();

        let mut logger = Logger::new(None).unwrap();
        resolve_wds_eapol(&[], &essid_map, &mut akm_map, &mut msg_store, &mut pmkid_store, &mut stats, &mut logger);

        assert_eq!(stats.eapol_tier1b_essid, 0);
        assert_eq!(stats.eapol_tier2_ack_discovery, 0);
        assert_eq!(stats.eapol_tier3_flag_fallback, 0);
        assert_eq!(msg_store.total_count(), 0);
    }

    // --- is_eapol_llc + extract_ack_flag tests (helpers live in common.rs) ---

    use super::super::common::{extract_ack_flag as common_extract_ack_flag, is_eapol_llc};

    #[test]
    fn is_eapol_llc_valid() {
        let body = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E, 0x00];
        assert!(is_eapol_llc(&body));
    }

    #[test]
    fn is_eapol_llc_wrong_ethertype() {
        let body = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]; // IPv4
        assert!(!is_eapol_llc(&body));
    }

    #[test]
    fn is_eapol_llc_wrong_dsap() {
        let body = [0xBB, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];
        assert!(!is_eapol_llc(&body));
    }

    #[test]
    fn is_eapol_llc_too_short() {
        assert!(!is_eapol_llc(&[0xAA, 0xAA, 0x03]));
        assert!(!is_eapol_llc(&[]));
    }

    #[test]
    fn extract_ack_flag_m1() {
        // M1: ACK=1 (bit B7 of Key Information, at body offset 13-14).
        let frame = make_eapol_frame(true, false, false, false, nonce_nonzero(), [0u8; 16], &[]);
        assert_eq!(common_extract_ack_flag(&frame), Some(true));
    }

    #[test]
    fn extract_ack_flag_m2() {
        // M2: ACK=0.
        let fake_ie = [0x30u8, 0x01, 0xFF];
        let frame = make_eapol_frame(false, true, false, false, nonce_nonzero(), mic_nonzero(), &fake_ie);
        assert_eq!(common_extract_ack_flag(&frame), Some(false));
    }

    #[test]
    fn extract_ack_flag_m3() {
        // M3: ACK=1.
        let frame = make_eapol_frame(true, true, true, true, nonce_nonzero(), mic_nonzero(), &[]);
        assert_eq!(common_extract_ack_flag(&frame), Some(true));
    }

    #[test]
    fn extract_ack_flag_too_short() {
        assert_eq!(common_extract_ack_flag(&[0xAA; 10]), None);
        assert_eq!(common_extract_ack_flag(&[]), None);
    }
}
