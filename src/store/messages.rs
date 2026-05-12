//! Phase 3 -- Extract: EAPOL message store (`HashMap<MacPair, Vec<EapolMessage>>`) -- the collect-then-pair invariant. See ARCHITECTURE.md §3.3 + §4.
//!
//! `EapolMessage` holds the complete fields extracted from a single M1/M2/M3/M4 frame:
//! raw EAPOL bytes, nonce, replay counter, MIC, optional PMKID, optional FT fields, and
//! AKM type. `MessageStore` is a `HashMap<MacPair, Vec<EapolMessage>>` -- each (AP, STA)
//! pair gets its own unbounded, append-only vector. No eviction, no ring buffer. This is
//! the central architectural difference from hcxpcapngtool, which uses a 64-entry circular
//! buffer shared across all pairs. See `ARCHITECTURE.md §3.3` and `§4` (invariant 2).

use std::collections::HashMap;
use std::sync::Arc;

use crate::ieee80211::eapol::EapolKey;
use crate::types::{AkmType, FtFields, MacAddr, MacPair, MicBytes, MsgType};

// --- EapolMessage ---

/// A single extracted EAPOL-Key message stored for later pairing.
///
/// Created by combining a parsed `EapolKey` frame with context from the capture:
/// the packet timestamp, the AKM type detected from Beacon/ProbeResponse IEs, and
/// optional FT fields from Association/FTE IEs. See `ARCHITECTURE.md §3.3`.
#[derive(Debug, Clone)]
pub struct EapolMessage {
    /// Packet capture timestamp in microseconds since epoch.
    pub timestamp: u64,
    /// M1, M2, M3, or M4 classification. [IEEE 802.11-2024] §12.7.2
    pub msg_type: MsgType,
    /// Key Descriptor Version (bits B0-B2 of Key Information).
    pub key_version: u8,
    /// EAPOL replay counter (big-endian u64). [IEEE 802.11-2024] §12.7.2
    pub replay_counter: u64,
    /// `ANonce` (M1/M3) or `SNonce` (M2/M4). [IEEE 802.11-2024] §12.7.2
    pub nonce: [u8; 32],
    /// Key MIC -- zero in M1, populated in M2/M3/M4. Width is 16 B (AKMs 1-6, 8, 9, 11)
    /// or 24 B (AKMs 12, 13, 19, 20, 22, 23). [IEEE 802.11-2024] §12.7.2 Table 12-11
    pub mic: MicBytes,
    /// PMKID from M1 Key Data KDE, if present.
    pub pmkid: Option<[u8; 16]>,
    /// Complete raw EAPOL frame bytes (MIC intact; zeroed at output time for hashcat).
    /// Stored as `Arc<[u8]>` so Phase 2 pairing threads can share the frame data without
    /// heap-allocating a copy for each of the millions of `PairedHash` objects.
    /// No size limit applied. [ARCHITECTURE.md §5]
    pub eapol_frame: Arc<[u8]>,
    /// FT-PSK fields (None for non-FT associations). [IEEE 802.11-2024] §9.4.2.45-46
    pub ft: Option<FtFields>,
    /// AKM type from Beacon/ProbeResponse RSN IE context. `Unknown` if no IE was seen.
    pub akm: AkmType,
    /// Whether the EAPOL frame used the RSN descriptor type (0x02 = WPA2/WPA3).
    /// `false` means WPA legacy descriptor type (0xFE). Used to conditionally set
    /// the NC flag in `message_pair` -- hcxpcapngtool omits NC for WPA legacy frames.
    pub is_rsn: bool,
}

impl EapolMessage {
    /// Constructs an `EapolMessage` from a parsed EAPOL-Key frame and capture context.
    ///
    /// `timestamp` is the packet capture time in microseconds. `akm` comes from the
    /// AP's Beacon/ProbeResponse RSN IE (stored in the AKM map before pairing). `ft`
    /// is populated for FT-PSK associations from MDE/FTE IEs.
    #[must_use]
    pub fn from_eapol_key(key: EapolKey, timestamp: u64, akm: AkmType, ft: Option<FtFields>) -> Self {
        Self {
            timestamp,
            msg_type: key.msg_type,
            key_version: key.key_version,
            replay_counter: key.replay_counter,
            nonce: key.nonce,
            mic: key.mic,
            pmkid: key.pmkid,
            eapol_frame: Arc::from(key.eapol_frame),
            ft,
            akm,
            is_rsn: key.is_rsn,
        }
    }
}

// --- MessageStore ---

/// Primary storage for EAPOL messages grouped by (AP, STA) pair.
///
/// Uses `HashMap<MacPair, Vec<EapolMessage>>` -- each (AP, STA) pair gets its own
/// unbounded, append-only vector. Messages are never evicted. The pairing engine
/// (Phase 5) reads from this store after all packets are collected.
/// See `ARCHITECTURE.md §3.3` and `§5.1`.
#[derive(Debug, Default)]
pub struct MessageStore {
    groups: HashMap<MacPair, Vec<EapolMessage>>,
    total_count: usize,
}

impl MessageStore {
    /// Creates an empty `MessageStore`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts an EAPOL message into the group for `(ap, sta)`.
    ///
    /// Creates the group if it does not yet exist. Messages are appended in
    /// arrival order; the pairing engine sorts by timestamp before pairing.
    ///
    /// **Dedup-on-insert.** A new message whose `(msg_type, akm, eapol_frame)`
    /// tuple already appears in the group is dropped silently. Two byte-
    /// identical EAPOL frames for the same `(AP, STA)` and the same logical
    /// role are the same message observed twice on the air -- they would
    /// pair into identical combos and the global `SipHash` fingerprint at emit
    /// time (`output::dedup`) would have collapsed the resulting hashcat
    /// lines to one anyway. Dropping at insert time bounds `MessageStore`
    /// memory on captures full of retransmissions without changing the
    /// output sorted-content sha256.
    ///
    /// `msg_type` is part of the key because Tier 1 direction-based and
    /// Tier 3 flag-based classification can assign different `MsgType`
    /// labels to byte-identical EAPOL frames (a `FromSta` data frame whose
    /// EAPOL body has `Install=1` lands as M2 under Tier 1 but M3 under
    /// the WDS Tier 3 fallback). Both labels are kept so pair generation
    /// can still produce the M3-nonce-with-M2-eapol combo where applicable.
    ///
    /// `akm` is part of the key because the same frame bytes could in
    /// principle be tagged with a different `AkmType` if the surrounding
    /// RSN-IE context advanced between two observations.
    pub fn add(&mut self, ap: MacAddr, sta: MacAddr, msg: EapolMessage) {
        let entries = self.groups.entry(MacPair::new(ap, sta)).or_default();
        if entries.iter().any(|m| m.msg_type == msg.msg_type && m.akm == msg.akm && m.eapol_frame == msg.eapol_frame) {
            return;
        }
        entries.push(msg);
        self.total_count += 1;
    }

    /// Iterates over all (AP, STA) groups and their message vectors.
    pub fn groups(&self) -> impl Iterator<Item = (&MacPair, &Vec<EapolMessage>)> {
        self.groups.iter()
    }

    /// Returns the total number of EAPOL messages stored across all groups.
    #[must_use]
    pub const fn total_count(&self) -> usize {
        self.total_count
    }

    /// Returns the number of distinct (AP, STA) groups.
    #[must_use]
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Drops every group and resets the total-message counter.
    ///
    /// Used by `--per-file` mode to reclaim store memory after each input
    /// file's hashes have been emitted. The map's capacity is *not* shrunk so
    /// the next file reuses the existing buckets (saves a re-alloc when the
    /// per-file pair count is similar across files).
    pub fn clear(&mut self) {
        self.groups.clear();
        self.total_count = 0;
    }

    /// Coarse heap + struct-bytes estimate for `--mem-stats` reporting.
    ///
    /// Sums the `HashMap` bucket overhead, every `Vec<EapolMessage>` allocation,
    /// every `EapolMessage` struct in the vectors, and every `Arc<[u8]>` payload
    /// each message holds. The Arc payloads are NOT deduplicated across pairs --
    /// a message that appears in two groups (rare; happens only for WDS resolution)
    /// is counted twice. Operators reading the report should treat this as an
    /// upper-bound on the EAPOL-store footprint.
    #[must_use]
    pub fn approx_bytes(&self) -> usize {
        let groups_cap_bytes = self.groups.capacity() * (size_of::<MacPair>() + size_of::<Vec<EapolMessage>>() + 8);
        let mut msgs_bytes = 0usize;
        for v in self.groups.values() {
            msgs_bytes += v.capacity() * size_of::<EapolMessage>();
            // Arc<[u8]> heap payload per message: 16-byte ArcInner header + bytes.
            for m in v {
                msgs_bytes = msgs_bytes.saturating_add(m.eapol_frame.len() + 16);
            }
        }
        size_of::<Self>() + groups_cap_bytes + msgs_bytes
    }

    /// Rewrites every group key and embedded `(ap, sta)` addresses using `canonicalize`,
    /// then merges groups that collide under the canonical key.
    ///
    /// Callers typically pass a closure that looks up the MLD MAC in an `MldStore`; any
    /// link address unknown to the store is returned unchanged. Groups whose canonical
    /// keys are already unique (the non-11be case) are preserved bit-identically.
    ///
    /// Returns the number of `(AP, STA)` groups that were merged into another group as
    /// a result of canonicalization -- zero when no MLD mapping changed any key.
    pub fn canonicalize_pairs<F>(&mut self, mut canonicalize: F) -> u64
    where
        F: FnMut(MacAddr) -> MacAddr,
    {
        let old = std::mem::take(&mut self.groups);
        let old_group_count = old.len();
        let old_total = self.total_count;
        self.total_count = 0;
        for (pair, mut msgs) in old {
            let canon_ap = canonicalize(pair.ap);
            let canon_sta = canonicalize(pair.sta);
            // Nothing changed for this pair if both addresses already equal the canonical form.
            let canon_pair = MacPair::new(canon_ap, canon_sta);
            self.total_count += msgs.len();
            // Messages may carry any addresses in their frame-level fields; the EapolMessage
            // struct does not store ap/sta per-message (they live in the store key), so we
            // only need to rewrite the key.
            self.groups.entry(canon_pair).or_default().append(&mut msgs);
        }
        debug_assert_eq!(self.total_count, old_total, "canonicalization must not drop messages");
        // Merged groups = (old distinct keys) - (new distinct keys).
        (old_group_count as u64).saturating_sub(self.groups.len() as u64)
    }

    /// Folds the earliest and latest message timestamps for every AP MAC in
    /// `wanted` into the `out` map.
    ///
    /// For each AP MAC present in `wanted`, scans every group whose key has
    /// that AP and updates the `(first_us, last_us)` tuple in `out` with the
    /// minimum / maximum `EapolMessage::timestamp` observed. Entries are
    /// inserted on demand. APs with no matching messages are left untouched.
    ///
    /// Used by the output pipeline to log a per-AP timestamp range for
    /// "`essid_not_found`" APs so the operator can locate the source frames in
    /// the original capture without having to grep the whole `MessageStore`.
    pub fn fold_timestamp_range_into(
        &self,
        wanted: &std::collections::HashSet<MacAddr>,
        out: &mut HashMap<MacAddr, (u64, u64)>,
    ) {
        for (mac_pair, msgs) in &self.groups {
            if !wanted.contains(&mac_pair.ap) {
                continue;
            }
            for msg in msgs {
                let entry = out.entry(mac_pair.ap).or_insert((u64::MAX, 0));
                entry.0 = entry.0.min(msg.timestamp);
                entry.1 = entry.1.max(msg.timestamp);
            }
        }
    }

    /// Counts (AP, STA) groups where any M1 `ANonce` differs from any M3 `ANonce`.
    ///
    /// Per IEEE 802.11-2024 §12.7.6.4, the `ANonce` in M3 must equal the `ANonce` in M1
    /// of the same 4-way handshake session: both are committed outputs of the AP's PTK
    /// derivation. A mismatch under the same `(AP, STA)` key means one of:
    ///
    /// 1. AP firmware regenerated a nonce between M1 and M3 (rare non-spec behavior).
    /// 2. Two interleaved handshake attempts collapsed into one `MacPair` because a
    ///    client reconnected within the capture window.
    /// 3. An injected or spoofed M3 frame from a different endpoint.
    ///
    /// This is a capture-quality diagnostic: wpawolf already emits both N1* and N3*
    /// combos, so output correctness is unaffected. A high count hints that a
    /// `--eapoltimeout` filter would be worthwhile.
    #[must_use]
    pub fn count_anonce_m1_m3_mismatches(&self) -> u64 {
        let mut mismatches: u64 = 0;
        for msgs in self.groups.values() {
            // Collect all distinct M1 and M3 ANonces in this group.
            let mut m1_nonces: Vec<[u8; 32]> = Vec::new();
            let mut m3_nonces: Vec<[u8; 32]> = Vec::new();
            for msg in msgs {
                let bucket = match msg.msg_type {
                    MsgType::M1 => &mut m1_nonces,
                    MsgType::M3 => &mut m3_nonces,
                    MsgType::M2 | MsgType::M4 => continue,
                };
                if !bucket.contains(&msg.nonce) {
                    bucket.push(msg.nonce);
                }
            }

            // Rule: a session is "mismatched" if either
            //   (a) there are multiple distinct M1 ANonces -- two handshake attempts collapsed, OR
            //   (b) there are multiple distinct M3 ANonces -- same, or
            //   (c) we have at least one of each and some M1 nonce disagrees with some M3 nonce.
            // Case (c) requires actually comparing; (a) and (b) stand alone.
            let multi_m1 = m1_nonces.len() > 1;
            let multi_m3 = m3_nonces.len() > 1;
            let cross_mismatch = if !m1_nonces.is_empty() && !m3_nonces.is_empty() {
                // Any pair where M1 ANonce != M3 ANonce is a mismatch.
                m1_nonces.iter().any(|n1| m3_nonces.iter().any(|n3| n1 != n3))
            } else {
                false
            };

            if multi_m1 || multi_m3 || cross_mismatch {
                mismatches += 1;
            }
        }
        mismatches
    }
}

// --- PendingEapol (deferred WDS EAPOL) ---

/// A deferred EAPOL frame from a WDS (4-address) data frame.
///
/// Direction is ambiguous for WDS relay frames (ToDS=1, FromDS=1) because the
/// transmitter address (addr2) could be either the AP or a relay node. These frames
/// are stored during Phase 1 and classified after the ESSID map is fully populated
/// (Phase 1.5), using a tiered resolution: `essid_map` lookup -> ACK-based AP discovery
/// -> flag-based fallback. [IEEE 802.11-2024] §9.3.2.1.2, Table 9-60.
#[derive(Debug)]
pub struct PendingEapol {
    /// Raw frame body from LLC/SNAP onward (same input as `eapol::parse()`).
    pub body: Vec<u8>,
    /// addr2 (transmitter address) -- `frame::parse()` labels this as `ap` for WDS frames.
    pub addr_ta: MacAddr,
    /// addr1 (receiver address) -- `frame::parse()` labels this as `sta` for WDS frames.
    pub addr_ra: MacAddr,
    /// Capture timestamp in microseconds.
    pub timestamp: u64,
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
    use crate::ieee80211::eapol;

    // Returns a MacAddr with all bytes set to `b`.
    fn mac(b: u8) -> MacAddr {
        MacAddr::from_bytes([b; 6])
    }

    // Builds a minimal valid M1 EapolKey by parsing a crafted frame.
    // Returns None if the internal parse fails (test will panic via unwrap at call site).
    fn minimal_eapol_key() -> EapolKey {
        minimal_eapol_key_with_discriminator(0xA5)
    }

    // Same as `minimal_eapol_key` but lets the caller inject a byte into the nonce so
    // two `add()` calls produce non-byte-identical EAPOL frames. Without this, the
    // dedup-on-insert path in `MessageStore::add` collapses identical messages.
    fn minimal_eapol_key_with_discriminator(disc: u8) -> EapolKey {
        // Construct the same way eapol::tests::make_eapol does:
        // LLC/SNAP + EAPOL-Key header + body.
        let nonce: [u8; 32] = {
            let mut n = [0u8; 32];
            n[0] = disc;
            n
        };
        let mut ki: u16 = 2; // KDV=2
        ki |= 1 << 7; // Key Ack=1 -> M1
        let kd_len: u16 = 0;
        let mut frame: Vec<u8> = Vec::new();
        // LLC/SNAP (8 bytes)
        frame.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);
        // EAPOL header (4 bytes)
        frame.push(0x02); // version
        frame.push(0x03); // packet type = EAPOL-Key
        frame.extend_from_slice(&95u16.to_be_bytes()); // body length
        // EAPOL-Key body
        frame.push(0x02); // descriptor type = RSN
        frame.extend_from_slice(&ki.to_be_bytes()); // key info
        frame.extend_from_slice(&[0x00, 0x10]); // key length
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // replay counter
        frame.extend_from_slice(&nonce); // nonce (32)
        frame.extend_from_slice(&[0u8; 16]); // key IV
        frame.extend_from_slice(&[0u8; 8]); // key RSC
        frame.extend_from_slice(&[0u8; 8]); // reserved
        frame.extend_from_slice(&[0u8; 16]); // MIC (zero for M1)
        frame.extend_from_slice(&kd_len.to_be_bytes()); // key data length
        eapol::parse(&frame, None).expect("minimal M1 frame must parse")
    }

    #[test]
    fn add_single_message() {
        let mut store = MessageStore::new();
        let ap = mac(0x11);
        let sta = mac(0x22);
        let key = minimal_eapol_key();
        let msg = EapolMessage::from_eapol_key(key, 1_000, AkmType::Wpa2Psk, None);
        store.add(ap, sta, msg);
        assert_eq!(store.total_count(), 1);
        assert_eq!(store.group_count(), 1);
    }

    #[test]
    fn add_two_messages_same_pair() {
        // Distinct discriminators -> two non-byte-identical EAPOL frames, both stored
        // by the dedup-on-insert path. Byte-identical retransmissions are exercised
        // by `add_byte_identical_message_deduped`.
        let mut store = MessageStore::new();
        let ap = mac(0x11);
        let sta = mac(0x22);
        store.add(
            ap,
            sta,
            EapolMessage::from_eapol_key(minimal_eapol_key_with_discriminator(0x11), 1_000, AkmType::Wpa2Psk, None),
        );
        store.add(
            ap,
            sta,
            EapolMessage::from_eapol_key(minimal_eapol_key_with_discriminator(0x22), 2_000, AkmType::Wpa2Psk, None),
        );
        assert_eq!(store.total_count(), 2);
        assert_eq!(store.group_count(), 1);
    }

    #[test]
    fn add_byte_identical_message_deduped() {
        // Two `add()` calls with identical (msg_type, akm, eapol_frame) tuples must
        // collapse to one stored message -- this is the dedup-on-insert invariant
        // that bounds `MessageStore` memory on retransmission-heavy captures.
        let mut store = MessageStore::new();
        let ap = mac(0x11);
        let sta = mac(0x22);
        store.add(ap, sta, EapolMessage::from_eapol_key(minimal_eapol_key(), 1_000, AkmType::Wpa2Psk, None));
        store.add(ap, sta, EapolMessage::from_eapol_key(minimal_eapol_key(), 2_000, AkmType::Wpa2Psk, None));
        assert_eq!(store.total_count(), 1, "retransmission collapsed by dedup-on-insert");
        assert_eq!(store.group_count(), 1);
    }

    #[test]
    fn add_two_messages_different_pairs() {
        let mut store = MessageStore::new();
        let ap1 = mac(0x11);
        let sta1 = mac(0x22);
        let ap2 = mac(0x33);
        let sta2 = mac(0x44);
        store.add(ap1, sta1, EapolMessage::from_eapol_key(minimal_eapol_key(), 1_000, AkmType::Wpa2Psk, None));
        store.add(ap2, sta2, EapolMessage::from_eapol_key(minimal_eapol_key(), 2_000, AkmType::Wpa2Psk, None));
        assert_eq!(store.total_count(), 2);
        assert_eq!(store.group_count(), 2);
    }

    #[test]
    fn groups_iter_contains_all() {
        let mut store = MessageStore::new();
        let ap1 = mac(0xAA);
        let sta1 = mac(0xBB);
        let ap2 = mac(0xCC);
        let sta2 = mac(0xDD);
        // Two distinct messages for pair 1 (different discriminators dodge the
        // dedup-on-insert path), one for pair 2.
        store.add(
            ap1,
            sta1,
            EapolMessage::from_eapol_key(minimal_eapol_key_with_discriminator(0x11), 1_000, AkmType::Wpa2Psk, None),
        );
        store.add(
            ap1,
            sta1,
            EapolMessage::from_eapol_key(minimal_eapol_key_with_discriminator(0x22), 2_000, AkmType::Wpa2Psk, None),
        );
        store.add(ap2, sta2, EapolMessage::from_eapol_key(minimal_eapol_key(), 3_000, AkmType::Wpa2Psk, None));

        let mut pair_counts: Vec<usize> = store.groups().map(|(_, msgs)| msgs.len()).collect();
        pair_counts.sort_unstable();
        assert_eq!(pair_counts, vec![1, 2]);
        assert_eq!(store.groups().count(), 2);
    }

    // --- count_anonce_m1_m3_mismatches tests ---

    // Build a test EapolMessage with the given type and nonce. Fields not exercised
    // by the mismatch counter (RC, EAPOL frame, MIC, etc.) are stock values. The
    // `eapol_frame` body embeds `nonce[0]` so two calls with distinct nonces produce
    // distinct frame bodies -- otherwise `MessageStore::add`'s dedup-on-insert path
    // would collapse messages that this helper deliberately keeps distinct.
    fn msg_with_nonce(msg_type: MsgType, nonce: [u8; 32]) -> EapolMessage {
        EapolMessage {
            timestamp: 0,
            msg_type,
            key_version: 2,
            replay_counter: 0,
            nonce,
            mic: MicBytes::ZERO_16,
            pmkid: None,
            eapol_frame: Arc::from(vec![nonce[0], 0u8, 0u8, 0u8]),
            ft: None,
            akm: AkmType::Wpa2Psk,
            is_rsn: true,
        }
    }

    #[test]
    fn anonce_mismatch_matching_nonces_no_count() {
        // Single session: M1 and M3 share the same ANonce -> spec-compliant, no count.
        let mut store = MessageStore::new();
        let nonce = [0xAA; 32];
        store.add(mac(0x11), mac(0x22), msg_with_nonce(MsgType::M1, nonce));
        store.add(mac(0x11), mac(0x22), msg_with_nonce(MsgType::M3, nonce));
        assert_eq!(store.count_anonce_m1_m3_mismatches(), 0);
    }

    #[test]
    fn anonce_mismatch_differing_nonces_counted() {
        // Classic cross-session pollution: M1 and M3 carry different ANonces.
        let mut store = MessageStore::new();
        let n1 = [0x11; 32];
        let n3 = [0x33; 32];
        store.add(mac(0x11), mac(0x22), msg_with_nonce(MsgType::M1, n1));
        store.add(mac(0x11), mac(0x22), msg_with_nonce(MsgType::M3, n3));
        assert_eq!(store.count_anonce_m1_m3_mismatches(), 1);
    }

    #[test]
    fn anonce_mismatch_requires_both_m1_and_m3() {
        // Only M1 present, or only M3 present -- nothing to compare, count stays at 0.
        let mut store = MessageStore::new();
        store.add(mac(0x11), mac(0x22), msg_with_nonce(MsgType::M1, [0x11; 32]));
        store.add(mac(0x33), mac(0x44), msg_with_nonce(MsgType::M3, [0x33; 32]));
        assert_eq!(store.count_anonce_m1_m3_mismatches(), 0);
    }

    #[test]
    fn anonce_mismatch_two_m1s_differ() {
        // Two distinct M1s in the same group -- the client saw two separate handshake
        // attempts. Counts as a mismatch once an M3 is present.
        let mut store = MessageStore::new();
        store.add(mac(0x11), mac(0x22), msg_with_nonce(MsgType::M1, [0x11; 32]));
        store.add(mac(0x11), mac(0x22), msg_with_nonce(MsgType::M1, [0x22; 32]));
        store.add(mac(0x11), mac(0x22), msg_with_nonce(MsgType::M3, [0x11; 32]));
        assert_eq!(store.count_anonce_m1_m3_mismatches(), 1);
    }

    #[test]
    fn anonce_mismatch_per_pair_counted_once() {
        // Two independent groups, each with a mismatch -> count is 2.
        let mut store = MessageStore::new();
        store.add(mac(0x11), mac(0x22), msg_with_nonce(MsgType::M1, [0x11; 32]));
        store.add(mac(0x11), mac(0x22), msg_with_nonce(MsgType::M3, [0x22; 32]));
        store.add(mac(0x33), mac(0x44), msg_with_nonce(MsgType::M1, [0x33; 32]));
        store.add(mac(0x33), mac(0x44), msg_with_nonce(MsgType::M3, [0x44; 32]));
        assert_eq!(store.count_anonce_m1_m3_mismatches(), 2);
    }

    #[test]
    fn canonicalize_pairs_merges_via_mld() {
        // Two distinct (AP, STA) groups whose STA addresses both canonicalize to the
        // same MLD MAC -> they should merge into a single group after canonicalization.
        let mut store = MessageStore::new();
        let ap = mac(0xAA);
        let link_a = mac(0x11);
        let link_b = mac(0x22);
        let mld = mac(0x55);
        store.add(ap, link_a, msg_with_nonce(MsgType::M1, [0x01; 32]));
        store.add(ap, link_b, msg_with_nonce(MsgType::M3, [0x01; 32]));
        assert_eq!(store.group_count(), 2);
        assert_eq!(store.total_count(), 2);

        let merged = store.canonicalize_pairs(|m| if m == link_a || m == link_b { mld } else { m });
        assert_eq!(store.group_count(), 1, "two links sharing one MLD must merge");
        assert_eq!(store.total_count(), 2, "messages preserved across merge");
        assert_eq!(merged, 1, "one group was merged into another");
    }

    #[test]
    fn canonicalize_pairs_noop_for_unmapped_addresses() {
        // No MLD mappings -> identity function; every group preserved.
        let mut store = MessageStore::new();
        store.add(mac(0x11), mac(0x22), msg_with_nonce(MsgType::M1, [0u8; 32]));
        store.add(mac(0x33), mac(0x44), msg_with_nonce(MsgType::M3, [0u8; 32]));
        let merged = store.canonicalize_pairs(|m| m);
        assert_eq!(store.group_count(), 2);
        assert_eq!(merged, 0);
    }

    #[test]
    fn anonce_mismatch_m2_m4_ignored() {
        // M2 (SNonce) and M4 (SNonce) must not influence the M1/M3 ANonce comparison.
        let mut store = MessageStore::new();
        let n = [0xAB; 32];
        store.add(mac(0x11), mac(0x22), msg_with_nonce(MsgType::M1, n));
        store.add(mac(0x11), mac(0x22), msg_with_nonce(MsgType::M2, [0xCD; 32]));
        store.add(mac(0x11), mac(0x22), msg_with_nonce(MsgType::M3, n));
        store.add(mac(0x11), mac(0x22), msg_with_nonce(MsgType::M4, [0xEF; 32]));
        assert_eq!(store.count_anonce_m1_m3_mismatches(), 0);
    }

    #[test]
    fn from_eapol_key_copies_fields() {
        let key = minimal_eapol_key();
        // Capture the fields before moving key.
        let expected_msg_type = key.msg_type;
        let expected_kv = key.key_version;
        let expected_rc = key.replay_counter;
        let expected_nonce = key.nonce;
        let expected_mic = key.mic;
        let expected_pmkid = key.pmkid;
        let expected_frame: Vec<u8> = key.eapol_frame.clone();

        let msg = EapolMessage::from_eapol_key(key, 999, AkmType::FtPsk, None);
        assert_eq!(msg.timestamp, 999);
        assert_eq!(msg.msg_type, expected_msg_type);
        assert_eq!(msg.key_version, expected_kv);
        assert_eq!(msg.replay_counter, expected_rc);
        assert_eq!(msg.nonce, expected_nonce);
        assert_eq!(msg.mic, expected_mic);
        assert_eq!(msg.pmkid, expected_pmkid);
        assert_eq!(*msg.eapol_frame, *expected_frame);
        assert!(msg.ft.is_none());
        assert_eq!(msg.akm, AkmType::FtPsk);
    }
}
