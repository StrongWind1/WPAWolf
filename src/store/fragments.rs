//! Phase 3 -- Extract: 802.11 MSDU fragmentation reassembly buffer. See
//! ARCHITECTURE.md §3.3.
//!
//! 802.11 supports fragmenting a single MSDU across multiple Data frames; an
//! EAPOL-Key MMPDU larger than the radio MTU (rare for v2-style WPA2 handshakes,
//! occasional for FT-PSK M2 with extended IEs) arrives as N+1 frames sharing the
//! same Sequence Number with Fragment Number 0..N. Per [IEEE 802.11-2024]
//! §9.2.4.1.5 / §9.2.4.4, every fragment except the last sets the More Fragments
//! flag (FC bit B10).
//!
//! # Lifecycle
//!
//! * On any fragment: the body bytes are stored in the per-(`SA`, `RA`, `SeqNum`)
//!   entry keyed by fragment number. Fragments may arrive in any order.
//! * Reassembly completes when the entry contains every fragment 0..=N and the
//!   final fragment (MoreFrag=0, FragNum>0) has been seen, establishing N.
//! * On a non-fragmented frame (`MoreFrag=0`, `FragNum=0`): no buffer is
//!   touched; the caller processes the body directly.
//!
//! # Memory bounds
//!
//! A pathological capture full of orphaned fragments that never complete could in
//! theory pin arbitrary memory. `MAX_ENTRIES` is a paranoid backstop against that,
//! sized so generously (1 M slots, ~60-200 MiB worst case depending on body sizes)
//! that no real-world capture should ever hit it. When the bound is reached, the
//! oldest entry by first-fragment timestamp is evicted and
//! `fragments_dropped_safety_cap` increments -- that counter is expected to stay at
//! 0 on legitimate captures; non-zero values indicate either an adversarial input or
//! that the bound itself needs revisiting. Time-based expiry is intentionally not
//! implemented.
//!
//! # Out of scope
//!
//! A-MSDU and A-MPDU aggregation (multiple MSDUs in one MPDU / multiple MPDUs
//! in one PHY-layer aggregate) are *separate* mechanisms and are not handled
//! here. Most WPA2/WPA3 EAPOL-Key handshakes traverse the radio as a single
//! unfragmented MPDU and do not exercise this code at all.

use std::collections::HashMap;

use crate::types::MacAddr;

/// Maximum number of in-flight fragmented MSDUs to keep buffered before evicting
/// the oldest entry. Sized as a paranoid backstop against an adversarial capture
/// that ships endless orphaned fragments that never complete; 1 M slots are
/// deliberately way above what any real capture exercises so that legitimate
/// fragments are never dropped. Worst-case memory at the cap is ~60-200 MiB
/// depending on body sizes, small next to `MessageStore`'s working set on the
/// same capture.
const MAX_ENTRIES: usize = 1_000_000;

/// Per-MSDU reassembly key. SA / RA pair plus Sequence Number identifies a
/// single MSDU per [IEEE 802.11-2024] §9.2.4.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FragKey {
    sa: MacAddr,
    ra: MacAddr,
    seq_num: u16,
}

/// In-flight reassembly state for one MSDU.
#[derive(Debug)]
struct FragEntry {
    /// Per-fragment bodies keyed by fragment number. Fragments may arrive in
    /// any order; reassembly concatenates 0..=`final_frag_num` when complete.
    /// The Fragment Number field is 4 bits per [IEEE 802.11-2024] §9.2.4.4.1,
    /// so at most 16 entries.
    parts: HashMap<u8, Vec<u8>>,
    /// Set when the final fragment (`MoreFrag=0`, `FragNum>0`) arrives. The
    /// value is that fragment's `FragNum`; reassembly is complete when `parts`
    /// contains every key in `0..=final_frag_num`.
    final_frag_num: Option<u8>,
    /// Timestamp of the first fragment seen for this MSDU (any `FragNum`),
    /// used as the entry's age for safety-cap eviction.
    first_seen_us: u64,
}

/// Bounded reassembly buffer for fragmented 802.11 MSDUs.
///
/// `insert_fragment` stores any fragment and returns the reassembled MSDU body
/// when all fragments 0..=N are present and the final fragment has been seen.
/// Fragments may arrive in any order. Memory is bounded by `max_entries`
/// (default `MAX_ENTRIES`): when full, the oldest entry by first-fragment
/// timestamp is evicted to make room for the new one. The bound is a paranoid
/// backstop sized so it should never fire on legitimate captures; see the
/// module-level docs.
#[derive(Debug)]
pub struct FragmentStore {
    entries: HashMap<FragKey, FragEntry>,
    max_entries: usize,
}

impl Default for FragmentStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Counters returned alongside reassembly events so the caller can update its
/// own `Stats` struct without reaching into private fields.
#[derive(Debug, Default, Clone, Copy)]
pub struct FragmentStats {
    /// Bumped each time `insert_fragment` buffers a fragment. A retransmitted
    /// fragment (same `FragNum` for the same key) overwrites the body but still
    /// increments this counter -- it is "fragments observed", not "distinct
    /// fragment bodies stored".
    pub fragments_seen: u64,
    /// MSDUs successfully reassembled and returned by `insert_fragment`.
    pub fragments_reassembled: u64,
    /// In-flight entries that never completed reassembly -- set from
    /// `FragmentStore::len()` at end of run, not during processing. Indicates
    /// genuinely missing fragments in the capture (partial radio visibility,
    /// channel hops, CRC failures on the monitor NIC).
    pub fragments_incomplete: u64,
    /// Entries evicted because the paranoid `MAX_ENTRIES` safety backstop was
    /// reached. Expected to be 0 on legitimate captures; non-zero values
    /// indicate either an adversarial input or that the backstop is sized
    /// wrong for the workload.
    pub fragments_dropped_safety_cap: u64,
}

impl FragmentStore {
    /// Creates an empty fragment store with the production safety cap.
    #[must_use]
    pub fn new() -> Self {
        Self { entries: HashMap::new(), max_entries: MAX_ENTRIES }
    }

    /// Test helper: creates an empty fragment store with a custom safety cap
    /// so eviction can be exercised without building a million entries.
    #[cfg(test)]
    fn with_max_entries(max_entries: usize) -> Self {
        Self { entries: HashMap::new(), max_entries }
    }

    /// Inserts a fragment into the reassembly buffer and returns the fully
    /// reassembled MSDU body if this fragment completed the set, `None`
    /// otherwise.
    ///
    /// Accepts fragments in any order. Reassembly completes when:
    /// 1. The final fragment (`MoreFrag=0`, `FragNum>0`) has been seen, AND
    /// 2. All fragment numbers `0..=final_frag_num` are present in the entry.
    ///
    /// Retransmitted fragments (same `FragNum` for the same key) overwrite
    /// the stored body silently -- retransmissions are common over the air.
    pub fn insert_fragment(
        &mut self,
        sa: MacAddr,
        ra: MacAddr,
        seq_num: u16,
        frag_num: u8,
        more_fragments: bool,
        body: &[u8],
        timestamp_us: u64,
        stats: &mut FragmentStats,
    ) -> Option<Vec<u8>> {
        let key = FragKey { sa, ra, seq_num };

        // Evict the oldest entry if at capacity and this key is new.
        if !self.entries.contains_key(&key)
            && self.entries.len() >= self.max_entries
            && let Some(victim_key) = self.oldest_key()
        {
            self.entries.remove(&victim_key);
            stats.fragments_dropped_safety_cap += 1;
        }

        let entry = self.entries.entry(key).or_insert_with(|| FragEntry {
            parts: HashMap::new(),
            final_frag_num: None,
            first_seen_us: timestamp_us,
        });

        entry.parts.insert(frag_num, body.to_vec());
        stats.fragments_seen += 1;

        if !more_fragments {
            entry.final_frag_num = Some(frag_num);
        }

        // Check if reassembly is complete: final fragment seen AND every
        // fragment 0..=final_frag_num present.
        let final_num = entry.final_frag_num?;
        if !(0..=final_num).all(|n| entry.parts.contains_key(&n)) {
            return None;
        }

        // All fragments present. Concatenate in ascending order and return.
        let completed = self.entries.remove(&key)?;
        let mut full = Vec::new();
        for n in 0..=final_num {
            if let Some(part) = completed.parts.get(&n) {
                full.extend_from_slice(part);
            }
        }
        stats.fragments_reassembled += 1;
        Some(full)
    }

    /// Currently buffered partial-MSDU count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Coarse heap + struct-bytes estimate for `--mem-stats` reporting.
    #[must_use]
    pub fn approx_bytes(&self) -> usize {
        let entry_overhead = size_of::<FragKey>() + size_of::<FragEntry>() + 8;
        let table_bytes = self.entries.capacity() * entry_overhead;
        let body_bytes: usize = self.entries.values().map(|e| e.parts.values().map(Vec::capacity).sum::<usize>()).sum();
        let parts_overhead: usize =
            self.entries.values().map(|e| e.parts.capacity() * (size_of::<u8>() + size_of::<Vec<u8>>() + 8)).sum();
        size_of::<Self>() + table_bytes + body_bytes + parts_overhead
    }

    /// True iff the store holds no in-flight fragments.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Helper: find the key with the oldest `first_seen_us`, used for
    /// safety-cap eviction.
    fn oldest_key(&self) -> Option<FragKey> {
        self.entries.iter().min_by_key(|(_, e)| e.first_seen_us).map(|(k, _)| *k)
    }
}

// --- Unit tests ---

#[cfg(test)]
mod tests {

    use super::*;

    fn mac(b: u8) -> MacAddr {
        MacAddr::from_bytes([b; 6])
    }

    #[test]
    fn unfragmented_frame_does_not_touch_store() {
        let s = FragmentStore::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn two_fragment_eapol_reassembles() {
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();
        let sa = mac(0xAA);
        let ra = mac(0xBB);
        let seq = 42;

        // First fragment, MoreFrag=1, FragNum=0.
        let result = s.insert_fragment(sa, ra, seq, 0, true, b"AAAAAAAAAA", 1_000_000, &mut st);
        assert!(result.is_none(), "not yet complete");
        assert_eq!(s.len(), 1);

        // Final fragment, MoreFrag=0, FragNum=1.
        let full =
            s.insert_fragment(sa, ra, seq, 1, false, b"BBBBBBBBBB", 1_000_001, &mut st).expect("must reassemble");
        assert_eq!(full, b"AAAAAAAAAABBBBBBBBBB");
        assert!(s.is_empty(), "completed entry must be removed");
        assert_eq!(st.fragments_reassembled, 1);
        assert_eq!(st.fragments_seen, 2);
    }

    #[test]
    fn three_fragment_msdu_reassembles_in_order() {
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();
        let sa = mac(0x11);
        let ra = mac(0x22);
        let seq = 7;

        assert!(s.insert_fragment(sa, ra, seq, 0, true, b"X", 1, &mut st).is_none());
        assert!(s.insert_fragment(sa, ra, seq, 1, true, b"Y", 2, &mut st).is_none());
        let full = s.insert_fragment(sa, ra, seq, 2, false, b"Z", 3, &mut st).unwrap();
        assert_eq!(full, b"XYZ");
        assert_eq!(st.fragments_seen, 3);
        assert_eq!(st.fragments_reassembled, 1);
    }

    #[test]
    fn out_of_order_fragments_reassemble() {
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();
        let sa = mac(0x11);
        let ra = mac(0x22);
        let seq = 7;

        // Final fragment arrives first.
        assert!(s.insert_fragment(sa, ra, seq, 2, false, b"Z", 1, &mut st).is_none());
        // Middle fragment.
        assert!(s.insert_fragment(sa, ra, seq, 1, true, b"Y", 2, &mut st).is_none());
        // First fragment completes the set.
        let full = s.insert_fragment(sa, ra, seq, 0, true, b"X", 3, &mut st).unwrap();
        assert_eq!(full, b"XYZ");
        assert_eq!(st.fragments_seen, 3);
        assert_eq!(st.fragments_reassembled, 1);
    }

    #[test]
    fn reverse_order_two_fragments() {
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();
        let sa = mac(0xAA);
        let ra = mac(0xBB);
        let seq = 42;

        // Final fragment arrives first.
        assert!(s.insert_fragment(sa, ra, seq, 1, false, b"BBBBBBBBBB", 1, &mut st).is_none());
        assert_eq!(s.len(), 1);

        // First fragment arrives second -- completes reassembly.
        let full = s.insert_fragment(sa, ra, seq, 0, true, b"AAAAAAAAAA", 2, &mut st).unwrap();
        assert_eq!(full, b"AAAAAAAAAABBBBBBBBBB");
        assert!(s.is_empty());
        assert_eq!(st.fragments_reassembled, 1);
    }

    #[test]
    fn duplicate_fragment_overwrites_body() {
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();
        let sa = mac(0x11);
        let ra = mac(0x22);

        s.insert_fragment(sa, ra, 1, 0, true, b"old", 1, &mut st);
        s.insert_fragment(sa, ra, 1, 0, true, b"new", 2, &mut st);
        let full = s.insert_fragment(sa, ra, 1, 1, false, b"+rest", 3, &mut st).unwrap();
        assert_eq!(full, b"new+rest");
    }

    #[test]
    fn orphan_final_fragment_stays_buffered() {
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();
        let result = s.insert_fragment(mac(0x11), mac(0x22), 1, 1, false, b"orphan", 1, &mut st);
        assert!(result.is_none());
        assert_eq!(s.len(), 1, "orphan entry stays buffered awaiting frag 0");
        assert_eq!(st.fragments_reassembled, 0);
        assert_eq!(st.fragments_seen, 1);
    }

    #[test]
    fn orphan_final_completes_when_frag0_arrives() {
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();
        let sa = mac(0x11);
        let ra = mac(0x22);

        // Final fragment arrives alone.
        assert!(s.insert_fragment(sa, ra, 1, 1, false, b"tail", 1, &mut st).is_none());
        assert_eq!(s.len(), 1);

        // Fragment 0 arrives later -- completes the MSDU.
        let full = s.insert_fragment(sa, ra, 1, 0, true, b"head", 2, &mut st).unwrap();
        assert_eq!(full, b"headtail");
        assert!(s.is_empty());
        assert_eq!(st.fragments_reassembled, 1);
    }

    #[test]
    fn gap_in_fragments_stays_incomplete() {
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();
        let sa = mac(0x11);
        let ra = mac(0x22);

        s.insert_fragment(sa, ra, 1, 0, true, b"A", 1, &mut st);
        // Final claims FragNum=3 but we only have 0 and 3 -- gap at 1, 2.
        let result = s.insert_fragment(sa, ra, 1, 3, false, b"D", 2, &mut st);
        assert!(result.is_none());
        assert_eq!(s.len(), 1, "entry stays buffered awaiting frags 1 and 2");
        assert_eq!(st.fragments_reassembled, 0);
    }

    #[test]
    fn safety_cap_evicts_oldest() {
        const TEST_CAP: usize = 16;
        let mut s = FragmentStore::with_max_entries(TEST_CAP);
        let mut st = FragmentStats::default();
        let ra = mac(0xFF);

        for i in 0..TEST_CAP {
            let sa_byte = u8::try_from(i).unwrap();
            let seq = u16::try_from(i).unwrap();
            let ts = u64::try_from(i).unwrap();
            s.insert_fragment(mac(sa_byte), ra, seq, 0, true, b"X", ts, &mut st);
        }
        assert_eq!(s.len(), TEST_CAP);

        // One more entry: oldest must be evicted, len stays at the cap.
        s.insert_fragment(mac(0x77), ra, 9999, 0, true, b"X", u64::MAX, &mut st);
        assert_eq!(s.len(), TEST_CAP);
        assert_eq!(st.fragments_dropped_safety_cap, 1);
    }

    #[test]
    fn different_seq_numbers_are_independent() {
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();
        let sa = mac(0x11);
        let ra = mac(0x22);

        s.insert_fragment(sa, ra, 1, 0, true, b"alpha", 1, &mut st);
        s.insert_fragment(sa, ra, 2, 0, true, b"beta", 1, &mut st);

        let f1 = s.insert_fragment(sa, ra, 1, 1, false, b"-end", 2, &mut st).unwrap();
        let f2 = s.insert_fragment(sa, ra, 2, 1, false, b"-tail", 2, &mut st).unwrap();

        assert_eq!(f1, b"alpha-end");
        assert_eq!(f2, b"beta-tail");
    }

    #[test]
    fn different_sa_ra_are_independent() {
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();

        s.insert_fragment(mac(0x11), mac(0xAA), 1, 0, true, b"x", 1, &mut st);
        s.insert_fragment(mac(0x22), mac(0xBB), 1, 0, true, b"y", 1, &mut st);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn existing_key_does_not_trigger_eviction() {
        const TEST_CAP: usize = 2;
        let mut s = FragmentStore::with_max_entries(TEST_CAP);
        let mut st = FragmentStats::default();

        s.insert_fragment(mac(0x11), mac(0xAA), 1, 0, true, b"a", 1, &mut st);
        s.insert_fragment(mac(0x22), mac(0xBB), 2, 0, true, b"b", 2, &mut st);
        assert_eq!(s.len(), 2);

        // Another fragment for an existing key should NOT evict.
        s.insert_fragment(mac(0x11), mac(0xAA), 1, 1, true, b"c", 3, &mut st);
        assert_eq!(s.len(), 2);
        assert_eq!(st.fragments_dropped_safety_cap, 0);
    }
}
