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
//! * On a non-final fragment (`MoreFrag=1`): the body bytes are appended to the
//!   per-(`SA`, `RA`, `SeqNum`) buffer.
//! * On the final fragment (`MoreFrag=0`, `FragNum>0`): all stored bytes plus
//!   this fragment's body are concatenated and returned to the caller as a
//!   single reassembled MSDU.
//! * On a non-fragmented frame (`MoreFrag=0`, `FragNum=0`): no buffer is
//!   touched; the caller processes the body directly.
//!
//! # Memory bounds
//!
//! A capture full of fragmented frames whose final piece never arrives could
//! pin arbitrary memory. `MAX_ENTRIES` caps the in-flight buffer count: when
//! the entry count would exceed this, the oldest entry by first-fragment
//! timestamp is dropped (counter: `dropped_overflow`). Time-based expiry is
//! intentionally not implemented -- EAPOL fragmentation is rare enough that
//! 1024 partial-MSDU slots is generous for any real capture, and the
//! oldest-first eviction reclaims any genuine orphan as new fragments arrive.
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
/// the oldest entry. Set high enough that legitimate concurrent reassemblies on
/// a busy AP do not collide; low enough that a malicious capture cannot pin
/// gigabytes of RAM. EAPOL fragmentation is rare, so 1024 is generous.
const MAX_ENTRIES: usize = 1024;

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
    /// Concatenated body bytes from all fragments received so far.
    body: Vec<u8>,
    /// Highest Fragment Number seen so far. Used to detect out-of-order or
    /// duplicate fragments (we accept them only in strict ascending order).
    last_frag: u8,
    /// Timestamp of the FIRST fragment, used as the entry's age for expiry.
    /// Per spec all fragments of one MSDU are transmitted within a single
    /// transmission opportunity, so the first-fragment timestamp dominates.
    first_seen_us: u64,
}

/// Bounded reassembly buffer for fragmented 802.11 MSDUs.
///
/// `push_fragment` adds a non-final fragment; `take_completed` consumes the
/// final fragment and returns the concatenated MSDU body. Memory is bounded
/// by `MAX_ENTRIES`: when full, the oldest entry by first-fragment timestamp
/// is evicted to make room for the new one.
#[derive(Debug, Default)]
pub struct FragmentStore {
    entries: HashMap<FragKey, FragEntry>,
}

/// Counters returned alongside reassembly events so the caller can update its
/// own `Stats` struct without reaching into private fields.
#[derive(Debug, Default, Clone, Copy)]
pub struct FragmentStats {
    /// Bumped each time `push_fragment` accepts a fragment-0 of a new MSDU or
    /// appends a subsequent in-order fragment. A fragment-0 that overwrites an
    /// existing entry for the same `(SA, RA, SeqNum)` (a retransmitted first
    /// fragment) increments this counter again -- it is "fragments observed",
    /// not "distinct MSDUs started".
    pub fragments_seen: u64,
    /// MSDUs successfully reassembled and returned by `take_completed`.
    pub fragments_reassembled: u64,
    /// Out-of-order, duplicate, or otherwise unusable fragments rejected.
    pub fragments_dropped_disorder: u64,
    /// Entries evicted because `MAX_ENTRIES` was reached.
    pub fragments_dropped_overflow: u64,
}

impl FragmentStore {
    /// Creates an empty fragment store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores a non-final fragment (`MoreFrag=1`). For Fragment Number 0 a new
    /// entry is created; for Fragment Number N>0 the body is appended to the
    /// existing entry. Returns `true` on success, `false` if the fragment was
    /// rejected (duplicate, out-of-order, or evicted to make room).
    pub fn push_fragment(
        &mut self,
        sa: MacAddr,
        ra: MacAddr,
        seq_num: u16,
        frag_num: u8,
        body: &[u8],
        timestamp_us: u64,
        stats: &mut FragmentStats,
    ) -> bool {
        let key = FragKey { sa, ra, seq_num };
        if frag_num == 0 {
            // First fragment of a new MSDU. Evict oldest entry if at capacity.
            if self.entries.len() >= MAX_ENTRIES {
                if let Some(victim_key) = self.oldest_key() {
                    self.entries.remove(&victim_key);
                    stats.fragments_dropped_overflow += 1;
                }
            }
            self.entries.insert(key, FragEntry { body: body.to_vec(), last_frag: 0, first_seen_us: timestamp_us });
            stats.fragments_seen += 1;
            return true;
        }
        // Fragment N > 0: must follow N-1.
        let Some(entry) = self.entries.get_mut(&key) else {
            stats.fragments_dropped_disorder += 1;
            return false;
        };
        if frag_num != entry.last_frag.saturating_add(1) {
            stats.fragments_dropped_disorder += 1;
            return false;
        }
        entry.body.extend_from_slice(body);
        entry.last_frag = frag_num;
        stats.fragments_seen += 1;
        true
    }

    /// Consumes the final fragment (`MoreFrag=0`, `FragNum>0`) and returns the
    /// fully reassembled MSDU body. Returns `None` if no in-flight entry
    /// matches (the final fragment arrived without preceding fragments) or if
    /// the fragment ordering was broken; in either case the disorder counter
    /// is incremented so the operator sees the loss.
    pub fn take_completed(
        &mut self,
        sa: MacAddr,
        ra: MacAddr,
        seq_num: u16,
        frag_num: u8,
        body: &[u8],
        stats: &mut FragmentStats,
    ) -> Option<Vec<u8>> {
        debug_assert!(frag_num > 0, "take_completed called for unfragmented frame");
        let key = FragKey { sa, ra, seq_num };
        let Some(entry) = self.entries.remove(&key) else {
            // Final fragment with no preceding state: peer's first N fragments
            // were lost or never captured. Count and drop.
            stats.fragments_dropped_disorder += 1;
            return None;
        };
        if frag_num != entry.last_frag.saturating_add(1) {
            stats.fragments_dropped_disorder += 1;
            return None;
        }
        let mut full = entry.body;
        full.extend_from_slice(body);
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
        let table_bytes = self.entries.capacity() * (size_of::<FragKey>() + size_of::<FragEntry>() + 8);
        let body_bytes: usize = self.entries.values().map(|e| e.body.capacity()).sum();
        size_of::<Self>() + table_bytes + body_bytes
    }

    /// True iff the store holds no in-flight fragments.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Helper: find the key with the oldest `first_seen_us`, used for
    /// `MAX_ENTRIES` eviction.
    fn oldest_key(&self) -> Option<FragKey> {
        self.entries.iter().min_by_key(|(_, e)| e.first_seen_us).map(|(k, _)| *k)
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

    fn mac(b: u8) -> MacAddr {
        MacAddr::from_bytes([b; 6])
    }

    #[test]
    fn unfragmented_frame_does_not_touch_store() {
        // Caller is expected NOT to call push_fragment for unfragmented frames;
        // the store is only consulted for MoreFrag=1 or FragNum>0 cases. This
        // test documents the empty-store invariant for the trivial path.
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

        let part0 = b"AAAAAAAAAA";
        let part1 = b"BBBBBBBBBB";

        // First fragment, MoreFrag=1, FragNum=0.
        assert!(s.push_fragment(sa, ra, seq, 0, part0, 1_000_000, &mut st));
        assert_eq!(s.len(), 1);

        // Final fragment, MoreFrag=0, FragNum=1.
        let full = s.take_completed(sa, ra, seq, 1, part1, &mut st).expect("must reassemble");
        assert_eq!(full, b"AAAAAAAAAABBBBBBBBBB");
        assert!(s.is_empty(), "completed entry must be removed");
        assert_eq!(st.fragments_reassembled, 1);
        assert_eq!(st.fragments_seen, 1);
    }

    #[test]
    fn three_fragment_msdu_reassembles_in_order() {
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();
        let sa = mac(0x11);
        let ra = mac(0x22);
        let seq = 7;

        assert!(s.push_fragment(sa, ra, seq, 0, b"X", 1, &mut st));
        assert!(s.push_fragment(sa, ra, seq, 1, b"Y", 2, &mut st));
        let full = s.take_completed(sa, ra, seq, 2, b"Z", &mut st).unwrap();
        assert_eq!(full, b"XYZ");
        assert_eq!(st.fragments_seen, 2);
        assert_eq!(st.fragments_reassembled, 1);
    }

    #[test]
    fn out_of_order_fragment_rejected() {
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();
        let sa = mac(0x11);
        let ra = mac(0x22);

        s.push_fragment(sa, ra, 1, 0, b"A", 1, &mut st);
        // Try to push fragment 2 before fragment 1 -- must reject.
        let accepted = s.push_fragment(sa, ra, 1, 2, b"C", 3, &mut st);
        assert!(!accepted);
        assert_eq!(st.fragments_dropped_disorder, 1);
    }

    #[test]
    fn duplicate_first_fragment_overwrites() {
        // Edge case: a duplicate frag-0 (e.g. retransmit) replaces the in-flight
        // entry. Spec-allowed because retransmissions are common; we accept the
        // newer body and reset state.
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();
        let sa = mac(0x11);
        let ra = mac(0x22);

        s.push_fragment(sa, ra, 1, 0, b"old", 1, &mut st);
        s.push_fragment(sa, ra, 1, 0, b"new", 2, &mut st);
        let full = s.take_completed(sa, ra, 1, 1, b"+rest", &mut st).unwrap();
        assert_eq!(full, b"new+rest");
    }

    #[test]
    fn final_fragment_without_predecessor_returns_none() {
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();
        let result = s.take_completed(mac(0x11), mac(0x22), 1, 1, b"orphan", &mut st);
        assert!(result.is_none());
        assert_eq!(st.fragments_reassembled, 0);
    }

    #[test]
    fn final_fragment_out_of_order_returns_none() {
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();
        let sa = mac(0x11);
        let ra = mac(0x22);

        s.push_fragment(sa, ra, 1, 0, b"A", 1, &mut st);
        // Final claims FragNum=3 but we only saw FragNum=0; gap -> reject.
        let result = s.take_completed(sa, ra, 1, 3, b"C", &mut st);
        assert!(result.is_none());
        assert_eq!(st.fragments_dropped_disorder, 1);
    }

    #[test]
    fn overflow_evicts_oldest() {
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();
        let ra = mac(0xFF);

        // Fill to MAX_ENTRIES. The store is keyed by (SA, RA, SeqNum); we
        // vary SA byte and SeqNum together so each entry is distinct without
        // the casts triggering pedantic truncation lints.
        for i in 0..MAX_ENTRIES {
            let sa_byte = u8::try_from(i & 0xFF).unwrap();
            let seq = u16::try_from(i & 0xFFFF).unwrap();
            let ts = u64::try_from(i).unwrap();
            s.push_fragment(mac(sa_byte), ra, seq, 0, b"X", ts, &mut st);
        }
        assert_eq!(s.len(), MAX_ENTRIES);

        // One more entry: oldest must be evicted, len stays at MAX_ENTRIES.
        s.push_fragment(mac(0x77), ra, 9999, 0, b"X", u64::MAX, &mut st);
        assert_eq!(s.len(), MAX_ENTRIES);
        assert_eq!(st.fragments_dropped_overflow, 1);
    }

    #[test]
    fn different_seq_numbers_are_independent() {
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();
        let sa = mac(0x11);
        let ra = mac(0x22);

        s.push_fragment(sa, ra, 1, 0, b"alpha", 1, &mut st);
        s.push_fragment(sa, ra, 2, 0, b"beta", 1, &mut st);

        let f1 = s.take_completed(sa, ra, 1, 1, b"-end", &mut st).unwrap();
        let f2 = s.take_completed(sa, ra, 2, 1, b"-tail", &mut st).unwrap();

        assert_eq!(f1, b"alpha-end");
        assert_eq!(f2, b"beta-tail");
    }

    #[test]
    fn different_sa_ra_are_independent() {
        // Same Sequence Number reused by two different senders -- per spec the
        // (SA, RA, SeqNum) tuple uniquely identifies an MSDU.
        let mut s = FragmentStore::new();
        let mut st = FragmentStats::default();

        s.push_fragment(mac(0x11), mac(0xAA), 1, 0, b"x", 1, &mut st);
        s.push_fragment(mac(0x22), mac(0xBB), 1, 0, b"y", 1, &mut st);
        assert_eq!(s.len(), 2);
    }
}
