//! Phase 3 -- Extract: ESSID-by-AP map (resolves ESSID for hash-line salt). See ARCHITECTURE.md §3.3.
//!
//! Maps AP MAC addresses to their SSID history. An AP may change its SSID during a long
//! capture, so the map stores all observed (ESSID bytes, first-seen timestamp) pairs.
//! The `resolve` method returns the ESSID whose timestamp is closest to a given packet
//! timestamp, giving the best contextual SSID for hash line output. SSIDs are stored as
//! raw `Vec<u8>` because 802.11 SSIDs are arbitrary byte strings and are not required to
//! be valid UTF-8. See `ARCHITECTURE.md §3.3`.

use std::collections::HashMap;

use crate::store::auxiliary::passes_hcx_essid_filter;
use crate::types::MacAddr;

/// A single ESSID observation with its first-seen timestamp and observation count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EssidEntry {
    /// Raw SSID bytes (0-32 bytes). Not required to be valid UTF-8.
    ///
    /// Per IEEE 802.11-2024 §9.4.2.3, the SSID element body is an arbitrary octet string
    /// of 0-32 bytes. The zero-length form is used by APs broadcasting a "hidden" network.
    pub essid: Vec<u8>,
    /// Capture timestamp (microseconds) when this SSID was first observed for this AP.
    pub timestamp: u64,
    /// Number of frames in which this (AP, SSID) pair was observed.
    ///
    /// Real broadcasts accumulate hundreds-to-thousands of observations across Beacon
    /// and Probe-Response frames; bit-flipped variants typically appear once or twice.
    /// The frequency gap is the discriminator used by the multi-ESSID inflation filter
    /// in `EssidMap::ssids_for_emit`.
    pub count: u64,
}

/// Maps AP MAC addresses to their SSID history with timestamp-nearest resolution.
///
/// Most APs have exactly one SSID over a capture lifetime; `Vec<EssidEntry>` handles
/// the rare SSID-change case without allocating per-entry. See `ARCHITECTURE.md §3.3`.
#[derive(Debug, Default)]
pub struct EssidMap {
    map: HashMap<MacAddr, Vec<EssidEntry>>,
}

impl EssidMap {
    /// Creates an empty `EssidMap`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an SSID observation for `ap` at `timestamp`.
    ///
    /// If the same SSID bytes are already recorded for this AP, updates the stored
    /// timestamp if the new observation is earlier (preserves the earliest-seen time).
    /// If the SSID bytes differ from all recorded SSIDs, appends a new `EssidEntry`.
    ///
    /// Admission is gated by `passes_hcx_essid_filter`: length 1-32 octets and
    /// first byte non-zero. This rejects three classes of input that would otherwise
    /// produce hashcat-invalid hash lines once `EssidMap::all_for_ap` feeds the
    /// output pipeline (`src/output/mod.rs`):
    ///
    /// - **Length 0**: the spec-defined wildcard SSID per [IEEE 802.11-2024]
    ///   §9.4.2.2 paragraph 3; carries no salt material.
    /// - **Length > 32**: malformed -- the SSID element's Length field is defined
    ///   as 0-32 octets per §9.4.2.2 (Figure 9-209), so any longer body comes
    ///   from a bit-flipped IE Length byte that caused the parser to slurp the
    ///   following IE's body. hcxtools mirrors this rule (`fileops.c:76`).
    /// - **First byte 0x00**: hidden-network convention. Some APs (and corrupt
    ///   frames) pad the SSID element with leading NUL bytes; the resulting
    ///   salt cannot derive a PMK that matches any real network, so the hash
    ///   is uncrackable. Mirrors hcxtools `fileops.c:79`.
    ///
    /// The same gate is applied to `EssidSet` (`-E`) and `ProbeEssidSet` (`-R`)
    /// in `src/store/auxiliary.rs`, so admission is uniform across every store
    /// that participates in hash emission. `WordlistStore` (`-W`) keeps a broader
    /// rule (control-byte splitting, sub-`min_len` runs) because its purpose is
    /// leaked-text salvage, not hash-salt material.
    pub fn insert(&mut self, ap: MacAddr, essid: Vec<u8>, timestamp: u64) {
        if !passes_hcx_essid_filter(&essid) {
            return;
        }
        let entries = self.map.entry(ap).or_default();
        if let Some(existing) = entries.iter_mut().find(|e| e.essid == essid) {
            // Preserve the earliest observation for this SSID; bump the count
            // so frequency-weighted filters in `ssids_for_emit` can distinguish
            // bit-flip noise (count == 1) from genuine broadcasts (count >> 1).
            if timestamp < existing.timestamp {
                existing.timestamp = timestamp;
            }
            existing.count = existing.count.saturating_add(1);
        } else {
            entries.push(EssidEntry { essid, timestamp, count: 1 });
        }
    }

    /// Returns the SSID for `ap` whose timestamp is closest to `target_timestamp`.
    ///
    /// With multiple SSIDs (rare SSID-change case), picks the one temporally closest to
    /// the packet being processed. Returns `None` if no SSID has been recorded for `ap`.
    ///
    /// Uses `u64::abs_diff` (stable since Rust 1.60) to avoid overflow when either
    /// operand is larger.
    #[must_use]
    pub fn resolve(&self, ap: &MacAddr, target_timestamp: u64) -> Option<&[u8]> {
        let entries = self.map.get(ap)?;
        entries.iter().min_by_key(|e| e.timestamp.abs_diff(target_timestamp)).map(|e| e.essid.as_slice())
    }

    /// Returns all ESSID entries recorded for `ap`, or an empty slice if none.
    ///
    /// Used by the output pipeline to emit one hash line per observed SSID when an AP
    /// has been seen advertising multiple SSIDs over the capture lifetime. Most APs
    /// return a single-element slice; the multi-SSID case is handled uniformly.
    ///
    /// Callers that route the result into hash emission should prefer
    /// [`EssidMap::ssids_for_emit`], which applies the frequency-weighted multi-ESSID
    /// inflation filter; this raw accessor is kept for diagnostic / tooling use.
    #[must_use]
    pub fn all_for_ap(&self, ap: &MacAddr) -> &[EssidEntry] {
        self.map.get(ap).map(Vec::as_slice).unwrap_or_default()
    }

    /// Returns the SSID byte strings to emit for `ap`, with the multi-ESSID
    /// inflation filter applied.
    ///
    /// The filter targets RF-corrupted captures where one physical AP appears in the
    /// store with many bit-flipped SSID variants of one real broadcast (e.g. an AP
    /// observed 44,865 times as `iPhone` plus 108 single-byte-flip variants observed
    /// 1-6 times each). Without the filter, every variant produces an independent
    /// hashcat line during emit, blowing up output by 100x or more for affected APs.
    ///
    /// Algorithm (matching the pseudocode reviewed against `/root/ALL_CAPS`):
    ///
    /// ```text
    /// if num_ssids <= fanout_threshold:
    ///     keep all SSIDs                           # singletons + small captures
    /// elif dominance_ratio < 2:
    ///     keep all SSIDs                           # filter disabled
    /// elif primary.count >= dominance_ratio * second.count:
    ///     keep only primary                        # RF-rot collapse
    /// else:
    ///     keep all SSIDs                           # legit multi-network AP
    /// ```
    ///
    /// `fanout_threshold` (default 3) is the gate -- APs with `<=` that many SSIDs are
    /// untouched. This preserves singleton-SSID APs (small captures with 1 beacon
    /// plus a handshake) and the long tail of legit dual-band / 3-SSID setups.
    ///
    /// `dominance_ratio` (default 10) is the trigger -- the primary SSID's observation
    /// count must be at least `N x` the second-most-frequent's count. Empirical
    /// finding from the reference corpus: real RF-rot APs show ratios of 10^2 to 10^4,
    /// while legit multi-network APs (e.g. a CTF AP advertising 11 distinct SSIDs)
    /// show ratios within an order of magnitude of 1. A ratio `< 2` disables the
    /// filter -- a useful escape hatch for operators who want every recorded SSID
    /// to enter hash output regardless of frequency.
    ///
    /// Returns an empty `Vec` when no SSIDs are recorded for `ap`. The caller is
    /// expected to drop the would-be hash line (no ESSID = uncrackable) and
    /// account for it via the per-AP `[essid_not_found_summary]` log line.
    #[must_use]
    pub fn ssids_for_emit(&self, ap: &MacAddr, fanout_threshold: usize, dominance_ratio: u64) -> Vec<&[u8]> {
        let Some(entries) = self.map.get(ap) else { return Vec::new() };
        if entries.len() <= fanout_threshold || dominance_ratio < 2 {
            return entries.iter().map(|e| e.essid.as_slice()).collect();
        }
        let mut sorted: Vec<&EssidEntry> = entries.iter().collect();
        sorted.sort_by_key(|e| std::cmp::Reverse(e.count));
        // entries.len() > fanout_threshold guarantees fanout >= 2 for any
        // non-zero threshold; the bounds-checked accessors below also cover
        // the threshold == 0 case where fanout could be 1 (still safe -- a
        // 1-entry vec returns at the .get(1) None branch and falls through
        // to "keep all").
        let (Some(primary), Some(second)) = (sorted.first().copied(), sorted.get(1).copied()) else {
            return sorted.iter().map(|e| e.essid.as_slice()).collect();
        };
        if primary.count >= dominance_ratio.saturating_mul(second.count) {
            vec![primary.essid.as_slice()]
        } else {
            sorted.iter().map(|e| e.essid.as_slice()).collect()
        }
    }

    /// Returns `true` if at least one ESSID has been recorded for `ap`.
    #[must_use]
    pub fn contains_ap(&self, ap: &MacAddr) -> bool {
        self.map.contains_key(ap)
    }

    /// Returns the number of APs with at least one recorded ESSID.
    #[must_use]
    pub fn ap_count(&self) -> usize {
        self.map.len()
    }

    /// Coarse heap + struct-bytes estimate for `--mem-stats` reporting.
    ///
    /// Sums `HashMap` bucket overhead, every `Vec<EssidEntry>` allocation,
    /// every `EssidEntry` struct, and the heap bytes of every SSID `Vec<u8>`.
    #[must_use]
    pub fn approx_bytes(&self) -> usize {
        let map_cap_bytes = self.map.capacity() * (size_of::<MacAddr>() + size_of::<Vec<EssidEntry>>() + 8);
        let mut entries_bytes = 0usize;
        for v in self.map.values() {
            entries_bytes += v.capacity() * size_of::<EssidEntry>();
            for e in v {
                entries_bytes = entries_bytes.saturating_add(e.essid.capacity());
            }
        }
        size_of::<Self>() + map_cap_bytes + entries_bytes
    }

    /// Returns all unique ESSID byte strings seen across all APs.
    ///
    /// Deduplicates by value -- the same ESSID broadcast by multiple APs appears once.
    /// Ordering of the returned slice is unspecified; callers that need deterministic
    /// output must sort the result.
    #[must_use]
    pub fn unique_essids(&self) -> Vec<&[u8]> {
        use std::collections::HashSet;
        let mut seen: HashSet<&[u8]> = HashSet::new();
        let mut result = Vec::new();
        for entries in self.map.values() {
            for entry in entries {
                if seen.insert(entry.essid.as_slice()) {
                    result.push(entry.essid.as_slice());
                }
            }
        }
        result
    }

    /// Rewrites every AP key using `canonicalize`, merging entries that map to the
    /// same canonical MAC. Returns the number of pre-merge link MACs that were
    /// folded into a different MLD MAC (so callers can surface a stat).
    ///
    /// Called once after Phase 1 ingest, when the `MldStore` is fully populated.
    /// Without this, an AP advertising itself under multiple link MACs (one per
    /// 2.4 / 5 / 6 GHz band) shows the SSID under each link MAC, but the EAPOL
    /// pair was already canonicalized to the MLD MAC -- so `all_for_ap(MLD)`
    /// returns nothing and the hash is dropped as uncrackable (and logged via
    /// `[essid_not_found_summary]`). Folding link-MAC SSIDs into the canonical
    /// MLD MAC closes that gap.
    pub fn canonicalize_pairs<F>(&mut self, mut canonicalize: F) -> u64
    where
        F: FnMut(MacAddr) -> MacAddr,
    {
        let old_map = std::mem::take(&mut self.map);
        let mut merged_link_macs: u64 = 0;
        for (ap, entries) in old_map {
            let canon = canonicalize(ap);
            if canon != ap {
                merged_link_macs += 1;
            }
            for entry in entries {
                // Reuse the same dedup-by-bytes / earliest-timestamp semantics as
                // `insert`. The hcx-essid filter was already applied at original
                // insert time, so re-checking here is a no-op for accepted entries.
                self.insert(canon, entry.essid, entry.timestamp);
            }
        }
        merged_link_macs
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
    fn insert_and_resolve_single() {
        let mut m = EssidMap::new();
        let ap = mac(0x11);
        m.insert(ap, b"HomeNet".to_vec(), 1000);
        assert_eq!(m.resolve(&ap, 1000), Some(b"HomeNet".as_slice()));
    }

    #[test]
    fn insert_empty_essid_ignored() {
        let mut m = EssidMap::new();
        let ap = mac(0x22);
        m.insert(ap, vec![], 500);
        assert_eq!(m.resolve(&ap, 500), None);
    }

    #[test]
    fn insert_oversized_essid_rejected() {
        // Spec [IEEE 802.11-2024] §9.4.2.2: SSID Length field is 0-32 octets.
        // 33 bytes is the canonical bit-flipped-IE-Length parse error and
        // produces hashcat-invalid hash lines (hcxtools rejects via
        // `ESSID_LEN_MAX = 32` at `fileops.c:76`).
        let mut m = EssidMap::new();
        let ap = mac(0x77);
        m.insert(ap, vec![b'A'; 33], 100);
        assert_eq!(m.resolve(&ap, 100), None, "33-byte SSID must be rejected");
        // Boundary: exactly 32 bytes is spec-valid and must be accepted.
        m.insert(ap, vec![b'A'; 32], 200);
        assert!(m.resolve(&ap, 200).is_some(), "32-byte SSID is at the spec limit");
    }

    #[test]
    fn insert_leading_nul_essid_rejected() {
        // Hidden-network convention: a single leading NUL with non-zero tail
        // bytes still has no usable salt material (hcxtools `fileops.c:79`).
        // Mirrors the gate already applied to `EssidSet` / `ProbeEssidSet`.
        let mut m = EssidMap::new();
        let ap = mac(0x88);
        m.insert(ap, vec![0x00, b'a', b'b', b'c'], 100);
        assert_eq!(m.resolve(&ap, 100), None, "leading-NUL SSID must be rejected");
    }

    #[test]
    fn insert_all_nul_essid_rejected() {
        // All-zero SSID was the previous filter's only rejection; still must
        // hit the leading-NUL branch under the broader filter.
        let mut m = EssidMap::new();
        let ap = mac(0x99);
        m.insert(ap, vec![0u8; 8], 100);
        assert_eq!(m.resolve(&ap, 100), None);
    }

    #[test]
    fn insert_single_byte_non_nul_accepted() {
        // 1-byte SSIDs are spec-valid and occasionally seen on guest networks.
        let mut m = EssidMap::new();
        let ap = mac(0xAB);
        m.insert(ap, vec![b'X'], 100);
        assert_eq!(m.resolve(&ap, 100), Some(b"X".as_slice()));
    }

    #[test]
    fn insert_increments_count_on_duplicate() {
        // Repeated insert of the same (AP, SSID) bumps the observation count;
        // count is the discriminator the multi-ESSID inflation filter relies on.
        let mut m = EssidMap::new();
        let ap = mac(0x12);
        m.insert(ap, b"Home".to_vec(), 1000);
        m.insert(ap, b"Home".to_vec(), 1100);
        m.insert(ap, b"Home".to_vec(), 1200);
        let entries = m.all_for_ap(&ap);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].count, 3);
    }

    #[test]
    fn ssids_for_emit_empty_when_unknown_ap() {
        let m = EssidMap::new();
        assert!(m.ssids_for_emit(&mac(0xCC), 3, 10).is_empty());
    }

    #[test]
    fn ssids_for_emit_passthrough_at_or_below_fanout_threshold() {
        // 3 SSIDs is the default threshold; even with extreme dominance the
        // filter must not collapse this AP (it's the legit-multi-network case).
        let mut m = EssidMap::new();
        let ap = mac(0x21);
        // primary 1000-fold dominance over secondary, which would collapse if
        // the fanout gate were not active.
        m.insert(ap, b"primary".to_vec(), 1);
        for _ in 0..1000 {
            m.insert(ap, b"primary".to_vec(), 1);
        }
        m.insert(ap, b"second".to_vec(), 1);
        m.insert(ap, b"third".to_vec(), 1);
        let kept = m.ssids_for_emit(&ap, 3, 10);
        assert_eq!(kept.len(), 3, "fanout 3 == threshold 3, must pass through");
    }

    #[test]
    fn ssids_for_emit_collapses_under_dominance() {
        // 4 SSIDs: primary count 100 + 3 secondaries count 1. Dominance ratio
        // 100/1 = 100x >= 10x, so collapse to primary-only.
        let mut m = EssidMap::new();
        let ap = mac(0x22);
        for _ in 0..100 {
            m.insert(ap, b"real".to_vec(), 1);
        }
        m.insert(ap, b"rot1".to_vec(), 1);
        m.insert(ap, b"rot2".to_vec(), 1);
        m.insert(ap, b"rot3".to_vec(), 1);
        let kept = m.ssids_for_emit(&ap, 3, 10);
        assert_eq!(kept, vec![b"real".as_slice()], "primary alone must survive");
    }

    #[test]
    fn ssids_for_emit_keeps_all_when_no_dominance() {
        // 4 SSIDs with comparable counts (worst dominance 5/4 = 1.25x, well below
        // the 10x trigger). All four must survive -- this is the legit
        // multi-network AP shape (CTF AP / school multi-SSID router).
        let mut m = EssidMap::new();
        let ap = mac(0x23);
        for _ in 0..5 {
            m.insert(ap, b"a".to_vec(), 1);
        }
        for _ in 0..5 {
            m.insert(ap, b"b".to_vec(), 1);
        }
        for _ in 0..4 {
            m.insert(ap, b"c".to_vec(), 1);
        }
        for _ in 0..4 {
            m.insert(ap, b"d".to_vec(), 1);
        }
        let kept = m.ssids_for_emit(&ap, 3, 10);
        assert_eq!(kept.len(), 4);
    }

    #[test]
    fn ssids_for_emit_disabled_when_ratio_below_two() {
        // Operator escape hatch: ratio = 0 disables the filter, every SSID is
        // emitted regardless of dominance (matches pre-filter behaviour).
        let mut m = EssidMap::new();
        let ap = mac(0x24);
        for _ in 0..100 {
            m.insert(ap, b"primary".to_vec(), 1);
        }
        m.insert(ap, b"a".to_vec(), 1);
        m.insert(ap, b"b".to_vec(), 1);
        m.insert(ap, b"c".to_vec(), 1);
        let kept = m.ssids_for_emit(&ap, 3, 0);
        assert_eq!(kept.len(), 4, "ratio < 2 disables the collapse");
        let kept = m.ssids_for_emit(&ap, 3, 1);
        assert_eq!(kept.len(), 4, "ratio = 1 is degenerate, also disables");
    }

    #[test]
    fn ssids_for_emit_singleton_passthrough() {
        // 1 SSID -> always kept; no fanout, nothing to filter. This is the
        // small-capture safety case (1 beacon + handshake).
        let mut m = EssidMap::new();
        let ap = mac(0x25);
        m.insert(ap, b"only".to_vec(), 1);
        assert_eq!(m.ssids_for_emit(&ap, 3, 10), vec![b"only".as_slice()]);
    }

    #[test]
    fn ssids_for_emit_dominance_check_at_boundary() {
        // 4 SSIDs: primary count 10, second count 1. Ratio = 10x exactly,
        // which the >= test triggers. Collapse expected.
        let mut m = EssidMap::new();
        let ap = mac(0x26);
        for _ in 0..10 {
            m.insert(ap, b"p".to_vec(), 1);
        }
        m.insert(ap, b"s1".to_vec(), 1);
        m.insert(ap, b"s2".to_vec(), 1);
        m.insert(ap, b"s3".to_vec(), 1);
        let kept = m.ssids_for_emit(&ap, 3, 10);
        assert_eq!(kept, vec![b"p".as_slice()]);

        // Same shape, ratio 11x (just under): no collapse.
        let mut m2 = EssidMap::new();
        let ap = mac(0x27);
        for _ in 0..10 {
            m2.insert(ap, b"p".to_vec(), 1);
        }
        m2.insert(ap, b"s1".to_vec(), 1);
        m2.insert(ap, b"s2".to_vec(), 1);
        m2.insert(ap, b"s3".to_vec(), 1);
        let kept = m2.ssids_for_emit(&ap, 3, 11);
        assert_eq!(kept.len(), 4, "ratio 11x not met by 10x dominance");
    }

    #[test]
    fn insert_same_ssid_updates_timestamp() {
        let mut m = EssidMap::new();
        let ap = mac(0x33);
        m.insert(ap, b"ssid".to_vec(), 2000);
        // Earlier observation -- should update to 800.
        m.insert(ap, b"ssid".to_vec(), 800);
        // Later observation -- should NOT update (2000 already replaced by 800).
        m.insert(ap, b"ssid".to_vec(), 5000);
        let entries = &m.map[&ap];
        assert_eq!(entries.len(), 1, "same SSID must not create duplicate entries");
        assert_eq!(entries[0].timestamp, 800, "timestamp must be the earliest seen");
    }

    #[test]
    fn insert_different_ssid_appended() {
        let mut m = EssidMap::new();
        let ap = mac(0x44);
        m.insert(ap, b"first".to_vec(), 100);
        m.insert(ap, b"second".to_vec(), 200);
        assert_eq!(m.map[&ap].len(), 2);
    }

    #[test]
    fn resolve_picks_closest() {
        let mut m = EssidMap::new();
        let ap = mac(0x55);
        // timestamp=100 -> ssid_a; timestamp=900 -> ssid_b; target=800 -> ssid_b is closer
        m.insert(ap, b"ssid_a".to_vec(), 100);
        m.insert(ap, b"ssid_b".to_vec(), 900);
        assert_eq!(m.resolve(&ap, 800), Some(b"ssid_b".as_slice()));
    }

    #[test]
    fn resolve_unknown_ap_returns_none() {
        let m = EssidMap::new();
        assert_eq!(m.resolve(&mac(0xAA), 0), None);
    }

    #[test]
    fn resolve_exact_match() {
        let mut m = EssidMap::new();
        let ap = mac(0x66);
        m.insert(ap, b"exact".to_vec(), 42);
        assert_eq!(m.resolve(&ap, 42), Some(b"exact".as_slice()));
    }

    #[test]
    fn all_for_ap_empty_when_missing() {
        let m = EssidMap::new();
        assert!(m.all_for_ap(&mac(0xBB)).is_empty());
    }

    #[test]
    fn all_for_ap_returns_all_entries() {
        let mut m = EssidMap::new();
        let ap = mac(0x77);
        m.insert(ap, b"ssid1".to_vec(), 100);
        m.insert(ap, b"ssid2".to_vec(), 200);
        let entries = m.all_for_ap(&ap);
        assert_eq!(entries.len(), 2);
        let ssids: Vec<&[u8]> = entries.iter().map(|e| e.essid.as_slice()).collect();
        assert!(ssids.contains(&b"ssid1".as_slice()));
        assert!(ssids.contains(&b"ssid2".as_slice()));
    }

    #[test]
    fn ap_count_correct() {
        let mut m = EssidMap::new();
        let ap1 = mac(0x11);
        let ap2 = mac(0x22);
        m.insert(ap1, b"net1".to_vec(), 1);
        m.insert(ap1, b"net2".to_vec(), 2); // same AP, different SSID
        m.insert(ap2, b"net3".to_vec(), 3);
        assert_eq!(m.ap_count(), 2);
    }

    #[test]
    fn canonicalize_pairs_folds_link_macs_into_mld() {
        // Two link MACs (0x11, 0x22) advertising the same SSID under their own
        // raw addresses get folded into one MLD canonical key (0xAA). After
        // canonicalize_pairs, all_for_ap(MLD) returns the SSID; the link MAC
        // entries no longer exist.
        let mut m = EssidMap::new();
        let link_a = mac(0x11);
        let link_b = mac(0x22);
        let mld = mac(0xAA);
        m.insert(link_a, b"HomeNet".to_vec(), 100);
        m.insert(link_b, b"HomeNet".to_vec(), 200); // 6 GHz link MAC, same SSID
        assert_eq!(m.ap_count(), 2);

        let merged = m.canonicalize_pairs(|x| if x == link_a || x == link_b { mld } else { x });

        assert_eq!(merged, 2, "both link MACs should have been merged");
        assert_eq!(m.ap_count(), 1, "single MLD key remains");
        let entries = m.all_for_ap(&mld);
        assert_eq!(entries.len(), 1, "duplicate SSID merged into one entry");
        assert_eq!(entries[0].essid, b"HomeNet");
        assert_eq!(entries[0].timestamp, 100, "earliest timestamp preserved");
        assert!(m.all_for_ap(&link_a).is_empty(), "link MAC entry gone after fold");
        assert!(m.all_for_ap(&link_b).is_empty(), "link MAC entry gone after fold");
    }

    #[test]
    fn canonicalize_pairs_no_op_when_identity() {
        // No MLE seen -> identity canonicalize -> no merges, map unchanged.
        let mut m = EssidMap::new();
        m.insert(mac(0x11), b"a".to_vec(), 1);
        m.insert(mac(0x22), b"b".to_vec(), 2);
        let merged = m.canonicalize_pairs(|x| x);
        assert_eq!(merged, 0);
        assert_eq!(m.ap_count(), 2);
        assert_eq!(m.all_for_ap(&mac(0x11))[0].essid, b"a");
    }

    #[test]
    fn canonicalize_pairs_preserves_distinct_ssids() {
        // Same MLD, different SSIDs (e.g. 2.4 GHz "HomeNet" vs 6 GHz "HomeNet-6E"):
        // both must survive the merge as separate entries.
        let mut m = EssidMap::new();
        let link_a = mac(0x11);
        let link_b = mac(0x22);
        let mld = mac(0xAA);
        m.insert(link_a, b"HomeNet".to_vec(), 100);
        m.insert(link_b, b"HomeNet-6E".to_vec(), 200);

        m.canonicalize_pairs(|x| if x == link_a || x == link_b { mld } else { x });

        let entries = m.all_for_ap(&mld);
        assert_eq!(entries.len(), 2);
    }
}
