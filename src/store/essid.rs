//! Phase 3 -- Extract: ESSID-by-AP map (resolves ESSID for hash-line salt). See ARCHITECTURE.md §3.3.
//!
//! Maps AP MAC addresses to their SSID history. An AP may change its SSID during a long
//! capture, so the map stores all observed (ESSID bytes, first-seen timestamp) pairs.
//! The `resolve` method returns the ESSID whose timestamp is closest to a given packet
//! timestamp, giving the best contextual SSID for hash line output. SSIDs are stored as
//! raw `Vec<u8>` because 802.11 SSIDs are arbitrary byte strings and are not required to
//! be valid UTF-8. See `ARCHITECTURE.md §3.3`.

use std::collections::HashMap;

use crate::types::MacAddr;

/// A single ESSID observation with its first-seen timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EssidEntry {
    /// Raw SSID bytes (0-32 bytes). Not required to be valid UTF-8.
    ///
    /// Per IEEE 802.11-2024 §9.4.2.3, the SSID element body is an arbitrary octet string
    /// of 0-32 bytes. The zero-length form is used by APs broadcasting a "hidden" network.
    pub essid: Vec<u8>,
    /// Capture timestamp (microseconds) when this SSID was first observed for this AP.
    pub timestamp: u64,
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
    /// Empty SSIDs (hidden-network broadcasts per IEEE 802.11-2024 §9.4.2.3) are ignored.
    pub fn insert(&mut self, ap: MacAddr, essid: Vec<u8>, timestamp: u64) {
        if essid.is_empty() {
            // hidden-network broadcast -- no useful SSID information, skip
            return;
        }
        // Skip all-null SSIDs (hidden AP using zero-filled SSID element).
        // Some APs broadcast `\x00...` instead of a zero-length SSID element to hide the
        // network; others use it in probe responses before revealing the real SSID.
        // Accepting all-null SSIDs causes timestamp-based resolution to pick the wrong SSID
        // when the null appears earlier in the capture than the real SSID.
        // [IEEE 802.11-2024] §9.4.2.3 -- SSID element; hidden networks may use length=0
        if essid.iter().all(|&b| b == 0) {
            return;
        }
        let entries = self.map.entry(ap).or_default();
        if let Some(existing) = entries.iter_mut().find(|e| e.essid == essid) {
            // Preserve the earliest observation for this SSID.
            if timestamp < existing.timestamp {
                existing.timestamp = timestamp;
            }
        } else {
            entries.push(EssidEntry { essid, timestamp });
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
    #[must_use]
    pub fn all_for_ap(&self, ap: &MacAddr) -> &[EssidEntry] {
        self.map.get(ap).map(Vec::as_slice).unwrap_or_default()
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
    /// returns nothing and the hash is emitted with a `[essid_not_found]` log.
    /// Folding link-MAC SSIDs into the canonical MLD MAC closes that gap.
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
                // `insert`. The all-zero / empty filters were already applied at
                // original insert time, so we can call insert directly.
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
