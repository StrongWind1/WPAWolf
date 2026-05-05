//! Phase 3 -- Extract: PMKID-by-(AP,STA) store, deduped at insert. See ARCHITECTURE.md §3.3 + §6.
//!
//! `PmkidEntry` records a single extracted PMKID with its source location, the AP and STA
//! MAC addresses, AKM type, and optional FT fields. PMKIDs flow in from all 20 spec-defined
//! locations covered by 19 `PmkidSource` variants (`types.rs`): S14 directed and S15
//! broadcast Probe Requests share one `ProbeRequest` variant by design (the directed-vs-
//! broadcast distinction is stats-only). The 19 variants are: the four canonical EAPOL/
//! Assoc paths (M1 Key Data KDE, M2 RSN IE, Association Request RSN IE, Reassociation
//! Request RSN IE), six FT/FILS/PASN Authentication frame paths (S5-S10), three FT
//! Action frame paths (S11-S13), Probe Request RSN IE (S14+S15), Beacon and Probe
//! Response RSN IEs (S16/S17, vendor firmware deviations), Mesh Peering Open and Confirm
//! AMPE chosen-PMK fields (S18/S19), and OSEN IE in Association Request (S20).
//! `PmkidStore` deduplicates by PMKID value within each (AP, STA) pair -- the same PMKID
//! observed in M1 and M2 is stored only once. See `ARCHITECTURE.md §6` for the 20-location
//! catalogue.

use std::collections::HashMap;

use crate::types::{AkmType, FtFields, MacAddr, MacPair, PmkidSource};

// --- PmkidEntry ---

/// A single extracted PMKID with its capture context.
///
/// PMKIDs can come from multiple frame types; `source` records the extraction origin
/// for statistics. The same 16-byte PMKID value for the same (AP, STA) pair is
/// deduplicated by `PmkidStore`. See `ARCHITECTURE.md §6`.
#[derive(Debug, Clone)]
pub struct PmkidEntry {
    /// Packet capture timestamp in microseconds since epoch.
    pub timestamp: u64,
    /// Access point MAC address.
    pub ap: MacAddr,
    /// Station MAC address.
    pub sta: MacAddr,
    /// The 16-byte PMKID value.
    pub pmkid: [u8; 16],
    /// Where this PMKID was extracted from.
    pub source: PmkidSource,
    /// AKM type for correct hash-line routing (22000 vs 37100).
    pub akm: AkmType,
    /// FT fields, present only for FT-PSK PMKIDs.
    pub ft: Option<FtFields>,
}

// --- PmkidStore ---

/// Storage for PMKIDs, grouped by (AP, STA) pair with per-pair deduplication.
///
/// When the same 16-byte PMKID value is seen multiple times for the same pair
/// (e.g., in both M1 Key Data and M2 RSN IE), only the first occurrence is kept.
/// Different PMKID values for the same pair are all stored. See `ARCHITECTURE.md §6`.
#[derive(Debug, Default)]
pub struct PmkidStore {
    groups: HashMap<MacPair, Vec<PmkidEntry>>,
}

impl PmkidStore {
    /// Creates an empty `PmkidStore`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a `PmkidEntry` if its PMKID value is not already present for this pair.
    ///
    /// Rejects all-zero PMKIDs (`[0u8; 16]`) -- these are firmware or stack artifacts
    /// with no cracking value. Matches hcxpcapngtool line 4012 zero-check before `addpmkid()`.
    ///
    /// Deduplication is by the 16-byte PMKID value within the (AP, STA) pair.
    /// Different PMKID values for the same pair are all retained.
    pub fn add(&mut self, entry: PmkidEntry) {
        // Reject all-zero and all-0xFF PMKIDs -- firmware/stack artifacts with no cracking value.
        // All-zero: hcxpcapngtool zeroed32 check [hcxpcapngtool:4012].
        // All-0xFF: firmware sentinel value (same class of artifact).
        if entry.pmkid == [0u8; 16] || entry.pmkid == [0xFFu8; 16] {
            return;
        }
        let pair = MacPair::new(entry.ap, entry.sta);
        let entries = self.groups.entry(pair).or_default();
        // Dedup: skip if this PMKID value is already stored for this pair.
        if entries.iter().any(|e| e.pmkid == entry.pmkid) {
            return;
        }
        entries.push(entry);
    }

    /// Iterates over all stored PMKID entries across all (AP, STA) pairs.
    pub fn iter(&self) -> impl Iterator<Item = &PmkidEntry> {
        self.groups.values().flatten()
    }

    /// Rewrites every group key and embedded AP/STA addresses using `canonicalize`.
    ///
    /// Groups that collide under the canonical key are merged; per-pair dedup is re-applied
    /// so that an identical PMKID value observed under two link addresses is stored once.
    /// Callers typically pass an `MldStore::canonicalize` closure. Bit-identical behavior
    /// for non-11be captures: when no mapping changes any address, the store is unchanged.
    pub fn canonicalize_pairs<F>(&mut self, mut canonicalize: F)
    where
        F: FnMut(MacAddr) -> MacAddr,
    {
        let old = std::mem::take(&mut self.groups);
        for (_pair, entries) in old {
            for mut entry in entries {
                entry.ap = canonicalize(entry.ap);
                entry.sta = canonicalize(entry.sta);
                // Re-use add() so dedup-by-PMKID runs on the merged group.
                self.add(entry);
            }
        }
    }

    /// Returns the total number of unique PMKIDs stored.
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.groups.values().map(Vec::len).sum()
    }

    /// Drops every PMKID entry. Used by `--per-file` mode after the per-file
    /// emit. The map's capacity is preserved across files so the next file
    /// reuses the existing buckets.
    pub fn clear(&mut self) {
        self.groups.clear();
    }

    /// Coarse heap + struct-bytes estimate for `--mem-stats` reporting.
    ///
    /// Counts the `HashMap` bucket overhead, every `Vec<PmkidEntry>` allocation,
    /// and every `PmkidEntry` struct. Does not count `FtFields` heap, which is
    /// rare (only FT-PSK PMKIDs).
    #[must_use]
    pub fn approx_bytes(&self) -> usize {
        let groups_cap_bytes = self.groups.capacity() * (size_of::<MacPair>() + size_of::<Vec<PmkidEntry>>() + 8);
        let mut entries_bytes = 0usize;
        for v in self.groups.values() {
            entries_bytes += v.capacity() * size_of::<PmkidEntry>();
        }
        size_of::<Self>() + groups_cap_bytes + entries_bytes
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

    /// Builds a `PmkidEntry` with `ap` and `sta` derived from single byte values,
    /// and the provided `pmkid`. All other fields are set to sensible defaults.
    fn make_entry(ap: u8, sta: u8, pmkid: [u8; 16]) -> PmkidEntry {
        PmkidEntry {
            timestamp: 1_000,
            ap: MacAddr::from_bytes([ap; 6]),
            sta: MacAddr::from_bytes([sta; 6]),
            pmkid,
            source: PmkidSource::M1KeyData,
            akm: AkmType::Wpa2Psk,
            ft: None,
        }
    }

    #[test]
    fn add_single_pmkid() {
        let mut store = PmkidStore::new();
        store.add(make_entry(0x11, 0x22, [0xAA; 16]));
        assert_eq!(store.total_count(), 1);
    }

    #[test]
    fn add_duplicate_pmkid_same_pair() {
        let mut store = PmkidStore::new();
        store.add(make_entry(0x11, 0x22, [0xAA; 16]));
        // Same PMKID bytes, same pair -- must be deduplicated.
        let mut dup = make_entry(0x11, 0x22, [0xAA; 16]);
        dup.source = PmkidSource::M2RsnIe; // different source, same value
        store.add(dup);
        assert_eq!(store.total_count(), 1);
    }

    #[test]
    fn add_different_pmkid_same_pair() {
        let mut store = PmkidStore::new();
        store.add(make_entry(0x11, 0x22, [0xAA; 16]));
        store.add(make_entry(0x11, 0x22, [0xBB; 16]));
        assert_eq!(store.total_count(), 2);
    }

    #[test]
    fn add_same_pmkid_different_pairs() {
        let mut store = PmkidStore::new();
        // Same PMKID bytes but different (ap, sta) pairs -> both are distinct entries.
        store.add(make_entry(0x11, 0x22, [0xAA; 16]));
        store.add(make_entry(0x33, 0x44, [0xAA; 16]));
        assert_eq!(store.total_count(), 2);
    }

    #[test]
    fn add_zero_pmkid_rejected() {
        // All-zero PMKID is a firmware artifact and must be rejected without incrementing count.
        let mut store = PmkidStore::new();
        store.add(make_entry(0x11, 0x22, [0u8; 16]));
        assert_eq!(store.total_count(), 0, "zero PMKID must be rejected");
    }

    #[test]
    fn add_ff_pmkid_rejected() {
        // A PMKID of all-0xFF is also a firmware artifact and must be rejected.
        let mut store = PmkidStore::new();
        store.add(make_entry(0x11, 0x22, [0xFF; 16]));
        assert_eq!(store.total_count(), 0, "all-0xFF PMKID must be rejected");
    }

    #[test]
    fn add_nonzero_nonff_pmkid_accepted() {
        // A mixed-byte PMKID must be accepted.
        let mut store = PmkidStore::new();
        store.add(make_entry(0x11, 0x22, [0xAB; 16]));
        assert_eq!(store.total_count(), 1);
    }

    #[test]
    fn iter_yields_all() {
        let mut store = PmkidStore::new();
        // Pair 1: two distinct PMKIDs.
        store.add(make_entry(0x11, 0x22, [0x01; 16]));
        store.add(make_entry(0x11, 0x22, [0x02; 16]));
        // Pair 2: one PMKID.
        store.add(make_entry(0x33, 0x44, [0x03; 16]));

        let count = store.iter().count();
        assert_eq!(count, 3);
    }

    #[test]
    fn canonicalize_pairs_merges_duplicate_pmkid() {
        // Same PMKID bytes observed under two link MACs that both map to one MLD ->
        // after canonicalization the PMKID is stored once for the merged pair.
        let mut store = PmkidStore::new();
        store.add(make_entry(0xAA, 0x11, [0x99; 16]));
        store.add(make_entry(0xAA, 0x22, [0x99; 16]));
        assert_eq!(store.total_count(), 2, "before canonicalization: distinct pairs");
        store.canonicalize_pairs(|m| {
            // Link STAs 0x11 and 0x22 both canonicalize to 0x55.
            if m == MacAddr::from_bytes([0x11; 6]) || m == MacAddr::from_bytes([0x22; 6]) {
                MacAddr::from_bytes([0x55; 6])
            } else {
                m
            }
        });
        assert_eq!(store.total_count(), 1, "merged pair must dedupe on PMKID value");
    }

    #[test]
    fn canonicalize_pairs_noop_identity() {
        // Identity canonicalization preserves every entry exactly.
        let mut store = PmkidStore::new();
        store.add(make_entry(0x11, 0x22, [0x01; 16]));
        store.add(make_entry(0x33, 0x44, [0x02; 16]));
        store.canonicalize_pairs(|m| m);
        assert_eq!(store.total_count(), 2);
    }

    #[test]
    fn total_count_correct() {
        let mut store = PmkidStore::new();
        // 3 unique adds + 2 duplicates -> count stays at 3.
        store.add(make_entry(0x11, 0x22, [0x01; 16]));
        store.add(make_entry(0x11, 0x22, [0x02; 16]));
        store.add(make_entry(0x33, 0x44, [0x03; 16]));
        store.add(make_entry(0x11, 0x22, [0x01; 16])); // dup
        store.add(make_entry(0x33, 0x44, [0x03; 16])); // dup
        assert_eq!(store.total_count(), 3);
    }
}
