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
    /// FT fields, present only for FT-PSK PMKIDs. Boxed because >99.9% of entries
    /// are non-FT.
    pub ft: Option<Box<FtFields>>,
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

    /// Inserts a `PmkidEntry` if it passes the garbage-pattern check and is not
    /// already present for this pair. Returns `true` if the entry was stored.
    ///
    /// Rejects every garbage pattern detected by `garbage_pattern_kind`: `null`
    /// (all-`0x00`), `ff` (all-`0xFF`), `repeat_1`, `repeat_2`, `repeat_4`. No healthy
    /// HMAC-SHA1-128 output matches any of these patterns; they are firmware
    /// stubs with zero cracking value. The caller uses the return value to
    /// decide whether to increment `pmkids_found` and per-source counters.
    ///
    /// Deduplication is by the 16-byte PMKID value within the (AP, STA) pair.
    /// Different PMKID values for the same pair are all retained.
    pub fn add(&mut self, entry: PmkidEntry) -> bool {
        if crate::types::garbage_pattern_kind(&entry.pmkid).is_some() {
            return false;
        }
        let pair = MacPair::new(entry.ap, entry.sta);
        let entries = self.groups.entry(pair).or_default();
        if entries.iter().any(|e| e.pmkid == entry.pmkid) {
            return false;
        }
        entries.push(entry);
        true
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

    /// Non-repeating 16-byte PMKID seeded from a single byte. Avoids
    /// garbage-pattern rejection by XOR-ing the seed with a position offset.
    const fn realistic_pmkid(seed: u8) -> [u8; 16] {
        let mut p = [0u8; 16];
        let mut i: u8 = 0;
        while i < 16 {
            p[i as usize] = seed ^ i.wrapping_mul(17);
            i += 1;
        }
        p
    }

    #[test]
    fn add_single_pmkid() {
        let mut store = PmkidStore::new();
        store.add(make_entry(0x11, 0x22, realistic_pmkid(0xAA)));
        assert_eq!(store.total_count(), 1);
    }

    #[test]
    fn add_duplicate_pmkid_same_pair() {
        let mut store = PmkidStore::new();
        store.add(make_entry(0x11, 0x22, realistic_pmkid(0xAA)));
        let mut dup = make_entry(0x11, 0x22, realistic_pmkid(0xAA));
        dup.source = PmkidSource::M2RsnIe;
        store.add(dup);
        assert_eq!(store.total_count(), 1);
    }

    #[test]
    fn add_different_pmkid_same_pair() {
        let mut store = PmkidStore::new();
        store.add(make_entry(0x11, 0x22, realistic_pmkid(0xAA)));
        store.add(make_entry(0x11, 0x22, realistic_pmkid(0xBB)));
        assert_eq!(store.total_count(), 2);
    }

    #[test]
    fn add_same_pmkid_different_pairs() {
        let mut store = PmkidStore::new();
        store.add(make_entry(0x11, 0x22, realistic_pmkid(0xAA)));
        store.add(make_entry(0x33, 0x44, realistic_pmkid(0xAA)));
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
        let mut store = PmkidStore::new();
        let pmkid = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        assert!(store.add(make_entry(0x11, 0x22, pmkid)));
        assert_eq!(store.total_count(), 1);
    }

    #[test]
    fn add_repeat1_pmkid_rejected() {
        let mut store = PmkidStore::new();
        assert!(!store.add(make_entry(0x11, 0x22, [0x55; 16])));
        assert_eq!(store.total_count(), 0);
    }

    #[test]
    fn add_repeat2_pmkid_rejected() {
        let mut store = PmkidStore::new();
        let pmkid = [0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34];
        assert!(!store.add(make_entry(0x11, 0x22, pmkid)));
        assert_eq!(store.total_count(), 0);
    }

    #[test]
    fn add_repeat4_pmkid_rejected() {
        let mut store = PmkidStore::new();
        let pmkid = [0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD];
        assert!(!store.add(make_entry(0x11, 0x22, pmkid)));
        assert_eq!(store.total_count(), 0);
    }

    #[test]
    fn iter_yields_all() {
        let mut store = PmkidStore::new();
        store.add(make_entry(0x11, 0x22, realistic_pmkid(0x01)));
        store.add(make_entry(0x11, 0x22, realistic_pmkid(0x02)));
        store.add(make_entry(0x33, 0x44, realistic_pmkid(0x03)));
        assert_eq!(store.iter().count(), 3);
    }

    #[test]
    fn canonicalize_pairs_merges_duplicate_pmkid() {
        let mut store = PmkidStore::new();
        store.add(make_entry(0xAA, 0x11, realistic_pmkid(0x99)));
        store.add(make_entry(0xAA, 0x22, realistic_pmkid(0x99)));
        assert_eq!(store.total_count(), 2, "before canonicalization: distinct pairs");
        store.canonicalize_pairs(|m| {
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
        let mut store = PmkidStore::new();
        store.add(make_entry(0x11, 0x22, realistic_pmkid(0x01)));
        store.add(make_entry(0x33, 0x44, realistic_pmkid(0x02)));
        store.canonicalize_pairs(|m| m);
        assert_eq!(store.total_count(), 2);
    }

    #[test]
    fn total_count_correct() {
        let mut store = PmkidStore::new();
        store.add(make_entry(0x11, 0x22, realistic_pmkid(0x01)));
        store.add(make_entry(0x11, 0x22, realistic_pmkid(0x02)));
        store.add(make_entry(0x33, 0x44, realistic_pmkid(0x03)));
        store.add(make_entry(0x11, 0x22, realistic_pmkid(0x01))); // dup
        store.add(make_entry(0x33, 0x44, realistic_pmkid(0x03))); // dup
        assert_eq!(store.total_count(), 3);
    }
}
