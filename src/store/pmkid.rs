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

use std::collections::{HashMap, HashSet};
use std::io::{BufReader, BufWriter, Seek, SeekFrom, Write as _};

use crate::store::disk_messages::{read_pmkid_entry, write_pmkid_entry};
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

/// Lightweight reference to a serialized PMKID entry on disk.
#[derive(Debug, Clone, Copy)]
struct PmkidRef {
    offset: u64,
}

/// Storage for PMKIDs, grouped by (AP, STA) pair with per-pair deduplication.
///
/// When the same 16-byte PMKID value is seen multiple times for the same pair
/// (e.g., in both M1 Key Data and M2 RSN IE), only the first occurrence is kept.
/// Different PMKID values for the same pair are all stored. See `ARCHITECTURE.md §6`.
#[derive(Default)]
pub struct PmkidStore {
    groups: HashMap<MacPair, Vec<PmkidEntry>>,
    disk_index: HashMap<MacPair, Vec<PmkidRef>>,
    /// Per-pair seen-PMKID set used for O(1) dedup in BOTH memory and disk mode.
    /// Kept in memory because the 16-byte PMKID values are small (~20 bytes per
    /// entry with `HashSet` overhead) and the total count is bounded by the number
    /// of unique PMKIDs in the capture (typically <100K). Replaces the former
    /// O(n)-per-insert linear scan of the per-pair `Vec` in the memory path.
    seen: HashMap<MacPair, HashSet<[u8; 16]>>,
    disk_writer: Option<BufWriter<std::fs::File>>,
    disk_path: Option<std::path::PathBuf>,
    disk_offset: u64,
    disk_mode: bool,
}

// Default is derived via #[derive(Default)] on the struct.

impl std::fmt::Debug for PmkidStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PmkidStore")
            .field("total_count", &self.total_count())
            .field("disk_mode", &self.disk_mode)
            .finish_non_exhaustive()
    }
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
        if self.disk_mode {
            return self.add_to_disk(&entry);
        }
        let pair = MacPair::new(entry.ap, entry.sta);
        // O(1) dedup via the per-pair seen-set (same accept/reject decision as the
        // former `entries.iter().any(..)` linear scan, but without the O(n^2) per-group
        // cost on captures that pack many distinct PMKIDs into one (AP, STA) pair).
        if !self.seen.entry(pair).or_default().insert(entry.pmkid) {
            return false;
        }
        self.groups.entry(pair).or_default().push(entry);
        true
    }

    fn add_to_disk(&mut self, entry: &PmkidEntry) -> bool {
        let pair = MacPair::new(entry.ap, entry.sta);
        if !self.seen.entry(pair).or_default().insert(entry.pmkid) {
            return false;
        }
        let Some(writer) = &mut self.disk_writer else {
            return false;
        };
        let Ok(written) = write_pmkid_entry(writer, entry) else {
            return false;
        };
        let refs = self.disk_index.entry(pair).or_default();
        refs.push(PmkidRef { offset: self.disk_offset });
        self.disk_offset += u64::from(written);
        true
    }

    /// Iterates over all stored PMKID entries across all (AP, STA) pairs.
    /// In disk mode, loads all entries from disk into a temporary Vec.
    #[must_use]
    #[expect(clippy::iter_without_into_iter, reason = "Box<dyn Iterator> return makes IntoIterator impractical")]
    pub fn iter(&self) -> Box<dyn Iterator<Item = PmkidEntry> + '_> {
        if self.disk_mode {
            let all: Vec<PmkidEntry> = self.load_all_entries();
            return Box::new(all.into_iter());
        }
        Box::new(self.groups.values().flatten().cloned())
    }

    /// Flushes the disk writer buffer. Must be called before `iter()` in disk
    /// mode to ensure all records written via `add_to_disk()` are readable.
    pub fn flush_disk_writer(&mut self) {
        if let Some(w) = &mut self.disk_writer {
            let _ = w.flush();
        }
    }

    fn load_all_entries(&self) -> Vec<PmkidEntry> {
        let Some(path) = &self.disk_path else {
            return Vec::new();
        };
        let Ok(file) = std::fs::File::open(path) else {
            return Vec::new();
        };
        let mut reader = BufReader::new(file);
        let mut entries = Vec::new();
        for refs in self.disk_index.values() {
            for pref in refs {
                if reader.seek(SeekFrom::Start(pref.offset)).is_ok()
                    && let Ok(entry) = read_pmkid_entry(&mut reader)
                {
                    entries.push(entry);
                }
            }
        }
        entries
    }

    /// Returns `true` if disk mode is active.
    #[must_use]
    pub const fn disk_mode(&self) -> bool {
        self.disk_mode
    }

    /// Flushes all in-memory PMKIDs to a temp file and switches to disk mode.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the temp file cannot be created or written.
    pub fn flush_to_disk(&mut self) -> crate::types::Result<()> {
        if self.disk_mode {
            return Ok(());
        }
        let dir = std::env::temp_dir();
        let path = dir.join(format!("wpawolf_pmkids_{}.bin", std::process::id()));
        let file = std::fs::File::create(&path)
            .map_err(|e| crate::types::Error::io(e, path.clone(), "create PMKID spill file"))?;
        let mut writer = BufWriter::new(file);
        let mut offset: u64 = 0;

        let old_groups = std::mem::take(&mut self.groups);
        for (pair, entries) in old_groups {
            let mut refs = Vec::with_capacity(entries.len());
            let seen = self.seen.entry(pair).or_default();
            for entry in &entries {
                seen.insert(entry.pmkid);
                let written = write_pmkid_entry(&mut writer, entry).map_err(crate::types::Error::Io)?;
                refs.push(PmkidRef { offset });
                offset += u64::from(written);
            }
            self.disk_index.insert(pair, refs);
        }
        writer.flush().map_err(crate::types::Error::Io)?;
        self.disk_writer = Some(writer);
        self.disk_path = Some(path);
        self.disk_offset = offset;
        self.disk_mode = true;
        Ok(())
    }

    /// Cleans up the temp file. Called on shutdown.
    pub fn cleanup_disk(&mut self) {
        if let Some(path) = self.disk_path.take() {
            let _ = std::fs::remove_file(path);
        }
        self.disk_writer = None;
    }

    /// Adds an MLD-keyed copy of every PMKID whose AP/STA canonicalizes to a
    /// different address, **keeping the original link-keyed entry**.
    ///
    /// Additive, not destructive, for the same reason as
    /// [`MessageStore::canonicalize_pairs`](crate::store::messages::MessageStore::canonicalize_pairs):
    /// a single-link PMKID is computed under the link MAC, a multi-link one under the
    /// MLD MAC, and only one is crackable -- so both are stored. Per-pair dedup is
    /// applied so an identical PMKID seen under two link addresses is not duplicated
    /// within a group. Bit-identical for non-11be captures (no address changes).
    /// Callers typically pass an `MldStore::canonicalize` closure.
    pub fn canonicalize_pairs<F>(&mut self, mut canonicalize: F)
    where
        F: FnMut(MacAddr) -> MacAddr,
    {
        if self.disk_mode {
            let mut additions: Vec<(MacPair, Vec<PmkidRef>)> = Vec::new();
            for (pair, refs) in &self.disk_index {
                let canon_pair = MacPair::new(canonicalize(pair.ap), canonicalize(pair.sta));
                if canon_pair != *pair {
                    additions.push((canon_pair, refs.clone()));
                }
            }
            for (canon_pair, refs) in additions {
                self.disk_index.entry(canon_pair).or_default().extend(refs);
            }
            return;
        }
        // Collect MLD-keyed copies, then re-insert them (dedup applies). The
        // originals stay in place.
        let mut additions: Vec<PmkidEntry> = Vec::new();
        for entries in self.groups.values() {
            for entry in entries {
                let canon_ap = canonicalize(entry.ap);
                let canon_sta = canonicalize(entry.sta);
                if canon_ap != entry.ap || canon_sta != entry.sta {
                    let mut copy = entry.clone();
                    copy.ap = canon_ap;
                    copy.sta = canon_sta;
                    additions.push(copy);
                }
            }
        }
        for entry in additions {
            self.add(entry);
        }
    }

    /// Returns the total number of unique PMKIDs stored.
    #[must_use]
    pub fn total_count(&self) -> usize {
        if self.disk_mode {
            return self.disk_index.values().map(Vec::len).sum();
        }
        self.groups.values().map(Vec::len).sum()
    }

    /// Drops every PMKID entry, reclaiming store memory for reuse. The map's
    /// capacity is preserved so a subsequent refill reuses the existing buckets.
    pub fn clear(&mut self) {
        self.groups.clear();
        self.disk_index.clear();
        self.seen.clear();
    }

    /// Coarse heap + struct-bytes estimate for `--mem-stats` reporting.
    #[must_use]
    pub fn approx_bytes(&self) -> usize {
        if self.disk_mode {
            let index_bytes = self.disk_index.capacity() * (size_of::<MacPair>() + size_of::<Vec<PmkidRef>>() + 8);
            let refs_bytes: usize = self.disk_index.values().map(|v| v.capacity() * size_of::<PmkidRef>()).sum();
            return size_of::<Self>() + index_bytes + refs_bytes;
        }
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
    fn canonicalize_pairs_adds_mld_copy_keeping_link_entries() {
        let mut store = PmkidStore::new();
        store.add(make_entry(0xAA, 0x11, realistic_pmkid(0x99)));
        store.add(make_entry(0xAA, 0x22, realistic_pmkid(0x99)));
        assert_eq!(store.total_count(), 2, "before canonicalization: distinct pairs");
        let mld = MacAddr::from_bytes([0x55; 6]);
        store.canonicalize_pairs(|m| {
            if m == MacAddr::from_bytes([0x11; 6]) || m == MacAddr::from_bytes([0x22; 6]) { mld } else { m }
        });
        // Additive: both link entries kept (single-link crackability) plus ONE
        // MLD-keyed copy (the two identical PMKIDs dedupe within the MLD group).
        assert_eq!(store.total_count(), 3, "two link entries kept + one deduped MLD copy");
        let mld_entries = store.iter().filter(|e| e.sta == mld).count();
        assert_eq!(mld_entries, 1, "MLD pair holds one deduped PMKID");
        let link_entries = store.iter().filter(|e| e.sta != mld).count();
        assert_eq!(link_entries, 2, "both original link-keyed PMKIDs survive");
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
