//! Phase 4 -- Emit: SipHash-1-3 fingerprint dedup gate (global, no look-back window). See ARCHITECTURE.md §4 + §7.
//!
//! Uses a `HashSet<u64>` of `SipHash` fingerprints to guarantee global uniqueness across
//! all emitted hash lines. Fingerprint inputs differ by hash-line type to prevent aliasing:
//! - PMKID lines: `kind_byte(01/03) || PMKID || MAC_AP || MAC_STA || ESSID`
//! - EAPOL lines: `kind_byte(02/04) || MIC || MAC_AP || MAC_STA || NONCE || EAPOL || ESSID`
//!
//! Replaces hcxpcapngtool's 20-entry look-back window with O(1) global lookup. At 1 M
//! unique hashes the set occupies approximately 56 MiB. See `ARCHITECTURE.md §4`.

use std::collections::HashSet;

use crate::pair::PairedHash;
use crate::store::pmkid::PmkidEntry;
use crate::types::{MacAddr, MsgType, hash_slices};

// --- CrossFileDedup ---

/// Cross-file EAPOL message dedup for `--per-file` mode.
///
/// In `--per-file` mode, `MessageStore` clears after each file. Without this filter,
/// the same EAPOL message appearing in multiple capture files gets re-stored,
/// re-paired (N#E# Cartesian explosion), and re-emitted -- with `PerSinkDedup`
/// catching duplicates at the output end. At wpa-sec scale (116M messages, 1.96B
/// hash lines) this causes `PerSinkDedup` to grow to ~36 GiB.
///
/// `CrossFileDedup` catches duplicates *before* pairing at the message level:
/// 116M entries (~1.1 GiB) instead of 1.96B entries (~36 GiB). Fingerprint is
/// ESSID-blind because ESSID resolves at emit time from `EssidMap`, not at ingest.
///
/// Gated behind `--per-file`: when the flag is off, `MessageStore` never clears
/// and `MessageStore::add()` already deduplicates naturally.
pub struct CrossFileDedup {
    seen: HashSet<u64>,
}

impl std::fmt::Debug for CrossFileDedup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrossFileDedup").field("len", &self.seen.len()).finish()
    }
}

impl Default for CrossFileDedup {
    fn default() -> Self {
        Self::new()
    }
}

impl CrossFileDedup {
    /// Creates an empty cross-file dedup filter.
    #[must_use]
    pub fn new() -> Self {
        Self { seen: HashSet::new() }
    }

    /// Returns `true` if this message is new (not a duplicate) and records it.
    ///
    /// Fingerprint: `kind(0x05) || AP(6) || STA(6) || msg_type(1) || akm(1) || eapol_frame(N)`.
    /// Kind byte `0x05` avoids collision with `PerSinkDedup`'s `0x01..0x04`.
    /// Includes AKM because `MessageStore::add()` deduplicates on
    /// `(msg_type, akm, eapol_frame)` -- the same frame bytes with a different
    /// AKM context (e.g. `Wpa2Psk` vs `PskSha256` from different beacon RSN IEs)
    /// are distinct messages that pair into different hash types.
    pub fn check_message(
        &mut self,
        ap: MacAddr,
        sta: MacAddr,
        msg_type: MsgType,
        akm: crate::types::AkmType,
        eapol_frame: &[u8],
    ) -> bool {
        let fp = hash_slices(0x05, &[&ap.0, &sta.0, &[msg_type as u8], &[akm as u8], eapol_frame]);
        self.seen.insert(fp)
    }

    /// Returns the number of unique messages recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Returns `true` if no messages have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Drops all recorded fingerprints, releasing memory.
    pub fn clear(&mut self) {
        self.seen = HashSet::new();
    }
}

// --- DedupSet ---

/// Global deduplication filter for hash lines.
///
/// Keeps a `HashSet<u64>` of fingerprints computed from the significant fields of each
/// hash line. `check_pmkid` / `check_eapol` return `true` (and insert the fingerprint)
/// only when the line is new. Duplicate lines return `false`.
///
/// A fixed-seed `RandomState` replacement is used so that fingerprints are stable within
/// a single run; cross-run stability is not required because the set is per-invocation.
/// See `ARCHITECTURE.md §4`.
pub struct DedupSet {
    seen: HashSet<u64>,
}

impl std::fmt::Debug for DedupSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DedupSet").field("len", &self.seen.len()).finish()
    }
}

impl DedupSet {
    /// Creates an empty `DedupSet`.
    #[must_use]
    pub fn new() -> Self {
        Self { seen: HashSet::new() }
    }

    /// Returns `true` if this PMKID entry is new (not a duplicate) and records it.
    ///
    /// Fingerprint covers: `kind_byte || PMKID || MAC_AP || MAC_STA || ESSID`.
    /// `kind_byte` is `0x01` for mode-22000 PMKIDs and `0x03` for FT-PSK PMKIDs,
    /// matching the WPA*01* / WPA*03* hash-line type prefixes.
    pub fn check_pmkid(&mut self, entry: &PmkidEntry, essid: &[u8]) -> bool {
        self.seen.insert(pmkid_fingerprint(entry, essid))
    }

    /// Returns `true` if this EAPOL pair is new (not a duplicate) and records it.
    ///
    /// Fingerprint covers: `kind_byte || MIC || MAC_AP || MAC_STA || NONCE || EAPOL || ESSID`.
    /// `kind_byte` is `0x02` for mode-22000 pairs and `0x04` for FT-PSK pairs.
    pub fn check_eapol(&mut self, pair: &PairedHash, essid: &[u8]) -> bool {
        self.seen.insert(eapol_fingerprint(pair, essid))
    }

    /// Inserts a raw fingerprint and returns `true` if it was not already present.
    ///
    /// Prefer `check_pmkid` / `check_eapol` for typed callers. This method is exposed
    /// for callers that have already computed the fingerprint via `pmkid_fingerprint` or
    /// `eapol_fingerprint` directly.
    pub fn insert(&mut self, fingerprint: u64) -> bool {
        self.seen.insert(fingerprint)
    }

    /// Returns the total number of unique fingerprints recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Returns `true` if no fingerprints have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl Default for DedupSet {
    fn default() -> Self {
        Self::new()
    }
}

// --- PerSinkDedup ---

/// Identifies which output sink a fingerprint belongs to.
///
/// Lets the per-sink dedup keep one `HashSet<u64>` per configured sink. The same
/// logical hash is written to multiple sinks (with different per-sink prefixes); each
/// sink dedups independently so an internal duplicate within a sink is suppressed but
/// the same hash still appears in every other sink it routes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkId {
    /// `--22000-out` (legacy hashcat mode 22000, WPA*01*/WPA*02* prefixes).
    Out22000,
    /// `--37100-out` (legacy hashcat mode 37100, WPA*03*/WPA*04* prefixes).
    Out37100,
    /// `-o`/`--out` (combined 11-type extended, every emitted hash).
    OutCombined,
    /// `--wpa1-out` (type 1).
    OutWpa1,
    /// `--wpa2-out` (types 2 + 3).
    OutWpa2,
    /// `--psk-sha256-out` (types 4 + 5).
    OutPskSha256,
    /// `--ft-out` (types 6 + 7).
    OutFt,
    /// `--psk-sha384-out` (types 8 + 9).
    OutPskSha384,
    /// `--ft-psk-sha384-out` (types 10 + 11).
    OutFtPskSha384,
}

impl SinkId {
    /// Total number of sink kinds. Kept in sync with the `SinkId` enum manually.
    pub const COUNT: usize = 9;

    /// Numeric index used to address the per-sink `HashSet` array in `PerSinkDedup`.
    #[must_use]
    pub const fn as_index(self) -> usize {
        self as usize
    }
}

/// Per-sink deduplication filter.
///
/// One `HashSet<u64>` per sink. The fingerprint scheme is identical to `DedupSet`'s
/// (`pmkid_fingerprint` / `eapol_fingerprint` -- the kind byte already distinguishes
/// PMKID from EAPOL and PSK from FT-PSK within a sink). Per-sink segregation lets
/// the same logical hash land in N sinks without any one sink suppressing another.
#[derive(Default)]
pub struct PerSinkDedup {
    sets: [HashSet<u64>; SinkId::COUNT],
}

impl std::fmt::Debug for PerSinkDedup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let lens: Vec<usize> = self.sets.iter().map(HashSet::len).collect();
        f.debug_struct("PerSinkDedup").field("lens", &lens).finish()
    }
}

impl PerSinkDedup {
    /// Creates an empty per-sink dedup with one `HashSet` per `SinkId`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-sizes every per-sink `HashSet` to hold at least `capacity` entries
    /// without reallocating. Eliminates the transient memory spike from
    /// hashbrown's power-of-2 resize doubling, where both old and new tables
    /// are alive simultaneously during the copy.
    pub fn reserve(&mut self, capacity: usize) {
        for set in &mut self.sets {
            set.reserve(capacity);
        }
    }

    /// Drops all recorded fingerprints, resetting every per-sink set to empty.
    /// Capacity is released so the allocator can reclaim the memory.
    ///
    /// Used by `--per-file` mode after each file's emit. Cross-file duplicate
    /// suppression is sacrificed (hashcat deduplicates at load time), but the
    /// dedup set no longer grows without bound across the corpus.
    pub fn clear(&mut self) {
        for set in &mut self.sets {
            *set = HashSet::new();
        }
    }

    /// Returns `true` if this PMKID entry is new for `sink` and records the fingerprint.
    pub fn check_pmkid(&mut self, sink: SinkId, entry: &PmkidEntry, essid: &[u8]) -> bool {
        let fp = pmkid_fingerprint(entry, essid);
        self.sets.get_mut(sink.as_index()).is_some_and(|set| set.insert(fp))
    }

    /// Returns `true` if this EAPOL pair is new for `sink` and records the fingerprint.
    pub fn check_eapol(&mut self, sink: SinkId, pair: &PairedHash, essid: &[u8]) -> bool {
        let fp = eapol_fingerprint(pair, essid);
        self.sets.get_mut(sink.as_index()).is_some_and(|set| set.insert(fp))
    }
}

// --- Fingerprint helpers ---
//
// `hash_slices` lives in `crate::types` so that both `pair` (per-group inline dedup)
// and `output::dedup` (cross-group final dedup) can share a single SipHash helper
// without a `pair -> output` back-edge in the module DAG. See `ARCHITECTURE.md §3`.

/// Computes the dedup fingerprint for a PMKID hash line (public, for direct callers).
///
/// Input layout: `kind(1) || pmkid(16) || mac_ap(6) || mac_sta(6) || essid(N)`
/// Kind byte: `0x01` for `WPA*01*` (PSK / PSK-SHA256 / Unknown), `0x03` for `WPA*03*` (FT-PSK).
#[must_use]
pub fn pmkid_fingerprint(entry: &PmkidEntry, essid: &[u8]) -> u64 {
    let kind: u8 = if entry.akm.is_ft() { 0x03 } else { 0x01 };
    hash_slices(kind, &[&entry.pmkid, &entry.ap.0, &entry.sta.0, essid])
}

/// Computes the dedup fingerprint for an EAPOL pair hash line (public, for direct callers).
///
/// Input layout: `kind(1) || mic(16) || mac_ap(6) || mac_sta(6) || nonce(32) || eapol(M) || essid(N) || message_pair(1)`
/// Kind byte: `0x02` for `WPA*02*` (PSK / PSK-SHA256 / Unknown), `0x04` for `WPA*04*` (FT-PSK).
/// Including the full EAPOL frame ensures that two pairs with the same MIC but different
/// frame bodies produce distinct fingerprints. Including `message_pair` ensures that N1E2
/// and N3E2 (or any two combos sharing identical frame/nonce bytes) produce distinct
/// fingerprints in `--all` mode and are both emitted.
#[must_use]
pub fn eapol_fingerprint(pair: &PairedHash, essid: &[u8]) -> u64 {
    let kind: u8 = if pair.akm.is_ft() { 0x04 } else { 0x02 };
    hash_slices(
        kind,
        &[pair.mic.as_slice(), &pair.ap.0, &pair.sta.0, &pair.nonce, &pair.eapol_frame, essid, &[pair.message_pair]],
    )
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

    use std::sync::Arc;

    use super::*;
    use crate::pair::{ComboType, PairedHash};
    use crate::store::pmkid::PmkidEntry;
    use crate::types::{AkmType, MacAddr, MicBytes, PmkidSource};

    // --- Test helpers ---

    fn make_pmkid_entry(pmkid: [u8; 16], akm: AkmType) -> PmkidEntry {
        PmkidEntry {
            timestamp: 0,
            ap: MacAddr::from_bytes([0x11; 6]),
            sta: MacAddr::from_bytes([0x22; 6]),
            pmkid,
            source: PmkidSource::M1KeyData,
            akm,
            ft: None,
        }
    }

    fn make_paired_hash(mic: [u8; 16], nonce: [u8; 32], eapol_frame: Vec<u8>, akm: AkmType) -> PairedHash {
        PairedHash {
            ap: MacAddr::from_bytes([0x33; 6]),
            sta: MacAddr::from_bytes([0x44; 6]),
            combo_type: ComboType::N1E2,
            nonce,
            eapol_frame: Arc::from(eapol_frame),
            mic: MicBytes::from_16(mic),
            message_pair: 0x00,
            akm,
            ft: None,
            rc_gap_magnitude: 0,
        }
    }

    // --- DedupSet::insert (raw fingerprint) ---

    #[test]
    fn new_fingerprint_accepted() {
        let mut d = DedupSet::new();
        assert!(d.insert(42), "first insert must return true");
    }

    #[test]
    fn duplicate_fingerprint_rejected() {
        let mut d = DedupSet::new();
        d.insert(99);
        assert!(!d.insert(99), "second insert of same fingerprint must return false");
    }

    #[test]
    fn different_fingerprints_both_accepted() {
        let mut d = DedupSet::new();
        assert!(d.insert(1));
        assert!(d.insert(2));
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn is_empty_and_len() {
        let mut d = DedupSet::new();
        assert!(d.is_empty());
        d.insert(0);
        assert!(!d.is_empty());
        assert_eq!(d.len(), 1);
    }

    // --- PMKID deduplication ---

    #[test]
    fn pmkid_dedup_same_entry() {
        let mut d = DedupSet::new();
        let entry = make_pmkid_entry([0xAA; 16], AkmType::Wpa2Psk);
        let essid = b"testnet";
        assert!(d.check_pmkid(&entry, essid), "first check must be accepted");
        assert!(!d.check_pmkid(&entry, essid), "second check must be rejected");
    }

    #[test]
    fn pmkid_dedup_different_essid() {
        // Same PMKID bytes but different ESSID -> different fingerprints -> both accepted.
        let mut d = DedupSet::new();
        let entry = make_pmkid_entry([0xBB; 16], AkmType::Wpa2Psk);
        assert!(d.check_pmkid(&entry, b"net1"));
        assert!(d.check_pmkid(&entry, b"net2"), "different essid must produce distinct fingerprint");
    }

    #[test]
    fn pmkid_dedup_different_pmkid() {
        let mut d = DedupSet::new();
        let e1 = make_pmkid_entry([0x01; 16], AkmType::Wpa2Psk);
        let e2 = make_pmkid_entry([0x02; 16], AkmType::Wpa2Psk);
        assert!(d.check_pmkid(&e1, b"ssid"));
        assert!(d.check_pmkid(&e2, b"ssid"), "different pmkid must be distinct");
    }

    // --- EAPOL deduplication ---

    #[test]
    fn eapol_dedup_same_pair() {
        let mut d = DedupSet::new();
        let pair = make_paired_hash([0x01; 16], [0x02; 32], vec![0xFFu8; 99], AkmType::Wpa2Psk);
        let essid = b"wlan";
        assert!(d.check_eapol(&pair, essid));
        assert!(!d.check_eapol(&pair, essid), "duplicate pair must be rejected");
    }

    #[test]
    fn eapol_dedup_different_mic() {
        let mut d = DedupSet::new();
        let p1 = make_paired_hash([0x01; 16], [0x00; 32], vec![0u8; 99], AkmType::Wpa2Psk);
        let p2 = make_paired_hash([0x02; 16], [0x00; 32], vec![0u8; 99], AkmType::Wpa2Psk);
        assert!(d.check_eapol(&p1, b"ssid"));
        assert!(d.check_eapol(&p2, b"ssid"), "different mic must be distinct");
    }

    // --- Kind-byte collision prevention ---

    #[test]
    fn kind_byte_prevents_collision() {
        // A PMKID entry and an EAPOL pair with maximally similar payloads must produce
        // different fingerprints solely because of the kind byte (0x01 vs 0x02).
        let pmkid_entry = make_pmkid_entry([0x55; 16], AkmType::Wpa2Psk);
        let fp_pmkid = pmkid_fingerprint(&pmkid_entry, &[]);

        let mut pair = make_paired_hash([0x55; 16], [0x00; 32], vec![], AkmType::Wpa2Psk);
        pair.ap = MacAddr::from_bytes([0x11; 6]);
        pair.sta = MacAddr::from_bytes([0x22; 6]);
        let fp_eapol = eapol_fingerprint(&pair, &[]);

        assert_ne!(fp_pmkid, fp_eapol, "kind byte must prevent cross-type fingerprint collision");
    }

    #[test]
    fn ft_psk_pmkid_uses_kind_03() {
        // FT-PSK PMKID fingerprint must differ from PSK fingerprint for the same entry bytes.
        let psk_entry = make_pmkid_entry([0xCC; 16], AkmType::Wpa2Psk);
        let ft_entry = make_pmkid_entry([0xCC; 16], AkmType::FtPsk);
        let fp_psk = pmkid_fingerprint(&psk_entry, b"net");
        let fp_ft = pmkid_fingerprint(&ft_entry, b"net");
        assert_ne!(fp_psk, fp_ft, "FT-PSK kind byte 0x03 must differ from PSK kind byte 0x01");
    }

    #[test]
    fn ft_psk_eapol_uses_kind_04() {
        // FT-PSK EAPOL fingerprint must differ from PSK fingerprint for the same pair bytes.
        let psk_pair = make_paired_hash([0xDD; 16], [0x00; 32], vec![0u8; 50], AkmType::Wpa2Psk);
        let ft_pair = make_paired_hash([0xDD; 16], [0x00; 32], vec![0u8; 50], AkmType::FtPsk);
        let fp_psk = eapol_fingerprint(&psk_pair, b"net");
        let fp_ft = eapol_fingerprint(&ft_pair, b"net");
        assert_ne!(fp_psk, fp_ft, "FT-PSK kind byte 0x04 must differ from PSK kind byte 0x02");
    }
}
