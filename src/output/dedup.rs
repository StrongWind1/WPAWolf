//! Phase 4 -- Emit: SipHash-1-3 fingerprint dedup gate (global, no look-back window). See ARCHITECTURE.md §4 + §7.
//!
//! Uses a `HashSet<u64>` of `SipHash` fingerprints to guarantee global uniqueness across
//! all emitted hash lines. Fingerprint inputs differ by hash-line type to prevent aliasing:
//! - PMKID lines: `kind_byte(01/03) || PMKID || MAC_AP || MAC_STA || ESSID`
//! - EAPOL lines: `kind_byte(02/04) || MIC || MAC_AP || MAC_STA || NONCE || EAPOL || ESSID [|| message_pair]` -- the trailing `message_pair` byte (hashcat metadata, not identity) is included by default and excluded under `--collapse-message-pair`, which then collapses content-identical combos.
//!
//! Replaces hcxpcapngtool's 20-entry look-back window with O(1) global lookup. At 1 M
//! unique hashes the set occupies approximately 56 MiB. See `ARCHITECTURE.md §4`.

use std::collections::HashSet;

use crate::pair::PairedHash;
use crate::store::pmkid::PmkidEntry;
use crate::types::hash_slices;

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
    /// `--collapse-message-pair`: when `true`, the `message_pair` byte is excluded from the
    /// EAPOL fingerprint so content-identical combos collapse. Default `false` (byte included).
    collapse_message_pair: bool,
}

impl std::fmt::Debug for DedupSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DedupSet")
            .field("len", &self.seen.len())
            .field("collapse_message_pair", &self.collapse_message_pair)
            .finish()
    }
}

impl DedupSet {
    /// Creates an empty `DedupSet`. `collapse_message_pair` mirrors the
    /// `--collapse-message-pair` flag (see [`eapol_fingerprint`]).
    #[must_use]
    pub fn new(collapse_message_pair: bool) -> Self {
        Self { seen: HashSet::new(), collapse_message_pair }
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
    /// Fingerprint covers: `kind_byte || MIC || MAC_AP || MAC_STA || NONCE || EAPOL || ESSID`,
    /// plus the trailing `message_pair` byte unless this set was built with
    /// `collapse_message_pair` (the `--collapse-message-pair` flag). See [`eapol_fingerprint`].
    /// `kind_byte` is `0x02` for mode-22000 pairs and `0x04` for FT-PSK pairs.
    pub fn check_eapol(&mut self, pair: &PairedHash, essid: &[u8]) -> bool {
        self.seen.insert(eapol_fingerprint(pair, essid, self.collapse_message_pair))
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
        Self::new(false)
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

    /// Converts a numeric index back to a `SinkId`, or `None` if out of range.
    #[must_use]
    pub const fn from_index(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(Self::Out22000),
            1 => Some(Self::Out37100),
            2 => Some(Self::OutCombined),
            3 => Some(Self::OutWpa1),
            4 => Some(Self::OutWpa2),
            5 => Some(Self::OutPskSha256),
            6 => Some(Self::OutFt),
            7 => Some(Self::OutPskSha384),
            8 => Some(Self::OutFtPskSha384),
            _ => None,
        }
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
    /// `--collapse-message-pair`: excludes the `message_pair` byte from the EAPOL
    /// fingerprint when `true` (see [`eapol_fingerprint`]). Default `false`.
    collapse_message_pair: bool,
}

impl std::fmt::Debug for PerSinkDedup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let lens: Vec<usize> = self.sets.iter().map(HashSet::len).collect();
        f.debug_struct("PerSinkDedup")
            .field("lens", &lens)
            .field("collapse_message_pair", &self.collapse_message_pair)
            .finish()
    }
}

impl PerSinkDedup {
    /// Creates an empty per-sink dedup with one `HashSet` per `SinkId`.
    /// `collapse_message_pair` mirrors the `--collapse-message-pair` flag.
    #[must_use]
    pub fn new(collapse_message_pair: bool) -> Self {
        Self { collapse_message_pair, ..Self::default() }
    }

    /// Returns whether `--collapse-message-pair` is active for this dedup, so direct
    /// `eapol_fingerprint` callers (e.g. the disk-dedup record path) stay consistent.
    #[must_use]
    pub const fn collapse_message_pair(&self) -> bool {
        self.collapse_message_pair
    }

    /// Pre-sizes per-sink `HashSet`s to hold at least `capacity` entries
    /// without reallocating. Only reserves for sinks whose index appears in
    /// `active_sinks`. Eliminates the transient memory spike from hashbrown's
    /// power-of-2 resize doubling, where both old and new tables are alive
    /// simultaneously during the copy.
    pub fn reserve(&mut self, capacity: usize, active_sinks: &[bool; SinkId::COUNT]) {
        for (idx, set) in self.sets.iter_mut().enumerate() {
            if active_sinks.get(idx).copied().unwrap_or(false) {
                set.reserve(capacity);
            }
        }
    }

    /// Flushes all in-memory fingerprints to a `DiskDedup`'s bucket files.
    ///
    /// Each fingerprint is recorded with `line_number = u64::MAX` (sentinel)
    /// so the cleaning pass knows these were already deduped in memory and
    /// don't correspond to output lines that need removal.
    ///
    /// # Errors
    ///
    /// Returns `Err` on I/O failure writing to bucket files.
    pub fn flush_to_buckets(&self, disk_dedup: &mut super::disk_dedup::DiskDedup) -> crate::types::Result<()> {
        for (idx, set) in self.sets.iter().enumerate() {
            if set.is_empty() {
                continue;
            }
            let Some(sink) = SinkId::from_index(idx) else { continue };
            disk_dedup.flush_hashset(sink, set)?;
        }
        Ok(())
    }

    /// Replaces all internal `HashSet`s with empty ones, freeing memory.
    /// Called after `flush_to_buckets` during mid-emission switchover.
    pub fn drain(&mut self) {
        self.sets = Default::default();
    }

    /// Returns the number of fingerprints recorded for `sink`. In memory mode a
    /// line is written iff its fingerprint was newly inserted, so this equals the
    /// number of lines already written to that sink's file -- the line base a
    /// mid-emission `DiskDedup` must start counting from.
    #[must_use]
    pub fn len_for_sink(&self, sink: SinkId) -> usize {
        self.sets.get(sink.as_index()).map_or(0, HashSet::len)
    }

    /// Returns `true` when no fingerprints have been recorded for any sink.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sets.iter().all(HashSet::is_empty)
    }

    /// Returns `true` if this PMKID entry is new for `sink` and records the fingerprint.
    pub fn check_pmkid(&mut self, sink: SinkId, entry: &PmkidEntry, essid: &[u8]) -> bool {
        let fp = pmkid_fingerprint(entry, essid);
        self.sets.get_mut(sink.as_index()).is_some_and(|set| set.insert(fp))
    }

    /// Returns `true` if this EAPOL pair is new for `sink` and records the fingerprint.
    pub fn check_eapol(&mut self, sink: SinkId, pair: &PairedHash, essid: &[u8]) -> bool {
        let fp = eapol_fingerprint(pair, essid, self.collapse_message_pair);
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
/// Input layout: `kind(1) || mic(16) || mac_ap(6) || mac_sta(6) || nonce(32) || eapol(M) || essid(N) [|| message_pair(1)]`
/// Kind byte: `0x02` for `WPA*02*` (PSK / PSK-SHA256 / Unknown), `0x04` for `WPA*04*` (FT-PSK).
/// Including the full EAPOL frame ensures that two pairs with the same MIC but different
/// frame bodies produce distinct fingerprints.
///
/// `collapse_message_pair` (the `--collapse-message-pair` flag) controls the trailing byte.
/// The `message_pair` byte is hashcat metadata (combo type in bits 0-2 plus the AP-less /
/// LE / BE / NC diagnostic flags), not crackable content. When `true`, it is **excluded**,
/// so two combos that share identical `mic || nonce || eapol || essid` bytes -- e.g. `N1E2`
/// and `N3E2` of a clean handshake where M1 and M3 carry the same `ANonce` -- collapse to one
/// line (the first-generated survivor `N1E2` already carries `FLAG_NC`, so it is the more
/// capable line). When `false` (the default), it is **included**, so every combo is emitted.
/// The kind byte separates PMKID/EAPOL and PSK/FT; for FT the MDID / R0KH-ID / R1KH-ID extras
/// live inside the EAPOL frame bytes, so they are covered transitively by `eapol`.
#[must_use]
pub fn eapol_fingerprint(pair: &PairedHash, essid: &[u8], collapse_message_pair: bool) -> u64 {
    let kind: u8 = if pair.akm.is_ft() { 0x04 } else { 0x02 };
    if collapse_message_pair {
        hash_slices(kind, &[pair.mic.as_slice(), &pair.ap.0, &pair.sta.0, &pair.nonce, &pair.eapol_frame, essid])
    } else {
        hash_slices(
            kind,
            &[
                pair.mic.as_slice(),
                &pair.ap.0,
                &pair.sta.0,
                &pair.nonce,
                &pair.eapol_frame,
                essid,
                &[pair.message_pair],
            ],
        )
    }
}

// --- Unit tests ---

#[cfg(test)]
mod tests {

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
        let mut d = DedupSet::new(false);
        assert!(d.insert(42), "first insert must return true");
    }

    #[test]
    fn duplicate_fingerprint_rejected() {
        let mut d = DedupSet::new(false);
        d.insert(99);
        assert!(!d.insert(99), "second insert of same fingerprint must return false");
    }

    #[test]
    fn different_fingerprints_both_accepted() {
        let mut d = DedupSet::new(false);
        assert!(d.insert(1));
        assert!(d.insert(2));
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn is_empty_and_len() {
        let mut d = DedupSet::new(false);
        assert!(d.is_empty());
        d.insert(0);
        assert!(!d.is_empty());
        assert_eq!(d.len(), 1);
    }

    // --- PMKID deduplication ---

    #[test]
    fn pmkid_dedup_same_entry() {
        let mut d = DedupSet::new(false);
        let entry = make_pmkid_entry([0xAA; 16], AkmType::Wpa2Psk);
        let essid = b"testnet";
        assert!(d.check_pmkid(&entry, essid), "first check must be accepted");
        assert!(!d.check_pmkid(&entry, essid), "second check must be rejected");
    }

    #[test]
    fn pmkid_dedup_different_essid() {
        // Same PMKID bytes but different ESSID -> different fingerprints -> both accepted.
        let mut d = DedupSet::new(false);
        let entry = make_pmkid_entry([0xBB; 16], AkmType::Wpa2Psk);
        assert!(d.check_pmkid(&entry, b"net1"));
        assert!(d.check_pmkid(&entry, b"net2"), "different essid must produce distinct fingerprint");
    }

    #[test]
    fn pmkid_dedup_different_pmkid() {
        let mut d = DedupSet::new(false);
        let e1 = make_pmkid_entry([0x01; 16], AkmType::Wpa2Psk);
        let e2 = make_pmkid_entry([0x02; 16], AkmType::Wpa2Psk);
        assert!(d.check_pmkid(&e1, b"ssid"));
        assert!(d.check_pmkid(&e2, b"ssid"), "different pmkid must be distinct");
    }

    // --- EAPOL deduplication ---

    #[test]
    fn eapol_dedup_same_pair() {
        let mut d = DedupSet::new(false);
        let pair = make_paired_hash([0x01; 16], [0x02; 32], vec![0xFFu8; 99], AkmType::Wpa2Psk);
        let essid = b"wlan";
        assert!(d.check_eapol(&pair, essid));
        assert!(!d.check_eapol(&pair, essid), "duplicate pair must be rejected");
    }

    #[test]
    fn eapol_dedup_different_mic() {
        let mut d = DedupSet::new(false);
        let p1 = make_paired_hash([0x01; 16], [0x00; 32], vec![0u8; 99], AkmType::Wpa2Psk);
        let p2 = make_paired_hash([0x02; 16], [0x00; 32], vec![0u8; 99], AkmType::Wpa2Psk);
        assert!(d.check_eapol(&p1, b"ssid"));
        assert!(d.check_eapol(&p2, b"ssid"), "different mic must be distinct");
    }

    #[test]
    fn eapol_collapse_message_pair_flag() {
        // Two pairs identical in all crackable content but differing only in the
        // message_pair metadata byte (e.g. N1E2 mp=0x00 vs the same content tagged
        // FLAG_NC=0x80). Default (collapse=false) keeps them distinct -> both emitted.
        // --collapse-message-pair (collapse=true) folds them to one fingerprint.
        let mut a = make_paired_hash([0x07; 16], [0x08; 32], vec![0x09u8; 99], AkmType::Wpa2Psk);
        let mut b = make_paired_hash([0x07; 16], [0x08; 32], vec![0x09u8; 99], AkmType::Wpa2Psk);
        a.message_pair = 0x00;
        b.message_pair = 0x80;
        let essid = b"net";
        assert_ne!(
            eapol_fingerprint(&a, essid, false),
            eapol_fingerprint(&b, essid, false),
            "default: message_pair byte distinguishes the two combos"
        );
        assert_eq!(
            eapol_fingerprint(&a, essid, true),
            eapol_fingerprint(&b, essid, true),
            "--collapse-message-pair: identical crackable content -> one fingerprint"
        );
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
        let fp_eapol = eapol_fingerprint(&pair, &[], false);

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
        let fp_psk = eapol_fingerprint(&psk_pair, b"net", false);
        let fp_ft = eapol_fingerprint(&ft_pair, b"net", false);
        assert_ne!(fp_psk, fp_ft, "FT-PSK kind byte 0x04 must differ from PSK kind byte 0x02");
    }
}
