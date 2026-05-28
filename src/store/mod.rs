//! Phase 3 -- Extract: store layer (in-memory data accumulated during ingest+decode). See ARCHITECTURE.md §3.3.
//!
//! The primary stores are `MessageStore` (EAPOL messages grouped by AP/STA pair,
//! no eviction) and `PmkidStore` (PMKIDs deduped per pair). Supporting stores are
//! `EssidMap` (AP MAC -> SSID history with timestamp-nearest resolution) and the
//! auxiliary sets for probe ESSIDs, EAP identities, usernames, and WPS device info.
//! `AkmMap` records the AKM type observed in Beacon/ProbeResponse RSN IEs so that
//! subsequent EAPOL frames for the same AP are tagged for correct output routing
//! (mode 22000 vs 37100). See `ARCHITECTURE.md §3.3` for data structure details and
//! memory budget estimates.

pub mod auxiliary;
pub mod disk_messages;
pub mod essid;
pub mod fragments;
pub mod messages;
pub mod pmkid;

use std::collections::HashMap;

use crate::types::{AkmType, MacAddr, MacPair};

// Re-export key types so callers can write `store::EssidMap` etc.
pub use essid::EssidMap;

// --- AKM context map ---

/// Two-layer AKM lookup: per-(AP, STA) overrides per-AP default.
///
/// Used during Phase 1 (Collect) to tag EAPOL messages with the correct AKM type for
/// output routing (mode 22000 vs 37100).
///
/// Beacons / `ProbeResponses` populate the AP-wide table via `insert`: `detect_akm`
/// returns the **first** AKM suite listed in the RSN IE, which is the PSK entry in
/// the common case where an AP advertises both AKM 2 (WPA2-PSK) and AKM 4 (FT-PSK).
///
/// Association Requests, Reassociation Requests, and embedded RSN IEs in M2 Key Data
/// reveal the **negotiated** AKM for a specific client session. These populate the
/// per-pair table via `insert_sta`. `get_best` prefers the per-pair entry because it
/// is authoritative for that handshake, falling back to the AP-wide entry when only
/// a Beacon has been observed. Without this, APs supporting both PSK and FT-PSK route
/// every handshake to mode 22000, never mode 37100 -- matching the observation that
/// upstream hcxpcapngtool emits FT-PSK hashes while wpawolf previously did not.
///
/// AKM suite type bytes are read from the RSN IE AKM Suite List (OUI `00:0F:AC`) per
/// IEEE 802.11-2024 §9.4.2.24, Table 9-190.
#[derive(Debug, Default)]
pub struct AkmMap {
    /// Per-AP default, populated from Beacon/ProbeResponse RSN IE.
    ap_map: HashMap<MacAddr, AkmType>,
    /// Per-(AP, STA) override, populated from AssocReq/ReassocReq RSN IE or M2 Key Data RSN IE.
    sta_map: HashMap<MacPair, AkmType>,
}

impl AkmMap {
    /// Creates an empty `AkmMap`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the per-AP AKM type from a Beacon/ProbeResponse RSN IE.
    ///
    /// A later Beacon/ProbeResponse supersedes an earlier one for the same AP.
    pub fn insert(&mut self, ap: MacAddr, akm: AkmType) {
        self.ap_map.insert(ap, akm);
    }

    /// Records the negotiated AKM type for a specific (AP, STA) session.
    ///
    /// Called from AssocReq/ReassocReq processing and from M2 embedded RSN IE parsing,
    /// where the peer has committed to a single AKM from the AP's advertised list.
    /// Only the first observation is kept (`entry().or_insert`) so an early
    /// authoritative signal is not overwritten by a later generic fallback.
    pub fn insert_sta(&mut self, ap: MacAddr, sta: MacAddr, akm: AkmType) {
        if akm == AkmType::Unknown {
            return;
        }
        self.sta_map.entry(MacPair { ap, sta }).or_insert(akm);
    }

    /// Returns the AKM type for `ap`, or `AkmType::Unknown` if no Beacon was seen.
    ///
    /// Layer-1 lookup only; used by code paths that have no STA context (e.g. PMKIDs
    /// discovered from an FT Action frame where the target AP is not the frame source).
    ///
    /// `.copied()` on `Option<&AkmType>` is a safe copy -- no `.unwrap()` involved.
    #[must_use]
    pub fn get(&self, ap: &MacAddr) -> AkmType {
        self.ap_map.get(ap).copied().unwrap_or(AkmType::Unknown)
    }

    /// Returns the best-known AKM for this (AP, STA) pair.
    ///
    /// Prefers the per-pair entry (set from `AssocReq` RSN IE or M2 Key Data RSN IE)
    /// over the per-AP default (set from Beacon RSN IE). Returns `AkmType::Unknown`
    /// when neither source has been observed.
    #[must_use]
    pub fn get_best(&self, ap: &MacAddr, sta: &MacAddr) -> AkmType {
        if let Some(&akm) = self.sta_map.get(&MacPair { ap: *ap, sta: *sta }) {
            return akm;
        }
        self.get(ap)
    }

    /// Coarse heap + struct-bytes estimate for `--mem-stats` reporting.
    ///
    /// Approximates `HashMap` overhead as `capacity * (entry_size + 8 B per-bucket)`
    /// per the hashbrown table layout. Off by a small fraction in practice; the
    /// purpose is to identify the dominant grower across a corpus run, not to give
    /// VM-page-accurate numbers.
    #[must_use]
    pub fn approx_bytes(&self) -> usize {
        size_of::<Self>()
            + self.ap_map.capacity() * (size_of::<(MacAddr, AkmType)>() + 8)
            + self.sta_map.capacity() * (size_of::<(MacPair, AkmType)>() + 8)
    }

    /// Total entry count across both inner maps (for `--mem-stats` reporting).
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.ap_map.len() + self.sta_map.len()
    }
}

// --- MldStore: link MAC -> MLD MAC ---

/// Maps an 802.11be link MAC address to its Multi-Link Device (MLD) MAC address.
///
/// Populated during Phase 1 (Collect) from Multi-Link Elements (ext ID 107) observed
/// in Beacons (AP MLD) and Association Requests (STA MLD). Used to canonicalize
/// `MacPair` keys before pairing so that a client cycling link addresses across
/// bands (typical in 802.11be) does not splinter into unrelated `(AP, STA)` groups.
///
/// Design note: we record each link MAC -> MLD MAC only once (first observation wins).
/// Consistency across a session is a spec requirement per [IEEE 802.11be] §35.3; if
/// a capture violates it, the later observation is ignored rather than crashing.
#[derive(Debug, Default)]
pub struct MldStore {
    link_to_mld: HashMap<MacAddr, MacAddr>,
}

impl MldStore {
    /// Creates an empty `MldStore`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that `link_addr` is a link of the multi-link device `mld_addr`.
    ///
    /// First observation wins. A self-mapping (`link == mld`) is stored verbatim --
    /// it is valid per the spec and means "this device is single-link or the link
    /// MAC equals the MLD MAC."
    pub fn record(&mut self, link_addr: MacAddr, mld_addr: MacAddr) {
        self.link_to_mld.entry(link_addr).or_insert(mld_addr);
    }

    /// Returns the MLD MAC for `link_addr`, or `link_addr` unchanged if no MLD
    /// mapping has been learned.
    ///
    /// Callers that want the canonical identity can simply call `canonicalize(m)`
    /// regardless of whether an MLD was seen.
    #[must_use]
    pub fn canonicalize(&self, link_addr: MacAddr) -> MacAddr {
        self.link_to_mld.get(&link_addr).copied().unwrap_or(link_addr)
    }

    /// Returns the number of link -> MLD mappings learned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.link_to_mld.len()
    }

    /// Returns `true` if no MLD mappings have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.link_to_mld.is_empty()
    }

    /// Coarse heap + struct-bytes estimate for `--mem-stats` reporting.
    #[must_use]
    pub fn approx_bytes(&self) -> usize {
        size_of::<Self>() + self.link_to_mld.capacity() * (size_of::<(MacAddr, MacAddr)>() + 8)
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
    use crate::types::AkmType;

    fn mac(b: u8) -> MacAddr {
        MacAddr::from_bytes([b; 6])
    }

    #[test]
    fn akm_map_insert_and_get() {
        let mut m = AkmMap::new();
        let ap = mac(0x11);
        m.insert(ap, AkmType::Wpa2Psk);
        assert_eq!(m.get(&ap), AkmType::Wpa2Psk);
    }

    #[test]
    fn akm_map_unknown_ap() {
        let m = AkmMap::new();
        assert_eq!(m.get(&mac(0xFF)), AkmType::Unknown);
    }

    #[test]
    fn akm_map_overwrite() {
        let mut m = AkmMap::new();
        let ap = mac(0x22);
        m.insert(ap, AkmType::Wpa2Psk);
        m.insert(ap, AkmType::FtPsk);
        assert_eq!(m.get(&ap), AkmType::FtPsk);
    }

    #[test]
    fn akm_map_sta_override_beats_ap_default() {
        // AP advertises PSK first (Beacon); STA negotiates FT-PSK (AssocReq).
        // get_best must prefer the per-pair authoritative signal.
        let mut m = AkmMap::new();
        let ap = mac(0x11);
        let sta = mac(0x22);
        m.insert(ap, AkmType::Wpa2Psk);
        m.insert_sta(ap, sta, AkmType::FtPsk);
        assert_eq!(m.get_best(&ap, &sta), AkmType::FtPsk);
        // Per-AP default unchanged.
        assert_eq!(m.get(&ap), AkmType::Wpa2Psk);
    }

    #[test]
    fn akm_map_sta_falls_back_to_ap_default() {
        let mut m = AkmMap::new();
        let ap = mac(0x11);
        let sta = mac(0x22);
        m.insert(ap, AkmType::PskSha256);
        // No insert_sta call -- get_best must fall back to AP default.
        assert_eq!(m.get_best(&ap, &sta), AkmType::PskSha256);
    }

    #[test]
    fn akm_map_sta_unknown_is_ignored() {
        // insert_sta must not overwrite with AkmType::Unknown.
        let mut m = AkmMap::new();
        let ap = mac(0x11);
        let sta = mac(0x22);
        m.insert_sta(ap, sta, AkmType::FtPsk);
        m.insert_sta(ap, sta, AkmType::Unknown);
        assert_eq!(m.get_best(&ap, &sta), AkmType::FtPsk);
    }

    #[test]
    fn akm_map_sta_first_insert_wins() {
        // entry().or_insert: first observation wins, later ones do not overwrite.
        // This matches the AssocReq -> M2 sequence where AssocReq is authoritative.
        let mut m = AkmMap::new();
        let ap = mac(0x11);
        let sta = mac(0x22);
        m.insert_sta(ap, sta, AkmType::FtPsk);
        m.insert_sta(ap, sta, AkmType::Wpa2Psk);
        assert_eq!(m.get_best(&ap, &sta), AkmType::FtPsk);
    }

    // --- MldStore tests ---

    #[test]
    fn mld_store_canonicalize_known() {
        let mut s = MldStore::new();
        let link = mac(0x11);
        let mld = mac(0xAA);
        s.record(link, mld);
        assert_eq!(s.canonicalize(link), mld);
    }

    #[test]
    fn mld_store_canonicalize_unknown_returns_self() {
        let s = MldStore::new();
        let link = mac(0x42);
        assert_eq!(s.canonicalize(link), link);
    }

    #[test]
    fn mld_store_first_record_wins() {
        // A later record for the same link address is ignored (spec requires consistency).
        let mut s = MldStore::new();
        let link = mac(0x11);
        s.record(link, mac(0xAA));
        s.record(link, mac(0xBB));
        assert_eq!(s.canonicalize(link), mac(0xAA));
    }

    #[test]
    fn mld_store_len_and_empty() {
        let mut s = MldStore::new();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        s.record(mac(0x11), mac(0xAA));
        assert!(!s.is_empty());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn mld_store_self_mapping_is_allowed() {
        // Single-link device: link MAC == MLD MAC.
        let mut s = MldStore::new();
        let m = mac(0x55);
        s.record(m, m);
        assert_eq!(s.canonicalize(m), m);
    }
}
