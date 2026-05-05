//! Phase 3 -- Extract: auxiliary stores for optional output modes (-W -I -U -D -E -R). See ARCHITECTURE.md §3.3 + §9.
//!
//! `EssidSet` collects unique AP-advertised SSIDs (`-E` output). `ProbeEssidSet` collects
//! unique client-requested SSIDs (`-R` output). `WordlistStore` is the comprehensive
//! leaked-text superset (`-W` output). `IdentitySet` and `UsernameSet` collect unique EAP
//! identity and username strings (`-I` and `-U` output). `DeviceInfoStore` accumulates WPS
//! device metadata entries (`-D` output). All stores are populated only when the
//! corresponding CLI flag is set -- zero overhead if the flag is absent. See
//! `ARCHITECTURE.md §3.3`.

use std::collections::HashSet;

use crate::types::{MacAddr, split_on_control_bytes};

/// Coarse heap-bytes estimate for a `HashSet<Vec<u8>>` store.
///
/// Sums table-bucket overhead (per-element struct size + 8 B per bucket) plus
/// every entry `Vec<u8>`'s heap capacity. Shared by `EssidSet`,
/// `ProbeEssidSet`, `WordlistStore`, and `WordlistScanIesStore` so the
/// approximation formula stays in one place. See `--mem-stats`.
fn approx_byte_set(set: &HashSet<Vec<u8>>) -> usize {
    let table_bytes = set.capacity() * (size_of::<Vec<u8>>() + 8);
    let entries_bytes: usize = set.iter().map(Vec::capacity).sum();
    table_bytes + entries_bytes
}

/// Maximum SSID length per IEEE 802.11-2024 §9.4.2.3.
///
/// SSIDs longer than this come from bit-flipped IE Length bytes or
/// mis-framed body fragments and are discarded at the `-E`/`-R` insertion
/// point. The strings-extract pass for `-W` still surfaces any printable
/// runs inside such blobs via `crate::strings_scan::extract_ascii_runs`.
const SSID_LEN_MAX: usize = 32;

/// Applies hcxpcapngtool's `fwriteessidstr` filter -- returns `true` iff
/// the SSID bytes pass hcx's write gate.
///
/// The 32-byte cap is spec-mandated: [IEEE 802.11-2024] §9.4.2.2 (Figure
/// 9-209) defines the SSID element Length field as 0-32 octets, so any
/// `> 32` body is by definition a parse error / bit-flipped IE Length.
/// Length 0 is the spec-defined wildcard SSID (used in Probe Requests
/// and mesh Beacon/Probe Response per §9.4.2.2 paragraph 3); not a
/// usable hash salt. The first-byte-zero gate is hcxtools' hidden-network
/// convention: APs that pad the SSID element with NUL bytes instead of
/// using length=0 produce a salt whose PMK derivation cannot match any
/// real network, so the resulting hash is uncrackable.
///
/// Mirror of `hcxtools/include/fileops.c:72-86`:
///
/// ```text
/// if ((len == 0) || (len > ESSID_LEN_MAX)) return;
/// if (essidstr[0] == 0) return;
/// ```
///
/// Used by `EssidSet` (`-E`), `ProbeEssidSet` (`-R`), and `EssidMap`
/// (the per-AP SSID history that drives hash-line ESSID resolution) so
/// the same admission rule governs every place SSIDs feed downstream.
/// Broader string collection -- corrupted-frame fragments, sub-`min_len`
/// runs, blobs `> 32` bytes -- happens only in `WordlistStore` (`-W`).
pub(crate) fn passes_hcx_essid_filter(essid: &[u8]) -> bool {
    if essid.is_empty() || essid.len() > SSID_LEN_MAX {
        return false;
    }
    essid.first() != Some(&0)
}

// --- AP ESSID set (-E) ---

/// Unique SSIDs observed in AP-transmitted frames.
///
/// Used for `-E` output. Collects SSIDs from Beacons, Probe Responses,
/// Association/Reassociation Requests, Probe Requests, Action Measurement
/// Requests, SSID List IEs (tag 84), Mesh ID IEs (tag 114), OWE Transition
/// Mode SSIDs, and vendor IE AP names. The first five sources are the ones
/// hcxpcapngtool's `-E` also covers (see its AP-list population across
/// `process80211{beacon,probe_resp,probe_req,probe_req_direct,
/// association_req,reassociation_req,actionmeasurement}` in
/// `hcxtools/hcxpcapngtool.c`); the remaining sources are wpawolf
/// additions that hcx does not parse.
///
/// Accepts only SSIDs passing hcx's `fwriteessidstr` gate (`len 1..=32`,
/// first byte non-zero). Stores bytes verbatim -- no control-byte
/// splitting, no autohex expansion. All stripping and formatting happens
/// at the output layer per `ARCHITECTURE.md §9`.
#[derive(Debug, Default)]
pub struct EssidSet {
    set: HashSet<Vec<u8>>,
}

impl EssidSet {
    /// Creates an empty `EssidSet`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts `essid` if it passes hcx's `fwriteessidstr` gate.
    ///
    /// Matches `hcxtools/include/fileops.c:72-86` so wolf's `-E`
    /// admission rule is byte-compatible with hcx's. Control-byte
    /// splitting and run-extraction were removed -- the `-W` store
    /// collects those via `crate::strings_scan` instead, keeping `-E` a
    /// strict AP-/client-SSID list rather than a generic wordlist.
    pub fn insert(&mut self, essid: &[u8]) {
        if passes_hcx_essid_filter(essid) {
            self.set.insert(essid.to_vec());
        }
    }

    /// Iterates over unique SSID byte strings in arbitrary order.
    pub fn iter(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.set.iter()
    }

    /// Returns the number of unique ESSIDs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Returns `true` if no ESSIDs have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Coarse heap + struct-bytes estimate for `--mem-stats` reporting.
    #[must_use]
    pub fn approx_bytes(&self) -> usize {
        size_of::<Self>() + approx_byte_set(&self.set)
    }
}

// --- Probe Request ESSID set (-R) ---

/// Unique SSIDs observed in client-originated frames.
///
/// Used for `-R` output. Collects SSIDs from directed and undirected Probe
/// Requests (IE#0 SSID and IE#84 SSID List) and Action Measurement Request
/// frames. These represent networks the client is actively seeking, not
/// networks advertised by APs. Matches the hcxpcapngtool `-R` source
/// inventory (subset of its AP list filtered by `status == ST_PROBE_REQ ||
/// status == ST_ACT_MR_REQ`).
///
/// Accepts only SSIDs passing hcx's `fwriteessidstr` gate (`len 1..=32`,
/// first byte non-zero). Stores bytes verbatim.
#[derive(Debug, Default)]
pub struct ProbeEssidSet {
    set: HashSet<Vec<u8>>,
}

impl ProbeEssidSet {
    /// Creates an empty `ProbeEssidSet`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts `essid` if it passes hcx's `fwriteessidstr` gate.
    ///
    /// See `EssidSet::insert` for the filter definition and rationale.
    pub fn insert(&mut self, essid: &[u8]) {
        if passes_hcx_essid_filter(essid) {
            self.set.insert(essid.to_vec());
        }
    }

    /// Iterates over unique SSID byte strings in arbitrary order.
    pub fn iter(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.set.iter()
    }

    /// Returns the number of unique probe-request ESSIDs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Returns `true` if no entries have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Coarse heap + struct-bytes estimate for `--mem-stats` reporting.
    #[must_use]
    pub fn approx_bytes(&self) -> usize {
        size_of::<Self>() + approx_byte_set(&self.set)
    }
}

// --- Wordlist store ---

/// All unique leaked-information strings for `-W` / `--wordlist-output`.
///
/// Superset of `EssidSet`: includes all ESSIDs from every source, plus WPS device
/// metadata strings (manufacturer, model, serial, device name), EAP identity/username
/// strings, country codes, vendor AP names, Mesh IDs, and any other text fields leaked
/// in management frames. Only populated when `--wordlist-output` (`-W`) is set.
///
/// Unlike `EssidSet` / `ProbeEssidSet`, every `insert(v)` additionally splits `v` on
/// ASCII control bytes (`0x00..=0x1F` and `0x7F`) via
/// `crate::types::split_on_control_bytes` and stores each non-empty chunk as a
/// separate wordlist entry. Bit-flipped SSIDs, NUL-delimited vendor fields, and
/// similar wire artefacts therefore expand into their salvageable printable runs
/// as additional PSK-crack candidates, while the full un-split value is still kept
/// for callers that want to try it verbatim. See `ARCHITECTURE.md §9`.
#[derive(Debug, Default)]
pub struct WordlistStore {
    set: HashSet<Vec<u8>>,
}

impl WordlistStore {
    /// Creates an empty `WordlistStore`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts `value` plus every control-byte-split non-empty sub-range.
    ///
    /// Empty input is a no-op. If `value` contains no control bytes, only
    /// the single full entry is stored (the splitter yields `value`
    /// unchanged and the `HashSet` dedups). If `value` contains control
    /// bytes, the full original bytes are stored AND each printable run
    /// bordered by control bytes is stored as an additional entry --
    /// nothing is dropped.
    pub fn insert(&mut self, value: Vec<u8>) {
        if value.is_empty() {
            return;
        }
        // Additional wordlist candidates from the control-byte split. Computed
        // before the full-value insert so the borrow of `value` is dropped in
        // time for the move below.
        for chunk in split_on_control_bytes(&value) {
            if chunk.len() != value.len() {
                // Only push fragment copies when they differ from the full value;
                // otherwise the HashSet just dedups the duplicate we're about to
                // store.
                self.set.insert(chunk.to_vec());
            }
        }
        self.set.insert(value);
    }

    /// Iterates over unique strings in arbitrary order.
    pub fn iter(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.set.iter()
    }

    /// Returns the number of unique entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Returns `true` if no entries have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Coarse heap + struct-bytes estimate for `--mem-stats` reporting.
    #[must_use]
    pub fn approx_bytes(&self) -> usize {
        size_of::<Self>() + approx_byte_set(&self.set)
    }
}

// --- IE-scan wordlist (separate strand from `WordlistStore`) ---

/// Unique printable-ASCII runs extracted from management-frame IE bodies via
/// the `--wordlist-scan-ies FILE` sweep.
///
/// This is the dedicated companion strand to `WordlistStore`. Runs come from
/// `crate::strings_scan::extract_ascii_runs` already filtered to
/// `[0x20..=0x7E]` and length `>= 8`, so unlike `WordlistStore` no further
/// control-byte splitting is applied -- the runs are already clean and
/// splitting them again would waste cycles and produce duplicate sub-runs.
///
/// Decoupled from `WordlistStore` (`-W`) by design: `-W` is the curated set
/// of "things that look like passwords" (ESSIDs, WPS device fields, EAP
/// identities, vendor AP names). The IE-scan strand is a wider net that
/// catches printable bytes inside vendor IE bodies wpawolf does not parse
/// structurally -- mostly noise, occasionally a useful candidate. Operators
/// triaging IE-scan output should not have to diff against `-W` to find what
/// the sweep added.
#[derive(Debug, Default)]
pub struct WordlistScanIesStore {
    set: HashSet<Vec<u8>>,
}

impl WordlistScanIesStore {
    /// Creates an empty `WordlistScanIesStore`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts `run` verbatim (no splitting). Empty input is a no-op.
    pub fn insert(&mut self, run: Vec<u8>) {
        if run.is_empty() {
            return;
        }
        self.set.insert(run);
    }

    /// Iterates over unique runs in arbitrary order.
    pub fn iter(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.set.iter()
    }

    /// Returns the number of unique entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Returns `true` if no entries have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Coarse heap + struct-bytes estimate for `--mem-stats` reporting.
    #[must_use]
    pub fn approx_bytes(&self) -> usize {
        size_of::<Self>() + approx_byte_set(&self.set)
    }
}

// --- EAP identity set ---

/// Unique EAP identity strings observed during the capture.
///
/// Only populated when `--identity-output` (`-I`) is set. Identity strings are
/// extracted from EAP-Response/Identity frames per RFC 3748 §5.1.
#[derive(Debug, Default)]
pub struct IdentitySet {
    set: HashSet<String>,
}

impl IdentitySet {
    /// Creates an empty `IdentitySet`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts `identity` if not already present. Empty strings are ignored.
    pub fn insert(&mut self, identity: String) {
        if !identity.is_empty() {
            self.set.insert(identity);
        }
    }

    /// Iterates over unique identity strings in arbitrary order.
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.set.iter()
    }

    /// Returns the number of unique EAP identity strings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Returns `true` if no identity strings have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Coarse heap + struct-bytes estimate for `--mem-stats` reporting.
    #[must_use]
    pub fn approx_bytes(&self) -> usize {
        let table_bytes = self.set.capacity() * (size_of::<String>() + 8);
        let entries_bytes: usize = self.set.iter().map(String::capacity).sum();
        size_of::<Self>() + table_bytes + entries_bytes
    }
}

// --- EAP username set ---

/// Unique EAP username strings observed during the capture.
///
/// Only populated when `--username-output` (`-U`) is set. Username strings are
/// extracted from EAP peer identity fields; the exact source depends on the EAP method.
#[derive(Debug, Default)]
pub struct UsernameSet {
    set: HashSet<String>,
}

impl UsernameSet {
    /// Creates an empty `UsernameSet`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts `username` if not already present. Empty strings are ignored.
    pub fn insert(&mut self, username: String) {
        if !username.is_empty() {
            self.set.insert(username);
        }
    }

    /// Iterates over unique username strings in arbitrary order.
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.set.iter()
    }

    /// Returns the number of unique usernames.
    #[must_use]
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// Returns `true` if no usernames have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    /// Coarse heap + struct-bytes estimate for `--mem-stats` reporting.
    #[must_use]
    pub fn approx_bytes(&self) -> usize {
        let table_bytes = self.set.capacity() * (size_of::<String>() + 8);
        let entries_bytes: usize = self.set.iter().map(String::capacity).sum();
        size_of::<Self>() + table_bytes + entries_bytes
    }
}

// --- WPS device info ---

/// A single WPS device metadata record extracted from a Beacon or `ProbeResponse` WPS IE.
///
/// Collected for `--device-output` (`-D`) and written verbatim. Attribute IDs are
/// defined by the Wi-Fi Protected Setup specification.
///
/// All eight fields appear in the `-D` output line, so `Hash`, `PartialEq`, and
/// `Eq` are derived over every field. Two entries that would render to a
/// byte-identical `-D` line collapse under `DeviceInfoStore`'s row-level dedup.
/// See `output/device_info.rs::write_device_info` for the column order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceInfoEntry {
    /// AP MAC address.
    pub mac: MacAddr,
    /// Device manufacturer name bytes. [Wi-Fi Protected Setup spec] attr 0x1021
    pub manufacturer: Vec<u8>,
    /// Device model name bytes. [Wi-Fi Protected Setup spec] attr 0x1023
    pub model_name: Vec<u8>,
    /// Device model number bytes. [Wi-Fi Protected Setup spec] attr 0x1024.
    pub model_number: Vec<u8>,
    /// Device serial number bytes. [Wi-Fi Protected Setup spec] attr 0x1042
    pub serial_number: Vec<u8>,
    /// Device friendly name bytes. [Wi-Fi Protected Setup spec] attr 0x1011
    pub device_name: Vec<u8>,
    /// UUID-E (16 bytes). [Wi-Fi Protected Setup spec] attr 0x1047
    pub uuid_e: Option<[u8; 16]>,
    /// AP ESSID at the time of the WPS IE observation.
    pub essid: Vec<u8>,
}

/// Collected WPS device metadata entries for `--device-output` (`-D`) output.
///
/// Dedupes at insertion time on the **output-rendered row identity** -- two pushes
/// that would produce a byte-identical `-D` line collapse to one stored entry. The
/// dedup key is the full set of fields in the output column order:
/// `(mac, manufacturer, model_name, model_number, serial_number, device_name,
/// uuid_e, essid)`. Entries with all five primary string fields empty
/// (`manufacturer`, `model_name`, `model_number`, `serial_number`, `device_name`)
/// are skipped on insert -- they would be filtered by `write_device_info`'s
/// all-empty-fields guard at write time anyway, so storing them wastes memory only.
///
/// **Why not `(MAC, UUID-E)` or MAC-only as the dedup key.** A sparse WPS Beacon
/// observation (manufacturer only) would collapse a rich Probe Response observation
/// (full attribute set) when keyed on identifier alone, and the rich row would be
/// permanently lost. Full-row equality avoids this: a sparse and a rich observation
/// for the same AP have non-equal dedup keys (different `model_name` / `serial_number`
/// / `device_name`) and both survive as distinct lines.
///
/// Insertion order is **not** preserved (the writer sorts by manufacturer at output
/// time, so this is invisible downstream). Only populated when `--device-output` is
/// set. See `ARCHITECTURE.md §3.3`.
#[derive(Debug, Default)]
pub struct DeviceInfoStore {
    entries: HashSet<DeviceInfoEntry>,
}

impl DeviceInfoStore {
    /// Creates an empty `DeviceInfoStore`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts `entry` if (a) at least one of the five primary string fields is
    /// non-empty AND (b) no byte-identical-rendered row is already stored.
    /// Otherwise the call is a no-op.
    ///
    /// The empty-fields guard mirrors the all-empty-fields skip in
    /// `output/device_info.rs::write_device_info` so the store does not retain
    /// observations that the writer would never emit.
    pub fn push(&mut self, entry: DeviceInfoEntry) {
        if entry.manufacturer.is_empty()
            && entry.model_name.is_empty()
            && entry.model_number.is_empty()
            && entry.serial_number.is_empty()
            && entry.device_name.is_empty()
        {
            return;
        }
        self.entries.insert(entry);
    }

    /// Iterates over all stored device info entries.
    ///
    /// Iteration order is `HashSet`-iteration order (not deterministic across runs).
    /// `write_device_info` sorts by manufacturer at output time so this does not
    /// affect the rendered file.
    pub fn iter(&self) -> impl Iterator<Item = &DeviceInfoEntry> {
        self.entries.iter()
    }

    /// Returns the number of unique stored entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no entries have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Coarse heap + struct-bytes estimate for `--mem-stats` reporting.
    #[must_use]
    pub fn approx_bytes(&self) -> usize {
        // HashSet has roughly capacity * entry-slot overhead; entry slots include
        // the key value plus per-bucket bookkeeping. Use the same per-entry struct
        // size estimate the prior Vec backing produced and add the per-byte-vec
        // capacity sums; close enough for the diagnostic output.
        let mut entries_bytes = self.entries.capacity() * (size_of::<DeviceInfoEntry>() + 8);
        for e in &self.entries {
            entries_bytes = entries_bytes
                .saturating_add(e.manufacturer.capacity())
                .saturating_add(e.model_name.capacity())
                .saturating_add(e.model_number.capacity())
                .saturating_add(e.serial_number.capacity())
                .saturating_add(e.device_name.capacity())
                .saturating_add(e.essid.capacity());
        }
        size_of::<Self>() + entries_bytes
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

    #[test]
    fn essid_set_dedup() {
        let mut s = EssidSet::new();
        s.insert(b"net");
        s.insert(b"net");
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn essid_set_empty_ignored() {
        let mut s = EssidSet::new();
        s.insert(&[]);
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
    }

    #[test]
    fn essid_set_all_null_ignored() {
        let mut s = EssidSet::new();
        s.insert(&[0, 0, 0]);
        assert!(s.is_empty());
    }

    #[test]
    fn essid_set_rejects_oversized() {
        // Per hcxpcapngtool's fwriteessidstr (`fileops.c:72-86`) and IEEE
        // 802.11-2024 §9.4.2.3 SSID Length <= 32, any byte string longer
        // than 32 bytes is not a valid SSID and never lands in -E.
        let mut s = EssidSet::new();
        let blob = vec![b'A'; 33];
        s.insert(&blob);
        assert_eq!(s.len(), 0);
        // At the 32-byte boundary the entry is still accepted.
        s.insert(&blob[..32]);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn essid_set_rejects_leading_nul() {
        // Matches hcx's `if (essidstr[0] == 0) return;` gate: SSID values
        // that begin with 0x00 are never written to -E. The trailing bytes
        // are not salvaged -- no control-byte splitting is performed at
        // this layer (the `-W` store captures such fragments via
        // `crate::strings_scan`).
        let mut s = EssidSet::new();
        s.insert(&[0x00, b'A', b'P', b'1']);
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn essid_set_preserves_control_bytes_in_value() {
        // Embedded control bytes in an otherwise valid SSID pass through
        // verbatim -- the spec permits any byte 0x00-0xFF in an SSID
        // element and we store bytes as they appear on the wire. The
        // output-layer NUL-padding trim is the only transform applied.
        let mut s = EssidSet::new();
        s.insert(b"HomeWiFi\x01");
        assert_eq!(s.len(), 1);
        assert_eq!(s.iter().next().unwrap().as_slice(), b"HomeWiFi\x01");
    }

    #[test]
    fn essid_set_preserves_high_bytes() {
        // High-bit bytes (0x80-0xFF) are spec-valid and pass through.
        let mut s = EssidSet::new();
        s.insert(b"caf\xc3\xa9"); // UTF-8 "cafe" with acute accent
        assert_eq!(s.len(), 1);
        assert_eq!(s.iter().next().unwrap().as_slice(), b"caf\xc3\xa9");
    }

    #[test]
    fn probe_essid_set_dedup() {
        let mut s = ProbeEssidSet::new();
        s.insert(b"coffee-wifi");
        s.insert(b"coffee-wifi");
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn probe_essid_set_empty_ignored() {
        let mut s = ProbeEssidSet::new();
        s.insert(&[]);
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
    }

    #[test]
    fn probe_essid_set_rejects_leading_nul_and_oversized() {
        let mut s = ProbeEssidSet::new();
        s.insert(&[0x00, b'G', b'u', b'e', b's', b't']); // leading NUL -> skipped
        assert_eq!(s.len(), 0);
        s.insert(&[b'A'; 33]); // >32 bytes -> skipped
        assert_eq!(s.len(), 0);
        s.insert(b"Guest"); // clean -> accepted
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn wordlist_store_dedup() {
        let mut s = WordlistStore::new();
        s.insert(b"MyRouter".to_vec());
        s.insert(b"MyRouter".to_vec());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn wordlist_store_empty_ignored() {
        let mut s = WordlistStore::new();
        s.insert(vec![]);
        assert!(s.is_empty());
    }

    #[test]
    fn wordlist_store_heterogeneous() {
        let mut s = WordlistStore::new();
        s.insert(b"MyNetwork".to_vec()); // ESSID
        s.insert(b"Linksys".to_vec()); // WPS manufacturer
        s.insert(b"US".to_vec()); // country code
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn wordlist_store_clean_value_no_split() {
        // A value with no control bytes stores a single entry: no chunk
        // equals the full value, so the full-value insert is the only one.
        let mut s = WordlistStore::new();
        s.insert(b"MyRouter".to_vec());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn wordlist_store_splits_on_embedded_nul() {
        // WPS vendor blob with embedded NUL padding -> full value kept +
        // the two non-empty fragments. Dedup ensures no duplicates.
        let mut s = WordlistStore::new();
        s.insert(b"Acme\x00Router".to_vec());
        assert_eq!(s.len(), 3);
        assert!(s.iter().any(|v| v.as_slice() == b"Acme\x00Router"));
        assert!(s.iter().any(|v| v.as_slice() == b"Acme"));
        assert!(s.iter().any(|v| v.as_slice() == b"Router"));
    }

    #[test]
    fn wordlist_store_splits_on_leading_and_trailing_controls() {
        // Leading/trailing NUL padding -> full value + single fragment.
        let mut s = WordlistStore::new();
        s.insert(b"\x00\x00Guest\x00".to_vec());
        assert_eq!(s.len(), 2);
        assert!(s.iter().any(|v| v.as_slice() == b"\x00\x00Guest\x00"));
        assert!(s.iter().any(|v| v.as_slice() == b"Guest"));
    }

    #[test]
    fn wordlist_store_splits_on_del_and_low_controls() {
        // 0x7F (DEL) and low-ASCII controls split; high bytes preserved.
        let mut s = WordlistStore::new();
        s.insert(b"foo\x7fbar\x01baz".to_vec());
        assert_eq!(s.len(), 4);
        assert!(s.iter().any(|v| v.as_slice() == b"foo\x7fbar\x01baz"));
        assert!(s.iter().any(|v| v.as_slice() == b"foo"));
        assert!(s.iter().any(|v| v.as_slice() == b"bar"));
        assert!(s.iter().any(|v| v.as_slice() == b"baz"));
    }

    #[test]
    fn wordlist_store_all_controls_keeps_full_value_only() {
        // A value containing only control bytes has no printable fragments,
        // so only the full raw value is stored (autohex-encoded on output).
        let mut s = WordlistStore::new();
        s.insert(vec![0x00, 0x01, 0x7F]);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn identity_set_dedup() {
        let mut s = IdentitySet::new();
        s.insert("user@example.com".to_owned());
        s.insert("user@example.com".to_owned());
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn identity_set_empty_ignored() {
        let mut s = IdentitySet::new();
        s.insert(String::new());
        assert!(s.is_empty());
    }

    #[test]
    fn username_set_dedup() {
        let mut s = UsernameSet::new();
        s.insert("alice".to_owned());
        s.insert("alice".to_owned());
        assert_eq!(s.len(), 1);
    }

    fn make_entry_with_mac(mac_byte: u8, manufacturer: &[u8]) -> DeviceInfoEntry {
        DeviceInfoEntry {
            mac: MacAddr::from_bytes([mac_byte; 6]),
            manufacturer: manufacturer.to_vec(),
            model_name: vec![],
            model_number: vec![],
            serial_number: vec![],
            device_name: vec![],
            uuid_e: None,
            essid: vec![],
        }
    }

    #[test]
    fn device_info_store_distinct_macs_both_retained() {
        // Two entries with DIFFERENT MACs -> both retained.
        let mut store = DeviceInfoStore::new();
        store.push(make_entry_with_mac(0x11, b"Acme"));
        store.push(make_entry_with_mac(0x22, b"Corp"));
        assert_eq!(store.len(), 2);
        // Iteration order is HashSet-order (non-deterministic); collect into a
        // sorted Vec for a stable assertion.
        let mut names: Vec<&[u8]> = store.iter().map(|e| e.manufacturer.as_slice()).collect();
        names.sort_unstable();
        assert_eq!(names, vec![b"Acme".as_slice(), b"Corp".as_slice()]);
    }

    #[test]
    fn device_info_store_same_mac_different_rows_both_retained() {
        // Two entries sharing a MAC but with different manufacturer -> distinct
        // dedup keys -> both retained. This guards against the prior "MAC-only
        // dedup" failure mode where a sparse Beacon observation overwrote a rich
        // Probe Response observation (or vice-versa).
        let mut store = DeviceInfoStore::new();
        store.push(make_entry_with_mac(0x11, b"Acme"));
        store.push(make_entry_with_mac(0x11, b"Corp")); // same MAC, different mfr
        assert_eq!(store.len(), 2, "same MAC + different fields must be retained");
    }

    #[test]
    fn device_info_store_dedupes_byte_identical_rows() {
        // Two byte-identical pushes -> one stored. This is the operator-friendly
        // contract: the -D output is already deduped, no `sort -u` post-processing
        // required.
        let mut store = DeviceInfoStore::new();
        store.push(make_entry_with_mac(0x11, b"Acme"));
        store.push(make_entry_with_mac(0x11, b"Acme"));
        assert_eq!(store.len(), 1, "byte-identical rows must collapse to one");
    }

    #[test]
    fn device_info_store_distinguishes_by_model_number() {
        // model_number is its own -D column (wpawolf addition over hcxtools), so
        // two entries differing only in model_number render to distinct lines and
        // must NOT collapse. Guards against accidentally reverting to the
        // hcx-parity behaviour where model_number was dropped from output.
        let mut store = DeviceInfoStore::new();
        let mut e1 = make_entry_with_mac(0x11, b"Acme");
        e1.model_number = b"v1".to_vec();
        let mut e2 = make_entry_with_mac(0x11, b"Acme");
        e2.model_number = b"v2".to_vec();
        store.push(e1);
        store.push(e2);
        assert_eq!(store.len(), 2, "differing model_number must produce distinct rows");
    }

    #[test]
    fn device_info_store_skips_all_empty_fields_on_insert() {
        // Mirrors the all-empty-fields skip in write_device_info. Storing such
        // entries wastes memory because the writer would skip them at output
        // time anyway. Both UUID-E and ESSID alone are NOT primary content --
        // the writer's all-empty guard ignores them.
        let mut store = DeviceInfoStore::new();
        let entry = DeviceInfoEntry {
            mac: MacAddr::from_bytes([0x11; 6]),
            manufacturer: vec![],
            model_name: vec![],
            model_number: vec![],
            serial_number: vec![],
            device_name: vec![],
            uuid_e: Some([0xAB; 16]),
            essid: b"NetX".to_vec(),
        };
        store.push(entry);
        assert_eq!(store.len(), 0, "all-primary-string-fields-empty entry must be skipped");
    }

    #[test]
    fn device_info_store_keeps_entry_with_only_one_primary_field() {
        // A single non-empty primary field is enough to retain the entry --
        // mirrors what write_device_info will emit. Tested via manufacturer here;
        // model_number alone is covered by device_info_store_keeps_entry_with_only_model_number.
        let mut store = DeviceInfoStore::new();
        store.push(make_entry_with_mac(0x11, b"Acme")); // manufacturer only
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn device_info_store_keeps_entry_with_only_model_number() {
        // model_number alone is sufficient content to retain the entry -- it is
        // a primary field with its own -D column.
        let mut store = DeviceInfoStore::new();
        let entry = DeviceInfoEntry {
            mac: MacAddr::from_bytes([0x11; 6]),
            manufacturer: vec![],
            model_name: vec![],
            model_number: b"v1".to_vec(),
            serial_number: vec![],
            device_name: vec![],
            uuid_e: None,
            essid: vec![],
        };
        store.push(entry);
        assert_eq!(store.len(), 1, "model_number alone counts as primary content");
    }
}
