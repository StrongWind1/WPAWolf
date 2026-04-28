//! Phase 4 -- Emit: output coordination (PMKID pipeline + EAPOL pair pipeline run independently). See ARCHITECTURE.md §3.4 + §7.
//!
//! Opens every configured hash sink (legacy `--22000-out` / `--37100-out` plus the
//! 11-type taxonomy sinks `--wpa1-out`, `--wpa2-out`, `--psk-sha256-out`, `--ft-out`,
//! `--psk-sha384-out`, `--ft-psk-sha384-out`, and the combined `-o`) and the auxiliary
//! wordlists. Every emitted hash is fanned out to *every* configured sink whose
//! accept-set contains the classified `HashType`, with the appropriate per-sink line
//! prefix and per-sink dedup. The PMKID and EAPOL pipelines run to completion
//! independently (Invariant OUT-1 in `ARCHITECTURE.md §7`).

pub mod dedup;
pub mod device_info;
pub mod hashcat;
pub mod wordlists;

use std::io::{BufWriter, Write as _};
use std::path::{Path, PathBuf};

use crate::log::Logger;
use crate::pair::combos::PairConfig;
use crate::pair::pair_all_groups;
use crate::pair::{ComboType, FLAG_BE, FLAG_LE, FLAG_NC, PairedHash};
use crate::store::AkmMap;
use crate::store::auxiliary::{DeviceInfoStore, EssidSet, IdentitySet, ProbeEssidSet, UsernameSet, WordlistStore};
use crate::store::messages::MessageStore;
use crate::store::pmkid::{PmkidEntry, PmkidStore};
use crate::types::{AkmType, FtFields, HashType, Result};

use self::dedup::{PerSinkDedup, SinkId};
use self::device_info::write_device_info;
use self::hashcat::{format_eapol_ft_line, format_eapol_line, format_pmkid_ft_line, format_pmkid_line};
use self::wordlists::{write_essid_list, write_identities, write_probe_essid_list, write_usernames, write_wordlist};

// --- OutputPaths ---

/// Paths for all optional output files.
///
/// `None` means the corresponding output was not requested by the user on the CLI.
/// All fields are optional so the caller can enable any subset of outputs.
#[derive(Debug, Default)]
pub struct OutputPaths {
    /// `--22000-out` -- legacy hashcat mode 22000 (every non-FT hash, `WPA*01*`/`WPA*02*`).
    pub out_22000: Option<PathBuf>,
    /// `--37100-out` -- legacy hashcat mode 37100 (every FT hash, `WPA*03*`/`WPA*04*`).
    pub out_37100: Option<PathBuf>,
    /// `-o`/`--out` -- combined 11-type taxonomy file (every emitted hash).
    pub out_combined: Option<PathBuf>,
    /// `--wpa1-out` -- type 1 only.
    pub out_wpa1: Option<PathBuf>,
    /// `--wpa2-out` -- types 2 + 3.
    pub out_wpa2: Option<PathBuf>,
    /// `--psk-sha256-out` -- types 4 + 5.
    pub out_psk_sha256: Option<PathBuf>,
    /// `--ft-out` -- types 6 + 7 (FT-PSK SHA-256, FT extras appended).
    pub out_ft: Option<PathBuf>,
    /// `--psk-sha384-out` -- types 8 + 9.
    pub out_psk_sha384: Option<PathBuf>,
    /// `--ft-psk-sha384-out` -- types 10 + 11 (FT-PSK SHA-384, FT extras appended).
    pub out_ft_psk_sha384: Option<PathBuf>,
    /// Path for ESSID list output (`-E`): AP-advertised ESSIDs.
    pub essid_list: Option<PathBuf>,
    /// Path for Probe Request ESSID list output (`-R`): client-requested ESSIDs.
    pub probe_essid_list: Option<PathBuf>,
    /// Path for leaked-information wordlist output (`-W`).
    pub wordlist: Option<PathBuf>,
    /// Path for EAP identity list output (`-I`).
    pub identity_list: Option<PathBuf>,
    /// Path for EAP username list output (`-U`).
    pub username_list: Option<PathBuf>,
    /// Path for device info output (`-D`).
    pub device_info: Option<PathBuf>,
}

// --- Per-sink line counts ---

/// One `u64` per sink, indexed by `SinkId::as_index()`.
type PerSinkCounts = [u64; SinkId::COUNT];

// --- OutputStats ---

/// Summary counts from a completed output run.
///
/// Returned by `run_output` for display in the final stats line and for testing.
/// Per-combo counts let `main` populate the detailed `Stats` breakdown -- one row
/// per N#E# combo (N1E2, N3E2, N1E4, N2E3, N4E3, N3E4).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct OutputStats {
    /// Total *logical* PMKID hashes that survived dedup at least once across all sinks.
    pub pmkids_written: usize,
    /// Total *logical* EAPOL pairs that survived dedup at least once across all sinks.
    pub pairs_written: usize,
    /// Total *logical* hashes suppressed by every configured sink's dedup.
    pub dedup_dropped: usize,

    /// Per-sink line counts (passed each sink's dedup, written to disk if configured).
    pub lines_per_sink: PerSinkCounts,
    /// Per-sink dedup-suppressed counts.
    pub dropped_per_sink: PerSinkCounts,

    // --- per-combo written counts ---
    /// N1E2 pairs written (challenge -- `ANonce` from M1, EAPOL from M2).
    pub n1e2: usize,
    /// N3E2 pairs written (authorized -- `ANonce` from M3, EAPOL from M2).
    pub n3e2: usize,
    /// N1E4 pairs written (authorized -- `ANonce` from M1, EAPOL from M4).
    pub n1e4: usize,
    /// N2E3 pairs written (AP-less authorized -- `SNonce` from M2, EAPOL from M3).
    pub n2e3: usize,
    /// N4E3 pairs written (AP-less authorized -- `SNonce` from M4, EAPOL from M3).
    pub n4e3: usize,
    /// N3E4 pairs written (authorized -- `ANonce` from M3, EAPOL from M4).
    pub n3e4: usize,

    // --- flag counters ---
    /// Pairs written with `FLAG_NC` set.
    pub pairs_nc: usize,
    /// Pairs written with `FLAG_LE` set.
    pub pairs_le: usize,
    /// Pairs written with `FLAG_BE` set.
    pub pairs_be: usize,
    /// Maximum `rc_gap_magnitude` seen across all written pairs.
    pub rc_gap_max: u64,

    /// Hash lines written, keyed by `HashType` (the 11-row taxonomy in
    /// `ARCHITECTURE.md §2`). Counted once per logical hash regardless of how many
    /// sinks it was fanned out to. Merged into `Stats::hash_type_emitted` after
    /// `run_output` returns.
    pub hash_type_emitted: std::collections::HashMap<HashType, u64>,

    /// Hash lines emitted with an empty SSID because `essid_map` had no entry for
    /// the AP. Surfaces the residual hidden-SSID gap after Beacon, Probe Response,
    /// `AssocReq` / `ReassocReq`, directed Probe Request, and MLD canonicalization
    /// have all run. A non-zero count means hashcat will not be able to crack
    /// those lines (PMK derivation requires the SSID).
    pub essid_unresolved_emissions: u64,
    /// Distinct AP MACs that triggered at least one `essid_unresolved_emissions`.
    /// Lower bound on the number of "truly hidden" APs in the capture.
    pub essid_unresolved_aps: u64,
}

impl OutputStats {
    /// Lines written to a given sink, or 0 if unconfigured / out of range.
    #[must_use]
    pub fn lines(&self, sink: SinkId) -> u64 {
        self.lines_per_sink.get(sink.as_index()).copied().unwrap_or(0)
    }

    /// Dedup-dropped lines for a given sink, or 0 if unconfigured / out of range.
    #[must_use]
    pub fn dropped(&self, sink: SinkId) -> u64 {
        self.dropped_per_sink.get(sink.as_index()).copied().unwrap_or(0)
    }
}

// --- HashSinks ---

/// One `BufWriter<File>` per configured sink. Unconfigured sinks hold `None`.
struct HashSinks {
    writers: [Option<BufWriter<std::fs::File>>; SinkId::COUNT],
}

impl HashSinks {
    /// Opens a writer for every configured path. Order of array slots matches `SinkId`.
    fn open(paths: &OutputPaths) -> Result<Self> {
        let writers = [
            open_writer(paths.out_22000.as_deref())?,
            open_writer(paths.out_37100.as_deref())?,
            open_writer(paths.out_combined.as_deref())?,
            open_writer(paths.out_wpa1.as_deref())?,
            open_writer(paths.out_wpa2.as_deref())?,
            open_writer(paths.out_psk_sha256.as_deref())?,
            open_writer(paths.out_ft.as_deref())?,
            open_writer(paths.out_psk_sha384.as_deref())?,
            open_writer(paths.out_ft_psk_sha384.as_deref())?,
        ];
        Ok(Self { writers })
    }

    /// Returns `true` if any sink has a configured writer.
    fn any_configured(&self) -> bool {
        self.writers.iter().any(Option::is_some)
    }

    /// Flushes every configured writer. Called after each pipeline finishes.
    fn flush_all(&mut self) -> Result<()> {
        for w in self.writers.iter_mut().flatten() {
            w.flush()?;
        }
        Ok(())
    }
}

/// Returns the per-AKM-family taxonomy sink that accepts a given `HashType`, if any.
const fn taxonomy_sink_for(ht: HashType) -> SinkId {
    match ht {
        HashType::Wpa1Eapol => SinkId::OutWpa1,
        HashType::Wpa2PskPmkid | HashType::Wpa2PskEapol => SinkId::OutWpa2,
        HashType::PskSha256Pmkid | HashType::PskSha256Eapol => SinkId::OutPskSha256,
        HashType::FtPskPmkid | HashType::FtPskEapol => SinkId::OutFt,
        HashType::PskSha384Pmkid | HashType::PskSha384Eapol => SinkId::OutPskSha384,
        HashType::FtPskSha384Pmkid | HashType::FtPskSha384Eapol => SinkId::OutFtPskSha384,
    }
}

/// Returns the legacy sink (`Out22000` / `Out37100`) for a given `HashType`,
/// or `None` for hash types whose wire shape hashcat's legacy kernels cannot
/// parse.
///
/// SHA-384 personal (types 8/9) and SHA-384 FT (types 10/11) carry a 24-byte
/// HMAC-SHA384-192 MIC and a SHA-384 PMKID derivation. hashcat's mode 22000
/// kernel rejects any line whose MIC field is not exactly 16 bytes
/// (`[hashcat module_22000.c:check_token]`), and mode 37100 only ships a
/// SHA-256 FT key-hierarchy kernel -- so writing those lines into the legacy
/// sinks generates `Token length exception` parse errors at hashcat startup
/// and pollutes the input file. The dedicated taxonomy sinks
/// (`--psk-sha384-out` / `--ft-psk-sha384-out`) and the combined `-o` sink
/// continue to receive these lines under their `WPA*08*..*11*` prefixes,
/// where downstream tooling can recognise the wider MIC width.
const fn legacy_sink_for(ht: HashType) -> Option<SinkId> {
    match ht {
        // SHA-384 family: skip legacy sinks (no compatible hashcat kernel).
        HashType::PskSha384Pmkid
        | HashType::PskSha384Eapol
        | HashType::FtPskSha384Pmkid
        | HashType::FtPskSha384Eapol => None,
        // FT-PSK-SHA-256 (types 6/7) -> mode 37100.
        HashType::FtPskPmkid | HashType::FtPskEapol => Some(SinkId::Out37100),
        // Everything else (WPA1 / WPA2 / PSK-SHA-256) -> mode 22000.
        HashType::Wpa1Eapol
        | HashType::Wpa2PskPmkid
        | HashType::Wpa2PskEapol
        | HashType::PskSha256Pmkid
        | HashType::PskSha256Eapol => Some(SinkId::Out22000),
    }
}

// --- Fan-out item ---

/// Renders a 6-byte AP MAC as a 12-char lowercase hex string for `[essid_not_found]`
/// log lines. Same encoding hashcat expects for the AP field in 22000/37100 lines.
fn format_mac_hex(mac: crate::types::MacAddr) -> String {
    let b = mac.0;
    format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
}

/// Closure-free input to `fan_out`. Borrows of `entry`/`pair`/`ft`/`essid` keep the
/// per-sink line construction allocation-bounded (the caller does not pre-build any
/// line; the writer constructs only the prefixes that are actually written to a
/// configured sink).
#[derive(Clone, Copy)]
enum FanItem<'a> {
    Pmkid { entry: &'a PmkidEntry, ft: Option<&'a FtFields>, essid: &'a [u8] },
    Eapol { pair: &'a PairedHash, ft: Option<&'a FtFields>, essid: &'a [u8] },
}

/// Builds the line text for a given `(item, sink, ht)` triple.
///
/// Legacy sinks use `ht.legacy_prefix()` plus -- for FT lines -- the FT-extra-field
/// formatter. Taxonomy sinks use `ht.taxonomy_prefix()`. PMKID rows of FT types route
/// through the FT formatter to keep MDID+R0KH+R1KH appended. Non-FT rows route through
/// the plain PMKID/EAPOL formatter.
fn build_line(item: &FanItem<'_>, sink: SinkId, ht: HashType) -> String {
    let prefix: &[u8] =
        if matches!(sink, SinkId::Out22000 | SinkId::Out37100) { ht.legacy_prefix().0 } else { ht.taxonomy_prefix() };
    match *item {
        FanItem::Pmkid { entry, ft, essid } => ft.map_or_else(
            || format_pmkid_line(prefix, entry, essid),
            |ft| format_pmkid_ft_line(prefix, entry, ft, essid),
        ),
        FanItem::Eapol { pair, ft, essid } => ft
            .map_or_else(|| format_eapol_line(prefix, pair, essid), |ft| format_eapol_ft_line(prefix, pair, ft, essid)),
    }
}

/// Fans one classified hash out to every configured sink that accepts it.
///
/// Returns `true` if at least one sink wrote the line (i.e. at least one sink was
/// configured AND its dedup accepted the fingerprint). The caller increments the
/// `pmkids_written` / `pairs_written` logical counter exactly when this returns
/// `true`. Per-sink line and dedup counters are bumped inside.
fn fan_out(
    sinks: &mut HashSinks,
    dedup: &mut PerSinkDedup,
    stats: &mut OutputStats,
    ht: HashType,
    item: FanItem<'_>,
) -> Result<bool> {
    // Each candidate sink: legacy (skipped for SHA-384) + per-AKM-family + combined.
    let candidates: [Option<SinkId>; 3] = [legacy_sink_for(ht), Some(taxonomy_sink_for(ht)), Some(SinkId::OutCombined)];
    let mut any_written = false;
    for sink in candidates.into_iter().flatten() {
        let idx = sink.as_index();
        let Some(slot) = sinks.writers.get_mut(idx) else { continue };
        let Some(writer) = slot.as_mut() else { continue };
        let accepted = match item {
            FanItem::Pmkid { entry, essid, .. } => dedup.check_pmkid(sink, entry, essid),
            FanItem::Eapol { pair, essid, .. } => dedup.check_eapol(sink, pair, essid),
        };
        if accepted {
            let line = build_line(&item, sink, ht);
            writeln!(writer, "{line}")?;
            if let Some(c) = stats.lines_per_sink.get_mut(idx) {
                *c += 1;
            }
            any_written = true;
        } else if let Some(c) = stats.dropped_per_sink.get_mut(idx) {
            *c += 1;
        }
    }
    Ok(any_written)
}

// --- run_output ---

/// Runs the full output pipeline.
///
/// Invariant OUT-1 (`ARCHITECTURE.md §7`): PMKIDs are emitted completely before
/// EAPOL pairs begin. The two pipelines share only the dedup filter and ESSID map.
///
/// For each PMKID and EAPOL pair:
/// 1. Resolves the ESSID from `essid_map` using the entry's AP MAC.
/// 2. Classifies the hash via `HashType::from_akm_and_attack`.
/// 3. Fans out to every configured sink with the appropriate per-sink prefix and
///    per-sink dedup (`HashSinks::fan_out`).
///
/// Returns `OutputStats` with counts of written and deduplicated lines.
///
/// # Errors
///
/// Returns `Err` on I/O failure.
#[allow(clippy::too_many_lines, reason = "linear pipeline orchestrator")]
#[allow(clippy::too_many_arguments, reason = "Phase 4 entry point owns every store + the structured logger")]
pub fn run_output(
    message_store: &MessageStore,
    pmkid_store: &PmkidStore,
    essid_map: &crate::store::essid::EssidMap,
    essid_set: &EssidSet,
    probe_essid_set: &ProbeEssidSet,
    wordlist_store: &WordlistStore,
    identity_set: &IdentitySet,
    username_set: &UsernameSet,
    device_store: &DeviceInfoStore,
    akm_map: &AkmMap,
    pair_config: &PairConfig,
    paths: &OutputPaths,
    thread_count: usize,
    logger: &mut Logger,
) -> Result<OutputStats> {
    let mut stats = OutputStats::default();
    let mut dedup = PerSinkDedup::new();
    let mut sinks = HashSinks::open(paths)?;
    let any_sink = sinks.any_configured();
    // Track distinct AP MACs that emit with no SSID. Sized at zero by default; a
    // capture with full SSID coverage never allocates beyond the empty set's
    // header. Counted into `stats.essid_unresolved_aps` once both pipelines
    // finish so the summary reflects pre-dedup unique-AP count.
    let mut unresolved_aps: std::collections::HashSet<crate::types::MacAddr> = std::collections::HashSet::new();

    // --- Pipeline 1: PMKIDs (Invariant OUT-1 -- always before EAPOL pairs) ---
    //
    // Emit one hash line per observed SSID for the AP. Most APs have exactly one SSID,
    // so this loop body executes once. When an AP advertised multiple SSIDs during the
    // capture (e.g. a multi-SSID device), each variant needs to be cracked independently
    // because the PMK is derived from PSK+SSID -- a different SSID is a different PMK.
    if any_sink {
        for entry in pmkid_store.iter() {
            // Per-source extractors may store entry.akm = Unknown when the
            // extraction site has no AKM context (e.g. AMPE element in a Mesh
            // Peering action frame, OSEN IE in an Association Request). When
            // the BSS still advertises a PSK AKM in its Beacon, fall back on
            // akm_map.get_best so the PMKID is still crackable. Without this
            // fallback the PMKID parses successfully and counts in stats but
            // never emits a hashcat line -- silent loss for the operator.
            let resolved_akm =
                if matches!(entry.akm, AkmType::Unknown) || HashType::from_akm_and_attack(entry.akm, true).is_none() {
                    let inferred = akm_map.get_best(&entry.ap, &entry.sta);
                    if matches!(inferred, AkmType::Unknown) { entry.akm } else { inferred }
                } else {
                    entry.akm
                };
            let Some(ht) = HashType::from_akm_and_attack(resolved_akm, true) else { continue };
            let ssids = essid_map.all_for_ap(&entry.ap);
            let is_ft = ht.is_ft();

            // For FT-PSK PMKIDs, only write when we have complete FT context (R0KH-ID required).
            // hashcat mode 37100 requires MDID + R0KH-ID + R1KH-ID to crack the PMK chain.
            // [hcxpcapngtool:2541] condition: mdidlen!=0 && r0khidlen!=0 && r1khidlen!=0
            let ft_ctx: Option<&FtFields> = if is_ft {
                match entry.ft.as_ref().filter(|ft| ft.r0khid_len > 0) {
                    Some(ft) => Some(ft),
                    None => continue, // FT-PSK PMKID without FT context -- not crackable
                }
            } else {
                None
            };

            // An empty `ssids` slice means we never observed a beacon / probe-resp / assoc
            // for this AP, so the hash line ships with a NULL ESSID. Only credit the
            // counter to a *line that actually shipped*: a dedup-dropped line must not
            // be billed as an unresolved emission.
            let (essid_list, is_unresolved): (Vec<&[u8]>, bool) = if ssids.is_empty() {
                (vec![&[]], true)
            } else {
                (ssids.iter().map(|e| e.essid.as_slice()).collect(), false)
            };

            for essid in essid_list {
                let item = FanItem::Pmkid { entry, ft: ft_ctx, essid };
                let written = fan_out(&mut sinks, &mut dedup, &mut stats, ht, item)?;
                if written {
                    stats.pmkids_written += 1;
                    *stats.hash_type_emitted.entry(ht).or_insert(0) += 1;
                    if is_unresolved {
                        logger.log_essid_not_found(&format_mac_hex(entry.ap));
                        stats.essid_unresolved_emissions += 1;
                        unresolved_aps.insert(entry.ap);
                    }
                } else {
                    stats.dedup_dropped += 1;
                }
            }
        }
    }

    // --- Pipeline 2: EAPOL pairs ---
    //
    // Same multi-SSID logic as Pipeline 1. The ESSID is part of the EAPOL hash line
    // (hashcat uses it to derive the PMK), so each unique SSID observed for the AP
    // must produce a separate hash line. Dedup fingerprints include the ESSID field,
    // so identical (pair + SSID) combinations are still deduplicated correctly.
    let all_pairs = pair_all_groups(message_store, pair_config, thread_count);
    if any_sink {
        for pair in &all_pairs {
            let Some(ht) = HashType::from_akm_and_attack(pair.akm, false) else { continue };
            let ssids = essid_map.all_for_ap(&pair.ap);
            let is_ft = ht.is_ft();

            // For FT-PSK EAPOL pairs, only write when FT context is present (R0KH-ID required).
            // [hcxpcapngtool:2351] condition: mdidlen!=0 && r0khidlen!=0 && r1khidlen!=0
            let ft_ctx: Option<&FtFields> = if is_ft {
                match pair.ft.as_ref().filter(|ft| ft.r0khid_len > 0) {
                    Some(ft) => Some(ft),
                    None => continue, // FT-PSK pair without FT context -- not crackable
                }
            } else {
                None
            };

            // See pipeline 1 comment: bill `essid_unresolved_emissions` only to lines
            // that actually shipped, not to dedup-dropped duplicates.
            let (essid_list, is_unresolved): (Vec<&[u8]>, bool) = if ssids.is_empty() {
                (vec![&[]], true)
            } else {
                (ssids.iter().map(|e| e.essid.as_slice()).collect(), false)
            };

            for essid in essid_list {
                let item = FanItem::Eapol { pair, ft: ft_ctx, essid };
                let written = fan_out(&mut sinks, &mut dedup, &mut stats, ht, item)?;
                if written {
                    stats.pairs_written += 1;
                    *stats.hash_type_emitted.entry(ht).or_insert(0) += 1;
                    if is_unresolved {
                        logger.log_essid_not_found(&format_mac_hex(pair.ap));
                        stats.essid_unresolved_emissions += 1;
                        unresolved_aps.insert(pair.ap);
                    }

                    // Per-combo / flag counters for the stats summary, bumped once per
                    // logical pair that survived at least one sink's dedup.
                    match pair.combo_type {
                        ComboType::N1E2 => stats.n1e2 += 1,
                        ComboType::N3E2 => stats.n3e2 += 1,
                        ComboType::N1E4 => stats.n1e4 += 1,
                        ComboType::N2E3 => stats.n2e3 += 1,
                        ComboType::N4E3 => stats.n4e3 += 1,
                        ComboType::N3E4 => stats.n3e4 += 1,
                    }
                    if pair.message_pair & FLAG_NC != 0 {
                        stats.pairs_nc += 1;
                    }
                    if pair.message_pair & FLAG_LE != 0 {
                        stats.pairs_le += 1;
                    }
                    if pair.message_pair & FLAG_BE != 0 {
                        stats.pairs_be += 1;
                    }
                    stats.rc_gap_max = stats.rc_gap_max.max(pair.rc_gap_magnitude);
                } else {
                    stats.dedup_dropped += 1;
                }
            }
        }
    }

    // Flush hash writers before opening auxiliary outputs.
    sinks.flush_all()?;

    // --- Auxiliary outputs ---

    if let Some(path) = &paths.essid_list {
        let mut f = BufWriter::new(std::fs::File::create(path)?);
        write_essid_list(essid_set, &mut f)?;
    }
    if let Some(path) = &paths.probe_essid_list {
        let mut f = BufWriter::new(std::fs::File::create(path)?);
        write_probe_essid_list(probe_essid_set, &mut f)?;
    }
    if let Some(path) = &paths.wordlist {
        let mut f = BufWriter::new(std::fs::File::create(path)?);
        write_wordlist(wordlist_store, &mut f)?;
    }
    if let Some(path) = &paths.identity_list {
        let mut f = BufWriter::new(std::fs::File::create(path)?);
        write_identities(identity_set, &mut f)?;
    }
    if let Some(path) = &paths.username_list {
        let mut f = BufWriter::new(std::fs::File::create(path)?);
        write_usernames(username_set, &mut f)?;
    }
    if let Some(path) = &paths.device_info {
        let mut f = BufWriter::new(std::fs::File::create(path)?);
        write_device_info(device_store, &mut f)?;
    }

    stats.essid_unresolved_aps = unresolved_aps.len() as u64;

    Ok(stats)
}

// --- Internal helpers ---

/// Opens a `BufWriter<std::fs::File>` at `path`, or returns `None` if path is `None`.
///
/// `BufWriter` reduces syscall count by batching small writes into 8 KiB chunks.
/// The file is truncated on open (standard `File::create` semantics).
fn open_writer(path: Option<&Path>) -> Result<Option<BufWriter<std::fs::File>>> {
    match path {
        Some(p) => Ok(Some(BufWriter::new(std::fs::File::create(p)?))),
        None => Ok(None),
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
    use crate::store::auxiliary::{DeviceInfoStore, EssidSet, IdentitySet, ProbeEssidSet, UsernameSet, WordlistStore};
    use crate::store::essid::EssidMap;
    use crate::store::messages::MessageStore;
    use crate::store::pmkid::PmkidStore;

    #[test]
    fn run_output_empty_stores() {
        // All stores empty, no paths set -> no writes, all counts zero, returns Ok.
        let msg_store = MessageStore::new();
        let pmkid_store = PmkidStore::new();
        let essid_map = EssidMap::new();
        let essid_set = EssidSet::new();
        let probe_essid_set = ProbeEssidSet::new();
        let wordlist_store = WordlistStore::new();
        let identity_set = IdentitySet::new();
        let username_set = UsernameSet::new();
        let device_store = DeviceInfoStore::new();
        let akm_map = AkmMap::new();
        let pair_config = PairConfig::default();
        let paths = OutputPaths::default();
        let mut logger = Logger::new(None).unwrap();

        let stats = run_output(
            &msg_store,
            &pmkid_store,
            &essid_map,
            &essid_set,
            &probe_essid_set,
            &wordlist_store,
            &identity_set,
            &username_set,
            &device_store,
            &akm_map,
            &pair_config,
            &paths,
            1,
            &mut logger,
        )
        .unwrap();

        assert_eq!(stats, OutputStats::default());
    }

    #[test]
    fn taxonomy_sink_routes_match_hash_type_family() {
        for ht in HashType::all() {
            let sink = taxonomy_sink_for(ht);
            let expected = match ht.type_code() {
                1 => SinkId::OutWpa1,
                2 | 3 => SinkId::OutWpa2,
                4 | 5 => SinkId::OutPskSha256,
                6 | 7 => SinkId::OutFt,
                8 | 9 => SinkId::OutPskSha384,
                10 | 11 => SinkId::OutFtPskSha384,
                _ => unreachable!(),
            };
            assert_eq!(sink, expected, "{}", ht.name());
        }
    }

    #[test]
    fn legacy_sink_routes_match_is_ft() {
        // SHA-384 hash types (8/9/10/11) skip the legacy sinks because hashcat's
        // mode 22000 / 37100 kernels reject the 24-byte HMAC-SHA384-192 MIC at
        // the parser; see `legacy_sink_for` doc.
        for ht in HashType::all() {
            let expected = match ht {
                HashType::PskSha384Pmkid
                | HashType::PskSha384Eapol
                | HashType::FtPskSha384Pmkid
                | HashType::FtPskSha384Eapol => None,
                _ if ht.is_ft() => Some(SinkId::Out37100),
                _ => Some(SinkId::Out22000),
            };
            assert_eq!(legacy_sink_for(ht), expected, "{}", ht.name());
        }
    }
}
