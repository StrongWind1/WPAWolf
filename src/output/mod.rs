//! Phase 4 -- Emit: output coordination (PMKID pipeline + EAPOL pair pipeline run independently). See ARCHITECTURE.md §3.4 + §7.
//!
//! Opens every configured hash sink (`-o` combined plus per-type sinks `--wpa1-eapol`,
//! `--wpa2-pmkid`, `--wpa2-eapol`, `--sha256-pmkid`, `--sha256-eapol`, `--ft-pmkid`,
//! `--ft-eapol`) and the auxiliary wordlists. All sinks emit hashcat mode 22000 format
//! (types 01-04). Every emitted hash is fanned out to the combined sink plus the
//! matching per-type sink, with per-sink dedup. The PMKID and EAPOL pipelines run to
//! completion independently (Invariant OUT-1 in `ARCHITECTURE.md §7`).

pub mod dedup;
pub mod device_info;
pub mod disk_dedup;
pub mod hashcat;
pub mod wordlists;

use std::collections::{HashMap, HashSet};
use std::io::{BufWriter, Write as _};
use std::path::{Path, PathBuf};

/// Buffer capacity for all output `BufWriter`s (hash sinks + auxiliary files).
///
/// The default 8 KiB causes ~160k write syscalls per 1.3 GB output file. 64 KiB
/// reduces that by 8x, cutting kernel overhead (`clear_page_rep`, `try_charge_memcg`,
/// `rep_movs`) visible in the perf profile.
const OUTPUT_BUF_CAPACITY: usize = 64 * 1024;

use crate::debug::{DebugPrinter, emit_progress_interval};
use crate::log::Logger;
use crate::pair::combos::PairConfig;
use crate::pair::{ComboType, FLAG_BE, FLAG_LE, FLAG_NC, PairedHash};
use crate::store::AkmMap;
use crate::store::auxiliary::{
    DeviceInfoStore, EssidSet, IdentitySet, ProbeEssidSet, UsernameSet, WordlistScanIesStore, WordlistStore,
};
use crate::store::messages::{EapolMessage, MessageStore};
use crate::store::pmkid::{PmkidEntry, PmkidStore};
use crate::types::{AkmType, FtFields, HashType, MacPair, Result};

use self::dedup::{PerSinkDedup, SinkId};
use self::device_info::write_device_info;
use self::hashcat::{format_eapol_body, format_eapol_ft_body, format_pmkid_ft_line, format_pmkid_line};
use self::wordlists::{
    write_essid_list, write_identities, write_probe_essid_list, write_usernames, write_wordlist, write_wordlist_scan,
};

// --- EssidFilterConfig ---

/// Tunables for the multi-ESSID inflation filter applied at hash emit time.
///
/// See `EssidMap::ssids_for_emit` for the full algorithm. Both fields originate
/// in CLI flags (`--essid-collapse-min`, `--essid-collapse-ratio`) with defaults
/// that pass through ~99.98% of hash-producing APs untouched and only collapse
/// the small set of RF-corrupted APs that produce 4+ bit-flipped SSID variants
/// of the same real broadcast.
#[derive(Debug, Clone, Copy)]
pub struct EssidFilterConfig {
    /// Filter only triggers on APs whose `EssidMap` fanout strictly exceeds this
    /// value. Default 3 -- preserves singleton-SSID APs (small captures with
    /// 1 beacon + a handshake), 2-SSID dual-band routers, and 3-SSID setups.
    pub collapse_min: usize,
    /// Primary SSID's observation count must be at least this many times the
    /// second-most-frequent SSID's count to trigger the collapse to primary-only.
    /// Default 10. A value below 2 disables the filter (every recorded SSID is
    /// emitted, matching pre-filter behaviour).
    pub collapse_ratio: u64,
}

impl Default for EssidFilterConfig {
    fn default() -> Self {
        Self { collapse_min: 3, collapse_ratio: 10 }
    }
}

// --- OutputPaths ---

/// Paths for all optional output files.
///
/// `None` means the corresponding output was not requested by the user on the CLI.
/// All fields are optional so the caller can enable any subset of outputs.
#[derive(Debug, Default)]
pub struct OutputPaths {
    /// `-o`/`--out` -- combined output (all crackable types 1-7, mode 22000 format).
    pub out_combined: Option<PathBuf>,
    /// `--wpa1-eapol` -- type 1 only.
    pub out_wpa1_eapol: Option<PathBuf>,
    /// `--wpa2-pmkid` -- type 2 only.
    pub out_wpa2_pmkid: Option<PathBuf>,
    /// `--wpa2-eapol` -- type 3 only.
    pub out_wpa2_eapol: Option<PathBuf>,
    /// `--sha256-pmkid` -- type 4 only.
    pub out_sha256_pmkid: Option<PathBuf>,
    /// `--sha256-eapol` -- type 5 only.
    pub out_sha256_eapol: Option<PathBuf>,
    /// `--ft-pmkid` -- type 6 only (FT extras appended).
    pub out_ft_pmkid: Option<PathBuf>,
    /// `--ft-eapol` -- type 7 only (FT extras appended).
    pub out_ft_eapol: Option<PathBuf>,
    /// Path for ESSID list output (`-E`): AP-advertised ESSIDs.
    pub essid_list: Option<PathBuf>,
    /// Path for Probe Request ESSID list output (`-R`): client-requested ESSIDs.
    pub probe_essid_list: Option<PathBuf>,
    /// Path for leaked-information wordlist output (`-W`).
    pub wordlist: Option<PathBuf>,
    /// Path for `--wordlist-scan FILE` -- IE-scan entries minus everything
    /// already in `-E` / `-R` / `-W`.
    pub wordlist_scan: Option<PathBuf>,
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
    /// Logical EAPOL pairs suppressed by every configured sink's dedup.
    pub dedup_dropped_pairs: usize,
    /// Logical PMKID hashes suppressed by every configured sink's dedup.
    pub dedup_dropped_pmkids: usize,
    /// Hashes dropped at emit because the AKM could not be mapped to one of the
    /// 11 types (`HashType::from_akm_and_attack` returned None) and the AKM was not a
    /// recognised non-PSK suite (i.e. a genuinely unclassifiable / `Unknown` case).
    pub emit_dropped_unclassified_akm: usize,
    /// Handshakes / PMKIDs dropped at emit because the AKM is a recognised non-PSK suite
    /// (`AkmType::NotPsk`: enterprise 802.1X / SAE / OWE / FILS / PASN). Out of v1 scope;
    /// no crackable PSK line exists. Split out from `emit_dropped_unclassified_akm` so the
    /// expected enterprise volume does not mask genuine anomalies.
    pub emit_dropped_notpsk_akm: usize,
    /// FT hashes dropped at emit because the FT context (R0KH-ID) was missing.
    pub emit_dropped_ft_no_context: usize,
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
    /// Lines collapsed by NC-dedup across all (AP, STA) groups. Equal to
    /// `NcDedupStats::collapsed_lines` summed during `pair_all_groups`.
    pub nc_dedup_collapsed_lines: u64,
    /// Number of NC-dedup clusters with at least two members. Equal to
    /// `NcDedupStats::cluster_count` summed during `pair_all_groups`.
    pub nc_dedup_cluster_count: u64,
    /// Largest single NC-dedup cluster observed. Equal to
    /// `NcDedupStats::max_cluster_size` across `pair_all_groups`.
    pub nc_dedup_max_cluster_size: u64,
    /// Candidate pairs dropped by the `--eapoltimeout` filter, summed across all
    /// groups (`NcDedupStats::time_filtered`). Zero in WIDE mode.
    pub pairs_time_filtered: u64,
    /// Candidate pairs dropped by the `--rc-drift` filter, summed across all
    /// groups (`NcDedupStats::rc_filtered`). Zero in WIDE mode.
    pub pairs_rc_filtered: u64,
    /// Messages excluded from pairing by the `--max-eapol-per-type` cap, summed
    /// across all groups (`NcDedupStats::messages_capped`). Zero when off.
    pub messages_capped: u64,
    /// `--smart` distinct handshake instances across multi-instance groups.
    pub smart_instances_attributed: u64,
    /// `--smart` candidate pairs pruned as provably uncrackable (cross-instance).
    pub smart_uncrackable_dropped: u64,
    /// `--smart` MIC-frames kept against all candidates (no unique RC link).
    pub smart_ambiguous_kept: u64,
    /// `--smart` FT MIC-frames retaining a non-APLESS survivor (clause F).
    pub smart_ft_nonapless_kept: u64,
    /// Groups where all four EAPOL message types (M1+M2+M3+M4) were present.
    pub groups_complete_4way: u64,
    /// Maximum `rc_gap_magnitude` seen across all written pairs.
    pub rc_gap_max: u64,

    /// EAPOL hash lines emitted where the frame exceeds hashcat's
    /// `WPA_EAPOL_LEN_MAX` (512 bytes). The line is still written -- this is
    /// informational so the operator knows how many lines hashcat will reject.
    pub eapol_exceeds_hashcat_max: u64,
    /// Largest number of pairs emitted from a single (AP, STA) group.
    pub max_pairs_per_group: u64,
    /// Groups that produced at least one crackable EAPOL pair.
    pub groups_with_pairs: usize,
    /// Groups that produced zero crackable EAPOL pairs.
    pub groups_without_pairs: usize,

    /// Hash lines written, keyed by `HashType` (the 11-type classification in
    /// `ARCHITECTURE.md §2`). Counted once per logical hash regardless of how many
    /// sinks it was fanned out to. Merged into `Stats::hash_type_emitted` after
    /// `run_output` returns.
    pub hash_type_emitted: HashMap<HashType, u64>,

    /// Unique crackable hashes *found* in the capture, keyed by `HashType`,
    /// counted independently of which output sinks are configured. A hash whose
    /// sinks are unconfigured (e.g. the SHA-384 family, which has no sinks) is
    /// absent from `hash_type_emitted` but still counted here, so the banner
    /// reports the full 11-type inventory of the capture's content. Deduped via
    /// `found_dedup` in memory mode; pre-dedup (write-through) in disk mode,
    /// matching `hash_type_emitted`.
    pub hash_type_found: HashMap<HashType, u64>,

    /// Hash lines emitted with an empty SSID because `essid_map` had no entry for
    /// the AP. Surfaces the residual hidden-SSID gap after Beacon, Probe Response,
    /// `AssocReq` / `ReassocReq`, directed Probe Request, and MLD canonicalization
    /// have all run. A non-zero count means hashcat will not be able to crack
    /// those lines (PMK derivation requires the SSID).
    pub essid_unresolved_emissions: u64,
    /// Distinct AP MACs that triggered at least one `essid_unresolved_emissions`.
    /// Lower bound on the number of "truly hidden" APs in the capture.
    pub essid_unresolved_aps: u64,

    // --- auxiliary sink entry counts (filled by `finalize`) ---
    /// Entries written to the `-E` ESSID list.
    pub entries_essid: usize,
    /// Entries written to the `-R` probe-ESSID list.
    pub entries_probe: usize,
    /// Entries written to the `-W` combined wordlist.
    pub entries_wordlist: usize,
    /// Entries written to the `--wordlist-scan` IE-scan wordlist.
    pub entries_wordlist_scan: usize,
    /// Entries written to the `-I` identity list.
    pub entries_identity: usize,
    /// Entries written to the `-U` username list.
    pub entries_username: usize,
    /// Entries written to the `-D` device-info table.
    pub entries_device: usize,
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

/// A configured hash sink with deferred file creation.
///
/// `path` is set at construction time, but no `File` is opened until the first
/// write. Sinks that never receive a hash line therefore never call
/// `File::create`, and an empty file is never left on disk.
struct LazySink {
    path: PathBuf,
    writer: Option<BufWriter<std::fs::File>>,
}

impl LazySink {
    /// Returns a writable handle, creating (and truncating) the file on first call.
    fn writer(&mut self) -> Result<&mut BufWriter<std::fs::File>> {
        if self.writer.is_none() {
            let file = std::fs::File::create(&self.path)
                .map_err(|e| crate::types::Error::io(e, self.path.clone(), "create hash sink"))?;
            self.writer = Some(BufWriter::with_capacity(OUTPUT_BUF_CAPACITY, file));
        }
        // The branch above guarantees Some.
        Ok(self.writer.as_mut().unwrap_or_else(|| unreachable!()))
    }

    /// Flushes the underlying writer if it has been opened.
    fn flush(&mut self) -> Result<()> {
        if let Some(w) = self.writer.as_mut() {
            w.flush()?;
        }
        Ok(())
    }
}

/// One `LazySink` per configured sink. Unconfigured sinks hold `None`.
struct HashSinks {
    sinks: [Option<LazySink>; SinkId::COUNT],
}

impl HashSinks {
    /// Records the configured path for every sink without opening any file.
    /// File creation is deferred to the first write per sink (see `LazySink`).
    fn open(paths: &OutputPaths) -> Self {
        let lazy = |p: Option<&Path>| p.map(|p| LazySink { path: p.to_path_buf(), writer: None });
        let sinks = [
            lazy(paths.out_combined.as_deref()),
            lazy(paths.out_wpa1_eapol.as_deref()),
            lazy(paths.out_wpa2_pmkid.as_deref()),
            lazy(paths.out_wpa2_eapol.as_deref()),
            lazy(paths.out_sha256_pmkid.as_deref()),
            lazy(paths.out_sha256_eapol.as_deref()),
            lazy(paths.out_ft_pmkid.as_deref()),
            lazy(paths.out_ft_eapol.as_deref()),
        ];
        Self { sinks }
    }

    /// Returns `true` if any sink has a configured path.
    fn any_configured(&self) -> bool {
        self.sinks.iter().any(Option::is_some)
    }

    /// Returns a boolean mask of which sinks have a configured path.
    fn active_mask(&self) -> [bool; SinkId::COUNT] {
        let mut mask = [false; SinkId::COUNT];
        for (i, s) in self.sinks.iter().enumerate() {
            if let Some(m) = mask.get_mut(i) {
                *m = s.is_some();
            }
        }
        mask
    }

    /// Flushes every sink whose file has actually been created.
    fn flush_all(&mut self) -> Result<()> {
        for s in self.sinks.iter_mut().flatten() {
            s.flush()?;
        }
        Ok(())
    }

    /// Returns the output path for a given sink, if configured.
    fn path(&self, sink: SinkId) -> Option<PathBuf> {
        self.sinks.get(sink.as_index()).and_then(Option::as_ref).map(|s| s.path.clone())
    }
}

/// Returns the per-type sink for a given `HashType`, or `None` for types 8-11
/// (SHA-384 family: classified and counted but not emitted -- the 24 B MIC
/// cannot fit mode 22000's 16 B field).
const fn per_type_sink_for(ht: HashType) -> Option<SinkId> {
    match ht {
        HashType::Wpa1Eapol => Some(SinkId::OutWpa1Eapol),
        HashType::Wpa2PskPmkid => Some(SinkId::OutWpa2Pmkid),
        HashType::Wpa2PskEapol => Some(SinkId::OutWpa2Eapol),
        HashType::PskSha256Pmkid => Some(SinkId::OutSha256Pmkid),
        HashType::PskSha256Eapol => Some(SinkId::OutSha256Eapol),
        HashType::FtPskPmkid => Some(SinkId::OutFtPmkid),
        HashType::FtPskEapol => Some(SinkId::OutFtEapol),
        HashType::PskSha384Pmkid
        | HashType::PskSha384Eapol
        | HashType::FtPskSha384Pmkid
        | HashType::FtPskSha384Eapol => None,
    }
}

// --- Fan-out item ---

/// Renders a 6-byte AP MAC as a 12-char lowercase hex string for `[essid_not_found]`
/// log lines. Same encoding hashcat expects for the AP field in mode 22000 lines.
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

/// Builds a PMKID line for a given `(entry, ft, essid, ht)`.
fn build_pmkid_line(entry: &PmkidEntry, ft: Option<&FtFields>, essid: &[u8], ht: HashType) -> String {
    let prefix = ht.prefix().0;
    ft.map_or_else(|| format_pmkid_line(prefix, entry, essid), |ft| format_pmkid_ft_line(prefix, entry, ft, essid))
}

/// Fans one classified hash out to every configured sink that accepts it.
///
/// Returns `true` if at least one sink wrote the line (i.e. at least one sink was
/// configured AND its dedup accepted the fingerprint). The caller increments the
/// `pmkids_written` / `pairs_written` logical counter exactly when this returns
/// `true`. Per-sink line and dedup counters are bumped inside.
///
/// For EAPOL items, the hex body (everything after the 7-byte prefix) is built once
/// and reused across both sinks. This avoids redundant EAPOL-frame hex encoding and
/// MIC-zeroing clones.
fn fan_out(
    sinks: &mut HashSinks,
    dedup: &mut PerSinkDedup,
    dd: &mut Option<disk_dedup::DiskDedup>,
    stats: &mut OutputStats,
    ht: HashType,
    item: FanItem<'_>,
) -> Result<bool> {
    let combined = if ht.hashcat_mode().is_some() { Some(SinkId::OutCombined) } else { None };
    let candidates: [Option<SinkId>; 2] = [combined, per_type_sink_for(ht)];
    let disk_mode = dd.is_some();
    let prefix = ht.prefix().0;

    // Pre-build the EAPOL body once (prefix-independent) if any sink will accept it.
    let eapol_body: Option<Vec<u8>> = match item {
        FanItem::Eapol { pair, ft, essid } => {
            let any_configured = candidates.iter().flatten().any(|&sink| {
                let idx = sink.as_index();
                sinks.sinks.get(idx).and_then(Option::as_ref).is_some()
            });
            if any_configured {
                Some(ft.map_or_else(|| format_eapol_body(pair, essid), |ft| format_eapol_ft_body(pair, ft, essid)))
            } else {
                None
            }
        },
        FanItem::Pmkid { .. } => None,
    };

    let mut any_written = false;
    for sink in candidates.into_iter().flatten() {
        let idx = sink.as_index();
        let Some(slot) = sinks.sinks.get_mut(idx) else { continue };
        let Some(lazy) = slot.as_mut() else { continue };

        // In disk mode: always accept (write-through), record fingerprint to buckets.
        // In memory mode: use in-memory HashSet dedup gate.
        let accepted = if disk_mode {
            true
        } else {
            match item {
                FanItem::Pmkid { entry, essid, .. } => dedup.check_pmkid(sink, entry, essid),
                FanItem::Eapol { pair, essid, .. } => dedup.check_eapol(sink, pair, essid),
            }
        };
        if accepted {
            let writer = lazy.writer()?;
            match (&eapol_body, item) {
                (Some(body), FanItem::Eapol { .. }) => {
                    writer.write_all(prefix)?;
                    writer.write_all(body)?;
                    writer.write_all(b"\n")?;
                },
                _ => {
                    if let FanItem::Pmkid { entry, ft, essid } = item {
                        let line = build_pmkid_line(entry, ft, essid, ht);
                        writeln!(writer, "{line}")?;
                    }
                },
            }
            if let Some(c) = stats.lines_per_sink.get_mut(idx) {
                *c += 1;
            }
            if let Some(disk) = dd.as_mut() {
                let fp = match item {
                    FanItem::Pmkid { entry, essid, .. } => dedup::pmkid_fingerprint(entry, essid),
                    FanItem::Eapol { pair, essid, .. } => {
                        dedup::eapol_fingerprint(pair, essid, dedup.collapse_message_pair())
                    },
                };
                disk.record(sink, fp)?;
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
pub fn run_output(
    message_store: &MessageStore,
    pmkid_store: &PmkidStore,
    essid_map: &crate::store::essid::EssidMap,
    essid_set: &EssidSet,
    probe_essid_set: &ProbeEssidSet,
    wordlist_store: &WordlistStore,
    scan_ies_store: &WordlistScanIesStore,
    identity_set: &IdentitySet,
    username_set: &UsernameSet,
    device_store: &DeviceInfoStore,
    akm_map: &AkmMap,
    pair_config: &PairConfig,
    paths: &OutputPaths,
    thread_count: usize,
    essid_filter: EssidFilterConfig,
    logger: &mut Logger,
    debug: &DebugPrinter,
    mem_monitor: &mut crate::mem_monitor::MemMonitor,
) -> Result<OutputStats> {
    let mut ctx = OutputContext::new(paths, pair_config.collapse_message_pair);
    ctx.emit(
        message_store,
        pmkid_store,
        essid_map,
        akm_map,
        pair_config,
        thread_count,
        essid_filter,
        debug,
        mem_monitor,
    )?;
    ctx.finalize(
        paths,
        essid_set,
        probe_essid_set,
        wordlist_store,
        scan_ies_store,
        identity_set,
        username_set,
        device_store,
        logger,
    )
}

// --- OutputContext ---

/// Stateful output pipeline driver.
///
/// `run_output` constructs a context, calls `emit` once over the fully
/// populated stores, and `finalize`s. The context is designed to tolerate
/// repeated `emit` calls as well: sinks stay open across calls, dedup state
/// accumulates (so duplicates across batches still collapse), and the per-AP
/// timestamp ranges needed for `[essid_not_found_summary]` are captured during
/// `emit` (when the stores are fully available) rather than re-scanned in
/// `finalize`.
pub struct OutputContext {
    stats: OutputStats,
    dedup: PerSinkDedup,
    sinks: HashSinks,
    disk_dedup: Option<disk_dedup::DiskDedup>,
    /// Sink-independent global dedup set used only to count `hash_type_found`:
    /// every classified hash is fingerprinted here so the 11-type inventory
    /// reflects what the capture contains, not just what reached a configured
    /// sink. Unused in disk mode (found falls back to write-through counting).
    found_dedup: dedup::DedupSet,
    /// APs whose hash lines we declined to emit because no ESSID was ever
    /// observed for them. Such lines are not crackable (hashcat needs the
    /// ESSID to derive the PMK), so they go to `--log` only -- nothing
    /// reaches a hash sink. Map value is the count of would-have-been-emitted
    /// lines per AP; the distinct-AP count is the map's `len()`. Accumulates
    /// across repeated `emit` calls.
    unresolved_drops: HashMap<crate::types::MacAddr, u64>,
    /// Per-AP `(first_seen_us, last_seen_us)` ranges captured during `emit`
    /// for every AP appearing in `unresolved_drops`. Captured here (rather
    /// than re-scanned in `finalize`) so the values are available even after
    /// the stores spill to disk.
    timestamp_ranges: HashMap<crate::types::MacAddr, (u64, u64)>,
}

impl std::fmt::Debug for OutputContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // sinks / dedup / stats are intentionally omitted -- they are large,
        // mutable, and not human-readable; counts are the useful summary.
        f.debug_struct("OutputContext")
            .field("unresolved_drops", &self.unresolved_drops.len())
            .field("timestamp_ranges", &self.timestamp_ranges.len())
            .finish_non_exhaustive()
    }
}

impl OutputContext {
    /// Builds a fresh context with sinks lazily configured per `paths`. No
    /// files are created until the first `emit` call writes a hash line.
    /// `collapse_message_pair` mirrors the `--collapse-message-pair` flag and is
    /// threaded into both dedup sets so the in-memory and disk paths agree.
    #[must_use]
    pub fn new(paths: &OutputPaths, collapse_message_pair: bool) -> Self {
        Self {
            stats: OutputStats::default(),
            dedup: PerSinkDedup::new(collapse_message_pair),
            sinks: HashSinks::open(paths),
            disk_dedup: None,
            found_dedup: dedup::DedupSet::new(collapse_message_pair),
            unresolved_drops: HashMap::new(),
            timestamp_ranges: HashMap::new(),
        }
    }

    /// Captures per-AP timestamp ranges for the unresolved set into
    /// `timestamp_ranges`, merging by min/max. Called at the end of `emit` so
    /// the values are available even after `MessageStore` / `PmkidStore` spill
    /// to disk.
    fn capture_timestamp_ranges(&mut self, message_store: &MessageStore, pmkid_store: &PmkidStore) {
        if self.unresolved_drops.is_empty() {
            return;
        }
        let wanted: HashSet<crate::types::MacAddr> = self.unresolved_drops.keys().copied().collect();
        let mut batch: HashMap<crate::types::MacAddr, (u64, u64)> = HashMap::new();
        message_store.fold_timestamp_range_into(&wanted, &mut batch);
        for entry in pmkid_store.iter() {
            if wanted.contains(&entry.ap) {
                let r = batch.entry(entry.ap).or_insert((u64::MAX, 0));
                r.0 = r.0.min(entry.timestamp);
                r.1 = r.1.max(entry.timestamp);
            }
        }
        // Merge this batch's ranges into the accumulator with min/max.
        for (ap, (first, last)) in batch {
            let r = self.timestamp_ranges.entry(ap).or_insert((u64::MAX, 0));
            r.0 = r.0.min(first);
            r.1 = r.1.max(last);
        }
    }

    /// Runs PMKID + EAPOL emission for the current contents of
    /// `message_store` / `pmkid_store`. Safe to call multiple times; sinks,
    /// dedup, and unresolved-drop bookkeeping accumulate across calls.
    ///
    /// # Errors
    ///
    /// Returns `Err` on I/O failure during fan-out.
    pub fn emit(
        &mut self,
        message_store: &MessageStore,
        pmkid_store: &PmkidStore,
        essid_map: &crate::store::essid::EssidMap,
        akm_map: &AkmMap,
        pair_config: &PairConfig,
        thread_count: usize,
        essid_filter: EssidFilterConfig,
        debug: &DebugPrinter,
        mem_monitor: &mut crate::mem_monitor::MemMonitor,
    ) -> Result<()> {
        // Pre-size the dedup sets so hashbrown never resizes mid-run. Without
        // this, a resize from 2^31 to 2^32 slots requires both tables to be
        // alive simultaneously (54 GiB transient spike at ~2B entries).
        // Only reserve for sinks that have a configured output path (fixes the
        // 9x over-allocation when only 1-2 sinks are active).
        // Skip pre-sizing entirely if the allocation would exceed the memory
        // threshold -- the sets will grow incrementally instead.
        let estimated_pairs = crate::pair::estimate_total_cost(message_store);
        let estimated_hashes = estimated_pairs.saturating_add(pmkid_store.total_count() as u64);
        if estimated_hashes > 0 {
            let active = self.sinks.active_mask();
            let active_count = active.iter().filter(|&&a| a).count() as u64;
            let estimated_bytes = estimated_hashes.saturating_mul(12).saturating_mul(active_count);
            if mem_monitor.would_exceed(estimated_bytes) {
                mem_monitor.force_disk_mode();
                if self.disk_dedup.is_none() {
                    self.disk_dedup = Some(disk_dedup::DiskDedup::new(&active)?);
                }
            } else if self.disk_dedup.is_none() {
                let cap = usize::try_from(estimated_hashes).unwrap_or(usize::MAX);
                self.dedup.reserve(cap, &active);
            }
        }

        let disk_trip = mem_monitor.disk_trip_handle();
        self.emit_inner(
            message_store,
            pmkid_store,
            essid_map,
            akm_map,
            pair_config,
            thread_count,
            essid_filter,
            debug,
            &disk_trip,
        )?;
        // Reconcile the monitor's sticky disk-mode flag for the Phase-5 banner: if
        // the watcher tripped (and drove the mid-stream switch in `emit_inner`),
        // record that the run went disk-backed.
        mem_monitor.poll_disk_trip();
        self.capture_timestamp_ranges(message_store, pmkid_store);
        Ok(())
    }

    /// Decides, before Phase 4, whether this run must go disk-backed and, if so,
    /// arms the disk-backed dedup. Returns `true` when disk mode is already
    /// engaged or the predicted hash-line allocation would cross the memory
    /// threshold, so the caller can flush the stores to disk and route pairing to
    /// the abort-free disk path (`pair_all_groups_disk`). Mirrors the pre-size
    /// estimate in [`Self::emit`]; `emit` then skips its own pre-size because
    /// `disk_dedup` is already set.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the disk-backed dedup temp files cannot be created.
    pub fn would_spill(
        &mut self,
        message_store: &MessageStore,
        pmkid_store: &PmkidStore,
        mem_monitor: &mut crate::mem_monitor::MemMonitor,
    ) -> Result<bool> {
        let active = self.sinks.active_mask();
        if mem_monitor.disk_mode() {
            if self.disk_dedup.is_none() {
                self.disk_dedup = Some(disk_dedup::DiskDedup::new(&active)?);
            }
            return Ok(true);
        }
        let estimated_pairs = crate::pair::estimate_total_cost(message_store);
        let estimated_hashes = estimated_pairs.saturating_add(pmkid_store.total_count() as u64);
        if estimated_hashes == 0 {
            return Ok(false);
        }
        let active_count = active.iter().filter(|&&a| a).count() as u64;
        let estimated_bytes = estimated_hashes.saturating_mul(12).saturating_mul(active_count);
        if mem_monitor.would_exceed(estimated_bytes) {
            mem_monitor.force_disk_mode();
            if self.disk_dedup.is_none() {
                self.disk_dedup = Some(disk_dedup::DiskDedup::new(&active)?);
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// The first R0KH-ID-bearing `FtFields` in `msgs`, if any. R0KH-ID is a
    /// per-(AP, STA)-session constant, so the first carrier message is sufficient.
    fn best_r0khid_ft(msgs: &[EapolMessage]) -> Option<Box<FtFields>> {
        msgs.iter().find_map(|m| m.ft.as_ref().filter(|ft| ft.r0khid_len > 0).cloned())
    }

    /// Session-level FT-context backfill: each `(AP, STA)` group mapped to the best
    /// R0KH-ID-bearing `FtFields` seen in any of its EAPOL messages. Lets an FT-PSK
    /// PMKID whose own carrier frame (e.g. an M1 PMKID KDE) omitted the R0KH-ID still
    /// emit its standalone WPA*03* line, matching hcxpcapngtool's cross-frame backfill
    /// \[`hcxpcapngtool.c`:2807-2884\]; otherwise the line is dropped
    /// (`emit_dropped_ft_no_context`) -- a never-miss gap for FT-PSK PMKIDs.
    fn build_ft_backfill(message_store: &MessageStore) -> HashMap<MacPair, Box<FtFields>> {
        let mut map: HashMap<MacPair, Box<FtFields>> = HashMap::new();
        if message_store.disk_mode() {
            for key in message_store.group_keys() {
                if let Some(ft) = Self::best_r0khid_ft(&message_store.load_group(&key)) {
                    map.insert(key, ft);
                }
            }
        } else {
            for (pair, msgs) in message_store.groups() {
                if let Some(ft) = Self::best_r0khid_ft(msgs) {
                    map.insert(*pair, ft);
                }
            }
        }
        map
    }

    /// True if any FT-classified PMKID lacks its own R0KH-ID, so building the session
    /// backfill is worthwhile. Cheap (no AKM-map resolution), so it gates the
    /// message-store scan -- important in disk mode where the scan re-reads spill.
    fn any_ft_pmkid_missing_context(pmkid_store: &PmkidStore) -> bool {
        pmkid_store.iter().any(|e| {
            matches!(e.akm, AkmType::FtPsk | AkmType::FtPskSha384 | AkmType::Unknown)
                && e.ft.as_ref().is_none_or(|ft| ft.r0khid_len == 0)
        })
    }

    fn emit_inner(
        &mut self,
        message_store: &MessageStore,
        pmkid_store: &PmkidStore,
        essid_map: &crate::store::essid::EssidMap,
        akm_map: &AkmMap,
        pair_config: &PairConfig,
        thread_count: usize,
        essid_filter: EssidFilterConfig,
        debug: &DebugPrinter,
        disk_trip: &std::sync::atomic::AtomicBool,
    ) -> Result<()> {
        let any_sink = self.sinks.any_configured();
        let stats = &mut self.stats;
        let dedup = &mut self.dedup;
        let sinks = &mut self.sinks;
        let disk_dedup = &mut self.disk_dedup;
        let found_dedup = &mut self.found_dedup;
        let unresolved_drops = &mut self.unresolved_drops;

        // FT-PSK PMKID backfill (never-miss): an FT-PSK PMKID whose own carrier frame
        // lacked an R0KH-ID can still emit using the session's R0KH-ID from M2/M3.
        // Built only when an FT PMKID actually needs it, so the common path pays
        // nothing and disk mode avoids an unnecessary spill re-read.
        // FT-context backfill: any FT PMKID or FT EAPOL pair whose own carrier
        // frame lacks R0KH-ID can use a session-mate's FtFields (e.g. M2/M3
        // carry FTE even when M1/M4 do not). Built when any FT material is
        // present; the scan is a single pass over the message store.
        let has_ft_material = Self::any_ft_pmkid_missing_context(pmkid_store)
            || message_store.groups().any(|(_, msgs)| msgs.iter().any(|m| m.akm.is_ft()));
        let ft_backfill: HashMap<MacPair, Box<FtFields>> =
            if any_sink && has_ft_material { Self::build_ft_backfill(message_store) } else { HashMap::new() };

        // --- Pipeline 1: PMKIDs (Invariant OUT-1 -- always before EAPOL pairs) ---
        //
        // Emit one hash line per observed SSID for the AP. Most APs have exactly one SSID,
        // so this loop body executes once. When an AP advertised multiple SSIDs during the
        // capture (e.g. a multi-SSID device), each variant needs to be cracked independently
        // because the PMK is derived from PSK+SSID -- a different SSID is a different PMK.
        if any_sink {
            for entry in pmkid_store.iter() {
                let resolved_akm = if matches!(entry.akm, AkmType::Unknown)
                    || HashType::from_akm_and_attack(entry.akm, true).is_none()
                {
                    let inferred = akm_map.get_best(&entry.ap, &entry.sta);
                    if matches!(inferred, AkmType::Unknown) { entry.akm } else { inferred }
                } else {
                    entry.akm
                };
                let Some(ht) = HashType::from_akm_and_attack(resolved_akm, true) else {
                    if matches!(resolved_akm, AkmType::NotPsk) {
                        stats.emit_dropped_notpsk_akm += 1;
                    } else {
                        stats.emit_dropped_unclassified_akm += 1;
                    }
                    continue;
                };
                let ssids = essid_map.ssids_for_emit(&entry.ap, essid_filter.collapse_min, essid_filter.collapse_ratio);
                let is_ft = ht.is_ft();

                let ft_ctx: Option<&FtFields> = if is_ft {
                    if let Some(ft) = entry.ft.as_ref().filter(|ft| ft.r0khid_len > 0) {
                        Some(ft)
                    } else if let Some(ft) = ft_backfill.get(&MacPair::new(entry.ap, entry.sta)) {
                        // Carrier frame (e.g. M1 PMKID KDE) lacked R0KH-ID; reuse the
                        // session's from M2/M3 so the standalone FT-PSK line still emits.
                        Some(ft.as_ref())
                    } else {
                        stats.emit_dropped_ft_no_context += 1;
                        continue;
                    }
                } else {
                    None
                };

                if ssids.is_empty() {
                    *unresolved_drops.entry(entry.ap).or_insert(0) += 1;
                    stats.essid_unresolved_emissions += 1;
                    continue;
                }

                for essid in ssids {
                    // Inventory count (sink-independent): tally this type as found
                    // whether or not a sink is configured to accept it. Deduped in
                    // memory; counted write-through in disk mode (like `emitted`).
                    if disk_dedup.is_some() || found_dedup.check_pmkid(&entry, essid) {
                        *stats.hash_type_found.entry(ht).or_insert(0) += 1;
                    }
                    let item = FanItem::Pmkid { entry: &entry, ft: ft_ctx, essid };
                    let written = fan_out(sinks, dedup, disk_dedup, stats, ht, item)?;
                    if written {
                        stats.pmkids_written += 1;
                        *stats.hash_type_emitted.entry(ht).or_insert(0) += 1;
                    } else {
                        stats.dedup_dropped_pmkids += 1;
                    }
                }
            }
        }

        // --- Pipeline 2: EAPOL pairs (streaming fan-out) ---
        //
        // Same multi-SSID logic as Pipeline 1. Pairs are fanned out per-group
        // inside the streaming callback, then dropped -- peak memory is one
        // group's pairs at a time instead of the full cross-product.
        let pairs_written_before = stats.pairs_written;
        let dedup_dropped_before = stats.dedup_dropped_pairs;

        #[expect(clippy::items_after_statements, reason = "EmitState defined after Pipeline 1 borrows are consumed")]
        struct EmitState<'a> {
            sinks: &'a mut HashSinks,
            dedup: &'a mut PerSinkDedup,
            disk_dedup: &'a mut Option<disk_dedup::DiskDedup>,
            found_dedup: &'a mut dedup::DedupSet,
            stats: &'a mut OutputStats,
            unresolved_drops: &'a mut HashMap<crate::types::MacAddr, u64>,
            first_error: Option<crate::types::Error>,
        }

        let emit_state = std::sync::Mutex::new(EmitState {
            sinks,
            dedup,
            disk_dedup,
            found_dedup,
            stats,
            unresolved_drops,
            first_error: None,
        });
        let total_pairs_processed = std::sync::atomic::AtomicUsize::new(0);

        let nc_stats =
            crate::pair::pair_all_groups_streaming(message_store, pair_config, thread_count, debug, |pairs| {
                if pairs.is_empty() {
                    return;
                }
                let batch_len = pairs.len();
                let mut guard = emit_state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);

                if guard.first_error.is_some() {
                    return;
                }

                // Mid-stream switch to disk-backed dedup when the memory watcher
                // signalled memory pressure. Sticky: once `disk_dedup` is `Some`
                // the check is skipped. The in-memory fingerprints already written
                // are flushed as sentinels into a line-base-seeded `DiskDedup`
                // (`len_for_sink` == lines already in each file), then the ~57 GB
                // set is dropped. `fan_out` auto-routes to write-through disk dedup
                // from here, and `finalize`'s cleaning pass removes the dupes.
                if any_sink && guard.disk_dedup.is_none() && disk_trip.load(std::sync::atomic::Ordering::Relaxed) {
                    let active = guard.sinks.active_mask();
                    let mut offsets = [0usize; SinkId::COUNT];
                    for (i, off) in offsets.iter_mut().enumerate() {
                        if let Some(sink) = SinkId::from_index(i) {
                            *off = guard.dedup.len_for_sink(sink);
                        }
                    }
                    match disk_dedup::DiskDedup::new_with_offsets(&active, &offsets) {
                        Ok(mut new_dd) => {
                            if let Err(e) = guard.dedup.flush_to_buckets(&mut new_dd) {
                                guard.first_error = Some(e);
                                return;
                            }
                            guard.dedup.drain();
                            *guard.disk_dedup = Some(new_dd);
                        },
                        Err(e) => {
                            guard.first_error = Some(e);
                            return;
                        },
                    }
                }

                if any_sink {
                    let EmitState {
                        sinks: s,
                        dedup: d,
                        disk_dedup: dd,
                        found_dedup: fd,
                        stats: st,
                        unresolved_drops: ud,
                        first_error,
                    } = &mut *guard;
                    // All pairs in this streaming batch belong to one (AP, STA) group,
                    // so the AP's emit-SSID set is identical for every pair -- resolve it
                    // once per group instead of once per paired hash (the per-pair call
                    // re-sorted the AP's SSID-variant list on every hash).
                    let group_ssids = pairs.first().map_or_else(Vec::new, |p| {
                        essid_map.ssids_for_emit(&p.ap, essid_filter.collapse_min, essid_filter.collapse_ratio)
                    });
                    let mut group_pairs_written: u64 = 0;
                    for pair in &pairs {
                        let Some(ht) = HashType::from_akm_and_attack(pair.akm, false) else {
                            if matches!(pair.akm, AkmType::NotPsk) {
                                st.emit_dropped_notpsk_akm += 1;
                            } else {
                                st.emit_dropped_unclassified_akm += 1;
                            }
                            continue;
                        };
                        let is_ft = ht.is_ft();
                        let ft_ctx: Option<&FtFields> = if is_ft {
                            if let Some(ft) = pair.ft.as_ref().filter(|ft| ft.r0khid_len > 0) {
                                Some(ft)
                            } else if let Some(ft) = ft_backfill.get(&MacPair::new(pair.ap, pair.sta)) {
                                Some(ft.as_ref())
                            } else {
                                // FT context missing (typically M4-anchored pair, no FTE).
                                // The MIC was computed from the FT key hierarchy; a non-FT
                                // WPA*02* line is structurally uncrackable (§7.4). Drop.
                                st.emit_dropped_ft_no_context += 1;
                                continue;
                            }
                        } else {
                            None
                        };
                        if group_ssids.is_empty() {
                            *ud.entry(pair.ap).or_insert(0) += 1;
                            st.essid_unresolved_emissions += 1;
                            continue;
                        }

                        for &essid in &group_ssids {
                            // Inventory count (sink-independent), as in Pipeline 1.
                            if dd.is_some() || fd.check_eapol(pair, essid) {
                                *st.hash_type_found.entry(ht).or_insert(0) += 1;
                            }
                            let item = FanItem::Eapol { pair, ft: ft_ctx, essid };
                            match fan_out(s, d, dd, st, ht, item) {
                                Ok(written) => {
                                    if written {
                                        st.pairs_written += 1;
                                        *st.hash_type_emitted.entry(ht).or_insert(0) += 1;
                                        match pair.combo_type {
                                            ComboType::N1E2 => st.n1e2 += 1,
                                            ComboType::N3E2 => st.n3e2 += 1,
                                            ComboType::N1E4 => st.n1e4 += 1,
                                            ComboType::N2E3 => st.n2e3 += 1,
                                            ComboType::N4E3 => st.n4e3 += 1,
                                            ComboType::N3E4 => st.n3e4 += 1,
                                        }
                                        if pair.message_pair & FLAG_NC != 0 {
                                            st.pairs_nc += 1;
                                        }
                                        if pair.message_pair & FLAG_LE != 0 {
                                            st.pairs_le += 1;
                                        }
                                        if pair.message_pair & FLAG_BE != 0 {
                                            st.pairs_be += 1;
                                        }
                                        st.rc_gap_max = st.rc_gap_max.max(pair.rc_gap_magnitude);
                                        if pair.eapol_frame.len() > 512 {
                                            st.eapol_exceeds_hashcat_max += 1;
                                        }
                                        group_pairs_written += 1;
                                    } else {
                                        st.dedup_dropped_pairs += 1;
                                    }
                                },
                                Err(e) => {
                                    *first_error = Some(e);
                                    return;
                                },
                            }
                        }
                    }
                    st.max_pairs_per_group = st.max_pairs_per_group.max(group_pairs_written);
                    if group_pairs_written > 0 {
                        st.groups_with_pairs += 1;
                    } else {
                        st.groups_without_pairs += 1;
                    }
                }

                let processed =
                    total_pairs_processed.fetch_add(batch_len, std::sync::atomic::Ordering::Relaxed) + batch_len;
                if debug.enabled
                    && processed / emit_progress_interval() != (processed - batch_len) / emit_progress_interval()
                {
                    debug.emit_progress(processed, 0, guard.stats.pairs_written.saturating_sub(pairs_written_before));
                }
            });

        // Recover mutable state from the Mutex. The references point back into
        // `self` -- they were moved in, not copied, so the compiler needs the
        // destructure to release the borrows.
        let es = emit_state.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(e) = es.first_error {
            return Err(e);
        }

        // `es.stats` etc. are `&mut self.stats` etc. -- writing through them
        // mutates `self` directly. No need to copy back.
        es.stats.nc_dedup_collapsed_lines += nc_stats.collapsed_lines;
        es.stats.nc_dedup_cluster_count += nc_stats.cluster_count;
        es.stats.nc_dedup_max_cluster_size = es.stats.nc_dedup_max_cluster_size.max(nc_stats.max_cluster_size);
        es.stats.pairs_time_filtered += nc_stats.time_filtered;
        es.stats.pairs_rc_filtered += nc_stats.rc_filtered;
        es.stats.messages_capped += nc_stats.messages_capped;
        es.stats.smart_instances_attributed += nc_stats.smart_instances_attributed;
        es.stats.smart_uncrackable_dropped += nc_stats.smart_uncrackable_dropped;
        es.stats.smart_ambiguous_kept += nc_stats.smart_ambiguous_kept;
        es.stats.smart_ft_nonapless_kept += nc_stats.smart_ft_nonapless_kept;
        es.stats.groups_complete_4way += nc_stats.complete_4way;

        let total_pairs = total_pairs_processed.load(std::sync::atomic::Ordering::Relaxed);
        debug.phase4_pairs_generated(total_pairs);
        debug.emit_fan_out_done(
            total_pairs,
            es.stats.pairs_written - pairs_written_before,
            es.stats.dedup_dropped_pairs - dedup_dropped_before,
            es.stats.nc_dedup_collapsed_lines,
            es.stats.nc_dedup_cluster_count,
        );
        Ok(())
    }

    /// Flushes hash sinks, writes the per-AP `[essid_not_found_summary]` log
    /// lines, and writes the auxiliary outputs. Consumes `self` and returns
    /// the final `OutputStats`.
    ///
    /// # Errors
    ///
    /// Returns `Err` on I/O failure during flush or aux output writes.
    pub fn finalize(
        mut self,
        paths: &OutputPaths,
        essid_set: &EssidSet,
        probe_essid_set: &ProbeEssidSet,
        wordlist_store: &WordlistStore,
        scan_ies_store: &WordlistScanIesStore,
        identity_set: &IdentitySet,
        username_set: &UsernameSet,
        device_store: &DeviceInfoStore,
        logger: &mut Logger,
    ) -> Result<OutputStats> {
        // Flush hash writers before the cleaning pass.
        self.sinks.flush_all()?;

        // Run the disk dedup cleaning pass if active. This rewrites each output
        // file to remove duplicate lines that were accepted in write-through mode.
        if let Some(mut dd) = self.disk_dedup.take() {
            let sinks_ref = &self.sinks;
            dd.clean_all(|sink| sinks_ref.path(sink))?;
        }

        // --- Per-AP unresolved-SSID summary ---
        //
        // Timestamp ranges were captured during `emit` (so the values are
        // correct even after the stores spill to disk). Walk the accumulated
        // `timestamp_ranges` plus `unresolved_drops` in sorted-by-MAC order so
        // the log lines are deterministic across runs.
        if !self.unresolved_drops.is_empty() {
            let mut aps: Vec<crate::types::MacAddr> = self.unresolved_drops.keys().copied().collect();
            aps.sort_unstable_by_key(|m| m.0);
            for ap in aps {
                let dropped = self.unresolved_drops.get(&ap).copied().unwrap_or(0);
                let (first_us, last_us) = self.timestamp_ranges.get(&ap).copied().unwrap_or((0, 0));
                let first_us = if first_us == u64::MAX { 0 } else { first_us };
                logger.log_essid_not_found_summary(format_mac_hex(ap), dropped, first_us, last_us);
            }
        }
        self.stats.essid_unresolved_aps = self.unresolved_drops.len() as u64;

        // --- Auxiliary outputs ---
        //
        // Per the I/O-errors-abort invariant (ARCHITECTURE.md §4 invariant 10),
        // every auxiliary writer must explicitly `flush()?` before its
        // `BufWriter` is dropped. `BufWriter`'s
        // `Drop` impl swallows flush errors silently, so without an explicit flush
        // a disk-full mid-write or a closed-pipe event would silently truncate the
        // file and the process would still exit `0`.

        if let Some(path) = &paths.essid_list {
            let file = std::fs::File::create(path)
                .map_err(|e| crate::types::Error::io(e, path.clone(), "create ESSID list"))?;
            let mut f = BufWriter::with_capacity(OUTPUT_BUF_CAPACITY, file);
            self.stats.entries_essid = write_essid_list(essid_set, &mut f)?;
            f.flush()?;
        }
        if let Some(path) = &paths.probe_essid_list {
            let file = std::fs::File::create(path)
                .map_err(|e| crate::types::Error::io(e, path.clone(), "create probe-ESSID list"))?;
            let mut f = BufWriter::with_capacity(OUTPUT_BUF_CAPACITY, file);
            self.stats.entries_probe = write_probe_essid_list(probe_essid_set, &mut f)?;
            f.flush()?;
        }
        if let Some(path) = &paths.wordlist {
            let file =
                std::fs::File::create(path).map_err(|e| crate::types::Error::io(e, path.clone(), "create wordlist"))?;
            let mut f = BufWriter::with_capacity(OUTPUT_BUF_CAPACITY, file);
            self.stats.entries_wordlist = write_wordlist(wordlist_store, &mut f)?;
            f.flush()?;
        }
        if let Some(path) = &paths.wordlist_scan {
            let file = std::fs::File::create(path)
                .map_err(|e| crate::types::Error::io(e, path.clone(), "create IE-scan wordlist"))?;
            let mut f = BufWriter::with_capacity(OUTPUT_BUF_CAPACITY, file);
            self.stats.entries_wordlist_scan =
                write_wordlist_scan(scan_ies_store, essid_set, probe_essid_set, wordlist_store, &mut f)?;
            f.flush()?;
        }
        if let Some(path) = &paths.identity_list {
            let file = std::fs::File::create(path)
                .map_err(|e| crate::types::Error::io(e, path.clone(), "create identity list"))?;
            let mut f = BufWriter::with_capacity(OUTPUT_BUF_CAPACITY, file);
            self.stats.entries_identity = write_identities(identity_set, &mut f)?;
            f.flush()?;
        }
        if let Some(path) = &paths.username_list {
            let file = std::fs::File::create(path)
                .map_err(|e| crate::types::Error::io(e, path.clone(), "create username list"))?;
            let mut f = BufWriter::with_capacity(OUTPUT_BUF_CAPACITY, file);
            self.stats.entries_username = write_usernames(username_set, &mut f)?;
            f.flush()?;
        }
        if let Some(path) = &paths.device_info {
            let file = std::fs::File::create(path)
                .map_err(|e| crate::types::Error::io(e, path.clone(), "create device-info list"))?;
            let mut f = BufWriter::with_capacity(OUTPUT_BUF_CAPACITY, file);
            self.stats.entries_device = write_device_info(device_store, &mut f)?;
            f.flush()?;
        }

        Ok(self.stats)
    }
}

// --- Unit tests ---

#[cfg(test)]
mod tests {

    use super::*;
    use crate::store::auxiliary::{
        DeviceInfoStore, EssidSet, IdentitySet, ProbeEssidSet, UsernameSet, WordlistScanIesStore, WordlistStore,
    };
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
        let scan_ies_store = WordlistScanIesStore::new();
        let identity_set = IdentitySet::new();
        let username_set = UsernameSet::new();
        let device_store = DeviceInfoStore::new();
        let akm_map = AkmMap::new();
        let pair_config = PairConfig::default();
        let paths = OutputPaths::default();
        let mut logger = Logger::new(None).unwrap();

        let mut mem_monitor = crate::mem_monitor::MemMonitor::new();
        let stats = run_output(
            &msg_store,
            &pmkid_store,
            &essid_map,
            &essid_set,
            &probe_essid_set,
            &wordlist_store,
            &scan_ies_store,
            &identity_set,
            &username_set,
            &device_store,
            &akm_map,
            &pair_config,
            &paths,
            1,
            EssidFilterConfig::default(),
            &mut logger,
            &DebugPrinter::new(false),
            &mut mem_monitor,
        )
        .unwrap();

        assert_eq!(stats, OutputStats::default());
    }

    #[test]
    fn per_type_sink_routes_match_hash_type() {
        for ht in HashType::all() {
            let sink = per_type_sink_for(ht);
            let expected = match ht.type_code() {
                1 => Some(SinkId::OutWpa1Eapol),
                2 => Some(SinkId::OutWpa2Pmkid),
                3 => Some(SinkId::OutWpa2Eapol),
                4 => Some(SinkId::OutSha256Pmkid),
                5 => Some(SinkId::OutSha256Eapol),
                6 => Some(SinkId::OutFtPmkid),
                7 => Some(SinkId::OutFtEapol),
                8..=11 => None,
                _ => unreachable!(),
            };
            assert_eq!(sink, expected, "{}", ht.name());
        }
    }
}
