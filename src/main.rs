//! Shared -- binary entry point and Phase 1-5 orchestrator. See ARCHITECTURE.md §3.
//!
//! Parses command-line arguments via `clap`, then runs the two-phase pipeline:
//! Phase 1 collects all EAPOL messages and PMKIDs from every input file into in-memory
//! stores; Phase 2 pairs messages and writes output files. See `ARCHITECTURE.md §3`.
//!
//! Unfiltered by default: all 6 N#E# combinations, unlimited session window, no
//! replay-counter check. Add output filter flags (`--rc-drift`, `--dedup-hash-combos`) to
//! narrow output to only well-validated hashes. See `ARCHITECTURE.md §8.8 (FR-CLI)`.

#![forbid(unsafe_code)]

// flate2 and crc32fast are used by the library (wpawolf::input::gzip and
// wpawolf::link::fcs respectively). The binary does not import them directly,
// so suppress the unused_crate_dependencies lint with the `as _` form.
use crc32fast as _;
use flate2 as _;
use rayon as _;
use sysinfo as _;

use clap::Parser;

use wpawolf::{
    debug::{DebugPrinter, GroupSummary},
    extract::{ExtractConfig, process_data, process_mgmt, resolve_wds_eapol},
    ieee80211::frame,
    input, link,
    log::Logger,
    output::{EssidFilterConfig, OutputPaths, dedup::SinkId},
    pair::combos::PairConfig,
    progress::ProgressReporter,
    stats::Stats,
    store::{
        AkmMap, MldStore,
        auxiliary::{
            DeviceInfoStore, EssidSet, IdentitySet, ProbeEssidSet, UsernameSet, WordlistScanIesStore, WordlistStore,
        },
        essid::EssidMap,
        fragments::FragmentStore,
        messages::{MessageStore, PendingEapol},
        pmkid::PmkidStore,
    },
};

// --- CLI ---

/// WPA/WPA2/WPA3-FT-PSK handshake extractor for hashcat (modes 22000 and 37100).
///
/// Reads pcap, pcapng, and gzip-compressed captures. Wide defaults: all 6 N#E# combos, unlimited session window, no replay-counter check. Garbage nonces/MICs/PMKIDs are always rejected. Use output-filter flags to narrow.
#[derive(Parser, Debug)]
#[command(
    name = "wpawolf",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("GIT_HASH"), ")"),
    about,
    long_about = None,
    arg_required_else_help = true,
    after_help = "\x1b[1;33mEXAMPLES:\x1b[0m
    wpawolf --22000-out h.22000 capture.pcap
    wpawolf --22000-out h.22000 --37100-out h.37100 *.pcap
    wpawolf --22000-out h.22000 --strict captures/
    wpawolf -o all.out -E essids.txt -W wordlist.txt captures/",
)]
#[allow(clippy::doc_markdown, reason = "doc comments are clap help text, not rustdoc API surface")]
struct Cli {
    /// Capture files or directories to process
    ///
    /// Each argument can be a capture file (pcap, pcapng, gzip) or a directory. Directories are walked recursively; files are included by magic-byte detection, never by extension. Accepted: pcap (microsecond, nanosecond, Kuznetzov, IXIA HW/SW -- each in LE and BE), pcapng, and gzip wrappers.
    #[arg(required = true, value_name = "INPUT", value_hint = clap::ValueHint::AnyPath)]
    input_files: Vec<std::path::PathBuf>,

    // ---- Hash output ----
    /// Write mode-22000 hashes (non-FT, hashcat-compatible)
    ///
    /// Every non-FT hash goes here. Line prefixes: WPA*01* (PMKID), WPA*02* (EAPOL). Drop-in for `hashcat -m 22000`.
    #[arg(long = "22000-out", value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Hash output", display_order = 1)]
    out_22000: Option<std::path::PathBuf>,

    /// Write mode-37100 hashes (FT-PSK, hashcat-compatible)
    ///
    /// Every FT hash goes here. Line prefixes: WPA*03* (PMKID), WPA*04* (EAPOL). Drop-in for `hashcat -m 37100`.
    #[arg(long = "37100-out", value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Hash output", display_order = 2)]
    out_37100: Option<std::path::PathBuf>,

    /// Write all hashes in the extended 11-type format
    ///
    /// Every emitted hash with its per-AKM prefix (WPA*01*..*11*). Not hashcat-readable today; useful for triage and future tooling.
    #[arg(short = 'o', long = "out", value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Hash output", display_order = 3)]
    out_combined: Option<std::path::PathBuf>,

    /// Write WPA1-PSK hashes only (type 1)
    #[arg(long = "wpa1-out", value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Hash output", display_order = 4)]
    out_wpa1: Option<std::path::PathBuf>,

    /// Write WPA2-PSK hashes (types 2+3)
    #[arg(long = "wpa2-out", value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Hash output", display_order = 5)]
    out_wpa2: Option<std::path::PathBuf>,

    /// Write PSK-SHA256 hashes (types 4+5)
    #[arg(long = "psk-sha256-out", value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Hash output", display_order = 6)]
    out_psk_sha256: Option<std::path::PathBuf>,

    /// Write FT-PSK hashes (types 6+7)
    #[arg(long = "ft-out", value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Hash output", display_order = 7)]
    out_ft: Option<std::path::PathBuf>,

    /// Write PSK-SHA384 hashes (types 8+9)
    #[arg(long = "psk-sha384-out", value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Hash output", display_order = 8)]
    out_psk_sha384: Option<std::path::PathBuf>,

    /// Write FT-PSK-SHA384 hashes (types 10+11)
    #[arg(long = "ft-psk-sha384-out", value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Hash output", display_order = 9)]
    out_ft_psk_sha384: Option<std::path::PathBuf>,

    // ---- Auxiliary output ----
    /// Write AP-side SSIDs (autohex)
    ///
    /// ESSIDs from Beacons, Probe Responses, Association/Reassociation Requests, FILS Discovery, OWE Transition, Cisco CCX1, vendor AP names.
    #[arg(short = 'E', long, value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Auxiliary output", display_order = 10)]
    essid_output: Option<std::path::PathBuf>,

    /// Write client-side SSIDs from Probe Requests (autohex)
    ///
    /// Directed Probe Requests (SSID IE), SSID List IE (tag 84), and Action Neighbor Report Request frames.
    #[arg(short = 'R', long, value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Auxiliary output", display_order = 11)]
    probe_output: Option<std::path::PathBuf>,

    /// Write combined wordlist (superset of -E, -R, WPS, EAP, ...)
    ///
    /// Everything from -E and -R plus WPS device strings, EAP identities, country codes, time zones, mesh IDs, vendor AP names. Useful as a targeted hashcat wordlist.
    #[arg(short = 'W', long, value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Auxiliary output", display_order = 12)]
    wordlist_output: Option<std::path::PathBuf>,

    /// Write EAP identity strings (autohex, sorted)
    ///
    /// EAP-Response/Identity strings per RFC 3748 section 5.1.
    #[arg(short = 'I', long, value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Auxiliary output", display_order = 13)]
    identity_output: Option<std::path::PathBuf>,

    /// Write EAP usernames (autohex, sorted)
    ///
    /// Peer identity strings from inner EAP methods (MSCHAPv2, LEAP, etc.).
    #[arg(short = 'U', long, value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Auxiliary output", display_order = 14)]
    username_output: Option<std::path::PathBuf>,

    /// Write WPS device info (tab-separated, sorted by manufacturer)
    ///
    /// Columns: MAC, manufacturer, model_name, model_number, serial, device_name, os_version, primary_device_type, secondary_device_type_list, uuid_e, essid. Deduplicated.
    #[arg(short = 'D', long, value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Auxiliary output", display_order = 15)]
    device_output: Option<std::path::PathBuf>,

    /// Write IE-scan wordlist (printable-ASCII runs not in -E/-R/-W)
    ///
    /// Scans every plaintext management-frame IE body for contiguous runs of printable bytes (>= 8 chars). Entries already in -E, -R, or -W are subtracted.
    #[arg(long = "wordlist-scan", value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Auxiliary output", display_order = 16)]
    wordlist_scan: Option<std::path::PathBuf>,

    /// Write structured processing log
    ///
    /// Eleven log categories: malformed_frame, plcp_error, unknown_linktype, unknown_akm, essid_not_found_summary, capture_read_error, skipped_input, invalid_nonce, invalid_mic, invalid_pmkid, essid_control_bytes. Each line carries the rejected bytes in hex for forensic grep.
    #[arg(short = 'l', long, value_name = "FILE", value_hint = clap::ValueHint::FilePath, help_heading = "Auxiliary output", display_order = 17)]
    log: Option<std::path::PathBuf>,

    // ---- Output filters ----
    /// Narrow output like hcxpcapngtool (bundle of 5 filters)
    ///
    /// Enables: --eapoltimeout=5, --rc-drift=8, --dedup-hash-combos, --per-file, --nc-dedup. Later flags override these defaults.
    #[arg(short = 's', long, help_heading = "Output filters", display_order = 20)]
    strict: bool,

    /// Max seconds between paired messages [bare: 600]
    ///
    /// Absent = unlimited (no time filter). Bare --eapoltimeout = 600 s. --eapoltimeout=N = custom window. Pairs exceeding this are discarded.
    #[arg(long, num_args = 0..=1, default_missing_value = "600", value_name = "SECONDS", help_heading = "Output filters", display_order = 21)]
    eapoltimeout: Option<u64>,

    /// Max replay-counter drift between paired messages [bare: 8]
    ///
    /// Absent = off (all pairs pass). Bare --rc-drift = tolerance 8. --rc-drift=N = custom tolerance. Pairs whose RC delta exceeds N are discarded.
    #[arg(long, num_args = 0..=1, default_missing_value = "8", value_name = "N", help_heading = "Output filters", display_order = 22)]
    rc_drift: Option<u8>,

    /// Collapse 6 combos to 3 unique per session
    ///
    /// A full handshake yields up to 6 N#E# combos but at most 3 are cryptographically distinct. Keeps one per equivalence class (best RC gap, then authorized combo priority).
    #[arg(long, help_heading = "Output filters", display_order = 23)]
    dedup_hash_combos: bool,

    /// Collapse near-identical-nonce lines to one survivor
    ///
    /// Clusters lines sharing (AP, STA, EAPOL, MIC, combo) where nonces differ only in the trailing 4 bytes. Survivor gets FLAG_NC so hashcat's nonce-error-corrections recovers the rest.
    #[arg(long, help_heading = "Output filters", display_order = 24)]
    nc_dedup: bool,

    /// Nonce-cluster span tolerance for --nc-dedup
    ///
    /// Max distance (max - min) on the trailing 4 nonce bytes within one cluster. Matches hashcat's NONCE_ERROR_CORRECTIONS=8 by default.
    #[arg(long, value_name = "N", help_heading = "Output filters", display_order = 25)]
    nc_tolerance: Option<u8>,

    /// Min SSIDs per AP before collapse fires
    ///
    /// APs with N or fewer distinct SSIDs always emit all of them. Raise for CTF captures where many real SSIDs are expected.
    #[arg(
        long = "essid-collapse-min",
        value_name = "N",
        default_value_t = 3,
        help_heading = "Output filters",
        display_order = 26
    )]
    essid_collapse_min: usize,

    /// Top/runner-up ratio to trigger SSID collapse
    ///
    /// When collapse fires, keep only the top SSID if its count >= N times the runner-up. Set below 2 to disable collapse entirely.
    #[arg(
        long = "essid-collapse-ratio",
        value_name = "N",
        default_value_t = 10,
        help_heading = "Output filters",
        display_order = 27
    )]
    essid_collapse_ratio: u64,

    // ---- Runtime ----
    /// Number of pairing threads [default: CPU count]
    ///
    /// Phase 4 worker count. Groups are assigned via LPT scheduling. Use --threads=1 for reproducible single-threaded output.
    #[arg(short = 't', long, value_name = "N", help_heading = "Runtime", display_order = 30)]
    threads: Option<u16>,

    /// Suppress progress lines
    ///
    /// Progress lines print every 5 s during ingestion. This flag silences them. The closing stats banner is unaffected.
    #[arg(short = 'q', long, help_heading = "Runtime", display_order = 31)]
    quiet: bool,

    /// Flush stores after each input file (no cross-file pairing)
    ///
    /// MessageStore and PmkidStore clear per file. Bounds RSS for large corpora at the cost of cross-file pairing (< 1% hash yield drop on per-session captures).
    #[arg(long = "per-file", help_heading = "Runtime", display_order = 32)]
    per_file: bool,

    /// Print per-store memory footprint at end of run
    ///
    /// Approximate byte counts for every long-lived store (MessageStore, PmkidStore, EssidMap, etc.), sorted descending. For OOM triage.
    #[arg(long, help_heading = "Runtime", display_order = 34)]
    mem_stats: bool,

    /// Print verbose diagnostic lines during processing
    ///
    /// Timestamped output at phase transitions, per-file deltas, heavy-group warnings, and memory checks. Redirect to a file for large corpora.
    #[arg(short = 'd', long, help_heading = "Runtime", display_order = 35)]
    debug: bool,
}

/// Apply `--strict` mode's bundled defaults to a parsed CLI.
///
/// `--strict` is a shortcut for a hcxpcapngtool-shape narrow output profile. It
/// turns on the five output filters that together close the volume gap against
/// hcxpcapngtool default (`--eapoltimeout=5`, `--rc-drift=8`,
/// `--dedup-hash-combos`, `--per-file`, `--nc-dedup`), but uses later-flag-wins
/// precedence so an explicit `--eapoltimeout=30` survives past `--strict`. The three boolean
/// flags can only be turned on, never off, so `--strict` always sets them.
const fn apply_strict_defaults(cli: &mut Cli) {
    if !cli.strict {
        return;
    }
    if cli.eapoltimeout.is_none() {
        cli.eapoltimeout = Some(5);
    }
    if cli.rc_drift.is_none() {
        cli.rc_drift = Some(8);
    }
    cli.dedup_hash_combos = true;
    cli.per_file = true;
    cli.nc_dedup = true;
}

// --- Entry point ---

fn main() {
    let mut cli = Cli::parse();
    apply_strict_defaults(&mut cli);

    // At least one output must be requested.
    let has_output = cli.out_22000.is_some()
        || cli.out_37100.is_some()
        || cli.out_combined.is_some()
        || cli.out_wpa1.is_some()
        || cli.out_wpa2.is_some()
        || cli.out_psk_sha256.is_some()
        || cli.out_ft.is_some()
        || cli.out_psk_sha384.is_some()
        || cli.out_ft_psk_sha384.is_some()
        || cli.essid_output.is_some()
        || cli.probe_output.is_some()
        || cli.wordlist_output.is_some()
        || cli.identity_output.is_some()
        || cli.username_output.is_some()
        || cli.device_output.is_some()
        || cli.wordlist_scan.is_some();
    if !has_output {
        println!(
            "error: no output specified (use --22000-out, --37100-out, -o/--out, --wpa1-out, --wpa2-out, --psk-sha256-out, --ft-out, --psk-sha384-out, --ft-psk-sha384-out, -E, -R, -W, -I, -U, -D, or --wordlist-scan)"
        );
        println!("Run with --help for usage.");
        std::process::exit(1);
    }

    // Reject duplicate output paths -- two sinks writing the same file causes silent data loss.
    {
        let paths: Vec<&std::path::Path> = [
            cli.out_22000.as_deref(),
            cli.out_37100.as_deref(),
            cli.out_combined.as_deref(),
            cli.out_wpa1.as_deref(),
            cli.out_wpa2.as_deref(),
            cli.out_psk_sha256.as_deref(),
            cli.out_ft.as_deref(),
            cli.out_psk_sha384.as_deref(),
            cli.out_ft_psk_sha384.as_deref(),
            cli.essid_output.as_deref(),
            cli.probe_output.as_deref(),
            cli.wordlist_output.as_deref(),
            cli.identity_output.as_deref(),
            cli.username_output.as_deref(),
            cli.device_output.as_deref(),
            cli.wordlist_scan.as_deref(),
            cli.log.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect();
        let mut seen = std::collections::HashSet::with_capacity(paths.len());
        for p in &paths {
            if !seen.insert(*p) {
                println!("error: duplicate output path: {}", p.display());
                std::process::exit(1);
            }
        }
    }

    if let Err(e) = run(&cli) {
        println!("error: {e}");
        std::process::exit(1);
    }
}

// --- Link-layer strip + FCS resolve + recovery ---

/// Strips the link-layer header, validates FCS via CRC-32, and attempts tiered
/// recovery on failure. Returns `None` (and logs/counts the error) when the
/// frame is unrecoverable.
fn strip_and_resolve<'a>(
    packet: &'a input::Packet,
    dlt: u16,
    stats: &mut Stats,
    logger: &mut Logger,
) -> Option<&'a [u8]> {
    match link::strip(&packet.data, dlt) {
        Ok((payload, header_says_fcs)) => {
            if dlt == link::DLT_RADIOTAP && link::radiotap::version_warning(&packet.data).is_some() {
                stats.radiotap_version_nonzero += 1;
            }
            let badfcs = dlt == link::DLT_RADIOTAP && link::radiotap::has_badfcs(&packet.data);
            let outcome = link::fcs::resolve(payload, header_says_fcs, badfcs);
            match outcome {
                link::fcs::FcsOutcome::HeaderAndCrcAgree => stats.fcs_header_and_crc_agree += 1,
                link::fcs::FcsOutcome::CrcDetected => stats.fcs_detected_by_crc += 1,
                link::fcs::FcsOutcome::BadFcsFlagged => stats.fcs_badfcs_flagged += 1,
                link::fcs::FcsOutcome::CrcMismatchNoFlag => stats.fcs_crc_mismatch_no_flag += 1,
                link::fcs::FcsOutcome::Neither => stats.fcs_neither += 1,
            }
            Some(link::fcs::strip_fcs(payload, outcome))
        },
        Err(e) => {
            if let Some(result) = link::recover::recover(&packet.data, dlt) {
                match result.tier {
                    link::recover::RecoveryTier::ComputedFromPresent => stats.recovered_tier2 += 1,
                    link::recover::RecoveryTier::Crc32Scan => stats.recovered_tier3 += 1,
                }
                Some(result.frame)
            } else {
                stats.link_errors += 1;
                logger.log_plcp_error(&format!("link strip failed: {e}"), dlt);
                None
            }
        },
    }
}

// --- Pipeline ---

/// Runs the full two-phase (Collect + Output) pipeline.
///
/// Phase 1 iterates every input file, dispatches management and data frames to their
/// respective collectors, and populates all in-memory stores. Phase 2 pairs EAPOL
/// messages, deduplicates, and writes all requested output files. Returns `Err` only
/// for I/O failures that should abort the run -- parse errors are logged and skipped.
fn run(cli: &Cli) -> wpawolf::types::Result<()> {
    // --- Debug printer (created once; no-op when --debug is off) ---
    let debug = DebugPrinter::new(cli.debug);

    // --- Initialise stores ---
    let mut message_store = MessageStore::new();
    let mut pmkid_store = PmkidStore::new();
    let mut fragment_store = FragmentStore::new();
    let mut essid_map = EssidMap::new();
    let mut akm_map = AkmMap::new();
    let mut mld_store = MldStore::new();
    let mut essid_set = EssidSet::new();
    let mut probe_essid_set = ProbeEssidSet::new();
    let mut wordlist_store = WordlistStore::new();
    let mut scan_ies_store = WordlistScanIesStore::new();
    let mut identity_set = IdentitySet::new();
    let mut username_set = UsernameSet::new();
    let mut device_store = DeviceInfoStore::new();
    let mut stats = Stats::new();
    let mut logger = Logger::new(cli.log.as_deref())?;
    let mut pending_eapol: Vec<PendingEapol> = Vec::new();
    // Periodic stderr progress lines during Phase 1. On by default; `--quiet`
    // suppresses entirely. The closing stats banner is unaffected. See
    // `wpawolf::progress`.
    let mut progress = ProgressReporter::new(!cli.quiet);

    // Per-frame extraction toggles derived from the CLI output flags. See
    // `wpawolf::extract::ExtractConfig`. `scan_ies` is independent of `-W`:
    // `--wordlist-scan-ies FILE` populates a dedicated `WordlistScanIesStore`,
    // not the curated `-W` wordlist.
    let extract_cfg = ExtractConfig {
        populate_wordlist: cli.wordlist_output.is_some(),
        populate_device: cli.device_output.is_some(),
        populate_identity: cli.identity_output.is_some(),
        populate_username: cli.username_output.is_some(),
        scan_ies: cli.wordlist_scan.is_some(),
    };

    // Expand any directory arguments to the recursive set of capture files they
    // contain. Plain file arguments pass through unchanged. Done up front so the
    // banner and last_file metadata reflect the actual processed set.
    let inputs = input::expand_inputs(&cli.input_files)?;
    if inputs.is_empty() {
        return Err(wpawolf::types::Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no input capture files found (check paths and extensions)",
        )));
    }

    // OOM guard: abort if RSS exceeds 80% of system RAM.
    let oom_threshold_bytes = wpawolf::progress::total_ram_bytes() * 80 / 100;

    // --- Phase 2 + 3 setup (moved up so per-file mode can emit inside the loop) ---
    let pair_config = PairConfig {
        eapol_timeout_us: cli.eapoltimeout.unwrap_or(600) * 1_000_000, // seconds to us
        rc_drift_tolerance: cli.rc_drift.unwrap_or(0),
        all_combos: !cli.dedup_hash_combos, // --dedup-hash-combos inverts the "emit all combos" flag
        time_check_enabled: cli.eapoltimeout.is_some(), // no flag = unlimited (no time filter)
        rc_drift_enabled: cli.rc_drift.is_some(), // output filter: off by default
        nc_dedup_enabled: cli.nc_dedup,     // output filter: off by default
        nc_tolerance: cli.nc_tolerance.unwrap_or(8), // ignored when nc_dedup_enabled=false
    };

    let paths = OutputPaths {
        out_22000: cli.out_22000.clone(),
        out_37100: cli.out_37100.clone(),
        out_combined: cli.out_combined.clone(),
        out_wpa1: cli.out_wpa1.clone(),
        out_wpa2: cli.out_wpa2.clone(),
        out_psk_sha256: cli.out_psk_sha256.clone(),
        out_ft: cli.out_ft.clone(),
        out_psk_sha384: cli.out_psk_sha384.clone(),
        out_ft_psk_sha384: cli.out_ft_psk_sha384.clone(),
        essid_list: cli.essid_output.clone(),
        probe_essid_list: cli.probe_output.clone(),
        wordlist: cli.wordlist_output.clone(),
        wordlist_scan: cli.wordlist_scan.clone(),
        identity_list: cli.identity_output.clone(),
        username_list: cli.username_output.clone(),
        device_info: cli.device_output.clone(),
    };

    let thread_count: usize = cli.threads.map_or_else(
        || std::thread::available_parallelism().map_or(1, std::num::NonZero::get),
        |t| usize::from(t.max(1)),
    );

    let essid_filter =
        EssidFilterConfig { collapse_min: cli.essid_collapse_min, collapse_ratio: cli.essid_collapse_ratio };

    // Hash-output state: opens lazily, accumulates dedup + per-AP unresolved-SSID
    // bookkeeping across calls. Per-file mode calls `emit` once per file; non-per-file
    // mode calls it once at end of run. Both modes converge on `finalize` to flush
    // sinks and write auxiliary outputs.
    let mut output_ctx = wpawolf::output::OutputContext::new(&paths);

    // --- Phase 1: Collect ---
    debug.phase_start(1, "Ingest");
    let total_inputs = inputs.len();
    for (file_idx, path) in inputs.iter().enumerate() {
        stats.last_file = path.display().to_string();

        // Per-file debug: snapshot cumulative counters before processing so we can
        // compute the delta (packets/EAPOL/PMKID contributed by this file alone).
        let pre_packets = stats.total_packets;
        let pre_eapol = stats.eapol_m1 + stats.eapol_m2 + stats.eapol_m3 + stats.eapol_m4;
        let pre_pmkid = stats.pmkids_found;
        let file_size = path.metadata().map_or(0, |m| m.len());
        debug.file_start(file_idx + 1, total_inputs, &path.display().to_string(), file_size);

        let mut reader = match input::open_reader(path) {
            Ok(r) => r,
            Err(e) => {
                // Route unrecognised-magic files through the log sink instead of stderr:
                // the corpus-scale failure mode (submission-staging watch directories
                // leaving sub-4-byte stubs behind) is "expected garbage", not
                // "operator-affecting error".
                // Genuine I/O failures (permission denied, disk error) still surface on
                // stderr so a runaway run doesn't silently misbehave.
                if matches!(e, wpawolf::types::Error::UnknownFormat(_)) {
                    stats.files_skipped_unknown_format += 1;
                    logger.log_skipped_input(path, &e.to_string());
                } else {
                    println!("warning: cannot open {}: {e}", path.display());
                }
                continue;
            },
        };

        // Populate file metadata from the reader. Histograms aggregate across
        // every input file so a directory walk can report a count + format /
        // endian / DLT distribution rather than only the last file's values.
        stats.input_file_count += 1;
        let meta = reader.file_metadata();
        // Save before meta fields are moved into stats HashMaps below.
        let file_fmt = meta.format.clone();
        let file_dlt = meta.dlt_desc.clone();
        *stats.file_formats_seen.entry(meta.format).or_insert(0) += 1;
        *stats.endians_seen.entry(meta.endian.to_owned()).or_insert(0) += 1;
        *stats.dlt_descs_seen.entry(meta.dlt_desc).or_insert(0) += 1;

        let mut prev_ts_us: u64 = 0;
        let mut frame_in_file: u64 = 0;
        logger.set_file(&path.display().to_string());

        loop {
            match reader.next_packet() {
                Ok(Some(mut packet)) => {
                    stats.total_packets += 1;
                    frame_in_file += 1;
                    logger.set_frame(frame_in_file);
                    // Periodic stderr progress line (no-op when --quiet). Cheap on the
                    // hot path: most calls return after a single u64 comparison.
                    let eapol_total = stats.eapol_m1 + stats.eapol_m2 + stats.eapol_m3 + stats.eapol_m4;
                    progress.tick(stats.total_packets, stats.input_file_count, eapol_total, stats.pmkids_found);
                    // Timestamp range (epoch microseconds). Initialise first_us on the very first packet.
                    if stats.timestamp_first_us == 0 && packet.timestamp_us > 0 {
                        stats.timestamp_first_us = packet.timestamp_us;
                    }
                    if packet.timestamp_us > stats.timestamp_last_us {
                        stats.timestamp_last_us = packet.timestamp_us;
                    }
                    // Per-file out-of-sequence detection. `prev_ts_us == 0` skips the
                    // first packet (no previous to compare); subsequent packets compare
                    // against the previous packet in this file. We accept equality (a
                    // genuinely simultaneous burst is plausible), only strict decrease
                    // triggers the counter.
                    if prev_ts_us != 0 && packet.timestamp_us < prev_ts_us {
                        stats.out_of_sequence_timestamps += 1;
                    }
                    prev_ts_us = packet.timestamp_us;

                    // Get the DLT for this interface.
                    let Some(dlt) = reader.link_type(packet.interface_id) else {
                        logger.log_unknown_linktype(packet.interface_id);
                        continue;
                    };

                    // Per-band packet count from radiotap Channel field (DLT 127 only).
                    // Band mapping per radiotap.org: 2412-2484 MHz = 2.4 GHz,
                    // 5180-5825 MHz = 5 GHz, 5925-7125 MHz = 6 GHz.
                    if let Some(freq) = link::channel_freq(&packet.data, dlt) {
                        match freq {
                            2412..=2484 => stats.band_24ghz += 1,
                            5180..=5825 => stats.band_5ghz += 1,
                            5925..=7125 => stats.band_6ghz += 1,
                            _ => {},
                        }
                    }

                    // Strip the link-layer radio header to expose the raw 802.11 frame.
                    if link::has_ampdu_status(&packet.data, dlt) {
                        stats.ampdu_status_frames += 1;
                    }
                    let Some(frame_data) = strip_and_resolve(&packet, dlt, &mut stats, &mut logger) else {
                        continue;
                    };

                    // Parse the 802.11 MAC header. The four-state classifier keeps
                    // spec-valid control frames out of the `malformed_frame` log,
                    // accepts non-zero Protocol Version frames as a forgivable
                    // anomaly (matches tshark behaviour), and reserves `Malformed`
                    // for frames we genuinely cannot dissect.
                    let mac_hdr = match frame::parse(frame_data) {
                        frame::ParseResult::Frame(h) => h,
                        frame::ParseResult::Lenient(h) => {
                            stats.lenient_proto_version += 1;
                            h
                        },
                        frame::ParseResult::Control => {
                            stats.ctrl_frames += 1;
                            continue;
                        },
                        frame::ParseResult::Malformed(reason) => {
                            stats.malformed_mac_hdr += 1;
                            logger.log_malformed_frame(reason);
                            continue;
                        },
                    };

                    // Count remaining frames (Data / Management / Extension).
                    // Control was already counted above via `ParseResult::Control`.
                    match mac_hdr.frame_type {
                        frame::TYPE_DATA => stats.data_frames += 1,
                        frame::TYPE_MANAGEMENT => stats.mgmt_frames += 1,
                        frame::TYPE_EXTENSION => {
                            stats.extension_frames += 1;
                            continue;
                        },
                        _ => continue, // unreachable: parse() returns one of the four types
                    }

                    // Slice the frame body (past MAC header).
                    let Some(body) = frame_data.get(mac_hdr.body_offset..) else {
                        continue;
                    };

                    match mac_hdr.frame_type {
                        frame::TYPE_MANAGEMENT => {
                            process_mgmt(
                                &mac_hdr,
                                body,
                                packet.timestamp_us,
                                &extract_cfg,
                                &mut essid_map,
                                &mut essid_set,
                                &mut probe_essid_set,
                                &mut akm_map,
                                &mut mld_store,
                                &mut pmkid_store,
                                &mut wordlist_store,
                                &mut scan_ies_store,
                                &mut device_store,
                                &mut stats,
                                &mut logger,
                            );
                        },
                        frame::TYPE_DATA => {
                            process_data(
                                &mac_hdr,
                                body,
                                packet.timestamp_us,
                                &extract_cfg,
                                &mut message_store,
                                &mut pmkid_store,
                                &essid_map,
                                &mut akm_map,
                                &mut identity_set,
                                &mut username_set,
                                &mut wordlist_store,
                                &mut stats,
                                &mut pending_eapol,
                                &mut fragment_store,
                                &mut logger,
                            );
                        },
                        _ => {},
                    }

                    reader.recycle_buffer(std::mem::take(&mut packet.data));
                },
                Ok(None) => break, // end of file
                Err(e) => {
                    // Per FR-IN-10 (ARCHITECTURE.md §3.1) an EOF or corrupt record header
                    // mid-stream stops this file but does not abort the run -- everything
                    // already decoded from earlier records in the same file is kept. Detail
                    // goes to `--log`; the operator-visible signal is the Phase 1 summary
                    // counter `capture files with truncated trailing record`.
                    stats.truncated_capture_files += 1;
                    stats.unreadable_packets += 1;
                    logger.log_capture_read_error(path, &format!("{e}"));
                    debug.capture_error(&path.display().to_string(), &e.to_string());
                    break;
                },
            }
        }

        // Per-file debug summary.
        {
            let post_eapol = stats.eapol_m1 + stats.eapol_m2 + stats.eapol_m3 + stats.eapol_m4;
            debug.file_done(
                file_idx + 1,
                total_inputs,
                &path.display().to_string(),
                &file_fmt,
                &file_dlt,
                stats.total_packets - pre_packets,
                post_eapol - pre_eapol,
                stats.pmkids_found - pre_pmkid,
                message_store.group_count(),
            );
            let _ = debug.memory_check(&format!("Phase 1 file {}/{total_inputs}", file_idx + 1));

            // OOM guard: every 1000 files, check RSS and abort if approaching OOM.
            if (file_idx + 1) % 1000 == 0 {
                let rss = wpawolf::progress::current_rss_bytes();
                if rss > oom_threshold_bytes {
                    let rss_mib = rss / (1024 * 1024);
                    let total_mib = wpawolf::progress::total_ram_bytes() / (1024 * 1024);
                    println!(
                        "error: approaching OOM -- RSS {rss_mib} MiB / {total_mib} MiB (>= 80%) during Phase 1 ingestion (file {}/{total_inputs}). Reduce input size, use --per-file, or increase available RAM.",
                        file_idx + 1
                    );
                    std::process::exit(1);
                }
            }
        }

        // --- Per-file emit (--per-file mode only) ---
        //
        // Resolve any deferred WDS frames seen this file (they need an ESSID
        // context; `essid_map` accumulates across files so even cross-file
        // ESSID-based resolution still works), MLD-canonicalize the per-file
        // stores, emit hashes for what we have, then drop the per-file EAPOL
        // and PMKID state. Auxiliaries (`-E`/`-W`/...), `essid_map`,
        // `akm_map`, `mld_store`, and the dedup state inside `output_ctx`
        // accumulate across files. See `ARCHITECTURE.md §3` for the
        // cross-file pairing tradeoff.
        if cli.per_file {
            if !pending_eapol.is_empty() {
                resolve_wds_eapol(
                    &pending_eapol,
                    &essid_map,
                    &mut akm_map,
                    &mut message_store,
                    &mut pmkid_store,
                    &mut stats,
                    &mut logger,
                );
                pending_eapol.clear();
            }
            if !mld_store.is_empty() {
                let merged = message_store.canonicalize_pairs(|m| mld_store.canonicalize(m));
                stats.mld_groups_merged = stats.mld_groups_merged.saturating_add(merged);
                pmkid_store.canonicalize_pairs(|m| mld_store.canonicalize(m));
            }
            stats.anonce_m1_m3_mismatch_sessions =
                stats.anonce_m1_m3_mismatch_sessions.saturating_add(message_store.count_anonce_m1_m3_mismatches());
            output_ctx.emit(
                &message_store,
                &pmkid_store,
                &essid_map,
                &akm_map,
                &pair_config,
                thread_count,
                essid_filter,
                &debug,
            )?;
            message_store.clear();
            pmkid_store.clear();
        }
    }

    // Final progress line at the end of Phase 1 so an operator always sees the
    // last state just before the closing banner -- even on tiny captures that
    // never crossed a cadence threshold.
    {
        let eapol_total = stats.eapol_m1 + stats.eapol_m2 + stats.eapol_m3 + stats.eapol_m4;
        progress.print_now(stats.total_packets, stats.input_file_count, eapol_total, stats.pmkids_found);
    }

    // --- Phase 1.5: Resolve deferred WDS EAPOL frames (non-per-file mode only) ---
    // WDS relay frames had ambiguous direction during Phase 1. Now that essid_map is fully
    // populated, resolve them using essid_map lookup, ACK-based AP discovery, or flag fallback.
    // In `--per-file` mode the resolve already ran per-file inside the ingest loop.
    if !cli.per_file && !pending_eapol.is_empty() {
        let wds_count = pending_eapol.len();
        resolve_wds_eapol(
            &pending_eapol,
            &essid_map,
            &mut akm_map,
            &mut message_store,
            &mut pmkid_store,
            &mut stats,
            &mut logger,
        );
        debug.wds_resolved(wds_count, 0);
    }

    // Snapshot ESSID count before handing off to output.
    // ap_count() returns usize; u64 can represent every possible usize value on supported platforms.
    {
        stats.essid_count = essid_map.ap_count() as u64;
    }

    // Record output paths in stats so the Phase 4 banner can show configured vs not-configured.
    let path_str = |p: &Option<std::path::PathBuf>| p.as_ref().map_or_else(String::new, |p| p.display().to_string());
    stats.path_22000 = path_str(&cli.out_22000);
    stats.path_37100 = path_str(&cli.out_37100);
    stats.path_combined = path_str(&cli.out_combined);
    stats.path_wpa1 = path_str(&cli.out_wpa1);
    stats.path_wpa2 = path_str(&cli.out_wpa2);
    stats.path_psk_sha256 = path_str(&cli.out_psk_sha256);
    stats.path_ft = path_str(&cli.out_ft);
    stats.path_psk_sha384 = path_str(&cli.out_psk_sha384);
    stats.path_ft_psk_sha384 = path_str(&cli.out_ft_psk_sha384);
    stats.essid_list_path = path_str(&cli.essid_output);
    stats.probe_list_path = path_str(&cli.probe_output);
    stats.wordlist_path = path_str(&cli.wordlist_output);
    stats.identity_list_path = path_str(&cli.identity_output);
    stats.username_list_path = path_str(&cli.username_output);
    stats.device_info_path = path_str(&cli.device_output);

    if cli.per_file {
        // Per-file mode also re-canonicalizes essid_map at end of run because
        // some link-MAC SSIDs may have been filed under their pre-MLD address
        // before the corresponding MLE was learned. Cheap because it only
        // touches the AP-keyed map.
        if !mld_store.is_empty() {
            stats.essid_link_macs_merged = essid_map.canonicalize_pairs(|m| mld_store.canonicalize(m));
        }
    } else {
        // 802.11be MLD canonicalization: if any Multi-Link Element was seen, rewrite all
        // MessageStore and PmkidStore keys so link addresses collapse onto the MLD identity.
        // When no MLE was observed, this is a no-op and byte-identical to pre-MLE behavior.
        // [IEEE 802.11be] §9.4.2.321
        if !mld_store.is_empty() {
            let merged = message_store.canonicalize_pairs(|m| mld_store.canonicalize(m));
            stats.mld_groups_merged = merged;
            pmkid_store.canonicalize_pairs(|m| mld_store.canonicalize(m));
            // Fold link-MAC SSIDs into the canonical MLD MAC so essid_map lookups by
            // canonical AP key (post-canonicalization on the pair side) actually find
            // them. Without this, hidden-SSID resolution silently fails for any MLD
            // AP whose SSID was advertised under a band-specific link MAC.
            stats.essid_link_macs_merged = essid_map.canonicalize_pairs(|m| mld_store.canonicalize(m));
        }

        // Capture-quality diagnostic: count sessions whose M1 and M3 ANonce disagree.
        // Per IEEE 802.11-2024 §12.7.6.4 they must match in the same handshake session.
        stats.anonce_m1_m3_mismatch_sessions = message_store.count_anonce_m1_m3_mismatches();

        // Phase 1 complete; log the full store state and the top heavy groups before Phase 4.
        {
            let eapol_total = stats.eapol_m1 + stats.eapol_m2 + stats.eapol_m3 + stats.eapol_m4;
            debug.phase_done(
                1,
                "Ingest",
                &format!(
                    "files={} packets={} groups={} eapol={}",
                    stats.input_file_count,
                    stats.total_packets,
                    message_store.group_count(),
                    eapol_total
                ),
            );
            let _ = debug.memory_check("Phase 1 complete");

            if debug.enabled {
                // Build group summaries for the top-25 survey and cost-tier breakdown.
                // Both come from the same single pass over the store.
                let mut summaries: Vec<GroupSummary> = message_store
                    .groups()
                    .map(|(pair, msgs)| GroupSummary::from_messages(pair.ap, pair.sta, msgs))
                    .collect();

                let (mut cost_zero, mut cost_low, mut cost_medium, mut cost_heavy) = (0usize, 0usize, 0usize, 0usize);
                for g in &summaries {
                    match g.cost {
                        0 => cost_zero += 1,
                        1..=999 => cost_low += 1,
                        1_000..=49_999 => cost_medium += 1,
                        _ => cost_heavy += 1,
                    }
                }

                summaries.sort_unstable_by_key(|g| std::cmp::Reverse(g.cost));
                summaries.truncate(25);
                let total_groups = message_store.group_count();

                debug.pre_phase4_store_summary(
                    stats.eapol_m1,
                    stats.eapol_m2,
                    stats.eapol_m3,
                    stats.eapol_m4,
                    total_groups,
                    cost_zero,
                    cost_low,
                    cost_medium,
                    cost_heavy,
                );
                debug.top_groups(&summaries, total_groups);
            }

            debug.phase_start(4, "Emit");
        }

        // Single-pass emit over the fully populated stores.
        output_ctx.emit(
            &message_store,
            &pmkid_store,
            &essid_map,
            &akm_map,
            &pair_config,
            thread_count,
            essid_filter,
            &debug,
        )?;

        debug.phase_done(4, "Emit", "");
    }

    let output_stats = output_ctx.finalize(
        &paths,
        &essid_set,
        &probe_essid_set,
        &wordlist_store,
        &scan_ies_store,
        &identity_set,
        &username_set,
        &device_store,
        &mut logger,
    )?;

    // All usize -> u64: u64 subsumes usize on all supported platforms.
    {
        stats.hashes_written = (output_stats.pmkids_written + output_stats.pairs_written) as u64;
        stats.dedup_dropped = output_stats.dedup_dropped as u64;
        // Total pairs attempted through dedup = written + dropped.
        stats.eapol_pairs_generated = (output_stats.pairs_written + output_stats.dedup_dropped) as u64;

        // Per-combo and flag counters from the output pipeline.
        stats.pairs_written_n1e2 = output_stats.n1e2 as u64;
        stats.pairs_written_n3e2 = output_stats.n3e2 as u64;
        stats.pairs_written_n1e4 = output_stats.n1e4 as u64;
        stats.pairs_written_n2e3 = output_stats.n2e3 as u64;
        stats.pairs_written_n4e3 = output_stats.n4e3 as u64;
        stats.pairs_written_n3e4 = output_stats.n3e4 as u64;
        stats.pairs_nc = output_stats.pairs_nc as u64;
        stats.pairs_le = output_stats.pairs_le as u64;
        stats.pairs_be = output_stats.pairs_be as u64;
        stats.nc_dedup_collapsed_lines = output_stats.nc_dedup_collapsed_lines;
        stats.nc_dedup_cluster_count = output_stats.nc_dedup_cluster_count;
        stats.nc_dedup_max_cluster_size = output_stats.nc_dedup_max_cluster_size;
        stats.rc_gap_max = output_stats.rc_gap_max;
        stats.rc_drift_enabled = cli.rc_drift.is_some();
        stats.eapol_pairs_useful = output_stats.pairs_written as u64;
        stats.essid_unresolved_emissions = output_stats.essid_unresolved_emissions;
        stats.essid_unresolved_aps = output_stats.essid_unresolved_aps;

        // Per-sink line / dropped counts for the Phase 4 banner. The fan-out engine
        // writes the same logical hash to every configured sink; counts here are per
        // sink and do not sum to `hashes_written`.
        stats.lines_22000 = output_stats.lines(SinkId::Out22000);
        stats.lines_37100 = output_stats.lines(SinkId::Out37100);
        stats.lines_combined = output_stats.lines(SinkId::OutCombined);
        stats.lines_wpa1 = output_stats.lines(SinkId::OutWpa1);
        stats.lines_wpa2 = output_stats.lines(SinkId::OutWpa2);
        stats.lines_psk_sha256 = output_stats.lines(SinkId::OutPskSha256);
        stats.lines_ft = output_stats.lines(SinkId::OutFt);
        stats.lines_psk_sha384 = output_stats.lines(SinkId::OutPskSha384);
        stats.lines_ft_psk_sha384 = output_stats.lines(SinkId::OutFtPskSha384);
        stats.dropped_22000 = output_stats.dropped(SinkId::Out22000);
        stats.dropped_37100 = output_stats.dropped(SinkId::Out37100);
        stats.dropped_combined = output_stats.dropped(SinkId::OutCombined);
        stats.dropped_wpa1 = output_stats.dropped(SinkId::OutWpa1);
        stats.dropped_wpa2 = output_stats.dropped(SinkId::OutWpa2);
        stats.dropped_psk_sha256 = output_stats.dropped(SinkId::OutPskSha256);
        stats.dropped_ft = output_stats.dropped(SinkId::OutFt);
        stats.dropped_psk_sha384 = output_stats.dropped(SinkId::OutPskSha384);
        stats.dropped_ft_psk_sha384 = output_stats.dropped(SinkId::OutFtPskSha384);

        // Per-hash-type breakdown -- one bucket per row of the 11-type table in
        // `ARCHITECTURE.md §2`. The output pipeline classifies each emitted
        // line via `HashType::from_akm_and_attack`; copy the resulting tally into
        // the global stats for `print_summary`.
        stats.hash_type_emitted = output_stats.hash_type_emitted;
    }

    logger.flush()?;
    stats.fragment_stats.fragments_incomplete = u64::try_from(fragment_store.len()).unwrap_or(u64::MAX);
    stats.print_summary();

    // Optional `--mem-stats` block: per-store byte-count table for OOM triage.
    if cli.mem_stats {
        let rows = wpawolf::mem_stats::collect(
            &message_store,
            &pmkid_store,
            &essid_map,
            &akm_map,
            &mld_store,
            &essid_set,
            &probe_essid_set,
            &wordlist_store,
            &scan_ies_store,
            &identity_set,
            &username_set,
            &device_store,
            &fragment_store,
        );
        wpawolf::mem_stats::print_report(&rows);
    }

    Ok(())
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// Parse a vector of args (binary name prepended) into a Cli, applying any
    /// post-parse fixup `apply_strict_defaults` would normally run in `main`.
    /// Requires a positional INPUT and at least one output flag to satisfy
    /// clap's `required` rules.
    fn parse_with_strict(extra_flags: &[&str]) -> Cli {
        let mut argv: Vec<&str> = vec!["wpawolf", "--22000-out", "out.22000"];
        argv.extend_from_slice(extra_flags);
        argv.push("dummy.pcap");
        let mut cli = Cli::try_parse_from(argv).expect("parse must succeed");
        apply_strict_defaults(&mut cli);
        cli
    }

    #[test]
    fn strict_off_leaves_filters_at_their_defaults() {
        let cli = parse_with_strict(&[]);
        assert!(!cli.strict, "no --strict -> field stays false");
        assert_eq!(cli.eapoltimeout, None, "no --strict -> eapoltimeout stays None (unlimited)");
        assert_eq!(cli.rc_drift, None, "no --strict -> rc_drift stays None (off)");
        assert!(!cli.dedup_hash_combos, "no --strict -> dedup_hash_combos stays off");
        assert!(!cli.per_file, "no --strict -> per_file stays off");
        assert!(!cli.nc_dedup, "no --strict -> nc_dedup stays off");
    }

    #[test]
    fn strict_alone_enables_all_five_bundled_filters() {
        let cli = parse_with_strict(&["--strict"]);
        assert!(cli.strict);
        assert_eq!(cli.eapoltimeout, Some(5), "--strict -> 5 s session window");
        assert_eq!(cli.rc_drift, Some(8), "--strict -> RC drift tolerance 8");
        assert!(cli.dedup_hash_combos, "--strict -> dedup_hash_combos on");
        assert!(cli.per_file, "--strict -> per_file on");
        assert!(cli.nc_dedup, "--strict -> nc_dedup on");
    }

    #[test]
    fn strict_with_explicit_eapoltimeout_preserves_user_value() {
        // Later-flag-wins: explicit --eapoltimeout=30 keeps 30, not the strict 5.
        let cli = parse_with_strict(&["--strict", "--eapoltimeout=30"]);
        assert!(cli.strict);
        assert_eq!(cli.eapoltimeout, Some(30), "explicit user value must override --strict default");
        assert_eq!(cli.rc_drift, Some(8), "untouched filters still take strict defaults");
        assert!(cli.dedup_hash_combos);
        assert!(cli.per_file);
        assert!(cli.nc_dedup);
    }

    #[test]
    fn strict_with_explicit_rc_drift_preserves_user_value() {
        let cli = parse_with_strict(&["--strict", "--rc-drift=4"]);
        assert_eq!(cli.rc_drift, Some(4), "explicit --rc-drift=4 wins over strict's 8");
        assert_eq!(cli.eapoltimeout, Some(5));
        assert!(cli.dedup_hash_combos);
        assert!(cli.per_file);
        assert!(cli.nc_dedup);
    }

    #[test]
    fn strict_with_both_filter_values_keeps_both_user_values() {
        let cli = parse_with_strict(&["--strict", "--eapoltimeout=60", "--rc-drift=2"]);
        assert_eq!(cli.eapoltimeout, Some(60));
        assert_eq!(cli.rc_drift, Some(2));
        assert!(cli.dedup_hash_combos, "strict still enables the three boolean filters");
        assert!(cli.per_file);
        assert!(cli.nc_dedup);
    }

    #[test]
    fn strict_idempotent_with_already_set_bools() {
        // --strict --per-file --dedup-hash-combos --nc-dedup is the same as --strict alone.
        let cli = parse_with_strict(&["--strict", "--per-file", "--dedup-hash-combos", "--nc-dedup"]);
        assert_eq!(cli.eapoltimeout, Some(5));
        assert_eq!(cli.rc_drift, Some(8));
        assert!(cli.dedup_hash_combos);
        assert!(cli.per_file);
        assert!(cli.nc_dedup);
    }

    #[test]
    fn strict_with_explicit_nc_tolerance_preserves_user_value() {
        // --strict folds in --nc-dedup but leaves --nc-tolerance None for the
        // PairConfig default of 8. An explicit --nc-tolerance=4 must survive.
        let cli = parse_with_strict(&["--strict", "--nc-tolerance=4"]);
        assert!(cli.nc_dedup, "--strict still enables nc_dedup");
        assert_eq!(cli.nc_tolerance, Some(4), "explicit --nc-tolerance=4 wins through --strict");
    }

    #[test]
    fn nc_dedup_off_by_default() {
        // Bare wpawolf: --nc-dedup absent -> cli.nc_dedup == false; --nc-tolerance absent
        // -> cli.nc_tolerance == None (Default::default() on the resulting PairConfig
        // substitutes 8 when the flag is later resolved).
        let cli = parse_with_strict(&[]);
        assert!(!cli.nc_dedup, "--nc-dedup absent -> field stays false");
        assert_eq!(cli.nc_tolerance, None, "--nc-tolerance absent -> field stays None");
    }

    #[test]
    fn nc_dedup_flag_sets_field() {
        let cli = parse_with_strict(&["--nc-dedup"]);
        assert!(cli.nc_dedup, "--nc-dedup -> field flips on");
        assert_eq!(cli.nc_tolerance, None, "tolerance still None when only --nc-dedup is given");
    }

    #[test]
    fn nc_tolerance_takes_explicit_value() {
        let cli = parse_with_strict(&["--nc-dedup", "--nc-tolerance=12"]);
        assert!(cli.nc_dedup);
        assert_eq!(cli.nc_tolerance, Some(12));
    }

    #[test]
    fn nc_tolerance_alone_parses_even_without_nc_dedup() {
        // --nc-tolerance is harmless when --nc-dedup is off: PairConfig construction
        // ignores the tolerance when nc_dedup_enabled=false. Parsing must still succeed.
        let cli = parse_with_strict(&["--nc-tolerance=4"]);
        assert!(!cli.nc_dedup);
        assert_eq!(cli.nc_tolerance, Some(4));
    }
}
