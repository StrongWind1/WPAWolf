//! Shared -- binary entry point and Phase 1-5 orchestrator. See ARCHITECTURE.md §3.
//!
//! Parses command-line arguments via `clap`, then runs the two-phase pipeline:
//! Phase 1 collects all EAPOL messages and PMKIDs from every input file into in-memory
//! stores; Phase 2 pairs messages and writes output files. See `ARCHITECTURE.md §3`.
//!
//! Unfiltered by default: all 6 N#E# combinations, 10-minute session window, no
//! replay-counter check. Add output filter flags (`--rc-drift`, `--dedup-hash-combos`) to
//! narrow output to only well-validated hashes. See `ARCHITECTURE.md §8.8 (FR-CLI)`.

#![forbid(unsafe_code)]

// flate2 is used by the library (wpawolf::input::gzip). The binary does not import it
// directly, so suppress the unused_crate_dependencies lint with the `as _` form.
use flate2 as _;

use clap::Parser;

use wpawolf::{
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
/// Reads pcap, pcapng, and gzip-compressed captures. Unfiltered by default:
/// all 6 N#E# combinations, 10-minute session window, no replay-counter check.
/// Invalid nonce/MIC/PMKID values (all-zero or all-0xFF) are always rejected.
/// Use output filter flags to further narrow the output.
#[derive(Parser, Debug)]
#[command(
    name = "wpawolf",
    version,
    about,
    long_about = None,
    arg_required_else_help = true,
)]
#[allow(clippy::struct_excessive_bools, reason = "independent CLI flags, not a state machine")]
struct Cli {
    /// Input capture file(s) and/or director(ies)
    ///
    /// Each positional argument may be either a capture file (pcap, pcapng, or
    /// gzip-compressed) or a directory. Directories are walked recursively and
    /// every regular file is opened, its first 4 bytes inspected, and included
    /// only if those bytes match a supported capture-file magic -- file
    /// extensions are never consulted. Accepted magics: pcap microsecond
    /// (`0xA1B2C3D4`), pcap nanosecond (`0xA1B23C4D`), pcap Kuznetzov
    /// (`0xA1B2CD34`), IXIA `lcap` HW (`0x1C0001AC`, nanosecond), IXIA `lcap`
    /// SW (`0x1C0001AB`, microsecond) -- each in either byte order; pcapng SHB
    /// (`0x0A0D0D0A`, byte-order-independent palindrome); and gzip
    /// (`0x1F 0x8B`). Within each directory, files are processed in sorted
    /// order, then subdirectories are descended in sorted order; symlinks are
    /// not followed.
    #[arg(required = true, value_name = "INPUT")]
    input_files: Vec<std::path::PathBuf>,

    // --- Output files (hash sinks) ---
    //
    // The legacy hashcat-compatible sinks (`--22000-out`, `--37100-out`) emit the
    // 4-prefix scheme `WPA*01*..WPA*04*` so the output remains drop-in for hashcat
    // modes 22000 / 37100. The taxonomy sinks (`--wpa1-out`, `--wpa2-out`, ...,
    // `-o`) emit the 11-type prefix scheme `WPA*01*..WPA*11*` from
    // `ARCHITECTURE.md §2`. The same logical hash is fanned out to every
    // configured sink with the appropriate per-sink prefix and per-sink dedup.
    /// hashcat mode 22000 file (legacy WPA*01* PMKID, WPA*02* EAPOL)
    ///
    /// Receives every non-FT emitted hash. Hashcat-compatible.
    #[arg(long = "22000-out", value_name = "FILE")]
    out_22000: Option<std::path::PathBuf>,

    /// hashcat mode 37100 file (legacy WPA*03* PMKID, WPA*04* EAPOL)
    ///
    /// Receives every FT emitted hash. Hashcat-compatible.
    #[arg(long = "37100-out", value_name = "FILE")]
    out_37100: Option<std::path::PathBuf>,

    /// 11-type taxonomy combined output (every emitted hash, prefix WPA*01*..WPA*11*)
    ///
    /// Operator-facing format; not directly hashcat-readable today.
    #[arg(short = 'o', long = "out", value_name = "FILE")]
    out_combined: Option<std::path::PathBuf>,

    /// type 1 only: WPA1-PSK-EAPOL (taxonomy format)
    #[arg(long = "wpa1-out", value_name = "FILE")]
    out_wpa1: Option<std::path::PathBuf>,

    /// types 2 + 3: WPA2-PSK-PMKID and WPA2-PSK-EAPOL (taxonomy format)
    #[arg(long = "wpa2-out", value_name = "FILE")]
    out_wpa2: Option<std::path::PathBuf>,

    /// types 4 + 5: PSK-SHA256-PMKID and PSK-SHA256-EAPOL (taxonomy format)
    #[arg(long = "psk-sha256-out", value_name = "FILE")]
    out_psk_sha256: Option<std::path::PathBuf>,

    /// types 6 + 7: FT-PSK-PMKID and FT-PSK-EAPOL (taxonomy, with FT extra fields)
    #[arg(long = "ft-out", value_name = "FILE")]
    out_ft: Option<std::path::PathBuf>,

    /// types 8 + 9: PSK-SHA384-PMKID and PSK-SHA384-EAPOL (taxonomy format)
    #[arg(long = "psk-sha384-out", value_name = "FILE")]
    out_psk_sha384: Option<std::path::PathBuf>,

    /// types 10 + 11: FT-PSK-SHA384-PMKID and FT-PSK-SHA384-EAPOL (taxonomy, FT extras)
    #[arg(long = "ft-psk-sha384-out", value_name = "FILE")]
    out_ft_psk_sha384: Option<std::path::PathBuf>,

    /// output ESSID wordlist (autohex) from all AP management frames
    ///
    /// Beacons, Probe Responses, Association/Reassociation Requests, FILS Discovery,
    /// OWE Transition, Cisco CCX1, vendor AP names. Format: plain ASCII or $HEX[...].
    #[arg(short = 'E', long)]
    essid_output: Option<std::path::PathBuf>,

    /// output ESSID wordlist (autohex) from Probe Request frames only
    ///
    /// Directed Probe Requests (IE#0 SSID), Probe Request SSID List IE (IE#84),
    /// and Action Neighbor Report Request frames. Same format as -E.
    #[arg(short = 'R', long)]
    probe_output: Option<std::path::PathBuf>,

    /// output combined wordlist: ESSIDs, Probe ESSIDs, WPS strings, EAP identities, and more
    ///
    /// Superset of -E and -R: also includes WPS device strings (manufacturer, model,
    /// serial, device name from both AP and STA WPS IEs), EAP identity bytes,
    /// country codes, time zones, mesh IDs, vendor AP names, OWE Transition SSIDs.
    /// Useful as a targeted password candidate list for hashcat.
    #[arg(short = 'W', long)]
    wordlist_output: Option<std::path::PathBuf>,

    /// output EAP identity list (autohex format, sorted)
    ///
    /// EAP-Response/Identity strings per RFC 3748 §5.1. Non-ASCII bytes are
    /// hex-encoded as $HEX[...].
    #[arg(short = 'I', long)]
    identity_output: Option<std::path::PathBuf>,

    /// output EAP username list (autohex format, sorted)
    ///
    /// EAP peer identity strings from inner methods (`MSCHAPv2`, `LEAP`, etc.).
    /// Non-ASCII bytes are hex-encoded as `$HEX[...]`.
    #[arg(short = 'U', long)]
    username_output: Option<std::path::PathBuf>,

    /// output WPS device info list
    ///
    /// Format (tab-separated): `MAC MANUFACTURER MODEL SERIAL DEVICENAME [UUID] ESSID`.
    /// Sorted by manufacturer. Deduplicated by AP MAC.
    #[arg(short = 'D', long)]
    device_output: Option<std::path::PathBuf>,

    /// output logfile (malformed frames, link-layer errors, sentinel rejections, ...)
    ///
    /// Eleven categories: `malformed_frame` (truncated or structurally invalid 802.11
    /// / EAPOL data), `plcp_error` (link-layer header validation failed -- radiotap /
    /// PPI / Prism / AVS error, or an unsupported DLT), `unknown_linktype` (pcapng
    /// EPB referenced an `interface_id` with no preceding IDB), `unknown_akm`
    /// (suite outside [IEEE 802.11-2024] Table 9-190), `essid_not_found_summary`
    /// (per-AP summary of hash lines dropped because no SSID was observed for the
    /// AP -- carries `dropped`, `first_seen_us`, `last_seen_us`),
    /// `capture_read_error` (per-file ingest failure -- typically a truncated
    /// trailing packet), `skipped_input` (input file whose magic bytes did not
    /// match any supported capture format -- typically a sub-4-byte stub left in a
    /// watch directory; counted but silenced on stderr), `invalid_nonce` /
    /// `invalid_mic` / `invalid_pmkid` (NULL, all-`0xFF`, or short-period
    /// repeating-byte garbage rejected at extract time -- nonces and MICs from
    /// the EAPOL Key parser, PMKIDs from every PMKID-bearing IE; each line
    /// ends with `nonce_hex=` / `mic_hex=` / `pmkid_hex=` carrying the
    /// rejected bytes in lowercase hex so an operator can grep the source
    /// capture for the exact sequence), `essid_control_bytes` (warning, not
    /// a discard: SSID body contained at least one byte in the ASCII C0
    /// control range `0x00..=0x1F` -- the SSID is still stored and emitted,
    /// the line carries `essid_hex=` in lowercase hex so an operator can
    /// audit the source frame). Per-category field layout matches
    /// `src/log.rs`: frame-bearing categories lead with `timestamp_us`,
    /// others (e.g. `unknown_akm`, `essid_not_found_summary`) carry only the
    /// event-specific field(s).
    #[arg(long)]
    log: Option<std::path::PathBuf>,

    // --- Output filters ---
    /// [output filter] maximum EAPOL session window in seconds
    ///
    /// Three states with explicit semantics:
    ///   * flag absent       -> unlimited (no time filter, the wpawolf default)
    ///   * `--eapoltimeout`  -> 600-second window (10-minute default)
    ///   * `--eapoltimeout=N` -> custom N-second window
    ///
    /// Two EAPOL messages more than this many seconds apart cannot form a pair and are
    /// discarded. hcxpcapngtool default is ~3 seconds (`--eapoltimeout=3`).
    ///
    /// Bare-flag note: clap parses this as an optional-positional, so the bare form
    /// (no `=N`) needs another `--`-prefixed flag to follow before any positional
    /// argument. `wpawolf --eapoltimeout capture.pcap` fails with exit 2 because clap
    /// tries to consume `capture.pcap` as the timeout value. Use `--eapoltimeout=`
    /// (explicit empty `=`) or place another flag in between, e.g.
    /// `wpawolf --eapoltimeout --22000-out hashes.22000 capture.pcap`.
    #[arg(long, num_args = 0..=1, default_missing_value = "600")]
    eapoltimeout: Option<u64>,

    /// [output filter] discard pairs whose replay-counter deviates by more than N
    ///
    /// Three states with explicit semantics:
    ///   * flag absent     -> off (all pairs pass regardless of RC values, the wpawolf default)
    ///   * `--rc-drift`    -> tolerance 8 (the bare-flag default)
    ///   * `--rc-drift=N`  -> custom tolerance N
    ///
    /// The Replay Counter (RC) is a 64-bit sequence number the AP increments for each
    /// EAPOL-Key frame to prevent message replay. In a clean handshake each message pair
    /// has a predictable RC relationship: M1/M2 share the same RC, M3 is RC+1. RC drift
    /// occurs when buggy AP firmware does not increment the counter correctly across frames.
    /// When the filter is on, pairs where `|actual_delta - expected_delta| > N` are
    /// discarded.
    ///
    /// Not to be confused with hashcat `--nonce-error-corrections`: that flag adjusts
    /// the ANonce/SNonce *bytes* during cracking to compensate for firmware that mutates
    /// the nonce between M1 and M3. RC drift is in the EAPOL-Key header sequence field
    /// only -- it has no effect on the nonce bytes and is not used in key derivation.
    ///
    /// Bare-flag note: same clap optional-positional gotcha as `--eapoltimeout`. The
    /// bare form (no `=N`) needs another `--`-prefixed flag to follow before any
    /// positional argument; otherwise clap consumes the trailing positional as the
    /// drift value and fails with exit 2. Use `--rc-drift=` or
    /// `--rc-drift --22000-out hashes.22000 capture.pcap`.
    #[arg(long, num_args = 0..=1, default_missing_value = "8")]
    rc_drift: Option<u8>,

    /// opt-in IE-scan output: printable-ASCII runs from plaintext management IE bodies
    ///
    /// When set, every plaintext Beacon / Probe / Assoc / Reassoc / Action frame's IE
    /// values are scanned for contiguous runs of `0x20..=0x7E` bytes of length >= 8,
    /// and each unique run is written to FILE (autohex-trim format, sorted). Data frames
    /// are never scanned.
    ///
    /// Output goes **only** to FILE; runs are no longer folded into `-W`. To get both
    /// streams in one file, point `-W` and `--wordlist-scan-ies` at the same path.
    /// `-W` therefore stays a curated wordlist (ESSIDs, WPS, EAP, country, vendor
    /// names) while the IE-scan strand is a wider, noisier net for vendor IE bodies
    /// wpawolf does not parse structurally. See `ARCHITECTURE.md §9`.
    #[arg(long = "wordlist-scan-ies", value_name = "FILE")]
    wordlist_scan_ies: Option<std::path::PathBuf>,

    /// [output filter] only collapse SSID variants when an AP has more than N SSIDs (default 3)
    ///
    /// One AP can show up under several SSID names: a few legitimately (dual-band
    /// routers, segmented rollouts), and more rarely many at once when noisy RF
    /// flips bits in beacon bodies and each corrupted variant decodes to a
    /// different SSID. This flag is the gate for the collapse: APs whose recorded
    /// SSID count is N or fewer always ship every SSID unchanged. Raise to keep
    /// more SSIDs (e.g. `--essid-collapse-min 16` for CTF-style APs that broadcast
    /// many real SSIDs); pair with `--essid-collapse-ratio 1` to disable the
    /// collapse entirely. See README "When one AP shows up under many SSIDs"
    /// and `ARCHITECTURE.md §9`.
    #[arg(long = "essid-collapse-min", value_name = "N", default_value_t = 3)]
    essid_collapse_min: usize,

    /// [output filter] collapse to the most-seen SSID when it appears N times more often than the runner-up (default 10)
    ///
    /// Once an AP passes `--essid-collapse-min`, the most-seen and second-most-seen
    /// SSIDs are compared: if the top count is at least N times the runner-up's,
    /// only the top SSID is written; otherwise every SSID is written. RF-corrupted
    /// APs in the wild show top counts of thousands against runner-ups of single
    /// digits (well above the default 10x), while genuinely multi-network APs
    /// stay within an order of magnitude of 1. Set below 2 to disable. See README
    /// "When one AP shows up under many SSIDs" and `ARCHITECTURE.md §9`.
    #[arg(long = "essid-collapse-ratio", value_name = "N", default_value_t = 10)]
    essid_collapse_ratio: u64,

    /// [output filter] deduplicate equivalent N#E# hash combos within each session
    ///
    /// Two states (boolean flag, no argument):
    ///   * flag absent          -> off (all 6 combos written, the wpawolf default)
    ///   * `--dedup-hash-combos` -> on (collapse to the 3 cryptographically unique combos)
    ///
    /// A complete 4-way handshake yields up to 6 hash combinations (N1E2, N1E4,
    /// N3E2, N2E3, N4E3, N3E4), but at most 3 are cryptographically unique for
    /// cracking: combos that share the same nonce bytes and EAPOL frame produce
    /// identical hashcat lines and need only appear once.
    ///
    /// When set, combos are grouped by (nonce, EAPOL frame) and only the best is
    /// kept per group. Survivor chosen by smallest RC gap (exact match preferred),
    /// then authorized combo priority (N3E2 > N1E2, N2E3 > N4E3, N3E4 > N1E4).
    /// Useful in noisy captures where one combo may survive a packet drop that
    /// would eliminate another.
    #[arg(long)]
    dedup_hash_combos: bool,

    /// [output filter] collapse near-identical-nonce siblings to one survivor
    ///
    /// Two states (boolean flag, no argument):
    ///   * flag absent   -> off (every observed nonce ships as its own line, the wpawolf default)
    ///   * `--nc-dedup`  -> on (collapse per (AP, STA, EAPOL frame, MIC, combo) cluster
    ///     to a single survivor with `FLAG_NC` set in the `message_pair` byte)
    ///
    /// Some firmware emits dozens of WPA*02* lines for one (AP, STA) that share the
    /// same MIC and EAPOL frame and differ only in the trailing bytes of the
    /// `ANonce`. Hashcat with the default `--nonce-error-corrections=8` recovers all
    /// of them from one representative line by iterating `+/- 4` on the trailing
    /// byte at MIC-verify time, but only if wpawolf emits the representative tagged
    /// with `FLAG_NC` (`0x80`). This flag enables that clustering pass.
    ///
    /// Cluster scope: pairs share `(AP, STA, EAPOL frame, MIC, combo_type)` and the
    /// first 28 bytes of the nonce; the trailing 4 bytes must fit within
    /// `--nc-tolerance` (default 8). Survivor is the sorted-median observed nonce so
    /// hashcat's symmetric iteration covers the full cluster span. LE / BE
    /// orientation is auto-detected per cluster and reflected in `FLAG_LE` / `FLAG_BE`.
    ///
    /// See `ARCHITECTURE.md §5.8.1` for the algorithm and IEEE 802.11-2024 §12.7.2
    /// NOTE 9 for the protocol-level justification (RC is a performance optimization,
    /// not a security primitive).
    #[arg(long)]
    nc_dedup: bool,

    /// [output filter] cluster span tolerance for `--nc-dedup` (default: 8)
    ///
    /// Maximum `max - min` on the trailing 4 bytes of the nonce within one cluster.
    /// Default 8 matches hashcat's `NONCE_ERROR_CORRECTIONS=8`, so the symmetric
    /// `survivor +/- 4` iteration on the cracker side covers the full cluster span
    /// when the survivor sits at the sorted-median index. Higher values collapse
    /// more aggressively but require a matching `--nonce-error-corrections=N` on the
    /// hashcat side; lower values are safe with smaller hashcat NC budgets at the
    /// cost of more representative lines per cluster. Ignored unless `--nc-dedup`
    /// is also set.
    #[arg(long, value_name = "N")]
    nc_tolerance: Option<u8>,

    // --- Misc ---
    /// number of pairing threads [default: available CPU count]
    ///
    /// Sets the Phase 2 worker thread count for parallel pairing. Groups are assigned
    /// via LPT (Longest Processing Time First) round-robin scheduling. Use `--threads=1`
    /// to reproduce single-threaded behavior.
    #[arg(long)]
    threads: Option<u16>,

    /// suppress periodic `[progress]` lines on stderr
    ///
    /// Progress lines are emitted by default during Phase 1 (Ingest) every 5 seconds
    /// (whichever fires first: wall-clock cadence or every 2M packets). They report
    /// elapsed time, files processed, packets seen, EAPOL messages stored, and
    /// PMKIDs found. The closing Phase 1-5 stats banner is unaffected by this flag --
    /// only the running progress lines are suppressed.
    ///
    /// Use for scripted / piped runs where progress lines would contaminate the
    /// output stream. Operators driving wpawolf interactively should leave this off.
    #[arg(long)]
    quiet: bool,

    /// emit a per-store memory-footprint table at end of run
    ///
    /// Adds one closing block to stderr listing approximate byte counts for every
    /// long-lived in-memory store (EAPOL groups, PMKID store, ESSID map, auxiliary
    /// sets, ...). Useful for triaging OOM behaviour on multi-GB corpus runs --
    /// the dominant grower shows up at the top of the sorted table.
    ///
    /// Approximations only: `HashMap` overhead is estimated as
    /// `capacity * (entry_size + 8 B)`, `Vec` heap as capacity not len. The goal
    /// is identifying outliers, not page-accurate accounting.
    #[arg(long)]
    mem_stats: bool,

    /// pair + emit hashes after each input file, clearing per-file stores in between
    ///
    /// Trades cross-file pairing for bounded memory: `MessageStore` and `PmkidStore`
    /// are flushed after every file. EAPOL handshakes that span files (e.g. M1/M2 in
    /// file A, M3/M4 in file B) will not pair. Hash sinks stay open across files;
    /// dedup state, auxiliary outputs (`-E` / `-W` / ...), `EssidMap` (so SSIDs
    /// observed in earlier files still resolve later hashes), `AkmMap`, and
    /// `MldStore` accumulate across the run.
    ///
    /// Useful for corpora where each capture is self-contained (wpa-sec uploads,
    /// per-session captures). Expected hash-yield delta versus a full run is < 1%
    /// on those workloads. See `ARCHITECTURE.md §3` for the cross-file tradeoff.
    #[arg(long = "per-file")]
    per_file: bool,

    /// shortcut for a hcxpcapngtool-like narrow output profile
    ///
    /// One flag turns on the five output filters that together produce roughly
    /// hcxpcapngtool-shape output from wpawolf's WIDE default: `--eapoltimeout=5`
    /// (5-second EAPOL session window, matches hcxpcapngtool's `EAPOLTIMEOUT`
    /// default), `--rc-drift=8` (replay-counter drift tolerance 8), `--dedup-hash-combos`
    /// (collapse the 6 N#E# combos to 3 cryptographically unique ones per session),
    /// `--per-file` (no cross-file pairing), and `--nc-dedup` (cluster
    /// near-identical-nonce siblings to one survivor with `FLAG_NC` set for
    /// hashcat NC-iteration recovery).
    ///
    /// Later-flag-wins conflict semantics: an explicit `--eapoltimeout=30` after
    /// `--strict` keeps the explicit 30; an explicit `--rc-drift=4` overrides the
    /// strict default of 8; an explicit `--nc-tolerance=4` overrides the strict
    /// default of 8. The three boolean flags (`--dedup-hash-combos`, `--per-file`,
    /// `--nc-dedup`) can only be turned on, not off, so `--strict` always enables them.
    ///
    /// Use this when you want hashcat-friendly density and accept the small
    /// hash-yield drop (~1% on wpa-sec-shape corpora). The bare wpawolf default
    /// stays wide -- this flag is the discoverable opt-in for the narrow-output
    /// behaviour that hcxpcapngtool ships by default.
    #[arg(long)]
    strict: bool,
}

/// Maximum `[out_of_sequence_timestamp]` lines logged per input file. Beyond this
/// the run-wide counter still ticks but the log file stays quiet to avoid
/// flooding on tampered captures.
const OOS_LOG_CAP_PER_FILE: u32 = 10;

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
        || cli.wordlist_scan_ies.is_some();
    if !has_output {
        eprintln!(
            "error: no output specified (use --22000-out, --37100-out, -o/--out, --wpa1-out, --wpa2-out, --psk-sha256-out, --ft-out, --psk-sha384-out, --ft-psk-sha384-out, -E, -R, -W, -I, -U, -D, or --wordlist-scan-ies)"
        );
        eprintln!("Run with --help for usage.");
        std::process::exit(1);
    }

    if let Err(e) = run(&cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

// --- Pipeline ---

/// Runs the full two-phase (Collect + Output) pipeline.
///
/// Phase 1 iterates every input file, dispatches management and data frames to their
/// respective collectors, and populates all in-memory stores. Phase 2 pairs EAPOL
/// messages, deduplicates, and writes all requested output files. Returns `Err` only
/// for I/O failures that should abort the run -- parse errors are logged and skipped.
#[allow(clippy::too_many_lines, reason = "linear pipeline orchestrator; each step is small but cumulative")]
fn run(cli: &Cli) -> wpawolf::types::Result<()> {
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
        scan_ies: cli.wordlist_scan_ies.is_some(),
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
        wordlist_scan_ies: cli.wordlist_scan_ies.clone(),
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
    for path in &inputs {
        stats.last_file = path.display().to_string();

        let mut reader = match input::open_reader(path) {
            Ok(r) => r,
            Err(e) => {
                // Route unrecognised-magic files through the log sink instead of stderr:
                // the corpus-scale failure mode (wpa-sec watch dir leaving sub-4-byte
                // stubs behind) is "expected garbage", not "operator-affecting error".
                // Genuine I/O failures (permission denied, disk error) still surface on
                // stderr so a runaway run doesn't silently misbehave.
                if matches!(e, wpawolf::types::Error::UnknownFormat(_)) {
                    stats.files_skipped_unknown_format += 1;
                    logger.log_skipped_input(path, &e.to_string());
                } else {
                    eprintln!("warning: cannot open {}: {e}", path.display());
                }
                continue;
            },
        };

        // Populate file metadata from the reader. Histograms aggregate across
        // every input file so a directory walk can report a count + format /
        // endian / DLT distribution rather than only the last file's values.
        stats.input_file_count += 1;
        let meta = reader.file_metadata();
        *stats.file_formats_seen.entry(meta.format).or_insert(0) += 1;
        *stats.endians_seen.entry(meta.endian.to_owned()).or_insert(0) += 1;
        *stats.dlt_descs_seen.entry(meta.dlt_desc).or_insert(0) += 1;

        // Per-file timestamp sequence tracker. A monotonic increase is what any
        // well-behaved capture tool produces; inversions almost always indicate
        // post-processed input (aircrack-ng deadly-clean, mergecap with
        // --strict-time-stamps=false, hand edit). wpawolf processes the packet
        // normally either way; the counter + log line exist only so an operator
        // triaging a corpus can identify which captures have been touched.
        // Matches hcxpcapngtool 7.1.2's "Warning: out of sequence timestamps!".
        // `OOS_LOG_CAP_PER_FILE` is declared at module scope (see below) to
        // satisfy `clippy::items_after_statements`.
        let mut prev_ts_us: u64 = 0;
        let mut oos_logged_this_file: u32 = 0;

        loop {
            match reader.next_packet() {
                Ok(Some(packet)) => {
                    stats.total_packets += 1;
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
                        if oos_logged_this_file < OOS_LOG_CAP_PER_FILE {
                            logger.log_out_of_sequence_timestamp(path, prev_ts_us, packet.timestamp_us);
                            oos_logged_this_file += 1;
                        }
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
                    // Capture the underlying error (unsupported DLT vs truncated radiotap
                    // header etc.) so `[plcp_error]` log entries are diagnostic, not
                    // a generic "link strip failed".
                    if link::has_ampdu_status(&packet.data, dlt) {
                        stats.ampdu_status_frames += 1;
                    }
                    let frame_data = match link::strip(&packet.data, dlt) {
                        Ok((d, had_fcs)) => {
                            if had_fcs {
                                stats.fcs_stripped_frames += 1;
                            }
                            d
                        },
                        Err(e) => {
                            stats.link_errors += 1;
                            logger.log_plcp_error(
                                packet.timestamp_us,
                                packet.interface_id,
                                &format!("link strip failed: {e}"),
                            );
                            continue;
                        },
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
                            logger.log_malformed_frame(
                                packet.timestamp_us,
                                packet.interface_id,
                                &format!("{reason} (len={})", frame_data.len()),
                            );
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
                    break;
                },
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
        resolve_wds_eapol(
            &pending_eapol,
            &essid_map,
            &mut akm_map,
            &mut message_store,
            &mut pmkid_store,
            &mut stats,
            &mut logger,
        );
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

        // Single-pass emit over the fully populated stores.
        output_ctx.emit(
            &message_store,
            &pmkid_store,
            &essid_map,
            &akm_map,
            &pair_config,
            thread_count,
            essid_filter,
        )?;
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
