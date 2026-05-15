//! `--debug` diagnostic output. See `ARCHITECTURE.md §3` for the pipeline phases referenced here.
//!
//! `DebugPrinter` writes timestamped, phase-annotated lines to stdout. When `enabled = false`
//! every method is a no-op except `memory_check`, which always fires a `[MEMORY WARNING]` line
//! when the system's used-RAM fraction exceeds `MEM_WARN_PCT` (80 %).
//!
//! ## Volume design
//!
//! Large corpora (100k+ groups) produce one debug line per group by default, which bloats
//! output to hundreds of thousands of lines. To stay usable, per-group lines are suppressed
//! unless `cost >= HEAVY_GROUP_COST`; lighter groups are instead captured by a periodic
//! progress ticker (one line every `GROUP_PROGRESS_INTERVAL` groups). The breakdown:
//!
//! | Category | Volume |
//! |---|---|
//! | Phase transitions | ~10 |
//! | Per-file (start + done) | `2 * file_count` |
//! | Per-file memory check | `file_count` |
//! | WDS resolution | 1 |
//! | Pre-Phase-4 summary (tiers + top-25) | ~30 |
//! | Phase 4 progress tickers | `groups / 5000` |
//! | Phase 4 HEAVY groups (start + done + mem) | `3 * heavy_count` |
//! | Capture parse errors | `error_count` |
//!
//! On a 282k-group corpus this yields ~5 500 lines vs 850 000 without filtering.

use std::io::Write as _;
use std::time::Instant;

use crate::types::{MacAddr, MsgType};

// --- Constants ---

/// Fraction of total RAM (0-100) above which `memory_check` always prints, even
/// without `--debug`. Matches the threshold described in the `--debug` help text.
const MEM_WARN_PCT: f64 = 80.0;

/// Groups above this cost get full per-group logging and a `[HEAVY]` flag in the survey.
/// Lighter groups are tallied but not individually logged.
pub const HEAVY_GROUP_COST: u64 = 50_000;

/// Phase 4 progress ticker interval: emit one line every this many completed groups.
const GROUP_PROGRESS_INTERVAL: usize = 5_000;

// --- DebugPrinter ---

/// Diagnostic output driver for `--debug` mode.
///
/// `Send + Sync` (holds only a `bool` and an `Instant`). Safe to share across
/// `std::thread::scope` workers in the parallel Phase 4 path.
#[derive(Debug)]
pub struct DebugPrinter {
    /// `false` = every method except `memory_check` is a no-op.
    pub enabled: bool,
    start: Instant,
}

impl DebugPrinter {
    /// Creates a new printer. When `enabled = false` the instance is essentially free.
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self { enabled, start: Instant::now() }
    }

    fn elapsed(&self) -> f64 {
        self.start.elapsed().as_secs_f64()
    }

    fn emit(&self, line: &str) {
        let t = self.elapsed();
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "[debug {t:9.3}s] {line}");
        let _ = out.flush();
    }

    // --- Phase transitions ---

    /// Logs the start of a pipeline phase with the current RSS.
    pub fn phase_start(&self, num: u8, name: &str) {
        if !self.enabled {
            return;
        }
        let rss = rss_tag();
        self.emit(&format!("=== Phase {num} {name} START ==={rss}"));
    }

    /// Logs the end of a pipeline phase with a detail string and RSS.
    pub fn phase_done(&self, num: u8, name: &str, detail: &str) {
        if !self.enabled {
            return;
        }
        let rss = rss_tag();
        self.emit(&format!("=== Phase {num} {name} DONE  === {detail}{rss}"));
    }

    // --- Phase 1: per-file ---

    /// Logged before a file is opened.
    pub fn file_start(&self, idx: usize, total: usize, path: &str, size_bytes: u64) {
        if !self.enabled {
            return;
        }
        self.emit(&format!("file [{idx:>7}/{total}] START  size={:>10}  {path}", human_bytes(size_bytes)));
    }

    /// Logged after a file finishes. `fmt` is the file format string from `FileMetadata`
    /// (e.g. `"pcap 2.4"`, `"pcapng"`); `dlt` is the link-layer descriptor string.
    pub fn file_done(
        &self,
        idx: usize,
        total: usize,
        path: &str,
        fmt: &str,
        dlt: &str,
        delta_packets: u64,
        delta_eapol: u64,
        delta_pmkid: u64,
        store_groups: usize,
    ) {
        if !self.enabled {
            return;
        }
        let rss = rss_tag();
        self.emit(&format!(
            "file [{idx:>7}/{total}] DONE   pkt={delta_packets:>8} eapol={delta_eapol:>6} pmkid={delta_pmkid:>5}  store_groups={store_groups}  fmt={fmt} dlt={dlt}{rss}  {path}"
        ));
    }

    /// Logs a capture-level parse error (truncated record, corrupt length field, etc.).
    /// These normally go only to `--log`; `--debug` echoes them to stdout so the operator
    /// can correlate with the per-file progress without grepping a separate log file.
    pub fn capture_error(&self, path: &str, reason: &str) {
        if !self.enabled {
            return;
        }
        self.emit(&format!("capture_error  {reason}  [{path}]"));
    }

    // --- Phase 1.5: WDS deferred EAPOL ---

    /// Logged after Phase 1.5 resolves deferred WDS relay frames.
    pub fn wds_resolved(&self, resolved: usize, still_pending: usize) {
        if !self.enabled {
            return;
        }
        self.emit(&format!("WDS deferred EAPOL: {resolved} resolved, {still_pending} unresolvable (no ESSID context)"));
    }

    // --- Pre-Phase-4 store summary ---

    /// Full store breakdown logged immediately before Phase 4 starts.
    ///
    /// Covers: per-type EAPOL totals, cost-tier group counts, saturation drops, and
    /// the top-`n` groups by pairing cost (from `top_groups`). Shows the exact load
    /// Phase 4 is about to process so OOM culprits are visible before the crash.
    #[allow(clippy::too_many_arguments, reason = "store summary: every field is a distinct diagnostic dimension")]
    pub fn pre_phase4_store_summary(
        &self,
        m1_total: u64,
        m2_total: u64,
        m3_total: u64,
        m4_total: u64,
        groups_total: usize,
        cost_zero: usize,
        cost_low: usize,
        cost_medium: usize,
        cost_heavy: usize,
        saturated_dropped: u64,
    ) {
        if !self.enabled {
            return;
        }
        let rss = rss_tag();
        self.emit(&format!(
            "store before Phase 4:  {groups_total} groups  m1={m1_total} m2={m2_total} m3={m3_total} m4={m4_total}{rss}"
        ));
        self.emit(&format!(
            "  cost tiers:  zero={cost_zero}  low(1-999)={cost_low}  medium(1k-49k)={cost_medium}  heavy(>=50k)={cost_heavy}"
        ));
        if saturated_dropped > 0 {
            self.emit(&format!("  per-type cap: {saturated_dropped} frames dropped (--max-eapol-per-type cap hit)"));
        }
    }

    /// Prints the top groups by Phase 4 cost. Call after `pre_phase4_store_summary`.
    pub fn top_groups(&self, groups: &[GroupSummary], store_total: usize) {
        if !self.enabled {
            return;
        }
        self.emit(&format!("  top-{} by cost (of {store_total} total):", groups.len()));
        for (rank, g) in groups.iter().enumerate() {
            let heavy = if g.cost >= HEAVY_GROUP_COST { "  [HEAVY]" } else { "" };
            self.emit(&format!(
                "    {:>4}.  ap={}  sta={}  m1={:>5} m2={:>5} m3={:>4} m4={:>4}  cost={:>12}{heavy}",
                rank + 1,
                g.ap,
                g.sta,
                g.m1,
                g.m2,
                g.m3,
                g.m4,
                g.cost
            ));
        }
    }

    // --- Phase 4: per-group (HEAVY only) and progress ticker ---

    /// Logged before pairing a group. Only emits when `cost >= HEAVY_GROUP_COST`;
    /// lighter groups are captured by the progress ticker instead.
    pub fn group_start(&self, ap: MacAddr, sta: MacAddr, m1: usize, m2: usize, m3: usize, m4: usize, cost: u64) {
        if !self.enabled || cost < HEAVY_GROUP_COST {
            return;
        }
        self.emit(&format!(
            "group ap={ap}  sta={sta}  m1={m1:>5} m2={m2:>5} m3={m3:>4} m4={m4:>4}  cost={cost:>10}  [HEAVY]"
        ));
    }

    /// Logged after pairing a group. Only emits when `cost >= HEAVY_GROUP_COST`.
    pub fn group_done(&self, ap: MacAddr, sta: MacAddr, pairs: usize, elapsed_us: u128, cost: u64) {
        if !self.enabled || cost < HEAVY_GROUP_COST {
            return;
        }
        self.emit(&format!("group ap={ap}  sta={sta}  DONE  {pairs:>8} pairs  {elapsed_us}us  [HEAVY]"));
    }

    /// Periodic progress line emitted every `GROUP_PROGRESS_INTERVAL` completed groups.
    /// `groups_done` is the number of groups completed so far (1-based after the last
    /// increment), `total` is the full group count, `pairs_so_far` is the running pair total.
    pub fn group_progress(&self, groups_done: usize, total: usize, pairs_so_far: usize) {
        if !self.enabled {
            return;
        }
        let rss = rss_tag();
        let pct = groups_done.checked_mul(100).map_or(100, |n| n / total.max(1));
        self.emit(&format!(
            "Phase4 progress  {groups_done:>7}/{total} groups ({pct:>3}%)  {pairs_so_far:>10} pairs{rss}"
        ));
    }

    // --- Memory monitoring ---

    /// Checks system RAM on Linux.
    ///
    /// Always emits `[MEMORY WARNING]` when usage >= `MEM_WARN_PCT`, regardless of
    /// whether `--debug` is set. Below the threshold, emits a regular `[debug]` line only
    /// when `enabled` is true.
    ///
    /// In Phase 4, this is called only for HEAVY groups (not every group) to avoid
    /// flooding the output with 280k memory readings.
    #[allow(
        clippy::must_use_candidate,
        reason = "callers that discard the percentage are fine -- the warning prints as a side effect"
    )]
    pub fn memory_check(&self, context: &str) -> Option<f64> {
        let (total_kb, avail_kb) = ram_info()?;
        let used_kb = total_kb.saturating_sub(avail_kb);
        #[allow(
            clippy::cast_precision_loss,
            reason = "coarse % display; precision loss above multi-TB RAM is irrelevant"
        )]
        let pct = used_kb as f64 / total_kb as f64 * 100.0;
        let used_mib = used_kb / 1024;
        let total_mib = total_kb / 1024;

        if pct >= MEM_WARN_PCT {
            let t = self.elapsed();
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "[MEMORY WARNING {t:.3}s] {used_mib} MiB / {total_mib} MiB ({pct:.1}%) -- {context}");
            let _ = out.flush();
        } else if self.enabled {
            self.emit(&format!("mem  {used_mib} MiB / {total_mib} MiB ({pct:.1}%)  -- {context}"));
        }

        Some(pct)
    }
}

// --- GroupSummary ---

/// Pre-computed per-(AP, STA) group statistics used by the top-groups survey and
/// the pre-Phase-4 cost-tier breakdown in `main.rs`.
#[derive(Debug)]
pub struct GroupSummary {
    /// AP MAC address.
    pub ap: MacAddr,
    /// STA MAC address.
    pub sta: MacAddr,
    /// Number of stored M1 messages.
    pub m1: usize,
    /// Number of stored M2 messages.
    pub m2: usize,
    /// Number of stored M3 messages.
    pub m3: usize,
    /// Number of stored M4 messages.
    pub m4: usize,
    /// Estimated Phase 4 pairing cost (sum of all six N#E# cross-product sizes).
    pub cost: u64,
}

impl GroupSummary {
    /// Builds a `GroupSummary` from a message slice, computing per-type counts and cost.
    #[must_use]
    pub fn from_messages(ap: MacAddr, sta: MacAddr, msgs: &[crate::store::messages::EapolMessage]) -> Self {
        let (mut m1, mut m2, mut m3, mut m4) = (0usize, 0usize, 0usize, 0usize);
        for m in msgs {
            match m.msg_type {
                MsgType::M1 => m1 += 1,
                MsgType::M2 => m2 += 1,
                MsgType::M3 => m3 += 1,
                MsgType::M4 => m4 += 1,
            }
        }
        let cost = (m1 as u64) * (m2 as u64)
            + (m1 as u64) * (m4 as u64)
            + (m3 as u64) * (m2 as u64)
            + (m2 as u64) * (m3 as u64)
            + (m4 as u64) * (m3 as u64)
            + (m3 as u64) * (m4 as u64);
        Self { ap, sta, m1, m2, m3, m4, cost }
    }
}

// --- Platform helpers ---

/// Returns `(MemTotal_kb, MemAvailable_kb)` from `/proc/meminfo` on Linux.
#[cfg(target_os = "linux")]
fn ram_info() -> Option<(u64, u64)> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total = 0u64;
    let mut avail = 0u64;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = rest.split_whitespace().next()?.parse().ok()?;
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            avail = rest.split_whitespace().next()?.parse().ok()?;
        }
        if total > 0 && avail > 0 {
            break;
        }
    }
    if total > 0 { Some((total, avail)) } else { None }
}

#[cfg(not(target_os = "linux"))]
fn ram_info() -> Option<(u64, u64)> {
    None
}

fn rss_tag() -> String {
    crate::progress::current_rss_mib().map_or_else(String::new, |r| format!("  rss={r}MiB"))
}

#[allow(clippy::cast_precision_loss, reason = "coarse display; precision loss above 4 PiB is irrelevant")]
fn human_bytes(bytes: u64) -> String {
    if bytes >= 1 << 30 {
        format!("{:.1}GiB", bytes as f64 / (1u64 << 30) as f64)
    } else if bytes >= 1 << 20 {
        format!("{:.1}MiB", bytes as f64 / (1u64 << 20) as f64)
    } else if bytes >= 1 << 10 {
        format!("{:.1}KiB", bytes as f64 / (1u64 << 10) as f64)
    } else {
        format!("{bytes}B")
    }
}

/// Returns the Phase 4 progress-ticker interval (groups between ticker lines).
#[must_use]
pub const fn group_progress_interval() -> usize {
    GROUP_PROGRESS_INTERVAL
}
