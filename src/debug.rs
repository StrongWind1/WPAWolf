//! `--debug` diagnostic output. See `ARCHITECTURE.md §3` for the pipeline phases referenced here.
//!
//! `DebugPrinter` writes timestamped, phase-annotated lines to stdout. When `enabled = false`
//! every method is a no-op except `memory_check`, which always fires a `[MEMORY WARNING]` line
//! when the system's used-RAM fraction exceeds `MEM_WARN_PCT` (80 %). The per-group Phase 4
//! logging is the primary tool for diagnosing OOM crashes caused by rotating-ANonce captures:
//! it shows every group's message-type breakdown and estimated pairing cost immediately before
//! the allocations that can exhaust memory.

use std::io::Write as _;
use std::time::Instant;

use crate::types::{MacAddr, MsgType};

// --- Constants ---

/// Fraction of total RAM used (0-100) above which `memory_check` always prints.
const MEM_WARN_PCT: f64 = 80.0;

/// Groups with an estimated pairing cost above this threshold get a `[HEAVY GROUP]` marker
/// on the group-start line so they stand out in a long debug trace.
const HEAVY_GROUP_COST: u64 = 50_000;

// --- DebugPrinter ---

/// Diagnostic output driver for `--debug` mode.
///
/// All writes go to stdout via `stdout().lock()` so output is interleaved cleanly
/// with the stats banner even in multi-threaded Phase 4. `DebugPrinter` is `Send + Sync`
/// (only holds a `bool` and an `Instant`) and may be shared across scoped threads.
#[derive(Debug)]
pub struct DebugPrinter {
    /// When `false` all methods except `memory_check` are no-ops.
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

    /// Logs the completion of a pipeline phase with a free-form detail string and RSS.
    pub fn phase_done(&self, num: u8, name: &str, detail: &str) {
        if !self.enabled {
            return;
        }
        let rss = rss_tag();
        self.emit(&format!("=== Phase {num} {name} DONE  === {detail}{rss}"));
    }

    // --- Phase 1: per-file ingestion ---

    /// Logged immediately before a file is opened.
    pub fn file_start(&self, idx: usize, total: usize, path: &str, size_bytes: u64) {
        if !self.enabled {
            return;
        }
        self.emit(&format!("file [{idx:>7}/{total}] START  size={:>10}  {path}", human_bytes(size_bytes)));
    }

    /// Logged after a file finishes, showing delta counts vs the start-of-file baseline.
    pub fn file_done(
        &self,
        idx: usize,
        total: usize,
        path: &str,
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
            "file [{idx:>7}/{total}] DONE   pkt={delta_packets:>8} eapol={delta_eapol:>6} pmkid={delta_pmkid:>5} store_groups={store_groups}{rss}  {path}"
        ));
    }

    // --- Pre-Phase-4: heavy-group survey ---

    /// Prints the top `n` (AP, STA) groups sorted by Phase 4 pairing cost.
    ///
    /// Call this once after Phase 1 completes and before Phase 4 starts. Entries with
    /// cost 0 are excluded (they produce no pairs regardless). Groups above
    /// `HEAVY_GROUP_COST` are flagged `[HEAVY]` so they stand out in the trace.
    pub fn top_groups(&self, groups: &[GroupSummary], store_total: usize) {
        if !self.enabled {
            return;
        }
        let rss = rss_tag();
        self.emit(&format!("top-{} groups by Phase-4 cost (of {store_total} total){rss}:", groups.len()));
        for (rank, g) in groups.iter().enumerate() {
            let heavy = if g.cost >= HEAVY_GROUP_COST { "  [HEAVY]" } else { "" };
            self.emit(&format!(
                "  {:>4}.  ap={}  sta={}  m1={:>6} m2={:>6} m3={:>4} m4={:>4}  cost={:>12}{heavy}",
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

    // --- Phase 4: per-group pairing ---

    /// Logged immediately before pairing a single (AP, STA) group.
    pub fn group_start(&self, ap: MacAddr, sta: MacAddr, m1: usize, m2: usize, m3: usize, m4: usize, cost: u64) {
        if !self.enabled {
            return;
        }
        let heavy = if cost >= HEAVY_GROUP_COST { "  [HEAVY]" } else { "" };
        self.emit(&format!(
            "group ap={ap}  sta={sta}  m1={m1:>5} m2={m2:>5} m3={m3:>4} m4={m4:>4}  cost={cost:>10}{heavy}"
        ));
    }

    /// Logged after pairing completes for a group, including wall-clock time.
    pub fn group_done(&self, ap: MacAddr, sta: MacAddr, pairs: usize, elapsed_us: u128) {
        if !self.enabled {
            return;
        }
        self.emit(&format!("group ap={ap}  sta={sta}  DONE  {pairs:>8} pairs  {elapsed_us}us"));
    }

    // --- Memory monitoring ---

    /// Reads system memory on Linux and either:
    ///   - Always emits `[MEMORY WARNING]` when usage >= `MEM_WARN_PCT`, or
    ///   - Emits a regular `[debug]` memory line when `self.enabled` and below threshold.
    ///
    /// `context` describes what the program is doing at the moment of the check; it is
    /// appended verbatim to the output line so operators can correlate the warning with
    /// the specific phase and group. Returns `Some(pct)` on Linux, `None` elsewhere.
    #[allow(
        clippy::must_use_candidate,
        reason = "callers that ignore the percentage are fine -- the warning prints as a side effect"
    )]
    pub fn memory_check(&self, context: &str) -> Option<f64> {
        let (total_kb, avail_kb) = ram_info()?;
        let used_kb = total_kb.saturating_sub(avail_kb);
        #[allow(
            clippy::cast_precision_loss,
            reason = "coarse percentage display; precision loss at multi-TB RAM is acceptable"
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

/// Pre-computed per-(AP, STA) group statistics for the top-groups display.
///
/// Built by `main.rs` from the fully-populated `MessageStore` using
/// `pair::estimate_group_cost` before Phase 4 starts. Kept separate from
/// `DebugPrinter` to avoid a circular crate dependency between `debug` and `pair`.
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
    /// Estimated Phase 4 pairing cost (sum of all N#E# cross-product sizes).
    pub cost: u64,
}

impl GroupSummary {
    /// Builds a `GroupSummary` from a message slice.
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

/// Reads `MemTotal` and `MemAvailable` from `/proc/meminfo` (Linux).
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

/// Returns `"  rss=NMiB"` if readable, empty string otherwise.
fn rss_tag() -> String {
    crate::progress::current_rss_mib().map_or_else(String::new, |r| format!("  rss={r}MiB"))
}

/// Formats a byte count as a human-readable string (`B`, `KiB`, `MiB`, `GiB`).
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
