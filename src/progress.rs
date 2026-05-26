//! Phase 1 -- periodic stderr progress reporter. See `ARCHITECTURE.md §3.1`.
//!
//! Emits one `[progress]` line per cadence interval during the Phase 1 ingest
//! loop so an operator running wpawolf against a multi-hour corpus has a live
//! pulse of where the run is. Greppable line prefix (`[progress]`); fields are
//! space-separated `key=value` pairs:
//!
//! `[progress] elapsed=<s> files=<n> packets=<n> eapol=<n> pmkids=<n> rss=<n>MiB`
//!
//! `rss` is populated via `sysinfo` (cross-platform: Linux, macOS, Windows).
//! The closing Phase 1-5 stats banner is unaffected by this reporter.
//!
//! Cadence is hybrid: every 5 seconds **or** every 2 000 000 packets, whichever
//! fires first. The packet check guards against single-file runs where wall
//! clock progress is dominated by I/O bursts; the wall clock guards against
//! tiny-packet runs where 2M packets fly past in well under 5 s.
//!
//! Suppress entirely with `--quiet` -- intended for piped / scripted contexts
//! where progress lines would contaminate downstream tools.

use std::fmt::Write as _;
use std::io::Write as _;
use std::time::Instant;

// --- Cadence thresholds ---

/// Elapsed seconds between forced progress prints.
///
/// 5 s is short enough that a stuck run is obvious quickly and long enough that
/// a healthy run does not flood the operator's terminal. Matches hcxpcapngtool's
/// default "still alive" pulse.
const ELAPSED_SECS_THRESHOLD: u64 = 5;

/// Packet count delta between forced progress prints.
///
/// 2M is roughly one fast HDD-rate second of small-packet ingest, so the packet
/// check fires *before* the wall clock for a healthy run and we get a smooth
/// stream of updates rather than a 5 s pulse-only cadence.
const PACKETS_THRESHOLD: u64 = 2_000_000;

/// Packet-count interval between wall-clock checks.
///
/// When `packet_delta < PACKETS_THRESHOLD` we must consult `Instant::elapsed()`
/// to enforce the 5-second cadence, but calling it on every packet is a
/// `clock_gettime` vDSO syscall that costs ~5% CPU on a 71M-packet corpus.
/// Only probe the clock once per this many packets; at typical ingest rates
/// 100k packets takes ~50 ms, well within the 5-second print window.
const CLOCK_CHECK_INTERVAL: u64 = 100_000;

/// Stderr-bound periodic progress reporter for the Phase 1 ingest loop.
///
/// Construct once before the loop starts; call `tick` once per packet (cheap;
/// most calls return without doing anything) and `print_now` at the end of
/// Phase 1 so the operator always sees a final progress line just before the
/// closing banner. Created with `enabled=false` (i.e. `--quiet`) the struct
/// becomes a no-op shell -- every method short-circuits.
#[derive(Debug)]
pub struct ProgressReporter {
    /// `false` collapses every method into a no-op (driven by the `--quiet`
    /// flag). The struct still exists so the call sites stay branch-free.
    enabled: bool,
    /// Run start instant; used to compute the `elapsed=` field.
    start: Instant,
    /// Most recent print instant; used for the wall-clock cadence check.
    last_print: Instant,
    /// Packet count at the most recent print; used for the packet cadence
    /// check. `0` until the first print so the first 2M packets count from
    /// run start.
    last_print_packets: u64,
}

impl ProgressReporter {
    /// Builds a new reporter. Pass `enabled=false` to make every method a no-op
    /// (this is what `--quiet` resolves to).
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        let now = Instant::now();
        Self { enabled, start: now, last_print: now, last_print_packets: 0 }
    }

    /// Cadence check + emit. Call once per ingested packet; the body
    /// short-circuits on the cheap path (one comparison per call) so the
    /// per-packet overhead is essentially zero.
    ///
    /// `total_packets` is the running ingest counter (`stats.total_packets`).
    /// The other fields are running per-store counts surfaced in the line.
    pub fn tick(&mut self, total_packets: u64, files: u64, eapol: u64, pmkids: u64) {
        if !self.enabled {
            return;
        }
        // Hybrid cadence: emit when EITHER threshold fires first.
        // The packet check is a u64 subtract -- effectively free. The wall-clock
        // check is a syscall on most platforms, so only consult it when the
        // packet delta is below threshold (avoids the syscall on the hot path).
        let packet_delta = total_packets.saturating_sub(self.last_print_packets);
        if packet_delta < PACKETS_THRESHOLD
            && (!packet_delta.is_multiple_of(CLOCK_CHECK_INTERVAL)
                || self.last_print.elapsed().as_secs() < ELAPSED_SECS_THRESHOLD)
        {
            return;
        }
        self.emit(total_packets, files, eapol, pmkids);
    }

    /// Forced emit: prints a progress line immediately if the reporter is
    /// enabled. Used at the very end of Phase 1 so there is always one line
    /// just before the closing stats banner -- an operator who ran a small
    /// fixture and Ctrl-C'd at exit still sees the final state.
    pub fn print_now(&mut self, total_packets: u64, files: u64, eapol: u64, pmkids: u64) {
        if self.enabled {
            self.emit(total_packets, files, eapol, pmkids);
        }
    }

    /// Internal: format and write the line, then update bookkeeping.
    fn emit(&mut self, total_packets: u64, files: u64, eapol: u64, pmkids: u64) {
        let elapsed_s = self.start.elapsed().as_secs();
        let mut line = format!(
            "[progress] elapsed={elapsed_s}s files={files} packets={total_packets} eapol={eapol} pmkids={pmkids}"
        );
        if let Some(rss) = current_rss_mib() {
            // write! to String never fails; suppress the Result.
            let _ = write!(line, " rss={rss}MiB");
        }
        let mut out = std::io::stdout().lock();
        let _ = writeln!(out, "{line}");
        let _ = out.flush();

        self.last_print = Instant::now();
        self.last_print_packets = total_packets;
    }
}

/// Returns the current process's resident set size in bytes, or 0 when the
/// platform probe fails. Cross-platform via `sysinfo`.
#[must_use]
pub fn current_rss_bytes() -> u64 {
    let Ok(pid) = sysinfo::get_current_pid() else { return 0 };
    let mut sys = sysinfo::System::new();
    let refresh = sysinfo::ProcessRefreshKind::nothing().with_memory();
    sys.refresh_processes_specifics(sysinfo::ProcessesToUpdate::Some(&[pid]), false, refresh);
    sys.process(pid).map_or(0, sysinfo::Process::memory)
}

/// Returns the current process's RSS in MiB, or `None` when the probe fails.
#[must_use]
pub fn current_rss_mib() -> Option<u64> {
    let bytes = current_rss_bytes();
    if bytes > 0 { Some(bytes / (1024 * 1024)) } else { None }
}

/// Returns the total physical RAM in bytes. Cross-platform via `sysinfo`.
#[must_use]
pub fn total_ram_bytes() -> u64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory_specifics(sysinfo::MemoryRefreshKind::nothing().with_ram());
    sys.total_memory()
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
    fn disabled_reporter_does_not_emit_anything_under_threshold() {
        // Smoke: a disabled reporter must not panic and must short-circuit `tick`.
        let mut r = ProgressReporter::new(false);
        r.tick(0, 0, 0, 0);
        r.tick(10_000, 1, 0, 0);
        r.print_now(20_000, 2, 5, 1);
        // No assertion on stderr -- the disabled branch should write nothing.
    }

    #[test]
    fn enabled_reporter_short_circuits_under_packet_threshold() {
        // Below the 2M-packet cadence the reporter must NOT emit anything.
        // We can't easily capture stderr, but we can assert no panic and the
        // bookkeeping fields don't move.
        let mut r = ProgressReporter::new(true);
        let snap_packets = r.last_print_packets;
        r.tick(100, 1, 0, 0);
        r.tick(1_000_000, 1, 0, 0);
        r.tick(1_999_999, 1, 0, 0);
        assert_eq!(r.last_print_packets, snap_packets, "no print -> bookkeeping unchanged");
    }

    #[test]
    fn time_fallback_emits_when_packet_delta_below_threshold() {
        // Simulate a slow stream: packet delta stays below 2M but wall clock
        // exceeds 5 s. The reporter must emit (the bug CR-23 fixed).
        let mut r = ProgressReporter::new(true);
        // Backdate `last_print` by 6 seconds to simulate elapsed time.
        r.last_print = Instant::now().checked_sub(std::time::Duration::from_secs(6)).unwrap();
        let snap_packets = r.last_print_packets;
        r.tick(CLOCK_CHECK_INTERVAL, 1, 0, 0); // packet_delta = CLOCK_CHECK_INTERVAL < 2M, but elapsed > 5s
        assert_ne!(r.last_print_packets, snap_packets, "time fallback should have triggered emit");
        assert_eq!(r.last_print_packets, CLOCK_CHECK_INTERVAL);
    }

    #[test]
    fn current_rss_mib_returns_a_value() {
        // sysinfo is cross-platform; should return Some(>0) on Linux/macOS/Windows.
        let r = current_rss_mib();
        assert!(r.is_some(), "sysinfo should report RSS on this platform");
        assert!(r.unwrap() > 0, "process must have non-zero RSS");
    }

    #[test]
    fn total_ram_bytes_returns_nonzero() {
        let ram = total_ram_bytes();
        assert!(ram > 0, "total_ram_bytes must report non-zero physical RAM");
    }

    #[test]
    fn current_rss_bytes_returns_nonzero() {
        let rss = current_rss_bytes();
        assert!(rss > 0, "current_rss_bytes must report non-zero RSS");
    }
}
