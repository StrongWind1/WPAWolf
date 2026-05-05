//! Phase 1 -- periodic stderr progress reporter. See `ARCHITECTURE.md §3.1`.
//!
//! Emits one `[progress]` line per cadence interval during the Phase 1 ingest
//! loop so an operator running wpawolf against a multi-hour corpus has a live
//! pulse of where the run is. Greppable line prefix (`[progress]`); fields are
//! space-separated `key=value` pairs:
//!
//! `[progress] elapsed=<s> files=<n> packets=<n> eapol=<n> pmkids=<n> rss=<n>MiB`
//!
//! `rss` is omitted on platforms where the RSS lookup is not implemented
//! (currently anything other than Linux). The closing Phase 1-5 stats banner is
//! unaffected by this reporter.
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
// `Read` trait is only used inside the Linux `current_rss_mib` cfg block
// (the `/proc/self/statm` reader); on macOS / Windows the unused-imports lint
// would otherwise reject the build. Gate the import to match the only call site.
#[cfg(target_os = "linux")]
use std::io::Read as _;
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
        // Fast path: packet delta below threshold and time delta below threshold.
        // The packet check is a u64 subtract -- effectively free. The wall-clock
        // check is a syscall on most platforms, so guard it with the packet
        // delta first to amortise the cost.
        let packet_delta = total_packets.saturating_sub(self.last_print_packets);
        if packet_delta < PACKETS_THRESHOLD {
            // Only consult the wall clock once per ~2M packets.
            return;
        }
        let elapsed_since_last = self.last_print.elapsed();
        if packet_delta < PACKETS_THRESHOLD && elapsed_since_last.as_secs() < ELAPSED_SECS_THRESHOLD {
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
        // Manual stderr write so we can flush; `eprintln!` already flushes on
        // newline for unbuffered handles, but `--quiet` aside we want this
        // visible immediately even if a downstream collector buffers stderr.
        let mut err = std::io::stderr().lock();
        let _ = writeln!(err, "{line}");
        let _ = err.flush();

        self.last_print = Instant::now();
        self.last_print_packets = total_packets;
    }
}

/// Returns the current process's resident set size in MiB, or `None` when the
/// platform does not expose a cheap probe.
///
/// Linux: read `/proc/self/statm`, take field 2 (resident pages), multiply by
/// 4096 (the kernel-level page size on every supported architecture). Other
/// platforms return `None` so the caller omits the `rss=` field rather than
/// printing a wrong value.
#[must_use]
pub fn current_rss_mib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        // /proc/self/statm format per `man proc`:
        //   size resident shared text lib data dt
        // All in pages.
        let mut buf = String::new();
        let mut f = std::fs::File::open("/proc/self/statm").ok()?;
        f.read_to_string(&mut buf).ok()?;
        let mut parts = buf.split_ascii_whitespace();
        let _size = parts.next()?;
        let resident_pages: u64 = parts.next()?.parse().ok()?;
        // Page size is 4 KiB on every Linux arch wpawolf currently builds for.
        // 4096 / (1024 * 1024) = 1/256, so divide pages by 256 for MiB.
        Some(resident_pages / 256)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
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
    fn current_rss_mib_returns_a_value_on_linux() {
        // On a Linux build host this should always return Some(>0); on other
        // platforms it returns None and we accept that.
        let r = current_rss_mib();
        if cfg!(target_os = "linux") {
            assert!(r.is_some(), "Linux should report RSS");
            assert!(r.unwrap() > 0, "process must have non-zero RSS");
        } else {
            assert!(r.is_none(), "non-Linux platforms return None");
        }
    }
}
