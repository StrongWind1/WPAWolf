//! Memory pressure monitor for automatic disk-backed fallback.
//!
//! Tracks process RSS relative to total system RAM via `sysinfo`. When RSS
//! reaches 80% of total RAM, sets a sticky `disk_mode` flag that tells the
//! pipeline to spill heavy stores to disk instead of growing unboundedly in
//! memory. The flag is one-way: once set, it stays set for the remainder of
//! the run.
//!
//! Check points:
//! - Phase 1: every file transition + every `CHECK_INTERVAL` packets
//! - Phase 4: before `dedup.reserve()`, every `EMIT_CHECK_INTERVAL` hash lines
//!
//! Uses process RSS (not system `available_memory`) to avoid premature triggers
//! from the kernel page cache filling during sequential pcap reads.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::progress;

/// Packets between memory checks during Phase 1.
const CHECK_INTERVAL: u64 = 50_000;

/// Hash lines between memory checks during Phase 4 output.
pub const EMIT_CHECK_INTERVAL: u64 = 100_000;

/// RAM usage threshold (tenths of a percent). 800 = 80.0%.
const THRESHOLD_TENTHS: u64 = 800;

/// Sampling cadence for the Phase-4 [`MemWatcher`] background thread.
const SAMPLE_INTERVAL_MS: u64 = 250;

/// Memory pressure monitor with sticky disk-mode flag.
pub struct MemMonitor {
    total_ram: u64,
    threshold_bytes: u64,
    last_rss: u64,
    /// Highest RSS sample observed across the run (Phase 5 `peak RSS` banner row).
    /// Shared with a [`MemWatcher`] so Phase-4 transients (where this monitor is
    /// otherwise not polled) are folded in via `fetch_max`; the banner value is
    /// therefore an accurate high-water mark, not a sampled lower bound.
    peak_rss: Arc<AtomicU64>,
    /// Set by a [`MemWatcher`] when sampled RSS crosses the threshold during
    /// Phase 4, where the monitor itself is never polled. `poll_disk_trip` reads
    /// it to flip into disk-backed mode mid-emission. C2.
    disk_trip: Arc<AtomicBool>,
    disk_mode: bool,
    packets_since_check: u64,
}

impl MemMonitor {
    /// Creates a new monitor. Probes total system RAM once at init.
    ///
    /// Override the 80% threshold via `WPAWOLF_MEM_THRESHOLD` (integer percent,
    /// e.g. `WPAWOLF_MEM_THRESHOLD=1` triggers at 1% for testing).
    #[must_use]
    pub fn new() -> Self {
        let total_ram = progress::total_ram_bytes();
        let tenths = std::env::var("WPAWOLF_MEM_THRESHOLD")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .map_or(THRESHOLD_TENTHS, |pct| pct.min(100) * 10);
        let threshold_bytes = total_ram / 1000 * tenths;
        Self {
            total_ram,
            threshold_bytes,
            last_rss: 0,
            peak_rss: Arc::new(AtomicU64::new(0)),
            disk_trip: Arc::new(AtomicBool::new(false)),
            disk_mode: false,
            packets_since_check: 0,
        }
    }

    /// Probes current RSS and activates disk mode if over threshold.
    /// Returns `true` if disk mode just activated (first crossing).
    pub fn check(&mut self) -> bool {
        self.packets_since_check = 0;
        let rss = progress::current_rss_bytes();
        self.last_rss = rss;
        self.peak_rss.fetch_max(rss, Ordering::Relaxed);
        if !self.disk_mode && rss >= self.threshold_bytes {
            self.disk_mode = true;
            let rss_mib = rss / (1024 * 1024);
            let total_mib = self.total_ram / (1024 * 1024);
            // stdout per FR-CLI-4: stderr produces no output.
            println!(
                "wpawolf: memory pressure ({rss_mib} MiB / {total_mib} MiB, >= 80%) -- switching to disk-backed mode"
            );
            return true;
        }
        false
    }

    /// Increments the packet counter and checks memory if the interval has elapsed.
    /// Returns `true` if disk mode just activated.
    pub fn tick_packet(&mut self) -> bool {
        self.packets_since_check += 1;
        if self.packets_since_check >= CHECK_INTERVAL {
            return self.check();
        }
        false
    }

    /// Predicts whether allocating `additional_bytes` would exceed the threshold.
    /// Does NOT activate disk mode -- the caller decides what to do.
    #[must_use]
    pub fn would_exceed(&mut self, additional_bytes: u64) -> bool {
        let rss = progress::current_rss_bytes();
        self.last_rss = rss;
        self.peak_rss.fetch_max(rss, Ordering::Relaxed);
        rss.saturating_add(additional_bytes) >= self.threshold_bytes
    }

    /// Forces disk mode on. Used when `would_exceed` returns true and the caller
    /// decides to skip a large allocation.
    pub fn force_disk_mode(&mut self) {
        if !self.disk_mode {
            self.disk_mode = true;
            let rss_mib = self.last_rss / (1024 * 1024);
            let total_mib = self.total_ram / (1024 * 1024);
            // stdout per FR-CLI-4: stderr produces no output.
            println!(
                "wpawolf: preemptive disk mode ({rss_mib} MiB / {total_mib} MiB) -- large allocation would exceed 80%"
            );
        }
    }

    /// Returns `true` if disk mode is active (sticky).
    #[must_use]
    pub const fn disk_mode(&self) -> bool {
        self.disk_mode
    }

    /// Total system RAM in bytes.
    #[must_use]
    pub const fn total_ram(&self) -> u64 {
        self.total_ram
    }

    /// Last observed RSS in bytes.
    #[must_use]
    pub const fn last_rss(&self) -> u64 {
        self.last_rss
    }

    /// Highest RSS observed so far in bytes. Accurate when a [`MemWatcher`] runs
    /// over Phase 4; otherwise reflects the pressure-check sample cadence.
    #[must_use]
    pub fn peak_rss_bytes(&self) -> u64 {
        self.peak_rss.load(Ordering::Relaxed)
    }

    /// Returns a clone of the shared peak-RSS atomic so a [`MemWatcher`] can fold
    /// its own samples into the same high-water mark this monitor reports.
    #[must_use]
    pub fn peak_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.peak_rss)
    }

    /// Returns a clone of the shared disk-trip flag so a [`MemWatcher`] can set
    /// it when sampled RSS crosses the threshold during Phase 4. C2.
    #[must_use]
    pub fn disk_trip_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.disk_trip)
    }

    /// The memory-pressure threshold in bytes (80% of total RAM by default), for
    /// a [`MemWatcher`] to compare its samples against.
    #[must_use]
    pub const fn threshold_bytes(&self) -> u64 {
        self.threshold_bytes
    }

    /// If a [`MemWatcher`] tripped the disk-trip flag and disk mode is not yet
    /// engaged, flips the sticky `disk_mode` on (printing the same notice as
    /// `check`) and returns `true`. The Phase-4 emit loop polls this to switch
    /// the in-memory dedup to disk mid-stream when real RSS crosses the threshold
    /// between the coarse pressure checks. C2.
    pub fn poll_disk_trip(&mut self) -> bool {
        if !self.disk_mode && self.disk_trip.load(Ordering::Relaxed) {
            self.disk_mode = true;
            let rss_mib = self.peak_rss.load(Ordering::Relaxed) / (1024 * 1024);
            let total_mib = self.total_ram / (1024 * 1024);
            // stdout per FR-CLI-4: stderr produces no output.
            println!(
                "wpawolf: memory pressure ({rss_mib} MiB / {total_mib} MiB, >= 80%) -- switching to disk-backed mode"
            );
            return true;
        }
        false
    }
}

impl Default for MemMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MemMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemMonitor")
            .field("total_ram", &self.total_ram)
            .field("peak_rss_mib", &(self.peak_rss.load(Ordering::Relaxed) / (1024 * 1024)))
            .field("disk_mode", &self.disk_mode)
            .field("disk_trip", &self.disk_trip.load(Ordering::Relaxed))
            .field("last_rss_mib", &(self.last_rss / (1024 * 1024)))
            .field("threshold_mib", &(self.threshold_bytes / (1024 * 1024)))
            .field("packets_since_check", &self.packets_since_check)
            .finish()
    }
}

// --- MemWatcher ---

/// Background thread that keeps a [`MemMonitor`]'s peak-RSS high-water mark
/// accurate during Phase 4.
///
/// The monitor itself is polled per-file in Phase 1 but never during Phase-4
/// pairing/fan-out, so a transient allocation spike between samples is invisible
/// to `peak_rss` (observed undercount: 4966 MiB reported vs 42.8 GiB true). This
/// watcher samples process RSS every ~250 ms and folds it into the shared peak
/// atomic obtained from [`MemMonitor::peak_handle`], regardless of
/// which rayon worker is busy. It does not change disk-mode triggering -- it only
/// makes the reported peak honest.
#[must_use = "the watcher stops as soon as it is dropped; bind it for the duration of Phase 4"]
pub struct MemWatcher {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl MemWatcher {
    /// Spawns the watcher, folding each sample into `peak` and setting `disk_trip`
    /// once a sample reaches `threshold_bytes` (the C2 mid-stream-spill signal). If
    /// an [`progress::RssSampler`] cannot be created, returns an inert watcher (no
    /// thread) so callers need no error handling.
    pub fn spawn(peak: Arc<AtomicU64>, threshold_bytes: u64, disk_trip: Arc<AtomicBool>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let Some(mut sampler) = progress::RssSampler::new() else {
            return Self { stop, handle: None };
        };
        let stop_thread = Arc::clone(&stop);
        let handle = std::thread::Builder::new()
            .name("wpawolf-memwatch".to_owned())
            .spawn(move || {
                while !stop_thread.load(Ordering::Relaxed) {
                    let rss = sampler.sample();
                    peak.fetch_max(rss, Ordering::Relaxed);
                    if rss >= threshold_bytes {
                        disk_trip.store(true, Ordering::Relaxed);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(SAMPLE_INTERVAL_MS));
                }
            })
            .ok();
        Self { stop, handle }
    }

    /// Signals the watcher to stop and joins its thread.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for MemWatcher {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl std::fmt::Debug for MemWatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemWatcher").field("running", &self.handle.is_some()).finish_non_exhaustive()
    }
}

// --- Unit tests ---

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, missing_docs, reason = "test module")]

    use super::*;

    #[test]
    fn new_does_not_panic() {
        let m = MemMonitor::new();
        assert!(!m.disk_mode());
        assert!(m.total_ram() > 0);
    }

    #[test]
    fn check_returns_false_when_under_threshold() {
        let mut m = MemMonitor::new();
        let activated = m.check();
        // On a machine with reasonable RAM, the test process itself is well under 80%.
        assert!(!activated);
        assert!(!m.disk_mode());
    }

    #[test]
    fn tick_packet_checks_at_interval() {
        let mut m = MemMonitor::new();
        for _ in 0..CHECK_INTERVAL - 1 {
            assert!(!m.tick_packet());
        }
        // The CHECK_INTERVAL-th tick triggers a check.
        let _ = m.tick_packet();
        assert_eq!(m.packets_since_check, 0, "counter should reset after check");
    }

    #[test]
    fn force_disk_mode_sets_flag() {
        let mut m = MemMonitor::new();
        assert!(!m.disk_mode());
        m.force_disk_mode();
        assert!(m.disk_mode());
    }

    #[test]
    fn would_exceed_with_absurd_value() {
        let mut m = MemMonitor::new();
        assert!(m.would_exceed(u64::MAX / 2));
    }

    #[test]
    fn disk_mode_is_sticky() {
        let mut m = MemMonitor::new();
        m.force_disk_mode();
        assert!(m.disk_mode());
        m.check(); // check again -- should stay true
        assert!(m.disk_mode());
    }

    #[test]
    fn peak_handle_reflects_external_updates() {
        let m = MemMonitor::new();
        let peak = m.peak_handle();
        peak.fetch_max(123 * 1024 * 1024, Ordering::Relaxed);
        assert_eq!(m.peak_rss_bytes(), 123 * 1024 * 1024, "monitor must report the shared peak");
    }

    #[test]
    fn mem_watcher_updates_peak_and_joins() {
        let m = MemMonitor::new();
        // High threshold so the trip never fires; this test only checks the peak.
        let watcher = MemWatcher::spawn(m.peak_handle(), u64::MAX, m.disk_trip_handle());
        // The watcher samples immediately on spawn; give it a beat to run once.
        std::thread::sleep(std::time::Duration::from_millis(100));
        watcher.stop(); // must join cleanly without hanging
        // The test process has nonzero RSS, so the watcher recorded a real sample.
        assert!(m.peak_rss_bytes() > 0, "watcher should fold a real RSS sample into the peak");
    }

    #[test]
    fn poll_disk_trip_flips_disk_mode_when_set() {
        let mut m = MemMonitor::new();
        assert!(!m.poll_disk_trip(), "no trip set -> no switch");
        m.disk_trip_handle().store(true, Ordering::Relaxed);
        assert!(m.poll_disk_trip(), "trip set -> switch returns true");
        assert!(m.disk_mode(), "disk mode now sticky-on");
        assert!(!m.poll_disk_trip(), "already in disk mode -> no repeat switch");
    }

    #[test]
    fn watcher_sets_disk_trip_at_zero_threshold() {
        let m = MemMonitor::new();
        // Threshold 0: any real RSS sample (always > 0) trips it.
        let watcher = MemWatcher::spawn(m.peak_handle(), 0, m.disk_trip_handle());
        std::thread::sleep(std::time::Duration::from_millis(100));
        watcher.stop();
        assert!(m.disk_trip_handle().load(Ordering::Relaxed), "watcher must set disk_trip at threshold 0");
    }
}
