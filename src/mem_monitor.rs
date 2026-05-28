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

use crate::progress;

/// Packets between memory checks during Phase 1.
const CHECK_INTERVAL: u64 = 50_000;

/// Hash lines between memory checks during Phase 4 output.
pub const EMIT_CHECK_INTERVAL: u64 = 100_000;

/// RAM usage threshold (tenths of a percent). 800 = 80.0%.
const THRESHOLD_TENTHS: u64 = 800;

/// Memory pressure monitor with sticky disk-mode flag.
pub struct MemMonitor {
    total_ram: u64,
    threshold_bytes: u64,
    last_rss: u64,
    disk_mode: bool,
    packets_since_check: u64,
}

impl MemMonitor {
    /// Creates a new monitor. Probes total system RAM once at init.
    #[must_use]
    pub fn new() -> Self {
        let total_ram = progress::total_ram_bytes();
        let threshold_bytes = total_ram / 1000 * THRESHOLD_TENTHS;
        Self { total_ram, threshold_bytes, last_rss: 0, disk_mode: false, packets_since_check: 0 }
    }

    /// Probes current RSS and activates disk mode if over threshold.
    /// Returns `true` if disk mode just activated (first crossing).
    pub fn check(&mut self) -> bool {
        self.packets_since_check = 0;
        let rss = progress::current_rss_bytes();
        self.last_rss = rss;
        if !self.disk_mode && rss >= self.threshold_bytes {
            self.disk_mode = true;
            let rss_mib = rss / (1024 * 1024);
            let total_mib = self.total_ram / (1024 * 1024);
            eprintln!(
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
    /// Does NOT activate disk mode — the caller decides what to do.
    #[must_use]
    pub fn would_exceed(&mut self, additional_bytes: u64) -> bool {
        let rss = progress::current_rss_bytes();
        self.last_rss = rss;
        rss.saturating_add(additional_bytes) >= self.threshold_bytes
    }

    /// Forces disk mode on. Used when `would_exceed` returns true and the caller
    /// decides to skip a large allocation.
    pub fn force_disk_mode(&mut self) {
        if !self.disk_mode {
            self.disk_mode = true;
            let rss_mib = self.last_rss / (1024 * 1024);
            let total_mib = self.total_ram / (1024 * 1024);
            eprintln!(
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
            .field("disk_mode", &self.disk_mode)
            .field("last_rss_mib", &(self.last_rss / (1024 * 1024)))
            .field("threshold_mib", &(self.threshold_bytes / (1024 * 1024)))
            .field("packets_since_check", &self.packets_since_check)
            .finish()
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
        m.check(); // check again — should stay true
        assert!(m.disk_mode());
    }
}
