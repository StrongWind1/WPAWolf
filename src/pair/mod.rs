//! Phase 4 -- Emit: pairing engine entry point (consumes Phase 3 stores, produces hash candidates). See ARCHITECTURE.md §3.4 + §5.
//!
//! After Phase 1 (Collect) completes, iterates every (AP, STA) group in `MessageStore`,
//! sorts messages by timestamp, generates all valid N#E# combination pairs via `combos`,
//! collapses equivalence classes via `collapse`, and resolves ESSIDs from `EssidMap`.
//! Also routes PMKIDs through ESSID resolution independently of the EAPOL pipeline
//! (Invariant OUT-1 in `ARCHITECTURE.md §7`). Returns all `PairedHash` and PMKID
//! entries for output. See `ARCHITECTURE.md §5`.

pub mod collapse;
pub mod combos;
pub mod constraints;

// --- Adaptive thinning ---

/// Configuration for memory-pressure-driven group thinning.
///
/// Constructed from `--mem-limit` and `--eapoltimeout` CLI flags. Passed into
/// the pair pipeline so `thin_group` can decide per-group whether to apply
/// session-window filtering before pairing.
#[derive(Debug, Clone)]
pub struct ThinConfig {
    /// RSS percentage of total RAM that triggers thinning (0-100). 0 = disabled.
    pub mem_limit_pct: u8,
    /// Total system RAM in bytes (from `sysinfo`).
    pub total_ram_bytes: u64,
    /// User's `--eapoltimeout` if set (microseconds), to avoid double-applying.
    pub user_eapol_timeout_us: Option<u64>,
}

/// Which thinning stage was applied to a group (for stats/debug reporting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThinStage {
    /// Cost within budget; no thinning applied.
    None,
    /// Applied 30-second session-window filter.
    SessionWindow30s,
    /// Applied 5-second session-window filter.
    SessionWindow5s,
    /// Kept only the best-quality N per type.
    QualitySubset,
}

/// Result of thinning a single group.
#[derive(Debug, Clone)]
pub struct ThinResult {
    /// Which stage was applied.
    pub stage: ThinStage,
    /// Messages before thinning.
    pub before_count: usize,
    /// Messages after thinning.
    pub after_count: usize,
}
/// Aggregate thinning stats across all groups in a pairing run.
#[derive(Debug, Default, Clone)]
pub struct ThinAggregateStats {
    /// Groups thinned with the 30-second session-window filter.
    pub groups_thinned_30s: u64,
    /// Groups thinned with the 5-second session-window filter.
    pub groups_thinned_5s: u64,
    /// Groups thinned to a quality-subset (max 64 per type).
    pub groups_thinned_subset: u64,
    /// Total messages removed by adaptive thinning.
    pub messages_thinned: u64,
}

impl ThinAggregateStats {
    const fn record(&mut self, result: &ThinResult) {
        match result.stage {
            ThinStage::None => {},
            ThinStage::SessionWindow30s => self.groups_thinned_30s += 1,
            ThinStage::SessionWindow5s => self.groups_thinned_5s += 1,
            ThinStage::QualitySubset => self.groups_thinned_subset += 1,
        }
        self.messages_thinned += result.before_count.saturating_sub(result.after_count) as u64;
    }
}

pub mod nc_dedup;

use std::sync::Arc;

use crate::types::{AkmType, FtFields, MacAddr, MicBytes};

// --- Shared output types ---

/// One of the six N#E# hashcat combination types.
///
/// The digit before `E` identifies which EAPOL message supplies the nonce field;
/// the digit after `E` identifies which message supplies the EAPOL frame and MIC.
/// `N1E2` = `ANonce` from M1, EAPOL frame from M2. See `ARCHITECTURE.md §5`.
///
/// Discriminant values match hcxtools `ST_M*` constants exactly so that the
/// `message_pair` byte written to the hash line is wire-compatible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ComboType {
    /// `ANonce` from M1, EAPOL frame from M2. Wire byte `0x00`. [hcxtools legacy alias `ST_M12E2`]
    N1E2 = 0,
    /// `ANonce` from M1, EAPOL frame from M4. Wire byte `0x01`. [hcxtools legacy alias `ST_M14E4`]
    N1E4 = 1,
    /// `ANonce` from M3, EAPOL frame from M2. Wire byte `0x02`. [hcxtools legacy alias `ST_M32E2`]
    N3E2 = 2,
    /// `SNonce` from M2, EAPOL frame from M3. Wire byte `0x03` (+ `APLESS` -> `0x13`). [hcxtools legacy alias `ST_M32E3`]
    N2E3 = 3,
    /// `SNonce` from M4, EAPOL frame from M3. Wire byte `0x04` (+ `APLESS` -> `0x14`). [hcxtools legacy alias `ST_M34E3`]
    N4E3 = 4,
    /// `ANonce` from M3, EAPOL frame from M4. Wire byte `0x05`. [hcxtools legacy alias `ST_M34E4`]
    N3E4 = 5,
}

/// `message_pair` flag bit: AP-less pair (N2E3 and N4E3 combos).
/// Set for both AP-less combos. [hcxtools legacy alias `ST_APLESS` = 0x10]
pub const FLAG_APLESS: u8 = 0x10;
/// `message_pair` flag bit: RC bytes interpreted as little-endian resolved the match.
/// [hcxtools `ST_LE` = 0x20]
pub const FLAG_LE: u8 = 1 << 5;
/// `message_pair` flag bit: RC bytes interpreted as big-endian resolved the match.
/// [hcxtools `ST_BE` = 0x40]
pub const FLAG_BE: u8 = 1 << 6;
/// `message_pair` flag bit: nonce-error-corrections tolerance was needed.
/// [hcxtools `ST_NC` = 0x80]
pub const FLAG_NC: u8 = 1 << 7;

/// A fully-paired EAPOL handshake combination ready for hash-line formatting.
///
/// Produced by `combos::generate` after constraint checking and, optionally, after
/// equivalence-class collapsing by `collapse::collapse`. One `PairedHash` corresponds
/// to one `WPA*02*` or `WPA*04*` line in the hashcat output file.
#[derive(Debug)]
pub struct PairedHash {
    /// AP MAC address (BSSID).
    pub ap: MacAddr,
    /// STA MAC address (client).
    pub sta: MacAddr,
    /// Which N#E# combination this pair represents.
    pub combo_type: ComboType,
    /// Nonce value: `ANonce` for N1/N3 combos, `SNonce` for N2/N4 combos.
    pub nonce: [u8; 32],
    /// Raw EAPOL frame bytes from the EAPOL message (MIC intact).
    /// The output formatter zeros the MIC field (offset 81 .. 81+`mic_len`) for hashcat.
    /// Stored as `Arc<[u8]>` to share frame data across paired hashes without cloning.
    pub eapol_frame: Arc<[u8]>,
    /// Key MIC from the EAPOL message: 16 or 24 bytes, see [`MicBytes`].
    pub mic: MicBytes,
    /// Encoded combo type (bits 0-2) plus RC relationship flags (bits 5-7).
    /// Format: `combo_type as u8 | FLAG_LE? | FLAG_BE? | FLAG_NC?`
    pub message_pair: u8,
    /// AKM suite type -- determines output file (22000 vs 37100).
    pub akm: AkmType,
    /// FT-PSK fields, present only for FT associations.
    pub ft: Option<FtFields>,
    /// Absolute deviation of the actual RC delta from the expected delta for this combo.
    /// 0 = exact RC match, lower is better. Used by `--dedup-hash-combos` survivor
    /// selection: when two combos produce the same crackable hash, prefer the smaller gap.
    /// Computed unconditionally so it is available whether or not dedup is active.
    pub rc_gap_magnitude: u64,
}

// --- Orchestration ---

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rayon::prelude::*;

use crate::debug::{DebugPrinter, HEAVY_GROUP_COST, group_progress_interval};
use crate::pair::collapse::collapse;
use crate::pair::combos::{PairConfig, generate};
use crate::pair::nc_dedup::{NcDedupStats, nc_dedup};
use crate::progress::current_rss_bytes;
use crate::store::messages::{EapolMessage, MessageStore, session_window_filter};
use crate::types::{MacPair, MsgType};

/// Cost threshold below which thinning is never applied (group too small to matter).
const THIN_COST_THRESHOLD: u64 = 50_000;

/// Checks whether memory pressure warrants thinning, then applies staged
/// session-window filters to a group's messages if needed.
///
/// Returns `None` when no thinning was applied (the caller should use the
/// original slice as-is), or `Some((filtered, result))` when filtering ran.
/// This avoids a heap clone on the common no-thinning path.
#[must_use]
pub fn thin_group(messages: &[EapolMessage], thin_config: &ThinConfig) -> Option<(Vec<EapolMessage>, ThinResult)> {
    if thin_config.mem_limit_pct == 0 {
        return None;
    }
    let cost = estimate_group_cost(messages);
    if cost < THIN_COST_THRESHOLD {
        return None;
    }
    let rss = current_rss_bytes();
    let threshold = u64::from(thin_config.mem_limit_pct) * thin_config.total_ram_bytes / 100;
    if rss < threshold {
        return None;
    }

    let before_count = messages.len();

    if thin_config.user_eapol_timeout_us.is_none_or(|t| t > 30_000_000) {
        let filtered = session_window_filter(messages, 30_000_000);
        if estimate_group_cost(&filtered) < THIN_COST_THRESHOLD {
            let after_count = filtered.len();
            return Some((filtered, ThinResult { stage: ThinStage::SessionWindow30s, before_count, after_count }));
        }
    }

    let filtered_5s = session_window_filter(messages, 5_000_000);
    if thin_config.user_eapol_timeout_us.is_none_or(|t| t > 5_000_000)
        && estimate_group_cost(&filtered_5s) < THIN_COST_THRESHOLD
    {
        let after_count = filtered_5s.len();
        return Some((filtered_5s, ThinResult { stage: ThinStage::SessionWindow5s, before_count, after_count }));
    }

    let mut filtered = filtered_5s;
    for msg_type in [MsgType::M1, MsgType::M2, MsgType::M3, MsgType::M4] {
        let typed_count = filtered.iter().filter(|m| m.msg_type == msg_type).count();
        if typed_count > 64 {
            let mut ts_pairs: Vec<(usize, u64)> = filtered
                .iter()
                .enumerate()
                .filter(|(_, m)| m.msg_type == msg_type)
                .map(|(i, m)| (i, m.timestamp))
                .collect();
            ts_pairs.sort_unstable_by_key(|&(_, ts)| ts);
            ts_pairs.truncate(64);
            let keep_set: std::collections::HashSet<usize> = ts_pairs.into_iter().map(|(i, _)| i).collect();
            let mut idx = 0;
            filtered.retain(|m| {
                let current = idx;
                idx += 1;
                m.msg_type != msg_type || keep_set.contains(&current)
            });
        }
    }

    let after_count = filtered.len();
    Some((filtered, ThinResult { stage: ThinStage::QualitySubset, before_count, after_count }))
}

/// Folds `other` into `acc` in place: `collapsed_lines` and `cluster_count`
/// sum component-wise; `max_cluster_size` takes the larger of the two.
const fn merge_nc_stats(acc: &mut NcDedupStats, other: NcDedupStats) {
    acc.collapsed_lines += other.collapsed_lines;
    acc.cluster_count += other.cluster_count;
    if other.max_cluster_size > acc.max_cluster_size {
        acc.max_cluster_size = other.max_cluster_size;
    }
}

/// Estimates the pairing cost of a single (AP, STA) group.
///
/// Returns the total number of message-pair comparisons across all six N#E# combos.
#[must_use]
pub fn estimate_group_cost(messages: &[EapolMessage]) -> u64 {
    let (_, _, _, _, cost) = group_counts_and_cost(messages);
    cost
}

/// Pairs a single group: clone, sort, generate combos, collapse, NC-dedup.
fn pair_one_group(
    mac_pair: &MacPair,
    messages: &[EapolMessage],
    config: &PairConfig,
) -> (Vec<PairedHash>, NcDedupStats) {
    let mut sorted = messages.to_vec();
    sorted.sort_unstable_by_key(|m| m.timestamp);
    let pairs = generate(mac_pair.ap, mac_pair.sta, &sorted, config);
    let pairs = collapse(pairs, config.all_combos);
    nc_dedup(pairs, config)
}

/// Streaming pairing pipeline: pairs each group and delivers results via callback.
///
/// Instead of materializing all pairs across all groups into a single `Vec`, this
/// function calls `on_group` once per group with that group's pairs. The caller
/// can process and drop pairs immediately, bounding peak memory to one group's
/// output at a time.
///
/// When `thread_count > 1`, uses rayon's work-stealing `par_iter` for parallel
/// pairing. The `on_group` callback is serialized via a `Mutex` so I/O-bound
/// fan-out (writing to `BufWriter`s) does not need to be thread-safe. Pairing
/// itself runs fully parallel across cores.
///
/// Returns the aggregate `NcDedupStats` across all groups.
pub fn pair_all_groups_streaming<F>(
    store: &MessageStore,
    config: &PairConfig,
    thin_config: Option<&ThinConfig>,
    thread_count: usize,
    debug: &DebugPrinter,
    on_group: F,
) -> (NcDedupStats, ThinAggregateStats)
where
    F: Fn(Vec<PairedHash>) + Send + Sync,
{
    let groups: Vec<(&MacPair, &Vec<EapolMessage>)> = store.groups().collect();

    if groups.is_empty() {
        return (NcDedupStats::default(), ThinAggregateStats::default());
    }

    let total_groups = groups.len();
    let groups_done = AtomicUsize::new(0);
    let pairs_done = AtomicUsize::new(0);
    let all_nc = Mutex::new(NcDedupStats::default());
    let all_thin = Mutex::new(ThinAggregateStats::default());

    let process_group = |mac_pair: &MacPair, messages: &[EapolMessage]| {
        let pairing_messages: Vec<EapolMessage>;
        #[allow(clippy::option_if_let_else, reason = "map_or cannot express the local-variable assignment")]
        let msgs_ref: &[EapolMessage] = if let Some(tc) = thin_config {
            if let Some((filtered, result)) = thin_group(messages, tc) {
                debug.group_thinned(mac_pair.ap, mac_pair.sta, &result);
                if let Ok(mut guard) = all_thin.lock() {
                    guard.record(&result);
                }
                pairing_messages = filtered;
                &pairing_messages
            } else {
                messages
            }
        } else {
            messages
        };
        let (m1, m2, m3, m4, cost) = group_counts_and_cost(msgs_ref);
        debug.group_start(mac_pair.ap, mac_pair.sta, m1, m2, m3, m4, cost);
        if cost >= HEAVY_GROUP_COST {
            let _ = debug.memory_check(&format!(
                "Phase 4 pairing ap={} sta={} m1={m1} m2={m2} m3={m3} m4={m4} cost={cost}",
                mac_pair.ap, mac_pair.sta
            ));
        }
        let t0 = Instant::now();
        let (pairs, nc) = pair_one_group(mac_pair, msgs_ref, config);
        let elapsed_us = t0.elapsed().as_micros();
        debug.group_done(mac_pair.ap, mac_pair.sta, pairs.len(), elapsed_us, cost);
        let done = groups_done.fetch_add(1, Ordering::Relaxed) + 1;
        pairs_done.fetch_add(pairs.len(), Ordering::Relaxed);
        if done % group_progress_interval() == 0 || done == total_groups {
            debug.group_progress(done, total_groups, pairs_done.load(Ordering::Relaxed));
        }
        on_group(pairs);
        if let Ok(mut guard) = all_nc.lock() {
            merge_nc_stats(&mut guard, nc);
        }
    };

    if thread_count <= 1 {
        for &(mac_pair, messages) in &groups {
            process_group(mac_pair, messages);
        }
    } else {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(thread_count).build().unwrap_or_else(|_| {
            rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap_or_else(|_| unreachable!())
        });
        pool.install(|| {
            groups.par_iter().for_each(|&(mac_pair, messages)| {
                process_group(mac_pair, messages);
            });
        });
    }

    let nc = all_nc.into_inner().unwrap_or_default();
    let thin = all_thin.into_inner().unwrap_or_default();
    (nc, thin)
}

/// Collects all pairs into a `Vec`. Prefer `pair_all_groups_streaming` when
/// peak memory matters -- this wrapper materializes the full pair set.
#[must_use]
pub fn pair_all_groups(
    store: &MessageStore,
    config: &PairConfig,
    thread_count: usize,
    debug: &DebugPrinter,
) -> (Vec<PairedHash>, NcDedupStats) {
    let all_pairs = Mutex::new(Vec::<PairedHash>::new());
    let (nc, _thin) = pair_all_groups_streaming(store, config, None, thread_count, debug, |pairs| {
        if let Ok(mut guard) = all_pairs.lock() {
            guard.extend(pairs);
        }
    });
    let pairs = all_pairs.into_inner().unwrap_or_default();
    (pairs, nc)
}

/// Returns `(m1, m2, m3, m4, cost)` for a message slice.
fn group_counts_and_cost(messages: &[EapolMessage]) -> (usize, usize, usize, usize, u64) {
    let (mut m1, mut m2, mut m3, mut m4) = (0usize, 0usize, 0usize, 0usize);
    for msg in messages {
        match msg.msg_type {
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
    (m1, m2, m3, m4, cost)
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
    use crate::debug::DebugPrinter;
    use crate::pair::combos::PairConfig;
    use crate::store::messages::{EapolMessage, MessageStore};
    use crate::types::{AkmType, MacAddr, MsgType};

    fn make_msg(msg_type: MsgType, rc: u64, ts: u64) -> EapolMessage {
        EapolMessage {
            timestamp: ts,
            msg_type,
            key_version: 2,
            replay_counter: rc,
            nonce: [1u8; 32],
            mic: MicBytes::from_16([0xABu8; 16]),
            pmkid: None,
            eapol_frame: Arc::from(vec![0u8; 99]),
            ft: None,
            akm: AkmType::Wpa2Psk,
            is_rsn: true,
        }
    }

    fn ap() -> MacAddr {
        MacAddr::from_bytes([0x11; 6])
    }

    fn sta() -> MacAddr {
        MacAddr::from_bytes([0x22; 6])
    }

    #[test]
    fn pair_all_groups_empty_store() {
        let store = MessageStore::new();
        let config = PairConfig::default();
        let (pairs, nc) = pair_all_groups(&store, &config, 1, &DebugPrinter::new(false));
        assert!(pairs.is_empty());
        assert_eq!(nc.collapsed_lines, 0);
        // Also verify parallel path handles empty store.
        let (pairs_par, nc_par) = pair_all_groups(&store, &config, 4, &DebugPrinter::new(false));
        assert!(pairs_par.is_empty());
        assert_eq!(nc_par.collapsed_lines, 0);
    }

    #[test]
    fn pair_all_groups_single_group() {
        let mut store = MessageStore::new();
        store.add(ap(), sta(), make_msg(MsgType::M1, 1, 0));
        store.add(ap(), sta(), make_msg(MsgType::M2, 1, 100));
        let config = PairConfig::default();
        let (pairs, _nc) = pair_all_groups(&store, &config, 1, &DebugPrinter::new(false));
        assert!(!pairs.is_empty(), "expected at least one PairedHash from M1+M2");
        assert_eq!(pairs[0].combo_type, ComboType::N1E2);
    }

    #[test]
    fn estimate_group_cost_known_counts() {
        // 3 M1, 2 M2, 1 M3, 1 M4
        // Cost = 3*2 + 3*1 + 1*2 + 2*1 + 1*1 + 1*1 = 6 + 3 + 2 + 2 + 1 + 1 = 15
        let msgs = vec![
            make_msg(MsgType::M1, 1, 0),
            make_msg(MsgType::M1, 2, 1),
            make_msg(MsgType::M1, 3, 2),
            make_msg(MsgType::M2, 1, 3),
            make_msg(MsgType::M2, 2, 4),
            make_msg(MsgType::M3, 1, 5),
            make_msg(MsgType::M4, 1, 6),
        ];
        assert_eq!(estimate_group_cost(&msgs), 15);
    }

    #[test]
    fn estimate_group_cost_empty() {
        assert_eq!(estimate_group_cost(&[]), 0);
    }

    #[test]
    fn estimate_group_cost_single_type() {
        // Only M1s: no pairings possible (all cross-products are 0).
        let msgs = vec![make_msg(MsgType::M1, 1, 0), make_msg(MsgType::M1, 2, 1)];
        assert_eq!(estimate_group_cost(&msgs), 0);
    }

    #[test]
    fn pair_all_groups_parallel_matches_serial() {
        // Build a store with multiple groups of varying sizes.
        let config = PairConfig::default();
        let mut store = MessageStore::new();

        // Group 1: full 4-way handshake
        let ap1 = MacAddr::from_bytes([0x11; 6]);
        let sta1 = MacAddr::from_bytes([0x22; 6]);
        store.add(ap1, sta1, make_msg(MsgType::M1, 1, 0));
        store.add(ap1, sta1, make_msg(MsgType::M2, 1, 100));
        store.add(ap1, sta1, make_msg(MsgType::M3, 2, 200));
        store.add(ap1, sta1, make_msg(MsgType::M4, 2, 300));

        // Group 2: M1+M2 only
        let ap2 = MacAddr::from_bytes([0x33; 6]);
        let sta2 = MacAddr::from_bytes([0x44; 6]);
        store.add(ap2, sta2, make_msg(MsgType::M1, 1, 0));
        store.add(ap2, sta2, make_msg(MsgType::M2, 1, 100));

        // Group 3: M1+M3+M4
        let ap3 = MacAddr::from_bytes([0x55; 6]);
        let sta3 = MacAddr::from_bytes([0x66; 6]);
        store.add(ap3, sta3, make_msg(MsgType::M1, 1, 0));
        store.add(ap3, sta3, make_msg(MsgType::M3, 2, 100));
        store.add(ap3, sta3, make_msg(MsgType::M4, 2, 200));

        let (serial, _nc_s) = pair_all_groups(&store, &config, 1, &DebugPrinter::new(false));
        let (parallel, _nc_p) = pair_all_groups(&store, &config, 4, &DebugPrinter::new(false));

        assert_eq!(serial.len(), parallel.len(), "serial and parallel must produce same count");

        // Compare by fingerprint set (order may differ due to group iteration order).
        let fp = |p: &PairedHash| (p.ap, p.sta, p.message_pair, p.nonce, p.mic);
        let mut s: Vec<_> = serial.iter().map(fp).collect();
        let mut p: Vec<_> = parallel.iter().map(fp).collect();
        s.sort();
        p.sort();
        assert_eq!(s, p, "serial and parallel must produce identical pair sets");
    }

    #[test]
    fn pair_all_groups_more_threads_than_groups() {
        // 2 groups, 16 threads -- must not panic or deadlock.
        let config = PairConfig::default();
        let mut store = MessageStore::new();
        store.add(ap(), sta(), make_msg(MsgType::M1, 1, 0));
        store.add(ap(), sta(), make_msg(MsgType::M2, 1, 100));
        let ap2 = MacAddr::from_bytes([0x33; 6]);
        let sta2 = MacAddr::from_bytes([0x44; 6]);
        store.add(ap2, sta2, make_msg(MsgType::M1, 1, 0));
        store.add(ap2, sta2, make_msg(MsgType::M2, 1, 100));

        let (pairs, _nc) = pair_all_groups(&store, &config, 16, &DebugPrinter::new(false));
        assert!(!pairs.is_empty());
    }
}
