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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use crate::debug::{DebugPrinter, HEAVY_GROUP_COST, group_progress_interval};
use crate::pair::collapse::collapse;
use crate::pair::combos::{PairConfig, generate};
use crate::pair::nc_dedup::{NcDedupStats, nc_dedup};
use crate::store::messages::{EapolMessage, MessageStore};
use crate::types::{MacPair, MsgType};

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
/// Used by `pair_all_groups` for LPT (Longest Processing Time) scheduling: groups
/// with higher cost are assigned first so the heaviest group doesn't end up queued
/// behind lighter groups on the same thread.
#[must_use]
pub fn estimate_group_cost(messages: &[EapolMessage]) -> u64 {
    let (mut m1, mut m2, mut m3, mut m4) = (0u64, 0u64, 0u64, 0u64);
    for msg in messages {
        match msg.msg_type {
            MsgType::M1 => m1 += 1,
            MsgType::M2 => m2 += 1,
            MsgType::M3 => m3 += 1,
            MsgType::M4 => m4 += 1,
        }
    }
    // Six combo cross-products: N1E2 + N1E4 + N3E2 + N2E3 + N4E3 + N3E4
    m1 * m2 + m1 * m4 + m3 * m2 + m2 * m3 + m4 * m3 + m3 * m4
}

/// Pairs a single group: clone, sort, generate combos, collapse, NC-dedup.
///
/// Factored out so both the serial path and threaded workers share the same
/// logic. Returns the pruned pair vec plus the NC-dedup stats triple; when
/// `config.nc_dedup_enabled` is false the stats triple is zero and the pair
/// vec is byte-identical to the pre-NC-dedup output.
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

/// Runs the full pairing pipeline over all (AP, STA) groups in `store`.
///
/// When `thread_count > 1` and there are multiple groups, uses `std::thread::scope`
/// to pair groups in parallel across `thread_count` worker threads. Groups are assigned
/// to threads via LPT (Longest Processing Time First) round-robin scheduling to
/// balance uneven workloads. Each thread returns its local `Vec<PairedHash>` and
/// results are concatenated after all threads join.
///
/// Falls back to a serial loop when `thread_count == 1` or there is only one group.
///
/// For each group:
/// 1. Sorts messages by timestamp (ascending).
/// 2. Calls `combos::generate` to try all six N#E# combinations.
/// 3. Unless `config.all_combos`, calls `collapse::collapse` to deduplicate
///    equivalence classes (up to 3 unique hashes per session).
/// 4. When `config.nc_dedup_enabled`, calls `nc_dedup::nc_dedup` to fold
///    near-identical-nonce siblings into one survivor.
///
/// Returns all `PairedHash` values across all groups plus the aggregate
/// `NcDedupStats` (component-wise sum, max for `max_cluster_size`).
/// See `ARCHITECTURE.md §5.5` and `§5.8.1`.
#[must_use]
pub fn pair_all_groups(
    store: &MessageStore,
    config: &PairConfig,
    thread_count: usize,
    debug: &DebugPrinter,
) -> (Vec<PairedHash>, NcDedupStats) {
    let groups: Vec<(&MacPair, &Vec<EapolMessage>)> = store.groups().collect();

    if groups.is_empty() {
        return (Vec::new(), NcDedupStats::default());
    }

    let effective_threads = thread_count.max(1).min(groups.len());
    let total_groups = groups.len();

    // Atomic counters shared between the serial / parallel paths for the progress ticker.
    // Relaxed ordering is fine: the ticker is display-only and does not gate correctness.
    let groups_done = AtomicUsize::new(0);
    let pairs_done = AtomicUsize::new(0);

    // --- Serial fast path ---
    if effective_threads <= 1 {
        let mut all_pairs: Vec<PairedHash> = Vec::new();
        let mut all_nc = NcDedupStats::default();
        for &(mac_pair, messages) in &groups {
            let (m1, m2, m3, m4, cost) = group_counts_and_cost(messages);
            debug.group_start(mac_pair.ap, mac_pair.sta, m1, m2, m3, m4, cost);
            if cost >= HEAVY_GROUP_COST {
                debug.memory_check(&format!(
                    "Phase 4 pairing ap={} sta={} m1={m1} m2={m2} m3={m3} m4={m4} cost={cost}",
                    mac_pair.ap, mac_pair.sta
                ));
            }
            let t0 = Instant::now();
            let (pairs, nc) = pair_one_group(mac_pair, messages, config);
            let elapsed_us = t0.elapsed().as_micros();
            debug.group_done(mac_pair.ap, mac_pair.sta, pairs.len(), elapsed_us, cost);
            let done = groups_done.fetch_add(1, Ordering::Relaxed) + 1;
            pairs_done.fetch_add(pairs.len(), Ordering::Relaxed);
            if done % group_progress_interval() == 0 || done == total_groups {
                debug.group_progress(done, total_groups, pairs_done.load(Ordering::Relaxed));
            }
            all_pairs.extend(pairs);
            merge_nc_stats(&mut all_nc, nc);
        }
        return (all_pairs, all_nc);
    }

    // --- Parallel path: LPT round-robin scheduling with std::thread::scope ---

    // Estimate cost per group for load-balancing.
    let mut indexed: Vec<(usize, u64)> =
        groups.iter().enumerate().map(|(i, &(_, msgs))| (i, estimate_group_cost(msgs))).collect();
    // Sort descending by cost (heaviest groups assigned first).
    indexed.sort_unstable_by_key(|entry| std::cmp::Reverse(entry.1));

    // Round-robin assignment to thread buckets (LPT heuristic).
    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); effective_threads];
    for (rank, &(group_idx, _)) in indexed.iter().enumerate() {
        if let Some(bucket) = buckets.get_mut(rank % effective_threads) {
            bucket.push(group_idx);
        }
    }

    // Spawn scoped threads -- each thread pairs its assigned groups and
    // returns (pairs, nc_stats). Stats merge after join.
    let groups_ref = &groups;
    let groups_done_ref = &groups_done;
    let pairs_done_ref = &pairs_done;
    std::thread::scope(|s| {
        let handles: Vec<_> = buckets
            .iter()
            .filter(|b| !b.is_empty())
            .map(|bucket| {
                s.spawn(move || {
                    let mut local_pairs: Vec<PairedHash> = Vec::new();
                    let mut local_nc = NcDedupStats::default();
                    for &group_idx in bucket {
                        let Some(&(mac_pair, messages)) = groups_ref.get(group_idx) else {
                            continue;
                        };
                        let (m1, m2, m3, m4, cost) = group_counts_and_cost(messages);
                        debug.group_start(mac_pair.ap, mac_pair.sta, m1, m2, m3, m4, cost);
                        if cost >= HEAVY_GROUP_COST {
                            debug.memory_check(&format!(
                                "Phase 4 pairing ap={} sta={} m1={m1} m2={m2} m3={m3} m4={m4} cost={cost}",
                                mac_pair.ap, mac_pair.sta
                            ));
                        }
                        let t0 = Instant::now();
                        let (pairs, nc) = pair_one_group(mac_pair, messages, config);
                        let elapsed_us = t0.elapsed().as_micros();
                        debug.group_done(mac_pair.ap, mac_pair.sta, pairs.len(), elapsed_us, cost);
                        let done = groups_done_ref.fetch_add(1, Ordering::Relaxed) + 1;
                        pairs_done_ref.fetch_add(pairs.len(), Ordering::Relaxed);
                        if done % group_progress_interval() == 0 || done == total_groups {
                            debug.group_progress(done, total_groups, pairs_done_ref.load(Ordering::Relaxed));
                        }
                        local_pairs.extend(pairs);
                        merge_nc_stats(&mut local_nc, nc);
                    }
                    (local_pairs, local_nc)
                })
            })
            .collect();

        // Collect results from all threads.
        let total_capacity: usize = handles.len() * 1024; // rough pre-alloc
        let mut all_pairs: Vec<PairedHash> = Vec::with_capacity(total_capacity);
        let mut all_nc = NcDedupStats::default();
        for handle in handles {
            // Thread body is pure computation (no indexing, no unwrap). Cannot panic.
            if let Ok((pairs, nc)) = handle.join() {
                all_pairs.extend(pairs);
                merge_nc_stats(&mut all_nc, nc);
            }
        }
        (all_pairs, all_nc)
    })
}

/// Returns `(m1, m2, m3, m4, cost)` for a message slice.
///
/// Extracted from `pair_all_groups` so both the serial and parallel paths share the
/// same counting logic without duplicating the iteration.
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
