//! Phase 4 -- Emit: cluster near-identical-nonce siblings within one (AP, STA, EAPOL, MIC, combo) class.
//!
//! Some firmware emits dozens of EAPOL-Key messages for one (AP, STA) that share
//! the same EAPOL body and MIC but differ only in the trailing bytes of the
//! `ANonce` (or `SNonce`). Each variant produces a distinct WPA*02* line under
//! wpawolf's default byte-exact dedup, even though hashcat with
//! `--nonce-error-corrections=N` (default 8) can recover all of them from a
//! single representative by iterating `+/- N/2` on the trailing byte at
//! MIC-verify time -- *if* wpawolf emits the representative tagged with
//! `FLAG_NC` (`0x80`).
//!
//! This module performs that clustering pass. It runs once per (AP, STA) group
//! after `collapse()` and is gated on `PairConfig::nc_dedup_enabled` (off by
//! default). Cluster scope: `(eapol_frame, mic, combo_type, nonce[..28])`. Within
//! each bucket the trailing 4 bytes of the nonce are interpreted as a `u32`
//! (both endiannesses tried), sorted, and split into contiguous runs whose
//! `max - min` span fits within `PairConfig::nc_tolerance` (default 8 -- matches
//! hashcat's `NONCE_ERROR_CORRECTIONS=8`). The hashcat-safest observed nonce in
//! each cluster -- the one minimising `max(tail - min, max - tail)` -- becomes
//! the survivor; its `message_pair` byte gains `FLAG_NC` plus `FLAG_LE` or
//! `FLAG_BE` depending on which interpretation produced the tighter
//! clustering. The remaining cluster members are dropped.
//!
//! Why hashcat-safest: hashcat with `NC=N` iterates
//! `[survivor - N/2, survivor + N/2]` symmetrically. For dense clusters the
//! sorted-median is the safest observation, but for sparse-edge clusters
//! (e.g. just `[0, N]`) the median sits at an edge and hashcat's `+/- N/2`
//! window cannot reach the opposite edge. The safety check skips collapse in
//! that case: better to emit both observations as singletons than to silently
//! drop a sibling hashcat cannot recover.
//!
//! Why this is safe by spec: IEEE 802.11-2024 §12.7.2 NOTE 9 -- "the key replay
//! counter does not play any role beyond a performance optimization; replay
//! protection is provided by selecting a never-before-used nonce." Merging
//! near-identical nonces does not violate the protocol; it acknowledges
//! firmware that re-uses an almost-identical nonce across consecutive
//! handshake attempts and lets the cracker recover the exact value within
//! tolerance.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::combos::PairConfig;
use super::{FLAG_BE, FLAG_LE, FLAG_NC, PairedHash};

// --- Public API ---

/// Counters produced by one call to [`nc_dedup`].
///
/// Surfaces to the closing stats banner so operators can see at a glance how
/// many lines the clustering pass removed and how dense the densest cluster
/// got. Fields aggregate naturally via component-wise sum (with `max` for
/// `max_cluster_size`); see `pair_all_groups` for the cross-group rollup.
#[derive(Default, Debug, Clone, Copy)]
pub struct NcDedupStats {
    /// Number of input lines dropped (`sum_over_clusters(size - 1)`).
    pub collapsed_lines: u64,
    /// Number of clusters of size >= 2 that produced a survivor.
    pub cluster_count: u64,
    /// Largest cluster size observed in this call.
    pub max_cluster_size: u64,
    /// Candidate pairs dropped by the `--eapoltimeout` filter in `generate`.
    /// Carried on this per-group stats struct so the filter drops ride the same
    /// streaming and disk merge paths as the NC-dedup counts. Zero in WIDE mode.
    pub time_filtered: u64,
    /// Candidate pairs dropped by the `--rc-drift` filter in `generate`. Zero in
    /// WIDE mode.
    pub rc_filtered: u64,
    /// Messages excluded from pairing by the `--max-eapol-per-type` cap in
    /// `generate`. Carried on the same per-group struct as the filter drops.
    /// Zero when the cap is off (the default).
    pub messages_capped: u64,
}

/// Collapses near-identical-nonce siblings within `pairs`, tagging the survivor
/// with `FLAG_NC` (plus `FLAG_LE` / `FLAG_BE`) so hashcat's
/// `--nonce-error-corrections` recovers the dropped variants.
///
/// Returns the surviving pairs in their original first-seen order plus a
/// counter triple describing how many lines were collapsed.
///
/// When `config.nc_dedup_enabled` is `false`, returns the input unchanged with
/// a zero stats triple. Singleton buckets (size 1) pass through untouched and
/// do NOT gain `FLAG_NC`, since hashcat NC iteration is wasted CPU when no
/// other observed nonce sits within tolerance.
#[must_use]
pub fn nc_dedup(pairs: Vec<PairedHash>, config: &PairConfig) -> (Vec<PairedHash>, NcDedupStats) {
    if !config.nc_dedup_enabled || pairs.len() < 2 {
        return (pairs, NcDedupStats::default());
    }

    // Step 1: bucket by (eapol_frame, mic, combo_type, nonce[..28]).
    //
    // `Arc<[u8]>` hashes by byte content (same convention as collapse.rs), so two
    // pairs that reference physically-distinct EAPOL allocations still bucket
    // together if their bytes match. `combo_type` is hashed via its u8 cast
    // because `ComboType` does not derive `Hash`.
    let tolerance = u32::from(config.nc_tolerance);
    let mut buckets: HashMap<ClusterKey, Vec<usize>> = HashMap::with_capacity(pairs.len());
    for (i, p) in pairs.iter().enumerate() {
        let mut prefix = [0u8; 28];
        prefix.copy_from_slice(&p.nonce[..28]);
        let key = ClusterKey {
            eapol_frame: Arc::clone(&p.eapol_frame),
            mic: p.mic,
            combo_disc: p.combo_type as u8,
            nonce_prefix: prefix,
        };
        buckets.entry(key).or_default().push(i);
    }

    // Step 2 + 3: cluster within each bucket; pick LE vs BE by whichever drops
    // the most lines (LE wins ties). Survivors get FLAG_NC | flag overlay.
    let mut stats = NcDedupStats::default();
    let mut to_drop: HashSet<usize> = HashSet::new();
    let mut overlay: HashMap<usize, u8> = HashMap::new();

    for (_, indices) in buckets {
        if indices.len() < 2 {
            continue; // singleton bucket -- nothing to cluster, no FLAG_NC.
        }

        let (le_clusters, le_collapsed) = cluster_indices(&indices, &pairs, tolerance, Endianness::Le);
        let (be_clusters, be_collapsed) = cluster_indices(&indices, &pairs, tolerance, Endianness::Be);

        let (clusters, flag, endian) = if le_collapsed >= be_collapsed {
            (le_clusters, FLAG_LE, Endianness::Le)
        } else {
            (be_clusters, FLAG_BE, Endianness::Be)
        };

        // Hashcat's `--nonce-error-corrections=tolerance` iterates `[survivor -
        // tolerance/2, survivor + tolerance/2]` around the emitted nonce. To
        // ensure every cluster member can be recovered, `max(survivor - min,
        // max - survivor)` must fit inside `tolerance / 2`. For densely-packed
        // clusters the median observation satisfies this; for sparse clusters
        // (e.g. just `[0, tolerance]`) no observation does, so we skip the
        // collapse entirely rather than emit a survivor that hashcat would
        // fail to recover the dropped siblings for.
        let half_tol = tolerance / 2;

        for cluster in clusters {
            if cluster.len() < 2 {
                continue; // singleton cluster -- not a collapse candidate.
            }
            // Pick the observed nonce whose iteration window best covers the
            // cluster: minimize `max(value - min, max - value)`. Falls back to
            // the smaller value on ties (deterministic across runs).
            let Some(survivor) = pick_safe_survivor(&cluster, &pairs, endian, half_tol) else {
                // No observation in the cluster can serve as a hashcat-safe
                // survivor for this `tolerance`. Leave the members as
                // singletons -- correctness over collapse.
                continue;
            };

            let size_u64 = u64::try_from(cluster.len()).unwrap_or(0);
            stats.collapsed_lines += size_u64.saturating_sub(1);
            stats.cluster_count += 1;
            if size_u64 > stats.max_cluster_size {
                stats.max_cluster_size = size_u64;
            }

            overlay.insert(survivor, FLAG_NC | flag);
            for &idx in &cluster {
                if idx != survivor {
                    to_drop.insert(idx);
                }
            }
        }
    }

    // Step 4: walk input in order; drop cluster non-survivors, apply overlay
    // to survivors. Preserves first-seen order so the emit phase sees a stable
    // line sequence.
    let mut kept: Vec<PairedHash> = Vec::with_capacity(pairs.len().saturating_sub(to_drop.len()));
    for (i, mut p) in pairs.into_iter().enumerate() {
        if to_drop.contains(&i) {
            continue;
        }
        if let Some(&flag) = overlay.get(&i) {
            p.message_pair |= flag;
        }
        kept.push(p);
    }

    (kept, stats)
}

// --- Internals ---

/// Hash key for the per-bucket clustering pass.
///
/// Two pairs share a bucket iff every field matches. `combo_type` participates
/// via its u8 discriminant because the parent enum does not derive `Hash`.
#[derive(Clone, Debug)]
struct ClusterKey {
    eapol_frame: Arc<[u8]>,
    mic: crate::types::MicBytes,
    combo_disc: u8,
    nonce_prefix: [u8; 28],
}

impl PartialEq for ClusterKey {
    fn eq(&self, other: &Self) -> bool {
        self.combo_disc == other.combo_disc
            && self.nonce_prefix == other.nonce_prefix
            && self.mic == other.mic
            && self.eapol_frame == other.eapol_frame
    }
}

impl Eq for ClusterKey {}

impl std::hash::Hash for ClusterKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Arc<[u8]>::hash defers to the slice contents, same as in pair::collapse.
        self.eapol_frame.hash(state);
        self.mic.hash(state);
        self.combo_disc.hash(state);
        self.nonce_prefix.hash(state);
    }
}

/// Which endianness is used to interpret the trailing 4 nonce bytes.
#[derive(Clone, Copy)]
enum Endianness {
    Le,
    Be,
}

/// Reads `nonce[28..32]` as a `u32` in the given endianness.
fn tail_u32(nonce: &[u8; 32], endian: Endianness) -> u32 {
    let bytes: [u8; 4] = nonce.get(28..32).and_then(|s| s.try_into().ok()).unwrap_or([0; 4]);
    match endian {
        Endianness::Le => u32::from_le_bytes(bytes),
        Endianness::Be => u32::from_be_bytes(bytes),
    }
}

/// Returns the cluster member whose tail value minimises
/// `max(tail - min, max - tail)`, provided that minimum fits inside
/// `half_tol` (= `tolerance / 2`).
///
/// Hashcat's `--nonce-error-corrections=tolerance` recovers a survivor's
/// dropped siblings only when every sibling's tail value lies within
/// `[survivor - half_tol, survivor + half_tol]`. For densely-packed clusters
/// the sorted-median observation satisfies this; for sparse-edge clusters
/// (e.g. just `[0, tolerance]`) no observation does, in which case we return
/// `None` so the caller leaves the members as singletons.
///
/// `cluster` is the index list returned by `cluster_indices`; the indices are
/// sorted ascending by tail value under the same `endian`.
fn pick_safe_survivor(cluster: &[usize], pairs: &[PairedHash], endian: Endianness, half_tol: u32) -> Option<usize> {
    // Compute tail values once. Cluster is already sorted ascending under
    // `endian`, so the first and last entries give min and max.
    let tails: Vec<u32> = cluster.iter().filter_map(|&i| pairs.get(i).map(|p| tail_u32(&p.nonce, endian))).collect();
    let &min_tail = tails.first()?;
    let &max_tail = tails.last()?;

    // Walk every member, track the one that minimises `max(t - min, max - t)`.
    // Ties resolve to the smaller cluster index for deterministic survivor
    // selection across runs.
    let mut best_idx: Option<usize> = None;
    let mut best_dist: u32 = u32::MAX;
    for (pos, &cluster_idx) in cluster.iter().enumerate() {
        let Some(&tail) = tails.get(pos) else { continue };
        let dist = std::cmp::max(tail.saturating_sub(min_tail), max_tail.saturating_sub(tail));
        if dist < best_dist {
            best_dist = dist;
            best_idx = Some(cluster_idx);
        }
    }

    // Hashcat-safety guard: every cluster member must be within +/-half_tol of
    // the survivor. If the best survivor cannot meet that, skip the collapse.
    if best_dist <= half_tol { best_idx } else { None }
}

/// Clusters `indices` (input positions into `pairs`) by `tail_u32` value under
/// `endian`, with a span tolerance of `tolerance`.
///
/// Returns `(clusters, collapsed_count)` where each inner `Vec<usize>` is
/// sorted ascending by tail value and `collapsed_count = sum(size - 1)` over
/// clusters of size >= 2. Singleton clusters are included in the return so the
/// caller can fold them back into the output stream untouched.
fn cluster_indices(
    indices: &[usize],
    pairs: &[PairedHash],
    tolerance: u32,
    endian: Endianness,
) -> (Vec<Vec<usize>>, u64) {
    // Build (tail_value, input_index) pairs, sort ascending.
    let mut tagged: Vec<(u32, usize)> =
        indices.iter().filter_map(|&i| pairs.get(i).map(|p| (tail_u32(&p.nonce, endian), i))).collect();
    tagged.sort_unstable_by_key(|&(v, _)| v);

    // Sliding span split: start a new cluster when the next tail value exceeds
    // `cluster_start + tolerance`. `max - min` thus stays <= `tolerance`
    // across every cluster member, not just adjacent ones.
    let mut clusters: Vec<Vec<usize>> = Vec::new();
    let mut current: Vec<usize> = Vec::new();
    let mut cluster_start: u32 = 0;
    for (val, idx) in tagged {
        if current.is_empty() {
            cluster_start = val;
        } else if val.saturating_sub(cluster_start) > tolerance {
            clusters.push(std::mem::take(&mut current));
            cluster_start = val;
        }
        current.push(idx);
    }
    if !current.is_empty() {
        clusters.push(current);
    }

    let collapsed: u64 =
        clusters.iter().filter(|c| c.len() >= 2).map(|c| u64::try_from(c.len()).unwrap_or(0).saturating_sub(1)).sum();

    (clusters, collapsed)
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
    use crate::pair::ComboType;
    use crate::types::{AkmType, MacAddr, MicBytes};

    /// Builds a `PairedHash` with the fields `nc_dedup` looks at (`nonce`,
    /// `mic`, `eapol_frame`, `combo_type`) varied; all other fields are sentinels.
    fn make_pair(combo: ComboType, nonce: [u8; 32], mic_byte: u8, eapol_byte: u8) -> PairedHash {
        PairedHash {
            ap: MacAddr::from_bytes([0x11; 6]),
            sta: MacAddr::from_bytes([0x22; 6]),
            combo_type: combo,
            nonce,
            eapol_frame: Arc::from(vec![eapol_byte; 99]),
            mic: MicBytes::from_16([mic_byte; 16]),
            message_pair: combo as u8,
            akm: AkmType::Wpa2Psk,
            ft: None,
            rc_gap_magnitude: 0,
        }
    }

    /// Builds a nonce with the trailing byte set to `tail` and the rest fixed.
    fn nonce_with_le_tail(tail: u8) -> [u8; 32] {
        // 28 bytes of fixed prefix, then [0x00, 0x00, 0x00, tail] -> LE u32 == tail
        let mut n = [0x42u8; 32];
        n[28] = tail;
        n[29] = 0x00;
        n[30] = 0x00;
        n[31] = 0x00;
        n
    }

    /// Builds a nonce with the trailing 4 bytes set to interpret as `value` in BE.
    fn nonce_with_be_tail_value(value: u32) -> [u8; 32] {
        let mut n = [0x99u8; 32];
        let bytes = value.to_be_bytes();
        n[28] = bytes[0];
        n[29] = bytes[1];
        n[30] = bytes[2];
        n[31] = bytes[3];
        n
    }

    fn config_with_nc(tolerance: u8) -> PairConfig {
        PairConfig { nc_dedup_enabled: true, nc_tolerance: tolerance, ..PairConfig::default() }
    }

    #[test]
    fn nc_dedup_disabled_passes_through_unchanged() {
        // With nc_dedup_enabled=false, even a perfect cluster passes through untouched.
        let pairs = (0u8..5).map(|t| make_pair(ComboType::N1E2, nonce_with_le_tail(t), 0xCC, 0xDD)).collect::<Vec<_>>();
        let original_len = pairs.len();
        let (out, stats) = nc_dedup(pairs, &PairConfig::default());
        assert_eq!(out.len(), original_len);
        assert_eq!(stats.collapsed_lines, 0);
        assert_eq!(stats.cluster_count, 0);
        assert_eq!(stats.max_cluster_size, 0);
        // No FLAG_NC must appear on any surviving pair.
        assert!(out.iter().all(|p| p.message_pair & FLAG_NC == 0));
    }

    #[test]
    fn nc_dedup_le_cluster_of_nine_collapses_to_one_with_flag_nc_and_flag_le() {
        // 9 pairs differing only in nonce[31] (LE tail) spanning 0..=8 -> 1 cluster.
        let pairs: Vec<PairedHash> =
            (0u8..=8).map(|t| make_pair(ComboType::N1E2, nonce_with_le_tail(t), 0xCC, 0xDD)).collect();
        let (out, stats) = nc_dedup(pairs, &config_with_nc(8));
        assert_eq!(out.len(), 1, "9 same-bucket nonces with span 8 -> one survivor");
        assert_eq!(stats.collapsed_lines, 8);
        assert_eq!(stats.cluster_count, 1);
        assert_eq!(stats.max_cluster_size, 9);
        let survivor = &out[0];
        assert_ne!(survivor.message_pair & FLAG_NC, 0, "survivor must carry FLAG_NC");
        assert_ne!(survivor.message_pair & FLAG_LE, 0, "LE clustering must set FLAG_LE");
    }

    #[test]
    fn nc_dedup_be_cluster_collapses_to_one_with_flag_be() {
        // 9 pairs differing in BE-interpreted tail value (big strides on byte 28,
        // identical bytes 29..32). LE interpretation produces 9 wildly-separated
        // values (256, 512, ..., 2304 vs the tolerance of 8); BE produces 9
        // consecutive values 0..=8. BE must win.
        let pairs: Vec<PairedHash> =
            (0u32..=8).map(|t| make_pair(ComboType::N1E2, nonce_with_be_tail_value(t), 0xCC, 0xDD)).collect();
        let (out, stats) = nc_dedup(pairs, &config_with_nc(8));
        assert_eq!(out.len(), 1);
        assert_eq!(stats.collapsed_lines, 8);
        assert_eq!(stats.cluster_count, 1);
        let survivor = &out[0];
        assert_ne!(survivor.message_pair & FLAG_NC, 0, "survivor must carry FLAG_NC");
        assert_ne!(survivor.message_pair & FLAG_BE, 0, "BE clustering must set FLAG_BE");
    }

    #[test]
    fn nc_dedup_span_exceeds_tolerance_splits_into_two() {
        // 17 pairs cycling LE tail 0x00..=0x10 with tolerance=8 split into two
        // clusters: [0x00..=0x08] (9 elements) and [0x09..=0x10] (8 elements).
        let pairs: Vec<PairedHash> =
            (0x00u8..=0x10).map(|t| make_pair(ComboType::N1E2, nonce_with_le_tail(t), 0xCC, 0xDD)).collect();
        let (out, stats) = nc_dedup(pairs, &config_with_nc(8));
        assert_eq!(out.len(), 2, "two clusters -> two survivors");
        assert_eq!(stats.cluster_count, 2);
        // 17 input - 2 survivors = 15 collapsed.
        assert_eq!(stats.collapsed_lines, 15);
        assert_eq!(stats.max_cluster_size, 9);
    }

    #[test]
    fn nc_dedup_isolated_singleton_unchanged() {
        // One bucket with one entry -> no clustering, no FLAG_NC, stats stay 0.
        let pairs = vec![make_pair(ComboType::N1E2, nonce_with_le_tail(0x42), 0xCC, 0xDD)];
        let (out, stats) = nc_dedup(pairs, &config_with_nc(8));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].message_pair & FLAG_NC, 0, "singleton must not gain FLAG_NC");
        assert_eq!(stats.collapsed_lines, 0);
        assert_eq!(stats.cluster_count, 0);
        assert_eq!(stats.max_cluster_size, 0);
    }

    #[test]
    fn nc_dedup_mixed_cluster_and_singleton() {
        // One cluster of 5 (tails 0..=4) plus three unrelated singletons (different
        // EAPOL frames). The cluster collapses to 1; the singletons survive as-is.
        let mut pairs: Vec<PairedHash> =
            (0u8..5).map(|t| make_pair(ComboType::N1E2, nonce_with_le_tail(t), 0xCC, 0xDD)).collect();
        // Three unrelated entries (different eapol_byte -> distinct bucket -> singletons).
        pairs.push(make_pair(ComboType::N1E2, nonce_with_le_tail(0x10), 0xCC, 0xEE));
        pairs.push(make_pair(ComboType::N1E2, nonce_with_le_tail(0x20), 0xCC, 0xEF));
        pairs.push(make_pair(ComboType::N1E2, nonce_with_le_tail(0x30), 0xCC, 0xF0));
        let (out, stats) = nc_dedup(pairs, &config_with_nc(8));
        assert_eq!(out.len(), 4, "1 cluster survivor + 3 singletons");
        assert_eq!(stats.collapsed_lines, 4);
        assert_eq!(stats.cluster_count, 1);
        assert_eq!(stats.max_cluster_size, 5);
    }

    #[test]
    fn nc_dedup_does_not_merge_across_eapol_frame() {
        // Identical nonces + MIC + combo but different EAPOL frame bytes ->
        // two separate buckets -> two singletons -> no collapse.
        let pairs = vec![
            make_pair(ComboType::N1E2, nonce_with_le_tail(0x42), 0xCC, 0xDD),
            make_pair(ComboType::N1E2, nonce_with_le_tail(0x42), 0xCC, 0xEE),
        ];
        let (out, stats) = nc_dedup(pairs, &config_with_nc(8));
        assert_eq!(out.len(), 2, "different EAPOL frames must not merge");
        assert_eq!(stats.collapsed_lines, 0);
    }

    #[test]
    fn nc_dedup_does_not_merge_across_combo_type() {
        // N1E2 and N3E2 with otherwise-identical fields must stay in separate buckets.
        let nonce = nonce_with_le_tail(0x42);
        let pairs = vec![make_pair(ComboType::N1E2, nonce, 0xCC, 0xDD), make_pair(ComboType::N3E2, nonce, 0xCC, 0xDD)];
        let (out, stats) = nc_dedup(pairs, &config_with_nc(8));
        assert_eq!(out.len(), 2, "different combo_type must not merge");
        assert_eq!(stats.collapsed_lines, 0);
    }

    #[test]
    fn nc_dedup_dense_cluster_survivor_is_center_observation() {
        // 9 pairs with LE tails 0x10..=0x18, tolerance 8. For a densely-packed
        // cluster the safest-survivor rule picks the same observation as the
        // sorted-median (0x14, distance 4 to both edges -- the only observation
        // hashcat NC=8 can recover every dropped sibling from).
        let pairs: Vec<PairedHash> =
            (0x10u8..=0x18).map(|t| make_pair(ComboType::N1E2, nonce_with_le_tail(t), 0xCC, 0xDD)).collect();
        let (out, _) = nc_dedup(pairs, &config_with_nc(8));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].nonce[28], 0x14, "dense-cluster safest survivor of 0x10..=0x18 is 0x14");
    }

    #[test]
    fn nc_dedup_sparse_two_member_cluster_at_tolerance_edges_does_not_collapse() {
        // Two pairs with LE tails 0 and 8 (span equals tolerance=8). Hashcat
        // NC=8 iterates `[survivor - 4, survivor + 4]`; neither tail can
        // reach the other from any survivor. NC-dedup must skip the
        // collapse so the dropped sibling is not silently uncrackable.
        let pairs = vec![
            make_pair(ComboType::N1E2, nonce_with_le_tail(0x00), 0xCC, 0xDD),
            make_pair(ComboType::N1E2, nonce_with_le_tail(0x08), 0xCC, 0xDD),
        ];
        let (out, stats) = nc_dedup(pairs, &config_with_nc(8));
        assert_eq!(out.len(), 2, "sparse 2-member cluster at edges must stay as two singletons");
        assert_eq!(stats.collapsed_lines, 0);
        assert_eq!(stats.cluster_count, 0);
        // Neither survivor must carry FLAG_NC.
        assert!(out.iter().all(|p| p.message_pair & FLAG_NC == 0));
    }

    #[test]
    fn nc_dedup_picks_non_median_survivor_when_it_is_hashcat_safer() {
        // Cluster of 5 tails [0x00, 0x04, 0x05, 0x06, 0x08]. Sorted-median
        // (index 2) is 0x05 -- distance to min is 5, to max is 3, max is 5 > 4
        // so a median survivor cannot recover all members under hashcat NC=8.
        // The non-median observation at 0x04 minimises max-distance to 4
        // (=half-tolerance) and is the only safe survivor.
        let tails: [u8; 5] = [0x00, 0x04, 0x05, 0x06, 0x08];
        let pairs: Vec<PairedHash> =
            tails.iter().map(|&t| make_pair(ComboType::N1E2, nonce_with_le_tail(t), 0xCC, 0xDD)).collect();
        let (out, stats) = nc_dedup(pairs, &config_with_nc(8));
        assert_eq!(out.len(), 1, "5-member cluster collapses to one safe survivor");
        assert_eq!(stats.collapsed_lines, 4);
        assert_eq!(
            out[0].nonce[28], 0x04,
            "survivor must be the hashcat-safest observation (0x04), not the sorted-median (0x05)"
        );
    }

    #[test]
    fn nc_dedup_stats_for_parity_report_26_nonce_cluster() {
        // Upstream parity-report shape: 26 nonces sharing the 28-byte prefix and MIC,
        // trailing byte cycling 0x4d..=0x66 (26 values). With tolerance=8, three
        // clusters of sizes 9, 9, 8 form; the maximum is 9 and 26 - 3 = 23 lines
        // collapse.
        let pairs: Vec<PairedHash> =
            (0x4du8..=0x66).map(|t| make_pair(ComboType::N1E2, nonce_with_le_tail(t), 0xCC, 0xDD)).collect();
        assert_eq!(pairs.len(), 26, "fixture must reproduce the reported nonce count");
        let (out, stats) = nc_dedup(pairs, &config_with_nc(8));
        assert_eq!(stats.collapsed_lines, 23, "26 input - 3 survivors = 23 collapsed");
        assert_eq!(stats.cluster_count, 3);
        assert_eq!(stats.max_cluster_size, 9);
        assert_eq!(out.len(), 3);
    }
}
