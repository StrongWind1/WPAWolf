//! Phase 4 -- Emit: N#E# combo generator (six combos: N1E2, N1E4, N3E2, N2E3, N4E3, N3E4). See ARCHITECTURE.md §5.
//!
//! For each (AP, STA) group produces all valid `(combo_type, nonce_message, eapol_message)`
//! triples from the six hashcat-recognised combinations: N1E2, N3E2, N2E3, N1E4, N4E3,
//! N3E4 -- where `N#` is the message supplying the nonce and `E#` the message supplying the
//! EAPOL frame. Pre-filters messages by type to achieve O(nxm) complexity rather than O(n^2).
//! Applies time-gap and replay-counter constraints from `constraints`. Tracks the best pair
//! per combo type (smallest time delta, then smallest RC delta). See `ARCHITECTURE.md §8`
//! FR-PAIR-2 and `ARCHITECTURE.md §5`.

use std::sync::Arc;

use crate::store::messages::EapolMessage;
use crate::types::{MacAddr, MsgType};

use super::constraints::{RcRelation, expected_rc_delta, within_rc_for_combo, within_time};
use super::nc_dedup::{Endianness, cluster_indices, pick_safe_survivor, tail_u32};
use super::{ComboType, FLAG_APLESS, FLAG_BE, FLAG_LE, FLAG_NC, PairedHash};

// --- PairConfig ---

/// Parameters controlling the pairing engine.
///
/// Holds tunable knobs exposed on the CLI (`--eapoltimeout`, `--rc-drift`,
/// `--dedup-hash-combos`). Keeping them in a single struct simplifies passing
/// through `generate` and `try_pair` without a long argument list.
#[derive(Debug, Clone, Copy)]
pub struct PairConfig {
    /// Maximum time gap between paired messages in microseconds.
    /// Only used when `time_check_enabled` is true. Default: `600_000_000` (10 minutes).
    pub eapol_timeout_us: u64,
    /// Accepted RC drift magnitude (`|actual_delta - expected_delta|`) for RC-drift filtering.
    /// Only used when `rc_drift_enabled` is true. Default: 8.
    pub rc_drift_tolerance: u8,
    /// If true, emit all 6 combos; if false, deduplicate equivalent combos first.
    pub all_combos: bool,
    /// Whether to apply the time-gap constraint. Default: false (unfiltered -- no time check).
    pub time_check_enabled: bool,
    /// Whether to apply the replay-counter (RC drift) constraint. Default: false (unfiltered).
    pub rc_drift_enabled: bool,
    /// Whether to run the post-collapse NC-dedup pass.
    ///
    /// When `true`, pairs sharing `(ap, sta, eapol_frame, mic, combo_type)` and whose
    /// trailing nonce bytes fit within `nc_tolerance` are collapsed to a single
    /// survivor with `FLAG_NC` set, so hashcat's `--nonce-error-corrections` (default
    /// 8) recovers the remaining variants at MIC-verify time. Default: `false`.
    pub nc_dedup_enabled: bool,
    /// Maximum span (`max - min`) on the trailing nonce bytes within which two pairs
    /// are treated as the same logical nonce by NC-dedup. Default: 8, matching
    /// hashcat's `NONCE_ERROR_CORRECTIONS=8` so the symmetric `survivor +/- 4`
    /// iteration on the cracker side covers the full cluster span when the survivor
    /// sits at the sorted-median index.
    pub nc_tolerance: u8,
    /// Opt-in per-(AP,STA)-per-type pairing cap (`--max-eapol-per-type`). When
    /// `> 0`, pairing iterates at most this many messages of each type
    /// (M1/M2/M3/M4) per group, bounding each N#E# combo to `cap^2` pairs. The
    /// store still holds every message (`FR-MSG-1`); this only limits pairing
    /// fan-out so a pathological rotating-ANonce group can't generate
    /// `O(M1*M2)` billions of near-duplicate lines. `0` = unlimited (the default
    /// WIDE behaviour, never miss).
    pub max_eapol_per_type: usize,
    /// Opt-in collapse of hash lines that differ only in the `message_pair` byte
    /// (`--collapse-message-pair`). The byte is hashcat metadata (combo type + NC/LE/BE
    /// flags), not crackable content. When `true`, it is excluded from the dedup
    /// fingerprint, so content-identical combos (e.g. `N1E2` and `N3E2` of a clean handshake
    /// where M1 and M3 carry the same `ANonce`) collapse to one line. Default: `false`
    /// (every combo emitted, `message_pair` is part of the dedup identity).
    pub collapse_message_pair: bool,
    /// Opt-in smart instance-attribution pairing (`--smart`). When `true`, the
    /// selector attributes each MIC to its handshake instance by joint
    /// replay-counter linkage and prunes only the provably-uncrackable
    /// cross-product cells, keeping every crackable line (never-miss). `false`
    /// (the default) emits the full WIDE cross-product. See
    /// `docs/smart-pairing-design.md`.
    pub smart: bool,
}

impl Default for PairConfig {
    /// Returns the default unfiltered pairing config.
    ///
    /// Unfiltered: no time check, no RC constraint, no NC-dedup, all 6 combos emitted.
    /// Invalid nonce/MIC values are always rejected at parse time (not controlled here).
    fn default() -> Self {
        Self {
            eapol_timeout_us: 600_000_000, // 10 minutes -- used only when time_check_enabled=true
            rc_drift_tolerance: 8,
            all_combos: true,             // unfiltered: all 6 combos emitted
            time_check_enabled: false,    // unfiltered: no time filter
            rc_drift_enabled: false,      // unfiltered: no RC drift filter
            nc_dedup_enabled: false,      // unfiltered: NC clustering off
            nc_tolerance: 8,              // matches hashcat NONCE_ERROR_CORRECTIONS default
            max_eapol_per_type: 0,        // unlimited: no pairing cap (never miss)
            collapse_message_pair: false, // unfiltered: message_pair is part of the dedup identity
            smart: false,                 // unfiltered: WIDE cross-product, no instance attribution
        }
    }
}

/// Truncates a per-type message list to at most `cap` entries (no-op when
/// `cap == 0`) and returns the number of messages dropped. Used by the opt-in
/// `--max-eapol-per-type` cap to bound pairing fan-out without evicting anything
/// from the store. See [`PairConfig::max_eapol_per_type`].
fn cap_list(list: &mut Vec<&EapolMessage>, cap: usize) -> u64 {
    if cap == 0 || list.len() <= cap {
        return 0;
    }
    let dropped = list.len() - cap;
    list.truncate(cap);
    u64::try_from(dropped).unwrap_or(u64::MAX)
}

// --- generate ---

/// Generates all valid N#E# paired hashes for a single (AP, STA) message group.
///
/// `messages` must already be sorted by timestamp (ascending). Returns one
/// `PairedHash` per surviving `(combo_type, nonce_msg, eapol_msg)` triple plus
/// the per-group `PairFilterStats`.
///
/// Thin materializing wrapper over [`generate_streaming`]: it buffers every
/// per-frame chunk into a single `Vec`. The two share the frame-major inner
/// (`build_frame_pairs` / `finalize_and_dedup`), so the materialized and
/// streaming paths are set-identical by construction -- pinned by
/// `streamed_matches_materialized` -- and a future `--smart` selector added to
/// the shared inner is inherited by both. The per-type cap, per-group
/// fingerprint dedup, endianness overlay, and the M3-anchored `FLAG_NC` rule all
/// live in the shared inner. See `ARCHITECTURE.md §5`.
#[must_use]
pub fn generate(
    ap: MacAddr,
    sta: MacAddr,
    messages: &[EapolMessage],
    config: &PairConfig,
) -> (Vec<PairedHash>, PairFilterStats) {
    let mut pairs: Vec<PairedHash> = Vec::new();
    let filter_stats = generate_streaming(ap, sta, messages, config, |chunk| pairs.extend(chunk));
    (pairs, filter_stats)
}

// --- generate_streaming (per-eapol-frame) ---

/// Session-level pairing context, computed once per group and reused for every
/// EAPOL frame in the streaming path.
struct GenCtx<'a> {
    ap: MacAddr,
    sta: MacAddr,
    config: &'a PairConfig,
    /// `true` when any M1 was seen or nonce-counter drift was detected -- drives
    /// the M3-anchored `FLAG_NC` rule. See `generate`.
    session_carries_nc: bool,
    /// `(le, be)` router-endianness flags from `detect_nonce_endianness`.
    router_endian: (bool, bool),
    ap_bytes: [u8; 6],
    sta_bytes: [u8; 6],
    /// Smart-mode (`--smart`) handshake-instance table for this group. Empty in
    /// WIDE mode; built once per group by `build_instance_table` and read by
    /// `select_smart`. Owned (no borrows) so `GenCtx` stays free of a second
    /// lifetime across the streaming `FnMut` boundary.
    instance_table: InstanceTable,
}

/// Applies the M3-anchored `FLAG_NC` rule, the LE/BE endianness overlay, and the
/// per-frame fingerprint dedup to a freshly built pair.
///
/// Returns `Some(pair)` if its fingerprint is new (push it), `None` if a
/// fingerprint-identical pair was already seen in this frame. Mirrors the
/// `dedup_push!` macro plus the N3E2/N3E4 `FLAG_NC` rule in `generate`; the
/// `streamed_matches_materialized` parity test pins the two against drift.
fn finalize_and_dedup(
    mut pair: PairedHash,
    ctx: &GenCtx<'_>,
    seen: &mut std::collections::HashSet<u64>,
) -> Option<PairedHash> {
    // M3-anchored pairs (N3E2 / N3E4) gain FLAG_NC from session state (M1
    // presence / endianness drift) or a per-pair RC deviation -- the same
    // three-source rule as `generate`. M1-anchored pairs already carry FLAG_NC
    // from `try_pair`.
    if matches!(pair.combo_type, ComboType::N3E2 | ComboType::N3E4)
        && (ctx.session_carries_nc || pair.rc_gap_magnitude > 0)
    {
        pair.message_pair |= FLAG_NC;
    }
    if pair.message_pair & FLAG_NC != 0 {
        if ctx.router_endian.0 {
            pair.message_pair |= FLAG_LE;
        }
        if ctx.router_endian.1 {
            pair.message_pair |= FLAG_BE;
        }
    }
    let kind: u8 = if pair.akm.is_ft() { 0x04 } else { 0x02 };
    // message_pair gated by --collapse-message-pair (metadata, not identity) -- kept
    // byte-identical to the materialized `dedup_push!` and to
    // output::dedup::eapol_fingerprint so the streaming and materialized paths agree.
    let fp = if ctx.config.collapse_message_pair {
        crate::types::hash_slices(
            kind,
            &[pair.mic.as_slice(), &ctx.ap_bytes, &ctx.sta_bytes, &pair.nonce, &pair.eapol_frame, &[]],
        )
    } else {
        crate::types::hash_slices(
            kind,
            &[
                pair.mic.as_slice(),
                &ctx.ap_bytes,
                &ctx.sta_bytes,
                &pair.nonce,
                &pair.eapol_frame,
                &[],
                &[pair.message_pair],
            ],
        )
    };
    if seen.insert(fp) { Some(pair) } else { None }
}

/// Builds every pair whose EAPOL frame is `eapol_msg`.
///
/// Covers the two combos that use it (`combo_a` over `nonce_a`, `combo_b` over
/// `nonce_b`) with a frame-local dedup set; returns that one frame's pairs and
/// tallies any filter rejections.
fn build_frame_pairs(
    ctx: &GenCtx<'_>,
    eapol_msg: &EapolMessage,
    nonce_a: &[&EapolMessage],
    combo_a: ComboType,
    nonce_b: &[&EapolMessage],
    combo_b: ComboType,
    filter_stats: &mut PairFilterStats,
) -> Vec<PairedHash> {
    let mut frame_pairs: Vec<PairedHash> = Vec::new();
    let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
    for (nonce_msgs, combo) in [(nonce_a, combo_a), (nonce_b, combo_b)] {
        for &nonce_msg in nonce_msgs {
            match try_pair(ctx.ap, ctx.sta, nonce_msg, eapol_msg, combo, ctx.config) {
                Ok(pair) => {
                    if let Some(p) = finalize_and_dedup(pair, ctx, &mut seen) {
                        frame_pairs.push(p);
                    }
                },
                Err(FilterReason::Time) => filter_stats.time_filtered += 1,
                Err(FilterReason::Rc) => filter_stats.rc_filtered += 1,
            }
        }
    }
    // Smart-mode Phase C: prune provably-uncrackable cross-instance candidates for
    // this frame's MIC (pass-through in WIDE mode). See `select_smart`.
    if ctx.config.smart {
        return select_smart(frame_pairs, eapol_msg, &ctx.instance_table, ctx.config, filter_stats);
    }
    frame_pairs
}

/// Streaming variant of [`generate`] for groups too large to materialize.
///
/// Emits pairs one EAPOL frame at a time via `on_chunk`, bounding peak memory to
/// a single frame's pairs (at most the group's nonce-message count) instead of
/// the `O(n*m)` product.
///
/// Set-identical to `generate` + the caller's `collapse`/`nc_dedup`: all three
/// reductions (`generate`'s `seen`, `collapse`'s `(nonce, eapol_frame)` key,
/// `nc_dedup`'s `(eapol_frame, mic, combo, nonce[..28])` bucket) partition by
/// `eapol_frame`, so two pairs with different EAPOL frames never interact. The
/// caller runs `collapse`/`nc_dedup` on each frame chunk before output. Frame
/// emission order differs from `generate` (frame-major, not combo-major), which
/// only affects mega-groups that already run in disk mode (set-, not
/// order-equivalent). `on_chunk` may be called with an empty `Vec`.
pub fn generate_streaming(
    ap: MacAddr,
    sta: MacAddr,
    messages: &[EapolMessage],
    config: &PairConfig,
    mut on_chunk: impl FnMut(Vec<PairedHash>),
) -> PairFilterStats {
    let mut m1s: Vec<&EapolMessage> = messages.iter().filter(|m| m.msg_type == MsgType::M1).collect();
    let mut m2s: Vec<&EapolMessage> = messages.iter().filter(|m| m.msg_type == MsgType::M2).collect();
    let mut m3s: Vec<&EapolMessage> = messages.iter().filter(|m| m.msg_type == MsgType::M3).collect();
    let mut m4s: Vec<&EapolMessage> = messages.iter().filter(|m| m.msg_type == MsgType::M4).collect();

    // Opt-in per-type pairing cap -- mirrors `generate`. See `cap_list`.
    let cap = config.max_eapol_per_type;
    let messages_capped =
        cap_list(&mut m1s, cap) + cap_list(&mut m2s, cap) + cap_list(&mut m3s, cap) + cap_list(&mut m4s, cap);

    let router_endian = detect_nonce_endianness(&m1s, &m3s);
    let mut filter_stats = PairFilterStats { messages_capped, ..PairFilterStats::default() };
    // Smart-mode Phase A: partition this group's AP-frames into handshake
    // instances (empty in WIDE mode). Tally instances from multi-instance groups
    // -- the only ones where the selector can prune -- for the banner.
    let instance_table = build_instance_table(&m1s, &m3s, config);
    if instance_table.instances.len() > 1 {
        filter_stats.smart_instances_attributed += u64::try_from(instance_table.instances.len()).unwrap_or(u64::MAX);
    }
    let ctx = GenCtx {
        ap,
        sta,
        config,
        session_carries_nc: !m1s.is_empty() || router_endian.0 || router_endian.1,
        router_endian,
        ap_bytes: ap.0,
        sta_bytes: sta.0,
        instance_table,
    };

    // M2-frame chunks: N1E2 (nonce M1) + N3E2 (nonce M3).
    for &eapol_msg in &m2s {
        on_chunk(build_frame_pairs(&ctx, eapol_msg, &m1s, ComboType::N1E2, &m3s, ComboType::N3E2, &mut filter_stats));
    }
    // M3-frame chunks: N2E3 (nonce M2) + N4E3 (nonce M4).
    for &eapol_msg in &m3s {
        on_chunk(build_frame_pairs(&ctx, eapol_msg, &m2s, ComboType::N2E3, &m4s, ComboType::N4E3, &mut filter_stats));
    }
    // M4-frame chunks: N1E4 (nonce M1) + N3E4 (nonce M3).
    for &eapol_msg in &m4s {
        on_chunk(build_frame_pairs(&ctx, eapol_msg, &m1s, ComboType::N1E4, &m3s, ComboType::N3E4, &mut filter_stats));
    }
    filter_stats
}

// --- Smart instance attribution (--smart) ---
//
// See `docs/smart-pairing-design.md`. The selector NEVER drops a crackable line:
// it prunes a candidate only when (1) the MIC RC-links to exactly one handshake
// instance and (2) the candidate's ANonce is unreachable from that instance's
// median even under hashcat's `+/- N/2` sweep -- i.e. provably not the live
// ANonce. Same-instance siblings are KEPT; the post-pass `nc_dedup` (which
// `--smart` implies) folds them to one `FLAG_NC` survivor. M3-EAPOL (APLESS)
// frames are kept whole (exempt). The line fold and the instance fold share one
// `+/- N/2` bound via the reused `nc_dedup` primitives.

/// One handshake instance: a maximal set of AP-frames (M1/M3) whose `ANonces` fold
/// to a single NC-safe median survivor (within hashcat's `+/- N/2` reach), plus
/// the replay counters those frames carried. Owned data -- no borrows of the
/// group's `messages` -- so it can live on `GenCtx` across the streaming closure.
#[derive(Clone, Debug, Default)]
struct Instance {
    /// Canonical `ANonce` = the `pick_safe_survivor` median, chosen so its
    /// `+/- N/2` window provably covers every AP-frame in the instance.
    canonical_nonce: [u8; 32],
    /// Replay counters of this instance's M1 frames.
    m1_rcs: Vec<u64>,
    /// Replay counters of this instance's M3 frames.
    m3_rcs: Vec<u64>,
    /// Per-instance endianness pin derived from this instance's own counter
    /// drift; `(false, false)` = unpinned (reachability must hold under BOTH
    /// interpretations before a drop is allowed -- design §2.3 rule 1).
    endian: (bool, bool),
}

/// Per-(AP, STA)-group table of handshake instances (Phase A output). Empty in
/// WIDE mode.
#[derive(Clone, Debug, Default)]
struct InstanceTable {
    instances: Vec<Instance>,
}

/// FT instance-identity key: two FT AP-frames that share an `ANonce` but differ in
/// their FT context (`mdid` / `r0khid` / `r1khid`, i.e. a different PMK-R1 key
/// hierarchy) are DIFFERENT cryptographic sessions and must seed separate
/// instances (design §3.2). Empty for non-FT frames.
fn ft_key_of(m: &EapolMessage) -> Vec<u8> {
    m.ft.as_ref().map_or_else(Vec::new, |ft| {
        let len = usize::from(ft.r0khid_len).min(ft.r0khid.len());
        let mut k = Vec::with_capacity(2 + len + 6);
        k.extend_from_slice(&ft.mdid);
        k.extend_from_slice(ft.r0khid.get(..len).unwrap_or(&[]));
        k.extend_from_slice(&ft.r1khid);
        k
    })
}

/// Builds one [`Instance`] from a set of frame indices: its canonical (median)
/// `ANonce`, endianness pin, and the M1/M3 replay counters of its members.
fn instance_from_members(
    frames: &[&EapolMessage],
    is_m3: &[bool],
    members: &[usize],
    canonical_nonce: [u8; 32],
    endian: (bool, bool),
) -> Instance {
    let mut inst = Instance { canonical_nonce, endian, ..Instance::default() };
    for &i in members {
        let Some(m) = frames.get(i) else { continue };
        if is_m3.get(i).copied().unwrap_or(false) {
            inst.m3_rcs.push(m.replay_counter);
        } else {
            inst.m1_rcs.push(m.replay_counter);
        }
    }
    inst
}

/// Phase A: partition the group's AP-frames (`m1s ++ m3s`) into handshake
/// instances. Groups by `(ANonce[0..28] prefix, FtFields)`, then within each
/// group splits the trailing dword into `+/- N/2`-safe instances via the reused
/// `nc_dedup` clustering primitives (LE vs BE by tighter clustering). Returns an
/// empty table when `!config.smart` so WIDE pays nothing.
fn build_instance_table(m1s: &[&EapolMessage], m3s: &[&EapolMessage], config: &PairConfig) -> InstanceTable {
    if !config.smart {
        return InstanceTable::default();
    }
    // Flatten AP-frames (owned references), tagged M1 (index < m1s.len()) vs M3.
    let frames: Vec<&EapolMessage> = m1s.iter().chain(m3s.iter()).copied().collect();
    let nonces: Vec<[u8; 32]> = frames.iter().map(|m| m.nonce).collect();
    let is_m3: Vec<bool> = (0..frames.len()).map(|i| i >= m1s.len()).collect();

    // Group frame indices by (28-byte ANonce prefix, FT key).
    let mut groups: std::collections::HashMap<([u8; 28], Vec<u8>), Vec<usize>> = std::collections::HashMap::new();
    for (i, m) in frames.iter().enumerate() {
        let mut prefix = [0u8; 28];
        prefix.copy_from_slice(m.nonce.get(..28).unwrap_or(&[0u8; 28]));
        groups.entry((prefix, ft_key_of(m))).or_default().push(i);
    }

    let tolerance = u32::from(config.nc_tolerance);
    let half_tol = tolerance / 2;
    let mut instances: Vec<Instance> = Vec::new();

    for (_, idxs) in groups {
        // Cluster the prefix-group's trailing dwords under both endiannesses; pick
        // the one that collapses more (mirrors nc_dedup; LE wins ties).
        let (le_clusters, le_c) = cluster_indices(&idxs, &nonces, tolerance, Endianness::Le);
        let (be_clusters, be_c) = cluster_indices(&idxs, &nonces, tolerance, Endianness::Be);
        let (clusters, endian, pin) = if le_c >= be_c {
            (le_clusters, Endianness::Le, (true, false))
        } else {
            (be_clusters, Endianness::Be, (false, true))
        };

        for cluster in clusters {
            let single = cluster.len() == 1;
            let endian_pin = if single { (false, false) } else { pin };
            let survivor =
                if single { cluster.first().copied() } else { pick_safe_survivor(&cluster, &nonces, endian, half_tol) };
            // Foldable cluster (incl. singleton): commit the median as canonical;
            // its `+/- N/2` window covers every member.
            if let Some(s) = survivor
                && let Some(&n) = nonces.get(s)
            {
                instances.push(instance_from_members(&frames, &is_m3, &cluster, n, endian_pin));
                continue;
            }
            // Sparse multi-member cluster (no NC-safe median): split into per-member
            // singletons -- never-miss-safe (keep more, never fold across a gap
            // hashcat's `+/- N/2` cannot bridge).
            for &m in &cluster {
                if let Some(&n) = nonces.get(m) {
                    instances.push(instance_from_members(&frames, &is_m3, &[m], n, (false, false)));
                }
            }
        }
    }

    InstanceTable { instances }
}

/// True if replay counters `a` and `b` are equal, tolerating a firmware
/// byte-swap on either side -- the swap-tolerant gap-0 RC link the attributor
/// uses directly (not behind `--rc-drift`). Byte-swapped RC firmware is rare
/// in practice but real; a swap that fails to link degrades to
/// keep-all (safe), never to mis-attribute.
const fn rc_link(a: u64, b: u64) -> bool {
    a == b || a.swap_bytes() == b || a == b.swap_bytes()
}

/// Phase B: the distinct instances the MIC of `eapol_msg` RC-links to with gap 0,
/// counted JOINTLY across both axes (design §3.3 Phase B / §4.4 cond 1):
/// for an M2, `{M1 at rc} U {M3 at rc+1}`; for an M4, `{M3 at rc} U {M1 at rc-1}`.
/// The joint count is what closes the cross-seed hole: an M2 that also links to a
/// distinct M3-seeded instance is NOT treated as unique. Only M2/M4 frames reach
/// here; M3-EAPOL frames are handled (kept whole) in `select_smart`.
fn attribute_mic(eapol_msg: &EapolMessage, table: &InstanceTable) -> Vec<usize> {
    let rc = eapol_msg.replay_counter;
    let mut hits: Vec<usize> = Vec::new();
    for (idx, inst) in table.instances.iter().enumerate() {
        let linked = match eapol_msg.msg_type {
            MsgType::M2 => {
                inst.m1_rcs.iter().any(|&r| rc_link(r, rc))
                    || rc.checked_add(1).is_some_and(|r1| inst.m3_rcs.iter().any(|&r| rc_link(r, r1)))
            },
            MsgType::M4 => {
                inst.m3_rcs.iter().any(|&r| rc_link(r, rc))
                    || rc.checked_sub(1).is_some_and(|r1| inst.m1_rcs.iter().any(|&r| rc_link(r, r1)))
            },
            MsgType::M1 | MsgType::M3 => false,
        };
        if linked {
            hits.push(idx);
        }
    }
    hits
}

/// True if `cand` `ANonce` is within hashcat's `+/- N/2` reach of `inst`'s
/// canonical median nonce: identical 28-byte prefix AND trailing dword within
/// `half_tol` in the instance's pinned endianness (or under EITHER endianness
/// when the instance is unpinned -- refuse-to-drop on ambiguity, design §4.4
/// cond 3). Used to decide KEEP (reachable, same instance -> `nc_dedup` folds it)
/// vs DROP (unreachable, cross-instance -> provably uncrackable).
fn nonce_reachable(cand: &[u8; 32], inst: &Instance, half_tol: u32) -> bool {
    if cand.get(..28) != inst.canonical_nonce.get(..28) {
        return false;
    }
    let within = |e: Endianness| tail_u32(cand, e).abs_diff(tail_u32(&inst.canonical_nonce, e)) <= half_tol;
    match inst.endian {
        (true, false) => within(Endianness::Le),
        (false, true) => within(Endianness::Be),
        // Unpinned (or impossibly both): reachable if EITHER direction reaches it.
        _ => within(Endianness::Le) || within(Endianness::Be),
    }
}

/// Phase C: prune provably-uncrackable cross-instance candidates for one EAPOL
/// frame's MIC. Pass-through when `!config.smart` or for M3-EAPOL (APLESS) frames
/// (exempt). For an M2/M4 frame uniquely RC-linked to one instance, KEEPS every
/// candidate whose `ANonce` is reachable from that instance's median (the post-pass
/// `nc_dedup` folds them) and DROPS the rest (cross-instance, unreachable even
/// under NC -- the only candidates this can lose for a MIC are ones the MIC's PTK
/// never signed). Never reduces a MIC below one line.
fn select_smart(
    candidates: Vec<PairedHash>,
    eapol_msg: &EapolMessage,
    table: &InstanceTable,
    config: &PairConfig,
    stats: &mut PairFilterStats,
) -> Vec<PairedHash> {
    if !config.smart {
        return candidates;
    }
    // M3-EAPOL frames carry only APLESS combos (N2E3 / N4E3); exempt -- they crack
    // in mode 22000 via lex-order and never under FT reasoning. Keep whole.
    if eapol_msg.msg_type == MsgType::M3 {
        return candidates;
    }

    // Joint RC attribution. Not exactly one instance -> keep all (§4.2).
    let hits = attribute_mic(eapol_msg, table);
    let &[inst_idx] = hits.as_slice() else {
        stats.smart_ambiguous_kept += 1;
        return candidates;
    };
    let Some(inst) = table.instances.get(inst_idx) else {
        return candidates;
    };
    let half_tol = u32::from(config.nc_tolerance) / 2;

    // Keep-at-least-one guard: if no candidate is reachable from the linked
    // instance (should not happen -- the instance's own ANonce is a candidate --
    // but never zero a MIC), degrade to keep-all.
    if !candidates.iter().any(|c| nonce_reachable(&c.nonce, inst, half_tol)) {
        stats.smart_ambiguous_kept += 1;
        return candidates;
    }

    let mut kept: Vec<PairedHash> = Vec::with_capacity(candidates.len());
    let mut dropped: u64 = 0;
    for cand in candidates {
        if nonce_reachable(&cand.nonce, inst, half_tol) {
            kept.push(cand);
        } else {
            dropped += 1;
        }
    }
    stats.smart_uncrackable_dropped += dropped;
    // M2/M4 survivors are non-APLESS (N1E2 / N3E2 / N1E4 / N3E4), so an FT session
    // with any M2/M4 MIC retains a 37100-crackable survivor -- clause F holds by
    // construction.
    if eapol_msg.akm.is_ft() {
        stats.smart_ft_nonapless_kept += 1;
    }
    kept
}

// --- try_pair ---

/// Attempts to build a `PairedHash` from a (`nonce_msg`, `eapol_msg`) candidate.
///
/// Returns `None` when either the time-gap or the RC constraint rejects the pair.
/// On success, encodes the `message_pair` byte: bits 0-2 hold the `ComboType` discriminant,
/// bits 4-7 carry the flags (`FLAG_APLESS`, `FLAG_LE`, `FLAG_BE`, `FLAG_NC`).
/// [hcxtools convention -- `message_pair` encoding]
fn try_pair(
    ap: MacAddr,
    sta: MacAddr,
    nonce_msg: &EapolMessage,
    eapol_msg: &EapolMessage,
    combo: ComboType,
    config: &PairConfig,
) -> Result<PairedHash, FilterReason> {
    // Time constraint: both messages must fall within the configured EAPOL session window.
    // [ARCHITECTURE.md §8 FR-PAIR-3]
    if config.time_check_enabled && !within_time(nonce_msg.timestamp, eapol_msg.timestamp, config.eapol_timeout_us) {
        return Err(FilterReason::Time);
    }

    // RC constraint (opt-in via --rc-drift): replay counters must be consistent with the
    // expected relationship for this combo type. Uses combo-aware offset so that N3E2/N2E3/N1E4
    // pairs with the standard M3.rc = M2.rc + 1 delta are not spuriously rejected.
    // Unfiltered (rc_drift_enabled=false): all pairs treated as RC-exact. [ARCHITECTURE.md §8 FR-PAIR-4]
    let rc_rel = if config.rc_drift_enabled {
        match within_rc_for_combo(nonce_msg, eapol_msg, combo, config.rc_drift_tolerance) {
            Some(rel) => rel,
            None => return Err(FilterReason::Rc),
        }
    } else {
        RcRelation::Exact // unfiltered: no RC constraint, treat all pairs as exact
    };

    // AP-less combos (N2E3, N4E3) always carry the APLESS flag (`0x10`).
    // [hcxtools legacy alias `ST_APLESS`]
    let apless = matches!(combo, ComboType::N2E3 | ComboType::N4E3);

    // Encode message_pair byte: combo type in bits 0-2, flags in bits 4-7.
    // [hcxtools convention -- message_pair field in WPA*02* hash lines]
    let mut message_pair = combo as u8;
    if apless {
        message_pair |= FLAG_APLESS; // APLESS set for N2E3 and N4E3 combos.
    }
    match rc_rel {
        RcRelation::Exact | RcRelation::WithinTolerance => {
            // NC flag (bit 7) for M1-anchored pairs (N1E2, N1E4): hcxpcapngtool
            // initialises every M1 with status = ST_NC (0x80) at
            // [hcxpcapngtool.c:4190] and addhandshake() propagates that status
            // onto the mpfield, so N1E2 / N1E4 always inherit NC from the M1
            // they originate from. M3-anchored pairs (N3E2 / N3E4) get
            // FLAG_NC applied in `generate` using the three-source rule
            // described above the partition block.
            let nonce_from_m1 = matches!(nonce_msg.msg_type, MsgType::M1);
            if !apless && nonce_from_m1 {
                message_pair |= FLAG_NC;
            }
        },
        RcRelation::ByteSwapped => {
            // Endianness correction sets LE+BE and NC. [hcxpcapngtool.c:2302-2305]
            message_pair |= FLAG_LE | FLAG_BE | FLAG_NC;
        },
    }

    // Compute actual RC gap magnitude regardless of whether the rc_drift filter is enabled.
    // Used by the collapse step to prefer the pair closest to the expected RC delta.
    // expected_rc_delta gives the canonical nonce_msg.rc - eapol_msg.rc for this combo.
    let expected_delta = i128::from(expected_rc_delta(combo));
    let nonce_rc = i128::from(nonce_msg.replay_counter);
    let eapol_rc = i128::from(eapol_msg.replay_counter);
    // RC values are u64 and delta is at most +/-1, so the absolute gap always fits in u64.
    // Saturate on the impossible overflow to keep clippy happy.
    let rc_gap_magnitude = u64::try_from((nonce_rc - eapol_rc - expected_delta).unsigned_abs()).unwrap_or(u64::MAX);

    Ok(PairedHash {
        ap,
        sta,
        combo_type: combo,
        nonce: nonce_msg.nonce,
        eapol_frame: Arc::clone(&eapol_msg.eapol_frame),
        mic: eapol_msg.mic,
        message_pair,
        akm: eapol_msg.akm,
        ft: eapol_msg.ft.clone(),
        rc_gap_magnitude,
    })
}

/// Why a candidate (nonce, EAPOL) pair was rejected by an opt-in output filter.
///
/// Both variants only ever occur when the corresponding filter flag is set
/// (`--eapoltimeout` / `--rc-drift`); in WIDE mode `try_pair` never returns `Err`.
/// `generate` tallies these so the banner can show how many pairs a filter removed
/// rather than letting them vanish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterReason {
    /// Dropped by the `--eapoltimeout` session-window constraint (FR-PAIR-3).
    Time,
    /// Dropped by the `--rc-drift` replay-counter constraint (FR-PAIR-4).
    Rc,
}

/// Per-group tally of pairs removed by the opt-in output filters. Zero in WIDE mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PairFilterStats {
    /// Candidate pairs dropped by the `--eapoltimeout` filter.
    pub time_filtered: u64,
    /// Candidate pairs dropped by the `--rc-drift` filter.
    pub rc_filtered: u64,
    /// Messages excluded from pairing by the `--max-eapol-per-type` cap, summed
    /// over the four types (`count - min(count, cap)` per type). Zero when off.
    pub messages_capped: u64,
    /// `--smart`: distinct handshake instances partitioned across multi-instance
    /// groups (informational). Zero in WIDE mode.
    pub smart_instances_attributed: u64,
    /// `--smart`: candidate pairs pruned as provably uncrackable -- cross-instance
    /// `ANonces` unreachable (by NC) from a uniquely-RC-linked MIC's instance.
    /// Standalone Phase-4 drop, outside Reconciliation Identity 3.
    pub smart_uncrackable_dropped: u64,
    /// `--smart`: MIC-frames kept against all candidates because the MIC did not
    /// uniquely RC-link to one instance (rc=1-pinned / cross-seed). Informational.
    pub smart_ambiguous_kept: u64,
    /// `--smart`: FT (mode 37100) MIC-frames where a non-APLESS survivor was
    /// retained after pruning, satisfying clause F. Informational.
    pub smart_ft_nonapless_kept: u64,
}

// --- Nonce endianness detection ---

/// Inspects M1 and M3 `ANonce` bytes to decide whether the AP is storing the nonce's
/// low-order counter bytes little-endian or big-endian.
///
/// hcxpcapngtool does this by pairwise-comparing any two M1 OR M3 nonces from the
/// same (AP, STA) session [hcxpcapngtool.c:3807-3829, 4235-4256] -- the loop guards
/// both branches with `((zeiger->message & HS_M1) == HS_M1) || ((zeiger->message
/// & HS_M3) == HS_M3)`, so cross-group comparisons (M1 vs M3) also trigger
/// detection on AP-driven nonce-counter increments observed between an early M1
/// and a later M3 retransmission. When the first 28 bytes match but the last 4
/// differ, the differences reveal where the low-order bytes live:
///
/// - bytes 30-31 differ  -> LE router (counter incremented at the tail, little-end)
/// - bytes 28-29 differ but 30-31 match -> BE router (counter deeper in, big-end)
///
/// \[`hcxpcapngtool.c`:3810-3822\]: `ST_LE = 0x20`, `ST_BE = 0x40`.
///
/// Returns `(le, be)` where each bool is set on the first positive pairwise match.
/// Both remain `false` for sessions with fewer than two M1/M3 messages combined
/// (most short captures). Used by `generate()` and `generate_streaming()` to propagate
/// the flag onto every paired hash with `FLAG_NC`, matching hcxpcapngtool's
/// `status = ST_LE + ST_NC` / `ST_BE + ST_NC` encoding.
fn detect_nonce_endianness(m1s: &[&EapolMessage], m3s: &[&EapolMessage]) -> (bool, bool) {
    let mut le = false;
    let mut be = false;
    // Combine M1s and M3s into a single anchor list so cross-group pairwise
    // comparisons (M1 vs M3) fire too -- matching hcxpcapngtool's HS_M1 || HS_M3
    // guard in both endianness-detection loops.
    let anchors: Vec<&&EapolMessage> = m1s.iter().chain(m3s.iter()).collect();
    for (i, a) in anchors.iter().enumerate() {
        for b in anchors.iter().skip(i + 1) {
            // First 28 bytes must match (the static portion of the AP's RNG seed),
            // last 4 bytes must differ (the counter portion). [hcxpcapngtool.c:3814]
            if a.nonce[..28] == b.nonce[..28] && a.nonce[28..32] != b.nonce[28..32] {
                if a.nonce[30..32] != b.nonce[30..32] {
                    le = true;
                } else if a.nonce[28..30] != b.nonce[28..30] {
                    be = true;
                }
            }
            if le && be {
                return (le, be);
            }
        }
    }
    (le, be)
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
    use crate::types::{AkmType, MacAddr, MicBytes, MsgType};

    // Builds a minimal EapolMessage for testing without needing a real parsed frame.
    // Each message gets a distinct eapol_frame (keyed by nonce_byte) so that the
    // per-group fingerprint dedup in generate() treats them as genuinely different
    // EAPOL messages, matching real-world behaviour where each M2/M3/M4 has a
    // unique frame body.
    fn make_msg(msg_type: MsgType, rc: u64, ts: u64, nonce_byte: u8) -> EapolMessage {
        let mut frame = vec![0u8; 99];
        frame[0] = nonce_byte; // distinguish different EAPOL messages
        EapolMessage {
            timestamp: ts,
            msg_type,
            key_version: 2,
            replay_counter: rc,
            nonce: [nonce_byte; 32],
            mic: MicBytes::from_16([0xAB; 16]),
            pmkid: None,
            eapol_frame: Arc::from(frame),
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

    /// Builds an M1 with a specific nonce pattern (for endianness-detection tests).
    fn make_m1_nonce(nonce: [u8; 32]) -> EapolMessage {
        EapolMessage {
            timestamp: 0,
            msg_type: MsgType::M1,
            key_version: 2,
            replay_counter: 0,
            nonce,
            mic: MicBytes::ZERO_16,
            pmkid: None,
            eapol_frame: Arc::from(vec![0u8; 99]),
            ft: None,
            akm: AkmType::Wpa2Psk,
            is_rsn: true,
        }
    }

    #[test]
    fn endianness_detect_none_with_single_m1() {
        // Single M1 -> no pairwise comparison possible -> both false.
        let a = make_m1_nonce([1u8; 32]);
        let (le, be) = detect_nonce_endianness(&[&a], &[]);
        assert!(!le && !be);
    }

    #[test]
    fn endianness_detect_le_on_trailing_byte_diff() {
        // First 28 bytes identical, bytes 30-31 differ -> LE.
        let mut n1 = [0u8; 32];
        let mut n2 = [0u8; 32];
        for (i, b) in n1.iter_mut().enumerate().take(28) {
            *b = u8::try_from(i).unwrap_or(0);
        }
        n2[..28].copy_from_slice(&n1[..28]);
        n2[30] = 0xAA; // bytes 30-31 differ
        n2[31] = 0xBB;
        let a = make_m1_nonce(n1);
        let b = make_m1_nonce(n2);
        let (le, be) = detect_nonce_endianness(&[&a, &b], &[]);
        assert!(le, "expected LE detection on trailing-byte difference");
        assert!(!be);
    }

    #[test]
    fn endianness_detect_be_on_mid_byte_diff() {
        // First 28 bytes identical, bytes 28-29 differ but 30-31 match -> BE.
        let mut n1 = [0u8; 32];
        let mut n2 = [0u8; 32];
        for (i, b) in n1.iter_mut().enumerate().take(28) {
            *b = u8::try_from(i).unwrap_or(0);
        }
        n2[..28].copy_from_slice(&n1[..28]);
        n2[28] = 0xAA;
        n2[29] = 0xBB;
        // bytes 30-31 stay zero on both -> equal
        let a = make_m1_nonce(n1);
        let b = make_m1_nonce(n2);
        let (le, be) = detect_nonce_endianness(&[&a, &b], &[]);
        assert!(be, "expected BE detection on mid-byte difference with matching tail");
        assert!(!le);
    }

    #[test]
    fn endianness_detect_neither_when_first_28_differ() {
        // First 28 bytes differ -> not the AP's nonce-RNG variation pattern -> neither.
        let mut n1 = [0u8; 32];
        let mut n2 = [0u8; 32];
        n1[0] = 0x11;
        n2[0] = 0x22;
        n2[30] = 0xAA; // would look LE if the 28-prefix matched
        let a = make_m1_nonce(n1);
        let b = make_m1_nonce(n2);
        let (le, be) = detect_nonce_endianness(&[&a, &b], &[]);
        assert!(!le && !be);
    }

    #[test]
    fn endianness_detect_from_m3_group() {
        // LE pattern must also be detected across M3 messages, not just M1s.
        let mut n1 = [0u8; 32];
        let mut n2 = [0u8; 32];
        for (i, b) in n1.iter_mut().enumerate().take(28) {
            *b = u8::try_from(i + 1).unwrap_or(0);
        }
        n2[..28].copy_from_slice(&n1[..28]);
        n2[30] = 0xCC;
        n2[31] = 0xDD;
        let a = EapolMessage { msg_type: MsgType::M3, ..make_m1_nonce(n1) };
        let b = EapolMessage { msg_type: MsgType::M3, ..make_m1_nonce(n2) };
        let (le, be) = detect_nonce_endianness(&[], &[&a, &b]);
        assert!(le && !be);
    }

    #[test]
    fn endianness_detect_across_m1_and_m3_groups() {
        // hcxpcapngtool's loop guard accepts HS_M1 || HS_M3, so an M1 and an M3
        // with matching 28-byte prefix and different trailing 4 bytes trigger
        // endianness detection too. wpawolf must mirror that or it silently
        // misses ST_LE+ST_NC inheritance on AP-counter-incrementing sessions.
        let mut n_m1 = [0u8; 32];
        let mut n_m3 = [0u8; 32];
        for (i, b) in n_m1.iter_mut().enumerate().take(28) {
            *b = u8::try_from(i + 1).unwrap_or(0);
        }
        n_m3[..28].copy_from_slice(&n_m1[..28]);
        n_m3[30] = 0x77;
        n_m3[31] = 0x88;
        let m1 = make_m1_nonce(n_m1);
        let m3 = EapolMessage { msg_type: MsgType::M3, ..make_m1_nonce(n_m3) };
        let (le, be) = detect_nonce_endianness(&[&m1], &[&m3]);
        assert!(le, "expected LE detection when M1 and M3 share prefix but differ in tail");
        assert!(!be);
    }

    fn default_config() -> PairConfig {
        PairConfig::default()
    }

    #[test]
    fn generate_n1e2_basic() {
        // M1 (RC=1, ts=0) paired with M2 (RC=1, ts=100) -> one N1E2 pair.
        let msgs = vec![make_msg(MsgType::M1, 1, 0, 0xAA), make_msg(MsgType::M2, 1, 100, 0xBB)];
        let (pairs, _) = generate(ap(), sta(), &msgs, &default_config());
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].combo_type, ComboType::N1E2);
    }

    #[test]
    fn max_eapol_per_type_off_emits_all_pairs() {
        // cap = 0 (default): every distinct M1 ANonce pairs with the M2.
        let mut msgs: Vec<EapolMessage> = (0..10u8).map(|i| make_msg(MsgType::M1, 1, u64::from(i), 0x10 + i)).collect();
        msgs.push(make_msg(MsgType::M2, 1, 1000, 0xBB));
        let (pairs, fs) = generate(ap(), sta(), &msgs, &default_config());
        assert_eq!(pairs.len(), 10, "all 10 M1xM2 N1E2 pairs emitted when the cap is off");
        assert_eq!(fs.messages_capped, 0);
    }

    #[test]
    fn max_eapol_per_type_caps_pairing() {
        // 10 M1s x 1 M2 with cap = 4: only the first 4 M1s pair -> 4 N1E2 pairs;
        // the other 6 M1s are excluded from pairing (the store still holds all).
        let mut msgs: Vec<EapolMessage> = (0..10u8).map(|i| make_msg(MsgType::M1, 1, u64::from(i), 0x10 + i)).collect();
        msgs.push(make_msg(MsgType::M2, 1, 1000, 0xBB));
        let config = PairConfig { max_eapol_per_type: 4, ..PairConfig::default() };
        let (pairs, fs) = generate(ap(), sta(), &msgs, &config);
        assert_eq!(pairs.len(), 4, "cap=4 bounds N1E2 to 4 pairs");
        assert_eq!(fs.messages_capped, 6, "6 of 10 M1s excluded from pairing");
    }

    #[test]
    fn max_eapol_per_type_caps_streaming_identically() {
        // The streaming path (used for mega-groups) must honour the same cap.
        let mut msgs: Vec<EapolMessage> = (0..10u8).map(|i| make_msg(MsgType::M1, 1, u64::from(i), 0x10 + i)).collect();
        msgs.push(make_msg(MsgType::M2, 1, 1000, 0xBB));
        let config = PairConfig { max_eapol_per_type: 4, ..PairConfig::default() };
        let mut streamed = 0usize;
        let fs = generate_streaming(ap(), sta(), &msgs, &config, |chunk| streamed += chunk.len());
        assert_eq!(streamed, 4, "streaming path honours cap=4");
        assert_eq!(fs.messages_capped, 6);
    }

    #[test]
    fn generate_no_pairs_timeout() {
        // M1 at ts=0, M2 at ts=6_000_000 (6 s) with a 5 s window -> no pairs.
        // Use a tight config with a 5_000_000 us timeout to exercise the time check.
        let config = PairConfig {
            eapol_timeout_us: 5_000_000,
            time_check_enabled: true,
            rc_drift_enabled: false,
            ..PairConfig::default()
        };
        let msgs = vec![make_msg(MsgType::M1, 1, 0, 0xAA), make_msg(MsgType::M2, 1, 6_000_000, 0xBB)];
        let (pairs, fs) = generate(ap(), sta(), &msgs, &config);
        assert!(pairs.is_empty());
        // The one N1E2 candidate was removed by the time filter and is counted,
        // not vanished. RC filter is off, so its tally stays zero.
        assert_eq!(fs.time_filtered, 1, "the time-filtered candidate must be tallied");
        assert_eq!(fs.rc_filtered, 0);
    }

    #[test]
    fn generate_no_pairs_rc_mismatch() {
        // M1 RC=1, M2 RC=100 -> delta=99 > tolerance=8 -> no pairs when rc_drift is on.
        let config = PairConfig { rc_drift_enabled: true, rc_drift_tolerance: 8, ..PairConfig::default() };
        let msgs = vec![make_msg(MsgType::M1, 1, 0, 0xAA), make_msg(MsgType::M2, 100, 100, 0xBB)];
        let (pairs, fs) = generate(ap(), sta(), &msgs, &config);
        assert!(pairs.is_empty());
        // The N1E2 candidate was removed by the RC filter and is counted.
        assert_eq!(fs.rc_filtered, 1, "the RC-filtered candidate must be tallied");
        assert_eq!(fs.time_filtered, 0);
    }

    #[test]
    fn generate_n3e2() {
        // M3 (RC=2, ts=200) paired with M2 (RC=2, ts=100) -> at least one N3E2 pair.
        // N2E3 also fires here (M2 as nonce, M3 as eapol, same RCs), so assert by filtering.
        let msgs = vec![make_msg(MsgType::M3, 2, 200, 0xAA), make_msg(MsgType::M2, 2, 100, 0xBB)];
        let (pairs, _) = generate(ap(), sta(), &msgs, &default_config());
        assert_eq!(pairs.iter().filter(|p| p.combo_type == ComboType::N3E2).count(), 1);
    }

    #[test]
    fn generate_n3e2_carries_flag_nc_when_m1_present() {
        // Standard handshake with M1 captured. M1 alone is enough to fire FLAG_NC
        // on the N3E2 anchor: in hcx every M1 is stored with `status = ST_NC`
        // [hcxpcapngtool.c:4190] and addhandshake's inheritance loop
        // [hcxpcapngtool.c:2758-2767] pulls that ST_NC into every subsequent
        // handshake for the same AP. Validated against hashcat module_22000.c
        // (lines 1302-1326): FLAG_NC=1 enables NC iteration (default 8); FLAG_NC=0
        // disables it. M1/M3 ANonce mismatch sessions are uncrackable without it.
        let msgs = vec![
            make_msg(MsgType::M1, 1, 0, 0xA1),
            make_msg(MsgType::M2, 1, 100, 0xB1),
            make_msg(MsgType::M3, 2, 200, 0xC1),
        ];
        let (pairs, _) = generate(ap(), sta(), &msgs, &default_config());
        let n3e2: Vec<&PairedHash> = pairs.iter().filter(|p| p.combo_type == ComboType::N3E2).collect();
        assert_eq!(n3e2.len(), 1, "expected one N3E2 pair");
        assert_ne!(
            n3e2[0].message_pair & FLAG_NC,
            0,
            "N3E2 must carry FLAG_NC when M1 is present (status inheritance from M1's ST_NC init)"
        );
    }

    #[test]
    fn generate_n3e2_carries_flag_nc_on_rc_deviation_without_m1() {
        // No M1 captured, and the actual M3/M2 RC delta deviates from the canonical
        // M3.rc = M2.rc + 1 (here both RCs are equal, so deviation = -1). hcx's
        // per-pair `rcgap > 0` rule [hcxpcapngtool.c:2787] fires, so FLAG_NC must
        // be set even without M1 inheritance. Mirrors the mid-capture-start case
        // where the AP retransmitted M3 against an earlier M2.
        let msgs = vec![make_msg(MsgType::M2, 1, 100, 0xB1), make_msg(MsgType::M3, 1, 200, 0xC1)];
        let (pairs, _) = generate(ap(), sta(), &msgs, &default_config());
        let n3e2: Vec<&PairedHash> = pairs.iter().filter(|p| p.combo_type == ComboType::N3E2).collect();
        assert_eq!(n3e2.len(), 1, "expected one N3E2 pair");
        assert_ne!(
            n3e2[0].message_pair & FLAG_NC,
            0,
            "N3E2 must carry FLAG_NC when RC deviates from expected handshake delta"
        );
    }

    #[test]
    fn generate_n3e2_no_flag_nc_on_standard_handshake_without_m1() {
        // Mid-capture session: only M2 (rc=1) and M3 (rc=2) captured, standard
        // RC deviation = 0, no M1, no endianness drift. hcx-default emits *02
        // (FLAG_NC=0) for these handshakes; wpawolf-WIDE must match to preserve
        // the line-by-line superset invariant against hcx-default. This test
        // pins the matching behaviour.
        let msgs = vec![make_msg(MsgType::M2, 1, 100, 0xB1), make_msg(MsgType::M3, 2, 200, 0xC1)];
        let (pairs, _) = generate(ap(), sta(), &msgs, &default_config());
        let n3e2: Vec<&PairedHash> = pairs.iter().filter(|p| p.combo_type == ComboType::N3E2).collect();
        assert_eq!(n3e2.len(), 1, "expected one N3E2 pair");
        assert_eq!(
            n3e2[0].message_pair & FLAG_NC,
            0,
            "N3E2 must NOT carry FLAG_NC for a standard mid-capture handshake (no M1, no endianness, deviation=0)"
        );
    }

    #[test]
    fn generate_n3e2_carries_flag_nc_on_endianness_without_m1() {
        // Two M3s sharing the first 28 nonce bytes but differing in the trailing
        // 4 -> wpawolf's endianness detector flags LE drift; hcx mirrors this at
        // [hcxpcapngtool.c:3814-3822] by setting `status = ST_LE + ST_NC` on the
        // M3 entries, then propagating ST_NC via addhandshake's inheritance loop.
        // Even without an M1 captured, the resulting N3E2 anchor must carry
        // FLAG_NC (and FLAG_LE on top via the dedup_push! overlay).
        let mut n_a = [0u8; 32];
        let mut n_b = [0u8; 32];
        for (i, b) in n_a.iter_mut().enumerate().take(28) {
            *b = u8::try_from(i + 1).unwrap_or(0);
        }
        n_b[..28].copy_from_slice(&n_a[..28]);
        n_b[30] = 0xCC;
        n_b[31] = 0xDD;
        let m3_a = EapolMessage { nonce: n_a, ..make_msg(MsgType::M3, 2, 200, 0xC1) };
        let m3_b = EapolMessage { nonce: n_b, ..make_msg(MsgType::M3, 2, 220, 0xC2) };
        let msgs = vec![make_msg(MsgType::M2, 1, 100, 0xB1), m3_a, m3_b];
        let (pairs, _) = generate(ap(), sta(), &msgs, &default_config());
        let n3e2: Vec<&PairedHash> = pairs.iter().filter(|p| p.combo_type == ComboType::N3E2).collect();
        assert!(!n3e2.is_empty(), "expected at least one N3E2 pair");
        for p in &n3e2 {
            assert_ne!(p.message_pair & FLAG_NC, 0, "endianness drift on M3 must set FLAG_NC on every N3E2 pair");
            assert_ne!(
                p.message_pair & FLAG_LE,
                0,
                "endianness drift on M3 must set FLAG_LE via the dedup_push! overlay"
            );
        }
    }

    #[test]
    fn generate_n2e3() {
        // M2 (RC=1, ts=100) paired with M3 (RC=2, ts=200) -> at least one N2E3 pair.
        // N3E2 also fires (M3 as nonce RC=2, M2 as eapol RC=1, delta=1 -> Exact), so filter.
        let msgs = vec![make_msg(MsgType::M2, 1, 100, 0xCC), make_msg(MsgType::M3, 2, 200, 0xDD)];
        let (pairs, _) = generate(ap(), sta(), &msgs, &default_config());
        assert_eq!(pairs.iter().filter(|p| p.combo_type == ComboType::N2E3).count(), 1);
    }

    #[test]
    fn generate_n1e4() {
        // M1 (RC=1, ts=0) paired with M4 (RC=2, ts=300) -> one N1E4 pair (RC diff=1 <= 8).
        // No other combos fire with only M1 and M4 in the list.
        let msgs = vec![make_msg(MsgType::M1, 1, 0, 0xAA), make_msg(MsgType::M4, 2, 300, 0xBB)];
        let (pairs, _) = generate(ap(), sta(), &msgs, &default_config());
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].combo_type, ComboType::N1E4);
    }

    #[test]
    fn generate_n4e3() {
        // M4 (RC=2, ts=300) paired with M3 (RC=2, ts=200) -> at least one N4E3 pair.
        // N3E4 also fires (same M3 as nonce, M4 as eapol, same RCs), so filter.
        let msgs = vec![make_msg(MsgType::M4, 2, 300, 0xAA), make_msg(MsgType::M3, 2, 200, 0xBB)];
        let (pairs, _) = generate(ap(), sta(), &msgs, &default_config());
        assert_eq!(pairs.iter().filter(|p| p.combo_type == ComboType::N4E3).count(), 1);
    }

    #[test]
    fn generate_n3e4() {
        // M3 (RC=2, ts=200) paired with M4 (RC=2, ts=300) -> at least one N3E4 pair.
        // N4E3 also fires (M4 as nonce, M3 as eapol, same RCs), so filter.
        let msgs = vec![make_msg(MsgType::M3, 2, 200, 0xAA), make_msg(MsgType::M4, 2, 300, 0xBB)];
        let (pairs, _) = generate(ap(), sta(), &msgs, &default_config());
        assert_eq!(pairs.iter().filter(|p| p.combo_type == ComboType::N3E4).count(), 1);
    }

    #[test]
    fn generate_multiple_m1m2() {
        // Two M1s and two M2s with the same RC -> 2x2 = 4 N1E2 pairs.
        let msgs = vec![
            make_msg(MsgType::M1, 1, 0, 0xA1),
            make_msg(MsgType::M1, 1, 10, 0xA2),
            make_msg(MsgType::M2, 1, 50, 0xB1),
            make_msg(MsgType::M2, 1, 60, 0xB2),
        ];
        let (pairs, _) = generate(ap(), sta(), &msgs, &default_config());
        // All four should be N1E2.
        assert_eq!(pairs.len(), 4);
        assert!(pairs.iter().all(|p| p.combo_type == ComboType::N1E2));
    }

    #[test]
    fn generate_empty_messages() {
        // Empty slice -> no pairs.
        let (pairs, _) = generate(ap(), sta(), &[], &default_config());
        assert!(pairs.is_empty());
    }

    #[test]
    fn generate_message_pair_flags_nc() {
        // RC diff = 4 (within tolerance=8) -> FLAG_NC must be set when rc_drift is active.
        let msgs = vec![
            make_msg(MsgType::M1, 1, 0, 0xAA),
            make_msg(MsgType::M2, 5, 100, 0xBB), // N1E2 expected delta=0; actual diff=4, within tolerance
        ];
        // Use a tight config with the rc_drift filter enabled so NC flag is applied.
        let tight = PairConfig {
            rc_drift_enabled: true,
            rc_drift_tolerance: 8,
            all_combos: true,
            time_check_enabled: true,
            eapol_timeout_us: 5_000_000,
            nc_dedup_enabled: false,
            nc_tolerance: 8,
            max_eapol_per_type: 0,
            collapse_message_pair: false,
            smart: false,
        };
        let (pairs, _) = generate(ap(), sta(), &msgs, &tight);
        // With rc_drift active and tolerance=8, the pair should be found with NC set.
        assert_eq!(pairs.len(), 1);
        assert_ne!(pairs[0].message_pair & FLAG_NC, 0, "FLAG_NC must be set for within-tolerance RC");
    }

    #[test]
    fn generate_combo_type_in_message_pair() {
        // N1E2 -> combo discriminant = 0, so message_pair & 0x07 == 0.
        let msgs = vec![make_msg(MsgType::M1, 1, 0, 0xAA), make_msg(MsgType::M2, 1, 100, 0xBB)];
        let (pairs, _) = generate(ap(), sta(), &msgs, &default_config());
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].message_pair & 0x07, ComboType::N1E2 as u8);
    }

    // --- Smart-mode (--smart) tests ---

    /// `--smart` config: instance attribution on, with its implied folds
    /// (`--dedup-hash-combos` + `--nc-dedup`) as `build_pair_config` sets them.
    fn smart_config() -> PairConfig {
        PairConfig { smart: true, nc_dedup_enabled: true, all_combos: false, ..PairConfig::default() }
    }

    #[test]
    fn smart_distinct_anonce_distinct_instance() {
        // Phase A: two distinct-prefix ANonces seed two instances.
        let m1a = make_msg(MsgType::M1, 5, 0, 0x10);
        let m1b = make_msg(MsgType::M1, 9, 1, 0x20);
        let m1s = vec![&m1a, &m1b];
        let m3s: Vec<&EapolMessage> = vec![];
        let table = build_instance_table(&m1s, &m3s, &smart_config());
        assert_eq!(table.instances.len(), 2, "distinct ANonces -> distinct instances");
    }

    #[test]
    fn smart_build_instance_table_empty_when_off() {
        let m1a = make_msg(MsgType::M1, 5, 0, 0x10);
        let m1s = vec![&m1a];
        let m3s: Vec<&EapolMessage> = vec![];
        assert!(build_instance_table(&m1s, &m3s, &PairConfig::default()).instances.is_empty());
    }

    #[test]
    fn smart_prunes_cross_instance_anonce() {
        // Two distinct ANonces at distinct RCs -> two instances. An M2 at rc=5
        // links only to instance A (M1 ANonce 0x10 @ rc=5); the wrong-instance
        // ANonce 0x20 paired with that M2 is provably uncrackable and pruned.
        let msgs = vec![
            make_msg(MsgType::M1, 5, 0, 0x10),
            make_msg(MsgType::M1, 9, 1, 0x20),
            make_msg(MsgType::M2, 5, 2, 0xAA),
        ];
        let (pairs, _) = generate(ap(), sta(), &msgs, &smart_config());
        let n1e2: Vec<_> = pairs.iter().filter(|p| p.combo_type == ComboType::N1E2).collect();
        assert_eq!(n1e2.len(), 1, "only the RC-linked instance's N1E2 survives");
        assert_eq!(n1e2[0].nonce, [0x10u8; 32], "kept ANonce is the RC-linked one");
    }

    #[test]
    fn smart_rc_ambiguous_keeps_all_anonces() {
        // Two distinct ANonces BOTH at rc=1 (rc=1-pinned). An M2 at rc=1 links to
        // BOTH instances -> not uniquely attributed -> keep all (never-miss).
        let msgs = vec![
            make_msg(MsgType::M1, 1, 0, 0x10),
            make_msg(MsgType::M1, 1, 1, 0x20),
            make_msg(MsgType::M2, 1, 2, 0xAA),
        ];
        let (pairs, _) = generate(ap(), sta(), &msgs, &smart_config());
        let n1e2 = pairs.iter().filter(|p| p.combo_type == ComboType::N1E2).count();
        assert_eq!(n1e2, 2, "rc-ambiguous -> both ANonces kept (the crackable one survives)");
    }

    #[test]
    fn smart_keeps_at_least_one_line_per_mic() {
        // Every distinct MIC-bearing M2 frame retains >=1 line under smart.
        let msgs = vec![
            make_msg(MsgType::M1, 5, 0, 0x10),
            make_msg(MsgType::M1, 9, 1, 0x20),
            make_msg(MsgType::M2, 5, 2, 0xAA),
            make_msg(MsgType::M2, 9, 3, 0xBB),
        ];
        let (pairs, _) = generate(ap(), sta(), &msgs, &smart_config());
        let frames: std::collections::HashSet<Vec<u8>> = pairs.iter().map(|p| p.eapol_frame.to_vec()).collect();
        assert!(frames.len() >= 2, "each M2 MIC frame keeps at least one line (never zero a MIC)");
    }

    #[test]
    fn smart_off_is_noop_vs_wide() {
        // smart=false must not change output: same survivor count as WIDE.
        let msgs = vec![
            make_msg(MsgType::M1, 5, 0, 0x10),
            make_msg(MsgType::M1, 9, 1, 0x20),
            make_msg(MsgType::M2, 5, 2, 0xAA),
        ];
        let (wide, _) = generate(ap(), sta(), &msgs, &default_config());
        let off = PairConfig { smart: false, ..PairConfig::default() };
        let (got, _) = generate(ap(), sta(), &msgs, &off);
        assert_eq!(wide.len(), got.len(), "smart=false leaves WIDE output unchanged");
    }

    #[test]
    fn smart_subset_of_wide() {
        // The never-miss machine check at unit scale: every smart-emitted pair is
        // also a WIDE-emitted pair (smart only ever drops, never invents lines).
        let msgs = vec![
            make_msg(MsgType::M1, 5, 0, 0x10),
            make_msg(MsgType::M1, 9, 1, 0x20),
            make_msg(MsgType::M1, 1, 2, 0x30),
            make_msg(MsgType::M2, 5, 3, 0xAA),
            make_msg(MsgType::M2, 9, 4, 0xBB),
            make_msg(MsgType::M3, 6, 5, 0x10),
        ];
        let (wide, _) = generate(ap(), sta(), &msgs, &default_config());
        let (smart, _) = generate(ap(), sta(), &msgs, &smart_config());
        let key = |p: &PairedHash| (p.combo_type as u8, p.nonce, p.eapol_frame.to_vec());
        let wide_set: std::collections::HashSet<_> = wide.iter().map(key).collect();
        for p in &smart {
            assert!(wide_set.contains(&key(p)), "every smart line must be a WIDE line (subset)");
        }
        assert!(smart.len() <= wide.len(), "smart never emits more than WIDE");
    }
}
