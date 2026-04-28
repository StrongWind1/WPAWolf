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
use super::{ComboType, FLAG_APLESS, FLAG_BE, FLAG_LE, FLAG_NC, PairedHash};

// --- PairConfig ---

/// Parameters controlling the pairing engine.
///
/// Holds tunable knobs exposed on the CLI (`--eapoltimeout`, `--rc-drift`,
/// `--dedup-hash-combos`). Keeping them in a single struct simplifies passing
/// through `generate` and `try_pair` without a long argument list.
#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools, reason = "these are independent CLI flags, not a state machine")]
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
}

impl Default for PairConfig {
    /// Returns the default unfiltered pairing config.
    ///
    /// Unfiltered: no time check, no RC constraint, all 6 combos emitted.
    /// Invalid nonce/MIC values are always rejected at parse time (not controlled here).
    fn default() -> Self {
        Self {
            eapol_timeout_us: 600_000_000, // 10 minutes -- used only when time_check_enabled=true
            rc_drift_tolerance: 8,
            all_combos: true,          // unfiltered: all 6 combos emitted
            time_check_enabled: false, // unfiltered: no time filter
            rc_drift_enabled: false,   // unfiltered: no RC drift filter
        }
    }
}

// --- generate ---

/// Generates all valid N#E# paired hashes for a single (AP, STA) message group.
///
/// `messages` must already be sorted by timestamp (ascending). Returns one `PairedHash`
/// per valid `(combo_type, nonce_msg, eapol_msg)` triple that passes both the time-gap
/// and RC constraints. When multiple pairs pass for the same combo type, all are returned
/// (the collapse step handles deduplication).
///
/// Pre-filters by message type for O(nxm) complexity per combo. See `ARCHITECTURE.md §5`.
///
/// Applies per-group dedup: after each pair passes constraint checks, its fingerprint
/// is checked against a local `HashSet`. Pairs with fingerprints already seen (from
/// retransmitted messages with identical nonces) are dropped immediately, avoiding the
/// Vec push and later traversal. This typically eliminates ~50-90% of generated pairs
/// at near-zero cost (fingerprint computation is ~20ns vs ~150ns for a full hash line).
/// The output phase runs a final ESSID-aware dedup for correctness.
#[must_use]
pub fn generate(ap: MacAddr, sta: MacAddr, messages: &[EapolMessage], config: &PairConfig) -> Vec<PairedHash> {
    use std::collections::HashSet;

    // Partition messages by type for O(n*m) pairing rather than O(n^2) over the full list.
    let m1s: Vec<&EapolMessage> = messages.iter().filter(|m| m.msg_type == MsgType::M1).collect();
    let m2s: Vec<&EapolMessage> = messages.iter().filter(|m| m.msg_type == MsgType::M2).collect();
    let m3s: Vec<&EapolMessage> = messages.iter().filter(|m| m.msg_type == MsgType::M3).collect();
    let m4s: Vec<&EapolMessage> = messages.iter().filter(|m| m.msg_type == MsgType::M4).collect();

    // Detect router endianness by pairwise-comparing ANonce variation across M1/M3 messages
    // for this (AP, STA) session. [hcxpcapngtool.c:3810-3822]
    //   * bytes 30-31 differ -> LE router (low-order bytes at the tail)
    //   * bytes 28-29 differ but 30-31 match -> BE router (low-order bytes deeper in)
    // Bits ORed onto `message_pair` whenever FLAG_NC would fire; hashcat uses them to
    // decide whether nonce-error-corrections must run.
    let router_endian = detect_nonce_endianness(&m1s, &m3s);

    let mut pairs: Vec<PairedHash> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();

    // Inline dedup helper: compute fingerprint and push only if new.
    // This uses the same fingerprint as output::dedup::eapol_fingerprint but with an
    // empty ESSID (ESSID is resolved later). The output phase runs a final ESSID-aware
    // dedup to catch the rare case where an AP advertises multiple SSIDs.
    let ap_bytes = ap.0;
    let sta_bytes = sta.0;

    // Inline dedup: push a pair only if its fingerprint hasn't been seen before.
    // Uses the same fingerprint layout as output::dedup::eapol_fingerprint but with
    // an empty ESSID (ESSID is resolved later). Eliminates ~50-90% of pairs at
    // generation time by catching retransmission duplicates (same nonce + EAPOL frame).
    //
    // Also overlays the session's detected router-endianness (LE/BE) onto the
    // message_pair byte, but only when the pair already carries FLAG_NC -- hcx
    // only emits LE/BE alongside NC (status = ST_LE + ST_NC or ST_BE + ST_NC).
    // Applying it here keeps try_pair's per-pair logic unchanged.
    macro_rules! dedup_push {
        ($pair:expr) => {{
            let mut p: PairedHash = $pair;
            if p.message_pair & FLAG_NC != 0 {
                if router_endian.0 {
                    p.message_pair |= FLAG_LE;
                }
                if router_endian.1 {
                    p.message_pair |= FLAG_BE;
                }
            }
            let kind: u8 = if p.akm.is_ft() { 0x04 } else { 0x02 };
            let fp = crate::types::hash_slices(
                kind,
                &[p.mic.as_slice(), &ap_bytes, &sta_bytes, &p.nonce, &p.eapol_frame, &[], &[p.message_pair]],
            );
            if seen.insert(fp) {
                pairs.push(p);
            }
        }};
    }

    // N1E2: ANonce from M1, EAPOL frame from M2. [ARCHITECTURE.md §5]
    for nonce_msg in &m1s {
        for eapol_msg in &m2s {
            if let Some(pair) = try_pair(ap, sta, nonce_msg, eapol_msg, ComboType::N1E2, config) {
                dedup_push!(pair);
            }
        }
    }

    // N1E4: ANonce from M1, EAPOL frame from M4. Spans the whole session. [ARCHITECTURE.md §5]
    for nonce_msg in &m1s {
        for eapol_msg in &m4s {
            if let Some(pair) = try_pair(ap, sta, nonce_msg, eapol_msg, ComboType::N1E4, config) {
                dedup_push!(pair);
            }
        }
    }

    // N3E2: ANonce from M3, EAPOL frame from M2. [ARCHITECTURE.md §5]
    for nonce_msg in &m3s {
        for eapol_msg in &m2s {
            if let Some(pair) = try_pair(ap, sta, nonce_msg, eapol_msg, ComboType::N3E2, config) {
                dedup_push!(pair);
            }
        }
    }

    // N2E3: SNonce from M2, EAPOL frame from M3. AP-less combo. [ARCHITECTURE.md §5]
    for nonce_msg in &m2s {
        for eapol_msg in &m3s {
            if let Some(pair) = try_pair(ap, sta, nonce_msg, eapol_msg, ComboType::N2E3, config) {
                dedup_push!(pair);
            }
        }
    }

    // N4E3: SNonce from M4, EAPOL frame from M3. AP-less combo. [ARCHITECTURE.md §5]
    for nonce_msg in &m4s {
        for eapol_msg in &m3s {
            if let Some(pair) = try_pair(ap, sta, nonce_msg, eapol_msg, ComboType::N4E3, config) {
                dedup_push!(pair);
            }
        }
    }

    // N3E4: ANonce from M3, EAPOL frame from M4. [ARCHITECTURE.md §5]
    //
    // NC flag for N3E4: hcxpcapngtool propagates M1's ST_NC=0x80 status to N3E4 pairs
    // via its 64-entry ring buffer whenever M1 is still present at pairing time. For
    // small captures M1 is always in the buffer; for large captures it may be evicted.
    // We approximate: set FLAG_NC whenever at least one M1 was seen in this session group.
    // This matches hcxpcapngtool's typical behaviour and ensures correct NC encoding for
    // hashcat. For cases where hcxpcapngtool would have evicted M1, this adds NC=1 where
    // hcxpcapngtool would output NC=0 -- hashcat applies redundant corrections that are safe.
    // [hcxpcapngtool include/hcxpcapngtool.h: ST_NC=0x80, addhandshake() status propagation]
    let has_m1_for_session = !m1s.is_empty();
    for nonce_msg in &m3s {
        for eapol_msg in &m4s {
            if let Some(mut pair) = try_pair(ap, sta, nonce_msg, eapol_msg, ComboType::N3E4, config) {
                if has_m1_for_session {
                    pair.message_pair |= FLAG_NC;
                }
                dedup_push!(pair);
            }
        }
    }

    pairs
}

// --- try_pair ---

/// Attempts to build a `PairedHash` from a (`nonce_msg`, `eapol_msg`) candidate.
///
/// Returns `None` when either the time-gap or the RC constraint rejects the pair.
/// On success, encodes the `message_pair` byte: bits 0-2 hold the `ComboType` discriminant,
/// bits 5-7 carry the RC relationship flags (`FLAG_LE`, `FLAG_BE`, `FLAG_NC`).
/// [hcxtools convention -- `message_pair` encoding]
fn try_pair(
    ap: MacAddr,
    sta: MacAddr,
    nonce_msg: &EapolMessage,
    eapol_msg: &EapolMessage,
    combo: ComboType,
    config: &PairConfig,
) -> Option<PairedHash> {
    // Time constraint: both messages must fall within the configured EAPOL session window.
    // [ARCHITECTURE.md §8 FR-PAIR-3]
    if config.time_check_enabled && !within_time(nonce_msg.timestamp, eapol_msg.timestamp, config.eapol_timeout_us) {
        return None;
    }

    // RC constraint (opt-in via --rc-drift): replay counters must be consistent with the
    // expected relationship for this combo type. Uses combo-aware offset so that N3E2/N2E3/N1E4
    // pairs with the standard M3.rc = M2.rc + 1 delta are not spuriously rejected.
    // Unfiltered (rc_drift_enabled=false): all pairs treated as RC-exact. [ARCHITECTURE.md §8 FR-PAIR-4]
    let rc_rel = if config.rc_drift_enabled {
        within_rc_for_combo(nonce_msg, eapol_msg, combo, config.rc_drift_tolerance)?
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
            // NC flag (bit 7) rule -- derived from hcxpcapngtool source analysis:
            //
            // hcxpcapngtool initialises every M1 with status = ST_NC (0x80). When a pair
            // is produced, addhandshake() propagates the AP's stored status bits (0xe0)
            // to the mpfield. So N1E2/N1E4 pairs always inherit NC from M1.
            //
            // For M3-sourced pairs (N3E2, N3E4): hcxpcapngtool only propagates NC when M1
            // is still in the 64-entry ring buffer at the time M3 is processed -- which is
            // rare in large captures. Empirically, N3E2 pairs in hcxpcapngtool output are
            // always 0x02 (NC=0) for ncvalue=0 (the default). N3E4 pairs may be 0x85 (NC=1)
            // when M1 was recently seen, but the NC flag there is ring-buffer-timing-dependent.
            //
            // Unfiltered (rc_drift_enabled=false, ncvalue=0): ncvalue=0 means the
            // `if(ncvalue > 0 && !(status & 0x10))` guard in hcxpcapngtool never fires.
            // NC for N3E2/N3E4 is therefore 0 in standard operation.
            //
            // Rule: NC = (!apless) AND (nonce from M1)
            // [hcxpcapngtool include/hcxpcapngtool.h: ST_NC=0x80, getkeyinfo() M1 path]
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

    Some(PairedHash {
        ap,
        sta,
        combo_type: combo,
        nonce: nonce_msg.nonce,
        eapol_frame: Arc::clone(&eapol_msg.eapol_frame),
        mic: eapol_msg.mic,
        message_pair,
        akm: eapol_msg.akm,
        ft: eapol_msg.ft,
        rc_gap_magnitude,
    })
}

// --- Nonce endianness detection ---

/// Inspects M1 and M3 `ANonce` bytes to decide whether the AP is storing the nonce's
/// low-order counter bytes little-endian or big-endian.
///
/// hcxpcapngtool does this by pairwise-comparing any two M1 (or M3) nonces from the
/// same (AP, STA) session. When the first 28 bytes match but the last 4 differ, the
/// differences reveal where the low-order bytes live:
///
/// - bytes 30-31 differ  -> LE router (counter incremented at the tail, little-end)
/// - bytes 28-29 differ but 30-31 match -> BE router (counter deeper in, big-end)
///
/// \[`hcxpcapngtool.c`:3810-3822\]: `ST_LE = 0x20`, `ST_BE = 0x40`.
///
/// Returns `(le, be)` where each bool is set on the first positive pairwise match.
/// Both remaining `false` for sessions with only one M1/M3 (most short captures).
/// Used by `generate()` to propagate the flag onto every paired hash with `FLAG_NC`,
/// matching hcxpcapngtool's `status = ST_LE + ST_NC` / `ST_BE + ST_NC` encoding.
fn detect_nonce_endianness(m1s: &[&EapolMessage], m3s: &[&EapolMessage]) -> (bool, bool) {
    let mut le = false;
    let mut be = false;
    for group in [m1s, m3s] {
        for (i, a) in group.iter().enumerate() {
            for b in group.iter().skip(i + 1) {
                // First 28 bytes must match (the static portion of the AP's RNG seed),
                // last 4 bytes must differ (the counter portion). [hcxpcapngtool.c:3810]
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

    fn default_config() -> PairConfig {
        PairConfig::default()
    }

    #[test]
    fn generate_n1e2_basic() {
        // M1 (RC=1, ts=0) paired with M2 (RC=1, ts=100) -> one N1E2 pair.
        let msgs = vec![make_msg(MsgType::M1, 1, 0, 0xAA), make_msg(MsgType::M2, 1, 100, 0xBB)];
        let pairs = generate(ap(), sta(), &msgs, &default_config());
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].combo_type, ComboType::N1E2);
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
        let pairs = generate(ap(), sta(), &msgs, &config);
        assert!(pairs.is_empty());
    }

    #[test]
    fn generate_no_pairs_rc_mismatch() {
        // M1 RC=1, M2 RC=100 -> delta=99 > tolerance=8 -> no pairs when rc_drift is on.
        let config = PairConfig { rc_drift_enabled: true, rc_drift_tolerance: 8, ..PairConfig::default() };
        let msgs = vec![make_msg(MsgType::M1, 1, 0, 0xAA), make_msg(MsgType::M2, 100, 100, 0xBB)];
        let pairs = generate(ap(), sta(), &msgs, &config);
        assert!(pairs.is_empty());
    }

    #[test]
    fn generate_n3e2() {
        // M3 (RC=2, ts=200) paired with M2 (RC=2, ts=100) -> at least one N3E2 pair.
        // N2E3 also fires here (M2 as nonce, M3 as eapol, same RCs), so assert by filtering.
        let msgs = vec![make_msg(MsgType::M3, 2, 200, 0xAA), make_msg(MsgType::M2, 2, 100, 0xBB)];
        let pairs = generate(ap(), sta(), &msgs, &default_config());
        assert_eq!(pairs.iter().filter(|p| p.combo_type == ComboType::N3E2).count(), 1);
    }

    #[test]
    fn generate_n2e3() {
        // M2 (RC=1, ts=100) paired with M3 (RC=2, ts=200) -> at least one N2E3 pair.
        // N3E2 also fires (M3 as nonce RC=2, M2 as eapol RC=1, delta=1 -> Exact), so filter.
        let msgs = vec![make_msg(MsgType::M2, 1, 100, 0xCC), make_msg(MsgType::M3, 2, 200, 0xDD)];
        let pairs = generate(ap(), sta(), &msgs, &default_config());
        assert_eq!(pairs.iter().filter(|p| p.combo_type == ComboType::N2E3).count(), 1);
    }

    #[test]
    fn generate_n1e4() {
        // M1 (RC=1, ts=0) paired with M4 (RC=2, ts=300) -> one N1E4 pair (RC diff=1 <= 8).
        // No other combos fire with only M1 and M4 in the list.
        let msgs = vec![make_msg(MsgType::M1, 1, 0, 0xAA), make_msg(MsgType::M4, 2, 300, 0xBB)];
        let pairs = generate(ap(), sta(), &msgs, &default_config());
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].combo_type, ComboType::N1E4);
    }

    #[test]
    fn generate_n4e3() {
        // M4 (RC=2, ts=300) paired with M3 (RC=2, ts=200) -> at least one N4E3 pair.
        // N3E4 also fires (same M3 as nonce, M4 as eapol, same RCs), so filter.
        let msgs = vec![make_msg(MsgType::M4, 2, 300, 0xAA), make_msg(MsgType::M3, 2, 200, 0xBB)];
        let pairs = generate(ap(), sta(), &msgs, &default_config());
        assert_eq!(pairs.iter().filter(|p| p.combo_type == ComboType::N4E3).count(), 1);
    }

    #[test]
    fn generate_n3e4() {
        // M3 (RC=2, ts=200) paired with M4 (RC=2, ts=300) -> at least one N3E4 pair.
        // N4E3 also fires (M4 as nonce, M3 as eapol, same RCs), so filter.
        let msgs = vec![make_msg(MsgType::M3, 2, 200, 0xAA), make_msg(MsgType::M4, 2, 300, 0xBB)];
        let pairs = generate(ap(), sta(), &msgs, &default_config());
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
        let pairs = generate(ap(), sta(), &msgs, &default_config());
        // All four should be N1E2.
        assert_eq!(pairs.len(), 4);
        assert!(pairs.iter().all(|p| p.combo_type == ComboType::N1E2));
    }

    #[test]
    fn generate_empty_messages() {
        // Empty slice -> no pairs.
        let pairs = generate(ap(), sta(), &[], &default_config());
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
        };
        let pairs = generate(ap(), sta(), &msgs, &tight);
        // With rc_drift active and tolerance=8, the pair should be found with NC set.
        assert_eq!(pairs.len(), 1);
        assert_ne!(pairs[0].message_pair & FLAG_NC, 0, "FLAG_NC must be set for within-tolerance RC");
    }

    #[test]
    fn generate_combo_type_in_message_pair() {
        // N1E2 -> combo discriminant = 0, so message_pair & 0x07 == 0.
        let msgs = vec![make_msg(MsgType::M1, 1, 0, 0xAA), make_msg(MsgType::M2, 1, 100, 0xBB)];
        let pairs = generate(ap(), sta(), &msgs, &default_config());
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].message_pair & 0x07, ComboType::N1E2 as u8);
    }
}
