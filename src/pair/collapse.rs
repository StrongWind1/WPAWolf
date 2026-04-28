//! Phase 4 -- Emit: 6 N#E# combos -> 3 equivalence classes per session. See ARCHITECTURE.md §5.
//!
//! Within a single handshake session where M1 and M3 carry the same `ANonce`, and M2 and M4
//! carry the same `SNonce`, the six N#E# combos reduce to three unique crackable hashes -- one
//! per distinct EAPOL frame (M2-EAPOL, M3-EAPOL, M4-EAPOL). Two pairs are considered
//! equivalent when both their NONCE field values and EAPOL frame bytes are identical. In
//! default mode, the "authorized" combo within each equivalence class survives; in `--all`
//! mode, all six are emitted. See `ARCHITECTURE.md §5` and `ARCHITECTURE.md §8` FR-PAIR-5.

use std::sync::Arc;

use super::{ComboType, PairedHash};

/// Authorized-handshake priority for equivalence-class collapsing.
///
/// Lower priority number = preferred. Within each EAPOL-source class:
/// - Hash-A (M2 EAPOL): prefer N3E2 (confirmed `ANonce` from M3) over N1E2
/// - Hash-B (M3 EAPOL): prefer N2E3 (`SNonce` from M2) over N4E3
/// - Hash-C (M4 EAPOL): prefer N3E4 (confirmed `ANonce` from M3) over N1E4
///
/// Per `ARCHITECTURE.md §5` and user specification (prefer authorized handshakes).
const fn authorized_priority(combo: ComboType) -> u8 {
    match combo {
        // Preferred: M3/M2-sourced nonce is confirmed/canonical
        ComboType::N3E2 | ComboType::N2E3 | ComboType::N3E4 => 0,
        // Fallback: M1/M4-sourced nonce
        ComboType::N1E2 | ComboType::N4E3 | ComboType::N1E4 => 1,
    }
}

/// Collapses equivalent N#E# pairs within a set of paired hashes.
///
/// Two pairs are equivalent when their `nonce` and `eapol_frame` bytes are identical.
/// Within each equivalence class the best pair survives, chosen by this priority:
/// 1. Smallest `rc_gap_magnitude` (exact RC match is most authentic; lower is better).
/// 2. Lowest `authorized_priority` as a tie-breaker (N3E2 > N1E2, N2E3 > N4E3, N3E4 > N1E4).
///
/// When `all_combos` is `true`, returns the input unchanged.
///
/// This reduces up to six combos per session to at most three unique crackable hashes,
/// avoiding duplicate work for hashcat. See `ARCHITECTURE.md §5`.
#[must_use]
pub fn collapse(pairs: Vec<PairedHash>, all_combos: bool) -> Vec<PairedHash> {
    if all_combos || pairs.len() <= 1 {
        return pairs;
    }

    // Group pairs by (nonce, eapol_frame). Within each group, keep the best pair.
    // Use a Vec-based approach since pair counts are tiny (<= 6 per session).
    let mut kept: Vec<PairedHash> = Vec::with_capacity(pairs.len());

    'outer: for pair in pairs {
        for existing in &mut kept {
            // Two pairs are equivalent iff both their nonce and EAPOL bytes match.
            // Arc::ptr_eq gives O(1) fast-path when both pairs share the same frame allocation
            // (common: N1E2 and N3E2 both reference the same M2's eapol_frame Arc).
            let frames_equal =
                Arc::ptr_eq(&existing.eapol_frame, &pair.eapol_frame) || existing.eapol_frame == pair.eapol_frame;
            if existing.nonce == pair.nonce && frames_equal {
                // Priority 1: smaller RC gap magnitude (exact match over tolerance).
                // Priority 2: authorized combo as tie-breaker.
                let should_replace = pair.rc_gap_magnitude < existing.rc_gap_magnitude
                    || (pair.rc_gap_magnitude == existing.rc_gap_magnitude
                        && authorized_priority(pair.combo_type) < authorized_priority(existing.combo_type));
                if should_replace {
                    *existing = pair;
                }
                continue 'outer;
            }
        }
        kept.push(pair);
    }

    kept
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
    use crate::{
        pair::ComboType,
        types::{AkmType, MacAddr, MicBytes},
    };

    /// Builds a `PairedHash` with only the fields that matter for equivalence testing
    /// varied; all other fields are set to fixed sentinel values.
    /// `rc_gap` defaults to 0 (exact RC match) unless overridden by the caller.
    fn make_pair(combo: ComboType, nonce_byte: u8, eapol_byte: u8) -> PairedHash {
        make_pair_with_gap(combo, nonce_byte, eapol_byte, 0)
    }

    fn make_pair_with_gap(combo: ComboType, nonce_byte: u8, eapol_byte: u8, rc_gap: u64) -> PairedHash {
        PairedHash {
            ap: MacAddr::from_bytes([0x11; 6]),
            sta: MacAddr::from_bytes([0x22; 6]),
            combo_type: combo,
            nonce: [nonce_byte; 32],
            eapol_frame: Arc::from(vec![eapol_byte; 10]),
            mic: MicBytes::ZERO_16,
            message_pair: combo as u8,
            akm: AkmType::Wpa2Psk,
            ft: None,
            rc_gap_magnitude: rc_gap,
        }
    }

    #[test]
    fn collapse_empty() {
        let result = collapse(vec![], false);
        assert!(result.is_empty());
    }

    #[test]
    fn collapse_single() {
        let pair = make_pair(ComboType::N1E2, 0xAA, 0xBB);
        let result = collapse(vec![pair], false);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].combo_type, ComboType::N1E2);
    }

    #[test]
    fn collapse_two_different() {
        // Different nonce bytes -> different equivalence classes -> both retained.
        let p1 = make_pair(ComboType::N1E2, 0x01, 0xFF);
        let p2 = make_pair(ComboType::N3E2, 0x02, 0xFF);
        let result = collapse(vec![p1, p2], false);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn collapse_two_equivalent_keeps_authorized_combo() {
        // N3E2 and N1E2 are equivalent; N3E2 should survive (authorized: M3 confirms ANonce).
        // Input order: N1E2 first to exercise the replacement path.
        let p_n1e2 = make_pair(ComboType::N1E2, 0xAA, 0xBB);
        let p_n3e2 = make_pair(ComboType::N3E2, 0xAA, 0xBB);
        let result = collapse(vec![p_n1e2, p_n3e2], false);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].combo_type, ComboType::N3E2);
    }

    #[test]
    fn collapse_three_combos_two_equivalent() {
        // N1E2 and N3E2 share the same nonce+eapol; N2E3 is different.
        let p_n1e2 = make_pair(ComboType::N1E2, 0xAA, 0xBB);
        let p_n3e2 = make_pair(ComboType::N3E2, 0xAA, 0xBB);
        let p_n2e3 = make_pair(ComboType::N2E3, 0xCC, 0xDD);
        let result = collapse(vec![p_n1e2, p_n3e2, p_n2e3], false);
        assert_eq!(result.len(), 2);
        // The surviving combo from the first class must be N3E2 (authorized: M3 confirms ANonce).
        let combos: Vec<ComboType> = result.iter().map(|p| p.combo_type).collect();
        assert!(combos.contains(&ComboType::N3E2));
        assert!(!combos.contains(&ComboType::N1E2));
        assert!(combos.contains(&ComboType::N2E3));
    }

    #[test]
    fn collapse_all_six_to_three() {
        // Three equivalence classes:
        //   Hash-A: N1E2 == N3E2  (nonce=0x01, eapol=0xAA) -> N3E2 authorized
        //   Hash-B: N2E3 == N4E3  (nonce=0x02, eapol=0xBB) -> N2E3 authorized
        //   Hash-C: N1E4 == N3E4  (nonce=0x03, eapol=0xCC) -> N3E4 authorized
        // Input order deliberately places the fallback combo first to exercise replacement.
        let pairs = vec![
            make_pair(ComboType::N1E2, 0x01, 0xAA), // Hash-A fallback
            make_pair(ComboType::N3E2, 0x01, 0xAA), // Hash-A authorized -- must win
            make_pair(ComboType::N4E3, 0x02, 0xBB), // Hash-B fallback
            make_pair(ComboType::N2E3, 0x02, 0xBB), // Hash-B authorized -- must win
            make_pair(ComboType::N1E4, 0x03, 0xCC), // Hash-C fallback
            make_pair(ComboType::N3E4, 0x03, 0xCC), // Hash-C authorized -- must win
        ];
        let result = collapse(pairs, false);
        assert_eq!(result.len(), 3);
        let combos: Vec<ComboType> = result.iter().map(|p| p.combo_type).collect();
        assert!(combos.contains(&ComboType::N3E2));
        assert!(combos.contains(&ComboType::N2E3));
        assert!(combos.contains(&ComboType::N3E4));
        assert!(!combos.contains(&ComboType::N1E2));
        assert!(!combos.contains(&ComboType::N4E3));
        assert!(!combos.contains(&ComboType::N1E4));
    }

    #[test]
    fn collapse_all_combos_true() {
        // With all_combos=true, two equivalent pairs are both returned unchanged.
        let p1 = make_pair(ComboType::N3E2, 0xAA, 0xBB);
        let p2 = make_pair(ComboType::N1E2, 0xAA, 0xBB);
        let result = collapse(vec![p1, p2], true);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn collapse_same_nonce_different_eapol() {
        // Same nonce byte but different EAPOL byte -> not equivalent -> both kept.
        let p1 = make_pair(ComboType::N1E2, 0xAA, 0x11);
        let p2 = make_pair(ComboType::N3E2, 0xAA, 0x22);
        let result = collapse(vec![p1, p2], false);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn collapse_same_eapol_different_nonce() {
        // Same EAPOL byte but different nonce byte -> not equivalent -> both kept.
        let p1 = make_pair(ComboType::N1E2, 0x11, 0xAA);
        let p2 = make_pair(ComboType::N3E2, 0x22, 0xAA);
        let result = collapse(vec![p1, p2], false);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn rc_gap_priority_beats_authorized_priority() {
        // N1E2 (fallback combo) with rc_gap=0 beats N3E2 (authorized) with rc_gap=5.
        // RC gap quality is the primary sort key; authorized priority is the tie-breaker.
        let p_n3e2_big_gap = make_pair_with_gap(ComboType::N3E2, 0xAA, 0xBB, 5);
        let p_n1e2_exact = make_pair_with_gap(ComboType::N1E2, 0xAA, 0xBB, 0);
        let result = collapse(vec![p_n3e2_big_gap, p_n1e2_exact], false);
        assert_eq!(result.len(), 1);
        // N1E2 wins because its RC gap (0 = exact) is smaller than N3E2's (5).
        assert_eq!(result[0].combo_type, ComboType::N1E2);
    }

    #[test]
    fn rc_gap_tie_uses_authorized_priority() {
        // Both combos have the same rc_gap -> authorized_priority is the tie-breaker.
        // N3E2 (authorized, priority 0) must win over N1E2 (fallback, priority 1)
        // when both have rc_gap=0.
        let p_n1e2_exact = make_pair_with_gap(ComboType::N1E2, 0xAA, 0xBB, 0);
        let p_n3e2_exact = make_pair_with_gap(ComboType::N3E2, 0xAA, 0xBB, 0);
        let result = collapse(vec![p_n1e2_exact, p_n3e2_exact], false);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].combo_type, ComboType::N3E2, "tie broken by authorized priority");
    }

    #[test]
    fn rc_gap_priority_all_six_combos() {
        // Three equivalence classes where the fallback combo has smaller RC gap.
        // Hash-A: N1E2 (gap=0) beats N3E2 (gap=2)
        // Hash-B: N4E3 (gap=0) beats N2E3 (gap=3)
        // Hash-C: N1E4 (gap=0) beats N3E4 (gap=1)
        let pairs = vec![
            make_pair_with_gap(ComboType::N3E2, 0x01, 0xAA, 2),
            make_pair_with_gap(ComboType::N1E2, 0x01, 0xAA, 0),
            make_pair_with_gap(ComboType::N2E3, 0x02, 0xBB, 3),
            make_pair_with_gap(ComboType::N4E3, 0x02, 0xBB, 0),
            make_pair_with_gap(ComboType::N3E4, 0x03, 0xCC, 1),
            make_pair_with_gap(ComboType::N1E4, 0x03, 0xCC, 0),
        ];
        let result = collapse(pairs, false);
        assert_eq!(result.len(), 3);
        let combos: Vec<ComboType> = result.iter().map(|p| p.combo_type).collect();
        // Fallback combos win here because their RC gaps are smaller.
        assert!(combos.contains(&ComboType::N1E2), "N1E2 wins Hash-A (gap=0 < N3E2 gap=2)");
        assert!(combos.contains(&ComboType::N4E3), "N4E3 wins Hash-B (gap=0 < N2E3 gap=3)");
        assert!(combos.contains(&ComboType::N1E4), "N1E4 wins Hash-C (gap=0 < N3E4 gap=1)");
    }
}
