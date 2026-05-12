//! Phase 4 -- Emit: pairing constraints (replay-counter drift, eapoltimeout, nonce endianness). See ARCHITECTURE.md §5 + §8.6.
//!
//! Validates candidate `(nonce_message, eapol_message)` pairs by checking two criteria:
//! (1) timestamp gap within the configured EAPOL timeout (`within_time`), and (2) replay
//! counter relationship within nonce-error-correction tolerance or byte-swapped endianness
//! (`within_rc` / `within_rc_for_combo`). Endianness ambiguity is resolved by comparing
//! the RC bytes under both native and swapped interpretation to set LE/BE flags in
//! `message_pair`. See `ARCHITECTURE.md §8` FR-PAIR-3 and FR-PAIR-4. Nonce-validity
//! enforcement (FR-PAIR-7) lives upstream in `src/ieee80211/eapol.rs` via
//! `garbage_pattern_kind`, which rejects `null` / `ff` / `repeat_1` / `repeat_2` /
//! `repeat_4` patterns at parse time on every message type, including the spec-valid
//! M4 NULL nonce per [IEEE 802.11-2024] §12.7.6.5 NOTE 9. Zero nonces never reach this
//! module.

use crate::pair::ComboType;
use crate::store::messages::EapolMessage;

// --- RcRelation ---

/// The relationship between two Replay Counter values that allowed a pair to pass.
///
/// Returned by `within_rc` to let the pairing engine set the correct `FLAG_NC`,
/// `FLAG_BE`, or `FLAG_LE` bits in the `message_pair` byte of the output hash line.
/// See `ARCHITECTURE.md §8` FR-PAIR-4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RcRelation {
    /// The RC values matched exactly (difference = 0) within native byte order.
    Exact,
    /// The RC values differed by up to `tolerance` within native byte order.
    /// The pairing engine should set `FLAG_NC` in `message_pair`.
    WithinTolerance,
    /// The RC values matched only after byte-swapping one of them.
    /// The pairing engine should set `FLAG_BE` or `FLAG_LE` in `message_pair`.
    ByteSwapped,
}

// --- Time constraint ---

/// Returns `true` if the two messages were captured within `timeout_us` microseconds.
///
/// Uses `u64::abs_diff` to avoid overflow on large or reversed timestamps. Only called
/// when `PairConfig::time_check_enabled` is true; pass `600_000_000` (10 minutes) or
/// whatever the operator specified via `--eapoltimeout`. [ARCHITECTURE.md §8 FR-PAIR-3]
#[must_use]
pub const fn within_time(ts_a: u64, ts_b: u64, timeout_us: u64) -> bool {
    ts_a.abs_diff(ts_b) <= timeout_us
}

// --- Replay Counter constraint ---

/// Returns `Some(relation)` if the Replay Counters of two messages are consistent
/// within `tolerance`, or `None` if neither native nor byte-swapped comparison succeeds.
///
/// Algorithm (FR-PAIR-4):
/// 1. Compute `native_diff = abs(rc_a - rc_b)`.
/// 2. If `native_diff == 0` -> `Some(Exact)`.
/// 3. If `native_diff <= tolerance` -> `Some(WithinTolerance)` (triggers `FLAG_NC`).
/// 4. Byte-swap `rc_a`; if swapped diff `<= tolerance` -> `Some(ByteSwapped)`.
/// 5. Byte-swap `rc_b`; if swapped diff `<= tolerance` -> `Some(ByteSwapped)`.
/// 6. Otherwise -> `None` (pair is rejected).
///
/// The `tolerance` parameter maps to `--rc-drift` (default 8 when the flag is bare).
/// Byte-swapping detects implementations that store the RC in the wrong endianness
/// (big-endian vs little-endian). [IEEE 802.11-2024] §12.7.2
#[must_use]
#[allow(clippy::similar_names, reason = "rc_a_swapped/rc_b_swapped mirror rc_a/rc_b naming pattern")]
pub fn within_rc(msg_a: &EapolMessage, msg_b: &EapolMessage, tolerance: u8) -> Option<RcRelation> {
    let rc_a = msg_a.replay_counter;
    let rc_b = msg_b.replay_counter;
    let tol = u64::from(tolerance);

    // Native comparison -- most common case.
    let native_diff = rc_a.abs_diff(rc_b);
    if native_diff == 0 {
        return Some(RcRelation::Exact);
    }
    if native_diff <= tol {
        return Some(RcRelation::WithinTolerance);
    }

    // Byte-swapped comparison: swap all 8 bytes of rc_a and compare with rc_b.
    // Detects firmware that writes the RC in reversed byte order.
    // [hcxtools convention -- observed deviation from IEEE 802.11-2024 §12.7.2]
    let rc_a_swapped = rc_a.swap_bytes();
    let swapped_diff_a = rc_a_swapped.abs_diff(rc_b);
    if swapped_diff_a <= tol {
        return Some(RcRelation::ByteSwapped);
    }

    // Also try swapping rc_b in case the endianness bug is on the other side.
    let rc_b_swapped = rc_b.swap_bytes();
    let swapped_diff_b = rc_a.abs_diff(rc_b_swapped);
    if swapped_diff_b <= tol {
        return Some(RcRelation::ByteSwapped);
    }

    None
}

// --- Combo-aware Replay Counter constraint ---

/// Expected value of `nonce_msg.rc - eapol_msg.rc` for each N#E# combination.
///
/// In a standard 4-way handshake: M1.rc == M2.rc, M3.rc == M2.rc + 1, M4.rc == M3.rc.
/// Applying the correct offset per combo prevents valid pairs from being rejected when
/// `tolerance == 0`. Without the offset, N3E2 always has delta=+1 (never 0), causing
/// every such pair to fail strict RC checking. [IEEE 802.11-2024] §12.7.2
///
/// Exposed as `pub(super)` so `combos::try_pair` can compute `rc_gap_magnitude` without
/// duplicating the delta table.
pub(super) const fn expected_rc_delta(combo: ComboType) -> i64 {
    match combo {
        // M1.rc == M2.rc, M4.rc == M3.rc, M3.rc == M4.rc
        ComboType::N1E2 | ComboType::N4E3 | ComboType::N3E4 => 0,
        // M4.rc == M1.rc + 1 (M1.rc - M4.rc == -1) and M2.rc - M3.rc == -1
        ComboType::N1E4 | ComboType::N2E3 => -1,
        ComboType::N3E2 => 1, // M3.rc == M2.rc + 1, so M3.rc - M2.rc == +1
    }
}

/// Checks whether the replay counters are consistent with the expected relationship
/// for `combo`, within `tolerance` steps.
///
/// Unlike `within_rc`, this function accounts for the fact that M3.rc = M2.rc + 1 in a
/// standard handshake, so N3E2/N2E3/N1E4 pairs have a natural delta of +/-1. Ignoring that
/// offset causes all such pairs to be rejected when `tolerance == 0`.
///
/// Returns the `RcRelation` if within tolerance, `None` if not. [IEEE 802.11-2024] §12.7.2
#[must_use]
pub fn within_rc_for_combo(
    nonce_msg: &EapolMessage,
    eapol_msg: &EapolMessage,
    combo: ComboType,
    tolerance: u8,
) -> Option<RcRelation> {
    let delta = expected_rc_delta(combo);
    let tol = u128::from(tolerance);

    let rc_a = i128::from(nonce_msg.replay_counter);
    let rc_b = i128::from(eapol_msg.replay_counter);
    let actual_delta = rc_a - rc_b;
    let expected = i128::from(delta);

    // Gap = how far the actual delta is from the expected delta.
    let gap = (actual_delta - expected).unsigned_abs();

    if gap == 0 {
        return Some(RcRelation::Exact);
    }
    if gap <= tol {
        return Some(RcRelation::WithinTolerance);
    }

    // Byte-swapped comparison: try swapping nonce_msg RC.
    // Detects firmware that writes the RC in reversed byte order.
    // [hcxtools convention -- observed deviation from IEEE 802.11-2024 §12.7.2]
    let nonce_rc_swapped = i128::from(nonce_msg.replay_counter.swap_bytes());
    let gap_nonce_swap = (nonce_rc_swapped - rc_b - expected).unsigned_abs();
    if gap_nonce_swap <= tol {
        return Some(RcRelation::ByteSwapped);
    }

    // Also try swapping eapol_msg RC.
    let eapol_rc_swapped = i128::from(eapol_msg.replay_counter.swap_bytes());
    let gap_eapol_swap = (rc_a - eapol_rc_swapped - expected).unsigned_abs();
    if gap_eapol_swap <= tol {
        return Some(RcRelation::ByteSwapped);
    }

    None
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

    use std::sync::Arc;

    use super::*;
    use crate::pair::ComboType;
    use crate::types::{AkmType, MicBytes, MsgType};

    /// Builds a minimal `EapolMessage` with the given `replay_counter`.
    /// All other fields are set to innocuous defaults so tests focus on the RC logic.
    fn make_msg(rc: u64) -> EapolMessage {
        EapolMessage {
            timestamp: 0,
            msg_type: MsgType::M1,
            key_version: 2,
            replay_counter: rc,
            nonce: [1u8; 32],
            mic: MicBytes::ZERO_16,
            pmkid: None,
            eapol_frame: Arc::from(Vec::new()),
            ft: None,
            akm: AkmType::Wpa2Psk,
            is_rsn: true,
        }
    }

    // --- within_time ---

    #[test]
    fn within_time_same_ts() {
        assert!(within_time(1000, 1000, 5000));
    }

    #[test]
    fn within_time_within_limit() {
        assert!(within_time(0, 4999, 5000));
    }

    #[test]
    fn within_time_at_limit() {
        // diff == timeout_us is still within (<=).
        assert!(within_time(0, 5000, 5000));
    }

    #[test]
    fn within_time_over_limit() {
        assert!(!within_time(0, 5001, 5000));
    }

    // --- within_rc ---

    #[test]
    fn within_rc_exact() {
        let a = make_msg(42);
        let b = make_msg(42);
        assert_eq!(within_rc(&a, &b, 8), Some(RcRelation::Exact));
    }

    #[test]
    fn within_rc_within_tolerance() {
        // diff = 8 == tolerance -> WithinTolerance.
        let a = make_msg(10);
        let b = make_msg(18);
        assert_eq!(within_rc(&a, &b, 8), Some(RcRelation::WithinTolerance));
    }

    #[test]
    fn within_rc_exceeds_tolerance() {
        // diff = 9 > tolerance=8, no byte-swap match -> None.
        let a = make_msg(10);
        let b = make_msg(19);
        assert_eq!(within_rc(&a, &b, 8), None);
    }

    #[test]
    fn within_rc_byte_swapped() {
        // rc_a = 0x0100_0000_0000_0000 (value 1 stored in big-endian by a buggy impl).
        // After swap_bytes it becomes 1, matching rc_b = 1 exactly (diff=0 <= tol=0).
        let a = make_msg(0x0100_0000_0000_0000_u64);
        let b = make_msg(1);
        assert_eq!(within_rc(&a, &b, 0), Some(RcRelation::ByteSwapped));
    }

    #[test]
    fn within_rc_zero_tolerance_exact() {
        let a = make_msg(99);
        let b = make_msg(99);
        assert_eq!(within_rc(&a, &b, 0), Some(RcRelation::Exact));
    }

    #[test]
    fn within_rc_zero_tolerance_different() {
        // diff = 1 > tol=0, no byte-swap match -> None.
        let a = make_msg(1);
        let b = make_msg(2);
        assert_eq!(within_rc(&a, &b, 0), None);
    }

    // --- within_rc_for_combo ---

    #[test]
    fn within_rc_for_combo_n1e2_exact() {
        // N1E2: M1.rc == M2.rc -> delta = 0, gap = 0 -> Exact.
        let nonce = make_msg(10);
        let eapol = make_msg(10);
        assert_eq!(within_rc_for_combo(&nonce, &eapol, ComboType::N1E2, 0), Some(RcRelation::Exact));
    }

    #[test]
    fn within_rc_for_combo_n3e2_natural_delta() {
        // N3E2: M3.rc = M2.rc + 1, so nonce.rc(=M3.rc) - eapol.rc(=M2.rc) == +1.
        // Expected delta = +1 -> gap = 0 -> Exact, even with tolerance=0.
        let nonce = make_msg(11); // M3.rc
        let eapol = make_msg(10); // M2.rc
        assert_eq!(within_rc_for_combo(&nonce, &eapol, ComboType::N3E2, 0), Some(RcRelation::Exact));
    }

    #[test]
    fn within_rc_for_combo_n2e3_natural_delta() {
        // N2E3: nonce=M2.rc=10, eapol=M3.rc=11. Expected delta = -1.
        // actual_delta = 10 - 11 = -1 == expected -> gap = 0 -> Exact.
        let nonce = make_msg(10); // M2.rc
        let eapol = make_msg(11); // M3.rc
        assert_eq!(within_rc_for_combo(&nonce, &eapol, ComboType::N2E3, 0), Some(RcRelation::Exact));
    }

    #[test]
    fn within_rc_for_combo_n1e4_natural_delta() {
        // N1E4: M4.rc = M1.rc + 1, so nonce.rc(=M1.rc) - eapol.rc(=M4.rc) == -1.
        // Expected delta = -1 -> gap = 0 -> Exact.
        let nonce = make_msg(10); // M1.rc
        let eapol = make_msg(11); // M4.rc
        assert_eq!(within_rc_for_combo(&nonce, &eapol, ComboType::N1E4, 0), Some(RcRelation::Exact));
    }

    #[test]
    fn within_rc_for_combo_n3e2_exceeds_tolerance() {
        // N3E2 with nonce.rc - eapol.rc = 5 but expected = 1 -> gap = 4 > tolerance=2 -> None.
        let nonce = make_msg(15);
        let eapol = make_msg(10);
        assert_eq!(within_rc_for_combo(&nonce, &eapol, ComboType::N3E2, 2), None);
    }

    #[test]
    fn within_rc_for_combo_n3e2_within_tolerance() {
        // N3E2 with nonce.rc - eapol.rc = 3 but expected = 1 -> gap = 2 <= tolerance=2 -> WithinTolerance.
        let nonce = make_msg(13);
        let eapol = make_msg(10);
        assert_eq!(within_rc_for_combo(&nonce, &eapol, ComboType::N3E2, 2), Some(RcRelation::WithinTolerance));
    }
}
