//! IEEE 802.11 FCS (Frame Check Sequence) verification via CRC-32.
//!
//! The 802.11 FCS is a standard CRC-32 (ISO 3309 / IEEE 802.3, polynomial
//! `0x04C11DB7` reflected as `0xEDB88320`, init `0xFFFF_FFFF`, final XOR
//! `0xFFFF_FFFF`) appended as 4 LE bytes to every MPDU on the air.
//!
//! A mathematical property of CRC: computing CRC-32 over `(data || crc32(data))`
//! always produces a fixed residue constant `0x2144_DF1C`, regardless of the
//! input. This lets us verify FCS presence in a single pass without separating
//! the checksum from the payload.
//!
//! Reference: [IEEE 802.11-2024] section 9.3.1.9 (FCS field);
//! [IEEE 802.3-2022] section 3.2.9 (Frame check sequence).

/// CRC-32 residue produced when the algorithm runs over `data || FCS(data)`.
///
/// If `crc32(frame_including_fcs) == CRC32_RESIDUE`, the FCS is present and valid.
/// [IEEE 802.3-2022] Annex G; verified empirically in unit tests below.
pub const CRC32_RESIDUE: u32 = 0x2144_DF1C;

/// Minimum frame size for FCS verification: the 4-byte FCS itself. A frame
/// shorter than this cannot contain an FCS.
const MIN_FCS_LEN: usize = 4;

/// Returns `true` if the trailing 4 bytes of `frame` are a valid IEEE 802.11 FCS.
///
/// Computes CRC-32 over the entire slice (payload + trailing FCS bytes). If the
/// result equals the magic residue `0x2144_DF1C`, the FCS is present and correct.
/// False positive rate: 1 in 2^32 per call.
#[must_use]
pub fn verify_crc32(frame: &[u8]) -> bool {
    frame.len() >= MIN_FCS_LEN && crc32fast::hash(frame) == CRC32_RESIDUE
}

/// Outcome of the FCS decision matrix (header signal vs CRC-32 signal vs BADFCS flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FcsOutcome {
    /// Header said FCS, CRC-32 confirmed. Strip last 4 bytes.
    HeaderAndCrcAgree,
    /// Header said no FCS, CRC-32 confirmed FCS present. Strip last 4 bytes.
    CrcDetected,
    /// Header said FCS, CRC-32 does not confirm, BADFCS flag set. The radio
    /// received this frame with a failed checksum on the air. Strip anyway.
    BadFcsFlagged,
    /// Header said FCS, CRC-32 does not confirm, no BADFCS flag. Unexpected
    /// corruption (during capture/processing, not on the air). Strip anyway.
    CrcMismatchNoFlag,
    /// Neither header nor CRC-32 indicates FCS. No strip.
    Neither,
}

impl FcsOutcome {
    /// Whether the trailing 4 bytes should be stripped from the frame.
    #[must_use]
    pub const fn should_strip(self) -> bool {
        matches!(self, Self::HeaderAndCrcAgree | Self::CrcDetected | Self::BadFcsFlagged | Self::CrcMismatchNoFlag)
    }
}

/// Resolves FCS presence from the header's flag, CRC-32 self-check, and BADFCS flag.
///
/// `header_says_fcs` is the link-layer header's FCS indicator (e.g. radiotap
/// Flags bit 4). `badfcs_flagged` is the radiotap BADFCS indicator (Flags bit 6).
/// `frame` is the 802.11 payload INCLUDING any trailing FCS bytes.
#[must_use]
pub fn resolve(frame: &[u8], header_says_fcs: bool, badfcs_flagged: bool) -> FcsOutcome {
    let crc_says_fcs = verify_crc32(frame);
    match (header_says_fcs, crc_says_fcs) {
        (true, true) => FcsOutcome::HeaderAndCrcAgree,
        (false, true) => FcsOutcome::CrcDetected,
        (true, false) if badfcs_flagged => FcsOutcome::BadFcsFlagged,
        (true, false) => FcsOutcome::CrcMismatchNoFlag,
        (false, false) => FcsOutcome::Neither,
    }
}

/// Strips the trailing 4-byte FCS from `frame` if `outcome` says to.
/// Returns the frame unchanged if no strip is needed.
#[must_use]
pub fn strip_fcs(frame: &[u8], outcome: FcsOutcome) -> &[u8] {
    if outcome.should_strip() { frame.get(..frame.len().saturating_sub(MIN_FCS_LEN)).unwrap_or(frame) } else { frame }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test assertions")]
mod tests {
    use super::*;

    // --- CRC-32 residue verification (gates all other work) ---

    #[test]
    fn crc32_residue_verified_from_first_principles() {
        // Build a known message, compute its CRC-32, append as LE bytes,
        // then verify that CRC-32 of the whole thing equals the residue.
        let message = b"Hello, 802.11!";
        let crc = crc32fast::hash(message);
        let mut frame_with_fcs = message.to_vec();
        frame_with_fcs.extend_from_slice(&crc.to_le_bytes());
        assert_eq!(
            crc32fast::hash(&frame_with_fcs),
            CRC32_RESIDUE,
            "CRC-32 residue constant 0x{CRC32_RESIDUE:08X} is wrong -- \
             got 0x{:08X} for message {:?}",
            crc32fast::hash(&frame_with_fcs),
            message,
        );
    }

    #[test]
    fn crc32_residue_verified_empty_payload() {
        // Edge case: zero-length payload. CRC-32("") = 0x0000_0000.
        let crc = crc32fast::hash(b"");
        let frame_with_fcs = crc.to_le_bytes();
        assert_eq!(crc32fast::hash(&frame_with_fcs), CRC32_RESIDUE);
    }

    #[test]
    fn crc32_residue_verified_all_zeros() {
        let message = [0u8; 64];
        let crc = crc32fast::hash(&message);
        let mut frame = message.to_vec();
        frame.extend_from_slice(&crc.to_le_bytes());
        assert_eq!(crc32fast::hash(&frame), CRC32_RESIDUE);
    }

    #[test]
    fn crc32_residue_verified_all_ff() {
        let message = [0xFFu8; 64];
        let crc = crc32fast::hash(&message);
        let mut frame = message.to_vec();
        frame.extend_from_slice(&crc.to_le_bytes());
        assert_eq!(crc32fast::hash(&frame), CRC32_RESIDUE);
    }

    #[test]
    fn crc32_residue_verified_minimal_beacon_frame() {
        // Minimal 802.11 Beacon: FC(2) + Duration(2) + DA(6) + SA(6) + BSSID(6)
        // + SeqCtrl(2) + Timestamp(8) + Interval(2) + Capability(2) = 36 bytes.
        let mut beacon = vec![0u8; 36];
        beacon[0] = 0x80; // FC: Beacon (type=0, subtype=8).
        beacon[1] = 0x00;
        // DA = broadcast.
        beacon[4..10].copy_from_slice(&[0xFF; 6]);
        let crc = crc32fast::hash(&beacon);
        let mut frame = beacon;
        frame.extend_from_slice(&crc.to_le_bytes());
        assert_eq!(crc32fast::hash(&frame), CRC32_RESIDUE);
    }

    // --- verify_crc32 ---

    #[test]
    fn verify_crc32_valid_fcs() {
        let msg = b"test frame body";
        let crc = crc32fast::hash(msg);
        let mut frame = msg.to_vec();
        frame.extend_from_slice(&crc.to_le_bytes());
        assert!(verify_crc32(&frame));
    }

    #[test]
    fn verify_crc32_invalid_fcs() {
        let mut frame = b"test frame body".to_vec();
        frame.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(!verify_crc32(&frame));
    }

    #[test]
    fn verify_crc32_too_short() {
        assert!(!verify_crc32(&[0u8; 3]));
        assert!(!verify_crc32(&[]));
    }

    #[test]
    fn verify_crc32_exactly_4_bytes() {
        // 0-byte payload + 4-byte FCS.
        let crc = crc32fast::hash(b"");
        let frame = crc.to_le_bytes();
        assert!(verify_crc32(&frame));
    }

    // --- resolve() ---

    #[test]
    fn resolve_both_agree_fcs_present() {
        let msg = b"frame";
        let crc = crc32fast::hash(msg);
        let mut frame = msg.to_vec();
        frame.extend_from_slice(&crc.to_le_bytes());
        assert_eq!(resolve(&frame, true, false), FcsOutcome::HeaderAndCrcAgree);
    }

    #[test]
    fn resolve_both_agree_no_fcs() {
        let frame = b"frame without fcs";
        assert_eq!(resolve(frame, false, false), FcsOutcome::Neither);
    }

    #[test]
    fn resolve_header_yes_crc_no_badfcs_flagged() {
        let frame = b"frame with bad trail\xDE\xAD\xBE\xEF";
        assert_eq!(resolve(frame, true, true), FcsOutcome::BadFcsFlagged);
    }

    #[test]
    fn resolve_header_yes_crc_no_no_badfcs() {
        let frame = b"frame with bad trail\xDE\xAD\xBE\xEF";
        assert_eq!(resolve(frame, true, false), FcsOutcome::CrcMismatchNoFlag);
    }

    #[test]
    fn resolve_header_no_crc_yes() {
        let msg = b"frame";
        let crc = crc32fast::hash(msg);
        let mut frame = msg.to_vec();
        frame.extend_from_slice(&crc.to_le_bytes());
        assert_eq!(resolve(&frame, false, false), FcsOutcome::CrcDetected);
    }

    // --- strip_fcs ---

    #[test]
    fn strip_fcs_removes_4_bytes_when_should_strip() {
        let frame = b"payload\x00\x00\x00\x00";
        let stripped = strip_fcs(frame, FcsOutcome::HeaderAndCrcAgree);
        assert_eq!(stripped, b"payload");
    }

    #[test]
    fn strip_fcs_preserves_when_neither() {
        let frame = b"payload_no_fcs";
        let stripped = strip_fcs(frame, FcsOutcome::Neither);
        assert_eq!(stripped, frame.as_slice());
    }

    #[test]
    fn strip_fcs_crc_detected_strips() {
        let frame = b"payload\x00\x00\x00\x00";
        let stripped = strip_fcs(frame, FcsOutcome::CrcDetected);
        assert_eq!(stripped, b"payload");
    }
}
