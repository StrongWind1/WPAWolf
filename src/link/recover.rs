//! Tiered frame recovery for corrupt link-layer headers.
//!
//! When `link::strip()` fails (unsupported DLT, corrupt radiotap header, etc.),
//! this module attempts to locate the 802.11 frame via progressively more
//! aggressive strategies:
//!
//! - **Tier 2**: Compute the radiotap header length from the `it_present` bitmask
//!   field sizes and alignment rules. Requires `it_present` to be valid.
//! - **Tier 3**: Scan candidate byte offsets using CRC-32 FCS validation. Works for
//!   any DLT, but only when the capture includes FCS (4-byte CRC-32 appended to the
//!   802.11 frame on the air).
//!
//! Tier 1 (relax `it_version`) is handled inside `radiotap::ieee80211_offset()`
//! directly and does not route through this module.

use super::fcs;

// --- Tier 2: radiotap offset from it_present ---

/// Radiotap field descriptor: (bit position, byte size, natural alignment).
/// [radiotap.org] defined fields table.
const RADIOTAP_FIELDS: &[(u32, usize, usize)] = &[
    (0, 8, 8),  // TSFT
    (1, 1, 1),  // Flags
    (2, 1, 1),  // Rate
    (3, 4, 2),  // Channel (u16 freq + u16 flags)
    (4, 2, 2),  // FHSS
    (5, 1, 1),  // Antenna Signal (dBm)
    (6, 1, 1),  // Antenna Noise (dBm)
    (7, 2, 2),  // Lock Quality
    (8, 2, 2),  // TX Attenuation
    (9, 2, 2),  // dB TX Attenuation
    (10, 1, 1), // dBm TX Power
    (11, 1, 1), // Antenna
    (12, 1, 1), // dB Antenna Signal
    (13, 1, 1), // dB Antenna Noise
    (14, 2, 2), // RX Flags
    // 15, 16: reserved (0 bytes)
    (17, 2, 2),  // TX Flags
    (18, 1, 1),  // RTS Retries
    (19, 1, 1),  // Data Retries
    (20, 8, 4),  // A-MPDU Status
    (21, 12, 2), // VHT
    (22, 12, 8), // Timestamp
    (23, 12, 2), // HE (802.11ax)
    (24, 12, 2), // HE-MU
    // 25: HE-MU-other-user (0 bytes, not defined)
    (26, 1, 1), // zero-length-PSDU
    (27, 4, 2), // L-SIG
                // 28: TLV -- BAIL OUT (variable)
                // 29: RadiotapNamespace -- 0 bytes, alignment reset
                // 30: VendorNamespace -- BAIL OUT (variable)
                // 31: Extended -- another it_present word follows
];

/// Computes the expected radiotap header length from the `it_present` bitmask.
///
/// Walks chained `it_present` words (bit 31 = extended), sums field sizes with
/// natural alignment padding per the radiotap.org spec. Returns `None` if:
/// - Data is too short to read `it_present` (< 8 bytes)
/// - Bit 28 (TLV) or bit 30 (`VendorNamespace`) is set (variable-length, unknowable)
/// - Computed offset exceeds `data_len`
#[must_use]
pub fn compute_offset_from_present(data: &[u8]) -> Option<usize> {
    if data.len() < 8 {
        return None;
    }

    let mut pos = 4usize; // first it_present word at offset 4
    let mut present_words: Vec<u32> = Vec::with_capacity(2);

    loop {
        let pw_bytes: [u8; 4] = data.get(pos..pos + 4)?.try_into().ok()?;
        let pw = u32::from_le_bytes(pw_bytes);

        // Bail out on variable-length fields we can't size.
        if pw & (1 << 28) != 0 || pw & (1 << 30) != 0 {
            return None;
        }

        present_words.push(pw);
        pos += 4;

        if pw & (1 << 31) == 0 {
            break;
        }
        if pos + 4 > data.len() {
            return None;
        }
    }

    // pos now points to the first variable-length field region.
    // Walk known fields from the FIRST present word only (chained words define
    // a second namespace starting over from bit 0 -- rare in practice, and the
    // field table only covers the primary namespace).
    let first_pw = present_words.first().copied()?;

    for &(bit, size, align) in RADIOTAP_FIELDS {
        if first_pw & (1 << bit) != 0 {
            // Natural alignment relative to byte 0 of the radiotap header.
            if align > 1 {
                let misalign = pos % align;
                if misalign != 0 {
                    pos += align - misalign;
                }
            }
            pos += size;
        }
    }

    if pos > data.len() {
        return None;
    }

    Some(pos)
}

// --- Tier 3: CRC-32 offset scan ---

/// Minimum candidate slice length for CRC-32 offset scan: 10-byte control frame
/// (FC + Duration + RA) plus 4-byte FCS = 14 bytes. Shorter slices produce
/// systematic false positives because `crc32([0x00]*4) == RESIDUE` (the
/// empty-message FCS) and `crc32([0xFF]*8) == RESIDUE` -- null/FF-padded
/// trailing bytes in short control frames trigger these.
const MIN_SCAN_SLICE: usize = 14;

/// Maximum link-layer header offset to scan. 144 = Prism header, the largest
/// known header format. Beyond this, no standard link-layer encapsulation exists.
const MAX_SCAN_OFFSET: usize = 144;

/// Scans every byte offset from 0 through `MAX_SCAN_OFFSET` using CRC-32 FCS
/// residue to find the 802.11 frame.
///
/// Returns `Some((offset, payload_without_fcs))` on the first CRC-32 match.
/// Ascending order ensures the smallest offset (most plausible header size) wins.
/// Returns `None` if no offset produces a valid CRC-32.
#[must_use]
pub fn crc32_offset_scan(data: &[u8]) -> Option<(usize, &[u8])> {
    let max_off = data.len().saturating_sub(MIN_SCAN_SLICE).min(MAX_SCAN_OFFSET);
    for offset in 0..=max_off {
        let candidate = data.get(offset..)?;
        if candidate.len() < MIN_SCAN_SLICE {
            break;
        }
        if fcs::verify_crc32(candidate) {
            let stripped = candidate.get(..candidate.len() - 4).unwrap_or(candidate);
            return Some((offset, stripped));
        }
    }
    None
}

/// Which recovery tier succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryTier {
    /// Tier 2: offset computed from `it_present` bitmask.
    ComputedFromPresent,
    /// Tier 3: CRC-32 scan found the frame at a candidate offset.
    Crc32Scan,
}

/// Result of a successful frame recovery attempt.
#[derive(Debug)]
pub struct RecoveryResult<'a> {
    /// The recovered 802.11 frame (FCS stripped if CRC-32 matched).
    pub frame: &'a [u8],
    /// Which tier produced the recovery.
    pub tier: RecoveryTier,
    /// The byte offset within the original packet data where the frame was found.
    pub offset: usize,
    /// Whether FCS was detected and stripped via CRC-32.
    pub fcs_stripped: bool,
}

/// Attempts to recover the 802.11 frame from a packet whose primary `link::strip()`
/// failed.
///
/// Tries Tier 2 (radiotap `it_present` computation) then Tier 3 (CRC-32 scan).
/// Tier 1 (version relaxation) is already handled inside `strip()` and doesn't
/// route here.
///
/// `data` is the raw packet bytes. `dlt` is the DLT from the interface descriptor.
/// For SLL/SLL2 with a corrupt inner radiotap, the caller should pass the inner
/// payload (after the SLL header) with `dlt = 127`.
#[must_use]
pub fn recover(data: &[u8], dlt: u16) -> Option<RecoveryResult<'_>> {
    // DLT 1 (Ethernet): wired traffic, no 802.11 content. Don't waste cycles.
    if dlt == 1 {
        return None;
    }

    // Tier 2: radiotap-specific -- compute offset from it_present.
    if dlt == super::DLT_RADIOTAP && data.len() >= 8 {
        if let Some(computed_offset) = compute_offset_from_present(data) {
            if let Some(payload) = data.get(computed_offset..) {
                if !payload.is_empty() {
                    let fcs_valid = fcs::verify_crc32(payload);
                    let frame = if fcs_valid {
                        payload.get(..payload.len().saturating_sub(4)).unwrap_or(payload)
                    } else {
                        payload
                    };
                    return Some(RecoveryResult {
                        frame,
                        tier: RecoveryTier::ComputedFromPresent,
                        offset: computed_offset,
                        fcs_stripped: fcs_valid,
                    });
                }
            }
        }
    }

    // Tier 3: CRC-32 offset scan -- works for any DLT.
    if let Some((offset, stripped_frame)) = crc32_offset_scan(data) {
        return Some(RecoveryResult {
            frame: stripped_frame,
            tier: RecoveryTier::Crc32Scan,
            offset,
            fcs_stripped: true,
        });
    }

    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test assertions")]
mod tests {
    use super::*;

    fn append_fcs(data: &[u8]) -> Vec<u8> {
        let crc = crc32fast::hash(data);
        let mut out = data.to_vec();
        out.extend_from_slice(&crc.to_le_bytes());
        out
    }

    fn make_radiotap_with_present(it_present: u32, field_data: &[u8]) -> Vec<u8> {
        let it_len = 8 + field_data.len();
        let mut buf = Vec::with_capacity(it_len);
        buf.push(0); // it_version
        buf.push(0); // pad
        #[allow(clippy::cast_possible_truncation, reason = "test data always < 256 bytes")]
        buf.extend_from_slice(&(it_len as u16).to_le_bytes());
        buf.extend_from_slice(&it_present.to_le_bytes());
        buf.extend_from_slice(field_data);
        buf
    }

    // --- Tier 2: compute_offset_from_present ---

    #[test]
    fn tier2_flags_only() {
        // it_present bit 1 (Flags, 1 byte, align 1). Offset = 8 + 1 = 9.
        let data = make_radiotap_with_present(1 << 1, &[0x00]);
        assert_eq!(compute_offset_from_present(&data), Some(9));
    }

    #[test]
    fn tier2_tsft_plus_flags() {
        // TSFT (8 bytes, align 8) + Flags (1 byte). After the present word at pos=8,
        // TSFT needs 8-align from byte 0: pos=8 is already 8-aligned. pos=8+8=16.
        // Flags at pos=16, size 1. Total = 17.
        let mut data = make_radiotap_with_present((1 << 0) | (1 << 1), &[0u8; 9]);
        data.truncate(17);
        assert_eq!(compute_offset_from_present(&data), Some(17));
    }

    #[test]
    fn tier2_channel_aligned() {
        // Flags(1) + Rate(1) + Channel(4, align 2). pos after present words = 8.
        // Flags: pos=8, size 1 -> pos=9. Rate: pos=9, size 1 -> pos=10.
        // Channel: align 2, 10%2=0 no pad, size 4 -> pos=14.
        let data = make_radiotap_with_present((1 << 1) | (1 << 2) | (1 << 3), &[0u8; 6]);
        assert_eq!(compute_offset_from_present(&data), Some(14));
    }

    #[test]
    fn tier2_bail_on_tlv() {
        // Bit 28 (TLV) set -> bail out.
        let data = make_radiotap_with_present(1 << 28, &[]);
        assert_eq!(compute_offset_from_present(&data), None);
    }

    #[test]
    fn tier2_bail_on_vendor() {
        // Bit 30 (VendorNamespace) set -> bail out.
        let data = make_radiotap_with_present(1 << 30, &[]);
        assert_eq!(compute_offset_from_present(&data), None);
    }

    #[test]
    fn tier2_too_short() {
        assert_eq!(compute_offset_from_present(&[0u8; 4]), None);
    }

    #[test]
    fn tier2_empty_present() {
        // it_present = 0 (no fields). Offset = 8 (just the fixed header).
        let data = make_radiotap_with_present(0, &[]);
        assert_eq!(compute_offset_from_present(&data), Some(8));
    }

    // --- Tier 3: crc32_offset_scan ---

    #[test]
    fn tier3_finds_frame_at_offset_0() {
        let frame = b"\x80\x00beacon-payload";
        let data = append_fcs(frame);
        let (offset, stripped) = crc32_offset_scan(&data).unwrap();
        assert_eq!(offset, 0);
        assert_eq!(stripped, frame);
    }

    #[test]
    fn tier3_finds_frame_at_offset_24() {
        let frame = b"\x80\x00beacon-payload";
        let frame_with_fcs = append_fcs(frame);
        let mut data = vec![0xAA; 24]; // 24 bytes of "header" garbage
        data.extend_from_slice(&frame_with_fcs);
        let (offset, stripped) = crc32_offset_scan(&data).unwrap();
        assert_eq!(offset, 24);
        assert_eq!(stripped, frame);
    }

    #[test]
    fn tier3_no_match_without_fcs() {
        let data = b"some random data without any valid fcs at any offset whatsoever";
        assert!(crc32_offset_scan(data).is_none());
    }

    #[test]
    fn tier3_too_short() {
        assert!(crc32_offset_scan(&[0u8; 3]).is_none());
    }

    // --- recover() ---

    #[test]
    fn recover_tier2_radiotap_corrupt_itlen() {
        // Build a packet with valid it_present (Flags only, bit 1) but corrupt it_len.
        // The real offset is 9 (8 fixed + 1 Flags byte).
        let frame = b"\x80\x00beacon";
        let mut pkt = Vec::new();
        pkt.push(0); // it_version
        pkt.push(0); // pad
        pkt.extend_from_slice(&2u16.to_le_bytes()); // CORRUPT it_len = 2 (< 8)
        pkt.extend_from_slice(&(1u32 << 1).to_le_bytes()); // it_present: Flags
        pkt.push(0x00); // Flags byte
        pkt.extend_from_slice(frame);

        let result = recover(&pkt, 127).unwrap();
        assert_eq!(result.tier, RecoveryTier::ComputedFromPresent);
        assert_eq!(result.offset, 9);
        assert_eq!(result.frame, frame);
    }

    #[test]
    fn recover_tier3_unknown_dlt() {
        // DLT 177 (LINUX_LAPD, mislabeled). Frame with valid FCS at offset 0.
        // Must be >= MIN_SCAN_SLICE (14) including FCS, so 10+ byte frame.
        let frame = b"\x80\x00beacon-pad";
        let data = append_fcs(frame);
        assert!(data.len() >= 14);
        let result = recover(&data, 177).unwrap();
        assert_eq!(result.tier, RecoveryTier::Crc32Scan);
        assert_eq!(result.offset, 0);
        assert_eq!(result.frame, frame);
        assert!(result.fcs_stripped);
    }

    #[test]
    fn recover_dlt1_ethernet_returns_none() {
        let data = b"some ethernet frame data with fcs maybe";
        assert!(recover(data, 1).is_none());
    }

    #[test]
    fn recover_empty_data() {
        assert!(recover(&[], 127).is_none());
    }
}
