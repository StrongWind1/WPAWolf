//! Phase 2 -- Decode: Prism monitor-mode radio header (DLT 119). See ARCHITECTURE.md §3.2 + §8.2.
//!
//! Host byte order (little-endian in practice). The header is nominally 144 bytes
//! (`msgcode` u32, `msglen` u32, `devname` 16 bytes, 10 x 12-byte `prism_item` structs)
//! but `msglen` is used as the actual payload offset. Includes AVS-within-Prism detection:
//! if the first 4 bytes read as a big-endian u32, masked with `0xFFFFF000`, equal
//! `0x80211000`, the frame is delegated to the AVS parser instead. Per hcxtools
//! `ieee80211.h:176-203` and libpcap `gencode.c:3441-3447`.

use crate::types::{Error, Result};

use super::avs;

/// Mask for AVS-within-Prism detection. [libpcap gencode.c:3441]
const AVS_MASK: u32 = 0xFFFF_F000;

/// Expected masked value indicating an AVS header embedded in a DLT 119 packet.
/// [libpcap gencode.c:3441]
const AVS_SIGNATURE: u32 = 0x8021_1000;

/// Byte offset of the `msglen` field within the Prism header. [hcxtools ieee80211.h:180]
const OFFSET_MSGLEN: usize = 4;

/// Minimum byte count needed to read `msgcode` + `msglen`. [hcxtools ieee80211.h:176-180]
const MIN_FOR_MSGLEN: usize = 8;

/// Returns the byte offset of the IEEE 802.11 frame within a Prism-encapsulated packet.
///
/// Performs AVS-within-Prism detection first: if the first 4 bytes read as a big-endian
/// u32 masked with `0xFFFFF000` equal `0x80211000`, the packet is delegated to
/// `avs::ieee80211_offset`. Otherwise the `msglen` field (u32 LE at offset 4) is used
/// as the payload offset. Per hcxtools `ieee80211.h:176-203` and libpcap
/// `gencode.c:3441-3447`.
///
/// # Errors
///
/// - `Error::Truncated` if `data` has fewer than 8 bytes (cannot read `msglen`).
/// - `Error::Truncated` if `msglen` exceeds `data.len()` (packet is incomplete).
/// - Propagates any error returned by `avs::ieee80211_offset` for AVS-within-Prism frames.
pub fn ieee80211_offset(data: &[u8]) -> Result<usize> {
    // AVS-within-Prism detection: read first 4 bytes as BE u32, check upper 20 bits.
    // [libpcap gencode.c:3441-3447]
    let first4: [u8; 4] = data.get(0..4).and_then(|s| s.try_into().ok()).ok_or(Error::Truncated {
        context: "Prism header",
        needed: MIN_FOR_MSGLEN,
        got: data.len(),
    })?;
    let be_word = u32::from_be_bytes(first4); // read as BE for AVS detection only

    if be_word & AVS_MASK == AVS_SIGNATURE {
        // This is an AVS header embedded in a DLT 119 packet.
        return avs::ieee80211_offset(data);
    }

    // Standard Prism header: use msglen (u32 LE at offset 4) as payload offset.
    // [hcxtools ieee80211.h:180] msglen is host byte order (LE in practice).
    let msglen_bytes: [u8; 4] = data
        .get(OFFSET_MSGLEN..OFFSET_MSGLEN + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Truncated { context: "Prism msglen", needed: OFFSET_MSGLEN + 4, got: data.len() })?;

    // msglen is u32; on all 64-bit platforms usize >= u32 so this cast is lossless.
    let msglen = u32::from_le_bytes(msglen_bytes) as usize; // LE per hcxtools ieee80211.h:180

    if msglen > data.len() {
        return Err(Error::Truncated { context: "Prism msglen exceeds packet", needed: msglen, got: data.len() });
    }

    Ok(msglen)
}

// --- Unit tests ---

#[cfg(test)]
mod tests {

    use super::*;

    /// Build a Prism buffer: first 4 bytes are `msgcode` (LE), next 4 are `msglen` (LE).
    /// The remaining bytes are zero-padded to `total_len`.
    fn make_prism(msgcode_le: [u8; 4], msglen: u32, total_len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; total_len];
        buf[0..4].copy_from_slice(&msgcode_le);
        buf[4..8].copy_from_slice(&msglen.to_le_bytes());
        buf
    }

    #[test]
    fn standard_prism_144() {
        // msgcode bytes read as BE must NOT hit the AVS signature.
        // Use [0x00, 0x00, 0x00, 0x44] -- BE u32 = 0x44, masked = 0 != AVS_SIGNATURE.
        let buf = make_prism([0x00, 0x00, 0x00, 0x44], 144, 200);
        assert_eq!(ieee80211_offset(&buf).unwrap(), 144);
    }

    #[test]
    fn avs_within_prism() {
        // Craft a buffer whose first 4 bytes, read as BE u32, equal the AVS signature
        // (0x80211000), AND whose bytes 4-7 read as BE u32 equal 64 (valid AVS len).
        // Total buffer must be at least 64 bytes for AVS len validation.
        //
        // bytes 0-3: 0x80 0x21 0x10 0x00  -> BE u32 = 0x80211000  (AVS version, upper 20 bits = 0x80211)
        // bytes 4-7: 0x00 0x00 0x00 0x40  -> BE u32 = 64          (AVS len)
        // bytes 8-63: zeros (padding)
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&[0x80, 0x21, 0x10, 0x00]);
        buf[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x40]);
        assert_eq!(ieee80211_offset(&buf).unwrap(), 64);
    }

    #[test]
    fn msglen_exceeds_data() {
        // msglen = 500 in a 200-byte packet -> Truncated
        let buf = make_prism([0x00, 0x00, 0x00, 0x01], 500, 200);
        let err = ieee80211_offset(&buf).unwrap_err();
        assert!(matches!(err, Error::Truncated { .. }));
    }

    #[test]
    fn truncated_too_short() {
        // 3-byte buffer -- cannot read the first 4 bytes
        let buf = vec![0x01, 0x02, 0x03];
        let err = ieee80211_offset(&buf).unwrap_err();
        assert!(matches!(err, Error::Truncated { .. }));
    }

    #[test]
    fn msglen_zero_accepted() {
        // msglen = 0: 802.11 frame begins at byte 0. Valid edge case.
        let buf = make_prism([0x00, 0x00, 0x00, 0x01], 0, 200);
        assert_eq!(ieee80211_offset(&buf).unwrap(), 0);
    }
}
