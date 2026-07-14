//! Phase 2 -- Decode: AVS / WLAN-NG radio header (DLT 163, embedded within DLT 119). See ARCHITECTURE.md §3.2 + §8.2.
//!
//! All fields are big-endian per the AVS specification. The upper 20 bits of the
//! `version` field (u32 BE) must equal `0x80211`. The `len` field (u32 BE) gives the
//! total header length; the IEEE 802.11 payload begins at offset `len`. Note: hcxtools
//! treats AVS fields as little-endian -- this is a documented bug. wpawolf uses big-endian
//! as specified. Per libpcap `gencode.c:3479`.

use crate::types::{Error, Result};

/// Minimum valid AVS header length in bytes. [libpcap gencode.c:3479]
const MIN_AVS_LEN: u32 = 64;

/// Mask to extract the upper 20 bits of the AVS version field.
/// [libpcap gencode.c:3479] `version & 0xFFFFF000 == 0x80211000`
const AVS_VERSION_MASK: u32 = 0xFFFF_F000;

/// Expected value of the upper 20 bits of the AVS version field.
/// [libpcap gencode.c:3479]
const AVS_VERSION_EXPECTED: u32 = 0x8021_1000;

/// Returns the byte offset of the IEEE 802.11 frame within an AVS-encapsulated packet.
///
/// All fields are big-endian per the AVS specification. Validates the `version` field's
/// upper 20 bits and the minimum header length. Used for both DLT 163 (direct AVS) and
/// AVS-within-Prism (DLT 119) frames.
///
/// # Errors
///
/// - `Error::Truncated` if `data` is too short to read the 8-byte fixed header.
/// - `Error::UnknownFormat` if the version field's upper 20 bits are not `0x80211`,
///   or if the `len` field is below the minimum valid AVS header size.
pub fn ieee80211_offset(data: &[u8]) -> Result<usize> {
    // version: u32 BE at offset 0. [libpcap gencode.c:3479]
    let ver_bytes: [u8; 4] = data.get(0..4).and_then(|s| s.try_into().ok()).ok_or(Error::Truncated {
        context: "AVS header version",
        needed: 8,
        got: data.len(),
    })?;
    let version = u32::from_be_bytes(ver_bytes); // BE per AVS spec

    if version & AVS_VERSION_MASK != AVS_VERSION_EXPECTED {
        return Err(Error::UnknownFormat(format!("AVS version field {version:#010x}: upper 20 bits not 0x80211")));
    }

    // len: u32 BE at offset 4. [libpcap gencode.c:3479]
    let len_bytes: [u8; 4] = data.get(4..8).and_then(|s| s.try_into().ok()).ok_or(Error::Truncated {
        context: "AVS header len",
        needed: 8,
        got: data.len(),
    })?;
    let avs_len = u32::from_be_bytes(len_bytes); // BE per AVS spec

    if avs_len < MIN_AVS_LEN {
        return Err(Error::UnknownFormat(format!("AVS len {avs_len} < minimum {MIN_AVS_LEN}")));
    }

    // avs_len is a u32 validated to be >= 64. On all platforms wpawolf targets
    // (64-bit), usize is at least 32 bits wide so this cast is lossless.
    Ok(avs_len as usize)
}

// --- Unit tests ---

#[cfg(test)]
mod tests {

    use super::*;

    /// Build a minimal 64-byte AVS buffer with the given raw version and len field bytes.
    fn make_avs(version_be: [u8; 4], len_be: [u8; 4], total_len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; total_len];
        buf[0..4].copy_from_slice(&version_be);
        buf[4..8].copy_from_slice(&len_be);
        buf
    }

    #[test]
    fn valid_avs_header() {
        // version = 0x80211000 (BE), len = 64 -> offset 64
        let buf = make_avs(0x8021_1000u32.to_be_bytes(), 64u32.to_be_bytes(), 128);
        assert_eq!(ieee80211_offset(&buf).unwrap(), 64);
    }

    #[test]
    fn valid_avs_large_len() {
        // version = 0x80211FFF -- upper 20 bits still 0x80211 (0x80211FFF >> 12 == 0x80211)
        let buf = make_avs(0x8021_1FFFu32.to_be_bytes(), 128u32.to_be_bytes(), 256);
        assert_eq!(ieee80211_offset(&buf).unwrap(), 128);
    }

    #[test]
    fn invalid_version() {
        let buf = make_avs(0xDEAD_BEEFu32.to_be_bytes(), 64u32.to_be_bytes(), 128);
        let err = ieee80211_offset(&buf).unwrap_err();
        assert!(matches!(err, Error::UnknownFormat(_)));
    }

    #[test]
    fn len_too_small() {
        // version valid, len = 32 (< 64) -> UnknownFormat
        let buf = make_avs(0x8021_1000u32.to_be_bytes(), 32u32.to_be_bytes(), 128);
        let err = ieee80211_offset(&buf).unwrap_err();
        assert!(matches!(err, Error::UnknownFormat(_)));
    }

    #[test]
    fn truncated_header() {
        // Only 6 bytes -- not enough to read both version and len fields.
        let buf = vec![0x80, 0x21, 0x10, 0x00, 0x00, 0x00];
        let err = ieee80211_offset(&buf).unwrap_err();
        assert!(matches!(err, Error::Truncated { .. }));
    }

    #[test]
    fn empty_data() {
        let err = ieee80211_offset(&[]).unwrap_err();
        assert!(matches!(err, Error::Truncated { .. }));
    }
}
