//! Phase 2 -- Decode: PPI (Per-Packet Information) radio header (DLT 192). See ARCHITECTURE.md §3.2 + §8.2.
//!
//! All fields are little-endian. The 8-byte fixed header contains `pph_version` (u8),
//! `pph_flags` (u8), `pph_len` (u16 LE, total header length), and `pph_dlt` (u32 LE,
//! inner DLT value). Only `pph_dlt == 105` (`DLT_IEEE802_11`) is processed; packets with
//! other inner DLTs are skipped. Per libpcap `dlt.h` and hcxtools `ieee80211.h:225-233`.

use crate::types::{Error, Result};

/// Minimum valid `pph_len`: the fixed 8-byte PPI header itself.
const MIN_HEADER_LEN: usize = 8;
/// Offset of `pph_len` (u16 LE): total header length.
const OFFSET_LEN: usize = 2; // [hcxtools ieee80211.h:228]
/// Offset of `pph_dlt` (u32 LE): inner link-layer type.
const OFFSET_DLT: usize = 4; // [hcxtools ieee80211.h:229]
/// Expected inner DLT -- raw IEEE 802.11 frames. [libpcap dlt.h: `DLT_IEEE802_11`]
const DLT_IEEE802_11: u32 = 105;

/// Returns the byte offset of the IEEE 802.11 frame within a PPI-encapsulated packet.
///
/// Validates that `pph_dlt == 105` (`DLT_IEEE802_11`). Packets with other inner DLTs
/// are skipped -- they carry a non-Wi-Fi link type within the PPI wrapper.
/// Per libpcap `dlt.h` and hcxtools `ieee80211.h:225-233`.
///
/// # Errors
///
/// - `Error::Truncated` -- `data` is shorter than the 8-byte fixed PPI header.
/// - `Error::UnknownFormat` -- `pph_dlt != 105` or `pph_len < 8`.
pub fn ieee80211_offset(data: &[u8]) -> Result<usize> {
    if data.len() < MIN_HEADER_LEN {
        return Err(Error::Truncated { context: "PPI header", needed: MIN_HEADER_LEN, got: data.len() });
    }

    // pph_len: u16 LE at offset 2. [hcxtools ieee80211.h:228]
    let len_bytes: [u8; 2] = data
        .get(OFFSET_LEN..OFFSET_LEN + 2)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Truncated { context: "PPI pph_len", needed: OFFSET_LEN + 2, got: data.len() })?;
    let pph_len = u16::from_le_bytes(len_bytes) as usize; // [hcxtools ieee80211.h:228] pph_len is u16 LE

    // pph_dlt: u32 LE at offset 4. [hcxtools ieee80211.h:229]
    let dlt_bytes: [u8; 4] = data
        .get(OFFSET_DLT..OFFSET_DLT + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Truncated { context: "PPI pph_dlt", needed: OFFSET_DLT + 4, got: data.len() })?;
    let pph_dlt = u32::from_le_bytes(dlt_bytes); // [hcxtools ieee80211.h:229] pph_dlt is u32 LE

    if pph_dlt != DLT_IEEE802_11 {
        return Err(Error::UnknownFormat(format!("PPI inner DLT {pph_dlt} is not DLT_IEEE802_11 (105)")));
    }

    if pph_len < MIN_HEADER_LEN {
        return Err(Error::UnknownFormat(format!("PPI pph_len {pph_len} < minimum {MIN_HEADER_LEN}")));
    }

    Ok(pph_len)
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

    /// Build a PPI header buffer with the given `pph_len` and `pph_dlt`.
    ///
    /// The buffer is sized to at least 8 bytes. `pph_version` and `pph_flags` are zero.
    fn make_ppi(pph_len: u16, pph_dlt: u32) -> Vec<u8> {
        let total = (pph_len as usize).max(8);
        let mut buf = vec![0u8; total];
        // pph_version at offset 0, pph_flags at offset 1 -- both zero
        let len_bytes = pph_len.to_le_bytes();
        buf[2] = len_bytes[0]; // pph_len low
        buf[3] = len_bytes[1]; // pph_len high
        let dlt_bytes = pph_dlt.to_le_bytes();
        buf[4] = dlt_bytes[0]; // pph_dlt byte 0
        buf[5] = dlt_bytes[1]; // pph_dlt byte 1
        buf[6] = dlt_bytes[2]; // pph_dlt byte 2
        buf[7] = dlt_bytes[3]; // pph_dlt byte 3
        buf
    }

    #[test]
    fn valid_ppi_dlt_ieee80211() {
        let buf = make_ppi(8, 105);
        assert_eq!(ieee80211_offset(&buf).unwrap(), 8);
    }

    #[test]
    fn valid_ppi_custom_len() {
        let buf = make_ppi(32, 105);
        assert_eq!(ieee80211_offset(&buf).unwrap(), 32);
    }

    #[test]
    fn wrong_dlt_rejected() {
        // DLT 1 = DLT_EN10MB (Ethernet) -- not Wi-Fi, must be rejected.
        let buf = make_ppi(8, 1);
        let err = ieee80211_offset(&buf).unwrap_err();
        assert!(matches!(err, Error::UnknownFormat(_)));
        assert!(err.to_string().contains("DLT_IEEE802_11 (105)"));
    }

    #[test]
    fn truncated_header() {
        // 5-byte buffer -- below the 8-byte minimum.
        let buf = [0u8; 5];
        let err = ieee80211_offset(&buf).unwrap_err();
        assert!(matches!(err, Error::Truncated { .. }));
    }

    #[test]
    fn pph_len_too_small() {
        // pph_len = 4, pph_dlt = 105: length check must fire after DLT check passes.
        // The buffer itself must be >= 8 bytes so we get past the initial length gate.
        let mut buf = make_ppi(8, 105);
        let small: u16 = 4;
        let b = small.to_le_bytes();
        buf[2] = b[0];
        buf[3] = b[1];
        let err = ieee80211_offset(&buf).unwrap_err();
        assert!(matches!(err, Error::UnknownFormat(_)));
        assert!(err.to_string().contains("< minimum 8"));
    }
}
