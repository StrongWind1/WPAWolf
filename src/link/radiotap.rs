//! Phase 2 -- Decode: radiotap radio header (DLT 127). See ARCHITECTURE.md §3.2 + §8.2.
//!
//! All fields are little-endian. The fixed 8-byte header contains `it_version` (must be 0),
//! a pad byte, `it_len` (u16 LE, total header length including the 8-byte fixed part), and
//! `it_present` (u32 LE, bitmap of present fields). The IEEE 802.11 payload begins at byte
//! offset `it_len`. FCS presence is detected via the Flags field when bit 1 of `it_present`
//! is set. Per the radiotap.org specification.

use crate::types::{Error, Result};

// Radiotap header field offsets (all little-endian per radiotap.org spec).
/// Offset of `it_version` (u8): must be 0.
const OFFSET_VERSION: usize = 0;
/// Offset of `it_len` (u16 LE): total header length in bytes.
const OFFSET_LEN: usize = 2;
/// Minimum valid `it_len`: the fixed 8-byte header itself.
const MIN_HEADER_LEN: usize = 8;

/// Returns the byte offset of the IEEE 802.11 frame within a radiotap-encapsulated packet.
///
/// Validates `it_version == 0` and `it_len >= 8`. The 802.11 frame starts at
/// byte `it_len`. Per the radiotap.org specification.
///
/// # Errors
///
/// - `Error::Truncated` -- `data` is too short to contain the fixed 8-byte header.
/// - `Error::UnknownFormat` -- `it_version != 0` or `it_len < 8`.
pub fn ieee80211_offset(data: &[u8]) -> Result<usize> {
    // Read it_version -- must be 0.
    let version = data.get(OFFSET_VERSION).ok_or(Error::Truncated {
        context: "radiotap header",
        needed: MIN_HEADER_LEN,
        got: data.len(),
    })?;
    if *version != 0 {
        return Err(Error::UnknownFormat(format!("radiotap it_version {version} != 0")));
    }

    // Read it_len (u16 LE at offset 2) -- total header length including the 8 fixed bytes.
    // [radiotap.org] it_len field is u16, little-endian.
    let len_bytes: [u8; 2] = data
        .get(OFFSET_LEN..OFFSET_LEN + 2)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Truncated { context: "radiotap it_len", needed: OFFSET_LEN + 2, got: data.len() })?;
    let it_len = u16::from_le_bytes(len_bytes) as usize; // [radiotap.org] it_len is u16 LE

    if it_len < MIN_HEADER_LEN {
        return Err(Error::UnknownFormat(format!("radiotap it_len {it_len} < minimum {MIN_HEADER_LEN}")));
    }

    // The 802.11 frame starts immediately after the radiotap header. Tail-side
    // FCS detection lives in `has_fcs` (the caller calls both) so this function
    // stays focused on the head-side offset.
    Ok(it_len)
}

/// Returns `true` if the radiotap header announces a 4-byte FCS appended to
/// the 802.11 frame body. The caller should chop the last 4 bytes from the
/// payload before handing it to higher layers.
///
/// FCS presence is encoded in the Flags field (bit 4, mask `0x10`,
/// `IEEE80211_RADIOTAP_F_FCS`). The Flags field is itself optional --
/// `it_present` bit 1 tells us whether the variable-fields region contains a
/// 1-byte Flags entry. When either signal is absent we conservatively return
/// `false` (no tail-strip), matching the pre-FCS-aware behaviour. Per
/// radiotap.org §3 (Defined Fields, "Flags").
#[must_use]
pub fn has_fcs(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    // it_version at byte 0 must be 0.
    if data.first().copied() != Some(0) {
        return false;
    }
    let Some(len_bytes) = data.get(2..4).and_then(|s| <[u8; 2]>::try_from(s).ok()) else {
        return false;
    };
    let it_len = u16::from_le_bytes(len_bytes) as usize;
    if it_len < 8 || it_len > data.len() {
        return false;
    }
    // First it_present word.
    let Some(pw_bytes) = data.get(4..8).and_then(|s| <[u8; 4]>::try_from(s).ok()) else {
        return false;
    };
    let first_pw = u32::from_le_bytes(pw_bytes);
    // Flags is bit 1 of it_present -- absent means no FCS signal.
    if first_pw & (1 << 1) == 0 {
        return false;
    }
    // Walk past all chained present words (bit 31 = extended present follows).
    let mut pos = 4usize;
    loop {
        let Some(pw_bytes) = data.get(pos..pos + 4).and_then(|s| <[u8; 4]>::try_from(s).ok()) else {
            return false;
        };
        let pw = u32::from_le_bytes(pw_bytes);
        pos += 4;
        if pw & (1 << 31) == 0 {
            break;
        }
        if pos + 4 > it_len {
            return false;
        }
    }
    // pos now indexes the first variable-length field.
    // Bit 0: TSFT (u64, 8-byte aligned from byte 0). Skip if present.
    if first_pw & (1 << 0) != 0 {
        let pad = (8 - (pos % 8)) % 8;
        pos += pad + 8;
    }
    // Bit 1: Flags (u8, no alignment) -- this is what we want.
    if pos >= it_len {
        return false;
    }
    let Some(&flags) = data.get(pos) else {
        return false;
    };
    // Bit 4 of Flags = `IEEE80211_RADIOTAP_F_FCS` (radiotap.org).
    (flags & 0x10) != 0
}

/// Returns true when the radiotap header advertises the A-MPDU Status field
/// (`it_present` bit 20).
///
/// Per the radiotap.org spec, A-MPDU Status is an 8-byte field (Reference
/// Number u32 LE + Flags u16 LE + Delimiter CRC u8 + Reserved u8) that flags
/// the encapsulated MPDU as a member of an aggregate. Its presence does **not**
/// imply that the radiotap payload contains a raw delimiter stream -- the
/// overwhelming majority of capture stacks (mac80211 / iwlwifi / brcmfmac)
/// re-split A-MPDUs into individual MPDUs before delivering them to libpcap,
/// so each radiotap-prefixed packet still holds exactly one 802.11 frame. We
/// surface presence as a Phase 2 stat (`stats.ampdu_status_frames`) for
/// visibility; raw delimiter walking is intentionally not implemented because
/// no real-world capture has demonstrated it (see `ARCHITECTURE.md §3.3`
/// transport-vector inventory, item 6).
#[must_use]
pub fn has_ampdu_status(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    if data.first().copied() != Some(0) {
        return false;
    }
    let Some(len_bytes) = data.get(2..4).and_then(|s| <[u8; 2]>::try_from(s).ok()) else {
        return false;
    };
    let it_len = u16::from_le_bytes(len_bytes) as usize;
    if it_len < 8 || it_len > data.len() {
        return false;
    }
    let Some(pw_bytes) = data.get(4..8).and_then(|s| <[u8; 4]>::try_from(s).ok()) else {
        return false;
    };
    let first_pw = u32::from_le_bytes(pw_bytes);
    // A-MPDU Status sits at it_present bit 20 [radiotap.org].
    first_pw & (1 << 20) != 0
}

/// Extracts the channel frequency (MHz) from the radiotap Channel field (`it_present` bit 3).
///
/// Walks the present-word chain and skips preceding fields (TSFT, Flags, Rate) with
/// correct natural alignment relative to byte 0 of the header. Returns `None` when the
/// Channel field is absent, the header is too short, or `it_version != 0`.
/// Per the radiotap.org specification; Channel field is 4 bytes: u16 freq + u16 flags.
#[must_use]
pub fn channel_freq(data: &[u8]) -> Option<u16> {
    if data.len() < 8 {
        return None;
    }
    // it_version at byte 0 must be 0. [radiotap.org]
    if data.first().copied()? != 0 {
        return None;
    }
    // it_len (u16 LE at bytes 2-3): total header length. [radiotap.org]
    let it_len = u16::from_le_bytes(data.get(2..4)?.try_into().ok()?) as usize;
    if it_len < 8 || it_len > data.len() {
        return None;
    }
    // First it_present word (u32 LE at bytes 4-7). [radiotap.org]
    let first_pw = u32::from_le_bytes(data.get(4..8)?.try_into().ok()?);
    // Channel field is bit 3 of it_present. Bail if absent.
    if first_pw & (1 << 3) == 0 {
        return None;
    }
    // Walk past all present words (bit 31 = extended present follows).
    // Each present word is u32 at the next 4-byte-aligned offset from byte 0.
    let mut pos = 4usize; // offset of first present word
    loop {
        let pw = u32::from_le_bytes(data.get(pos..pos + 4)?.try_into().ok()?);
        pos += 4;
        if pw & (1 << 31) == 0 {
            break; // last present word
        }
        if pos + 4 > it_len {
            return None;
        }
    }
    // pos now points to the first variable-length field.
    // Skip fields that precede Channel (bit 3), applying natural alignment from byte 0.

    // Bit 0: TSFT (u64), 8-byte aligned from byte 0.
    if first_pw & (1 << 0) != 0 {
        let pad = (8 - (pos % 8)) % 8;
        pos += pad + 8;
    }
    // Bit 1: Flags (u8), no alignment required.
    if first_pw & (1 << 1) != 0 {
        pos += 1;
    }
    // Bit 2: Rate (u8), no alignment required.
    if first_pw & (1 << 2) != 0 {
        pos += 1;
    }
    // Bit 3: Channel (u16 freq + u16 flags), 2-byte aligned from byte 0.
    pos += pos % 2; // align to 2
    if pos + 2 > it_len {
        return None;
    }
    let freq = u16::from_le_bytes(data.get(pos..pos + 2)?.try_into().ok()?);
    Some(freq)
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

    /// Build a minimal valid radiotap header with the given `it_len`.
    ///
    /// Bytes beyond the fixed 8 are zeroed (stand-ins for optional fields).
    fn make_header(version: u8, it_len: u16) -> Vec<u8> {
        let total = (it_len as usize).max(8);
        let mut buf = vec![0u8; total];
        buf[0] = version; // it_version
        buf[1] = 0; // it_pad (ignored)
        let len_bytes = it_len.to_le_bytes();
        buf[2] = len_bytes[0]; // it_len low
        buf[3] = len_bytes[1]; // it_len high
        // it_present (u32 LE at offset 4) -- zero means no optional fields present
        buf
    }

    #[test]
    fn version_zero_accepted() {
        let buf = make_header(0, 8);
        assert_eq!(ieee80211_offset(&buf).unwrap(), 8);
    }

    #[test]
    fn version_nonzero_rejected() {
        let buf = make_header(1, 8);
        let err = ieee80211_offset(&buf).unwrap_err();
        assert!(matches!(err, Error::UnknownFormat(_)));
        assert!(err.to_string().contains("it_version 1 != 0"));
    }

    #[test]
    fn it_len_too_small() {
        // Craft a buffer where it_len field says 4 (below minimum of 8).
        let mut buf = make_header(0, 8);
        let small: u16 = 4;
        let b = small.to_le_bytes();
        buf[2] = b[0];
        buf[3] = b[1];
        let err = ieee80211_offset(&buf).unwrap_err();
        assert!(matches!(err, Error::UnknownFormat(_)));
        assert!(err.to_string().contains("< minimum 8"));
    }

    #[test]
    fn it_len_32() {
        let buf = make_header(0, 32);
        assert_eq!(ieee80211_offset(&buf).unwrap(), 32);
    }

    #[test]
    fn truncated_data() {
        // 3-byte buffer -- too short to reach even it_version reliably, and definitely
        // too short to read it_len at offset 2..4.
        let buf = [0u8, 0, 0];
        let err = ieee80211_offset(&buf).unwrap_err();
        assert!(matches!(err, Error::Truncated { .. }));
    }

    #[test]
    fn empty_data() {
        let buf: [u8; 0] = [];
        let err = ieee80211_offset(&buf).unwrap_err();
        assert!(matches!(err, Error::Truncated { .. }));
    }

    // --- channel_freq tests ---
    //
    // Radiotap field layout (all LE):
    //   byte 0: version; byte 1: pad; bytes 2-3: it_len; bytes 4-7: it_present
    //   fields follow from byte 8, aligned from byte 0:
    //     bit 0 = TSFT (u64, 8-byte aligned)
    //     bit 1 = Flags (u8, no align)
    //     bit 2 = Rate (u8, no align)
    //     bit 3 = Channel (u16 freq + u16 flags, 2-byte aligned)

    /// Build a radiotap header with only the Channel field (`it_present` bit 3).
    ///
    /// Layout: 8 fixed bytes + 4 channel bytes (freq u16 LE + flags u16 LE).
    fn make_channel_only_header(freq: u16) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0] = 0; // it_version
        // it_len = 12 (LE)
        buf[2] = 12;
        buf[3] = 0;
        // it_present = bit 3 (Channel)
        buf[4] = 0x08;
        // Channel freq at offset 8 (2-byte aligned from byte 0, 8%2==0 -> no pad)
        let f = freq.to_le_bytes();
        buf[8] = f[0];
        buf[9] = f[1];
        buf
    }

    #[test]
    fn channel_freq_ch6_2437mhz() {
        // 2437 MHz = 802.11g channel 6 (2.4 GHz)
        let buf = make_channel_only_header(2437);
        assert_eq!(channel_freq(&buf), Some(2437));
    }

    #[test]
    fn channel_freq_ch36_5180mhz() {
        // 5180 MHz = 802.11a channel 36 (5 GHz)
        let buf = make_channel_only_header(5180);
        assert_eq!(channel_freq(&buf), Some(5180));
    }

    #[test]
    fn channel_freq_no_channel_field() {
        // it_present = 0 (no fields) -> None
        let buf = make_header(0, 8);
        assert_eq!(channel_freq(&buf), None);
    }

    #[test]
    fn channel_freq_version_nonzero() {
        // version != 0 -> None (invalid radiotap header)
        let buf = make_channel_only_header(2437);
        let mut bad = buf;
        bad[0] = 1;
        assert_eq!(channel_freq(&bad), None);
    }

    #[test]
    fn channel_freq_too_short() {
        // Buffer < 8 bytes -> None
        assert_eq!(channel_freq(&[0u8; 7]), None);
    }

    #[test]
    fn channel_freq_with_tsft_before_channel() {
        // it_present = bits 0 + 3 (TSFT + Channel).
        // TSFT occupies bytes 8-15 (8-byte aligned from byte 0, pos=8 -> no pad).
        // Channel freq at bytes 16-17 (2-byte aligned, 16%2==0 -> no pad).
        // it_len = 8 fixed + 8 TSFT + 4 Channel = 20
        let freq: u16 = 5180;
        let mut buf = vec![0u8; 20];
        buf[0] = 0; // version
        let it_len: u16 = 20;
        buf[2..4].copy_from_slice(&it_len.to_le_bytes());
        let it_present: u32 = (1 << 0) | (1 << 3); // TSFT + Channel
        buf[4..8].copy_from_slice(&it_present.to_le_bytes());
        // bytes 8-15: TSFT (zeroed)
        // Channel freq at bytes 16-17
        buf[16..18].copy_from_slice(&freq.to_le_bytes());
        assert_eq!(channel_freq(&buf), Some(freq));
    }

    #[test]
    fn channel_freq_with_flags_rate_before_channel() {
        // it_present = bits 1 + 2 + 3 (Flags + Rate + Channel).
        // Flags at byte 8 (u8, no align), Rate at byte 9, Channel at bytes 10-11
        // (2-byte aligned: 10%2==0 -> no pad). it_len = 8 + 1 + 1 + 4 = 14
        let freq: u16 = 2412; // channel 1
        let mut buf = vec![0u8; 14];
        buf[0] = 0;
        let it_len: u16 = 14;
        buf[2..4].copy_from_slice(&it_len.to_le_bytes());
        let it_present: u32 = (1 << 1) | (1 << 2) | (1 << 3); // Flags + Rate + Channel
        buf[4..8].copy_from_slice(&it_present.to_le_bytes());
        // buf[8] = Flags = 0x00, buf[9] = Rate = 0x00
        buf[10..12].copy_from_slice(&freq.to_le_bytes());
        assert_eq!(channel_freq(&buf), Some(freq));
    }

    #[test]
    fn channel_freq_with_all_preceding_fields() {
        // it_present = bits 0+1+2+3 (TSFT + Flags + Rate + Channel).
        // TSFT: pos=8 (8-aligned, no pad) -> pos=16
        // Flags: pos=16 -> pos=17
        // Rate: pos=17 -> pos=18
        // Channel: 18%2==0 -> no pad, freq at 18-19. it_len=22
        let freq: u16 = 5745; // 5 GHz channel 149
        let mut buf = vec![0u8; 22];
        buf[0] = 0;
        buf[2..4].copy_from_slice(&22u16.to_le_bytes());
        let it_present: u32 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3);
        buf[4..8].copy_from_slice(&it_present.to_le_bytes());
        // bytes 8-15: TSFT, buf[16]: Flags, buf[17]: Rate
        buf[18..20].copy_from_slice(&freq.to_le_bytes());
        assert_eq!(channel_freq(&buf), Some(freq));
    }

    // --- has_fcs tests ---

    /// Build a radiotap header with only the Flags field set in `it_present`.
    /// Layout: 8 fixed bytes + 1 Flags byte (no alignment) + 3 padding to give
    /// `it_len` = 12 (the spec only requires `it_len` >= header size, padding
    /// is fine).
    fn make_flags_only_header(flags_byte: u8) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0] = 0; // it_version
        buf[2] = 12; // it_len LE
        buf[3] = 0;
        buf[4] = 0x02; // it_present bit 1 = Flags
        buf[8] = flags_byte;
        buf
    }

    #[test]
    fn has_fcs_flag_set() {
        // Flags byte = 0x10 -> FCS present bit set.
        let buf = make_flags_only_header(0x10);
        assert!(has_fcs(&buf));
    }

    #[test]
    fn has_fcs_flag_clear() {
        // Flags byte = 0x00 -> no FCS bit.
        let buf = make_flags_only_header(0x00);
        assert!(!has_fcs(&buf));
    }

    #[test]
    fn has_fcs_other_flag_bits_ignored() {
        // Flags byte = 0xEF (every bit except 0x10) -> still false.
        let buf = make_flags_only_header(0xEF);
        assert!(!has_fcs(&buf));
    }

    #[test]
    fn has_fcs_flags_field_absent() {
        // it_present bit 1 not set -> Flags field absent -> false.
        let buf = make_header(0, 8); // it_present = 0
        assert!(!has_fcs(&buf));
    }

    #[test]
    fn has_fcs_with_tsft_preceding_flags() {
        // it_present = bits 0 + 1 (TSFT + Flags).
        // TSFT at bytes 8-15 (8-byte aligned, pos=8 -> no pad).
        // Flags at byte 16 (no alignment). it_len = 17.
        let mut buf = vec![0u8; 17];
        buf[0] = 0;
        buf[2..4].copy_from_slice(&17u16.to_le_bytes());
        let it_present: u32 = (1 << 0) | (1 << 1);
        buf[4..8].copy_from_slice(&it_present.to_le_bytes());
        // TSFT bytes 8-15 stay zeroed.
        buf[16] = 0x10; // FCS bit
        assert!(has_fcs(&buf));
    }

    #[test]
    fn has_fcs_truncated_buffer() {
        // Buffer claims it_len=12 but is only 10 bytes -- has_fcs returns false.
        let mut buf = [0u8; 10];
        buf[0] = 0;
        buf[2] = 12;
        buf[3] = 0;
        buf[4] = 0x02;
        assert!(!has_fcs(&buf));
    }

    #[test]
    fn has_fcs_version_nonzero() {
        let mut buf = make_flags_only_header(0x10);
        buf[0] = 1;
        assert!(!has_fcs(&buf));
    }

    #[test]
    fn has_fcs_chained_present_words() {
        // it_present has bit 31 set in the first word -> a second present word
        // follows. The first word's bit 1 (Flags) determines that the Flags
        // field is in the variable region. it_len = 8 fixed + 4 second present
        // word + 1 Flags byte = 13.
        let mut buf = vec![0u8; 13];
        buf[0] = 0;
        buf[2..4].copy_from_slice(&13u16.to_le_bytes());
        let first_pw: u32 = (1 << 1) | (1 << 31); // Flags + extended
        buf[4..8].copy_from_slice(&first_pw.to_le_bytes());
        let second_pw: u32 = 0; // no further extension
        buf[8..12].copy_from_slice(&second_pw.to_le_bytes());
        buf[12] = 0x10; // Flags = FCS present
        assert!(has_fcs(&buf));
    }

    // --- has_ampdu_status tests ---

    #[test]
    fn has_ampdu_status_bit_set() {
        // it_present has bit 20 (A-MPDU Status) set; we don't need any other
        // bits because the helper only inspects the first present word.
        let mut buf = make_header(0, 8);
        let it_present: u32 = 1 << 20;
        buf[4..8].copy_from_slice(&it_present.to_le_bytes());
        assert!(has_ampdu_status(&buf));
    }

    #[test]
    fn has_ampdu_status_bit_clear() {
        // No bits set in it_present -> field absent.
        let buf = make_header(0, 8);
        assert!(!has_ampdu_status(&buf));
    }

    #[test]
    fn has_ampdu_status_other_bits_only() {
        // TSFT + Flags + Channel set; A-MPDU Status (bit 20) is clear.
        let mut buf = make_header(0, 8);
        let it_present: u32 = (1 << 0) | (1 << 1) | (1 << 3);
        buf[4..8].copy_from_slice(&it_present.to_le_bytes());
        assert!(!has_ampdu_status(&buf));
    }

    #[test]
    fn has_ampdu_status_version_nonzero() {
        // Reject mis-versioned headers regardless of bit 20.
        let mut buf = make_header(0, 8);
        let it_present: u32 = 1 << 20;
        buf[4..8].copy_from_slice(&it_present.to_le_bytes());
        buf[0] = 1;
        assert!(!has_ampdu_status(&buf));
    }

    #[test]
    fn has_ampdu_status_too_short() {
        assert!(!has_ampdu_status(&[0u8; 7]));
        assert!(!has_ampdu_status(&[]));
    }
}
