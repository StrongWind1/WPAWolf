//! Link-layer header wrappers.
//!
//! Each constant matches what `wpawolf::link::*` parses; mirrored from
//! `src/link/{radiotap,ppi,prism,avs}.rs`. The wrappers in this module take a
//! raw 802.11 frame and produce the byte stream that lands on the wire after
//! the link-layer header is prepended.

/// Data-link types per `tcpdump.org` / IANA.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LinkType {
    /// `DLT_IEEE802_11` -- raw 802.11 with no header (105).
    Raw = 105,
    /// `DLT_PRISM_HEADER` -- Prism monitor header (119).
    Prism = 119,
    /// `DLT_IEEE802_11_RADIO` -- radiotap (127).
    Radiotap = 127,
    /// `DLT_IEEE802_11_AVS` -- AVS / WLAN-NG header (163). Big-endian per
    /// spec; hcxtools interprets it little-endian (documented bug).
    Avs = 163,
    /// `DLT_PPI` -- Per-Packet Information (192).
    Ppi = 192,
}

impl LinkType {
    /// Returns the DLT integer used by pcap/pcapng linktype fields.
    #[must_use]
    pub const fn dlt(self) -> u32 {
        self as u32
    }
}

/// Wrap a raw 802.11 frame in a minimal radiotap header.
///
/// `with_fcs = true` sets the radiotap Flags bit `0x10` and appends a fake
/// 4-byte FCS so wpawolf's FCS-strip path (`src/link/radiotap.rs::has_fcs`)
/// is exercised. Header layout: `it_version (1) | it_pad (1) | it_len (2) |
/// it_present (4) | <fields>`. With Flags bit (`it_present` bit 1) set, the
/// header is 9 bytes total.
#[must_use]
pub fn radiotap(frame: &[u8], with_fcs: bool) -> Vec<u8> {
    const HEADER_LEN: u16 = 9;
    let mut out = Vec::with_capacity(HEADER_LEN as usize + frame.len() + 4);
    out.push(0); // it_version.
    out.push(0); // it_pad.
    out.extend_from_slice(&HEADER_LEN.to_le_bytes());
    out.extend_from_slice(&0x0000_0002u32.to_le_bytes()); // Flags present.
    out.push(if with_fcs { 0x10 } else { 0x00 }); // Flags byte.
    out.extend_from_slice(frame);
    if with_fcs {
        out.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    }
    out
}

/// Wrap a raw 802.11 frame in a 144-byte Prism monitor header.
///
/// `[Prism]` headers are entirely synthetic for the fixture: only `msglen`
/// (offset 4, LE u32) is consulted by `wpawolf::link::prism`.
#[must_use]
pub fn prism(frame: &[u8]) -> Vec<u8> {
    const HEADER_LEN: u32 = 144;
    let mut out = Vec::with_capacity(HEADER_LEN as usize + frame.len());
    out.extend_from_slice(&0x4144_4d40u32.to_le_bytes()); // msgcode (arbitrary).
    out.extend_from_slice(&HEADER_LEN.to_le_bytes());
    out.resize(HEADER_LEN as usize, 0);
    out.extend_from_slice(frame);
    out
}

/// Wrap a raw 802.11 frame in a 64-byte AVS header.
///
/// `[AVS]` is big-endian on the wire (`wpawolf::link::avs`). Version (BE u32)
/// upper 20 bits = `0x80211`; `len` field (BE u32 at offset 4) is the total
/// header length.
#[must_use]
pub fn avs(frame: &[u8]) -> Vec<u8> {
    const HEADER_LEN: u32 = 64;
    let mut out = Vec::with_capacity(HEADER_LEN as usize + frame.len());
    out.extend_from_slice(&0x8021_1001u32.to_be_bytes()); // version.
    out.extend_from_slice(&HEADER_LEN.to_be_bytes()); // len.
    out.resize(HEADER_LEN as usize, 0);
    out.extend_from_slice(frame);
    out
}

/// Build an AVS-formatted payload that exercises wpawolf's
/// "AVS-within-Prism" delegation path.
///
/// `src/link/prism.rs::ieee80211_offset` reads the first 4 bytes of any
/// DLT 119 (Prism) packet as a BE u32 -- if its upper 20 bits equal
/// `0x80211`, the packet is forwarded to the AVS parser starting at byte 0.
/// In other words, the bytes on the wire ARE the AVS frame; the only thing
/// that distinguishes this path from a normal AVS packet is that the pcap
/// IDB advertises link-type 119 instead of 163. This helper exists so
/// callers can pair the pcap DLT (Prism) with the right payload bytes (AVS).
#[must_use]
pub fn prism_wrapping_avs(frame: &[u8]) -> Vec<u8> {
    avs(frame)
}

/// Wrap a raw 802.11 frame in an 8-byte PPI header.
///
/// `pph_dlt` is fixed at 105 (`DLT_IEEE802_11`) -- PPI itself does not carry
/// 802.11-radio metadata for fixture purposes.
#[must_use]
pub fn ppi(frame: &[u8]) -> Vec<u8> {
    const HEADER_LEN: u16 = 8;
    let mut out = Vec::with_capacity(HEADER_LEN as usize + frame.len());
    out.push(0); // pph_version.
    out.push(0); // pph_flags.
    out.extend_from_slice(&HEADER_LEN.to_le_bytes());
    out.extend_from_slice(&105u32.to_le_bytes()); // pph_dlt.
    out.extend_from_slice(frame);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROBE: &[u8] = b"\x80\x00probe-payload";

    #[test]
    fn radiotap_no_fcs_round_trip() {
        let wrapped = radiotap(PROBE, false);
        // 9-byte header.
        assert_eq!(&wrapped[..2], &[0u8, 0u8]);
        assert_eq!(u16::from_le_bytes([wrapped[2], wrapped[3]]), 9);
        assert!(&wrapped[9..].starts_with(PROBE));
    }

    #[test]
    fn radiotap_with_fcs_appends_four_bytes() {
        let wrapped = radiotap(PROBE, true);
        assert_eq!(&wrapped[wrapped.len() - 4..], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn prism_header_length() {
        let wrapped = prism(PROBE);
        assert_eq!(wrapped.len(), 144 + PROBE.len());
        assert!(wrapped.ends_with(PROBE));
    }

    #[test]
    fn avs_header_length_and_be_version() {
        let wrapped = avs(PROBE);
        assert_eq!(wrapped.len(), 64 + PROBE.len());
        // Version BE: upper 20 bits = 0x80211.
        let v = u32::from_be_bytes([wrapped[0], wrapped[1], wrapped[2], wrapped[3]]);
        assert_eq!(v >> 12, 0x8_0211);
    }

    #[test]
    fn ppi_header_length_and_dlt() {
        let wrapped = ppi(PROBE);
        assert_eq!(wrapped.len(), 8 + PROBE.len());
        let dlt = u32::from_le_bytes([wrapped[4], wrapped[5], wrapped[6], wrapped[7]]);
        assert_eq!(dlt, 105);
    }

    #[test]
    fn prism_wrapping_avs_emits_avs_bytes() {
        let wrapped = prism_wrapping_avs(PROBE);
        // The bytes are AVS-shaped: BE u32 version with upper 20 bits = 0x80211
        // and the AVS_MASK match makes wpawolf delegate.
        let outer = u32::from_be_bytes([wrapped[0], wrapped[1], wrapped[2], wrapped[3]]);
        assert_eq!(outer & 0xFFFF_F000, 0x8021_1000);
        // Total length matches the bare AVS variant.
        assert_eq!(wrapped.len(), 64 + PROBE.len());
    }

    #[test]
    fn linktype_dlt_values() {
        assert_eq!(LinkType::Raw.dlt(), 105);
        assert_eq!(LinkType::Prism.dlt(), 119);
        assert_eq!(LinkType::Radiotap.dlt(), 127);
        assert_eq!(LinkType::Avs.dlt(), 163);
        assert_eq!(LinkType::Ppi.dlt(), 192);
    }
}
