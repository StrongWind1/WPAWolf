//! Linux cooked capture (SLL / SLL2) header parsing.
//!
//! SLL is a meta-header prepended by libpcap when capturing on the Linux `any`
//! pseudo-device. The `sll_hatype` field carries the kernel's ARPHRD value, which
//! determines the inner payload format. Only three ARPHRD values carry 802.11:
//!
//! - `ARPHRD_IEEE80211` (801) -- raw 802.11 frames
//! - `ARPHRD_IEEE80211_PRISM` (802) -- Prism header + 802.11
//! - `ARPHRD_IEEE80211_RADIOTAP` (803) -- radiotap header + 802.11
//!
//! All other ARPHRD values (Ethernet, loopback, tunnel, etc.) are non-Wi-Fi and
//! produce `Err(UnknownFormat)`.
//!
//! Struct layouts from `libpcap/pcap/sll.h`; ARPHRD constants from `linux/if_arp.h`.

use crate::types::{Error, Result};

use super::{prism, radiotap};

// --- SLL header sizes ---

/// Total header length for SLL v1 (DLT 113). [`libpcap` `sll.h`: `SLL_HDR_LEN`]
const SLL_HDR_LEN: usize = 16;

/// Total header length for SLL v2 (DLT 276). [`libpcap` `sll.h`: `SLL2_HDR_LEN`]
const SLL2_HDR_LEN: usize = 20;

// --- ARPHRD constants (linux/if_arp.h) ---

/// Raw IEEE 802.11 frames, no radio header. [`linux/if_arp.h`: `ARPHRD_IEEE80211`]
const ARPHRD_IEEE80211: u16 = 801;

/// IEEE 802.11 + Prism2 monitor header. [`linux/if_arp.h`: `ARPHRD_IEEE80211_PRISM`]
const ARPHRD_IEEE80211_PRISM: u16 = 802;

/// IEEE 802.11 + radiotap header. [`linux/if_arp.h`: `ARPHRD_IEEE80211_RADIOTAP`]
const ARPHRD_IEEE80211_RADIOTAP: u16 = 803;

// --- SLL v1 field offsets (all fields big-endian per sll.h) ---
// sll_pkttype:  offset 0, u16
// sll_hatype:   offset 2, u16   <- ARPHRD
// sll_halen:    offset 4, u16
// sll_addr:     offset 6, [u8; 8]
// sll_protocol: offset 14, u16

// --- SLL v2 field offsets (all multi-byte fields big-endian per sll.h) ---
// sll2_protocol:     offset 0, u16
// sll2_reserved_mbz: offset 2, u16
// sll2_if_index:     offset 4, u32
// sll2_hatype:       offset 8, u16   <- ARPHRD
// sll2_pkttype:      offset 10, u8
// sll2_halen:        offset 11, u8
// sll2_addr:         offset 12, [u8; 8]

/// Reads `sll_hatype` from an SLL v1 header (offset 2, u16 BE).
fn read_hatype_v1(data: &[u8]) -> Option<u16> {
    let b: [u8; 2] = data.get(2..4)?.try_into().ok()?;
    Some(u16::from_be_bytes(b))
}

/// Reads `sll2_hatype` from an SLL v2 header (offset 8, u16 BE).
fn read_hatype_v2(data: &[u8]) -> Option<u16> {
    let b: [u8; 2] = data.get(8..10)?.try_into().ok()?;
    Some(u16::from_be_bytes(b))
}

/// Strips the SLL v1 header and any inner radio header, returning
/// `(offset_to_80211, had_fcs)`.
///
/// Reads `sll_hatype` (offset 2, u16 BE) to determine the inner payload format,
/// then delegates to the appropriate radio-header parser for the 802.11 offset.
///
/// # Errors
///
/// Returns `Err(Truncated)` if the data is shorter than the 16-byte SLL header.
/// Returns `Err(UnknownFormat)` if the ARPHRD value is not 802.11.
pub fn strip(data: &[u8]) -> Result<(usize, bool)> {
    let hatype =
        read_hatype_v1(data).ok_or(Error::Truncated { context: "SLL header", needed: SLL_HDR_LEN, got: data.len() })?;
    dispatch_arphrd(data, SLL_HDR_LEN, hatype)
}

/// Strips the SLL v2 header and any inner radio header, returning
/// `(offset_to_80211, had_fcs)`.
///
/// Reads `sll2_hatype` (offset 8, u16 BE) to determine the inner payload format.
///
/// # Errors
///
/// Returns `Err(Truncated)` if the data is shorter than the 20-byte SLL2 header.
/// Returns `Err(UnknownFormat)` if the ARPHRD value is not 802.11.
pub fn strip_v2(data: &[u8]) -> Result<(usize, bool)> {
    let hatype = read_hatype_v2(data).ok_or(Error::Truncated {
        context: "SLL2 header",
        needed: SLL2_HDR_LEN,
        got: data.len(),
    })?;
    dispatch_arphrd(data, SLL2_HDR_LEN, hatype)
}

/// Shared ARPHRD dispatch for both SLL v1 and v2.
fn dispatch_arphrd(data: &[u8], base: usize, hatype: u16) -> Result<(usize, bool)> {
    let inner =
        data.get(base..).ok_or(Error::Truncated { context: "SLL inner payload", needed: base, got: data.len() })?;
    match hatype {
        // Raw 802.11: inner payload is the 802.11 frame directly.
        ARPHRD_IEEE80211 => Ok((base, false)),
        // Prism header wrapping 802.11. Also covers AVS-within-Prism via the
        // magic-detection path in prism::ieee80211_offset().
        ARPHRD_IEEE80211_PRISM => {
            let inner_offset = prism::ieee80211_offset(inner)?;
            Ok((base + inner_offset, false))
        },
        // Radiotap header wrapping 802.11, with per-frame FCS detection.
        ARPHRD_IEEE80211_RADIOTAP => {
            let inner_offset = radiotap::ieee80211_offset(inner)?;
            let fcs = radiotap::has_fcs(inner);
            Ok((base + inner_offset, fcs))
        },
        _ => Err(Error::UnknownFormat(format!("SLL ARPHRD {hatype} is not 802.11"))),
    }
}

/// Extracts the radiotap channel frequency from an SLL v1 packet, if the inner
/// payload is radiotap (ARPHRD 803). Returns `None` for all other ARPHRD values.
#[must_use]
pub fn channel_freq(data: &[u8]) -> Option<u16> {
    let hatype = read_hatype_v1(data)?;
    if hatype == ARPHRD_IEEE80211_RADIOTAP { radiotap::channel_freq(data.get(SLL_HDR_LEN..)?) } else { None }
}

/// Extracts the radiotap channel frequency from an SLL v2 packet, if the inner
/// payload is radiotap (ARPHRD 803). Returns `None` for all other ARPHRD values.
#[must_use]
pub fn channel_freq_v2(data: &[u8]) -> Option<u16> {
    let hatype = read_hatype_v2(data)?;
    if hatype == ARPHRD_IEEE80211_RADIOTAP { radiotap::channel_freq(data.get(SLL2_HDR_LEN..)?) } else { None }
}

/// Returns true when the inner radiotap header of an SLL v1 packet has A-MPDU
/// Status (`it_present` bit 20). Always false for non-radiotap ARPHRD.
#[must_use]
pub fn has_ampdu_status(data: &[u8]) -> bool {
    read_hatype_v1(data).is_some_and(|h| {
        h == ARPHRD_IEEE80211_RADIOTAP && data.get(SLL_HDR_LEN..).is_some_and(radiotap::has_ampdu_status)
    })
}

/// Returns true when the inner radiotap header of an SLL v2 packet has A-MPDU
/// Status (`it_present` bit 20). Always false for non-radiotap ARPHRD.
#[must_use]
pub fn has_ampdu_status_v2(data: &[u8]) -> bool {
    read_hatype_v2(data).is_some_and(|h| {
        h == ARPHRD_IEEE80211_RADIOTAP && data.get(SLL2_HDR_LEN..).is_some_and(radiotap::has_ampdu_status)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test assertions")]
mod tests {
    use super::*;

    const PROBE: &[u8] = b"\x80\x00probe-payload";

    fn make_sll_v1(arphrd: u16, inner: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SLL_HDR_LEN + inner.len());
        buf.extend_from_slice(&0u16.to_be_bytes()); // sll_pkttype = HOST.
        buf.extend_from_slice(&arphrd.to_be_bytes()); // sll_hatype.
        buf.extend_from_slice(&6u16.to_be_bytes()); // sll_halen.
        buf.extend_from_slice(&[0u8; 8]); // sll_addr.
        buf.extend_from_slice(&0u16.to_be_bytes()); // sll_protocol.
        buf.extend_from_slice(inner);
        buf
    }

    fn make_sll_v2(arphrd: u16, inner: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SLL2_HDR_LEN + inner.len());
        buf.extend_from_slice(&0u16.to_be_bytes()); // sll2_protocol.
        buf.extend_from_slice(&0u16.to_be_bytes()); // sll2_reserved_mbz.
        buf.extend_from_slice(&1u32.to_be_bytes()); // sll2_if_index = 1.
        buf.extend_from_slice(&arphrd.to_be_bytes()); // sll2_hatype.
        buf.push(0); // sll2_pkttype = HOST.
        buf.push(6); // sll2_halen.
        buf.extend_from_slice(&[0u8; 8]); // sll2_addr.
        buf.extend_from_slice(inner);
        buf
    }

    fn minimal_radiotap(frame: &[u8], with_fcs: bool) -> Vec<u8> {
        let header_len: u16 = 9;
        let mut out = Vec::with_capacity(header_len as usize + frame.len() + 4);
        out.push(0); // it_version.
        out.push(0); // it_pad.
        out.extend_from_slice(&header_len.to_le_bytes());
        out.extend_from_slice(&0x0000_0002u32.to_le_bytes()); // Flags present.
        out.push(if with_fcs { 0x10 } else { 0x00 }); // Flags byte.
        out.extend_from_slice(frame);
        if with_fcs {
            out.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        }
        out
    }

    fn minimal_prism(frame: &[u8]) -> Vec<u8> {
        let header_len: u32 = 144;
        let mut out = Vec::with_capacity(header_len as usize + frame.len());
        out.extend_from_slice(&0x4144_4d40u32.to_le_bytes()); // msgcode.
        out.extend_from_slice(&header_len.to_le_bytes());
        out.resize(header_len as usize, 0);
        out.extend_from_slice(frame);
        out
    }

    // --- SLL v1 tests ---

    #[test]
    fn sll_v1_arphrd_raw_802_11() {
        let pkt = make_sll_v1(ARPHRD_IEEE80211, PROBE);
        let (offset, fcs) = strip(&pkt).unwrap();
        assert_eq!(offset, SLL_HDR_LEN);
        assert!(!fcs);
        assert_eq!(&pkt[offset..], PROBE);
    }

    #[test]
    fn sll_v1_arphrd_radiotap_no_fcs() {
        let rt = minimal_radiotap(PROBE, false);
        let pkt = make_sll_v1(ARPHRD_IEEE80211_RADIOTAP, &rt);
        let (offset, fcs) = strip(&pkt).unwrap();
        assert_eq!(offset, SLL_HDR_LEN + 9); // 16 + 9-byte radiotap.
        assert!(!fcs);
        assert_eq!(&pkt[offset..], PROBE);
    }

    #[test]
    fn sll_v1_arphrd_radiotap_with_fcs() {
        let rt = minimal_radiotap(PROBE, true);
        let pkt = make_sll_v1(ARPHRD_IEEE80211_RADIOTAP, &rt);
        let (offset, fcs) = strip(&pkt).unwrap();
        assert_eq!(offset, SLL_HDR_LEN + 9);
        assert!(fcs);
    }

    #[test]
    fn sll_v1_arphrd_prism() {
        let pr = minimal_prism(PROBE);
        let pkt = make_sll_v1(ARPHRD_IEEE80211_PRISM, &pr);
        let (offset, fcs) = strip(&pkt).unwrap();
        assert_eq!(offset, SLL_HDR_LEN + 144); // 16 + 144-byte Prism.
        assert!(!fcs);
        assert_eq!(&pkt[offset..], PROBE);
    }

    #[test]
    fn sll_v1_arphrd_ethernet_rejected() {
        let pkt = make_sll_v1(1, PROBE); // ARPHRD_ETHER.
        let err = strip(&pkt).unwrap_err();
        assert!(err.to_string().contains("ARPHRD 1"));
    }

    #[test]
    fn sll_v1_arphrd_loopback_rejected() {
        let pkt = make_sll_v1(772, PROBE); // ARPHRD_LOOPBACK.
        let err = strip(&pkt).unwrap_err();
        assert!(err.to_string().contains("ARPHRD 772"));
    }

    #[test]
    fn sll_v1_truncated_header() {
        let err = strip(&[0u8; 3]).unwrap_err();
        assert!(err.to_string().contains("SLL header"));
    }

    // --- SLL v2 tests ---

    #[test]
    fn sll_v2_arphrd_raw_802_11() {
        let pkt = make_sll_v2(ARPHRD_IEEE80211, PROBE);
        let (offset, fcs) = strip_v2(&pkt).unwrap();
        assert_eq!(offset, SLL2_HDR_LEN);
        assert!(!fcs);
        assert_eq!(&pkt[offset..], PROBE);
    }

    #[test]
    fn sll_v2_arphrd_radiotap_no_fcs() {
        let rt = minimal_radiotap(PROBE, false);
        let pkt = make_sll_v2(ARPHRD_IEEE80211_RADIOTAP, &rt);
        let (offset, fcs) = strip_v2(&pkt).unwrap();
        assert_eq!(offset, SLL2_HDR_LEN + 9); // 20 + 9-byte radiotap.
        assert!(!fcs);
        assert_eq!(&pkt[offset..], PROBE);
    }

    #[test]
    fn sll_v2_arphrd_radiotap_with_fcs() {
        let rt = minimal_radiotap(PROBE, true);
        let pkt = make_sll_v2(ARPHRD_IEEE80211_RADIOTAP, &rt);
        let (offset, fcs) = strip_v2(&pkt).unwrap();
        assert_eq!(offset, SLL2_HDR_LEN + 9);
        assert!(fcs);
    }

    #[test]
    fn sll_v2_arphrd_prism() {
        let pr = minimal_prism(PROBE);
        let pkt = make_sll_v2(ARPHRD_IEEE80211_PRISM, &pr);
        let (offset, fcs) = strip_v2(&pkt).unwrap();
        assert_eq!(offset, SLL2_HDR_LEN + 144);
        assert!(!fcs);
        assert_eq!(&pkt[offset..], PROBE);
    }

    #[test]
    fn sll_v2_arphrd_ethernet_rejected() {
        let pkt = make_sll_v2(1, PROBE);
        let err = strip_v2(&pkt).unwrap_err();
        assert!(err.to_string().contains("ARPHRD 1"));
    }

    #[test]
    fn sll_v2_truncated_header() {
        let err = strip_v2(&[0u8; 9]).unwrap_err();
        assert!(err.to_string().contains("SLL2 header"));
    }

    // --- channel_freq / has_ampdu_status helpers ---

    #[test]
    fn channel_freq_radiotap_inner_returns_none_without_channel_field() {
        let rt = minimal_radiotap(PROBE, false); // No Channel field in it_present.
        let pkt = make_sll_v1(ARPHRD_IEEE80211_RADIOTAP, &rt);
        assert_eq!(channel_freq(&pkt), None);
    }

    #[test]
    fn channel_freq_raw_inner_returns_none() {
        let pkt = make_sll_v1(ARPHRD_IEEE80211, PROBE);
        assert_eq!(channel_freq(&pkt), None);
    }

    #[test]
    fn channel_freq_v2_raw_inner_returns_none() {
        let pkt = make_sll_v2(ARPHRD_IEEE80211, PROBE);
        assert_eq!(channel_freq_v2(&pkt), None);
    }

    #[test]
    fn ampdu_status_raw_inner_returns_false() {
        let pkt = make_sll_v1(ARPHRD_IEEE80211, PROBE);
        assert!(!has_ampdu_status(&pkt));
    }

    #[test]
    fn ampdu_status_v2_raw_inner_returns_false() {
        let pkt = make_sll_v2(ARPHRD_IEEE80211, PROBE);
        assert!(!has_ampdu_status_v2(&pkt));
    }

    #[test]
    fn ampdu_status_truncated_returns_false() {
        assert!(!has_ampdu_status(&[0u8; 3]));
        assert!(!has_ampdu_status_v2(&[0u8; 3]));
    }
}
