//! Phase 2 -- Decode: link-layer header dispatch by DLT. See ARCHITECTURE.md §3.2.
//!
//! Matches on the DLT (Data Link Type) value from the pcap/pcapng interface descriptor
//! and strips the appropriate radio/monitor-mode header to expose the raw IEEE 802.11
//! frame payload. Supported DLTs: 105 (raw 802.11), 113 (Linux SLL), 119 (Prism),
//! 127 (Radiotap), 163 (AVS), 192 (PPI), 276 (Linux SLL2). Unknown DLTs are logged
//! and the packet is skipped.

pub mod avs;
pub mod fcs;
pub mod ppi;
pub mod prism;
pub mod radiotap;
pub mod sll;

use crate::types::{Error, Result};

// DLT constants -- values from libpcap dlt.h and the pcapng spec.
/// Raw IEEE 802.11 frames, no radio header. [libpcap dlt.h: `DLT_IEEE802_11`]
pub const DLT_IEEE802_11: u16 = 105;
/// Prism monitor-mode header prepended to 802.11. [libpcap dlt.h: `DLT_PRISM_HEADER`]
pub const DLT_PRISM: u16 = 119;
/// Radiotap header prepended to 802.11. [libpcap dlt.h: `DLT_IEEE802_11_RADIO`]
pub const DLT_RADIOTAP: u16 = 127;
/// AVS/WLAN-NG radio header. [libpcap dlt.h: `DLT_IEEE802_11_RADIO_AVS`]
pub const DLT_AVS: u16 = 163;
/// Per-Packet Information header. [libpcap dlt.h: `DLT_PPI`]
pub const DLT_PPI: u16 = 192;
/// Linux cooked capture v1 (`any` device). [libpcap dlt.h: `DLT_LINUX_SLL`]
pub const DLT_LINUX_SLL: u16 = 113;
/// Linux cooked capture v2 (`any` device, with interface index). [libpcap dlt.h: `DLT_LINUX_SLL2`]
pub const DLT_LINUX_SLL2: u16 = 276;

/// Strips the link-layer header from `data` for the given `dlt` and returns
/// `(payload, header_says_fcs)`.
///
/// `payload` is the raw IEEE 802.11 frame bytes **including** any trailing FCS.
/// FCS tail-strip is NOT performed here -- the caller is responsible for running
/// `fcs::resolve()` to cross-check the header's FCS flag against CRC-32 and
/// then calling `fcs::strip_fcs()` on the result.
///
/// `header_says_fcs` is the link-layer header's FCS indicator: `true` when the
/// radiotap Flags field has bit 4 set, `false` for all other DLTs (which lack
/// a reliable per-frame FCS signal).
///
/// # Errors
///
/// Returns `Err(Error::Truncated {...})` if the header claims an offset beyond
/// the end of `data`. Returns `Err(Error::UnknownFormat(...))` for unsupported
/// DLTs.
pub fn strip(data: &[u8], dlt: u16) -> Result<(&[u8], bool)> {
    let (offset, header_says_fcs) = match dlt {
        // Raw 802.11: no header to strip, no FCS metadata.
        DLT_IEEE802_11 => (0usize, false),
        // Radiotap: variable-length header, length in bytes 2-3 (u16 LE). FCS
        // signaled by Flags bit 4 when it_present bit 1 is set.
        DLT_RADIOTAP => (radiotap::ieee80211_offset(data)?, radiotap::has_fcs(data)),
        // Prism: variable-length header with AVS-within-Prism detection. No
        // standard FCS indicator -- conservatively assume no FCS.
        DLT_PRISM => (prism::ieee80211_offset(data)?, false),
        // AVS: big-endian header, length in bytes 4-7 (u32 BE). No FCS field.
        DLT_AVS => (avs::ieee80211_offset(data)?, false),
        // PPI: header length in bytes 2-3 (u16 LE), inner DLT must be 105.
        // PPI's 802.11-Common field has an FCS-error bit but no spec-clean
        // FCS-at-end signal we can rely on; skip tail-strip.
        DLT_PPI => (ppi::ieee80211_offset(data)?, false),
        // Linux cooked capture: meta-header wrapping another link-layer format.
        // ARPHRD dispatch determines the inner parser (raw/prism/radiotap).
        DLT_LINUX_SLL => sll::strip(data)?,
        DLT_LINUX_SLL2 => sll::strip_v2(data)?,

        other => {
            return Err(Error::UnknownFormat(format!("unsupported DLT {other}")));
        },
    };

    let payload = data.get(offset..).ok_or(Error::Truncated {
        context: "link-layer payload",
        needed: offset,
        got: data.len(),
    })?;

    Ok((payload, header_says_fcs))
}

/// Extracts the channel frequency (MHz) from the radio metadata in `data` for the given DLT.
///
/// Currently implemented for `DLT_RADIOTAP` (127) only, where the Channel field
/// (`it_present` bit 3) carries the frequency. Returns `None` for all other DLTs or when
/// the Channel field is absent from the radiotap header.
///
/// Band mapping: 2412-2484 MHz = 2.4 GHz; 5180-5825 MHz = 5 GHz; 5925-7125 MHz = 6 GHz.
#[must_use]
pub fn channel_freq(data: &[u8], dlt: u16) -> Option<u16> {
    match dlt {
        DLT_RADIOTAP => radiotap::channel_freq(data),
        DLT_LINUX_SLL => sll::channel_freq(data),
        DLT_LINUX_SLL2 => sll::channel_freq_v2(data),
        _ => None,
    }
}

/// Returns true when the radio header advertises the radiotap A-MPDU Status field
/// (`it_present` bit 20).
///
/// Only meaningful for `DLT_RADIOTAP` (127); always false for other DLTs because no
/// other supported radio header carries an A-MPDU indicator. Used to drive the
/// `stats.ampdu_status_frames` Phase 2 counter for visibility into raw-aggregation
/// captures. See `ARCHITECTURE.md §3.3` transport-vector inventory item 6.
#[must_use]
pub fn has_ampdu_status(data: &[u8], dlt: u16) -> bool {
    match dlt {
        DLT_RADIOTAP => radiotap::has_ampdu_status(data),
        DLT_LINUX_SLL => sll::has_ampdu_status(data),
        DLT_LINUX_SLL2 => sll::has_ampdu_status_v2(data),
        _ => false,
    }
}
