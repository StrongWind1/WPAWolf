//! Association Request and Reassociation Request builders.
//!
//! `[IEEE 802.11-2024]` §9.3.3.6 / §9.3.3.8. Reassociation adds a 6-byte
//! `Current AP Address` field after the listen interval. Both frames carry
//! the RSN IE that is the canonical S3 / S4 PMKID source, plus -- for the FT
//! taxonomy -- the MDE (`tag 54`) and FTE (`tag 55`).

use crate::frame::{ie, mac};

/// Build an Association Request frame body.
///
/// The fixed fields are Capability (2 B) + Listen Interval (2 B). `extra_ies`
/// is appended verbatim after the SSID + RSN IE so callers can attach MDE +
/// FTE for FT-PSK fixtures or an OSEN vendor IE for the S20 fixture.
#[must_use]
pub fn assoc_request(bssid: [u8; 6], sta: [u8; 6], ssid: &[u8], rsn: &[u8], extra_ies: &[u8]) -> Vec<u8> {
    let mut frame = mac::header_3addr(mac::TYPE_MGMT, mac::SUBTYPE_ASSOC_REQ, false, false, bssid, sta, bssid).to_vec();
    frame.extend_from_slice(&0x0011u16.to_le_bytes()); // Capability: ESS | Privacy.
    frame.extend_from_slice(&100u16.to_le_bytes()); // Listen Interval.
    frame.extend_from_slice(&ie::ssid(ssid));
    frame.extend_from_slice(rsn);
    frame.extend_from_slice(extra_ies);
    frame
}

/// Build a Reassociation Request frame body.
#[must_use]
pub fn reassoc_request(
    bssid: [u8; 6],
    sta: [u8; 6],
    current_ap: [u8; 6],
    ssid: &[u8],
    rsn: &[u8],
    extra_ies: &[u8],
) -> Vec<u8> {
    let mut frame =
        mac::header_3addr(mac::TYPE_MGMT, mac::SUBTYPE_REASSOC_REQ, false, false, bssid, sta, bssid).to_vec();
    frame.extend_from_slice(&0x0011u16.to_le_bytes());
    frame.extend_from_slice(&100u16.to_le_bytes());
    frame.extend_from_slice(&current_ap);
    frame.extend_from_slice(&ie::ssid(ssid));
    frame.extend_from_slice(rsn);
    frame.extend_from_slice(extra_ies);
    frame
}
