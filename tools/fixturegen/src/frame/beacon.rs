//! Beacon and Probe Response frame builders.
//!
//! `[IEEE 802.11-2024]` §9.3.3.3 (Beacon) / §9.3.3.10 (Probe Response): both
//! frames share the same fixed-field layout (Timestamp, Beacon Interval,
//! Capability Information) followed by an IE list. The fixture generator
//! emits the minimal required IE set: SSID, Supported Rates, DS Parameter,
//! plus the security suite (RSN IE for WPA2/3, vendor IE for WPA1).

use crate::frame::{ie, mac};

/// Build a Beacon frame body (header + fixed fields + IEs).
///
/// `bssid` doubles as both `addr2` (TA) and `addr3` (BSSID); broadcast goes
/// in `addr1`. Fixed fields are: Timestamp (8 B, zero), Beacon Interval
/// (2 B, 100 TU), Capability Information (2 B, ESS + Privacy = 0x0011).
#[must_use]
pub fn beacon(bssid: [u8; 6], ssid: &[u8], rsn: &[u8]) -> Vec<u8> {
    let mut frame =
        mac::header_3addr(mac::TYPE_MGMT, mac::SUBTYPE_BEACON, false, false, [0xFF; 6], bssid, bssid).to_vec();
    frame.extend_from_slice(&[0u8; 8]); // Timestamp.
    frame.extend_from_slice(&100u16.to_le_bytes()); // Beacon Interval (TU).
    frame.extend_from_slice(&0x0011u16.to_le_bytes()); // Capability: ESS | Privacy.
    frame.extend_from_slice(&ie::ssid(ssid));
    frame.extend_from_slice(&[ie::TAG_SUPP_RATES, 4, 0x82, 0x84, 0x8B, 0x96]);
    frame.extend_from_slice(&[ie::TAG_DS_PARAM, 1, 6]); // Channel 6.
    frame.extend_from_slice(rsn);
    frame
}

/// Build a Probe Response frame body. Identical layout to Beacon -- only the
/// subtype byte differs.
#[must_use]
pub fn probe_response(bssid: [u8; 6], sta: [u8; 6], ssid: &[u8], rsn: &[u8]) -> Vec<u8> {
    let mut frame =
        mac::header_3addr(mac::TYPE_MGMT, mac::SUBTYPE_PROBE_RESP, false, false, sta, bssid, bssid).to_vec();
    frame.extend_from_slice(&[0u8; 8]);
    frame.extend_from_slice(&100u16.to_le_bytes());
    frame.extend_from_slice(&0x0011u16.to_le_bytes());
    frame.extend_from_slice(&ie::ssid(ssid));
    frame.extend_from_slice(&[ie::TAG_SUPP_RATES, 4, 0x82, 0x84, 0x8B, 0x96]);
    frame.extend_from_slice(&[ie::TAG_DS_PARAM, 1, 6]);
    frame.extend_from_slice(rsn);
    frame
}
