//! Probe Request frame builder.
//!
//! `[IEEE 802.11-2024]` §9.3.3.9: a Probe Request carries no fixed fields,
//! just an IE list (SSID, Supported Rates, optional Extended Supported Rates,
//! optional RSN IE for the S14 / S15 PMKID extraction sites).

use crate::frame::{ie, mac};

/// Build a Probe Request frame body.
///
/// `dst` is `addr1`/`addr3` -- broadcast for an undirected probe, the AP
/// BSSID for a directed probe. The optional `rsn` argument carries the RSN
/// IE bytes (use [`crate::frame::ie::rsn_ie`]) for the directed-probe PMKID
/// fixtures.
#[must_use]
pub fn probe_request(dst: [u8; 6], sta: [u8; 6], ssid: &[u8], rsn: Option<&[u8]>) -> Vec<u8> {
    let mut frame = mac::header_3addr(mac::TYPE_MGMT, mac::SUBTYPE_PROBE_REQ, false, false, dst, sta, dst).to_vec();
    frame.extend_from_slice(&ie::ssid(ssid));
    frame.extend_from_slice(&[ie::TAG_SUPP_RATES, 4, 0x82, 0x84, 0x8B, 0x96]);
    if let Some(r) = rsn {
        frame.extend_from_slice(r);
    }
    frame
}

/// Build a broadcast Probe Request that still binds to a specific BSSID.
///
/// `[IEEE 802.11-2024]` §11.1.4.3: a STA may issue a Probe Request with
/// `addr1 = FF:FF:FF:FF:FF:FF` (wildcard receiver) but a non-wildcard
/// `addr3` (BSSID) when it knows the target AP -- this is the S15 wire
/// shape. wpawolf keys `akm_map` on `mac_hdr.ap` (= addr3 = BSSID), so
/// pinning addr3 to the real AP MAC lets the broadcast probe resolve its
/// AKM via the preceding Beacon and emit a PMKID hash line.
#[must_use]
pub fn probe_request_broadcast_to_ap(ap: [u8; 6], sta: [u8; 6], ssid: &[u8], rsn: Option<&[u8]>) -> Vec<u8> {
    let mut frame =
        mac::header_3addr(mac::TYPE_MGMT, mac::SUBTYPE_PROBE_REQ, false, false, [0xFF; 6], sta, ap).to_vec();
    frame.extend_from_slice(&ie::ssid(ssid));
    frame.extend_from_slice(&[ie::TAG_SUPP_RATES, 4, 0x82, 0x84, 0x8B, 0x96]);
    if let Some(r) = rsn {
        frame.extend_from_slice(r);
    }
    frame
}
