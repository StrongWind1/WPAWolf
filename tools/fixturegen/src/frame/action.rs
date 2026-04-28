//! Action frame builder.
//!
//! `[IEEE 802.11-2024]` §9.3.3.14: an Action frame body is `Category (1 B) ||
//! Action (1 B) || body`. The fixture generator emits two categories:
//!
//! - Category `6` -- Fast BSS Transition (FT) Action. Action codes 1 / 2 / 3
//!   are FT Request / Response / Confirm (S11 / S12 / S13).
//! - Category `15` -- Mesh. Action codes 1 / 2 are Mesh Peering Open /
//!   Confirm (S18 / S19).

use crate::frame::mac;

/// Category: Fast BSS Transition (`[IEEE 802.11-2024]` table 9-79).
pub const CATEGORY_FT: u8 = 6;
/// Category: Mesh.
pub const CATEGORY_MESH: u8 = 15;

/// Action: FT Request (`[IEEE 802.11-2024]` §9.6.8.2).
pub const FT_ACTION_REQUEST: u8 = 1;
/// Action: FT Response.
pub const FT_ACTION_RESPONSE: u8 = 2;
/// Action: FT Confirm.
pub const FT_ACTION_CONFIRM: u8 = 3;
/// Action: Mesh Peering Open (§9.6.15.2).
pub const MESH_PEERING_OPEN: u8 = 1;
/// Action: Mesh Peering Confirm (§9.6.15.3).
pub const MESH_PEERING_CONFIRM: u8 = 2;

/// Build an Action frame body.
#[must_use]
pub fn action(addr1: [u8; 6], addr2: [u8; 6], bssid: [u8; 6], category: u8, action: u8, body: &[u8]) -> Vec<u8> {
    let mut frame = mac::header_3addr(mac::TYPE_MGMT, mac::SUBTYPE_ACTION, false, false, addr1, addr2, bssid).to_vec();
    frame.push(category);
    frame.push(action);
    frame.extend_from_slice(body);
    frame
}
