//! Key Data Element (KDE) builders.
//!
//! `[IEEE 802.11-2024]` §12.7.2 table 12-8 -- KDE format:
//!
//! ```text
//! Type (0xDD) | Length | OUI (3 B) | Data Type (1 B) | Data (var)
//! ```
//!
//! All KDEs the fixture generator emits use the IEEE OUI `00:0F:AC`.

/// KDE wrapper tag (vendor-specific IE format used inside Key Data).
pub const KDE_TAG: u8 = 0xDD;
/// IEEE 802.11 RSN OUI.
pub const KDE_OUI: [u8; 3] = [0x00, 0x0F, 0xAC];

/// KDE Data Type: PMKID (S1 PMKID source).
pub const KDE_TYPE_PMKID: u8 = 0x04;
/// KDE Data Type: GTK.
pub const KDE_TYPE_GTK: u8 = 0x01;

/// Build a PMKID KDE: `DD 14 00 0F AC 04 <16-byte PMKID>`.
#[must_use]
pub fn pmkid(pmkid: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    out.push(KDE_TAG);
    out.push(0x14); // Length = 4 (OUI+type) + 16 (PMKID).
    out.extend_from_slice(&KDE_OUI);
    out.push(KDE_TYPE_PMKID);
    out.extend_from_slice(pmkid);
    out
}
