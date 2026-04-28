//! 802.11 MAC header builders.
//!
//! `[IEEE 802.11-2024]` §9.3.1: the 24-byte 3-address MAC header is the
//! baseline; 4-address (WDS) and `QoS` variants add 6 / 2 bytes respectively.
//! All Frame Control bits are little-endian on the wire (§9.2.4.1).

/// Frame Control type/subtype: Management = 0.
pub const TYPE_MGMT: u8 = 0;
/// Frame Control type/subtype: Control = 1.
pub const TYPE_CTRL: u8 = 1;
/// Frame Control type/subtype: Data = 2.
pub const TYPE_DATA: u8 = 2;

/// Subtype: Association Request (`[IEEE 802.11-2024]` table 9-1).
pub const SUBTYPE_ASSOC_REQ: u8 = 0;
/// Subtype: Reassociation Request.
pub const SUBTYPE_REASSOC_REQ: u8 = 2;
/// Subtype: Probe Request.
pub const SUBTYPE_PROBE_REQ: u8 = 4;
/// Subtype: Probe Response.
pub const SUBTYPE_PROBE_RESP: u8 = 5;
/// Subtype: Beacon.
pub const SUBTYPE_BEACON: u8 = 8;
/// Subtype: Authentication.
pub const SUBTYPE_AUTH: u8 = 11;
/// Subtype: Action.
pub const SUBTYPE_ACTION: u8 = 13;

/// Build a 24-byte 3-address MAC header.
///
/// Address ordering follows `[IEEE 802.11-2024]` §9.3.1.1 figure 9-2:
/// `addr1 = RA / DA`, `addr2 = TA / SA`, `addr3 = BSSID / SA / DA` depending
/// on `to_ds` / `from_ds`. Sequence Control is left zero -- callers that
/// care (fragment reassembly fixtures) overwrite bytes 22-23.
#[must_use]
pub fn header_3addr(
    ftype: u8,
    subtype: u8,
    to_ds: bool,
    from_ds: bool,
    addr1: [u8; 6],
    addr2: [u8; 6],
    addr3: [u8; 6],
) -> [u8; 24] {
    let mut h = [0u8; 24];
    // Frame Control byte 0: Protocol Version (2 bits) | Type (2) | Subtype (4).
    h[0] = (subtype << 4) | (ftype << 2);
    // Frame Control byte 1: ToDS | FromDS | MoreFrag | Retry | PwrMgt | MoreData | ProtFrame | Order.
    let mut fc1 = 0u8;
    if to_ds {
        fc1 |= 0x01;
    }
    if from_ds {
        fc1 |= 0x02;
    }
    h[1] = fc1;
    // Bytes 2-3: Duration / ID -- left zero for fixture frames.
    h[4..10].copy_from_slice(&addr1);
    h[10..16].copy_from_slice(&addr2);
    h[16..22].copy_from_slice(&addr3);
    h
}

/// Build a 30-byte 4-address (WDS) MAC header (`to_ds = from_ds = 1`).
#[must_use]
pub fn header_4addr(
    ftype: u8,
    subtype: u8,
    addr1: [u8; 6],
    addr2: [u8; 6],
    addr3: [u8; 6],
    addr4: [u8; 6],
) -> [u8; 30] {
    let mut h = [0u8; 30];
    let three = header_3addr(ftype, subtype, true, true, addr1, addr2, addr3);
    h[..24].copy_from_slice(&three);
    h[24..30].copy_from_slice(&addr4);
    h
}
