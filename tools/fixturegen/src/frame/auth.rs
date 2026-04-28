//! Authentication frame builder.
//!
//! `[IEEE 802.11-2024]` §9.3.3.11: an Authentication frame body is fixed
//! fields (Algorithm Number, Sequence Number, Status Code) followed by an
//! algorithm-specific IE list. Algorithm numbers used by the fixture
//! generator: `2` = FT (S5 / S6), `4` = FILS Shared Key (S7 / S8), `5` =
//! FILS Public Key (S7 / S8), `7` = PASN (S9 / S10).

use crate::frame::{ie, mac};

/// Algorithm Number: Fast BSS Transition (`[IEEE 802.11-2024]` table 9-43).
pub const ALGO_FT: u16 = 2;
/// Algorithm Number: FILS Shared Key.
pub const ALGO_FILS_SK: u16 = 4;
/// Algorithm Number: FILS Public Key.
pub const ALGO_FILS_PK: u16 = 5;
/// Algorithm Number: Pre-Association Security Negotiation.
pub const ALGO_PASN: u16 = 7;

/// Build an Authentication frame body.
///
/// `addr1` is the receiver, `addr2` the transmitter, `addr3` the BSSID.
/// `ies` is the algorithm-specific IE list (RSN IE for FT/FILS/PASN, plus
/// MDE + FTE for FT seq=2). The status code is fixed at `0` (Success).
#[must_use]
pub fn auth(addr1: [u8; 6], addr2: [u8; 6], bssid: [u8; 6], algo: u16, seq: u16, ies: &[u8]) -> Vec<u8> {
    let mut frame = mac::header_3addr(mac::TYPE_MGMT, mac::SUBTYPE_AUTH, false, false, addr1, addr2, bssid).to_vec();
    frame.extend_from_slice(&algo.to_le_bytes());
    frame.extend_from_slice(&seq.to_le_bytes());
    frame.extend_from_slice(&0u16.to_le_bytes()); // Status Code.
    frame.extend_from_slice(ies);
    frame
}

/// Build the IE list for an FT Authentication frame (RSN IE + MDE + FTE).
#[must_use]
pub fn ft_ies(rsn: &[u8], mde: &[u8], fte: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rsn.len() + mde.len() + fte.len());
    out.extend_from_slice(rsn);
    out.extend_from_slice(mde);
    out.extend_from_slice(fte);
    out
}

/// Stub MDE bytes (`tag 54`, `len 3`, `MDID = 0x1234`, `FT Capability = 0`).
#[must_use]
pub fn mde_stub() -> Vec<u8> {
    let mut out = Vec::new();
    ie::push_tlv(&mut out, ie::TAG_MDE, &[0x12, 0x34, 0x00]);
    out
}
