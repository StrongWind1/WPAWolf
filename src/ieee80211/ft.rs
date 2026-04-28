//! Phase 2 -- Decode: Fast BSS Transition (802.11r) IE parser (MDID / R0KH-ID / R1KH-ID). See ARCHITECTURE.md §2 + §3.2.
//!
//! Parses the Mobility Domain Element (MDE, Element ID 54) for the MDID (2 bytes) and
//! FT Capability byte per IEEE 802.11-2024 §9.4.2.45, and the Fast Transition Element
//! (FTE, Element ID 55) for `ANonce`, `SNonce`, MIC, and subelements including R0KH-ID
//! (subelement type 3) and R1KH-ID (subelement type 1) per §9.4.2.46. These fields
//! are required for hashcat mode 37100 (FT-PSK) output.

use crate::types::FtFields;

use super::ie::iter_ies;

// --- Subelement type constants ---

/// FTE subelement type 1: R1 Key Holder ID (6-byte MAC). [IEEE 802.11-2024] §9.4.2.46
const SUB_TYPE_R1KHID: u8 = 1;
/// FTE subelement type 3: R0 Key Holder ID (1-48 bytes). [IEEE 802.11-2024] §9.4.2.46
const SUB_TYPE_R0KHID: u8 = 3;

// --- Output types ---

/// Mobility Domain Element data. [IEEE 802.11-2024] §9.4.2.45
#[derive(Debug, Clone, Copy)]
pub struct MdeInfo {
    /// 2-byte Mobility Domain Identifier.
    pub mdid: [u8; 2],
}

/// Fast Transition Element data. [IEEE 802.11-2024] §9.4.2.46
#[derive(Debug, Clone)]
pub struct FteInfo {
    /// Authenticator Nonce (32 bytes).
    pub anonce: [u8; 32],
    /// Supplicant Nonce (32 bytes).
    pub snonce: [u8; 32],
    /// R1 Key Holder ID (6 bytes, MAC address). Subelement type 1.
    pub r1khid: Option<[u8; 6]>,
    /// R0 Key Holder ID (1-48 bytes). Subelement type 3.
    pub r0khid: Option<Vec<u8>>,
}

// --- Parse functions ---

/// Parses a Mobility Domain IE value (Element ID 54).
///
/// `value` is `ie.value` -- the bytes after the Element ID and Length fields. Requires
/// at least 2 bytes for the MDID; the FT Capability byte (offset 2) is present but
/// not returned (not needed for hash output). Returns `None` if the value is too short.
/// [IEEE 802.11-2024] §9.4.2.45.
#[must_use]
pub fn parse_mde(value: &[u8]) -> Option<MdeInfo> {
    // MDID is the first 2 bytes. FT Capability at offset 2 is not needed for output.
    let mdid: [u8; 2] = value.get(0..2).and_then(|s| s.try_into().ok())?;
    Some(MdeInfo { mdid })
}

/// Parses a Fast Transition IE value (Element ID 55).
///
/// `value` is `ie.value`. Minimum 82 bytes: MIC Control (2) + MIC (16) + `ANonce` (32) +
/// `SNonce` (32). The MIC itself is not stored -- it is not needed for hash construction.
/// Subelements after offset 82 are parsed for R1KH-ID and R0KH-ID. Returns `None` if
/// the value is shorter than 82 bytes. [IEEE 802.11-2024] §9.4.2.46.
#[must_use]
pub fn parse_fte(value: &[u8]) -> Option<FteInfo> {
    // Minimum fixed-field layout:
    //   MIC Control: 2 bytes (offset 0)
    //   MIC:        16 bytes (offset 2)
    //   ANonce:     32 bytes (offset 18)
    //   SNonce:     32 bytes (offset 50)
    //   Total:      82 bytes
    if value.len() < 82 {
        return None;
    }
    // MIC Control (offset 0, 2 bytes) and MIC (offset 2, 16 bytes) are not needed for
    // hash output -- skip directly to ANonce.
    let anonce: [u8; 32] = value.get(18..50).and_then(|s| s.try_into().ok())?;
    let snonce: [u8; 32] = value.get(50..82).and_then(|s| s.try_into().ok())?;

    let mut r1khid: Option<[u8; 6]> = None;
    let mut r0khid: Option<Vec<u8>> = None;

    // Parse subelements: each is type(1) + length(1) + value(length).
    let mut pos = 82usize;
    while pos + 2 <= value.len() {
        let Some(&sub_type) = value.get(pos) else { break };
        let sub_len = match value.get(pos + 1) {
            Some(&l) => l as usize,
            None => break,
        };
        let Some(sub_val) = value.get(pos + 2..pos + 2 + sub_len) else { break };
        match sub_type {
            SUB_TYPE_R1KHID => {
                // R1KH-ID must be exactly 6 bytes (MAC address form).
                // [IEEE 802.11-2024] §9.4.2.46 subelement type 1
                r1khid = sub_val.try_into().ok();
            },
            SUB_TYPE_R0KHID => {
                // R0KH-ID is 1-48 bytes. [IEEE 802.11-2024] §9.4.2.46 subelement type 3
                r0khid = Some(sub_val.to_vec());
            },
            _ => {}, // Unknown subelement type -- skip.
        }
        pos += 2 + sub_len;
    }

    Some(FteInfo { anonce, snonce, r1khid, r0khid })
}

/// Extracts FT fields for mode 37100 from tagged parameters.
///
/// Looks for both MDE (id=54) and FTE (id=55). Returns populated `FtFields` only
/// when both are found. R0KH-ID is truncated to 48 bytes if longer (spec max is 48).
/// [IEEE 802.11-2024] §9.4.2.45 and §9.4.2.46.
#[must_use]
pub fn extract_ft_fields(tagged_params: &[u8]) -> Option<FtFields> {
    let mut mde: Option<MdeInfo> = None;
    let mut fte: Option<FteInfo> = None;

    for ie in iter_ies(tagged_params) {
        match ie.id {
            54 => mde = parse_mde(ie.value), // MDE [IEEE 802.11-2024] §9.4.2.45
            55 => fte = parse_fte(ie.value), // FTE [IEEE 802.11-2024] §9.4.2.46
            _ => {},
        }
    }

    let mde = mde?;
    let fte = fte?;

    let mut fields = FtFields {
        mdid: mde.mdid,
        r0khid_len: 0,
        r0khid: [0u8; 48],
        // unwrap_or is not unwrap -- no lint fires.
        r1khid: fte.r1khid.unwrap_or([0u8; 6]),
    };

    if let Some(r0) = fte.r0khid {
        let copy_len = r0.len().min(48);
        // copy_len is at most 48, always fits in u8.
        fields.r0khid_len = u8::try_from(copy_len).unwrap_or(48);
        if let Some(dst) = fields.r0khid.get_mut(..copy_len) {
            if let Some(src) = r0.get(..copy_len) {
                dst.copy_from_slice(src);
            }
        }
    }

    Some(fields)
}

// --- Unit tests ---

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        missing_docs,
        clippy::wildcard_imports,
        reason = "test module"
    )]

    use super::*;

    // Builds a minimal 82-byte FTE value with given ANonce and SNonce.
    fn make_fte_value(anonce: [u8; 32], snonce: [u8; 32]) -> Vec<u8> {
        let mut v = vec![0u8; 82];
        // MIC Control (2 bytes, offset 0) and MIC (16 bytes, offset 2) are zeroed.
        v[18..50].copy_from_slice(&anonce);
        v[50..82].copy_from_slice(&snonce);
        v
    }

    #[test]
    fn parse_mde_valid() {
        let value = [0x12u8, 0x34, 0x00]; // MDID + FT Capability
        let info = parse_mde(&value).unwrap();
        assert_eq!(info.mdid, [0x12, 0x34]);
    }

    #[test]
    fn parse_mde_too_short() {
        // Only 1 byte -- cannot read 2-byte MDID.
        assert!(parse_mde(&[0x12]).is_none());
    }

    #[test]
    fn parse_fte_minimal() {
        let anonce = [0x11u8; 32];
        let snonce = [0x22u8; 32];
        let value = make_fte_value(anonce, snonce);
        let info = parse_fte(&value).unwrap();
        assert_eq!(info.anonce, anonce);
        assert_eq!(info.snonce, snonce);
        assert!(info.r1khid.is_none());
        assert!(info.r0khid.is_none());
    }

    #[test]
    fn parse_fte_with_r1khid() {
        let anonce = [0x11u8; 32];
        let snonce = [0x22u8; 32];
        let mut value = make_fte_value(anonce, snonce);
        // Append subelement type=1, len=6, value=[0xAA..0xFF]
        let r1 = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        value.push(1); // sub type
        value.push(6); // sub len
        value.extend_from_slice(&r1);

        let info = parse_fte(&value).unwrap();
        assert_eq!(info.r1khid, Some(r1));
    }

    #[test]
    fn parse_fte_with_r0khid() {
        let anonce = [0x33u8; 32];
        let snonce = [0x44u8; 32];
        let mut value = make_fte_value(anonce, snonce);
        // Append subelement type=3, len=8, arbitrary value
        let r0 = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        value.push(3); // sub type
        value.push(8); // sub len
        value.extend_from_slice(&r0);

        let info = parse_fte(&value).unwrap();
        assert_eq!(info.r0khid, Some(r0.to_vec()));
    }

    #[test]
    fn parse_fte_too_short() {
        // 80 bytes -- 2 bytes short of the minimum 82.
        let value = vec![0u8; 80];
        assert!(parse_fte(&value).is_none());
    }

    #[test]
    fn extract_ft_fields_complete() {
        let anonce = [0x55u8; 32];
        let snonce = [0x66u8; 32];
        let r1 = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66];
        let r0 = [0xAAu8, 0xBB, 0xCC, 0xDD];

        // Build MDE tagged IE.
        let mut tagged = Vec::new();
        tagged.push(54u8); // MDE id
        tagged.push(3u8); // len = MDID(2) + FT Cap(1)
        tagged.extend_from_slice(&[0x12, 0x34, 0x00]); // MDID + cap

        // Build FTE tagged IE.
        let mut fte_value = make_fte_value(anonce, snonce);
        fte_value.push(1); // R1KH-ID sub type
        fte_value.push(6);
        fte_value.extend_from_slice(&r1);
        fte_value.push(3); // R0KH-ID sub type
        fte_value.push(r0.len() as u8);
        fte_value.extend_from_slice(&r0);

        tagged.push(55u8); // FTE id
        tagged.push(fte_value.len() as u8);
        tagged.extend_from_slice(&fte_value);

        let fields = extract_ft_fields(&tagged).unwrap();
        assert_eq!(fields.mdid, [0x12, 0x34]);
        assert_eq!(fields.r1khid, r1);
        assert_eq!(fields.r0khid_len, r0.len() as u8);
        assert_eq!(fields.r0khid[..r0.len()], r0);
    }

    #[test]
    fn extract_ft_fields_missing_fte() {
        // Only MDE present -- FTE absent -- must return None.
        let mut tagged = Vec::new();
        tagged.push(54u8); // MDE id
        tagged.push(3u8);
        tagged.extend_from_slice(&[0x12, 0x34, 0x00]);

        assert!(extract_ft_fields(&tagged).is_none());
    }

    #[test]
    fn parse_fte_skips_unknown_subelement() {
        let anonce = [0x77u8; 32];
        let snonce = [0x88u8; 32];
        let mut value = make_fte_value(anonce, snonce);
        // Unknown subelement type 99 followed by a known type 1.
        value.push(99); // unknown sub type
        value.push(4); // len
        value.extend_from_slice(&[0xDEu8, 0xAD, 0xBE, 0xEF]);
        let r1 = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06];
        value.push(1); // R1KH-ID
        value.push(6);
        value.extend_from_slice(&r1);

        let info = parse_fte(&value).unwrap();
        assert_eq!(info.r1khid, Some(r1));
    }
}
