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
/// `value` is `ie.value`. The MIC field is variable-length: 16 bytes for SHA-256
/// AKMs (4, 3-6, 8, 9, 11), 24 bytes for SHA-384 AKMs (12, 13, 19, 20), 32 bytes
/// for SHA-512 (AKM 25 with MIC Length subfield = 2). The MIC length is determined
/// from the MIC Control field's MIC Length subfield (bits B1-B3) per Table 9-220:
/// 0->16, 1->24, 2->32. For AKMs other than 25 the subfield is "reserved" but
/// well-behaved firmware sets it correctly; we validate against the IE body length
/// and fall back to 16 if the decoded length is inconsistent.
/// [IEEE 802.11-2024] §9.4.2.46, Figure 9-436, Table 9-220, Table 12-11.
#[must_use]
pub fn parse_fte(value: &[u8]) -> Option<FteInfo> {
    // MIC Control: 2 bytes (offset 0). Bits B1-B3 = MIC Length subfield.
    // [IEEE 802.11-2024] Figure 9-437, Table 9-220
    if value.len() < 2 {
        return None;
    }
    let mic_ctrl_lo = *value.first()?;
    let mic_len_code = (mic_ctrl_lo >> 1) & 0x07;
    let mic_len: usize = match mic_len_code {
        1 => 24,
        2 => 32,
        _ => 16, // 0 or reserved values default to 16
    };

    // Layout: MIC Control (2) + MIC (mic_len) + ANonce (32) + SNonce (32).
    let anonce_off = 2 + mic_len;
    let body_required = anonce_off + 64; // 32 ANonce + 32 SNonce

    // If the decoded mic_len makes the FTE too short, fall back to 16.
    let anonce_off = if body_required > value.len() {
        let fallback = 2 + 16; // 16-byte MIC default
        if fallback + 64 > value.len() {
            return None;
        }
        fallback
    } else {
        anonce_off
    };

    let anonce: [u8; 32] = value.get(anonce_off..anonce_off + 32).and_then(|s| s.try_into().ok())?;
    let snonce: [u8; 32] = value.get(anonce_off + 32..anonce_off + 64).and_then(|s| s.try_into().ok())?;

    let mut r1khid: Option<[u8; 6]> = None;
    let mut r0khid: Option<Vec<u8>> = None;

    // Parse subelements: each is type(1) + length(1) + value(length).
    let mut pos = anonce_off + 64;
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

    // Builds a minimal FTE value with 16-byte MIC (MIC Length subfield = 0).
    fn make_fte_value(anonce: [u8; 32], snonce: [u8; 32]) -> Vec<u8> {
        // MIC Control: 0x0000 (MIC Length = 0 -> 16 bytes).
        let mut v = vec![0u8; 82]; // 2 + 16 + 32 + 32 = 82
        v[18..50].copy_from_slice(&anonce);
        v[50..82].copy_from_slice(&snonce);
        v
    }

    // Builds an FTE value with 24-byte MIC (MIC Length subfield = 1, for SHA-384 AKMs).
    fn make_fte_value_24mic(anonce: [u8; 32], snonce: [u8; 32]) -> Vec<u8> {
        // MIC Control byte 0: MIC Length subfield (bits B1-B3) = 1 -> 24-byte MIC.
        // Encoding: bit B0 = RSNXE Used = 0, bits B1-B3 = 001 -> byte = 0x02.
        let mut v = vec![0u8; 90]; // 2 + 24 + 32 + 32 = 90
        v[0] = 0x02; // MIC Length = 1
        // ANonce at offset 2 + 24 = 26
        v[26..58].copy_from_slice(&anonce);
        // SNonce at offset 26 + 32 = 58
        v[58..90].copy_from_slice(&snonce);
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
    fn parse_fte_24byte_mic() {
        // SHA-384 AKMs (e.g., AKM 12/13) use 24-byte MIC. [IEEE 802.11-2024] Table 9-220
        let anonce = [0xAAu8; 32];
        let snonce = [0xBBu8; 32];
        let value = make_fte_value_24mic(anonce, snonce);
        assert_eq!(value.len(), 90); // 2 + 24 + 32 + 32
        let info = parse_fte(&value).unwrap();
        assert_eq!(info.anonce, anonce);
        assert_eq!(info.snonce, snonce);
        assert!(info.r1khid.is_none());
        assert!(info.r0khid.is_none());
    }

    #[test]
    fn parse_fte_32byte_mic() {
        // SHA-512 AKM 25 uses 32-byte MIC (MIC Length subfield = 2). [IEEE 802.11-2024] Table 9-220
        let anonce = [0xCCu8; 32];
        let snonce = [0xDDu8; 32];
        // MIC Control byte 0: bits B1-B3 = 2 -> byte = 0x04.
        let mut v = vec![0u8; 98]; // 2 + 32 + 32 + 32 = 98
        v[0] = 0x04; // MIC Length = 2
        // ANonce at offset 2 + 32 = 34
        v[34..66].copy_from_slice(&anonce);
        // SNonce at offset 34 + 32 = 66
        v[66..98].copy_from_slice(&snonce);

        let info = parse_fte(&v).unwrap();
        assert_eq!(info.anonce, anonce);
        assert_eq!(info.snonce, snonce);
    }

    #[test]
    fn parse_fte_mic_length_fallback() {
        // If MIC Control claims 24-byte MIC but body is only 82 bytes (fits 16, not 24),
        // the parser falls back to 16.
        let anonce = [0xEEu8; 32];
        let snonce = [0xFFu8; 32];
        let mut v = vec![0u8; 82]; // Only fits 16-byte MIC layout
        v[0] = 0x02; // Claims MIC Length = 1 (24 bytes) but body too short
        // With fallback to 16: ANonce at offset 18, SNonce at 50
        v[18..50].copy_from_slice(&anonce);
        v[50..82].copy_from_slice(&snonce);

        let info = parse_fte(&v).unwrap();
        assert_eq!(info.anonce, anonce);
        assert_eq!(info.snonce, snonce);
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
