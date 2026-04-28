//! Information Element (IE) builders.
//!
//! Tag numbers and OUIs are quoted from `[IEEE 802.11-2024]` clause 9.4.2.
//! Vendor IEs (tag 221) carry their own OUI / type discriminator inside the
//! TLV body -- WPA1 (`00:50:F2 type 1`), OSEN (`50:6F:9A type 18`), WPS
//! (`00:50:F2 type 4`).

/// Tag: SSID (`[IEEE 802.11-2024]` §9.4.2.2).
pub const TAG_SSID: u8 = 0;
/// Tag: Supported Rates (§9.4.2.3).
pub const TAG_SUPP_RATES: u8 = 1;
/// Tag: DS Parameter Set (§9.4.2.4).
pub const TAG_DS_PARAM: u8 = 3;
/// Tag: RSN (§9.4.2.24).
pub const TAG_RSN: u8 = 48;
/// Tag: Mobility Domain Element (§9.4.2.45).
pub const TAG_MDE: u8 = 54;
/// Tag: Fast BSS Transition Element (§9.4.2.46).
pub const TAG_FTE: u8 = 55;
/// Tag: AMPE element used inside Mesh Peering Confirm (§9.4.2.103).
pub const TAG_AMPE: u8 = 139;
/// Tag: Vendor-Specific (§9.4.2.25).
pub const TAG_VENDOR: u8 = 221;
/// Tag: RSN Extended (§9.4.2.241).
pub const TAG_RSNXE: u8 = 244;

/// IEEE 802.11 RSN OUI (`00:0F:AC`).
pub const OUI_IEEE: [u8; 3] = [0x00, 0x0F, 0xAC];
/// WFA Passpoint / OSEN OUI (`50:6F:9A`).
pub const OUI_WFA: [u8; 3] = [0x50, 0x6F, 0x9A];
/// Microsoft / WPA1 OUI (`00:50:F2`).
pub const OUI_MS: [u8; 3] = [0x00, 0x50, 0xF2];

/// Pack a tag-length-value triple into the supplied buffer.
pub fn push_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    // IE length is one byte (`[IEEE 802.11-2024]` §9.4.1) -- callers building
    // IEs longer than 255 bytes must use the Element ID Extension mechanism.
    let len = u8::try_from(value.len()).unwrap_or(u8::MAX);
    out.push(len);
    out.extend_from_slice(value);
}

/// Build the SSID IE.
#[must_use]
pub fn ssid(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + name.len());
    push_tlv(&mut out, TAG_SSID, name);
    out
}

/// Build a minimal RSN IE with one AKM and an optional PMKID.
///
/// `akm_byte` is the low byte of the AKM suite selector (`00:0F:AC:<byte>`):
/// 2 = WPA2-PSK, 4 = FT-PSK, 6 = PSK-SHA-256, 19 = FT-PSK-SHA384,
/// 20 = PSK-SHA384. Group + pairwise are pinned to CCMP (`00:0F:AC:04`); RSN
/// capabilities are zeroed.
#[must_use]
pub fn rsn_ie(akm_byte: u8, pmkid: Option<&[u8; 16]>) -> Vec<u8> {
    let mut value: Vec<u8> = Vec::with_capacity(32);
    value.extend_from_slice(&1u16.to_le_bytes()); // Version.
    value.extend_from_slice(&OUI_IEEE);
    value.push(0x04); // Group cipher: CCMP.
    value.extend_from_slice(&1u16.to_le_bytes());
    value.extend_from_slice(&OUI_IEEE);
    value.push(0x04); // Pairwise: CCMP.
    value.extend_from_slice(&1u16.to_le_bytes());
    value.extend_from_slice(&OUI_IEEE);
    value.push(akm_byte);
    value.extend_from_slice(&[0x00, 0x00]); // RSN capabilities.
    if let Some(p) = pmkid {
        value.extend_from_slice(&1u16.to_le_bytes());
        value.extend_from_slice(p);
    }
    let mut ie = Vec::with_capacity(2 + value.len());
    push_tlv(&mut ie, TAG_RSN, &value);
    ie
}

/// Build a WPA1 vendor IE (`tag 221`, OUI `00:50:F2`, type `1`).
///
/// `[Wi-Fi Alliance]` WPA spec: legacy pre-RSN security advertised via
/// vendor IE. Group + pairwise pinned to TKIP (`00:50:F2:02`), AKM = PSK
/// (`00:50:F2:02`). Used for the type-1 (WPA1) fixture and S16 / S17 vendor
/// firmware deviation tests.
#[must_use]
pub fn wpa1_vendor_ie() -> Vec<u8> {
    let mut value = Vec::with_capacity(24);
    value.extend_from_slice(&OUI_MS);
    value.push(0x01); // Type 1 = WPA.
    value.extend_from_slice(&1u16.to_le_bytes()); // Version.
    value.extend_from_slice(&OUI_MS);
    value.push(0x02); // Group cipher: TKIP.
    value.extend_from_slice(&1u16.to_le_bytes());
    value.extend_from_slice(&OUI_MS);
    value.push(0x02); // Pairwise: TKIP.
    value.extend_from_slice(&1u16.to_le_bytes());
    value.extend_from_slice(&OUI_MS);
    value.push(0x02); // AKM: PSK (WPA1).
    let mut ie = Vec::with_capacity(2 + value.len());
    push_tlv(&mut ie, TAG_VENDOR, &value);
    ie
}

/// Build an OSEN IE -- vendor `tag 221`, OUI `50:6F:9A`, type `0x12` (18).
///
/// Hotspot 2.0 OSU Server-Only Authenticated Layer 2 EN. The S20 PMKID
/// extraction site embeds a PMKID in this IE inside an Association Request.
///
/// Body layout after the OUI+type prefix follows the standard RSN IE
/// structure (Version, Group, Pairwise, AKM, Caps, PMKIDs) so wpawolf's
/// `extract_pmkids_from_osen()` -- which delegates to `parse_rsn_ie()` --
/// reaches the PMKID list. The OSEN AKM suite uses the WFA OUI per
/// Wi-Fi Alliance HS 2.0; `parse_rsn_ie()` ignores non-IEEE AKMs but still
/// advances `pos`, so the PMKID list parses correctly.
#[must_use]
pub fn osen_ie(pmkid: Option<&[u8; 16]>) -> Vec<u8> {
    let mut value = Vec::with_capacity(48);
    value.extend_from_slice(&OUI_WFA);
    value.push(0x12); // OSEN type.
    value.extend_from_slice(&1u16.to_le_bytes()); // Version.
    value.extend_from_slice(&OUI_IEEE);
    value.push(0x04); // Group placeholder: CCMP.
    value.extend_from_slice(&1u16.to_le_bytes());
    value.extend_from_slice(&OUI_IEEE);
    value.push(0x04); // Pairwise: CCMP.
    value.extend_from_slice(&1u16.to_le_bytes());
    value.extend_from_slice(&OUI_WFA);
    value.push(0x01); // AKM: OSEN [WFA HS 2.0].
    value.extend_from_slice(&[0x00, 0x00]); // RSN capabilities.
    if let Some(p) = pmkid {
        value.extend_from_slice(&1u16.to_le_bytes());
        value.extend_from_slice(p);
    }
    let mut ie = Vec::with_capacity(2 + value.len());
    push_tlv(&mut ie, TAG_VENDOR, &value);
    ie
}

/// Build the Mobility Domain Element (`tag 54`, `[IEEE 802.11-2024]` §9.4.2.45).
#[must_use]
pub fn mde(mdid: u16, ft_capability: u8) -> Vec<u8> {
    let mut value = [0u8; 3];
    value[..2].copy_from_slice(&mdid.to_le_bytes());
    value[2] = ft_capability;
    let mut ie = Vec::with_capacity(5);
    push_tlv(&mut ie, TAG_MDE, &value);
    ie
}

/// Inputs for an FT Element (`tag 55`, `[IEEE 802.11-2024]` §9.4.2.46).
#[derive(Debug, Clone)]
pub struct FteInputs<'a> {
    /// `MIC Control` field (2 B).
    pub mic_control: [u8; 2],
    /// Pre-computed MIC (16 or 24 bytes; pad/zero on write if needed).
    pub mic: &'a [u8],
    /// `ANonce` (32 B).
    pub a_nonce: [u8; 32],
    /// `SNonce` (32 B).
    pub s_nonce: [u8; 32],
    /// R0KH-ID subelement value (1-48 B).
    pub r0kh_id: &'a [u8],
    /// R1KH-ID subelement value (6 B MAC address).
    pub r1kh_id: [u8; 6],
}

/// FTE subelement IDs (`[IEEE 802.11-2024]` §9.4.2.46).
const FTE_SUBELEM_R1KH_ID: u8 = 1;
const FTE_SUBELEM_R0KH_ID: u8 = 3;

/// Build an FT Element (`tag 55`).
#[must_use]
pub fn fte(input: &FteInputs<'_>) -> Vec<u8> {
    let mut body = Vec::with_capacity(82 + input.r0kh_id.len() + 8);
    body.extend_from_slice(&input.mic_control);
    body.extend_from_slice(input.mic);
    // The fixed-portion FTE always carries 16-byte MIC slot in the legacy
    // form. SHA-384 FTEs use a 24-byte MIC; both cases are passed through
    // verbatim by the caller.
    body.extend_from_slice(&input.a_nonce);
    body.extend_from_slice(&input.s_nonce);
    // R1KH-ID subelement (id 1, len 6).
    body.push(FTE_SUBELEM_R1KH_ID);
    body.push(6);
    body.extend_from_slice(&input.r1kh_id);
    // R0KH-ID subelement (id 3, len N).
    body.push(FTE_SUBELEM_R0KH_ID);
    body.push(u8::try_from(input.r0kh_id.len()).unwrap_or(u8::MAX));
    body.extend_from_slice(input.r0kh_id);
    let mut ie = Vec::with_capacity(2 + body.len());
    push_tlv(&mut ie, TAG_FTE, &body);
    ie
}

/// Build an RSNXE IE (`tag 244`, `[IEEE 802.11-2024]` §9.4.2.241).
///
/// Single-byte capability variant -- sufficient for fixtures that need the
/// IE's presence but no specific capability bit.
#[must_use]
pub fn rsnxe(capabilities: u8) -> Vec<u8> {
    let mut ie = Vec::with_capacity(3);
    push_tlv(&mut ie, TAG_RSNXE, &[capabilities]);
    ie
}

/// Build an AMPE element with a PMKID at the tail.
///
/// `tag 139`, `[IEEE 802.11-2024]` §9.4.2.103. wpawolf treats the trailing
/// 16 bytes of the element as the PMKID (`src/extract/action.rs::139` for
/// S18 / S19).
#[must_use]
pub fn ampe_with_pmkid(pmkid: &[u8; 16]) -> Vec<u8> {
    let mut body = Vec::with_capacity(48);
    body.extend_from_slice(&[0u8; 16]); // Selected pairwise cipher suite count + suite list (placeholder).
    body.extend_from_slice(&[0u8; 16]); // Local link-id placeholder.
    body.extend_from_slice(pmkid);
    let mut ie = Vec::with_capacity(2 + body.len());
    push_tlv(&mut ie, TAG_AMPE, &body);
    ie
}
