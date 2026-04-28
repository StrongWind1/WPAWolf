//! Phase 2 -- Decode: RSN IE + AKM-suite detection (Table 9-190). See ARCHITECTURE.md §2 + §3.2 + §8.3.
//!
//! Parses Element ID 48 per IEEE 802.11-2024 §9.4.2.24, Figure 9-367 to extract AKM
//! suite types, pairwise cipher suites, and the embedded PMKID list. AKM type bytes
//! under OUI `00:0F:AC` are mapped to `AkmType` variants per Table 9-190. Also parses
//! the legacy WPA vendor IE (tag 221, OUI `00:50:F2`, type 1) which carries the same
//! inner structure but is not in the IEEE spec (Wi-Fi Alliance proprietary).

use crate::types::AkmType;

use super::ie::{iter_ies, vendor_ie_body};

// --- AKM OUI constant ---

/// OUI for IEEE 802.11 defined AKM suites. [IEEE 802.11-2024] §9.4.2.24, Table 9-190
const OUI_IEEE: [u8; 3] = [0x00, 0x0F, 0xAC];

// --- Output types ---

/// Result of parsing an RSN or WPA Information Element.
///
/// Holds the AKM suite types and any PMKIDs advertised by the peer. Both fields may
/// be empty if the IE is absent or truncated before those sections.
#[derive(Debug, Default, Clone)]
pub struct RsnInfo {
    /// AKM suite types found in the AKM Suite List.
    /// Empty if no AKM suites were present or the IE was truncated before the AKM section.
    pub akm_types: Vec<AkmType>,
    /// PMKIDs found in the PMKID List (each 16 bytes).
    pub pmkids: Vec<[u8; 16]>,
}

// --- Core IE parser ---

/// Parses an RSN IE value (Element ID 48) and extracts AKM types and PMKIDs.
///
/// `value` is `ie.value` -- the bytes after the Element ID and Length fields.
/// Returns `None` if Version != 1 or the IE is too short for the version field.
/// Each section after Version is optional per the spec; parsing stops cleanly when
/// the buffer ends. [IEEE 802.11-2024] §9.4.2.24, Figure 9-367.
#[must_use]
pub fn parse_rsn_ie(value: &[u8]) -> Option<RsnInfo> {
    let mut info = RsnInfo::default();
    let mut pos = 0usize;

    // Version (2 bytes LE) -- must be 1. [IEEE 802.11-2024] §9.4.2.24
    let ver_bytes: [u8; 2] = value.get(pos..pos + 2).and_then(|s| s.try_into().ok())?;
    if u16::from_le_bytes(ver_bytes) != 1 {
        return None;
    }
    pos += 2;

    // Group Cipher Suite (4 bytes) -- optional; if absent, all later fields also absent.
    if pos + 4 > value.len() {
        return Some(info);
    }
    pos += 4;

    // Pairwise Cipher Suite Count + List -- optional.
    if pos + 2 > value.len() {
        return Some(info);
    }
    let pw_count = u16::from_le_bytes(value.get(pos..pos + 2).and_then(|s| s.try_into().ok())?) as usize;
    pos += 2;
    pos += pw_count * 4;
    if pos > value.len() {
        return Some(info);
    }

    // AKM Suite Count + List. [IEEE 802.11-2024] §9.4.2.24, Figure 9-367
    if pos + 2 > value.len() {
        return Some(info);
    }
    let akm_count = u16::from_le_bytes(value.get(pos..pos + 2).and_then(|s| s.try_into().ok())?) as usize;
    pos += 2;
    for _ in 0..akm_count {
        if pos + 4 > value.len() {
            break;
        }
        let Some(suite) = value.get(pos..pos + 4) else { break };
        let Some(oui) = suite.get(0..3) else { break };
        let Some(&suite_type) = suite.get(3) else { break };
        // Only IEEE 802.11 defined AKM suites use OUI 00:0F:AC.
        // [IEEE 802.11-2024] §9.4.2.24, Table 9-190
        if oui == OUI_IEEE {
            let akm = match suite_type {
                2 => AkmType::Wpa2Psk,      // WPA2-PSK (HMAC-SHA1, PRF-SHA1)
                4 => AkmType::FtPsk,        // FT-PSK (SHA-256 chain)
                6 => AkmType::PskSha256,    // PSK-SHA256 (KDF-SHA256, AES-CMAC)
                19 => AkmType::FtPskSha384, // FT-PSK-SHA384 (SHA-384 chain)
                20 => AkmType::PskSha384,   // PSK-SHA384 (KDF-SHA384, HMAC-SHA384-192 MIC)
                _ => {
                    // SAE (8), OWE (18), EAP variants, etc. -- out of v1 scope.
                    pos += 4;
                    continue;
                },
            };
            info.akm_types.push(akm);
        }
        pos += 4;
    }

    // RSN Capabilities (2 bytes) -- optional; we read past it to reach PMKIDs.
    if pos + 2 > value.len() {
        return Some(info);
    }
    pos += 2;

    // PMKID Count + List. [IEEE 802.11-2024] §9.4.2.24, Figure 9-367
    if pos + 2 > value.len() {
        return Some(info);
    }
    let pmkid_count = u16::from_le_bytes(value.get(pos..pos + 2).and_then(|s| s.try_into().ok())?) as usize;
    pos += 2;
    for _ in 0..pmkid_count {
        if pos + 16 > value.len() {
            break;
        }
        let pmkid: [u8; 16] = match value.get(pos..pos + 16).and_then(|s| s.try_into().ok()) {
            Some(p) => p,
            None => break,
        };
        info.pmkids.push(pmkid);
        pos += 16;
    }

    Some(info)
}

/// Parses a WPA vendor IE body (after OUI+type prefix) with the same structure.
///
/// The WPA IE (OUI `00:50:F2`, type 1) uses the same inner format as the RSN IE but
/// carries version 1 (as `0x01, 0x00`). [Wi-Fi Alliance WPA spec]
#[must_use]
pub fn parse_wpa_ie(value: &[u8]) -> Option<RsnInfo> {
    // Same inner layout as RSN IE -- delegate directly.
    parse_rsn_ie(value)
}

// --- Public helpers ---

/// Extracts the best AKM type from tagged parameters.
///
/// Iterates all IEs looking for RSN IE (id=48) and WPA vendor IE (id=221).
/// Returns the first recognised AKM type, preferring RSN over WPA. Returns
/// `AkmType::Unknown` if no RSN/WPA IE is found or no known AKM is present.
#[must_use]
pub fn detect_akm(tagged_params: &[u8]) -> AkmType {
    // OUI and type for the legacy WPA vendor IE. [Wi-Fi Alliance WPA spec]
    const OUI_WFA: [u8; 3] = [0x00, 0x50, 0xF2];
    const WPA_IE_TYPE: u8 = 1;

    let mut rsn_akm: Option<AkmType> = None;
    let mut wpa_akm: Option<AkmType> = None;

    for ie in iter_ies(tagged_params) {
        match ie.id {
            48 => {
                // RSN IE [IEEE 802.11-2024] §9.4.2.24
                if let Some(info) = parse_rsn_ie(ie.value) {
                    if let Some(&akm) = info.akm_types.first() {
                        rsn_akm = Some(akm);
                    }
                }
            },
            221 if wpa_akm.is_none() => {
                // Vendor IE -- check for WPA1 IE (OUI 00:50:F2, type 1). The legacy WPA1
                // vendor IE reuses the RSN inner format including the AKM-2 selector for
                // its PSK suite, but the IE container itself signals WPA1: KDV 1
                // HMAC-MD5 MIC, PRF-SHA1 PTK, no PMKID field. Per the 11-type taxonomy
                // (ARCHITECTURE.md §2) this is type 1 (WPA1-PSK-EAPOL), distinct from
                // type 3 (WPA2-PSK-EAPOL) which the AKM 2 selector would otherwise imply.
                // Map the inner WPA2-PSK to the dedicated AkmType::Wpa1 variant.
                if let Some(body) = vendor_ie_body(&ie, OUI_WFA, WPA_IE_TYPE) {
                    if let Some(info) = parse_wpa_ie(body) {
                        if let Some(&akm) = info.akm_types.first() {
                            wpa_akm = Some(if akm == AkmType::Wpa2Psk { AkmType::Wpa1 } else { akm });
                        }
                    }
                }
            },
            _ => {},
        }
        // Short-circuit once we have an RSN AKM -- it takes precedence.
        if rsn_akm.is_some() {
            break;
        }
    }

    rsn_akm.or(wpa_akm).unwrap_or(AkmType::Unknown)
}

/// Extracts all PMKIDs from RSN IE in tagged parameters.
///
/// Scans the tagged parameter block for the RSN IE (Element ID 48) and returns every
/// PMKID found in its PMKID List. Returns an empty `Vec` if no RSN IE is present or
/// the IE contains no PMKIDs. [IEEE 802.11-2024] §9.4.2.24.
#[must_use]
pub fn extract_pmkids(tagged_params: &[u8]) -> Vec<[u8; 16]> {
    for ie in iter_ies(tagged_params) {
        if ie.id == 48 {
            // RSN IE [IEEE 802.11-2024] §9.4.2.24
            if let Some(info) = parse_rsn_ie(ie.value) {
                return info.pmkids;
            }
        }
    }
    Vec::new()
}

/// Extracts PMKIDs from an OSEN vendor IE body.
///
/// OSEN (Online Signup Enabled) uses a vendor IE with OUI `50:6F:9A`, type `0x12`.
/// The body after OUI+type (4 bytes) is identical to an RSN IE starting from the
/// Group Cipher Suite field, including the PMKID Count and PMKID List at the same
/// relative offsets. [Wi-Fi Passpoint spec; `packet-ieee80211.c:20399`]
///
/// `value` is the raw IE value bytes (after tag and length). Returns empty vec on
/// OUI/type mismatch or parse failure.
#[must_use]
pub fn extract_pmkids_from_osen(value: &[u8]) -> Vec<[u8; 16]> {
    const OSEN_OUI: [u8; 3] = [0x50, 0x6F, 0x9A];
    const OSEN_TYPE: u8 = 0x12;
    if value.len() < 4 {
        return vec![];
    }
    // Check OUI (bytes 0-2) and type (byte 3). [Hotspot 2.0 / OSEN spec]
    let Some(oui) = value.get(0..3) else { return vec![] };
    let Some(&ie_type) = value.get(3) else { return vec![] };
    if oui != OSEN_OUI || ie_type != OSEN_TYPE {
        return vec![];
    }
    // Re-use RSN IE parser on the body after OUI + type (4 bytes skipped).
    parse_rsn_ie(value.get(4..).unwrap_or(&[])).map(|rsn| rsn.pmkids).unwrap_or_default()
}

// --- RSN Extension IE (RSNXE, tag 244) ---

/// Element ID for the RSN Extension element (RSNXE). [IEEE 802.11-2024] §9.4.2.241
pub const IE_RSN_EXTENSION: u8 = 244;

// Extended RSN Capabilities bit map. [IEEE 802.11-2024] §9.4.2.241, Figure 9-711.
//
// The field is a little-endian bit-stream. Byte 0 bits 0-3 carry the length nibble;
// bits 4-7 carry extended capability flags (bit 5 = `SaeH2e`, bit 6 = `SaePK`).
// Byte 1 bit 0 = `SecureLtf` (11az); byte 1 bit 3 = `ProtectedTwt`. We parse the
// first two bytes only; deeper bytes are implementation-defined and not needed for
// diagnostic counters.

/// Extended RSN Capabilities decoded from a RSN Extension IE (tag 244).
///
/// Diagnostic flags only -- these do not influence PSK/FT-PSK hash emission. Used by
/// the stats summary to report WPA3 / 11az / 11ax feature advertisements observed in
/// the capture. [IEEE 802.11-2024] §9.4.2.241, Figure 9-711.
#[allow(clippy::struct_excessive_bools, reason = "one flag per capability bit; not a state machine")]
#[derive(Debug, Default, Clone, Copy)]
pub struct RsnxeInfo {
    /// Bit 5 of byte 0: SAE Hash-to-Element required (WPA3-H2E). [§9.4.2.241]
    pub sae_h2e: bool,
    /// Bit 6 of byte 0: SAE Public Key support (SAE-PK). [§9.4.2.241]
    pub sae_pk: bool,
    /// Bit 8 of byte 0: Secure LTF support (11az Enhanced Ranging). [§9.4.2.241]
    pub secure_ltf: bool,
    /// Bit 11 of byte 0: Protected TWT (Target Wake Time) Operations support. [§9.4.2.241]
    pub protected_twt: bool,
}

/// Parses the body of an RSN Extension IE (Element ID 244) and returns decoded flags.
///
/// The first byte's low nibble is the field-length indicator (ignored); the high
/// nibble and following bytes carry capability bits. We expose four diagnostic bits
/// used by the stats summary. Returns `RsnxeInfo::default()` if the body is empty.
/// Per [IEEE 802.11-2024] §9.4.2.241.
#[must_use]
pub fn parse_rsnxe(value: &[u8]) -> RsnxeInfo {
    let mut info = RsnxeInfo::default();
    // Byte 0 carries bits 0..=7. Length nibble is bits 0..=3; capability bits start at bit 4.
    if let Some(&b0) = value.first() {
        info.sae_h2e = b0 & (1 << 5) != 0;
        info.sae_pk = b0 & (1 << 6) != 0;
    }
    // Byte 1 carries bits 8..=15. Secure LTF is bit 8; Protected TWT is bit 11.
    if let Some(&b1) = value.get(1) {
        info.secure_ltf = b1 & (1 << 0) != 0;
        info.protected_twt = b1 & (1 << 3) != 0;
    }
    info
}

/// Finds the RSN Extension IE (tag 244) in a tagged parameter block and parses it.
///
/// Returns `None` if no RSNXE is present. [IEEE 802.11-2024] §9.4.2.241.
#[must_use]
pub fn extract_rsnxe(tagged_params: &[u8]) -> Option<RsnxeInfo> {
    for ie in iter_ies(tagged_params) {
        if ie.id == IE_RSN_EXTENSION {
            return Some(parse_rsnxe(ie.value));
        }
    }
    None
}

// --- Assoc/Reassoc AKM classification ---

/// AKM suite flags extracted from an Association or Reassociation Request RSN IE.
///
/// Used to bucket assoc/reassoc frames into per-AKM stats counters. Covers crackable
/// and non-crackable AKMs so the operator can see the full security-mode distribution
/// of clients in the capture. Per [IEEE 802.11-2024] §9.4.2.24.3, Table 9-190.
#[allow(clippy::struct_excessive_bools, reason = "one flag per AKM category; not a state machine")]
#[derive(Debug, Default, Clone, Copy)]
pub struct AssocAkmFlags {
    /// AKM 2: WPA2-PSK (HMAC-SHA1 PMKID, PRF-SHA1 PTK).
    pub psk: bool,
    /// AKM 4 or 19 (union). Preserved for routing: FT family uses hashcat mode 37100.
    /// Prefer the hash-specific flags `ft_psk_sha256` / `ft_psk_sha384` for stats counters.
    pub ft_psk: bool,
    /// AKM 4 only: FT-PSK (SHA-256 PMKR0Name/PMKR1Name chain, AES-CMAC MIC).
    /// [IEEE 802.11-2024] §13.8.3, Table 9-190.
    pub ft_psk_sha256: bool,
    /// AKM 19 only: FT-PSK-SHA384 (SHA-384 key hierarchy, HMAC-SHA384 MIC).
    /// [IEEE 802.11-2024] §13.8.3, Table 9-190.
    pub ft_psk_sha384: bool,
    /// AKM 6 or 20 (union). Preserved for routing: both go to hashcat mode 22000 today
    /// but hashcat treats them differently. Prefer `psk_sha256` / `psk_sha384` for stats.
    pub psk_sha256: bool,
    /// AKM 6 only: PSK-SHA256 (KDF-SHA256 PTK, AES-CMAC MIC).
    pub psk_sha256_only: bool,
    /// AKM 20 only: PSK-SHA384 (KDF-SHA384 PTK, HMAC-SHA384 MIC). No hashcat module yet.
    pub psk_sha384: bool,
    /// AKM 8, 9, 24, or 25: WPA3-SAE / FT-SAE / SAE-EXT-KEY / FT-SAE-EXT-KEY.
    /// [IEEE 802.11-2024] §12.4, Table 9-190.
    pub sae: bool,
    /// AKM 18: OWE (Opportunistic Wireless Encryption).
    pub owe: bool,
    /// AKM 14, 15, 16, or 17: FILS-SHA256 / FILS-SHA384 / FT-FILS-SHA256 / FT-FILS-SHA384.
    /// [IEEE 802.11-2024] §12.11, Table 9-190.
    pub fils: bool,
    /// AKM 21: PASN (Pre-Association Security Negotiation).
    /// [IEEE 802.11-2024] §12.13, Table 9-190.
    pub pasn: bool,
    /// AKM 1 or 3: IEEE 802.1X / FT-802.1X using HMAC-SHA1-based PRF.
    /// [IEEE 802.11-2024] Table 9-190. Enterprise EAP family, legacy hash.
    pub enterprise_sha1: bool,
    /// AKM 5 or 11: IEEE 802.1X-SHA256 and 802.1X Suite B (SHA-256).
    /// [IEEE 802.11-2024] Table 9-190. Enterprise EAP family, SHA-256 hash.
    pub enterprise_sha256: bool,
    /// AKM 12, 13, 22, or 23: 802.1X Suite B (SHA-384), FT-802.1X-SHA384, and alt variants.
    /// [IEEE 802.11-2024] Table 9-190. Enterprise EAP family, SHA-384 hash.
    pub enterprise_sha384: bool,
    /// AKM 7: Tunneled Direct Link Setup (TDLS) peer-key derivation.
    /// [IEEE 802.11-2024] §12.7.5, Table 9-190.
    pub tdls: bool,
    /// AKM 10: AP Peer Key. Deprecated; reserved for historical 802.11 mesh variants.
    /// [IEEE 802.11-2024] Table 9-190.
    pub appeerkey: bool,
    /// An `00:0F:AC` AKM suite type outside the IEEE 802.11-2024 Table 9-190 enumeration
    /// (unknown / future / reserved). Prevents silent drops.
    pub akm_unknown: bool,
    /// First out-of-table AKM suite byte observed when `akm_unknown` is set.
    ///
    /// Surfaced so the ingest loop can pass it to `Logger::log_unknown_akm`. Only
    /// the first such byte per frame is recorded; if a single RSN IE lists multiple
    /// unknown AKMs the trailing ones are still bucketed via `akm_unknown` but only
    /// the first byte is logged. `None` when no unknown AKM was seen.
    pub first_unknown_akm: Option<u8>,
    /// Legacy WPA1 vendor IE (OUI `00:50:F2`, type 1) detected on the frame.
    /// WPA1 predates RSN and uses a vendor IE for its security suite; the inner
    /// AKM-2 selector is reused but the container signals WPA1-PSK-EAPOL (type 1
    /// in the 11-type taxonomy, ARCHITECTURE.md §2). Mutually exclusive with
    /// `psk` in well-formed Beacons but not enforced here.
    pub wpa1: bool,
}

/// Detects AKM suite flags from the RSN IE in a tagged parameter block.
///
/// Scans for the RSN IE (Element ID 48) and maps each `00:0F:AC` AKM suite type to a
/// flag in `AssocAkmFlags`. Includes SAE (8/24/25) and OWE (18) which the core `AkmType`
/// enum omits (out of v1 cracking scope). Called for each Assoc/Reassoc Request frame.
#[must_use]
pub fn detect_assoc_akm_flags(tagged_params: &[u8]) -> AssocAkmFlags {
    // WPA1 vendor IE (OUI 00:50:F2, type 1). Pre-RSN security mode; the IE
    // container itself signals WPA1, independent of the AKM-2 selector inside.
    const OUI_WFA: [u8; 3] = [0x00, 0x50, 0xF2];
    const WPA_IE_TYPE: u8 = 1;

    let mut flags = AssocAkmFlags::default();
    for ie in iter_ies(tagged_params) {
        if ie.id == 221 && vendor_ie_body(&ie, OUI_WFA, WPA_IE_TYPE).is_some() {
            flags.wpa1 = true;
            continue;
        }
        if ie.id == 48 {
            if let Some(akm_types) = parse_rsn_ie_raw_akm_types(ie.value) {
                for suite_type in akm_types {
                    match suite_type {
                        // Enterprise (802.1X / EAP) family, SHA-1-based PRFs.
                        // AKM 1 = 802.1X, AKM 3 = FT-802.1X. [Table 9-190]
                        1 | 3 => flags.enterprise_sha1 = true,
                        // AKM 2: WPA2-PSK (HMAC-SHA1 PMKID, PRF-SHA1 PTK; hashcat mode 22000).
                        2 => flags.psk = true,
                        // AKM 4: FT-PSK (SHA-256 chain; hashcat mode 37100).
                        4 => {
                            flags.ft_psk = true;
                            flags.ft_psk_sha256 = true;
                        },
                        // Enterprise SHA-256: AKM 5 = 802.1X-SHA256, AKM 11 = Suite B.
                        5 | 11 => flags.enterprise_sha256 = true,
                        // AKM 6: PSK-SHA256 (KDF-SHA256 PTK, AES-CMAC MIC; hashcat mode 22000).
                        6 => {
                            flags.psk_sha256 = true;
                            flags.psk_sha256_only = true;
                        },
                        // TDLS peer-key (AKM 7). [§12.7.5]
                        7 => flags.tdls = true,
                        // WPA3-SAE family including FT-SAE (9) and SAE-EXT-KEY (24, 25). [§12.4]
                        8 | 9 | 24 | 25 => flags.sae = true,
                        // APPeerKey (AKM 10) -- deprecated but still observable.
                        10 => flags.appeerkey = true,
                        // Enterprise SHA-384: AKM 12 (Suite B 384), 13 (FT-802.1X-SHA384),
                        // 22 (802.1X-SHA384), 23 (FT-802.1X-SHA384 alt). [Table 9-190]
                        12 | 13 | 22 | 23 => flags.enterprise_sha384 = true,
                        // FILS: AKM 14 (FILS-SHA256), 15 (FILS-SHA384),
                        // 16 (FT-FILS-SHA256), 17 (FT-FILS-SHA384). [§12.11, Table 9-190]
                        14..=17 => flags.fils = true,
                        18 => flags.owe = true,
                        // AKM 19: FT-PSK-SHA384 (no hashcat module; output suppressed).
                        19 => {
                            flags.ft_psk = true;
                            flags.ft_psk_sha384 = true;
                        },
                        // AKM 20: PSK-SHA384 (no hashcat module; output suppressed).
                        20 => {
                            flags.psk_sha256 = true;
                            flags.psk_sha384 = true;
                        },
                        // PASN: AKM 21 (Pre-Association Security Negotiation).
                        // [IEEE 802.11-2024] §12.13, Table 9-190.
                        21 => flags.pasn = true,
                        // Unknown / reserved / future AKM type -- never drop silently.
                        other => {
                            flags.akm_unknown = true;
                            if flags.first_unknown_akm.is_none() {
                                flags.first_unknown_akm = Some(other);
                            }
                        },
                    }
                }
            }
            // Only one RSN IE per frame [IEEE 802.11-2024] §9.4.2.24, but the
            // outer loop must keep walking IEs to find the WPA1 vendor IE if
            // present (mixed-mode WPA1+WPA2 beacons advertise both).
        }
    }
    flags
}

/// Parses an RSN IE value and returns raw AKM suite type bytes for OUI `00:0F:AC`.
///
/// Mirrors `parse_rsn_ie()` field-walking but returns raw `u8` type bytes so that
/// SAE (8, 24, 25) and OWE (18) -- which `AkmType` omits -- are preserved for stats.
/// Returns `None` on version mismatch; returns an empty `Vec` when the IE is truncated
/// before the AKM section. [IEEE 802.11-2024] §9.4.2.24.3
fn parse_rsn_ie_raw_akm_types(value: &[u8]) -> Option<Vec<u8>> {
    let mut pos = 0usize;
    let ver: [u8; 2] = value.get(pos..pos + 2).and_then(|s| s.try_into().ok())?;
    if u16::from_le_bytes(ver) != 1 {
        return None; // Version must be 1. [IEEE 802.11-2024] §9.4.2.24
    }
    pos += 2;
    if pos + 4 > value.len() {
        return Some(vec![]);
    }
    pos += 4; // Group Cipher Suite (4 bytes).
    if pos + 2 > value.len() {
        return Some(vec![]);
    }
    let pw_count = u16::from_le_bytes(value.get(pos..pos + 2).and_then(|s| s.try_into().ok())?) as usize;
    pos += 2 + pw_count * 4; // Skip pairwise count + list.
    if pos > value.len() {
        return Some(vec![]);
    }
    if pos + 2 > value.len() {
        return Some(vec![]);
    }
    let akm_count = u16::from_le_bytes(value.get(pos..pos + 2).and_then(|s| s.try_into().ok())?) as usize;
    pos += 2;
    let mut types: Vec<u8> = Vec::with_capacity(akm_count.min(16));
    for _ in 0..akm_count {
        if pos + 4 > value.len() {
            break;
        }
        let Some(suite) = value.get(pos..pos + 4) else { break };
        // Only collect IEEE 802.11 defined AKM suites (OUI 00:0F:AC). [Table 9-190]
        if suite.get(..3) == Some(&OUI_IEEE) {
            if let Some(&t) = suite.get(3) {
                types.push(t);
            }
        }
        pos += 4;
    }
    Some(types)
}

// --- Unit tests ---

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        missing_docs,
        clippy::wildcard_imports,
        clippy::cast_possible_truncation,
        reason = "test module"
    )]

    use super::*;

    // Builds a minimal RSN IE value reaching the AKM list.
    // Structure: Version(2) + GroupCipher(4) + PairwiseCount(2) + PairwiseSuite(4) + AkmCount(2) + AkmSuites(4*n)
    fn rsn_ie_with_akms(akm_types: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x01, 0x00]); // Version = 1
        v.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // Group cipher: CCMP
        v.extend_from_slice(&[0x01, 0x00]); // Pairwise count = 1
        v.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // CCMP pairwise
        let count = akm_types.len() as u16;
        v.extend_from_slice(&count.to_le_bytes()); // AKM count
        for &t in akm_types {
            v.extend_from_slice(&[0x00, 0x0F, 0xAC, t]); // AKM suite
        }
        v
    }

    // Appends RSN Capabilities + PMKID list after a base IE value.
    fn append_pmkids(base: &mut Vec<u8>, pmkids: &[[u8; 16]]) {
        base.extend_from_slice(&[0x00, 0x00]); // RSN Capabilities
        let count = pmkids.len() as u16;
        base.extend_from_slice(&count.to_le_bytes());
        for pmkid in pmkids {
            base.extend_from_slice(pmkid);
        }
    }

    #[test]
    fn parse_rsn_ie_psk_akm() {
        let ie = rsn_ie_with_akms(&[2]);
        let info = parse_rsn_ie(&ie).unwrap();
        assert_eq!(info.akm_types, vec![AkmType::Wpa2Psk]);
    }

    #[test]
    fn parse_rsn_ie_ft_psk_akm() {
        let ie = rsn_ie_with_akms(&[4]);
        let info = parse_rsn_ie(&ie).unwrap();
        assert_eq!(info.akm_types, vec![AkmType::FtPsk]);
    }

    #[test]
    fn parse_rsn_ie_psk_sha256() {
        let ie = rsn_ie_with_akms(&[6]);
        let info = parse_rsn_ie(&ie).unwrap();
        assert_eq!(info.akm_types, vec![AkmType::PskSha256]);
    }

    #[test]
    fn parse_rsn_ie_two_akms() {
        let ie = rsn_ie_with_akms(&[2, 4]);
        let info = parse_rsn_ie(&ie).unwrap();
        assert_eq!(info.akm_types, vec![AkmType::Wpa2Psk, AkmType::FtPsk]);
    }

    #[test]
    fn parse_rsn_ie_with_pmkid() {
        let mut ie = rsn_ie_with_akms(&[2]);
        let pmkid = [0xABu8; 16];
        append_pmkids(&mut ie, &[pmkid]);
        let info = parse_rsn_ie(&ie).unwrap();
        assert_eq!(info.pmkids.len(), 1);
        assert_eq!(info.pmkids[0], pmkid);
    }

    #[test]
    fn parse_rsn_ie_bad_version() {
        let mut ie = rsn_ie_with_akms(&[2]);
        // Overwrite the version bytes with version 2 -- must reject.
        ie[0] = 0x02;
        ie[1] = 0x00;
        assert!(parse_rsn_ie(&ie).is_none());
    }

    #[test]
    fn parse_rsn_ie_truncated_at_version() {
        // Only 1 byte -- can't read the 2-byte version field.
        assert!(parse_rsn_ie(&[0x01]).is_none());
    }

    #[test]
    fn parse_rsn_ie_truncated_at_pairwise() {
        // Version only (2 bytes) -- group cipher absent -> return empty RsnInfo.
        let ie = [0x01u8, 0x00];
        let info = parse_rsn_ie(&ie).unwrap();
        assert!(info.akm_types.is_empty());
        assert!(info.pmkids.is_empty());
    }

    #[test]
    fn detect_akm_finds_rsn() {
        // Build a tagged parameter block containing an RSN IE (id=48) with AKM PSK.
        let rsn_value = rsn_ie_with_akms(&[2]);
        let mut tagged = Vec::new();
        tagged.push(48u8); // Element ID
        tagged.push(rsn_value.len() as u8);
        tagged.extend_from_slice(&rsn_value);

        let akm = detect_akm(&tagged);
        assert_eq!(akm, AkmType::Wpa2Psk);
    }

    #[test]
    fn detect_akm_no_rsn_returns_unknown() {
        // Tagged params with only an SSID IE (id=0) -- no RSN, no WPA.
        let tagged = [0u8, 4, b't', b'e', b's', b't'];
        assert_eq!(detect_akm(&tagged), AkmType::Unknown);
    }

    #[test]
    fn parse_rsn_ie_akm_type_19_maps_to_ft_psk_sha384() {
        // FT-PSK-SHA384 (type 19) -> dedicated AkmType::FtPskSha384 variant.
        // Routing via AkmType::is_ft() keeps it on the 37100 path.
        let ie = rsn_ie_with_akms(&[19]);
        let info = parse_rsn_ie(&ie).unwrap();
        assert_eq!(info.akm_types, vec![AkmType::FtPskSha384]);
    }

    #[test]
    fn parse_rsn_ie_akm_type_20_maps_to_psk_sha384() {
        // PSK-SHA384 (type 20) -> dedicated AkmType::PskSha384 variant.
        let ie = rsn_ie_with_akms(&[20]);
        let info = parse_rsn_ie(&ie).unwrap();
        assert_eq!(info.akm_types, vec![AkmType::PskSha384]);
    }

    #[test]
    fn parse_rsn_ie_skips_sae_akm() {
        // SAE (type 8) is out of v1 scope -- must be skipped, not stored.
        let ie = rsn_ie_with_akms(&[8]);
        let info = parse_rsn_ie(&ie).unwrap();
        assert!(info.akm_types.is_empty());
    }

    #[test]
    fn extract_pmkids_from_tagged_params() {
        let pmkid = [0xCDu8; 16];
        let mut rsn_value = rsn_ie_with_akms(&[2]);
        append_pmkids(&mut rsn_value, &[pmkid]);
        let mut tagged = Vec::new();
        tagged.push(48u8);
        tagged.push(rsn_value.len() as u8);
        tagged.extend_from_slice(&rsn_value);

        let pmkids = extract_pmkids(&tagged);
        assert_eq!(pmkids.len(), 1);
        assert_eq!(pmkids[0], pmkid);
    }

    #[test]
    fn extract_pmkids_no_rsn_ie() {
        // No RSN IE in tagged params -> empty vec.
        let tagged = [0u8, 2, 0xAA, 0xBB];
        assert!(extract_pmkids(&tagged).is_empty());
    }

    #[test]
    fn parse_wpa_ie_psk_akm() {
        // WPA IE uses the same inner structure as RSN IE, version = 1.
        // The body passed here is what comes after the OUI+type prefix.
        let body = rsn_ie_with_akms(&[2]);
        let info = parse_wpa_ie(&body).unwrap();
        assert_eq!(info.akm_types, vec![AkmType::Wpa2Psk]);
    }

    #[test]
    fn detect_akm_via_wpa_vendor_ie_maps_to_wpa1() {
        // WPA vendor IE: tag=221, value= OUI(00:50:F2) + type(1) + rsn_body.
        // Inner format reuses AKM-2 selector for PSK, but the WPA1 vendor IE
        // container means this is WPA1-PSK-EAPOL (type 1), not WPA2-PSK-EAPOL.
        let rsn_body = rsn_ie_with_akms(&[2]);
        let mut tagged = Vec::new();
        tagged.push(221u8); // Vendor IE
        let ie_value_len = 4 + rsn_body.len(); // OUI(3) + type(1) + body
        tagged.push(ie_value_len as u8);
        tagged.extend_from_slice(&[0x00, 0x50, 0xF2, 0x01]); // OUI + type 1
        tagged.extend_from_slice(&rsn_body);

        let akm = detect_akm(&tagged);
        assert_eq!(akm, AkmType::Wpa1);
    }

    #[test]
    fn detect_akm_rsn_takes_precedence_over_wpa_vendor_ie() {
        // When both an RSN IE (id=48) and a WPA1 vendor IE (id=221) are present,
        // the RSN IE wins -- this is a WPA1+WPA2 mixed-mode beacon, and a STA
        // capable of WPA2 will use it. AkmType reports WPA2-PSK, not WPA1.
        let rsn_body = rsn_ie_with_akms(&[2]);
        let mut tagged = Vec::new();
        // RSN IE first.
        tagged.push(48u8);
        tagged.push(rsn_body.len() as u8);
        tagged.extend_from_slice(&rsn_body);
        // Then WPA1 vendor IE.
        tagged.push(221u8);
        let ie_value_len = 4 + rsn_body.len();
        tagged.push(ie_value_len as u8);
        tagged.extend_from_slice(&[0x00, 0x50, 0xF2, 0x01]);
        tagged.extend_from_slice(&rsn_body);

        let akm = detect_akm(&tagged);
        assert_eq!(akm, AkmType::Wpa2Psk);
    }

    // --- extract_pmkids_from_osen tests ---

    fn make_osen_ie_value(pmkids: &[[u8; 16]]) -> Vec<u8> {
        // Vendor IE value: OUI(3) + type(1) + RSN-body (same as RSN IE after version).
        let mut rsn_body = rsn_ie_with_akms(&[2]);
        append_pmkids(&mut rsn_body, pmkids);
        let mut value = vec![0x50, 0x6F, 0x9A, 0x12]; // OUI + OSEN type
        value.extend_from_slice(&rsn_body);
        value
    }

    #[test]
    fn extract_pmkids_from_osen_with_pmkid() {
        // Vendor IE with correct OSEN OUI/type and a PMKID -> extracted.
        let pmkid = [0xABu8; 16];
        let value = make_osen_ie_value(&[pmkid]);
        let pmkids = extract_pmkids_from_osen(&value);
        assert_eq!(pmkids.len(), 1);
        assert_eq!(pmkids[0], pmkid);
    }

    #[test]
    fn extract_pmkids_from_osen_wrong_oui() {
        // OUI mismatch (50:6F:9B) -> no extraction.
        let pmkid = [0xCDu8; 16];
        let mut value = make_osen_ie_value(&[pmkid]);
        value[2] = 0x9B; // corrupt last OUI byte
        let pmkids = extract_pmkids_from_osen(&value);
        assert!(pmkids.is_empty());
    }

    #[test]
    fn extract_pmkids_from_osen_wrong_type() {
        // Type mismatch (0x11 instead of 0x12) -> no extraction.
        let pmkid = [0xEFu8; 16];
        let mut value = make_osen_ie_value(&[pmkid]);
        value[3] = 0x11; // wrong type
        let pmkids = extract_pmkids_from_osen(&value);
        assert!(pmkids.is_empty());
    }

    #[test]
    fn extract_pmkids_from_osen_too_short() {
        // Value shorter than 4 bytes -> empty vec, no panic.
        assert!(extract_pmkids_from_osen(&[0x50, 0x6F]).is_empty());
    }

    #[test]
    fn extract_pmkids_from_osen_no_pmkid() {
        // Correct OUI/type but RSN body with no PMKIDs -> empty vec.
        let mut value = vec![0x50, 0x6F, 0x9A, 0x12];
        value.extend_from_slice(&rsn_ie_with_akms(&[2])); // no PMKIDs appended
        let pmkids = extract_pmkids_from_osen(&value);
        assert!(pmkids.is_empty());
    }

    // --- detect_assoc_akm_flags tests ---

    // Wraps an RSN IE value into a tagged parameter block (id=48 + len + value).
    fn tagged_with_rsn_akms(akm_types: &[u8]) -> Vec<u8> {
        let rsn_value = rsn_ie_with_akms(akm_types);
        let mut tagged = Vec::new();
        tagged.push(48u8);
        tagged.push(rsn_value.len() as u8);
        tagged.extend_from_slice(&rsn_value);
        tagged
    }

    #[test]
    fn assoc_akm_flags_psk_only() {
        // AKM 2 (PSK): only psk flag set
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[2]));
        assert!(flags.psk);
        assert!(!flags.ft_psk);
        assert!(!flags.psk_sha256);
        assert!(!flags.sae);
        assert!(!flags.owe);
    }

    #[test]
    fn assoc_akm_flags_ft_psk_type4() {
        // AKM 4 (FT-PSK)
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[4]));
        assert!(!flags.psk);
        assert!(flags.ft_psk);
    }

    #[test]
    fn assoc_akm_flags_psk_sha256_type6() {
        // AKM 6 (PSK-SHA256)
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[6]));
        assert!(flags.psk_sha256);
        assert!(!flags.psk);
    }

    #[test]
    fn assoc_akm_flags_sae_type8() {
        // AKM 8 (SAE/WPA3-Personal)
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[8]));
        assert!(flags.sae);
        assert!(!flags.psk);
    }

    #[test]
    fn assoc_akm_flags_owe_type18() {
        // AKM 18 (OWE)
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[18]));
        assert!(flags.owe);
    }

    #[test]
    fn assoc_akm_flags_combo_psk_and_ft() {
        // Dual-AKM frame advertising PSK (2) and FT-PSK (4) simultaneously
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[2, 4]));
        assert!(flags.psk);
        assert!(flags.ft_psk);
        assert!(!flags.psk_sha256);
        assert!(!flags.sae);
    }

    #[test]
    fn assoc_akm_flags_no_rsn_ie() {
        // Tagged params with only an SSID IE -- no RSN IE -> all flags false
        let tagged = [0u8, 4, b't', b'e', b's', b't'];
        let flags = detect_assoc_akm_flags(&tagged);
        assert!(!flags.psk && !flags.ft_psk && !flags.psk_sha256 && !flags.sae && !flags.owe);
        assert!(!flags.ft_psk_sha256 && !flags.ft_psk_sha384 && !flags.psk_sha256_only && !flags.psk_sha384);
        assert!(!flags.akm_unknown);
        assert!(!flags.fils && !flags.pasn);
        assert!(!flags.enterprise_sha1 && !flags.enterprise_sha256 && !flags.enterprise_sha384);
        assert!(!flags.tdls && !flags.appeerkey);
    }

    #[test]
    fn assoc_akm_flags_ft_sha384_type19() {
        // AKM 19 (FT-PSK-SHA384) -> ft_psk union flag AND ft_psk_sha384 fine-grained flag
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[19]));
        assert!(flags.ft_psk);
        assert!(flags.ft_psk_sha384);
        assert!(!flags.ft_psk_sha256, "AKM 19 must not set ft_psk_sha256");
    }

    #[test]
    fn assoc_akm_flags_ft_psk_type4_sets_sha256_only() {
        // AKM 4 (FT-PSK SHA-256 chain) -> ft_psk union flag + ft_psk_sha256 fine-grained.
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[4]));
        assert!(flags.ft_psk);
        assert!(flags.ft_psk_sha256);
        assert!(!flags.ft_psk_sha384, "AKM 4 must not set ft_psk_sha384");
    }

    #[test]
    fn assoc_akm_flags_sae_ext_key_type24() {
        // AKM 24 (SAE-EXT-KEY) -> sae flag
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[24]));
        assert!(flags.sae);
    }

    #[test]
    fn assoc_akm_flags_psk_sha384_type20() {
        // AKM 20 (PSK-SHA384) -> psk_sha256 union flag AND psk_sha384 fine-grained flag.
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[20]));
        assert!(flags.psk_sha256);
        assert!(flags.psk_sha384);
        assert!(!flags.psk_sha256_only, "AKM 20 must not set psk_sha256_only");
    }

    #[test]
    fn assoc_akm_flags_psk_sha256_type6_sets_only_flag() {
        // AKM 6 (PSK-SHA256) -> psk_sha256 union flag + psk_sha256_only fine-grained.
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[6]));
        assert!(flags.psk_sha256);
        assert!(flags.psk_sha256_only);
        assert!(!flags.psk_sha384, "AKM 6 must not set psk_sha384");
    }

    #[test]
    fn assoc_akm_flags_unknown_future_akm_type_26() {
        // AKM 26 and higher are reserved / not defined in IEEE 802.11-2024 Table 9-190.
        // They must set the akm_unknown bucket instead of silently dropping.
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[26]));
        assert!(flags.akm_unknown);
        assert_eq!(flags.first_unknown_akm, Some(26), "must surface the AKM byte for log_unknown_akm");
        assert!(!flags.psk && !flags.ft_psk && !flags.psk_sha256 && !flags.sae);
    }

    #[test]
    fn assoc_akm_flags_unknown_zero_suite_type() {
        // Suite type 0 is reserved; must fall into the unknown bucket.
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[0]));
        assert!(flags.akm_unknown);
        assert_eq!(flags.first_unknown_akm, Some(0));
    }

    #[test]
    fn assoc_akm_flags_unknown_plus_known_coexist() {
        // Dual-AKM frame with PSK (2) + an unknown future AKM (250): both buckets set.
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[2, 250]));
        assert!(flags.psk);
        assert!(flags.akm_unknown);
        assert_eq!(flags.first_unknown_akm, Some(250), "first unknown byte must be captured even after a known AKM");
    }

    #[test]
    fn assoc_akm_flags_first_unknown_only_records_first() {
        // When multiple unknown AKMs appear, only the FIRST is captured for logging;
        // trailing ones still set akm_unknown but are not stored individually.
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[200, 201, 202]));
        assert!(flags.akm_unknown);
        assert_eq!(flags.first_unknown_akm, Some(200));
    }

    #[test]
    fn assoc_akm_flags_empty_ies() {
        // Empty slice -> all flags false, no panic
        let flags = detect_assoc_akm_flags(&[]);
        assert!(!flags.psk && !flags.ft_psk && !flags.psk_sha256 && !flags.sae && !flags.owe);
        assert!(!flags.ft_psk_sha256 && !flags.ft_psk_sha384 && !flags.psk_sha256_only && !flags.psk_sha384);
        assert!(!flags.akm_unknown);
        assert!(!flags.fils && !flags.pasn);
        assert!(!flags.enterprise_sha1 && !flags.enterprise_sha256 && !flags.enterprise_sha384);
        assert!(!flags.tdls && !flags.appeerkey);
        assert!(!flags.wpa1);
    }

    // --- Tests for the expanded AKM enumeration ---

    #[test]
    fn assoc_akm_flags_enterprise_sha1_type1() {
        // AKM 1: 802.1X (HMAC-SHA1).
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[1]));
        assert!(flags.enterprise_sha1);
        assert!(!flags.psk && !flags.enterprise_sha256);
    }

    #[test]
    fn assoc_akm_flags_enterprise_sha1_type3_ft() {
        // AKM 3: FT-802.1X (SHA-1).
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[3]));
        assert!(flags.enterprise_sha1);
    }

    #[test]
    fn assoc_akm_flags_enterprise_sha256_type5() {
        // AKM 5: 802.1X-SHA256.
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[5]));
        assert!(flags.enterprise_sha256);
        assert!(!flags.enterprise_sha1 && !flags.enterprise_sha384);
    }

    #[test]
    fn assoc_akm_flags_enterprise_sha256_type11_suite_b() {
        // AKM 11: 802.1X Suite B (SHA-256).
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[11]));
        assert!(flags.enterprise_sha256);
    }

    #[test]
    fn assoc_akm_flags_enterprise_sha384_type12() {
        // AKM 12: 802.1X Suite B (SHA-384).
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[12]));
        assert!(flags.enterprise_sha384);
        assert!(!flags.enterprise_sha1 && !flags.enterprise_sha256);
    }

    #[test]
    fn assoc_akm_flags_enterprise_sha384_type13_ft() {
        // AKM 13: FT-802.1X-SHA384.
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[13]));
        assert!(flags.enterprise_sha384);
    }

    #[test]
    fn assoc_akm_flags_enterprise_sha384_type22() {
        // AKM 22: 802.1X-SHA384 (non-FT).
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[22]));
        assert!(flags.enterprise_sha384);
    }

    #[test]
    fn assoc_akm_flags_enterprise_sha384_type23_ft_alt() {
        // AKM 23: FT-802.1X-SHA384 (alt variant).
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[23]));
        assert!(flags.enterprise_sha384);
    }

    #[test]
    fn assoc_akm_flags_tdls_type7() {
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[7]));
        assert!(flags.tdls);
        assert!(!flags.psk);
    }

    #[test]
    fn assoc_akm_flags_wpa1_vendor_ie_sets_wpa1_only() {
        // WPA1 vendor IE (id=221, OUI 00:50:F2, type 1) carries an AKM-2
        // selector inside but the IE container signals WPA1-PSK-EAPOL.
        // detect_assoc_akm_flags must set `wpa1` and not also set `psk`
        // (which is reserved for the WPA2-PSK RSN IE id=48 path).
        let rsn_body = rsn_ie_with_akms(&[2]);
        let mut tagged = Vec::new();
        tagged.push(221u8);
        let ie_value_len = 4 + rsn_body.len();
        tagged.push(ie_value_len as u8);
        tagged.extend_from_slice(&[0x00, 0x50, 0xF2, 0x01]);
        tagged.extend_from_slice(&rsn_body);
        let flags = detect_assoc_akm_flags(&tagged);
        assert!(flags.wpa1, "WPA1 vendor IE must set wpa1 flag");
        assert!(!flags.psk, "WPA1 vendor IE must NOT set psk (RSN-AKM-2) flag");
    }

    #[test]
    fn assoc_akm_flags_wpa1_and_rsn_psk_coexist() {
        // Mixed-mode beacon: WPA1 vendor IE + RSN IE both present. wpa1 and
        // psk both set so the operator sees the dual-mode advertisement.
        let rsn_body = rsn_ie_with_akms(&[2]);
        let mut tagged = Vec::new();
        // RSN IE first.
        tagged.push(48u8);
        tagged.push(rsn_body.len() as u8);
        tagged.extend_from_slice(&rsn_body);
        // Then WPA1 vendor IE.
        tagged.push(221u8);
        let ie_value_len = 4 + rsn_body.len();
        tagged.push(ie_value_len as u8);
        tagged.extend_from_slice(&[0x00, 0x50, 0xF2, 0x01]);
        tagged.extend_from_slice(&rsn_body);
        let flags = detect_assoc_akm_flags(&tagged);
        assert!(flags.wpa1);
        assert!(flags.psk);
    }

    #[test]
    fn assoc_akm_flags_ft_sae_type9_now_counted() {
        // AKM 9 (FT-SAE) was previously unmatched; must now set the sae flag.
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[9]));
        assert!(flags.sae, "FT-SAE (AKM 9) must be counted as SAE");
    }

    #[test]
    fn assoc_akm_flags_appeerkey_type10() {
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[10]));
        assert!(flags.appeerkey);
        assert!(!flags.psk);
    }

    #[test]
    fn assoc_akm_flags_mixed_enterprise_and_psk() {
        // Real-world: dual-mode AP advertising 802.1X-SHA256 (enterprise) + PSK.
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[5, 2]));
        assert!(flags.enterprise_sha256);
        assert!(flags.psk);
    }

    #[test]
    fn assoc_akm_flags_fils_sha256_type14() {
        // AKM 14 (FILS-SHA256) -> fils flag
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[14]));
        assert!(flags.fils);
        assert!(!flags.psk && !flags.ft_psk && !flags.psk_sha256 && !flags.sae && !flags.owe);
        assert!(!flags.ft_psk_sha256 && !flags.ft_psk_sha384 && !flags.psk_sha256_only && !flags.psk_sha384);
        assert!(!flags.akm_unknown);
        assert!(!flags.pasn);
    }

    #[test]
    fn assoc_akm_flags_fils_sha384_type15() {
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[15]));
        assert!(flags.fils);
    }

    #[test]
    fn assoc_akm_flags_ft_fils_sha256_type16() {
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[16]));
        assert!(flags.fils);
    }

    #[test]
    fn assoc_akm_flags_ft_fils_sha384_type17() {
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[17]));
        assert!(flags.fils);
    }

    #[test]
    fn assoc_akm_flags_pasn_type21() {
        // AKM 21 (PASN) -> pasn flag
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[21]));
        assert!(flags.pasn);
        assert!(!flags.psk && !flags.ft_psk && !flags.psk_sha256 && !flags.sae && !flags.owe);
        assert!(!flags.ft_psk_sha256 && !flags.ft_psk_sha384 && !flags.psk_sha256_only && !flags.psk_sha384);
        assert!(!flags.akm_unknown);
        assert!(!flags.fils);
    }

    #[test]
    fn assoc_akm_flags_combo_psk_and_pasn() {
        // Dual-AKM frame advertising PSK (2) and PASN (21) simultaneously
        let flags = detect_assoc_akm_flags(&tagged_with_rsn_akms(&[2, 21]));
        assert!(flags.psk);
        assert!(flags.pasn);
    }

    // --- RSNXE (tag 244) tests ---

    #[test]
    fn rsnxe_empty_body_defaults_to_zero_flags() {
        let info = parse_rsnxe(&[]);
        assert!(!info.sae_h2e && !info.sae_pk && !info.secure_ltf && !info.protected_twt);
    }

    #[test]
    fn rsnxe_sae_h2e_only() {
        // Byte 0 bit 5 set -> SAE-H2E.
        let info = parse_rsnxe(&[0b0010_0000]);
        assert!(info.sae_h2e);
        assert!(!info.sae_pk && !info.secure_ltf && !info.protected_twt);
    }

    #[test]
    fn rsnxe_sae_pk_only() {
        // Byte 0 bit 6 set -> SAE-PK.
        let info = parse_rsnxe(&[0b0100_0000]);
        assert!(info.sae_pk);
        assert!(!info.sae_h2e);
    }

    #[test]
    fn rsnxe_sae_h2e_and_pk() {
        // Real WPA3-Personal router advertisement: H2E required + PK supported.
        let info = parse_rsnxe(&[0b0110_0000]);
        assert!(info.sae_h2e && info.sae_pk);
    }

    #[test]
    fn rsnxe_secure_ltf_on_byte1_bit0() {
        // Byte 1 bit 0 (global bit 8) set -> Secure LTF (11az Enhanced Ranging).
        let info = parse_rsnxe(&[0x00, 0b0000_0001]);
        assert!(info.secure_ltf);
        assert!(!info.protected_twt);
    }

    #[test]
    fn rsnxe_protected_twt_on_byte1_bit3() {
        // Byte 1 bit 3 (global bit 11) set -> Protected TWT.
        let info = parse_rsnxe(&[0x00, 0b0000_1000]);
        assert!(info.protected_twt);
        assert!(!info.secure_ltf);
    }

    #[test]
    fn rsnxe_ignores_length_nibble() {
        // Byte 0 low nibble (length) is ignored -- only high-nibble bits matter.
        // 0b0000_0011 (bits 0 and 1 set, both in length nibble) -> all flags false.
        let info = parse_rsnxe(&[0b0000_0011]);
        assert!(!info.sae_h2e && !info.sae_pk);
    }

    #[test]
    fn extract_rsnxe_from_tagged_params() {
        // Build a tagged-parameter block with a single RSNXE: tag=244, len=1, value=0b0110_0000.
        let tagged = [IE_RSN_EXTENSION, 1, 0b0110_0000];
        let info = extract_rsnxe(&tagged).unwrap();
        assert!(info.sae_h2e && info.sae_pk);
    }

    #[test]
    fn extract_rsnxe_absent_returns_none() {
        // Tagged block with only an SSID IE -- no RSNXE -> None.
        let tagged = [0u8, 4, b't', b'e', b's', b't'];
        assert!(extract_rsnxe(&tagged).is_none());
    }
}
