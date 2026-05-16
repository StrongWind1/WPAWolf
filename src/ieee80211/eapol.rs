// SPDX-License-Identifier: MIT
//! Phase 2 -- Decode: EAPOL-Key frame parser, M1/M2/M3/M4 classification per [IEEE 802.11-2024] §12.7.2. See ARCHITECTURE.md §5.
//!
//! Strips the LLC/SNAP header (DSAP=`0xAA`, SSAP=`0xAA`, Ctrl=`0x03`, OUI=`00:00:00`,
//! `EtherType`=`0x888E`), then parses the 4-byte EAPOL header and the EAPOL-Key body per
//! IEEE 802.11-2024 §12.7.2, Figure 12-35. Classifies frames as M1/M2/M3/M4 from the
//! Key Information bit fields: ACK (bit 7), MIC (bit 8), Secure (bit 9), Install (bit 6),
//! Encrypted Key Data (bit 12). No EAPOL frame-size limit is applied -- all valid frames
//! are stored regardless of byte length. Extracts PMKIDs from M1 Key Data KDEs and M2
//! Key Data RSN IEs.

use crate::ieee80211::frame::FrameDirection;
use crate::types::{MicBytes, MsgType, garbage_pattern_kind};

/// Width in bytes of the Key Nonce field. [IEEE 802.11-2024] §12.7.2
const NONCE_LEN: usize = 32;

// --- LLC/SNAP constants [IEEE 802.11-2012 Annex P, Table P-2] ---

/// DSAP byte in the LLC header: value `0xAA` (SNAP extension).
const DSAP: u8 = 0xAA;
/// SSAP byte in the LLC header: value `0xAA` (SNAP extension).
const SSAP: u8 = 0xAA;
/// LLC Control byte: value `0x03` (UI frame, unnumbered information).
const CTRL: u8 = 0x03;
/// High byte of the EAPOL `EtherType` `0x888E`. [IEEE 802.11-2012 Annex P, Table P-2]
const ETHERTYPE_EAPOL_HIGH: u8 = 0x88;
/// Low byte of the EAPOL `EtherType` `0x888E`. [IEEE 802.11-2012 Annex P, Table P-2]
const ETHERTYPE_EAPOL_LOW: u8 = 0x8E;
/// High byte of the IEEE 802.11 preauthentication `EtherType` `0x88C7`.
/// Used for inter-AP preauthentication frames carrying EAPOL over the DS prior to
/// roaming (extension to the wired 0x888E carrier). [IEEE 802.11-2024] §12.3.2
const ETHERTYPE_PREAUTH_HIGH: u8 = 0x88;
/// Low byte of the IEEE 802.11 preauthentication `EtherType` `0x88C7`.
const ETHERTYPE_PREAUTH_LOW: u8 = 0xC7;

// --- EAPOL header constants [IEEE 802.11-2024 §12.6.3] ---

/// EAPOL Packet Type 3: EAPOL-Key. Other types (0=EAP-Packet, 1=Start, 2=Logoff) are ignored.
const PACKET_TYPE_KEY: u8 = 3;

// --- EAPOL-Key Descriptor Type constants [IEEE 802.11-2024 §12.7.2 Table 12-7] ---

/// Descriptor Type 2: RSN (WPA2/WPA3). [IEEE 802.11-2024] §12.7.2 Table 12-7
const DESC_TYPE_RSN: u8 = 2;
/// Descriptor Type 254: Legacy WPA (WPA1). [IEEE 802.11-2024] §12.7.2 Table 12-7
const DESC_TYPE_WPA: u8 = 254;

// --- Offsets within the EAPOL frame (from EAPOL Protocol Version byte = offset 0 of eapol slice) ---

// EAPOL header: Protocol Version (1) + Packet Type (1) + Body Length (2) = 4 bytes.
// Not stored as a const because the header is consumed implicitly by the offset constants below.

/// Offset of the Key Descriptor Type byte within the EAPOL frame.
const OFF_DESC_TYPE: usize = 4;
/// Offset of the Key Information field (2 bytes, big-endian) within the EAPOL frame.
/// [IEEE 802.11-2024] §12.7.2, Figure 12-36
const OFF_KEY_INFO: usize = 5;
/// Offset of the Replay Counter (8 bytes, big-endian u64) within the EAPOL frame.
/// [IEEE 802.11-2024] §12.7.2
const OFF_REPLAY_CTR: usize = 9;
/// Offset of the Key Nonce (32 bytes) within the EAPOL frame.
/// `ANonce` in M1/M3; `SNonce` in M2/M4. [IEEE 802.11-2024] §12.7.2
const OFF_NONCE: usize = 17;
/// Offset of the Key MIC field within the EAPOL frame. Width is variable per AKM:
/// 16 bytes (AKMs 1-6, 8, 9, 11) or 24 bytes (AKMs 12, 13, 19, 20, 22, 23 -- the
/// SHA-384 / Suite-B family). [IEEE 802.11-2024] §12.7.2 Table 12-11
const OFF_MIC: usize = 81;
/// Offset of the Key Data Length field for a 16-byte MIC (AKMs 1-6, 8, 9, 11).
const OFF_KEY_DATA_LEN_16: usize = 97;
/// Offset of the Key Data payload for a 16-byte MIC.
const OFF_KEY_DATA_16: usize = 99;
/// Offset of the Key Data Length field for a 24-byte MIC (SHA-384 / Suite-B AKMs).
/// [IEEE 802.11-2024] §12.7.2 Table 12-11
const OFF_KEY_DATA_LEN_24: usize = 105;
/// Offset of the Key Data payload for a 24-byte MIC.
const OFF_KEY_DATA_24: usize = 107;
/// Body-length overhead (every byte except Key Data) for a 16-byte MIC frame:
/// `desc_type(1) + key_info(2) + key_length(2) + replay_ctr(8) + nonce(32) +
///  key_iv(16) + key_rsc(8) + reserved(8) + mic(16) + key_data_len(2)` = 95.
/// `body_len = 95 + key_data_len` for 16-B MIC EAPOL-Key frames.
const BODY_OVERHEAD_16: usize = 95;
/// Body-length overhead for a 24-byte MIC frame: `BODY_OVERHEAD_16 + 8` = 103.
/// `body_len = 103 + key_data_len` for SHA-384-family EAPOL-Key frames.
const BODY_OVERHEAD_24: usize = 103;
/// Minimum EAPOL-Key frame length for a 16-byte MIC: must reach at least the Key Data Length field.
const MIN_EAPOL_KEY_LEN_16: usize = 99;
/// Minimum EAPOL-Key frame length for a 24-byte MIC.
const MIN_EAPOL_KEY_LEN_24: usize = 107;
/// EAPOL-Key body length for WPA legacy M4 with no key data: exactly one WPA key descriptor.
/// hcxpcapngtool uses `authlen == 0x5f` to distinguish WPA M4 (Secure=0) from M2.
/// `[hcxpcapngtool.c: if(authlen != 0x5f) process_m2 else process_m4]`
const WPA_M4_BODY_LEN: usize = 95; // 0x5f

// --- LLC/SNAP header size ---

/// Length of the LLC/SNAP header prepended to every EAPOL frame body in 802.11 data frames.
const LLC_SNAP_LEN: usize = 8;

// --- Invalid field detection ---

/// Per-field invalid-value check result, returned by [`check_invalid_fields`].
///
/// Each field carries the kind of garbage pattern detected (`"null"`, `"ff"`,
/// `"repeat_1"`, `"repeat_2"`, `"repeat_4"` -- see [`garbage_pattern_kind`])
/// paired with the raw bytes that triggered the rejection, or `None` when
/// the field is structurally clean. Callers route the kind string into stats
/// counters and pass the bytes into the `[invalid_*]` log categories so the
/// rejected value is preserved as `nonce_hex=` / `mic_hex=` for forensic
/// traceability.
///
/// M1 NULL MIC is spec-valid and is **never** flagged here. M4 NULL nonce IS
/// flagged: although [IEEE 802.11-2024] §12.7.6.5 mandates an all-zero M4 Key
/// Nonce, an EAPOL hash line built from such an M4 carries no usable `SNonce`
/// and is mathematically uncrackable -- the live PTK was derived from M2's
/// `SNonce`, which the M4 frame does not carry. This matches hcxpcapngtool's
/// `eapolm4zeroedcount++; return;` gate at hcxpcapngtool.c:3636.
#[derive(Debug, Default, Clone, Copy)]
pub struct InvalidCheck {
    /// Garbage-pattern kind detected in the Key Nonce paired with the 32-byte
    /// nonce that triggered the rejection, or `None` when clean. NULL nonces
    /// are flagged on every message type including M4: spec §12.7.6.5 allows
    /// the wire bytes but the resulting EAPOL hash line cannot crack because
    /// the live PTK depends on M2's `SNonce`, which is not present in M4.
    pub nonce_garbage: Option<(&'static str, [u8; NONCE_LEN])>,
    /// Garbage-pattern kind detected in the Key MIC paired with the MIC bytes
    /// (16 or 24 wide per AKM) when the Key MIC flag (bit B8) is set, or
    /// `None` when clean. M1 frames have no MIC by spec and are never flagged
    /// here -- the gate is `key_mic_flag`, not `msg_type`.
    pub mic_garbage: Option<(&'static str, MicBytes)>,
    /// EAPOL-Key message classification computed from the same Key Information /
    /// body-length bits the parser later uses. `None` when the frame is not a
    /// valid EAPOL-Key (`ACK=0 MIC=0`) or when truncation prevents
    /// classification. Surfaced to callers so the operator-visible stats
    /// breakdown and the `[invalid_*]` log lines can distinguish M4 NULL nonce
    /// (spec-zero, expected, harmless) from M1 / M2 / M3 NULL nonce (abnormal,
    /// entropy starvation or firmware bug). The classification is informational
    /// -- the same garbage gate fires on every message type regardless.
    pub msg_type: Option<MsgType>,
}

/// Checks for invalid field values (NULL, `0xFF`, repeating patterns) in a raw frame body.
///
/// Call this on any frame body that has already passed the EAPOL `EtherType` check
/// before calling [`parse`]. Used by the caller to increment statistics counters for
/// frames that [`parse`] will reject, without duplicating the full parse logic.
///
/// Returns a zeroed [`InvalidCheck`] if `data` is too short or is not an EAPOL-Key frame.
#[must_use]
pub fn check_invalid_fields(data: &[u8]) -> InvalidCheck {
    // Require EAPOL-Key packet type (eapol[1] = 3). [IEEE 802.11-2024] §12.6.3
    if data.get(LLC_SNAP_LEN + 1) != Some(&PACKET_TYPE_KEY) {
        return InvalidCheck::default();
    }
    // Minimum length to reach Key Data Length (16-B MIC: data offset 105-106).
    if data.len() < LLC_SNAP_LEN + OFF_KEY_DATA_LEN_16 + 2 {
        return InvalidCheck::default();
    }

    // Key Information (BE u16) at eapol offset 5. [IEEE 802.11-2024] §12.7.2, Figure 12-36.
    // We extract every bit needed to classify the message type pre-parse so the
    // operator-visible counters and log lines can distinguish M4 NULL nonce
    // (spec-zero, expected) from M1 / M2 / M3 NULL nonce (abnormal). The flag /
    // body-length logic here mirrors what `parse()` does later; the MIC garbage
    // check is still gated on `key_mic_flag` because M1 carries no MIC.
    let ki = u16::from_be_bytes([
        *data.get(LLC_SNAP_LEN + OFF_KEY_INFO).unwrap_or(&0),
        *data.get(LLC_SNAP_LEN + OFF_KEY_INFO + 1).unwrap_or(&0),
    ]);
    let key_ack = (ki >> 7) & 1 != 0;
    let key_install = (ki >> 6) & 1 != 0;
    let key_mic_flag = (ki >> 8) & 1 != 0;
    let key_secure = (ki >> 9) & 1 != 0;

    // Body length (BE u16) at eapol offset 2-3. Used to disambiguate the MIC width:
    // 16-B MIC frames satisfy `body_len == 95 + key_data_len_16`; 24-B SHA-384 frames
    // satisfy `body_len == 103 + key_data_len_24`. [IEEE 802.11-2024] §12.6.3
    let body_len =
        u16::from_be_bytes([*data.get(LLC_SNAP_LEN + 2).unwrap_or(&0), *data.get(LLC_SNAP_LEN + 3).unwrap_or(&0)])
            as usize;
    let mic_width = detect_mic_width(data.get(LLC_SNAP_LEN..).unwrap_or(&[]), body_len);

    // Message-type classification by flags + body length (same heuristic as `parse()`).
    // Used purely to label the rejection in stats / log lines so the operator can
    // tell at a glance whether the dropped frame was a spec-zero M4 (expected) or
    // an abnormal NULL nonce on M1 / M2 / M3 (entropy starvation, firmware bug).
    let msg_type = classify_by_flags(key_ack, key_install, key_mic_flag, key_secure, body_len);

    // Nonce at eapol offset 17. [IEEE 802.11-2024] §12.7.2
    // Every garbage pattern flags on every message type. NULL on M4 is spec-valid
    // on the wire (§12.7.6.5) but cryptographically dead (the live PTK requires
    // M2's `SNonce`, which the M4 frame does not carry), so the line cannot crack
    // and is rejected like any other garbage. Matches hcxpcapngtool's
    // eapolm4zeroedcount drop at hcxpcapngtool.c:3636.
    let nonce_slice = data.get(LLC_SNAP_LEN + OFF_NONCE..LLC_SNAP_LEN + OFF_NONCE + NONCE_LEN);
    let nonce_garbage = nonce_slice.and_then(|s| {
        let arr: [u8; NONCE_LEN] = s.try_into().ok()?;
        garbage_pattern_kind(&arr).map(|kind| (kind, arr))
    });

    // MIC at eapol offset 81 with width 16 or 24. Only relevant when Key MIC flag
    // is set (M2/M3/M4). M1 MIC is legitimately NULL per spec and is never flagged.
    // [IEEE 802.11-2024] §12.7.2 Table 12-11
    let mic_slice = data.get(LLC_SNAP_LEN + OFF_MIC..LLC_SNAP_LEN + OFF_MIC + mic_width);
    let mic_garbage = if key_mic_flag {
        mic_slice.and_then(MicBytes::from_slice).and_then(|mb| mb.garbage_pattern_kind().map(|kind| (kind, mb)))
    } else {
        None
    };

    InvalidCheck { nonce_garbage, mic_garbage, msg_type }
}

// --- MIC width disambiguation ---

/// Picks the MIC width (16 or 24 bytes) consistent with the declared body length.
///
/// Per [IEEE 802.11-2024] §12.7.2 Table 12-11, MIC width is AKM-dependent. The wire
/// signal that disambiguates without consulting the negotiated AKM is the EAPOL Body
/// Length field at eapol offset 2-3:
///   16-B MIC frames satisfy `body_len == 95 + key_data_len_at_offset_97`
///   24-B MIC frames satisfy `body_len == 103 + key_data_len_at_offset_105`
///
/// When exactly one interpretation is consistent, that width is selected. When both
/// are consistent (rare collision), 16 is preferred for backward compatibility -- the
/// SHA-384 family always sets `body_len > 99`, so the 16-B candidate wins for any
/// frame that an existing AKM 1-6 deployment would emit. When neither is consistent
/// (firmware leaves `body_len` unset, captures truncated mid-frame), 16 is the safe
/// default that preserves the pre-SHA-384-aware parse behavior.
#[must_use]
fn detect_mic_width(eapol: &[u8], body_len: usize) -> usize {
    let frame_len = eapol.len();
    // Read candidate Key Data Length at each offset; degrade to 0 when out-of-range.
    let kd_len_16 = if frame_len >= MIN_EAPOL_KEY_LEN_16 {
        u16::from_be_bytes([
            *eapol.get(OFF_KEY_DATA_LEN_16).unwrap_or(&0),
            *eapol.get(OFF_KEY_DATA_LEN_16 + 1).unwrap_or(&0),
        ]) as usize
    } else {
        return 16;
    };
    let consistent_16 = body_len == BODY_OVERHEAD_16 + kd_len_16;
    if frame_len >= MIN_EAPOL_KEY_LEN_24 {
        let kd_len_24 = u16::from_be_bytes([
            *eapol.get(OFF_KEY_DATA_LEN_24).unwrap_or(&0),
            *eapol.get(OFF_KEY_DATA_LEN_24 + 1).unwrap_or(&0),
        ]) as usize;
        let consistent_24 = body_len == BODY_OVERHEAD_24 + kd_len_24;
        match (consistent_16, consistent_24) {
            // 16 wins on collision (backward compat); body_len missing or wrong -> fall back to 16.
            (false, true) => 24, // unambiguous SHA-384 frame
            (true, _) | (false, false) => 16,
        }
    } else {
        16
    }
}

// --- PMKID KDE constants [IEEE 802.11-2024] §12.7.2 ---

/// KDE type byte for vendor-specific (RSN-derived) KDEs.
const KDE_TYPE_VENDOR: u8 = 0xDD;
/// KDE length value for the PMKID KDE (20 = OUI 3 + KDE-type 1 + PMKID 16).
const KDE_PMKID_LEN: u8 = 0x14;
/// KDE sub-type for PMKID within the 00:0F:AC OUI. [IEEE 802.11-2024] §12.7.2
const KDE_PMKID_SUBTYPE: u8 = 0x04;

// --- Output type ---

/// A parsed EAPOL-Key frame extracted from an IEEE 802.11 data frame body.
///
/// The `eapol_frame` field contains the complete raw bytes starting from the EAPOL
/// header (not the LLC/SNAP header) with the Key MIC intact. At hash-line output time,
/// a copy with MIC zeroed at offset 81-96 is produced. No size limit is applied.
#[derive(Debug)]
pub struct EapolKey {
    /// M1, M2, M3, or M4 classification from Key Information bits.
    pub msg_type: MsgType,
    /// Key Descriptor Version (bits B0-B2 of Key Information).
    /// 1=HMAC-MD5+ARC4, 2=HMAC-SHA1+AES, 3=AES-CMAC+AES. [IEEE 802.11-2024] §12.7.2
    pub key_version: u8,
    /// EAPOL replay counter (8 bytes, big-endian). [IEEE 802.11-2024] §12.7.2
    pub replay_counter: u64,
    /// Key nonce: `ANonce` for M1/M3, `SNonce` for M2/M4. [IEEE 802.11-2024] §12.7.2
    pub nonce: [u8; 32],
    /// Key MIC: 16 bytes (AKMs 1-6, 8, 9, 11) or 24 bytes (AKMs 12, 13, 19, 20, 22, 23 --
    /// the SHA-384 / Suite-B family). Zero in M1; populated in M2/M3/M4.
    /// [IEEE 802.11-2024] §12.7.2 Table 12-11
    pub mic: MicBytes,
    /// Raw Key Data bytes (variable length). Used for PMKID extraction and RSN IE parsing.
    pub key_data: Vec<u8>,
    /// Complete raw EAPOL frame bytes (from EAPOL Protocol Version byte, not LLC/SNAP).
    /// MIC is intact here; the zeroed copy for hashcat is made at output time.
    /// No size limit applied -- stored regardless of frame length. [ARCHITECTURE.md §5]
    pub eapol_frame: Vec<u8>,
    /// PMKID from M1 Key Data KDE, if present.
    /// KDE: type=0xDD, len=0x14, OUI=00:0F:AC, type=0x04, 16-byte PMKID.
    pub pmkid: Option<[u8; 16]>,
    /// Whether this frame uses the RSN (WPA2/WPA3) key descriptor type (0x02).
    /// `false` means WPA legacy descriptor type (0xFE = 254). Used to determine
    /// whether to set the NC flag in the `message_pair` byte -- hcxpcapngtool does not
    /// set NC for WPA legacy descriptor frames. \[`hcxpcapngtool_hashtable.c:4186`\]
    pub is_rsn: bool,
    /// Key ACK flag (bit B7 of Key Information). True for AP-sent frames (M1/M3).
    /// Used for direction cross-check in the caller. [IEEE 802.11-2024] §12.7.2
    pub key_ack: bool,
}

// --- PMKID KDE scanner ---

/// Scans `key_data` for a PMKID KDE and returns the 16-byte PMKID if found.
///
/// PMKID KDEs appear in M1 Key Data per IEEE 802.11-2024 §12.7.2. The KDE format is:
/// `[0xDD] [len=0x14] [OUI: 00:0F:AC] [type: 0x04] [16-byte PMKID]`
///
/// The scan is linear and advances by the declared KDE length at each step, so
/// malformed length fields cause early termination rather than a panic.
fn extract_pmkid_kde(key_data: &[u8]) -> Option<[u8; 16]> {
    // Each KDE is: type (1) + length (1) + <length> bytes; total element = 2 + length.
    // A PMKID KDE has length=20 (0x14), so total size = 22.
    const KDE_TOTAL_MIN: usize = 22;
    const OUI_IEEE_80211: [u8; 3] = [0x00, 0x0F, 0xAC]; // [IEEE 802.11-2024] §12.7.2

    let mut pos = 0usize;
    while pos + KDE_TOTAL_MIN <= key_data.len() {
        let kde_type = key_data.get(pos).copied()?;
        let kde_len = key_data.get(pos + 1).copied()? as usize;

        if kde_type == KDE_TYPE_VENDOR
            && kde_len == usize::from(KDE_PMKID_LEN)
            && key_data.get(pos + 2..pos + 5) == Some(&OUI_IEEE_80211)
            && key_data.get(pos + 5).copied() == Some(KDE_PMKID_SUBTYPE)
        {
            // Bytes pos+6 .. pos+22 are the 16-byte PMKID.
            let pmkid: [u8; 16] = key_data.get(pos + 6..pos + 22)?.try_into().ok()?;
            return Some(pmkid);
        }

        // Advance past this KDE (type byte + length byte + declared payload).
        pos += 2 + kde_len;
    }
    None
}

// --- Flag-based classifier (Tier 3 fallback) ---

/// Classifies M1/M2/M3/M4 from Key Information flags only.
///
/// This is the hcxpcapngtool-compatible decision tree used as a fallback when frame
/// direction is unavailable (WDS relay frames). Returns `None` for invalid flag
/// combinations (ACK=0, MIC=0).
///
/// Decision tree:
///   ACK=1, Install=1 -> M3
///   ACK=1, Install=0 -> M1
///   ACK=0, MIC=0     -> invalid (None)
///   ACK=0, MIC=1, Secure=1 -> M4
///   ACK=0, MIC=1, Secure=0, body=95 -> M4 (WPA legacy)
///   ACK=0, MIC=1, Secure=0, body!=95 -> M2
///
/// \[hcxpcapngtool include/ieee80211.c:4 `getkeyinfo()`\]
const fn classify_by_flags(ack: bool, install: bool, mic: bool, secure: bool, body_len: usize) -> Option<MsgType> {
    match (ack, install) {
        (true, true) => Some(MsgType::M3),
        (true, false) => Some(MsgType::M1),
        (false, _) => match (mic, secure) {
            (false, _) => None,
            (true, true) => Some(MsgType::M4),
            (true, false) => {
                if body_len == WPA_M4_BODY_LEN {
                    Some(MsgType::M4)
                } else {
                    Some(MsgType::M2)
                }
            },
        },
    }
}

// --- Public parser ---

/// Parses an EAPOL-Key frame from the body of an IEEE 802.11 Data frame.
///
/// `data` is the frame body beginning immediately after the MAC header (at the
/// LLC/SNAP header). `direction` provides the frame transmitter role from the
/// MAC header's ToDS/FromDS bits. When direction is available, classification
/// uses the mathematically superior direction-based tree (Tier 1). When direction
/// is `None` (WDS relay or unknown), falls back to flag-based classification (Tier 3).
///
/// Returns `None` if:
/// - The LLC/SNAP `EtherType` is not `0x888E` (not EAPOL)
/// - The EAPOL Packet Type is not 3 (not EAPOL-Key)
/// - The Key Descriptor Type is not 2 (RSN) or 254 (WPA)
/// - The Key Information pattern does not match M1/M2/M3/M4
/// - The frame is shorter than the minimum EAPOL-Key frame (99 bytes from EAPOL start)
/// - Validation fails (MIC all-zero for M2/M3/M4, or Nonce all-zero for M1/M2/M3)
///
/// Parse failures return `None` (log-and-continue); I/O errors are not possible here.
#[must_use]
pub fn parse(data: &[u8], direction: Option<FrameDirection>) -> Option<EapolKey> {
    // --- 1. Strip and validate LLC/SNAP header (8 bytes) ---
    // DSAP, SSAP, and Control field must match SNAP encapsulation.
    // [IEEE 802.11-2012 Annex P, Table P-2]
    if data.first() != Some(&DSAP) || data.get(1) != Some(&SSAP) || data.get(2) != Some(&CTRL) {
        return None;
    }
    // OUI bytes 3-5 (00:00:00) are not enforced -- some implementations set non-zero values.
    // Only the EtherType gates further parsing. Accept both 0x888E (standard EAPOL) and
    // 0x88C7 (IEEE 802.11 preauthentication carrier per [IEEE 802.11-2024] §12.3.2).
    let et_high = data.get(6);
    let et_low = data.get(7);
    let is_eapol = et_high == Some(&ETHERTYPE_EAPOL_HIGH) && et_low == Some(&ETHERTYPE_EAPOL_LOW);
    let is_preauth = et_high == Some(&ETHERTYPE_PREAUTH_HIGH) && et_low == Some(&ETHERTYPE_PREAUTH_LOW);
    if !is_eapol && !is_preauth {
        return None;
    }

    // EAPOL frame starts immediately after the 8-byte LLC/SNAP header.
    let eapol = data.get(LLC_SNAP_LEN..)?;

    // --- 2. Validate EAPOL header ---
    // Byte 1 of the EAPOL header is the Packet Type. Only type 3 (EAPOL-Key) is handled.
    // [IEEE 802.11-2024] §12.6.3
    if eapol.get(1) != Some(&PACKET_TYPE_KEY) {
        return None;
    }
    // Ensure the buffer is long enough to contain the 16-B-MIC fixed-field set.
    // 24-B-MIC frames need 8 more bytes; that requirement is enforced after the
    // MIC width is determined below.
    if eapol.len() < MIN_EAPOL_KEY_LEN_16 {
        return None;
    }

    // --- 3. Parse EAPOL-Key body ---
    // Descriptor Type: must be RSN (2) or legacy WPA (254). [IEEE 802.11-2024] §12.7.2
    let desc_type = *eapol.get(OFF_DESC_TYPE)?;
    if desc_type != DESC_TYPE_RSN && desc_type != DESC_TYPE_WPA {
        return None;
    }

    // Key Information (2 bytes, big-endian). [IEEE 802.11-2024] §12.7.2, Figure 12-36
    let ki_bytes: [u8; 2] = eapol.get(OFF_KEY_INFO..OFF_KEY_INFO + 2).and_then(|s| s.try_into().ok())?;
    let ki = u16::from_be_bytes(ki_bytes); // big-endian per §12.7.2

    // Key Descriptor Version: bits B0-B2. Valid values: 0-3. [IEEE 802.11-2024] §12.7.2
    let key_desc_version = (ki & 0x0007) as u8;
    // Install flag: bit B6. [IEEE 802.11-2024] §12.7.2, Figure 12-36
    let install = (ki >> 6) & 1 != 0;
    // Key Ack flag: bit B7. [IEEE 802.11-2024] §12.7.2, Figure 12-36
    let key_ack = (ki >> 7) & 1 != 0;
    // Key MIC flag: bit B8. [IEEE 802.11-2024] §12.7.2, Figure 12-36
    let key_mic = (ki >> 8) & 1 != 0;
    // Secure flag: bit B9. [IEEE 802.11-2024] §12.7.2, Figure 12-36
    let secure = (ki >> 9) & 1 != 0;

    // Key Descriptor Version 0-3 are the only values defined. [IEEE 802.11-2024] §12.7.2
    if key_desc_version > 3 {
        return None;
    }

    // Replay Counter (8 bytes, big-endian). [IEEE 802.11-2024] §12.7.2
    let rc_bytes: [u8; 8] = eapol.get(OFF_REPLAY_CTR..OFF_REPLAY_CTR + 8).and_then(|s| s.try_into().ok())?;
    let replay_counter = u64::from_be_bytes(rc_bytes); // big-endian per §12.7.2

    // Key Nonce (32 bytes). ANonce in M1/M3, SNonce in M2/M4. [IEEE 802.11-2024] §12.7.2
    let nonce: [u8; 32] = eapol.get(OFF_NONCE..OFF_NONCE + 32).and_then(|s| s.try_into().ok())?;

    // EAPOL Body Length (u16, BE) at eapol offset 2-3. Drives the MIC-width detection
    // and is needed by the WPA M4 flag-based classifier. [IEEE 802.11-2024] §12.6.3
    let body_len_bytes_early: [u8; 2] = eapol.get(2..4).and_then(|s| s.try_into().ok()).unwrap_or([0u8; 2]);
    let declared_body_len_early = u16::from_be_bytes(body_len_bytes_early) as usize;

    // MIC width (16 or 24) decided from the wire body length. SHA-384 / Suite-B AKMs
    // (12, 13, 19, 20, 22, 23) carry a 24-byte MIC and shift Key Data Length to offset
    // 105. [IEEE 802.11-2024] §12.7.2 Table 12-11
    let mic_len = detect_mic_width(eapol, declared_body_len_early);
    let off_kd_len = if mic_len == 24 { OFF_KEY_DATA_LEN_24 } else { OFF_KEY_DATA_LEN_16 };
    let off_kd = if mic_len == 24 { OFF_KEY_DATA_24 } else { OFF_KEY_DATA_16 };

    // 24-B MIC frames need the larger fixed-field footprint to even contain the
    // Key Data Length. Reject truncated 24-B claims that lack 8 trailing bytes.
    if mic_len == 24 && eapol.len() < MIN_EAPOL_KEY_LEN_24 {
        return None;
    }

    // Key MIC (16 or 24 bytes). Zero in M1; non-zero in M2/M3/M4. [IEEE 802.11-2024] §12.7.2
    let mic_slice = eapol.get(OFF_MIC..OFF_MIC + mic_len)?;
    let mic = MicBytes::from_slice(mic_slice)?;

    // Key Data Length (u16, big-endian) and Key Data payload at the width-correct offsets.
    let kd_len_bytes: [u8; 2] = eapol.get(off_kd_len..off_kd_len + 2).and_then(|s| s.try_into().ok())?;
    // u16 always fits in usize on any supported platform (usize >= 16 bits).
    let kd_len = u16::from_be_bytes(kd_len_bytes) as usize;

    // Use the frame's declared Key Data Length, but tolerate truncated captures gracefully:
    // if the buffer is shorter than declared, use whatever bytes remain.
    // `unwrap_or_else` avoids eager evaluation of the fallback slice expression.
    let key_data = eapol.get(off_kd..off_kd + kd_len).unwrap_or_else(|| eapol.get(off_kd..).unwrap_or(&[])).to_vec();

    // --- 4. Classify M1/M2/M3/M4 ---
    //
    // Tiered classification using direction (from MAC header ToDS/FromDS) when available,
    // falling back to flag-based classification for WDS relay frames or unknown direction.
    //
    // Tier 1 -- Direction-based (for standard BSS data frames):
    //   AP->STA (FromAp): Install=1 -> M3, Install=0 -> M1
    //   STA->AP (FromSta): key_data_len > 0 -> M2, key_data_len == 0 -> M4
    //
    // Tier 3 -- Flag-based fallback (for WDS/unknown, matches hcxpcapngtool getkeyinfo()):
    //   ACK=1, Install=1 -> M3; ACK=1, Install=0 -> M1
    //   ACK=0, MIC=0 -> invalid; ACK=0, MIC=1, Secure=1 -> M4
    //   ACK=0, MIC=1, Secure=0, body=95 -> M4(WPA); else -> M2
    //
    // Direction from ToDS/FromDS is physics (set by radio hardware), not a flag that can
    // be mis-set by firmware. Install has zero exceptions across 2.6M real frames.
    // key_data_len > 0 has zero false positives for M2 (no M4 ever carries key data).
    //
    // [IEEE 802.11-2024] §12.7.2, §9.3.2.1.2
    let msg_type = match direction {
        Some(FrameDirection::FromAp) => {
            // Tier 1: AP transmitted. Install -> M1 vs M3.
            // Install has zero exceptions in 2.6M observed frames.
            // MIC flag is intentionally not checked -- some M3 frames have MIC_flag=0
            // but valid MIC bytes. [hcxpcapngtool getkeyinfo(): only ACK+Install]
            if install { MsgType::M3 } else { MsgType::M1 }
        },
        Some(FrameDirection::FromSta) => {
            // Tier 1: STA transmitted. Key Data presence -> M2 vs M4.
            // M2 must carry RSN IE (data_len > 0); M4 never carries key data.
            // Zero false positives for M2 across 2.6M observed frames.
            // This eliminates the unreliable Secure flag for M2/M4 discrimination.
            if kd_len > 0 { MsgType::M2 } else { MsgType::M4 }
        },
        _ => {
            // Tier 3: WDS/IBSS/unknown -- flag-based fallback.
            classify_by_flags(key_ack, install, key_mic, secure, declared_body_len_early)?
        },
    };

    // --- 5. Validate per-message requirements ---

    // MIC validation.
    // M1: no MIC per spec -- the NULL MIC in M1 is spec-valid and is NOT checked.
    // M2/M3/M4: MIC MUST carry no garbage pattern (NULL, all-0xFF, or short
    // repeating period). Width is variable (16 or 24 B) per AKM;
    // `MicBytes::garbage_pattern_kind` examines only the active prefix.
    // [IEEE 802.11-2024] §12.7.2 Table 12-11
    if matches!(msg_type, MsgType::M2 | MsgType::M3 | MsgType::M4) && mic.garbage_pattern_kind().is_some() {
        return None;
    }

    // Nonce validation.
    // Every garbage pattern (null, ff, repeat_1/2/4) rejects on every message type.
    // M4 NULL nonce is spec-valid on the wire per [IEEE 802.11-2024] §12.7.6.5 NOTE 9
    // (the spec mandates an all-zero M4 Key Nonce), but an EAPOL hash line built from
    // such an M4 carries no usable `SNonce`: the live PTK was derived from M2's `SNonce`,
    // which the M4 frame does not carry. Combining the M4 NULL with M3's ANonce in
    // an N3E4 line, or with M3's EAPOL body in an N4E3 line, yields a PTK input pair
    // (NULL, M3_ANonce) that does not reproduce the live PTK -- the line cannot crack
    // for any spec-compliant M4. Drop at extract so those dead lines are never built,
    // matching hcxpcapngtool's eapolm4zeroedcount drop at hcxpcapngtool.c:3636. The
    // rare non-conforming firmware that copies M2's `SNonce` into M4 still passes here
    // (non-NULL nonce -> no garbage pattern).
    // [IEEE 802.11-2024] §12.7.2, §12.7.6.5
    if garbage_pattern_kind(&nonce).is_some() {
        return None;
    }

    // --- 6. Extract PMKID from M1 Key Data KDE (if present) ---
    // PMKID KDEs are only expected in M1 frames. [IEEE 802.11-2024] §12.7.2
    let pmkid = if msg_type == MsgType::M1 { extract_pmkid_kde(&key_data) } else { None };

    // Store the EAPOL frame starting from the EAPOL Protocol Version byte (not LLC/SNAP).
    // Truncate to the declared body length to strip 802.11 frame-padding bytes appended
    // by some APs after the EAPOL payload. The declared length is the u16 BE value at
    // EAPOL header bytes 2-3 (Body Length field). [IEEE 802.11-2024] §12.6.3
    // The MIC is kept intact here; the zeroed-MIC copy for hashcat is made at output time.
    // [ARCHITECTURE.md §5]
    let body_len_bytes: [u8; 2] = eapol.get(2..4).and_then(|s| s.try_into().ok()).unwrap_or([0u8; 2]);
    let declared_body_len = u16::from_be_bytes(body_len_bytes) as usize;
    let frame_len = 4 + declared_body_len; // EAPOL header (4 bytes) + declared body
    // Truncate to declared length; fall back to full slice if declared length exceeds buffer.
    let eapol_frame = eapol.get(..frame_len).map_or_else(|| eapol.to_vec(), <[u8]>::to_vec);

    // RSN (WPA2/WPA3) descriptor type = 2; WPA legacy = 254. [IEEE 802.11-2024] §12.7.2
    let is_rsn = desc_type == DESC_TYPE_RSN;

    Some(EapolKey {
        msg_type,
        key_version: key_desc_version,
        replay_counter,
        nonce,
        mic,
        key_data,
        eapol_frame,
        pmkid,
        is_rsn,
        key_ack,
    })
}

/// Diagnoses why [`parse`] returned `None` for a frame that passed the LLC/packet-type gate.
///
/// Walks the same validation steps as [`parse`] and returns a short static string
/// naming the first failing constraint. Used at the `eapol_llc_invalid` logging
/// site to give the operator an exact rejection reason without duplicating the
/// full parse logic in the caller.
///
/// Returns `"garbage_nonce"` or `"garbage_mic"` for frames already counted by the
/// dedicated `null_nonce_rejected` / `null_mic_rejected` stats; the caller can
/// filter those to avoid redundant log entries.
#[must_use]
pub fn parse_rejection_reason(data: &[u8]) -> &'static str {
    // Steps mirror parse() in declaration order.
    if data.first() != Some(&DSAP) || data.get(1) != Some(&SSAP) || data.get(2) != Some(&CTRL) {
        return "bad_llc_header";
    }
    let et_high = data.get(6);
    let et_low = data.get(7);
    let is_eapol = et_high == Some(&ETHERTYPE_EAPOL_HIGH) && et_low == Some(&ETHERTYPE_EAPOL_LOW);
    let is_preauth = et_high == Some(&ETHERTYPE_PREAUTH_HIGH) && et_low == Some(&ETHERTYPE_PREAUTH_LOW);
    if !is_eapol && !is_preauth {
        return "bad_ethertype";
    }
    let Some(eapol) = data.get(LLC_SNAP_LEN..) else { return "truncated_at_llc" };
    if eapol.get(1) != Some(&PACKET_TYPE_KEY) {
        return "non_key_packet_type";
    }
    if eapol.len() < MIN_EAPOL_KEY_LEN_16 {
        return "truncated_short";
    }
    let desc_type = *eapol.get(OFF_DESC_TYPE).unwrap_or(&0);
    if desc_type != DESC_TYPE_RSN && desc_type != DESC_TYPE_WPA {
        return "bad_descriptor_type";
    }
    let ki: u16 = eapol
        .get(OFF_KEY_INFO..OFF_KEY_INFO + 2)
        .and_then(|s| <[u8; 2]>::try_from(s).ok())
        .map_or(0, u16::from_be_bytes);
    let key_desc_version = (ki & 0x0007) as u8;
    if key_desc_version > 3 {
        return "bad_kdv";
    }
    let body_len_bytes: [u8; 2] = eapol.get(2..4).and_then(|s| s.try_into().ok()).unwrap_or([0u8; 2]);
    let declared_body_len = u16::from_be_bytes(body_len_bytes) as usize;
    let mic_len = detect_mic_width(eapol, declared_body_len);
    if mic_len == 24 && eapol.len() < MIN_EAPOL_KEY_LEN_24 {
        return "truncated_24mic";
    }
    // Nonce and MIC slices are in-bounds after the MIN_EAPOL_KEY_LEN checks above
    // (nonce ends at offset 49, MIC at 97 for 16-B; both < 99 / 107).
    if let Some(nonce_arr) = eapol.get(OFF_NONCE..OFF_NONCE + NONCE_LEN).and_then(|s| <[u8; 32]>::try_from(s).ok()) {
        if garbage_pattern_kind(&nonce_arr).is_some() {
            return "garbage_nonce";
        }
    }
    let key_mic = (ki >> 8) & 1 != 0;
    if key_mic {
        if let Some(mic_slice) = eapol.get(OFF_MIC..OFF_MIC + mic_len) {
            if let Some(mb) = MicBytes::from_slice(mic_slice) {
                if mb.garbage_pattern_kind().is_some() {
                    return "garbage_mic";
                }
            }
        }
    }
    // Tier-3 (WDS/unknown direction) classify_by_flags returned None: ACK=0 MIC=0 is
    // the only unclassifiable combination. [IEEE 802.11-2024] §12.7.2
    "classify_flags_invalid"
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

    // --- Test helpers ---

    /// Builds a minimal valid EAPOL-Key frame with LLC/SNAP header for use in tests.
    ///
    /// The caller provides Key Information flag values, nonce, MIC, and optional extra
    /// Key Data bytes. Descriptor Type is set to RSN (2). Replay Counter is set to
    /// `0x0000_0000_0000_0001` unless overridden via the returned buffer.
    #[allow(clippy::fn_params_excessive_bools, reason = "test helper matching Key Information bit flags")]
    fn make_eapol(
        key_ack: bool,
        key_mic: bool,
        secure: bool,
        install: bool,
        nonce: [u8; 32],
        mic: [u8; 16],
        key_data_extra: &[u8],
    ) -> Vec<u8> {
        let mut ki: u16 = 0;
        // Key Descriptor Version: set to 2 (HMAC-SHA1 + AES-WRAP). bits B0-B2
        ki |= 2;
        if install {
            ki |= 1 << 6;
        } // bit B6
        if key_ack {
            ki |= 1 << 7;
        } // bit B7
        if key_mic {
            ki |= 1 << 8;
        } // bit B8
        if secure {
            ki |= 1 << 9;
        } // bit B9

        let kd_len = key_data_extra.len() as u16;
        let mut frame = Vec::with_capacity(8 + 99 + key_data_extra.len());

        // LLC/SNAP header (8 bytes) [IEEE 802.11-2012 Annex P, Table P-2]
        frame.extend_from_slice(&[
            0xAA, // DSAP
            0xAA, // SSAP
            0x03, // Control (UI)
            0x00, 0x00, 0x00, // OUI
            0x88, 0x8E, // EtherType = EAPOL
        ]);

        // EAPOL header (4 bytes)
        frame.push(0x02); // Protocol Version (ignored)
        frame.push(0x03); // Packet Type = EAPOL-Key
        let body_len = (95u16 + kd_len).to_be_bytes();
        frame.extend_from_slice(&body_len); // Body Length

        // EAPOL-Key body fixed fields
        frame.push(0x02); // Descriptor Type = RSN (2)
        frame.extend_from_slice(&ki.to_be_bytes()); // Key Information
        frame.extend_from_slice(&[0x00, 0x10]); // Key Length = 16
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // Replay Counter
        frame.extend_from_slice(&nonce); // Key Nonce (32)
        frame.extend_from_slice(&[0u8; 16]); // Key IV (ignored)
        frame.extend_from_slice(&[0u8; 8]); // Key RSC (ignored)
        frame.extend_from_slice(&[0u8; 8]); // Reserved
        frame.extend_from_slice(&mic); // Key MIC (16)
        frame.extend_from_slice(&kd_len.to_be_bytes()); // Key Data Length
        frame.extend_from_slice(key_data_extra); // Key Data

        frame
    }

    /// Returns a non-zero 32-byte nonce for use in tests.
    fn nonce_nonzero() -> [u8; 32] {
        let mut n = [0u8; 32];
        n[0] = 0xA5;
        n[31] = 0x5A;
        n
    }

    /// Returns a non-zero 16-byte MIC for use in tests.
    fn mic_nonzero() -> [u8; 16] {
        let mut m = [0u8; 16];
        m[0] = 0xDE;
        m[15] = 0xAD;
        m
    }

    // --- Tests ---

    #[test]
    fn parse_m1_valid() {
        let frame = make_eapol(true, false, false, false, nonce_nonzero(), [0u8; 16], &[]);
        let result = parse(&frame, None).unwrap();
        assert_eq!(result.msg_type, MsgType::M1);
        assert_eq!(result.key_version, 2);
        assert_eq!(result.nonce, nonce_nonzero());
        assert_eq!(result.mic, MicBytes::ZERO_16);
        assert!(result.pmkid.is_none());
    }

    #[test]
    fn parse_m1_with_pmkid() {
        // PMKID KDE: 0xDD 0x14 [00:0F:AC] 0x04 [16 bytes]
        let pmkid_val: [u8; 16] =
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let mut kde = Vec::new();
        kde.push(0xDD); // KDE type: vendor-specific
        kde.push(0x14); // KDE length = 20
        kde.extend_from_slice(&[0x00, 0x0F, 0xAC]); // OUI = 00:0F:AC
        kde.push(0x04); // KDE sub-type = PMKID
        kde.extend_from_slice(&pmkid_val);

        let frame = make_eapol(true, false, false, false, nonce_nonzero(), [0u8; 16], &kde);
        let result = parse(&frame, None).unwrap();
        assert_eq!(result.msg_type, MsgType::M1);
        assert_eq!(result.pmkid, Some(pmkid_val));
    }

    #[test]
    fn parse_m2_valid() {
        // M2 must have body_len > 95 to avoid the WPA-M4 heuristic.
        // A real M2 carries at least one RSN IE (tag 48 = 0x30), making body > 95 bytes.
        // [hcxpcapngtool.c: if(authlen != 0x5f) process_m2 else process_m4]
        let fake_ie = [0x30u8, 0x01, 0xFF]; // RSN IE tag + 1 byte body (minimal, non-empty)
        let frame = make_eapol(false, true, false, false, nonce_nonzero(), mic_nonzero(), &fake_ie);
        let result = parse(&frame, None).unwrap();
        assert_eq!(result.msg_type, MsgType::M2);
        assert_eq!(result.mic, MicBytes::from_16(mic_nonzero()));
        assert_eq!(result.nonce, nonce_nonzero());
        assert!(result.pmkid.is_none());
    }

    #[test]
    fn parse_wpa_m4_by_length() {
        // WPA legacy M4 has Ack=0, Secure=0, MIC=1, body_len=95 (no key data).
        // hcxpcapngtool identifies these as M4 via `authlen == 0x5f`.
        // Use a non-NULL nonce: NULL M4 is dropped at extract (§12.7.6.5 spec-valid
        // on the wire but cryptographically dead -- see parse()).
        let frame = make_eapol(false, true, false, false, nonce_nonzero(), mic_nonzero(), &[]);
        let result = parse(&frame, None).unwrap();
        assert_eq!(result.msg_type, MsgType::M4, "WPA M4 with body_len=95 must classify as M4");
    }

    #[test]
    fn parse_m3_valid() {
        let frame = make_eapol(true, true, true, true, nonce_nonzero(), mic_nonzero(), &[]);
        let result = parse(&frame, None).unwrap();
        assert_eq!(result.msg_type, MsgType::M3);
    }

    #[test]
    fn parse_m3_wpa1_secure_zero() {
        // WPA1/TKIP M3 has Secure=0 -- the handshake does not set Secure until M4.
        // Must be classified as M3 (Ack=1, MIC=1, Install=1). [IEEE 802.11-2024] §12.7.2
        let frame = make_eapol(true, true, false, true, nonce_nonzero(), mic_nonzero(), &[]);
        let result = parse(&frame, None).unwrap();
        assert_eq!(result.msg_type, MsgType::M3, "WPA1/TKIP M3 with Secure=0 must classify as M3");
    }

    #[test]
    fn parse_m3_mic_flag_zero() {
        // Some APs send M3 with Ack=1, Install=1, MIC_flag=0 but valid MIC bytes.
        // hcxpcapngtool getkeyinfo() classifies Ack=1+Install=1 as M3 regardless of MIC flag.
        // wpawolf must match this to avoid misclassifying these frames as M1.
        // [hcxpcapngtool include/ieee80211.c getkeyinfo(): only Ack and Install are checked]
        let frame = make_eapol(
            true,  // key_ack = 1
            false, // key_mic = 0 (MIC flag unset -- unusual but seen in the wild)
            false, // secure = 0
            true,  // install = 1 -> M3 per getkeyinfo()
            nonce_nonzero(),
            mic_nonzero(), // MIC BYTES are non-zero (frame is authenticated)
            &[],
        );
        let result = parse(&frame, None).unwrap();
        assert_eq!(result.msg_type, MsgType::M3, "Ack=1, Install=1, MIC_flag=0 must classify as M3");
    }

    #[test]
    fn parse_m4_valid_nonzero_nonce() {
        // M4 with non-NULL nonce (non-conforming per spec but seen in the wild).
        let frame = make_eapol(false, true, true, false, nonce_nonzero(), mic_nonzero(), &[]);
        let result = parse(&frame, None).unwrap();
        assert_eq!(result.msg_type, MsgType::M4);
        assert_eq!(result.nonce, nonce_nonzero());
    }

    #[test]
    fn parse_m4_null_nonce_rejected() {
        // M4 with all-NULL nonce is spec-valid on the wire per [IEEE 802.11-2024] §12.7.6.5
        // ("M4 Key Nonce SHALL be zero"), but an EAPOL hash line built from it cannot
        // crack -- the live PTK was derived from M2's `SNonce`, which the M4 frame does not
        // carry. Drop at extract to avoid emitting cryptographically dead N1E4 / N4E3 /
        // N3E4 lines, matching hcxpcapngtool's eapolm4zeroedcount drop at
        // hcxpcapngtool.c:3636.
        let frame = make_eapol(false, true, true, false, [0u8; 32], mic_nonzero(), &[]);
        assert!(parse(&frame, None).is_none(), "M4 with all-zero Key Nonce must be dropped at extract");
    }

    #[test]
    fn parse_m4_ff_nonce_rejected() {
        // M4 with all-0xFF nonce must be rejected (firmware sentinel, never spec-valid).
        let frame = make_eapol(false, true, true, false, [0xFF_u8; 32], mic_nonzero(), &[]);
        assert!(parse(&frame, None).is_none(), "M4 with all-0xFF nonce must be rejected");
    }

    #[test]
    fn parse_m1_ff_nonce_rejected() {
        // M1 with all-0xFF nonce must be rejected.
        let frame = make_eapol(true, false, false, false, [0xFFu8; 32], [0u8; 16], &[]);
        assert!(parse(&frame, None).is_none(), "M1 with all-0xFF nonce must be rejected");
    }

    #[test]
    fn parse_m2_ff_mic_rejected() {
        // M2 with all-0xFF MIC must be rejected.
        let frame = make_eapol(false, true, false, false, nonce_nonzero(), [0xFFu8; 16], &[]);
        assert!(parse(&frame, None).is_none(), "M2 with all-0xFF MIC must be rejected");
    }

    #[test]
    fn parse_m2_zero_mic_rejected() {
        let frame = make_eapol(false, true, false, false, nonce_nonzero(), [0u8; 16], &[]);
        assert!(parse(&frame, None).is_none(), "M2 with all-zero MIC must be rejected");
    }

    #[test]
    fn parse_m1_zero_nonce_rejected() {
        let frame = make_eapol(true, false, false, false, [0u8; 32], [0u8; 16], &[]);
        assert!(parse(&frame, None).is_none(), "M1 with all-zero nonce must be rejected");
    }

    #[test]
    fn parse_m1_repeat_byte_nonce_rejected() {
        // M1 nonce of all-`0x55` is `repeat_1` garbage -- firmware test stub,
        // not a cryptographic random nonce. Parser must reject.
        let frame = make_eapol(true, false, false, false, [0x55u8; 32], [0u8; 16], &[]);
        assert!(parse(&frame, None).is_none(), "M1 with all-`0x55` nonce must be rejected (repeat_1)");
    }

    #[test]
    fn parse_m1_period_2_nonce_rejected() {
        // 5555AAAA... 2-byte period is `repeat_2` garbage.
        let mut nonce = [0u8; 32];
        for chunk in nonce.chunks_exact_mut(2) {
            chunk[0] = 0x55;
            chunk[1] = 0xAA;
        }
        let frame = make_eapol(true, false, false, false, nonce, [0u8; 16], &[]);
        assert!(parse(&frame, None).is_none(), "M1 with 2-byte period nonce must be rejected (repeat_2)");
    }

    #[test]
    fn parse_m1_period_4_nonce_rejected() {
        // 01020304... 4-byte period is `repeat_4` garbage.
        let mut nonce = [0u8; 32];
        for chunk in nonce.chunks_exact_mut(4) {
            chunk[0] = 0x01;
            chunk[1] = 0x02;
            chunk[2] = 0x03;
            chunk[3] = 0x04;
        }
        let frame = make_eapol(true, false, false, false, nonce, [0u8; 16], &[]);
        assert!(parse(&frame, None).is_none(), "M1 with 4-byte period nonce must be rejected (repeat_4)");
    }

    #[test]
    fn parse_m2_repeat_byte_mic_rejected() {
        // M2 with all-`0xAB` MIC is `repeat_1` garbage. M2 MICs are HMAC outputs
        // (random); a uniform-byte MIC indicates a firmware stub.
        let frame = make_eapol(false, true, false, false, nonce_nonzero(), [0xABu8; 16], &[]);
        assert!(parse(&frame, None).is_none(), "M2 with all-`0xAB` MIC must be rejected (repeat_1)");
    }

    #[test]
    fn wrong_ethertype_returns_none() {
        let mut frame = make_eapol(true, false, false, false, nonce_nonzero(), [0u8; 16], &[]);
        // Corrupt the EtherType bytes (offsets 6-7 in the LLC/SNAP header).
        frame[6] = 0x08;
        frame[7] = 0x00; // EtherType 0x0800 = IPv4, not EAPOL
        assert!(parse(&frame, None).is_none());
    }

    #[test]
    fn not_eapol_key_returns_none() {
        let mut frame = make_eapol(true, false, false, false, nonce_nonzero(), [0u8; 16], &[]);
        // Offset 9 (LLC 8 + EAPOL byte 1) is the Packet Type.
        frame[9] = 0x00; // EAP-Packet, not EAPOL-Key
        assert!(parse(&frame, None).is_none());
    }

    #[test]
    fn bad_descriptor_type_returns_none() {
        let mut frame = make_eapol(true, false, false, false, nonce_nonzero(), [0u8; 16], &[]);
        // Offset 12 (LLC 8 + EAPOL header 4) = OFF_DESC_TYPE within eapol slice.
        frame[12] = 0x05; // invalid descriptor type
        assert!(parse(&frame, None).is_none());
    }

    #[test]
    fn too_short_returns_none() {
        // A 50-byte blob can't reach the minimum EAPOL-Key fixed fields (99 bytes from EAPOL start).
        let short = vec![0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];
        assert!(parse(&short, None).is_none());

        // Also test a buffer that is exactly too short for MIN_EAPOL_KEY_LEN.
        let mut frame = make_eapol(true, false, false, false, nonce_nonzero(), [0u8; 16], &[]);
        frame.truncate(8 + 50); // 8 LLC + 50 bytes of EAPOL, less than MIN_EAPOL_KEY_LEN
        assert!(parse(&frame, None).is_none());
    }

    /// Builds a SHA-384-family EAPOL-Key frame: 24-byte MIC, Key Data Length at offset 105.
    /// Used to exercise the MIC-width disambiguation path in `parse()`.
    /// [IEEE 802.11-2024] §12.7.2 Table 12-11
    #[allow(clippy::fn_params_excessive_bools, reason = "test helper matching Key Information bit flags")]
    fn make_eapol_24(
        key_ack: bool,
        key_mic: bool,
        secure: bool,
        install: bool,
        nonce: [u8; 32],
        mic: [u8; 24],
        key_data_extra: &[u8],
    ) -> Vec<u8> {
        let mut ki: u16 = 0; // KDV=0 (AKM-defined; SHA-384 family uses 0)
        if install {
            ki |= 1 << 6;
        }
        if key_ack {
            ki |= 1 << 7;
        }
        if key_mic {
            ki |= 1 << 8;
        }
        if secure {
            ki |= 1 << 9;
        }

        let kd_len = key_data_extra.len() as u16;
        let mut frame = Vec::with_capacity(8 + 107 + key_data_extra.len());
        // LLC/SNAP
        frame.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);
        // EAPOL header
        frame.push(0x02); // Protocol Version
        frame.push(0x03); // EAPOL-Key
        // Body length = 103 + kd_len for 24-B MIC
        let body_len = (103u16 + kd_len).to_be_bytes();
        frame.extend_from_slice(&body_len);
        // EAPOL-Key body fixed fields
        frame.push(0x02); // Descriptor Type = RSN
        frame.extend_from_slice(&ki.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x10]); // Key Length
        frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]); // Replay Counter
        frame.extend_from_slice(&nonce);
        frame.extend_from_slice(&[0u8; 16]); // Key IV
        frame.extend_from_slice(&[0u8; 8]); // Key RSC
        frame.extend_from_slice(&[0u8; 8]); // Reserved
        frame.extend_from_slice(&mic); // 24-byte MIC
        frame.extend_from_slice(&kd_len.to_be_bytes());
        frame.extend_from_slice(key_data_extra);
        frame
    }

    fn mic24_nonzero() -> [u8; 24] {
        let mut m = [0u8; 24];
        m[0] = 0xDE;
        m[8] = 0xAD;
        m[16] = 0xBE;
        m[23] = 0xEF;
        m
    }

    #[test]
    fn parse_sha384_m1_24_byte_mic() {
        // SHA-384 M1: KDV=0, 24-B MIC field, Key Data Length at offset 105.
        let frame = make_eapol_24(true, false, false, false, nonce_nonzero(), [0u8; 24], &[]);
        let result = parse(&frame, None).expect("SHA-384 M1 frame must parse");
        assert_eq!(result.msg_type, MsgType::M1);
        assert_eq!(result.mic.len(), 24, "MIC width must be 24 for SHA-384 frame");
        assert_eq!(result.mic, MicBytes::ZERO_24);
    }

    #[test]
    fn parse_sha384_m2_24_byte_mic_with_key_data() {
        // SHA-384 M2 with non-empty Key Data (RSN IE).
        let fake_ie = [0x30u8, 0x01, 0xFF];
        let frame = make_eapol_24(false, true, false, false, nonce_nonzero(), mic24_nonzero(), &fake_ie);
        let result = parse(&frame, None).expect("SHA-384 M2 frame must parse");
        assert_eq!(result.msg_type, MsgType::M2);
        assert_eq!(result.mic.len(), 24);
        assert_eq!(result.mic, MicBytes::from_24(mic24_nonzero()));
        assert_eq!(result.key_data, fake_ie, "Key Data must be sliced from offset 107, not 99");
    }

    #[test]
    fn parse_sha384_m2_zero_mic_rejected() {
        // 24-byte all-zero MIC must be rejected for M2.
        let fake_ie = [0x30u8, 0x01, 0xFF];
        let frame = make_eapol_24(false, true, false, false, nonce_nonzero(), [0u8; 24], &fake_ie);
        assert!(parse(&frame, None).is_none());
    }

    #[test]
    fn parse_sha384_m2_ff_mic_rejected() {
        let fake_ie = [0x30u8, 0x01, 0xFF];
        let frame = make_eapol_24(false, true, false, false, nonce_nonzero(), [0xFFu8; 24], &fake_ie);
        assert!(parse(&frame, None).is_none());
    }

    #[test]
    fn parse_preauth_ethertype_accepted() {
        // 0x88C7 (preauth) frames carry the same EAPOL-Key payload and must parse
        // identically to 0x888E. [IEEE 802.11-2024] §12.3.2
        let mut frame = make_eapol(true, false, false, false, nonce_nonzero(), [0u8; 16], &[]);
        frame[7] = 0xC7; // change EtherType low from 0x8E (EAPOL) to 0xC7 (preauth)
        let result = parse(&frame, None).expect("preauth EtherType must be accepted");
        assert_eq!(result.msg_type, MsgType::M1);
    }

    #[test]
    fn replay_counter_parsed_correctly() {
        let frame = make_eapol(true, false, false, false, nonce_nonzero(), [0u8; 16], &[]);
        let result = parse(&frame, None).unwrap();
        // make_eapol writes replay counter as 0x0000_0000_0000_0001.
        assert_eq!(result.replay_counter, 0x0000_0000_0000_0001u64);
    }

    #[test]
    fn replay_counter_large_value() {
        // Build a frame then manually patch the replay counter bytes.
        let mut frame = make_eapol(true, false, false, false, nonce_nonzero(), [0u8; 16], &[]);
        // Replay counter is at eapol offset 9, which is LLC(8) + 9 = frame byte 17.
        let rc: u64 = 0xDEAD_BEEF_0123_4567;
        let rc_bytes = rc.to_be_bytes();
        frame[17..25].copy_from_slice(&rc_bytes);
        let result = parse(&frame, None).unwrap();
        assert_eq!(result.replay_counter, rc);
    }

    #[test]
    fn eapol_frame_stored_without_llc_snap() {
        // The stored eapol_frame must start from the EAPOL header, not the LLC/SNAP.
        let frame = make_eapol(true, false, false, false, nonce_nonzero(), [0u8; 16], &[]);
        let result = parse(&frame, None).unwrap();
        // eapol_frame[0] = EAPOL Protocol Version (0x02 in make_eapol)
        // eapol_frame[1] = EAPOL Packet Type (0x03 = EAPOL-Key)
        assert_eq!(result.eapol_frame[0], 0x02);
        assert_eq!(result.eapol_frame[1], 0x03);
        // Total stored length: frame.len() - 8 (no LLC/SNAP).
        assert_eq!(result.eapol_frame.len(), frame.len() - 8);
    }

    #[test]
    fn eapol_frame_strips_802_11_padding() {
        // Some APs append zero-padding bytes after the EAPOL payload inside the 802.11 frame.
        // The stored eapol_frame must be truncated to the declared body length, not
        // include the trailing padding. [IEEE 802.11-2024] §12.6.3 Body Length field.
        let mut frame = make_eapol(true, false, false, false, nonce_nonzero(), [0u8; 16], &[]);
        // Append 8 bytes of 802.11 frame-padding after the EAPOL payload.
        frame.extend_from_slice(&[0xFFu8; 8]);
        let result = parse(&frame, None).unwrap();
        // Declared body length = 95; eapol_frame must be 4 + 95 = 99 bytes, not 107.
        assert_eq!(result.eapol_frame.len(), 4 + 95, "eapol_frame must not include 802.11 padding");
    }

    #[test]
    fn wpa_descriptor_type_accepted() {
        // Descriptor Type 254 (0xFE) = legacy WPA. Should parse identically to RSN.
        let mut frame = make_eapol(true, false, false, false, nonce_nonzero(), [0u8; 16], &[]);
        frame[12] = 0xFE; // Descriptor Type = WPA (254)
        let result = parse(&frame, None).unwrap();
        assert_eq!(result.msg_type, MsgType::M1);
    }

    #[test]
    fn pmkid_kde_not_extracted_from_m2() {
        // Even if M2 Key Data contains a PMKID KDE, pmkid field must be None.
        let pmkid_val: [u8; 16] = [0xAA; 16];
        let mut kde = Vec::new();
        kde.push(0xDD);
        kde.push(0x14);
        kde.extend_from_slice(&[0x00, 0x0F, 0xAC]);
        kde.push(0x04);
        kde.extend_from_slice(&pmkid_val);

        let frame = make_eapol(false, true, false, false, nonce_nonzero(), mic_nonzero(), &kde);
        let result = parse(&frame, None).unwrap();
        assert_eq!(result.msg_type, MsgType::M2);
        assert!(result.pmkid.is_none(), "PMKID should not be extracted from M2");
    }

    #[test]
    fn m3_zero_mic_rejected() {
        let frame = make_eapol(true, true, true, true, nonce_nonzero(), [0u8; 16], &[]);
        assert!(parse(&frame, None).is_none(), "M3 with all-zero MIC must be rejected");
    }

    #[test]
    fn m3_zero_nonce_rejected() {
        let frame = make_eapol(true, true, true, true, [0u8; 32], mic_nonzero(), &[]);
        assert!(parse(&frame, None).is_none(), "M3 with all-zero nonce must be rejected");
    }

    // --- Direction-based (Tier 1) classification tests ---

    #[test]
    fn direction_from_ap_install_false_is_m1() {
        // AP transmitted, Install=0 -> M1 regardless of other flags.
        let frame = make_eapol(true, false, false, false, nonce_nonzero(), [0u8; 16], &[]);
        let result = parse(&frame, Some(FrameDirection::FromAp)).unwrap();
        assert_eq!(result.msg_type, MsgType::M1);
        assert!(result.key_ack);
    }

    #[test]
    fn direction_from_ap_install_true_is_m3() {
        // AP transmitted, Install=1 -> M3 regardless of other flags.
        let frame = make_eapol(true, true, true, true, nonce_nonzero(), mic_nonzero(), &[]);
        let result = parse(&frame, Some(FrameDirection::FromAp)).unwrap();
        assert_eq!(result.msg_type, MsgType::M3);
    }

    #[test]
    fn direction_from_sta_with_key_data_is_m2() {
        // STA transmitted, key_data_len > 0 -> M2 regardless of Secure flag.
        let fake_ie = [0x30u8, 0x01, 0xFF];
        let frame = make_eapol(false, true, false, false, nonce_nonzero(), mic_nonzero(), &fake_ie);
        let result = parse(&frame, Some(FrameDirection::FromSta)).unwrap();
        assert_eq!(result.msg_type, MsgType::M2);
        assert!(!result.key_ack);
    }

    #[test]
    fn direction_from_sta_no_key_data_is_m4() {
        // STA transmitted, key_data_len == 0 -> M4 regardless of Secure flag.
        // Use a non-NULL nonce -- NULL M4 is dropped at extract (cryptographically dead).
        let frame = make_eapol(false, true, true, false, nonce_nonzero(), mic_nonzero(), &[]);
        let result = parse(&frame, Some(FrameDirection::FromSta)).unwrap();
        assert_eq!(result.msg_type, MsgType::M4);
        assert_eq!(result.nonce, nonce_nonzero());
    }

    #[test]
    fn direction_from_sta_rekey_m2_with_secure() {
        // STA transmitted, Secure=1, key_data_len > 0 -> M2 (rekey scenario).
        // Without direction, this would be misclassified as M4 by the flag-based tree.
        let fake_ie = [0x30u8, 0x01, 0xFF];
        let frame = make_eapol(false, true, true, false, nonce_nonzero(), mic_nonzero(), &fake_ie);
        // With direction: M2
        let with_dir = parse(&frame, Some(FrameDirection::FromSta)).unwrap();
        assert_eq!(with_dir.msg_type, MsgType::M2, "direction-based must classify rekey M2 correctly");
        // Without direction: M4 (flag-based sees Secure=1)
        let without_dir = parse(&frame, None).unwrap();
        assert_eq!(without_dir.msg_type, MsgType::M4, "flag-based misclassifies rekey M2 as M4");
    }

    #[test]
    fn direction_from_sta_wpa_m4_no_secure() {
        // STA transmitted, Secure=0, body_len=95, no key data -> M4.
        // Direction-based: kd_len=0 -> M4 (correct, no body_len heuristic needed).
        // Use a non-NULL nonce -- NULL M4 is dropped at extract (cryptographically dead).
        let frame = make_eapol(false, true, false, false, nonce_nonzero(), mic_nonzero(), &[]);
        let result = parse(&frame, Some(FrameDirection::FromSta)).unwrap();
        assert_eq!(result.msg_type, MsgType::M4, "direction-based correctly identifies WPA M4");
    }

    #[test]
    fn direction_wds_falls_back_to_flags() {
        // WDS direction -> falls through to flag-based Tier 3.
        let frame = make_eapol(true, false, false, false, nonce_nonzero(), [0u8; 16], &[]);
        let result = parse(&frame, Some(FrameDirection::Wds)).unwrap();
        assert_eq!(result.msg_type, MsgType::M1, "WDS falls back to flag-based (ACK=1, Install=0 -> M1)");
    }

    #[test]
    fn direction_none_falls_back_to_flags() {
        // None direction -> falls through to flag-based Tier 3.
        // Use a non-NULL nonce -- NULL M4 is dropped at extract (cryptographically dead).
        let frame = make_eapol(false, true, true, false, nonce_nonzero(), mic_nonzero(), &[]);
        let result = parse(&frame, None).unwrap();
        assert_eq!(result.msg_type, MsgType::M4, "None direction uses flag-based (Secure=1 -> M4)");
    }

    // --- classify_by_flags exhaustive tests ---

    #[test]
    fn classify_flags_ack_install_is_m3() {
        assert_eq!(classify_by_flags(true, true, true, true, 200), Some(MsgType::M3));
        // MIC and Secure are irrelevant when ACK+Install are both set.
        assert_eq!(classify_by_flags(true, true, false, false, 200), Some(MsgType::M3));
    }

    #[test]
    fn classify_flags_ack_no_install_is_m1() {
        assert_eq!(classify_by_flags(true, false, false, false, 200), Some(MsgType::M1));
        // MIC and Secure are irrelevant when ACK=1, Install=0.
        assert_eq!(classify_by_flags(true, false, true, true, 200), Some(MsgType::M1));
    }

    #[test]
    fn classify_flags_no_ack_no_mic_is_invalid() {
        assert_eq!(classify_by_flags(false, false, false, false, 200), None);
        assert_eq!(classify_by_flags(false, true, false, true, 200), None);
    }

    #[test]
    fn classify_flags_no_ack_mic_secure_is_m4() {
        assert_eq!(classify_by_flags(false, false, true, true, 200), Some(MsgType::M4));
    }

    #[test]
    fn classify_flags_no_ack_mic_no_secure_wpa_body_is_m4() {
        // body_len == 95 (WPA_M4_BODY_LEN) -> WPA legacy M4.
        assert_eq!(classify_by_flags(false, false, true, false, 95), Some(MsgType::M4));
    }

    #[test]
    fn classify_flags_no_ack_mic_no_secure_other_body_is_m2() {
        assert_eq!(classify_by_flags(false, false, true, false, 200), Some(MsgType::M2));
        assert_eq!(classify_by_flags(false, false, true, false, 99), Some(MsgType::M2));
    }
}
