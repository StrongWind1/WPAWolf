//! Phase 4 -- Emit: hashcat 22000 / 37100 hash-line formatter. See ARCHITECTURE.md §7.
//!
//! Produces the four hashcat hash-line types:
//! - `WPA*01*...` -- PMKID hash (mode 22000)
//! - `WPA*02*...` -- EAPOL handshake hash (mode 22000)
//! - `WPA*03*...` -- FT-PSK PMKID hash (mode 37100)
//! - `WPA*04*...` -- FT-PSK EAPOL handshake hash (mode 37100)
//!
//! All hex fields are lowercase. The EAPOL frame in the output has the MIC field
//! (bytes 81-96 from the start of the EAPOL header) zeroed, as required by hashcat.
//! No frame-size gating is applied -- all valid frames are emitted. See
//! `ARCHITECTURE.md §8` FR-OUT-*.

use crate::pair::PairedHash;
use crate::store::pmkid::PmkidEntry;
use crate::types::{FtFields, encode_hex};

// --- MIC zeroing ---

/// Returns a copy of `eapol_frame` with the Key MIC field set to all-zero bytes.
///
/// The Key MIC starts at byte 81 of the EAPOL frame and is 16 bytes wide for AKMs
/// 1-6, 8, 9, 11 or 24 bytes wide for AKMs 12, 13, 19, 20, 22, 23 (the SHA-384 /
/// Suite-B family). Hashcat requires the MIC to be cleared before computing the hash.
/// Per `ARCHITECTURE.md §5` and [IEEE 802.11-2024] §12.7.2 Table 12-11.
fn eapol_with_mic_zeroed(eapol_frame: &[u8], mic_len: usize) -> Vec<u8> {
    let mut frame = eapol_frame.to_vec();
    if let Some(mic_field) = frame.get_mut(81..81 + mic_len) {
        mic_field.fill(0);
    }
    frame
}

// --- Public formatters ---

/// Formats a PMKID entry as a `WPA*01*` hash line (hashcat mode 22000).
///
/// Format: `WPA*01*{pmkid}*{mac_ap}*{mac_sta}*{essid}*`
/// All hex fields are lowercase. The trailing `*` is required by hashcat.
/// An empty ESSID produces an empty field (`**` pair), which hashcat accepts.
/// See [hcxtools convention] and `ARCHITECTURE.md §8` FR-OUT-01.
#[must_use]
pub fn format_pmkid_22000(entry: &PmkidEntry, essid: &[u8]) -> String {
    format_pmkid_line(b"WPA*01*", entry, essid)
}

/// Formats a paired EAPOL handshake as a `WPA*02*` hash line (hashcat mode 22000).
///
/// Format: `WPA*02*{mic}*{mac_ap}*{mac_sta}*{essid}*{nonce}*{eapol_zeroed}*{msgpair}`
/// The MIC field carries the actual Key MIC extracted from the frame. The `eapol`
/// field carries the complete frame with the MIC zeroed at offset 81-96.
/// See [hcxtools convention] and `ARCHITECTURE.md §8` FR-OUT-02.
#[must_use]
pub fn format_eapol_22000(pair: &PairedHash, essid: &[u8]) -> String {
    format_eapol_line(b"WPA*02*", pair, essid)
}

/// Formats an FT-PSK PMKID entry as a `WPA*03*` hash line (hashcat mode 37100).
///
/// Format: `WPA*03*{pmkid}*{mac_ap}*{mac_sta}*{essid}***{mp}*{mdid}*{r0khid}*{r1khid}`
///
/// The `ft` argument must carry the MDID, R0KH-ID, and R1KH-ID extracted from the
/// EAPOL Key Data or the Association/Reassociation frame FT IEs. hashcat cannot crack
/// mode 37100 without these fields; the caller must only call this function when all
/// three are present. See `ARCHITECTURE.md §8` FR-OUT-03.
/// [hcxpcapngtool:2544-2554]
#[must_use]
pub fn format_pmkid_37100(entry: &PmkidEntry, ft: &FtFields, essid: &[u8]) -> String {
    format_pmkid_ft_line(b"WPA*03*", entry, ft, essid)
}

/// Same as `format_pmkid_37100` but with a caller-supplied line prefix.
///
/// Used by the new 11-type taxonomy sinks (`--ft-out`, `--ft-psk-sha384-out`, `-o`)
/// which write `WPA*06*` / `WPA*10*` instead of the legacy `WPA*03*`.
#[must_use]
pub fn format_pmkid_ft_line(prefix: &[u8], entry: &PmkidEntry, ft: &FtFields, essid: &[u8]) -> String {
    let mp = pmkid_message_pair(entry);
    let mut out: Vec<u8> = Vec::with_capacity(120 + essid.len() * 2 + usize::from(ft.r0khid_len) * 2);
    out.extend_from_slice(prefix);
    encode_hex(&entry.pmkid, &mut out);
    out.push(b'*');
    encode_hex(&entry.ap.0, &mut out);
    out.push(b'*');
    encode_hex(&entry.sta.0, &mut out);
    out.push(b'*');
    encode_hex(essid, &mut out);
    // "***{mp}*{mdid}*{r0khid}*{r1khid}"
    // Two empty fields (nonce, eapol) then mp, then FT fields.
    // [hcxpcapngtool:2551] "***%02x*%04x*" followed by r0khid, "*", r1khid
    out.extend_from_slice(b"***");
    encode_hex(&[mp], &mut out);
    out.push(b'*');
    encode_hex(&ft.mdid, &mut out); // 4 hex chars (2 bytes, BE as written)
    out.push(b'*');
    let r0len = usize::from(ft.r0khid_len).min(ft.r0khid.len());
    if let Some(r0) = ft.r0khid.get(..r0len) {
        encode_hex(r0, &mut out);
    }
    out.push(b'*');
    encode_hex(&ft.r1khid, &mut out);
    String::from_utf8(out).unwrap_or_default()
}

/// Formats an FT-PSK EAPOL handshake as a `WPA*04*` hash line (hashcat mode 37100).
///
/// Format: `WPA*04*{mic}*{mac_ap}*{mac_sta}*{essid}*{anonce}*{eapol_zeroed}*{mp}*{mdid}*{r0khid}*{r1khid}`
///
/// Requires FT fields from the EAPOL Key Data FTE subelements (R0KH-ID, R1KH-ID) and
/// the MDIE (MDID). hashcat cannot crack mode 37100 without these; caller must only
/// call this when `ft.r0khid_len > 0`. See `ARCHITECTURE.md §8` FR-OUT-04.
/// [hcxpcapngtool:2354-2373]
#[must_use]
pub fn format_eapol_37100(pair: &PairedHash, ft: &FtFields, essid: &[u8]) -> String {
    format_eapol_ft_line(b"WPA*04*", pair, ft, essid)
}

/// Same as `format_eapol_37100` but with a caller-supplied line prefix.
///
/// Used by the new 11-type taxonomy sinks (`--ft-out`, `--ft-psk-sha384-out`, `-o`)
/// which write `WPA*07*` / `WPA*11*` instead of the legacy `WPA*04*`.
#[must_use]
pub fn format_eapol_ft_line(prefix: &[u8], pair: &PairedHash, ft: &FtFields, essid: &[u8]) -> String {
    let zeroed = eapol_with_mic_zeroed(&pair.eapol_frame, pair.mic.len());
    let capacity = 150 + essid.len() * 2 + zeroed.len() * 2 + usize::from(ft.r0khid_len) * 2;
    let mut out: Vec<u8> = Vec::with_capacity(capacity);
    out.extend_from_slice(prefix);
    encode_hex(pair.mic.as_slice(), &mut out);
    out.push(b'*');
    encode_hex(&pair.ap.0, &mut out);
    out.push(b'*');
    encode_hex(&pair.sta.0, &mut out);
    out.push(b'*');
    encode_hex(essid, &mut out);
    out.push(b'*');
    encode_hex(&pair.nonce, &mut out);
    out.push(b'*');
    encode_hex(&zeroed, &mut out);
    // "*{mp}*{mdid}*{r0khid}*{r1khid}"
    // [hcxpcapngtool:2368] "*%02x*%04x*" followed by r0khid, "*", r1khid
    out.push(b'*');
    encode_hex(&[pair.message_pair], &mut out);
    out.push(b'*');
    encode_hex(&ft.mdid, &mut out);
    out.push(b'*');
    let r0len = usize::from(ft.r0khid_len).min(ft.r0khid.len());
    if let Some(r0) = ft.r0khid.get(..r0len) {
        encode_hex(r0, &mut out);
    }
    out.push(b'*');
    encode_hex(&ft.r1khid, &mut out);
    String::from_utf8(out).unwrap_or_default()
}

// --- Internal helpers ---

/// Maps a `PmkidSource` to the hashcat `message_pair` byte for PMKID lines.
///
/// Values from hcxpcapngtool `hcxpcapngtool.h` lines 386-390:
///   - Mode 22000 (non-FT): `PMKID_AP = 0x01`, `PMKID_APPSK256 = 0x02`, `PMKID_CLIENT = 0x04`.
///   - Mode 37100 (FT-PSK): `PMKID_AP_FTPSK = 0x10`, `PMKID_CLIENT_FTPSK = 0x20`.
///
/// hcxpcapngtool routes the same PMKID through different `addpmkid` /
/// `addpmkid_ftpsk` paths depending on the AKM at extract time, so the
/// status byte that surfaces in the output line is always the right kind
/// for the line's prefix (`WPA*01*` vs `WPA*03*`). wpawolf reuses one
/// `PmkidEntry` across both sinks, so this function inspects `entry.akm`
/// to pick the FT-PSK pair when emitting a `WPA*03*` / mode 37100 line.
///
/// New sources use the same AP/client convention from the source-map table
/// in `ARCHITECTURE.md §6`.
const fn pmkid_message_pair(entry: &PmkidEntry) -> u8 {
    use crate::types::PmkidSource;
    let is_ft = entry.akm.is_ft();
    match entry.source {
        // AP-side sources: M1 KDE, assoc frames, AP-sent auth responses,
        // AP-originated mgmt frames (Beacon, ProbeResp), FT Action Response.
        // hcx: PMKID_AP=0x01 in mode 22000, PMKID_AP_FTPSK=0x10 in mode 37100.
        PmkidSource::M1KeyData
        | PmkidSource::AssocRequest
        | PmkidSource::ReassocRequest
        | PmkidSource::FtAuthApToSta
        | PmkidSource::FilsAuthApToSta
        | PmkidSource::PasnAuthApToSta
        | PmkidSource::FtActionResponse
        | PmkidSource::BeaconRsnIe
        | PmkidSource::ProbeRespRsnIe => {
            if is_ft {
                0x10
            } else {
                0x01
            }
        },
        // Client-side sources: M2 RSN IE, STA-sent auth, probe req,
        // FT Action Request/Confirm, Mesh Peering, OSEN.
        // hcx: PMKID_CLIENT=0x04 in mode 22000, PMKID_CLIENT_FTPSK=0x20 in mode 37100.
        PmkidSource::M2RsnIe
        | PmkidSource::FtAuthStaToAp
        | PmkidSource::FilsAuthStaToAp
        | PmkidSource::PasnAuthStaToAp
        | PmkidSource::FtActionRequest
        | PmkidSource::FtActionConfirm
        | PmkidSource::ProbeRequest
        | PmkidSource::MeshPeeringOpen
        | PmkidSource::MeshPeeringConfirm
        | PmkidSource::OsenIe => {
            if is_ft {
                0x20
            } else {
                0x04
            }
        },
    }
}

/// Builds a PMKID hash line with the given prefix byte string.
///
/// Shared by `format_pmkid_22000`, `format_pmkid_37100`, and the new 11-type taxonomy
/// sinks (`--wpa1-out`, `--wpa2-out`, `--psk-sha256-out`, `--psk-sha384-out`, `-o` for
/// non-FT rows). The prefix selects the hashcat-line type; all other fields are
/// identical. Uses `encode_hex` to write directly into the output buffer so no
/// intermediate allocations are needed per field.
#[must_use]
pub fn format_pmkid_line(prefix: &[u8], entry: &PmkidEntry, essid: &[u8]) -> String {
    // Format: WPA*01*{pmkid}*{mac_ap}*{mac_sta}*{essid}***{mp:02x}
    // The two empty fields (nonce + eapol) are present but empty, giving "***" before mp.
    // [hcxpcapngtool.c:2523] fprintf(fh_pmkideapol, "***%02x\n", zeigerpmkid->status)
    let mp = pmkid_message_pair(entry);
    let mut out: Vec<u8> = Vec::with_capacity(71 + essid.len() * 2);
    out.extend_from_slice(prefix);
    encode_hex(&entry.pmkid, &mut out);
    out.push(b'*');
    encode_hex(&entry.ap.0, &mut out);
    out.push(b'*');
    encode_hex(&entry.sta.0, &mut out);
    out.push(b'*');
    encode_hex(essid, &mut out);
    // Three separators: end-of-essid, end-of-empty-nonce, end-of-empty-eapol, then mp.
    // [hcxpcapngtool.c:2523] fprintf(..., "***%02x\n", status) appended after essid field.
    out.extend_from_slice(b"***");
    encode_hex(&[mp], &mut out);
    // encode_hex writes only ASCII bytes from HEX_TABLE (b"0123456789abcdef").
    // from_utf8 cannot fail; unwrap_or_default returns "" on the unreachable Err branch.
    String::from_utf8(out).unwrap_or_default()
}

/// Builds an EAPOL hash line with the given prefix byte string.
///
/// Shared by `format_eapol_22000`, `format_eapol_37100`, and the new 11-type
/// taxonomy sinks (non-FT rows). The EAPOL frame is copied and the MIC bytes zeroed
/// before hex-encoding; the original `PairedHash` is not modified. `message_pair`
/// is encoded as exactly two hex characters.
#[must_use]
pub fn format_eapol_line(prefix: &[u8], pair: &PairedHash, essid: &[u8]) -> String {
    let zeroed = eapol_with_mic_zeroed(&pair.eapol_frame, pair.mic.len());
    // WPA*02*: 7 + (32 or 48) + 1 + 12 + 1 + 12 + 1 + essid*2 + 1 + 64 + 1 + eapol*2 + 1 + 2
    let capacity = 135 + pair.mic.len() * 2 + essid.len() * 2 + zeroed.len() * 2;
    let mut out: Vec<u8> = Vec::with_capacity(capacity);
    out.extend_from_slice(prefix);
    encode_hex(pair.mic.as_slice(), &mut out);
    out.push(b'*');
    encode_hex(&pair.ap.0, &mut out);
    out.push(b'*');
    encode_hex(&pair.sta.0, &mut out);
    out.push(b'*');
    encode_hex(essid, &mut out);
    out.push(b'*');
    encode_hex(&pair.nonce, &mut out);
    out.push(b'*');
    encode_hex(&zeroed, &mut out);
    out.push(b'*');
    // message_pair as exactly 2 hex characters (one byte).
    encode_hex(&[pair.message_pair], &mut out);
    // encode_hex writes only ASCII bytes from HEX_TABLE (b"0123456789abcdef").
    // from_utf8 cannot fail; unwrap_or_default returns "" on the unreachable Err branch.
    String::from_utf8(out).unwrap_or_default()
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
        reason = "test module"
    )]

    use std::sync::Arc;

    use super::*;
    use crate::pair::{ComboType, PairedHash};
    use crate::store::pmkid::PmkidEntry;
    use crate::types::{AkmType, MacAddr, MicBytes, PmkidSource};

    // --- Test helpers ---

    fn make_pmkid_entry(ap: [u8; 6], sta: [u8; 6], pmkid: [u8; 16]) -> PmkidEntry {
        PmkidEntry {
            timestamp: 0,
            ap: MacAddr::from_bytes(ap),
            sta: MacAddr::from_bytes(sta),
            pmkid,
            source: PmkidSource::M1KeyData,
            akm: AkmType::Wpa2Psk,
            ft: None,
        }
    }

    fn make_paired_hash(
        ap: [u8; 6],
        sta: [u8; 6],
        mic: [u8; 16],
        nonce: [u8; 32],
        eapol_frame: Vec<u8>,
        message_pair: u8,
    ) -> PairedHash {
        PairedHash {
            ap: MacAddr::from_bytes(ap),
            sta: MacAddr::from_bytes(sta),
            combo_type: ComboType::N1E2,
            nonce,
            eapol_frame: Arc::from(eapol_frame),
            mic: MicBytes::from_16(mic),
            message_pair,
            akm: AkmType::Wpa2Psk,
            ft: None,
            rc_gap_magnitude: 0,
        }
    }

    fn make_paired_hash_24(
        ap: [u8; 6],
        sta: [u8; 6],
        mic: [u8; 24],
        nonce: [u8; 32],
        eapol_frame: Vec<u8>,
        message_pair: u8,
        akm: AkmType,
    ) -> PairedHash {
        PairedHash {
            ap: MacAddr::from_bytes(ap),
            sta: MacAddr::from_bytes(sta),
            combo_type: ComboType::N1E2,
            nonce,
            eapol_frame: Arc::from(eapol_frame),
            mic: MicBytes::from_24(mic),
            message_pair,
            akm,
            ft: None,
            rc_gap_magnitude: 0,
        }
    }

    // --- MIC-zeroing ---

    #[test]
    fn eapol_with_mic_zeroed_short_frame() {
        // Frames shorter than 97 bytes must not panic; zeroing is skipped.
        let frame = vec![0xFFu8; 80];
        let result = eapol_with_mic_zeroed(&frame, 16);
        assert_eq!(result, frame, "short frame must be returned unchanged");
    }

    #[test]
    fn eapol_with_mic_zeroed_exact_boundary() {
        // Frame of exactly 97 bytes: bytes 81-96 (indices 81..97) should be zero.
        let frame = vec![0xFFu8; 97];
        let result = eapol_with_mic_zeroed(&frame, 16);
        assert!(result[..81].iter().all(|&b| b == 0xFF));
        assert!(result[81..97].iter().all(|&b| b == 0x00));
    }

    #[test]
    fn eapol_with_mic_zeroed_longer_frame() {
        // Only the 16-byte MIC window must be zeroed; surrounding bytes unchanged.
        let frame = vec![0xFFu8; 200];
        let result = eapol_with_mic_zeroed(&frame, 16);
        assert!(result[..81].iter().all(|&b| b == 0xFF));
        assert!(result[81..97].iter().all(|&b| b == 0x00));
        assert!(result[97..].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn eapol_with_mic_zeroed_24_byte_window() {
        // SHA-384-family frame: 24-byte MIC at offset 81..105 must be zeroed,
        // and bytes outside that window must be preserved untouched.
        let frame = vec![0xFFu8; 200];
        let result = eapol_with_mic_zeroed(&frame, 24);
        assert!(result[..81].iter().all(|&b| b == 0xFF));
        assert!(result[81..105].iter().all(|&b| b == 0x00), "24 B MIC window must be zero");
        assert!(result[105..].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn format_eapol_22000_emits_24_byte_mic() {
        // SHA-384 frame: MIC field in the line should be 48 hex chars (24 bytes),
        // and the eapol field's MIC window should be zeroed across all 24 bytes.
        let frame = vec![0xFFu8; 107]; // 107 = MIN_EAPOL_KEY_LEN_24
        let pair = make_paired_hash_24([0x11; 6], [0x22; 6], [0xAB; 24], [0x03; 32], frame, 0x00, AkmType::PskSha384);
        let line = format_eapol_22000(&pair, b"");
        let fields: Vec<&str> = line.splitn(10, '*').collect();
        // Field 2 is the MIC; should be 48 hex chars = 24 bytes.
        assert_eq!(fields[2].len(), 48, "SHA-384 MIC must be 24 B = 48 hex chars: {line}");
        assert_eq!(fields[2], "ababababababababababababababababababababababababab"[..48].to_string());
        // Field 7 is the eapol frame; bytes 81..105 must all be "00".
        let eapol_hex = fields[7];
        let mic_hex = &eapol_hex[162..210]; // 24 bytes = 48 hex chars
        assert!(mic_hex.chars().all(|c| c == '0'), "24 B MIC window must be zeroed in eapol field");
    }

    // --- WPA*01* ---

    #[test]
    fn format_pmkid_22000_basic() {
        let entry =
            make_pmkid_entry([0x11, 0x22, 0x33, 0x44, 0x55, 0x66], [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], [0x01; 16]);
        let essid = b"TestNet";
        let line = format_pmkid_22000(&entry, essid);
        // Verify prefix.
        assert!(line.starts_with("WPA*01*"), "bad prefix: {line}");
        // Verify field order by splitting on '*'.
        let fields: Vec<&str> = line.splitn(7, '*').collect();
        assert_eq!(fields[0], "WPA");
        assert_eq!(fields[1], "01");
        assert_eq!(fields[2], "01010101010101010101010101010101", "pmkid hex");
        assert_eq!(fields[3], "112233445566", "ap hex");
        assert_eq!(fields[4], "aabbccddeeff", "sta hex");
        assert_eq!(fields[5], "546573744e6574", "essid hex");
        // New format: after essid come two empty fields then mp -- so fields[6] = "*01"
        // when split with splitn(7, '*'): last segment contains "**01" sans leading *
        assert_eq!(fields[6], "**01", "empty nonce + empty eapol + mp");
    }

    #[test]
    fn format_pmkid_22000_empty_essid() {
        let entry = make_pmkid_entry([0x11; 6], [0x22; 6], [0xAA; 16]);
        let line = format_pmkid_22000(&entry, &[]);
        // Empty ESSID: line ends with "***01" (essid empty, two empty fields, mp byte).
        assert!(line.ends_with("****01"), "expected trailing ****01 for empty essid: {line}");
    }

    // --- WPA*02* ---

    #[test]
    fn format_eapol_22000_basic() {
        let pair = make_paired_hash(
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x02; 16],
            [0x03; 32],
            vec![0xFFu8; 99],
            0x00,
        );
        let line = format_eapol_22000(&pair, b"Net");
        assert!(line.starts_with("WPA*02*"), "bad prefix: {line}");
        // Field order: WPA * 02 * mic * ap * sta * essid * nonce * eapol * msgpair
        let fields: Vec<&str> = line.splitn(10, '*').collect();
        assert_eq!(fields[0], "WPA");
        assert_eq!(fields[1], "02");
        assert_eq!(fields[2], "02020202020202020202020202020202", "mic hex");
        assert_eq!(fields[3], "112233445566", "ap hex");
        assert_eq!(fields[4], "aabbccddeeff", "sta hex");
        assert_eq!(fields[5], "4e6574", "essid hex (Net)");
        // nonce: 32 bytes of 0x03 -> 64 hex chars of "03"
        assert_eq!(fields[6].len(), 64, "nonce field length");
        assert!(fields[6].chars().all(|c| c == '0' || c == '3'), "nonce all 03");
    }

    #[test]
    fn format_eapol_22000_mic_zeroed() {
        // Build a 99-byte EAPOL frame filled with 0xFF.
        // After zeroing bytes 81-96, hex positions 162-193 (32 chars) must be "00".
        let pair = make_paired_hash([0x11; 6], [0x22; 6], [0xAB; 16], [0x00; 32], vec![0xFFu8; 99], 0x00);
        let line = format_eapol_22000(&pair, b"");
        // Split off the eapol field (index 7, 0-based after splitting on '*').
        let fields: Vec<&str> = line.splitn(10, '*').collect();
        let eapol_hex = fields[7];
        // 99 bytes -> 198 hex chars total.
        assert_eq!(eapol_hex.len(), 198, "eapol hex length");
        // Bytes 81-96 (16 bytes) start at hex offset 162 and span 32 chars.
        let mic_hex = &eapol_hex[162..194];
        assert_eq!(mic_hex, "00000000000000000000000000000000", "MIC must be zeroed");
        // Bytes before and after must remain 0xFF.
        assert!(eapol_hex[..162].chars().all(|c| c == 'f'), "bytes before MIC untouched");
        assert!(eapol_hex[194..].chars().all(|c| c == 'f'), "bytes after MIC untouched");
    }

    #[test]
    fn format_eapol_22000_message_pair() {
        let pair = make_paired_hash([0x11; 6], [0x22; 6], [0x00; 16], [0x00; 32], vec![0u8; 99], 0x05);
        let line = format_eapol_22000(&pair, b"");
        // message_pair is the last field (no trailing '*').
        assert!(line.ends_with("05"), "expected last field '05': {line}");
    }

    // --- WPA*03* ---

    fn make_ft_fields(mdid: [u8; 2], r0khid: &[u8], r1khid: [u8; 6]) -> FtFields {
        let mut f = FtFields { mdid, r0khid_len: 0, r0khid: [0u8; 48], r1khid };
        let copy_len = r0khid.len().min(48);
        // copy_len <= 48 always fits in u8; unwrap_or is unreachable but satisfies the lint.
        f.r0khid_len = u8::try_from(copy_len).unwrap_or(48);
        if let Some(dst) = f.r0khid.get_mut(..copy_len) {
            if let Some(src) = r0khid.get(..copy_len) {
                dst.copy_from_slice(src);
            }
        }
        f
    }

    #[test]
    fn format_pmkid_37100_prefix() {
        let mut entry = make_pmkid_entry([0x11; 6], [0x22; 6], [0xAA; 16]);
        entry.akm = AkmType::FtPsk;
        let ft = make_ft_fields([0x12, 0x34], &[0xAB, 0xCD], [0x55; 6]);
        let line = format_pmkid_37100(&entry, &ft, b"ssid");
        assert!(line.starts_with("WPA*03*"), "expected WPA*03* prefix: {line}");
    }

    #[test]
    fn format_pmkid_37100_includes_ft_fields() {
        // Verify that MDID, R0KH-ID, and R1KH-ID appear after the message_pair byte.
        // Format: WPA*03*{pmkid}*{ap}*{sta}*{essid}***{mp}*{mdid}*{r0khid}*{r1khid}
        // [hcxpcapngtool:2551-2554]
        let mut entry = make_pmkid_entry([0x11; 6], [0x22; 6], [0xAA; 16]);
        entry.akm = AkmType::FtPsk;
        let ft = make_ft_fields([0x12, 0x34], &[0xAB, 0xCD, 0xEF], [0x55; 6]);
        let line = format_pmkid_37100(&entry, &ft, b"net");
        // Split: WPA * 03 * pmkid * ap * sta * essid * * * mp * mdid * r0khid * r1khid
        let fields: Vec<&str> = line.splitn(13, '*').collect();
        assert_eq!(fields[1], "03", "prefix type");
        assert_eq!(fields[9], "1234", "MDID: 2 bytes as 4 hex chars");
        assert_eq!(fields[10], "abcdef", "R0KH-ID: 3 bytes");
        assert_eq!(fields[11], "555555555555", "R1KH-ID: 6 bytes");
    }

    #[test]
    fn format_pmkid_37100_message_pair_ap_side_is_ftpsk_value() {
        // FT-PSK PMKID sourced from an AP-side frame (M1 KDE in this case) must
        // emit `PMKID_AP_FTPSK = 0x10`, not the mode-22000 `PMKID_AP = 0x01`.
        // [hcxpcapngtool.h:386-390 + hcxpcapngtool.c:2554]
        let mut entry = make_pmkid_entry([0x11; 6], [0x22; 6], [0xAA; 16]);
        entry.akm = AkmType::FtPsk;
        entry.source = PmkidSource::M1KeyData;
        let ft = make_ft_fields([0x12, 0x34], &[0xAB], [0x55; 6]);
        let line = format_pmkid_37100(&entry, &ft, b"net");
        let fields: Vec<&str> = line.splitn(13, '*').collect();
        assert_eq!(fields[8], "10", "AP-side FT-PSK PMKID must emit PMKID_AP_FTPSK=0x10");
    }

    #[test]
    fn format_pmkid_37100_message_pair_client_side_is_ftpsk_value() {
        // FT-PSK PMKID sourced from a client-side frame (M2 RSN IE) must emit
        // `PMKID_CLIENT_FTPSK = 0x20`, not the mode-22000 `PMKID_CLIENT = 0x04`.
        // Worked example: capture 4b2a84b7 in the 2026-05-12 corpus run --
        // hcx-default emitted *20 for a Hitron VastVortex FT-PSK session and
        // wpawolf was emitting *04, causing per-capture superset violations.
        let mut entry = make_pmkid_entry([0x11; 6], [0x22; 6], [0xAA; 16]);
        entry.akm = AkmType::FtPsk;
        entry.source = PmkidSource::M2RsnIe;
        let ft = make_ft_fields([0x12, 0x34], &[0xAB], [0x55; 6]);
        let line = format_pmkid_37100(&entry, &ft, b"net");
        let fields: Vec<&str> = line.splitn(13, '*').collect();
        assert_eq!(fields[8], "20", "client-side FT-PSK PMKID must emit PMKID_CLIENT_FTPSK=0x20");
    }

    #[test]
    fn format_pmkid_22000_message_pair_unchanged_for_non_ft() {
        // Regression pin: non-FT entries keep the mode-22000 mp bytes
        // (PMKID_AP=0x01 for AP-side, PMKID_CLIENT=0x04 for client-side).
        let mut entry = make_pmkid_entry([0x11; 6], [0x22; 6], [0xAA; 16]);
        entry.akm = AkmType::Wpa2Psk;
        entry.source = PmkidSource::M1KeyData;
        let line = format_pmkid_22000(&entry, b"net");
        let fields: Vec<&str> = line.splitn(10, '*').collect();
        assert_eq!(fields[8], "01", "AP-side non-FT PMKID must keep PMKID_AP=0x01");

        entry.source = PmkidSource::M2RsnIe;
        let line = format_pmkid_22000(&entry, b"net");
        let fields: Vec<&str> = line.splitn(10, '*').collect();
        assert_eq!(fields[8], "04", "client-side non-FT PMKID must keep PMKID_CLIENT=0x04");
    }

    // --- WPA*04* ---

    #[test]
    fn format_eapol_37100_prefix() {
        let pair = make_paired_hash([0x11; 6], [0x22; 6], [0x00; 16], [0x00; 32], vec![0u8; 99], 0x00);
        let ft = make_ft_fields([0x12, 0x34], &[0xAB], [0x55; 6]);
        let line = format_eapol_37100(&pair, &ft, b"ssid");
        assert!(line.starts_with("WPA*04*"), "expected WPA*04* prefix: {line}");
    }

    #[test]
    fn format_eapol_37100_includes_ft_fields() {
        // Verify MDID, R0KH-ID, R1KH-ID appended after message_pair.
        // Format: WPA*04*{mic}*{ap}*{sta}*{essid}*{nonce}*{eapol}*{mp}*{mdid}*{r0khid}*{r1khid}
        // [hcxpcapngtool:2368-2371]
        let pair = make_paired_hash([0x11; 6], [0x22; 6], [0xCD; 16], [0xEF; 32], vec![0x77u8; 99], 0x03);
        let ft = make_ft_fields([0x56, 0x78], &[0x01, 0x02, 0x03, 0x04], [0x99; 6]);
        let line = format_eapol_37100(&pair, &ft, b"ssid");
        // WPA * 04 * mic * ap * sta * essid * nonce * eapol * mp * mdid * r0khid * r1khid
        let fields: Vec<&str> = line.splitn(13, '*').collect();
        assert_eq!(fields[1], "04", "prefix type");
        assert_eq!(fields[9], "5678", "MDID: 2 bytes as 4 hex chars");
        assert_eq!(fields[10], "01020304", "R0KH-ID: 4 bytes");
        assert_eq!(fields[11], "999999999999", "R1KH-ID: 6 bytes");
    }
}
