//! Handshake orchestration.
//!
//! Ties [`crate::crypto`] and [`crate::frame`] together to produce a full
//! M1-M4 sequence with cryptographically valid PMK / PMKID / MIC for one
//! `(PSK, SSID, AP, STA, AKM)` tuple.
//!
//! Each `build_*` function returns the wire bytes of one EAPOL-Key frame;
//! [`Handshake::all`] returns the full sequence plus the derived secrets so
//! callers (the catalog) can stitch them into pcap records and lock them
//! into the ground-truth manifest.

use crate::crypto::{
    FtContext, HashFamily, compute_mic, derive_ft_ptk, derive_pmk, derive_pmk_r0, derive_pmk_r1, derive_pmkid,
    derive_ptk, kck_from_ptk, mic_len,
};
use crate::frame::eapol::{Direction, KeySpec, Message, body_for_mic, build, data_frame, mic_offset};
use crate::frame::ie::{FteInputs, fte, mde, rsn_ie, wpa1_vendor_ie};
use crate::frame::kde::pmkid as pmkid_kde;
use crate::{Error, Result};

/// `MDID` used by every FT fixture in the catalog.
///
/// Stored in wire byte order (little-endian octets per `[IEEE 802.11-2024]`
/// §9.4.2.45) so it matches the `MDE` IE bytes emitted in M2 / M3 Key Data and
/// `AssocReq`, the raw `mdid` field hashcat reads back from the `WPA*03*` line,
/// and the `MDID` octets fed to the FT-R0 KDF -- all three must agree
/// byte-for-byte or `PMK-R1Name` won't match what `module_37100.c` derives.
pub const FT_MDID: [u8; 2] = [0x34, 0x12];
/// `R0KH-ID` used by every FT fixture. See [`FT_MDID`].
pub const FT_R0KH_ID: &[u8] = b"r0kh";
/// `R1KH-ID` (always 6 bytes -- a MAC address) used by every FT fixture.
/// See [`FT_MDID`].
pub const FT_R1KH_ID: [u8; 6] = [0x06, 0x06, 0x06, 0x06, 0x06, 0x06];

/// Inputs to one full handshake.
///
/// AKMs split MIC and PMKID across different hash families: PSK-SHA-256
/// (AKM 6) and FT-PSK (AKM 4) compute PMKID with HMAC-SHA-256 but the MIC
/// with AES-128-CMAC. Each is named separately so callers can pair them
/// per `[IEEE 802.11-2024]` table 12-11.
#[derive(Debug, Clone)]
pub struct Inputs {
    /// Pre-shared passphrase (e.g. `b"hashcat"` matches hashcat's canonical
    /// 22000 example).
    pub psk: Vec<u8>,
    /// SSID -- `<= 32` bytes per `[IEEE 802.11-2024]` §9.4.2.2.
    pub ssid: Vec<u8>,
    /// AP MAC (`AA` in PRF inputs, `addr3 / BSSID`).
    pub ap: [u8; 6],
    /// STA MAC (`SPA` in PRF inputs).
    pub sta: [u8; 6],
    /// Hash family for PMKID + KCK derivation. SHA-1 for AKM 2; SHA-256 for
    /// AKMs 4 / 6; SHA-384 for AKMs 19 / 20.
    pub kdf_family: HashFamily,
    /// MIC algorithm. HMAC-MD5 for KDV=1 / WPA1; HMAC-SHA1-128 for KDV=2;
    /// AES-128-CMAC for KDV=3 with SHA-256 KDF; HMAC-SHA-384-192 for the
    /// SHA-384 family.
    pub mic_family: HashFamily,
    /// AKM byte for the RSN IE (`00:0F:AC:<byte>`).
    pub akm_byte: u8,
    /// `ANonce` -- AP-side random.
    pub a_nonce: [u8; 32],
    /// `SNonce` -- STA-side random.
    pub s_nonce: [u8; 32],
    /// Replay counter for M1; M2 follows the FR-CLI-RC table.
    pub replay_counter: u64,
    /// Key Descriptor Version (0 = AKM-defined, 1 = MD5, 2 = SHA-1, 3 = CMAC).
    pub kdv: u8,
    /// `true` to use the WPA1 descriptor type (`0xFE`); `false` for RSN
    /// (`0x02`).
    pub wpa1: bool,
}

/// Derived secrets and the four wire frames produced by [`Handshake::all`].
#[derive(Debug, Clone)]
pub struct Handshake {
    /// 32-byte PMK.
    pub pmk: [u8; 32],
    /// 16-byte PMKID. `None` for WPA1 (no PMKID defined).
    pub pmkid: Option<[u8; 16]>,
    /// PTK (length depends on family: 48 for SHA-1/256, 88 for SHA-384).
    pub ptk: Vec<u8>,
    /// KCK -- the leading slice of the PTK used for MIC computation.
    pub kck: Vec<u8>,
    /// M1 wire bytes (data-frame wrapped; AP -> STA).
    pub m1: Vec<u8>,
    /// M2 wire bytes (data-frame wrapped; STA -> AP).
    pub m2: Vec<u8>,
    /// M3 wire bytes.
    pub m3: Vec<u8>,
    /// M4 wire bytes.
    pub m4: Vec<u8>,
}

impl Handshake {
    /// Derive PMK / PMKID / PTK / KCK and build all four EAPOL-Key frames.
    ///
    /// # Errors
    ///
    /// Forwards any [`crate::Error`] from the crypto or framing layers.
    pub fn all(inputs: &Inputs) -> Result<Self> {
        let pmk = derive_pmk(&inputs.psk, &inputs.ssid)?;
        // For FT-PSK (AKMs 4 / 19) the four-way handshake runs over the FT
        // key hierarchy: PMKID is `PMK-R1Name`, KCK derives from the FT PTK
        // (`KDF-Hash(PMK-R1, "FT-PTK", SNonce || ANonce || BSSID || SPA)`).
        // hashcat's mode 37100 verifier expects this exact derivation, so
        // emitting the non-FT keys here would make the line unrecoverable
        // even with the correct PSK.
        let (pmkid, ptk) = if inputs.wpa1 {
            // WPA1: no PMKID; PTK derives via legacy PRF-SHA1.
            (None, derive_ptk(inputs.kdf_family, &pmk, inputs.ap, inputs.sta, &inputs.a_nonce, &inputs.s_nonce)?)
        } else if is_ft_akm(inputs.akm_byte) {
            let ft_ctx = FtContext { ssid: &inputs.ssid, mdid: FT_MDID, r0kh_id: FT_R0KH_ID, r1kh_id: FT_R1KH_ID };
            let (pmk_r0, pmk_r0_name) = derive_pmk_r0(inputs.kdf_family, &pmk, &ft_ctx, inputs.sta)?;
            let (pmk_r1, pmk_r1_name) =
                derive_pmk_r1(inputs.kdf_family, &pmk_r0, &pmk_r0_name, FT_R1KH_ID, inputs.sta)?;
            // FT PTK uses SNonce || ANonce ordering and BSSID || SPA
            // unconditionally (no min/max), per `[IEEE 802.11-2024]` §13.4.5.
            let ptk_ft =
                derive_ft_ptk(inputs.kdf_family, &pmk_r1, &inputs.s_nonce, &inputs.a_nonce, inputs.ap, inputs.sta)?;
            (Some(pmk_r1_name), ptk_ft)
        } else {
            let ptk = derive_ptk(inputs.kdf_family, &pmk, inputs.ap, inputs.sta, &inputs.a_nonce, &inputs.s_nonce)?;
            (Some(derive_pmkid(inputs.kdf_family, &pmk, inputs.ap, inputs.sta)?), ptk)
        };
        let kck = kck_from_ptk(inputs.kdf_family, &ptk)?;

        // M1: AP -> STA, ANonce, no MIC. PMKID KDE in Key Data when not WPA1.
        // For FT initial association the PMKID inside the M1 KDE is the
        // PMKR1Name (`[IEEE 802.11-2024]` §13.4.5); we use the PMKID directly
        // since wpawolf treats both identically when classifying.
        let m1_key_data = pmkid.as_ref().map(pmkid_kde).unwrap_or_default();
        let m1 = build_frame(inputs, Message::M1, inputs.replay_counter, inputs.a_nonce, m1_key_data, &kck, false)?;

        // M2: STA -> AP, SNonce, MIC, RSN IE in Key Data. Same RC as M1. For
        // FT-PSK (AKM 4 / 19) M2 must additionally carry MDE + FTE so wpawolf
        // can detect FT context (`src/extract/common.rs::store_eapol_key`
        // calls `extract_ft_fields(&key.key_data)`; it requires both tag 54
        // and tag 55 to fire). Without this, FT EAPOL hashes (Type 7 / 11)
        // never reach the FT-EAPOL emission gate.
        // WPA1 M2 carries the STA's WPA1 vendor IE in Key Data, as real WPA1
        // four-way handshakes do. Without it, wpawolf's Tier-1 classifier sees
        // a MIC'd uplink frame with empty Key Data and labels it M4 (not M2),
        // so the M2-anchored combos N1E2 / N3E2 / N2E3 never form. RSN (WPA2)
        // M2 gets its RSN IE the same way.
        let m2_key_data =
            if inputs.wpa1 { wpa1_vendor_ie() } else { wpa2_or_ft_key_data(inputs, inputs.akm_byte, true) };
        let m2 = build_frame(inputs, Message::M2, inputs.replay_counter, inputs.s_nonce, m2_key_data, &kck, true)?;

        // M3: AP -> STA, ANonce, MIC, Install + Secure. RC = M1.RC + 1. For
        // FT, M3 carries RSN + MDE + FTE in Key Data per `[IEEE 802.11-2024]`
        // §13.4.5; in production the field is encrypted under the KEK so
        // wpawolf treats M3 key data as opaque, but emitting it plaintext
        // in the fixture surfaces any future detection-from-M3 path the
        // parser grows.
        let m3_key_data = if inputs.wpa1 || !is_ft_akm(inputs.akm_byte) {
            Vec::new()
        } else {
            wpa2_or_ft_key_data(inputs, inputs.akm_byte, true)
        };
        let m3 = build_frame(inputs, Message::M3, inputs.replay_counter + 1, inputs.a_nonce, m3_key_data, &kck, true)?;

        // M4: STA -> AP, MIC, Secure, no Key Data. RC = M3.RC.
        let m4 = build_frame(inputs, Message::M4, inputs.replay_counter + 1, inputs.s_nonce, Vec::new(), &kck, true)?;

        Ok(Self { pmk, pmkid, ptk, kck, m1, m2, m3, m4 })
    }
}

/// AKM byte-to-FT-suite predicate. Mirrors
/// `wpawolf::types::AkmType::is_ft()`: AKM 4 = `FT-PSK` (SHA-256 chain),
/// AKM 19 = `FT-PSK-SHA384`.
const fn is_ft_akm(akm_byte: u8) -> bool {
    matches!(akm_byte, 4 | 19)
}

/// Build the Key Data field for an M2 / M3 EAPOL frame. Always emits the
/// RSN IE; when `include_ft` is true and the AKM is FT, appends MDE + FTE
/// subelements so wpawolf's `extract_ft_fields` reaches the FT classification
/// path (`[IEEE 802.11-2024]` §13.4.5).
fn wpa2_or_ft_key_data(inputs: &Inputs, akm_byte: u8, include_ft: bool) -> Vec<u8> {
    let mut out = rsn_ie(akm_byte, None);
    if include_ft && is_ft_akm(akm_byte) {
        out.extend_from_slice(&mde(0x1234, 0));
        // FTE MIC field is fixed at 16 B in the layout wpawolf parses
        // (`src/ieee80211/ft.rs::parse_fte` reads `ANonce` from offset 18 and
        // `SNonce` from offset 50; the SHA-384 amendment that widens this to
        // 24 B is not yet wired into the parser). Emit the legacy 16 B form
        // for both AKM 4 and AKM 19 so the fixture is round-trippable; the
        // MIC value is zero and the fixture does not exercise FT MIC
        // verification.
        let mic = [0u8; 16];
        out.extend_from_slice(&fte(&FteInputs {
            mic_control: [0, 0],
            mic: &mic,
            a_nonce: inputs.a_nonce,
            s_nonce: inputs.s_nonce,
            r0kh_id: b"r0kh",
            r1kh_id: [0x06, 0x06, 0x06, 0x06, 0x06, 0x06],
        }));
    }
    out
}

/// Build one EAPOL-Key wire frame, computing the MIC if requested.
///
/// `with_mic = true` zeroes the MIC, computes HMAC over the EAPOL body, and
/// patches the result back into the frame in place. Exposed to the catalog so
/// the replay-counter-endianness fixtures can build a single message with a
/// byte-swapped `rc` value -- `build` writes `rc` big-endian, so passing
/// `rc.swap_bytes()` yields the little-endian wire bytes a buggy AP firmware
/// emits, and the MIC is computed over those exact bytes (still crackable).
///
/// # Errors
///
/// Forwards any MIC-computation or framing error.
pub(crate) fn build_frame(
    inputs: &Inputs,
    msg: Message,
    rc: u64,
    nonce: [u8; 32],
    key_data: Vec<u8>,
    kck: &[u8],
    with_mic: bool,
) -> Result<Vec<u8>> {
    let mic_width = mic_len(inputs.mic_family);
    let mic_zeros = vec![0u8; mic_width];
    let spec = KeySpec {
        msg,
        kdv: inputs.kdv,
        mic_len: mic_width,
        replay_counter: rc,
        nonce,
        mic: mic_zeros,
        key_data,
        wpa1: inputs.wpa1,
    };
    let mut eapol = build(&spec);
    if with_mic {
        let mic = compute_mic(inputs.mic_family, kck, body_for_mic(&eapol))?;
        let off = mic_offset();
        let slot = eapol.get_mut(off..off + mic_width).ok_or(Error::InvalidWireFormat("MIC offset out of range"))?;
        slot.copy_from_slice(&mic);
    }
    let direction = match msg {
        Message::M1 | Message::M3 => Direction::Downlink,
        Message::M2 | Message::M4 => Direction::Uplink,
    };
    Ok(data_frame(inputs.ap, inputs.sta, direction, &eapol))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inputs(kdf_family: HashFamily, mic_family: HashFamily, akm_byte: u8, kdv: u8, wpa1: bool) -> Inputs {
        Inputs {
            psk: b"hashcat".to_vec(),
            ssid: b"wpawolf-test".to_vec(),
            ap: [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
            sta: [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            kdf_family,
            mic_family,
            akm_byte,
            a_nonce: [0xA5; 32],
            s_nonce: [0x5A; 32],
            replay_counter: 1,
            kdv,
            wpa1,
        }
    }

    #[test]
    fn wpa2_psk_handshake_produces_four_frames() {
        let h = Handshake::all(&sample_inputs(HashFamily::Sha1, HashFamily::Sha1, 2, 2, false)).expect("handshake");
        assert!(h.pmkid.is_some());
        assert_eq!(h.kck.len(), 16);
        for frame in [&h.m1, &h.m2, &h.m3, &h.m4] {
            assert!(frame.len() > 24, "data frame must include MAC header + EAPOL body");
        }
        // M1 has zero MIC, M2/M3/M4 have non-zero MIC.
        assert!(non_zero_mic(&h.m2, 16));
        assert!(non_zero_mic(&h.m3, 16));
        assert!(non_zero_mic(&h.m4, 16));
    }

    #[test]
    fn wpa1_handshake_has_no_pmkid() {
        let h = Handshake::all(&sample_inputs(HashFamily::Sha1, HashFamily::Md5, 2, 1, true)).expect("wpa1 handshake");
        assert!(h.pmkid.is_none());
    }

    #[test]
    fn sha384_handshake_uses_24_byte_mic() {
        let h = Handshake::all(&sample_inputs(HashFamily::Sha384, HashFamily::Sha384, 20, 0, false))
            .expect("sha384 handshake");
        assert_eq!(h.kck.len(), 24);
        assert!(non_zero_mic(&h.m2, 24));
    }

    #[test]
    fn psksha256_handshake_uses_aes_cmac_mic() {
        // KDF = SHA-256 (PMKID + KCK), MIC = AES-CMAC.
        let h = Handshake::all(&sample_inputs(HashFamily::Sha256, HashFamily::AesCmac128, 6, 3, false))
            .expect("psksha256 handshake");
        assert!(h.pmkid.is_some());
        assert_eq!(h.kck.len(), 16);
        assert!(non_zero_mic(&h.m2, 16));
    }

    /// Locate the MIC field inside a data-frame-wrapped EAPOL frame and
    /// confirm it is non-zero. Data frame MAC header is 24 bytes; LLC/SNAP
    /// is the next 8 bytes, then the MIC offset within the EAPOL body.
    fn non_zero_mic(data_frame: &[u8], width: usize) -> bool {
        let mac_hdr = 24;
        let off = mac_hdr + mic_offset();
        let slice = &data_frame[off..off + width];
        slice.iter().any(|b| *b != 0)
    }
}
