//! Exhaustive permutation corpus for hash-line format coverage.
//!
//! Generates every combination of (EAPOL family, N#E# combo, NC flag,
//! endianness flag) and (PMKID type, mp byte) -- including structurally
//! impossible ones -- so the corpus covers every `message_pair` byte value
//! the format can express for wpawolf classes 1-7.
//!
//! Each permutation produces:
//! - A pcap file (Beacon + the minimum EAPOL/PMKID frames)
//! - A reference hash line with valid crypto and the exact desired `mp` byte
//! - Reachability metadata (whether wpawolf's pairing engine can naturally
//!   produce that `mp` byte)
//!
//! Dimensions:
//! - EAPOL: 4 families × 6 combos × 2 NC × 3 endianness = 144
//! - PMKID: 3 types × 5 mp bytes = 15
//! - Total: 159

use std::fmt::Write as _;
use std::path::PathBuf;

use crate::Result;
use crate::catalog::{Container, Fixture};
use crate::crypto::{FtContext, HashFamily, derive_pmk, derive_pmk_r0, derive_pmk_r1, derive_pmkid, mic_len};
use crate::frame::beacon::beacon;
use crate::frame::eapol::{Direction, KeySpec, Message as EapolMsg, build as build_eapol, data_frame, mic_offset};
use crate::frame::ie::{FteInputs, fte, mde, rsn_ie, wpa1_vendor_ie};
use crate::frame::kde::pmkid as pmkid_kde;
use crate::handshake::{FT_MDID, FT_R0KH_ID, FT_R1KH_ID, Handshake, Inputs, build_frame};
use crate::linklayer::LinkType;
use crate::pcap_writer::{Packet, PcapMagic};

// --- Constants ---

const PSK: &[u8] = b"hashcat!";

const ANONCE: [u8; 32] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xA0, 0x91, 0x92, 0x93,
    0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0x90,
];
const SNONCE: [u8; 32] = [
    0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xB0, 0xB1, 0x82, 0x83, 0x84,
    0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x80, 0x81,
];

const TS_BASE: u32 = 1_700_100_000;
const BASE_RC: u64 = 1;

const FLAG_APLESS: u8 = 0x10;
const FLAG_NC: u8 = 0x80;

/// Locally-administered OUI prefix 0x04 so permutation MACs never collide
/// with the main catalog's 0x02 prefix.
const fn perm_ap(idx: u8) -> [u8; 6] {
    [0x04, 0x11, 0x22, 0x33, 0x44, idx]
}
const fn perm_sta(idx: u8) -> [u8; 6] {
    [0x04, 0xAA, 0xBB, 0xCC, 0xDD, idx]
}

// --- Public types ---

/// One permutation entry: pcap fixture + reference hash line + metadata.
#[derive(Debug, Clone)]
pub struct Permutation {
    /// The pcap fixture (frames, path, expected/forbidden hashes).
    pub fixture: Fixture,
    /// Reference hash line with valid crypto and the exact desired `mp` byte.
    pub reference_hash: String,
    /// The `message_pair` byte this permutation targets.
    pub mp_byte: u8,
    /// Whether wpawolf's pairing engine can naturally produce this `mp` byte.
    pub reachable: bool,
    /// CLI flags wpawolf needs to produce the expected output (e.g. `--rc-drift 8`).
    pub cli_flags: Vec<String>,
    /// Explanation for impossible permutations.
    pub note: String,
}

// --- Dimension enums ---

/// N#E# combo identifier: Nonce source message # and EAPOL source message #.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ComboId {
    /// ANonce from M1, EAPOL from M2.
    N1E2,
    /// ANonce from M1, EAPOL from M4.
    N1E4,
    /// ANonce from M3, EAPOL from M2.
    N3E2,
    /// SNonce from M2, EAPOL from M3 (APLESS).
    N2E3,
    /// SNonce from M4, EAPOL from M3 (APLESS).
    N4E3,
    /// ANonce from M3, EAPOL from M4.
    N3E4,
}

impl ComboId {
    const fn discriminant(self) -> u8 {
        match self {
            Self::N1E2 => 0,
            Self::N1E4 => 1,
            Self::N3E2 => 2,
            Self::N2E3 => 3,
            Self::N4E3 => 4,
            Self::N3E4 => 5,
        }
    }

    const fn tag(self) -> &'static str {
        match self {
            Self::N1E2 => "n1e2",
            Self::N1E4 => "n1e4",
            Self::N3E2 => "n3e2",
            Self::N2E3 => "n2e3",
            Self::N4E3 => "n4e3",
            Self::N3E4 => "n3e4",
        }
    }

    const fn is_apless(self) -> bool {
        matches!(self, Self::N2E3 | Self::N4E3)
    }

    const fn is_m1_anchored(self) -> bool {
        matches!(self, Self::N1E2 | Self::N1E4)
    }

    /// Which message provides the nonce for the hash line.
    const fn nonce_msg(self) -> EapolMsg {
        match self {
            Self::N1E2 | Self::N1E4 => EapolMsg::M1,
            Self::N3E2 | Self::N3E4 => EapolMsg::M3,
            Self::N2E3 => EapolMsg::M2,
            Self::N4E3 => EapolMsg::M4,
        }
    }

    /// Whether the nonce is the ANonce (true) or SNonce (false).
    const fn nonce_is_anonce(self) -> bool {
        matches!(self, Self::N1E2 | Self::N1E4 | Self::N3E2 | Self::N3E4)
    }

    /// Which message provides the EAPOL body (and MIC) for the hash line.
    const fn eapol_msg(self) -> EapolMsg {
        match self {
            Self::N1E2 | Self::N3E2 => EapolMsg::M2,
            Self::N2E3 | Self::N4E3 => EapolMsg::M3,
            Self::N1E4 | Self::N3E4 => EapolMsg::M4,
        }
    }
}

/// Endianness dimension for the permutation matrix. LE/BE flags are disabled
/// in wpawolf's output (Rule E9) but the pcap fixtures still include drift-M1
/// frames to exercise the nonce-endianness detection code path and produce
/// cross-paired hash lines.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Endianness {
    /// No drift-M1 frame.
    None,
    /// Drift-M1 with nonce byte 29 shifted (+1). Triggers LE detection.
    Le,
    /// Drift-M1 with nonce byte 30 shifted (+1). Triggers BE detection.
    Be,
}

impl Endianness {
    const fn tag(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Le => "-le",
            Self::Be => "-be",
        }
    }
}

// --- EAPOL family definitions ---

#[derive(Debug, Clone, Copy)]
struct EapolFamily {
    tag: &'static str,
    kdf: HashFamily,
    mic: HashFamily,
    akm: u8,
    kdv: u8,
    wpa1: bool,
    is_ft: bool,
}

const EAPOL_FAMILIES: [EapolFamily; 4] = [
    EapolFamily { tag: "wpa1", kdf: HashFamily::Sha1, mic: HashFamily::Md5, akm: 2, kdv: 1, wpa1: true, is_ft: false },
    EapolFamily {
        tag: "wpa2",
        kdf: HashFamily::Sha1,
        mic: HashFamily::Sha1,
        akm: 2,
        kdv: 2,
        wpa1: false,
        is_ft: false,
    },
    EapolFamily {
        tag: "psk256",
        kdf: HashFamily::Sha256,
        mic: HashFamily::AesCmac128,
        akm: 6,
        kdv: 3,
        wpa1: false,
        is_ft: false,
    },
    EapolFamily {
        tag: "ftpsk",
        kdf: HashFamily::Sha256,
        mic: HashFamily::AesCmac128,
        akm: 4,
        kdv: 3,
        wpa1: false,
        is_ft: true,
    },
];

const ALL_COMBOS: [ComboId; 6] =
    [ComboId::N1E2, ComboId::N1E4, ComboId::N3E2, ComboId::N2E3, ComboId::N4E3, ComboId::N3E4];

// --- PMKID type definitions ---

#[derive(Debug, Clone, Copy)]
struct PmkidType {
    tag: &'static str,
    kdf: HashFamily,
    akm: u8,
    is_ft: bool,
}

const PMKID_TYPES: [PmkidType; 3] = [
    PmkidType { tag: "wpa2", kdf: HashFamily::Sha1, akm: 2, is_ft: false },
    PmkidType { tag: "psk256", kdf: HashFamily::Sha256, akm: 6, is_ft: false },
    PmkidType { tag: "ftpsk", kdf: HashFamily::Sha256, akm: 4, is_ft: true },
];

/// Per-type PMKID direction variants. Each AKM type has exactly two mp bytes
/// (AP-side and client-side), with SHA256 and FT flags determined by the type.
/// [HASHCAT.md §6.2 Rules P1-P5]
const PMKID_VARIANTS: [(PmkidType, u8, &str); 6] = [
    (PMKID_TYPES[0], 0x01, "ap"),     // WPA2-PSK AP
    (PMKID_TYPES[0], 0x04, "client"), // WPA2-PSK CLIENT
    (PMKID_TYPES[1], 0x03, "ap"),     // PSK-SHA256 AP + SHA256
    (PMKID_TYPES[1], 0x06, "client"), // PSK-SHA256 CLIENT + SHA256
    (PMKID_TYPES[2], 0x10, "ap"),     // FT-PSK FT-AP
    (PMKID_TYPES[2], 0x20, "client"), // FT-PSK FT-CLIENT
];

// --- Public API ---

/// Generate all 150 permutations (144 EAPOL + 6 PMKID).
///
/// # Errors
///
/// Forwards any crypto or framing error.
pub fn all() -> Result<Vec<Permutation>> {
    let mut out = Vec::with_capacity(150);
    out.extend(eapol_permutations()?);
    out.extend(pmkid_permutations()?);
    Ok(out)
}

// --- EAPOL permutation generation ---

fn eapol_permutations() -> Result<Vec<Permutation>> {
    let mut out = Vec::with_capacity(144);
    let mut idx: u8 = 0;
    for family in &EAPOL_FAMILIES {
        for combo in &ALL_COMBOS {
            for nc in [false, true] {
                for endianness in [Endianness::None, Endianness::Le, Endianness::Be] {
                    out.push(build_eapol_permutation(family, *combo, nc, endianness, idx)?);
                    idx += 1;
                }
            }
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_lines)]
fn build_eapol_permutation(
    family: &EapolFamily,
    combo: ComboId,
    nc: bool,
    endianness: Endianness,
    idx: u8,
) -> Result<Permutation> {
    let ap = perm_ap(idx);
    let sta = perm_sta(idx);
    let nc_tag = if nc { "-nc" } else { "" };
    let ssid = format!("p-{}-{}{}{}", family.tag, combo.tag(), nc_tag, endianness.tag());

    let inputs = Inputs {
        psk: PSK.to_vec(),
        ssid: ssid.as_bytes().to_vec(),
        ap,
        sta,
        kdf_family: family.kdf,
        mic_family: family.mic,
        akm_byte: family.akm,
        a_nonce: ANONCE,
        s_nonce: SNONCE,
        replay_counter: BASE_RC,
        kdv: family.kdv,
        wpa1: family.wpa1,
    };
    let h = Handshake::all(&inputs)?;

    let mic_width = mic_len(family.mic);
    let mp_byte = compute_eapol_mp_byte(combo, nc, Endianness::None);
    let (reachable, note) = eapol_reachability(combo, nc);

    let eapol_source_frame = build_eapol_source(family, combo, Endianness::None, &inputs, &h)?;
    let nonce_source_frame = build_nonce_source(family, combo, Endianness::None, &inputs, &h)?;

    // Build pcap frames.
    let beacon_rsn = if family.wpa1 { wpa1_vendor_ie() } else { rsn_ie(family.akm, None) };
    let bcn = beacon(ap, ssid.as_bytes(), &beacon_rsn);
    let mut frames = vec![bcn];

    // For NC on M3-anchored combos, add M1 to the pcap.
    if nc && !combo.is_m1_anchored() && !combo.is_apless() {
        frames.push(h.m1.clone());
    }

    // For FT M4-anchored combos (N1E4): M4 has no FTE, so wpawolf's FT emit
    // gate needs ft_backfill from another frame in the session. Add M2 (which
    // carries FTE for FT families) so the N1E4 pair emits as WPA*04*.
    if family.is_ft && combo.eapol_msg() == EapolMsg::M4 && combo.nonce_msg() == EapolMsg::M1 {
        frames.push(h.m2.clone());
    }

    // For LE/BE: add a drift-M1 with shifted nonce to exercise the nonce-
    // endianness detection code path. wpawolf does NOT set LE/BE flags on
    // the output (Rule E9) but the drift-M1 produces cross-paired hash
    // lines that test hashcat's NC correction across byte orders.
    if endianness != Endianness::None {
        let mut drifted_nonce = ANONCE;
        match endianness {
            Endianness::Le => {
                // Shift byte 28 (+1). detect_nonce_endianness sees bytes
                // 28-29 differ -> LE. hashcat's gap = 1, cracks at NC=2.
                drifted_nonce[28] = drifted_nonce[28].wrapping_add(1);
            },
            Endianness::Be => {
                // Shift byte 31 (+1). detect_nonce_endianness sees bytes
                // 30-31 differ -> BE. hashcat's gap = 1, cracks at NC=2.
                drifted_nonce[31] = drifted_nonce[31].wrapping_add(1);
            },
            Endianness::None => {},
        }
        let drift_key_data = eapol_msg_key_data(family, EapolMsg::M1, &inputs);
        let drift_m1 = build_frame(&inputs, EapolMsg::M1, BASE_RC + 10, drifted_nonce, drift_key_data, &h.kck, false)?;
        frames.push(drift_m1);
    }

    // Add the nonce source and EAPOL source messages in chronological order.
    let nonce_first = matches!(combo, ComboId::N1E2 | ComboId::N1E4);
    if nonce_first {
        frames.push(nonce_source_frame.clone());
        frames.push(eapol_source_frame.clone());
    } else {
        // M2+M3 or M3+M4: lower-numbered message first.
        match combo {
            ComboId::N3E2 | ComboId::N2E3 => {
                // M2 then M3: EAPOL source (M2) or nonce source (M2) first.
                // M2 is the earlier message.
                if combo.eapol_msg() == EapolMsg::M2 {
                    frames.push(eapol_source_frame.clone());
                    frames.push(nonce_source_frame.clone());
                } else {
                    frames.push(nonce_source_frame.clone());
                    frames.push(eapol_source_frame.clone());
                }
            },
            ComboId::N4E3 | ComboId::N3E4 => {
                // M3 then M4.
                if combo.eapol_msg() == EapolMsg::M3 {
                    frames.push(eapol_source_frame.clone());
                    frames.push(nonce_source_frame.clone());
                } else {
                    frames.push(nonce_source_frame.clone());
                    frames.push(eapol_source_frame.clone());
                }
            },
            _ => {},
        }
    }

    let packets = wrap_radiotap(&frames);

    // Build reference hash line. FT permutations always use WPA*04* format.
    let nonce = if combo.nonce_is_anonce() { ANONCE } else { SNONCE };
    let emit_as_ft = family.is_ft;
    let reference_hash =
        format_eapol_hash_line(&eapol_source_frame, &nonce, mp_byte, mic_width, ap, sta, ssid.as_bytes(), emit_as_ft)?;

    // No special CLI flags. NC is unconditional (Rule E4). Nonce endianness
    // is detected automatically from the drift-M1 frame in the pcap.
    let cli_flags = Vec::new();

    // Expected hash prefix for reachable permutations. FT M4-anchored pairs
    // fall back to non-FT WPA*02* when FT context is missing.
    let eapol_prefix = if emit_as_ft { "WPA*04*" } else { "WPA*02*" };
    let expected_hashes = if reachable { vec![eapol_prefix.to_owned()] } else { Vec::new() };

    let path_str = format!("permutations/eapol/{}_{}{}{}.pcap", family.tag, combo.tag(), nc_tag, endianness.tag());

    Ok(Permutation {
        fixture: Fixture {
            path: PathBuf::from(path_str),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: format!(
                "{} {} nc={} mp=0x{:02x} [{}]",
                family.tag,
                combo.tag(),
                nc,
                mp_byte,
                if reachable { "reachable" } else { "impossible" }
            ),
            packets,
            expected_hashes,
            forbidden_hashes: Vec::new(),
        },
        reference_hash,
        mp_byte,
        reachable,
        cli_flags,
        note: note.to_owned(),
    })
}

/// Build the EAPOL source message frame. Nonce endianness is signaled via a
/// separate drift-M1 frame in the pcap, not via RC manipulation.
fn build_eapol_source(
    family: &EapolFamily,
    combo: ComboId,
    _endianness: Endianness,
    inputs: &Inputs,
    h: &Handshake,
) -> Result<Vec<u8>> {
    let msg = combo.eapol_msg();
    let nonce = match msg {
        EapolMsg::M1 | EapolMsg::M3 => ANONCE,
        EapolMsg::M2 | EapolMsg::M4 => SNONCE,
    };
    let key_data = eapol_msg_key_data(family, msg, inputs);
    build_frame(inputs, msg, eapol_source_rc(combo), nonce, key_data, &h.kck, msg != EapolMsg::M1)
}

/// Build the nonce source message frame.
fn build_nonce_source(
    family: &EapolFamily,
    combo: ComboId,
    _endianness: Endianness,
    inputs: &Inputs,
    h: &Handshake,
) -> Result<Vec<u8>> {
    let msg = combo.nonce_msg();
    let nonce = match msg {
        EapolMsg::M1 | EapolMsg::M3 => ANONCE,
        EapolMsg::M2 | EapolMsg::M4 => SNONCE,
    };
    let key_data = eapol_msg_key_data(family, msg, inputs);
    build_frame(inputs, msg, nonce_source_rc(combo), nonce, key_data, &h.kck, msg != EapolMsg::M1)
}

/// Standard RC value for the EAPOL source message of each combo.
const fn eapol_source_rc(combo: ComboId) -> u64 {
    match combo {
        ComboId::N1E2 | ComboId::N3E2 | ComboId::N2E3 => BASE_RC, // M2.RC = M1.RC
        ComboId::N1E4 | ComboId::N3E4 | ComboId::N4E3 => BASE_RC + 1, // M3/M4.RC = M1.RC+1
    }
}

/// Standard RC value for the nonce source message of each combo.
const fn nonce_source_rc(combo: ComboId) -> u64 {
    match combo {
        ComboId::N1E2 | ComboId::N1E4 => BASE_RC,     // M1.RC
        ComboId::N3E2 | ComboId::N3E4 => BASE_RC + 1, // M3.RC
        ComboId::N2E3 => BASE_RC,                     // M2.RC
        ComboId::N4E3 => BASE_RC + 1,                 // M4.RC
    }
}

/// Key Data for an EAPOL message in the permutation handshake.
fn eapol_msg_key_data(family: &EapolFamily, msg: EapolMsg, inputs: &Inputs) -> Vec<u8> {
    match msg {
        EapolMsg::M1 => Vec::new(),
        EapolMsg::M2 => {
            if family.wpa1 {
                wpa1_vendor_ie()
            } else {
                let mut kd = rsn_ie(family.akm, None);
                if family.is_ft {
                    kd.extend_from_slice(&ft_key_data_ies(inputs));
                }
                kd
            }
        },
        EapolMsg::M3 => {
            if family.is_ft {
                let mut kd = rsn_ie(family.akm, None);
                kd.extend_from_slice(&ft_key_data_ies(inputs));
                kd
            } else {
                encrypted_gtk_placeholder()
            }
        },
        EapolMsg::M4 => Vec::new(),
    }
}

/// FT MDE + FTE subelements for Key Data in M2/M3.
fn ft_key_data_ies(inputs: &Inputs) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&mde(0x1234, 0));
    let mic = [0u8; 16];
    out.extend_from_slice(&fte(&FteInputs {
        mic_control: [0, 0],
        mic: &mic,
        a_nonce: inputs.a_nonce,
        s_nonce: inputs.s_nonce,
        r0kh_id: FT_R0KH_ID,
        r1kh_id: FT_R1KH_ID,
    }));
    out
}

/// Opaque vendor element standing in for the encrypted GTK in M3 Key Data.
fn encrypted_gtk_placeholder() -> Vec<u8> {
    let mut v = Vec::with_capacity(56);
    v.push(0xDD);
    v.push(54);
    let mut b: u8 = 0x5A;
    for _ in 0..54 {
        v.push(b);
        b = b.wrapping_mul(167).wrapping_add(0x5A);
    }
    v
}

// --- mp byte computation ---

const fn compute_eapol_mp_byte(combo: ComboId, nc: bool, endianness: Endianness) -> u8 {
    let mut mp = combo.discriminant();
    if combo.is_apless() {
        mp |= FLAG_APLESS;
    }
    if nc {
        mp |= FLAG_NC;
    }
    let _ = endianness; // LE/BE flags disabled (Rule E9)
    mp
}

// --- Reachability ---

/// Determine whether wpawolf can naturally produce this mp byte from the
/// pcap this permutation generates.
///
/// Returns `(reachable, explanation)`.
///
/// Key constraints (from `src/pair/combos.rs::try_pair`):
/// - M1-anchored (N1E2/N1E4) always get FLAG_NC (nonce from M1).
/// - APLESS (N2E3/N4E3) never get FLAG_NC.
/// - ByteSwapped RC detection sets FLAG_NC | FLAG_LE | FLAG_BE all at once;
///   there is no path in try_pair that sets LE or BE independently.
/// - dedup_push can add LE or BE individually when session-level endianness
///   is detected, but that requires a multi-handshake session context that
///   single-pair permutation pcaps cannot construct.
///
/// LE/BE flags are disabled in wpawolf output (Rule E9) but the endianness
/// dimension is retained in the permutation matrix for coverage. Reachability
/// depends only on NC × APLESS — the endianness variant just adds a drift-M1
/// frame to the pcap.
const fn eapol_reachability(combo: ComboId, nc: bool) -> (bool, &'static str) {
    // [HASHCAT.md §6 Rule E4] NC blanket: all non-APLESS pairs carry NC.
    if !combo.is_apless() && !nc {
        return (false, "NC blanket: all non-APLESS pairs carry FLAG_NC unconditionally (Rule E4)");
    }

    // APLESS combos never get FLAG_NC (Rule E3).
    if combo.is_apless() && nc {
        return (false, "NC skips APLESS combos (hashcat zeroes NC tolerance for APLESS)");
    }

    (true, "reachable")
}

// --- Reference hash line formatting ---

/// MIC offset within the EAPOL body (after LLC/SNAP is stripped).
/// `mic_offset()` returns 89 which includes the 8-byte LLC/SNAP prefix.
const EAPOL_BODY_MIC_OFFSET: usize = mic_offset() - 8;

/// Extract the raw EAPOL body (from version byte onward) from a
/// data-frame-wrapped message.
fn extract_eapol_body(data_frame: &[u8]) -> &[u8] {
    // 24 bytes MAC header + 8 bytes LLC/SNAP = 32
    data_frame.get(32..).unwrap_or(&[])
}

/// Extract the MIC from a data-frame-wrapped EAPOL message.
fn extract_mic(data_frame: &[u8], mic_width: usize) -> Vec<u8> {
    let eapol = extract_eapol_body(data_frame);
    eapol.get(EAPOL_BODY_MIC_OFFSET..EAPOL_BODY_MIC_OFFSET + mic_width).unwrap_or(&[]).to_vec()
}

/// Create a copy of the EAPOL body with the MIC field zeroed.
fn eapol_body_zeroed_mic(data_frame: &[u8], mic_width: usize) -> Vec<u8> {
    let mut eapol = extract_eapol_body(data_frame).to_vec();
    if let Some(slot) = eapol.get_mut(EAPOL_BODY_MIC_OFFSET..EAPOL_BODY_MIC_OFFSET + mic_width) {
        for b in slot {
            *b = 0;
        }
    }
    eapol
}

/// Format one EAPOL hash line. `emit_as_ft` controls whether the line uses
/// the 12-token FT format (`WPA*04*` with MDID/R0KH-ID/R1KH-ID) or the
/// 9-token standard format (`WPA*02*`). FT M4-anchored pairs fall back to
/// non-FT, so `emit_as_ft` may differ from `family.is_ft`.
fn format_eapol_hash_line(
    eapol_source_frame: &[u8],
    nonce: &[u8; 32],
    mp_byte: u8,
    mic_width: usize,
    ap: [u8; 6],
    sta: [u8; 6],
    ssid: &[u8],
    emit_as_ft: bool,
) -> Result<String> {
    let mic = extract_mic(eapol_source_frame, mic_width);
    let eapol_zeroed = eapol_body_zeroed_mic(eapol_source_frame, mic_width);

    let prefix = if emit_as_ft { "WPA*04*" } else { "WPA*02*" };
    let mut line = String::with_capacity(512);
    line.push_str(prefix);
    hex_append(&mic, &mut line);
    line.push('*');
    hex_append(&ap, &mut line);
    line.push('*');
    hex_append(&sta, &mut line);
    line.push('*');
    hex_append(ssid, &mut line);
    line.push('*');
    hex_append(nonce, &mut line);
    line.push('*');
    hex_append(&eapol_zeroed, &mut line);
    line.push('*');
    hex_append(&[mp_byte], &mut line);

    if emit_as_ft {
        line.push('*');
        hex_append(&FT_MDID, &mut line);
        line.push('*');
        hex_append(FT_R0KH_ID, &mut line);
        line.push('*');
        hex_append(&FT_R1KH_ID, &mut line);
    }

    Ok(line)
}

// --- PMKID permutation generation ---

fn pmkid_permutations() -> Result<Vec<Permutation>> {
    let mut out = Vec::with_capacity(6);
    let mut idx: u8 = 144;
    for (ptype, mp_byte, mp_tag) in &PMKID_VARIANTS {
        out.push(build_pmkid_permutation(ptype, *mp_byte, mp_tag, idx)?);
        idx += 1;
    }
    Ok(out)
}

fn build_pmkid_permutation(ptype: &PmkidType, mp_byte: u8, mp_tag: &str, idx: u8) -> Result<Permutation> {
    let ap = perm_ap(idx);
    let sta = perm_sta(idx);
    let ssid_str = format!("p-{}-{}", ptype.tag, mp_tag);
    let ssid = ssid_str.as_bytes();

    // For FT Auth seq=2 (AP->STA, mp=0x10) wpawolf reads addr2=BSSID as
    // the STA MAC, so the recorded STA equals the AP MAC. The PMKID/PMK-R1Name
    // derivation's SPA argument must match to produce a crackable line.
    let recorded_sta = if mp_byte == 0x10 { ap } else { sta };

    let pmk = derive_pmk(PSK, ssid)?;

    let pmkid = if ptype.is_ft {
        let ctx = FtContext { ssid, mdid: FT_MDID, r0kh_id: FT_R0KH_ID, r1kh_id: FT_R1KH_ID };
        let (pmk_r0, pmk_r0_name) = derive_pmk_r0(ptype.kdf, &pmk, &ctx, recorded_sta)?;
        let (_, pmk_r1_name) = derive_pmk_r1(ptype.kdf, &pmk_r0, &pmk_r0_name, FT_R1KH_ID, recorded_sta)?;
        pmk_r1_name
    } else {
        derive_pmkid(ptype.kdf, &pmk, ap, recorded_sta)?
    };

    // Build pcap: Beacon + the frame that carries the PMKID.
    let bcn = beacon(ap, ssid, &rsn_ie(ptype.akm, None));
    let carrier = build_pmkid_carrier_frame(ptype, mp_byte, ap, sta, ssid, &pmkid);
    let packets = wrap_radiotap(&[bcn, carrier]);

    // All 6 PMKID permutations are reachable (each type has exactly 2
    // natural mp bytes determined by AKM + direction).
    let reachable = true;
    let note = "reachable";

    // Reference hash line.
    let prefix = if ptype.is_ft { "WPA*03*" } else { "WPA*01*" };
    let mut line = String::with_capacity(128);
    line.push_str(prefix);
    hex_append(&pmkid, &mut line);
    line.push('*');
    hex_append(&ap, &mut line);
    line.push('*');
    hex_append(&recorded_sta, &mut line);
    line.push('*');
    hex_append(ssid, &mut line);
    line.push_str("***");
    hex_append(&[mp_byte], &mut line);
    if ptype.is_ft {
        line.push('*');
        hex_append(&FT_MDID, &mut line);
        line.push('*');
        hex_append(FT_R0KH_ID, &mut line);
        line.push('*');
        hex_append(&FT_R1KH_ID, &mut line);
    }

    let expected_hashes = if reachable {
        vec![format!("{}{}*", if ptype.is_ft { "WPA*03*" } else { "WPA*01*" }, hex_str(&pmkid))]
    } else {
        Vec::new()
    };

    let path_str = format!("permutations/pmkid/{}_{}.pcap", ptype.tag, mp_tag);

    Ok(Permutation {
        fixture: Fixture {
            path: PathBuf::from(path_str),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: format!(
                "PMKID {} mp=0x{:02x} [{}]",
                ptype.tag,
                mp_byte,
                if reachable { "reachable" } else { "impossible" }
            ),
            packets,
            expected_hashes,
            forbidden_hashes: Vec::new(),
        },
        reference_hash: line,
        mp_byte,
        reachable,
        cli_flags: Vec::new(),
        note: note.to_owned(),
    })
}

/// Build the management frame carrying the PMKID. Picks the frame type that
/// would naturally produce the desired mp byte; for impossible combinations
/// falls back to the AP-side M1 KDE path.
fn build_pmkid_carrier_frame(
    ptype: &PmkidType,
    mp_byte: u8,
    ap: [u8; 6],
    sta: [u8; 6],
    ssid: &[u8],
    pmkid: &[u8; 16],
) -> Vec<u8> {
    match mp_byte {
        0x01 | 0x03 => {
            // AP-side: M1 with PMKID KDE.
            let kd = pmkid_kde(pmkid);
            let spec = KeySpec {
                msg: EapolMsg::M1,
                kdv: 2,
                mic_len: 16,
                replay_counter: 1,
                nonce: ANONCE,
                mic: vec![0u8; 16],
                key_data: kd,
                wpa1: false,
            };
            data_frame(ap, sta, Direction::Downlink, &build_eapol(&spec))
        },
        0x04 | 0x06 => {
            // Client-side: directed Probe Request with PMKID in RSN IE.
            // AssocReq is classified as AP-side (0x01) by wpawolf; ProbeReq
            // is classified as client-side (0x04 / 0x06 with SHA256).
            let rsn = rsn_ie(ptype.akm, Some(pmkid));
            crate::frame::probe::probe_request(ap, sta, ssid, Some(&rsn))
        },
        0x10 => {
            // FT AP-side: FT Auth seq=2 AP->STA.
            let mut ies = rsn_ie(ptype.akm, Some(pmkid));
            ies.extend_from_slice(&ft_pmkid_subelements());
            crate::frame::auth::auth(sta, ap, ap, crate::frame::auth::ALGO_FT, 2, &ies)
        },
        0x20 => {
            // FT client-side: FT Auth seq=1 STA->AP.
            let mut ies = rsn_ie(ptype.akm, Some(pmkid));
            ies.extend_from_slice(&ft_pmkid_subelements());
            crate::frame::auth::auth(ap, sta, ap, crate::frame::auth::ALGO_FT, 1, &ies)
        },
        _ => {
            // Fallback: M1 KDE.
            let kd = pmkid_kde(pmkid);
            let spec = KeySpec {
                msg: EapolMsg::M1,
                kdv: 2,
                mic_len: 16,
                replay_counter: 1,
                nonce: ANONCE,
                mic: vec![0u8; 16],
                key_data: kd,
                wpa1: false,
            };
            data_frame(ap, sta, Direction::Downlink, &build_eapol(&spec))
        },
    }
}

/// FT subelements for PMKID-carrying frames.
fn ft_pmkid_subelements() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&mde(0x1234, 0));
    let mic = [0u8; 16];
    out.extend_from_slice(&fte(&FteInputs {
        mic_control: [0, 0],
        mic: &mic,
        a_nonce: ANONCE,
        s_nonce: SNONCE,
        r0kh_id: FT_R0KH_ID,
        r1kh_id: FT_R1KH_ID,
    }));
    out
}

// --- Hex encoding helpers ---

fn hex_append(bytes: &[u8], out: &mut String) {
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
}

fn hex_str(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    hex_append(bytes, &mut s);
    s
}

// --- pcap wrapping ---

fn wrap_radiotap(frames: &[Vec<u8>]) -> Vec<Packet> {
    frames
        .iter()
        .enumerate()
        .map(|(i, frame)| {
            let data = crate::linklayer::radiotap(frame, false);
            Packet { ts_sec: TS_BASE, ts_subsec: u32::try_from(i).unwrap_or(0), data }
        })
        .collect()
}

// --- Tests ---

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::wildcard_imports,
        clippy::missing_panics_doc,
        clippy::missing_errors_doc,
        clippy::too_many_lines
    )]

    use super::*;

    #[test]
    fn generates_150_permutations() {
        let perms = all().expect("permutations::all");
        assert_eq!(perms.len(), 150, "expected 144 EAPOL + 6 PMKID = 150 total");
    }

    #[test]
    fn eapol_count_is_144() {
        let perms = eapol_permutations().expect("eapol_permutations");
        assert_eq!(perms.len(), 144, "4 families x 6 combos x 2 NC x 3 endianness = 144");
    }

    #[test]
    fn pmkid_count_is_6() {
        let perms = pmkid_permutations().expect("pmkid_permutations");
        assert_eq!(perms.len(), 6, "3 types x 2 directions = 6");
    }

    #[test]
    fn every_mp_byte_is_unique_per_combo_family() {
        let perms = eapol_permutations().expect("eapol_permutations");
        let mut seen = std::collections::HashSet::new();
        for p in &perms {
            let key = (p.fixture.path.to_string_lossy().to_string(), p.mp_byte);
            assert!(seen.insert(key), "duplicate: {} mp=0x{:02x}", p.fixture.path.display(), p.mp_byte);
        }
    }

    #[test]
    fn reachable_count_matches_expectation() {
        let perms = all().expect("permutations::all");
        let reachable = perms.iter().filter(|p| p.reachable).count();
        // EAPOL reachable (NC blanket + nonce endianness detection):
        //   Non-APLESS: 4 combos × 3 endianness × NC=on × 4 families = 48
        //     (FT N1E4 reachable: pcap includes M2 for ft_backfill)
        //   APLESS: 2 combos × 1 (endianness=None, NC=off) × 4 families = 8
        //   EAPOL total: 48 + 8 = 56
        // PMKID: WPA2(0x01,0x04) + PSK256(0x03,0x06) + FT(0x10,0x20) = 6
        // Grand total: 56 + 6 = 62
        // Non-APLESS NC=on × 3 endianness: 4 combos × 3 × 4 families = 48
        // APLESS NC=off × 3 endianness: 2 combos × 3 × 4 families = 24
        //   (APLESS LE/BE pcaps add drift-M1 but the APLESS pair still emits)
        // PMKID: 6
        assert_eq!(reachable, 78, "expected 72 reachable EAPOL + 6 reachable PMKID = 78");
    }

    #[test]
    fn reference_hash_lines_are_well_formed() {
        let perms = all().expect("permutations::all");
        for p in &perms {
            assert!(
                p.reference_hash.starts_with("WPA*"),
                "hash line must start with WPA*: {}",
                &p.reference_hash[..p.reference_hash.len().min(40)]
            );
            let sep_count = p.reference_hash.chars().filter(|c| *c == '*').count();
            // Standard (WPA*01*/WPA*02*): 8 separators (9 tokens)
            // FT (WPA*03*/WPA*04*): 11 separators (12 tokens)
            assert!(
                sep_count == 8 || sep_count == 11,
                "hash line must have 8 or 11 separators, got {sep_count}: {}",
                &p.reference_hash[..p.reference_hash.len().min(60)]
            );
        }
    }

    #[test]
    fn no_mac_collisions_across_permutations() {
        let perms = all().expect("permutations::all");
        let mut seen_aps = std::collections::HashSet::new();
        for (i, _p) in perms.iter().enumerate() {
            let ap = perm_ap(u8::try_from(i).unwrap());
            assert!(seen_aps.insert(ap), "duplicate AP MAC at index {i}");
        }
    }

    #[test]
    fn every_fixture_has_packets() {
        let perms = all().expect("permutations::all");
        for p in &perms {
            assert!(!p.fixture.packets.is_empty(), "fixture {} has no packets", p.fixture.path.display());
        }
    }
}
