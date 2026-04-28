//! Fixture catalog -- enumerates the corpus the generator emits.
//!
//! `catalog::all()` returns a deterministic `Vec<Fixture>` so the CLI and the
//! integration test both walk the corpus in the same order. Each `Fixture`
//! carries everything needed to produce one pcap or pcapng file: the link
//! layer, the container, the frame sequence, and the ground-truth hash
//! lines wpawolf is expected to emit.
//!
//! The catalog is organised by code path under test:
//!
//! - **`11_types/`** -- one fixture per [`HashType`](crate::types::HashType);
//!   exercises every (AKM, KDV, MIC width, source) combination wpawolf can
//!   classify.
//! - **`20_pmkid_sites/`** -- one fixture per [`PmkidSource`] S1-S20.
//! - **`6_combos/`** -- one fixture per N#E# pairing combo.
//! - **`edge/`** -- one fixture per defensive edge case
//!   (NULL/`0xFF` sentinels, FCS strip, container variants, ...).

use std::path::PathBuf;

use crate::Result;
use crate::crypto::{FtContext, HashFamily, derive_pmk, derive_pmk_r0, derive_pmk_r1, derive_pmkid};
use crate::frame::action::{
    CATEGORY_FT, CATEGORY_MESH, FT_ACTION_CONFIRM, FT_ACTION_REQUEST, FT_ACTION_RESPONSE, MESH_PEERING_CONFIRM,
    MESH_PEERING_OPEN, action,
};
use crate::frame::assoc::assoc_request;
use crate::frame::auth::{ALGO_FILS_PK, ALGO_FILS_SK, ALGO_FT, ALGO_PASN, auth};
use crate::frame::beacon::{beacon, probe_response};
use crate::frame::eapol::{
    Direction, KeySpec, Message as EapolMsg, amsdu_data_frame, build as build_eapol, data_frame,
    fragmented_data_frames, wds_data_frame,
};
use crate::frame::ie::{FteInputs, ampe_with_pmkid, fte, mde, osen_ie, rsn_ie, ssid as ssid_ie, wpa1_vendor_ie};
use crate::frame::kde::pmkid as pmkid_kde;
use crate::frame::probe::{probe_request, probe_request_broadcast_to_ap};
use crate::handshake::{FT_MDID, FT_R0KH_ID, FT_R1KH_ID, Handshake, Inputs};
use crate::linklayer::{LinkType, avs, ppi, prism, prism_wrapping_avs, radiotap};
use crate::pcap_writer::{Packet, PcapMagic};

/// One fixture file the generator will write.
///
/// Multi-file fixtures (M1 in file A, M2-M4 in file B) are modelled as two
/// separate [`Fixture`] entries that share a `multi_file_group` key in their
/// description; the integration test groups them at runtime.
#[derive(Debug, Clone)]
pub struct Fixture {
    /// Output path relative to the corpus root (e.g.
    /// `11_types/type02_wpa2_pmkid.pcap`).
    pub path: PathBuf,
    /// Container + byte-order variant.
    pub container: Container,
    /// DLT (link type) embedded in the container.
    pub link_type: LinkType,
    /// Human-readable description -- emitted to the manifest.
    pub description: String,
    /// Wire packets to write in order.
    pub packets: Vec<Packet>,
    /// Hash lines this fixture is expected to produce when run through
    /// wpawolf. Empty if the fixture exercises a rejection path.
    pub expected_hashes: Vec<String>,
    /// Hash-line prefixes that must NOT appear when wpawolf processes this
    /// fixture in isolation. Negative-emission oracle for sentinel-rejection
    /// fixtures (NULL / `0xFF` nonces / PMKIDs / MICs) and incomplete-handshake
    /// fixtures (`multi_file_a` carries M1 only -- it must not emit the EAPOL
    /// pair line that appears when paired with `multi_file_b`). Catches
    /// regressions where a sentinel check is removed or a pairing path leaks
    /// a hash from an incomplete fixture.
    pub forbidden_hashes: Vec<String>,
}

/// Container the fixture is wrapped in.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Container {
    /// Classic pcap.
    Pcap(PcapMagic),
    /// pcapng with little-endian section.
    PcapNg,
    /// pcapng with big-endian section.
    PcapNgBe,
    /// Gzipped pcap.
    PcapGz(PcapMagic),
    /// Gzipped pcapng (LE section).
    PcapNgGz,
}

const PSK: &[u8] = b"hashcat!";
const ANONCE: [u8; 32] = [0xA1; 32];
const SNONCE: [u8; 32] = [0xB2; 32];

const TS_BASE_SEC: u32 = 1_700_000_000;

/// Per-fixture AP MAC. `idx` is reserved per fixture so that the whole-corpus
/// pairing run (every file processed in one wpawolf invocation) keeps each
/// fixture's handshakes inside its own `MacPair{ap,sta}` namespace and cannot
/// cross-pollinate ESSIDs / EAPOL frames between fixtures.
///
/// Locally-administered OUI (high bit of byte 0 set) so the address cannot
/// collide with any real-world device.
const fn ap_mac(idx: u8) -> [u8; 6] {
    [0x02, 0x11, 0x22, 0x33, 0x44, idx]
}

/// Per-fixture STA MAC. See [`ap_mac`].
const fn sta_mac(idx: u8) -> [u8; 6] {
    [0x02, 0xAA, 0xBB, 0xCC, 0xDD, idx]
}

// Per-section MAC index ranges. Reserve 16 IDs per section so future growth
// (more S-sites, more combos, more edge cases) does not require renumbering.
const IDX_TYPES_BASE: u8 = 0x10; // 11_types/: 0x10..=0x1A
const IDX_PMKID_BASE: u8 = 0x20; // 20_pmkid_sites/: 0x20..=0x33
const IDX_COMBO_BASE: u8 = 0x40; // 6_combos/: 0x40..=0x45
const IDX_LINK_LAYERS: u8 = 0x50; // link_layers/: shared across all 7 variants
const IDX_CONTAINERS: u8 = 0x60; // containers/: shared across all 14 variants
const IDX_EDGE_BASE: u8 = 0x70; // edge/: 0x70+
const IDX_AKM_VARIANTS: u8 = 0x80; // 20_pmkid_sites/sNN_<akm>.pcap variants: 0x80+
// edge/multi_file_a + edge/multi_file_b share this idx so wpawolf can pair
// across the two files (FR-PAIR-CROSS-FILE).
const IDX_EDGE_MULTI_FILE: u8 = 0x7E;

/// Taxonomy prefixes a per-`HashType` fixture must produce when wpawolf
/// processes it in isolation. Each pair of consecutive types (PMKID + EAPOL)
/// shares a fixture so both prefixes are expected for `n in {2..11}`.
fn types_expected_prefixes(n: u8) -> Vec<String> {
    match n {
        1 => vec!["WPA*01*".to_owned()],
        2 | 3 => vec!["WPA*02*".to_owned(), "WPA*03*".to_owned()],
        4 | 5 => vec!["WPA*04*".to_owned(), "WPA*05*".to_owned()],
        6 | 7 => vec!["WPA*06*".to_owned(), "WPA*07*".to_owned()],
        8 | 9 => vec!["WPA*08*".to_owned(), "WPA*09*".to_owned()],
        10 | 11 => vec!["WPA*10*".to_owned(), "WPA*11*".to_owned()],
        _ => Vec::new(),
    }
}

/// Baseline WPA2-PSK handshake expected output: PMKID (Type 02) + EAPOL
/// (Type 03). Used by `link_layers/`, `containers/`, and the WPA2-baseline
/// `edge/` fixtures that actually emit handshakes.
fn wpa2_baseline_prefixes() -> Vec<String> {
    vec!["WPA*02*".to_owned(), "WPA*03*".to_owned()]
}

/// Build the full corpus catalog.
///
/// # Errors
///
/// Forwards any [`crate::Error`] from the handshake / framing layers.
pub fn all() -> Result<Vec<Fixture>> {
    let mut out = Vec::new();
    out.extend(types_section()?);
    out.extend(pmkid_section()?);
    out.extend(pmkid_akm_variants_section()?);
    out.extend(combo_section()?);
    out.extend(link_layers_section()?);
    out.extend(containers_section()?);
    out.extend(edge_section()?);
    Ok(out)
}

/// One taxonomy entry in the cases table.
struct TypeCase {
    n: u8,
    name: &'static str,
    kdf_family: HashFamily,
    mic_family: HashFamily,
    akm_byte: u8,
    kdv: u8,
    wpa1: bool,
    descr: &'static str,
}

/// Build a per-`HashType` fixture for each of the 11 taxonomy entries.
fn types_section() -> Result<Vec<Fixture>> {
    let cases: &[TypeCase] = &[
        TypeCase {
            n: 1,
            name: "type01_wpa1_eapol",
            kdf_family: HashFamily::Sha1,
            mic_family: HashFamily::Md5,
            akm_byte: 2,
            kdv: 1,
            wpa1: true,
            descr: "WPA1-PSK EAPOL (KDV=1, HMAC-MD5 MIC)",
        },
        TypeCase {
            n: 2,
            name: "type02_wpa2_pmkid",
            kdf_family: HashFamily::Sha1,
            mic_family: HashFamily::Sha1,
            akm_byte: 2,
            kdv: 2,
            wpa1: false,
            descr: "WPA2-PSK PMKID (HMAC-SHA1-128)",
        },
        TypeCase {
            n: 3,
            name: "type03_wpa2_eapol",
            kdf_family: HashFamily::Sha1,
            mic_family: HashFamily::Sha1,
            akm_byte: 2,
            kdv: 2,
            wpa1: false,
            descr: "WPA2-PSK EAPOL (KDV=2, HMAC-SHA1-128 MIC)",
        },
        TypeCase {
            n: 4,
            name: "type04_psksha256_pmkid",
            kdf_family: HashFamily::Sha256,
            mic_family: HashFamily::AesCmac128,
            akm_byte: 6,
            kdv: 3,
            wpa1: false,
            descr: "PSK-SHA256 PMKID (HMAC-SHA256-128)",
        },
        TypeCase {
            n: 5,
            name: "type05_psksha256_eapol",
            kdf_family: HashFamily::Sha256,
            mic_family: HashFamily::AesCmac128,
            akm_byte: 6,
            kdv: 3,
            wpa1: false,
            descr: "PSK-SHA256 EAPOL (KDV=3, AES-128-CMAC MIC)",
        },
        TypeCase {
            n: 6,
            name: "type06_ftpsk_pmkid",
            kdf_family: HashFamily::Sha256,
            mic_family: HashFamily::AesCmac128,
            akm_byte: 4,
            kdv: 3,
            wpa1: false,
            descr: "FT-PSK PMKID (SHA-256 chain)",
        },
        TypeCase {
            n: 7,
            name: "type07_ftpsk_eapol",
            kdf_family: HashFamily::Sha256,
            mic_family: HashFamily::AesCmac128,
            akm_byte: 4,
            kdv: 3,
            wpa1: false,
            descr: "FT-PSK EAPOL (KDV=3, AES-128-CMAC MIC)",
        },
        TypeCase {
            n: 8,
            name: "type08_psksha384_pmkid",
            kdf_family: HashFamily::Sha384,
            mic_family: HashFamily::Sha384,
            akm_byte: 20,
            kdv: 0,
            wpa1: false,
            descr: "PSK-SHA384 PMKID (HMAC-SHA384-128)",
        },
        TypeCase {
            n: 9,
            name: "type09_psksha384_eapol",
            kdf_family: HashFamily::Sha384,
            mic_family: HashFamily::Sha384,
            akm_byte: 20,
            kdv: 0,
            wpa1: false,
            descr: "PSK-SHA384 EAPOL (KDV=0, 24-byte MIC)",
        },
        TypeCase {
            n: 10,
            name: "type10_ftpsk_sha384_pmkid",
            kdf_family: HashFamily::Sha384,
            mic_family: HashFamily::Sha384,
            akm_byte: 19,
            kdv: 0,
            wpa1: false,
            descr: "FT-PSK-SHA384 PMKID",
        },
        TypeCase {
            n: 11,
            name: "type11_ftpsk_sha384_eapol",
            kdf_family: HashFamily::Sha384,
            mic_family: HashFamily::Sha384,
            akm_byte: 19,
            kdv: 0,
            wpa1: false,
            descr: "FT-PSK-SHA384 EAPOL (24-byte MIC)",
        },
    ];
    let mut fixtures = Vec::with_capacity(cases.len());
    for c in cases {
        let ssid = format!("wpawolf-t{:02}", c.n);
        let ap = ap_mac(IDX_TYPES_BASE + c.n);
        let sta = sta_mac(IDX_TYPES_BASE + c.n);
        let inputs = Inputs {
            psk: PSK.to_vec(),
            ssid: ssid.as_bytes().to_vec(),
            ap,
            sta,
            kdf_family: c.kdf_family,
            mic_family: c.mic_family,
            akm_byte: c.akm_byte,
            a_nonce: ANONCE,
            s_nonce: SNONCE,
            replay_counter: 1,
            kdv: c.kdv,
            wpa1: c.wpa1,
        };
        let h = Handshake::all(&inputs)?;
        let beacon_rsn = if c.wpa1 { wpa1_vendor_ie() } else { rsn_ie(c.akm_byte, None) };
        let bcn = beacon(ap, ssid.as_bytes(), &beacon_rsn);
        let assoc_extra = if matches!(c.akm_byte, 4 | 19) { ft_extras() } else { Vec::new() };
        // Embed the PMKID in the AssocReq RSN IE (S3 source) so the
        // FR-OUT-3 emission gate (FT types need MDID + R0KH-ID + R1KH-ID
        // attached to the PMKID) is satisfied for all 11 hash types.
        // WPA1 has no PMKID; the if-let handles that.
        let assoc_rsn = if c.wpa1 {
            wpa1_vendor_ie()
        } else if let Some(pmkid) = h.pmkid.as_ref() {
            rsn_ie(c.akm_byte, Some(pmkid))
        } else {
            rsn_ie(c.akm_byte, None)
        };
        let assoc = assoc_request(ap, sta, ssid.as_bytes(), &assoc_rsn, &assoc_extra);
        let packets = wrap_with_radiotap(&[bcn, assoc, h.m1.clone(), h.m2.clone(), h.m3.clone(), h.m4.clone()]);
        fixtures.push(Fixture {
            path: PathBuf::from(format!("11_types/{}.pcap", c.name)),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: c.descr.to_owned(),
            packets,
            expected_hashes: types_expected_prefixes(c.n),
            forbidden_hashes: Vec::new(),
        });
    }
    Ok(fixtures)
}

/// Build one fixture per S1-S20 PMKID extraction site.
///
/// Each fixture isolates one frame type carrying a PMKID so wpawolf's per-
/// source counter can be verified in isolation. Per-fixture AP/STA pair
/// derived from `IDX_PMKID_BASE + s` so cross-fixture pollination is
/// impossible when wpawolf processes the whole corpus in one run.
///
/// All builders return `Vec<Vec<u8>>` (a frame sequence). Most prepend a
/// Beacon carrying the right AKM so wpawolf's `akm_map` is primed before
/// the carrier frame is parsed -- without this, the PMKID would be stored
/// with `AkmType::Unknown` and dropped by the FR-OUT-3 emit gate. The
/// builders for S3 / S4 / S16 / S17 do not need a separate beacon because
/// the carrier frame is itself a Beacon / ProbeResp / AssocReq with an
/// inline RSN IE that primes the AKM map at the same point.
///
/// `(S-number, file-stem, description, frame-builder)` -- one row per S1-S20.
/// Aliased to keep the table type below the `clippy::type_complexity` limit.
type PmkidEntry = (u8, &'static str, &'static str, fn([u8; 6], [u8; 6], &[u8; 16]) -> Vec<Vec<u8>>);

fn pmkid_section() -> Result<Vec<Fixture>> {
    // Synthetic byte pattern used for S-sites whose AKMs are out of wpawolf's
    // PSK-cracking scope (FILS, Mesh). These sites verify the extraction
    // *path* but cannot be cracked by hashcat regardless of the PMKID
    // value, so we keep an obviously-not-derived sentinel pattern.
    let synthetic_pmkid: [u8; 16] =
        [0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let mut out = Vec::new();
    // Some sources need a Beacon for AKM context (S1 / S2). Each entry
    // returns the frame sequence to write rather than a single frame.
    let frames: &[PmkidEntry] = &[
        (1, "s01_eapol_m1_kde", "S1 EAPOL M1 PMKID KDE", build_s1_m1_kde),
        (2, "s02_eapol_m2_rsn_ie", "S2 EAPOL M2 RSN IE in Key Data", build_s2_m2_rsn_ie),
        (3, "s03_assoc_req_rsn_ie", "S3 Association Request RSN IE", |ap, sta, p| vec![build_s3_assoc_req(ap, sta, p)]),
        (4, "s04_reassoc_req_rsn_ie", "S4 Reassociation Request RSN IE", |ap, sta, p| {
            vec![build_s4_reassoc_req(ap, sta, p)]
        }),
        (5, "s05_ft_auth_seq1", "S5 FT Auth seq=1 STA->AP", build_s5_ft_auth_1),
        (6, "s06_ft_auth_seq2", "S6 FT Auth seq=2 AP->STA", build_s6_ft_auth_2),
        (7, "s07_fils_auth_seq1", "S7 FILS Auth seq=1 STA->AP", build_s7_fils_auth_1),
        (8, "s08_fils_auth_seq2", "S8 FILS Auth seq=2 AP->STA", build_s8_fils_auth_2),
        (9, "s09_pasn_auth_seq1", "S9 PASN Auth seq=1 STA->AP", build_s9_pasn_auth_1),
        (10, "s10_pasn_auth_seq2", "S10 PASN Auth seq=2 AP->STA", build_s10_pasn_auth_2),
        (11, "s11_ft_action_request", "S11 FT Action Request", build_s11_ft_action),
        (12, "s12_ft_action_response", "S12 FT Action Response", build_s12_ft_action_response),
        (13, "s13_ft_action_confirm", "S13 FT Action Confirm", build_s13_ft_action_confirm),
        (14, "s14_probe_req_directed", "S14 Probe Request directed", build_s14_probe_req_directed),
        (15, "s15_probe_req_broadcast", "S15 Probe Request broadcast", build_s15_probe_req_broadcast),
        (16, "s16_beacon_rsn_ie", "S16 Beacon RSN IE (vendor firmware deviation)", |ap, _sta, p| {
            vec![build_s16_beacon(ap, p)]
        }),
        (17, "s17_probe_resp_rsn_ie", "S17 Probe Response RSN IE", |ap, sta, p| vec![build_s17_probe_resp(ap, sta, p)]),
        (18, "s18_mesh_peering_open", "S18 Mesh Peering Open AMPE", build_s18_mesh_peering_open),
        (19, "s19_mesh_peering_confirm", "S19 Mesh Peering Confirm AMPE", build_s19_mesh_peering_confirm),
        (20, "s20_assoc_req_osen", "S20 Association Request OSEN IE", build_s20_osen),
    ];
    for (s, name, descr, builder) in frames {
        let ap = ap_mac(IDX_PMKID_BASE + s);
        let sta = sta_mac(IDX_PMKID_BASE + s);
        let pmkid = s_site_pmkid(*s, ap, sta, &synthetic_pmkid)?;
        let seq = builder(ap, sta, &pmkid);
        // Per-site emission expectations. Non-emitting sites are
        // architectural limits in wpawolf, not fixture defects:
        //   S7/S8  (FILS):  AKM 14-17 not in `AkmType` enum, so the FILS
        //                   PMKID is stored with akm=Unknown and dropped
        //                   by the emit gate.
        //   S18/S19 (Mesh): mesh peering PMKIDs are stored with
        //                   akm=Unknown per `src/extract/action.rs:200`
        //                   because mesh authentication uses SAE, which
        //                   is out of wpawolf's PSK scope.
        // The wpawolf-side counters still increment (`pmkid_fils_auth`,
        // `pmkid_mesh` in `stats.rs`), proving the parse path is
        // exercised end-to-end. PASN (S9/S10) and OSEN (S20) used to be
        // in this list before the algo=7 PASN dispatch fix and the
        // OSEN-IE-as-RSN-IE layout fix respectively; their base AKMP
        // resolves to WPA2-PSK via beacon-side AKM advertising, and
        // their PMKIDs are now crackable.
        let expected: Vec<String> = match s {
            1 | 2 | 3 | 4 | 9 | 10 | 14 | 15 | 16 | 17 | 20 => vec!["WPA*02*".to_owned()],
            5 | 6 | 11 | 12 | 13 => vec!["WPA*06*".to_owned()],
            _ => Vec::new(),
        };
        out.push(Fixture {
            path: PathBuf::from(format!("20_pmkid_sites/{name}.pcap")),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: format!("{descr} (S{s})"),
            packets: wrap_with_radiotap(&seq),
            expected_hashes: expected,
            forbidden_hashes: Vec::new(),
        });
    }
    Ok(out)
}

/// Returns the SSID used by the S-site fixture for site `s`. Mirrors the
/// `b"wpawolf-sNN"` literals embedded in the per-site builders so the
/// dispatcher can derive the right PMKID without each builder also taking
/// the SSID as an argument.
fn s_site_ssid(s: u8) -> Vec<u8> {
    format!("wpawolf-s{s:02}").into_bytes()
}

/// Compute the PMKID a wpawolf cracker should reproduce for S-site `s`.
///
/// WPA2-PSK sites (S1-S4, S14-S17, S20) derive `Truncate-128(HMAC-SHA1(PMK,
/// "PMK Name" || AP || SPA))` per `[IEEE 802.11-2024]` §12.7.1.3. FT-PSK
/// sites (S5, S6, S11-S13) derive the FT key hierarchy and use
/// `PMK-R1Name` -- the value hashcat 37100 expects in the `WPA*03*` slot.
/// Sites whose AKMs are out of wpawolf's PSK scope (FILS S7/S8, Mesh
/// S18/S19) keep the synthetic byte pattern the caller passes in: those
/// PMKIDs are never crackable, and the fixture only verifies the
/// parser's extraction path. S20 (OSEN, Hotspot 2.0) embeds a PMKID in
/// an Assoc Request whose BSSID is also advertised as WPA2-PSK by the
/// fixture beacon -- wpawolf resolves the OSEN entry to `Wpa2Psk` at
/// emission time, so the hash is crackable.
///
/// The `SPA` argument to `HMAC-SHA1` must match the STA MAC wpawolf
/// records for the entry, *not* the wire `addr1`. For management frames
/// with `ToDS = FromDS = 0` (Beacon S16, ProbeResp S17) wpawolf records
/// `sta = addr2 = BSSID`, so the PMKID derivation uses `ap` for both
/// arguments. The other WPA2 sites (S1-S4, S14, S15) all have
/// `sta = addr2 = STA-MAC` and use the regular `(ap, sta)` pair.
fn s_site_pmkid(s: u8, ap: [u8; 6], sta: [u8; 6], synthetic: &[u8; 16]) -> Result<[u8; 16]> {
    let ssid = s_site_ssid(s);
    let pmk = derive_pmk(PSK, &ssid)?;
    let recorded_sta = match s {
        // S6 (FT Auth seq=2 AP->STA), S10 (PASN Auth seq=2 AP->STA), S16
        // (Beacon), and S17 (ProbeResp) all carry `addr2 = BSSID` on the
        // wire. wpawolf reads `addr2` into `mac_hdr.sta` for management
        // frames (`src/ieee80211/frame.rs:225`), so the recorded STA in the
        // `PmkidEntry` is the AP MAC -- and so is the SPA hashcat feeds
        // into the PMKID HMAC. Use `ap` for both arguments.
        6 | 10 | 16 | 17 => ap,
        _ => sta,
    };
    match s {
        // WPA2-PSK family -- HMAC-SHA1 PMKID.
        1 | 2 | 3 | 4 | 9 | 10 | 14 | 15 | 16 | 17 | 20 => derive_pmkid(HashFamily::Sha1, &pmk, ap, recorded_sta),
        // FT-PSK SHA-256 family -- PMK-R1Name is the cracker-visible PMKID.
        5 | 6 | 11 | 12 | 13 => {
            let ctx = FtContext { ssid: &ssid, mdid: FT_MDID, r0kh_id: FT_R0KH_ID, r1kh_id: FT_R1KH_ID };
            let (pmk_r0, pmk_r0_name) = derive_pmk_r0(HashFamily::Sha256, &pmk, &ctx, recorded_sta)?;
            let (_, pmk_r1_name) = derive_pmk_r1(HashFamily::Sha256, &pmk_r0, &pmk_r0_name, FT_R1KH_ID, recorded_sta)?;
            Ok(pmk_r1_name)
        },
        // Non-PSK or out-of-scope AKMs: keep the synthetic byte pattern.
        _ => Ok(*synthetic),
    }
}

/// Per-AKM variant fixtures for the S-sites that the type-fixture corpus
/// does not implicitly exercise.
///
/// Type fixtures (`11_types/typeNN_*.pcap`) build a full 4-way handshake
/// per AKM family, which already pins down S1 (M1 KDE), S2 (M2 RSN IE),
/// and S3 (Assoc Request) for every AKM. The S-sites that have *no*
/// type-fixture analogue, and so would silently lose AKM-byte-to-HashType
/// coverage if a regression broke the resolver for a non-WPA2 AKM, are:
///
/// - S4  Reassociation Request (no Reassoc in type fixtures)
/// - S14 Probe Request directed   (no ProbeReq in type fixtures)
/// - S17 Probe Response           (no ProbeResp in type fixtures)
///
/// We add a single PSK-SHA-256 (AKM 6) variant for each of these three.
/// hashcat 22000 cracks PSK-SHA-256 EAPOL but not its PMKID (kernel uses
/// HMAC-SHA1 only); the manifest expected_hashes therefore checks for the
/// taxonomy prefix `WPA*04*` (PSK-SHA-256 PMKID) on the combined sink,
/// which proves the AKM was resolved correctly even if the legacy 22000
/// sink can't crack the line. Per-fixture AP / STA MAC pairs come from
/// `IDX_AKM_VARIANTS + i` so they cannot pollinate the existing AKM=2
/// S-sites at corpus-wide processing time.
fn pmkid_akm_variants_section() -> Result<Vec<Fixture>> {
    let mut out = Vec::new();
    let synthetic: [u8; 16] = [0u8; 16]; // unused for these wired AKMs

    // Closure-style entry: (suffix index, file stem, description, AKM byte,
    // builder closure that takes `(ap, sta, akm, ssid, pmkid)` and returns
    // the frame sequence).
    type Builder = fn(ap: [u8; 6], sta: [u8; 6], akm: u8, ssid: &[u8], pmkid: &[u8; 16]) -> Vec<Vec<u8>>;
    // Tuple: (idx, file stem, short SSID (<=32 B), description, AKM byte, builder).
    let entries: &[(u8, &str, &str, &str, u8, Builder)] = &[
        (
            0,
            "s04_reassoc_req_psk_sha256",
            "wpawolf-s04-256",
            "S4 Reassociation Request RSN IE -- PSK-SHA256 AKM variant",
            6,
            |ap, sta, akm, ssid, pmkid| {
                vec![crate::frame::assoc::reassoc_request(ap, sta, ap, ssid, &rsn_ie(akm, Some(pmkid)), &[])]
            },
        ),
        (
            1,
            "s14_probe_req_directed_psk_sha256",
            "wpawolf-s14-256",
            "S14 directed Probe Request -- PSK-SHA256 AKM variant",
            6,
            |ap, sta, akm, ssid, pmkid| {
                let bcn = beacon_for_akm(ap, ssid, akm);
                let rsn = rsn_ie(akm, Some(pmkid));
                vec![bcn, probe_request(ap, sta, ssid, Some(&rsn))]
            },
        ),
        (
            2,
            "s17_probe_resp_psk_sha256",
            "wpawolf-s17-256",
            "S17 Probe Response -- PSK-SHA256 AKM variant",
            6,
            |ap, sta, akm, ssid, pmkid| vec![probe_response(ap, sta, ssid, &rsn_ie(akm, Some(pmkid)))],
        ),
    ];

    for (idx, stem, ssid_str, descr, akm_byte, builder) in entries {
        let ap = ap_mac(IDX_AKM_VARIANTS + idx);
        let sta = sta_mac(IDX_AKM_VARIANTS + idx);
        let ssid = ssid_str.as_bytes().to_vec();
        // PSK-SHA-256 PMKID derivation: HMAC-SHA256(PMK, "PMK Name" || AA || SPA)[0..16].
        // S17 (ProbeResp) carries `addr2 = BSSID` so wpawolf records sta=ap;
        // S4 / S14 record the actual STA MAC. See `s_site_pmkid` for the
        // mirroring rationale.
        let recorded_sta = if stem.starts_with("s17_") { ap } else { sta };
        let pmk = derive_pmk(PSK, &ssid)?;
        let pmkid = derive_pmkid(HashFamily::Sha256, &pmk, ap, recorded_sta)?;
        let _ = synthetic; // suppress unused warning when no synthetic branch fires
        let frames = builder(ap, sta, *akm_byte, &ssid, &pmkid);
        out.push(Fixture {
            path: PathBuf::from(format!("20_pmkid_sites/{stem}.pcap")),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: (*descr).to_owned(),
            packets: wrap_with_radiotap(&frames),
            // The PSK-SHA-256 PMKID emits as taxonomy `WPA*04*`; that's the
            // existence proof that the AKM resolver mapped AKM 6 correctly.
            // hashcat 22000 cannot crack this line (HMAC-SHA1 kernel only);
            // the `--psk-sha256-out` taxonomy sink keeps it crackable for
            // future tooling.
            expected_hashes: vec!["WPA*04*".to_owned()],
            forbidden_hashes: vec!["WPA*02*".to_owned()],
        });
    }

    Ok(out)
}

/// Build one fixture per N#E# pairing combo.
///
/// All six combos share the same crypto-derivation parameters but each gets
/// its own AP/STA MAC pair (`IDX_COMBO_BASE + i`) so wpawolf cannot pair an
/// M1 from one combo's pcap with an M2 from another's when the corpus is
/// processed in one invocation.
fn combo_section() -> Result<Vec<Fixture>> {
    let combos: [(&str, &str, fn(&Handshake) -> Vec<Vec<u8>>); 6] = [
        ("n1e2", "N1E2 -- ANonce(M1) + EAPOL(M2)", |h| vec![h.m1.clone(), h.m2.clone()]),
        ("n1e4", "N1E4 -- ANonce(M1) + EAPOL(M4)", |h| vec![h.m1.clone(), h.m4.clone()]),
        ("n3e2", "N3E2 -- ANonce(M3) + EAPOL(M2)", |h| vec![h.m2.clone(), h.m3.clone()]),
        ("n2e3", "N2E3 -- SNonce(M2) + EAPOL(M3) (APLESS)", |h| vec![h.m2.clone(), h.m3.clone()]),
        ("n4e3", "N4E3 -- SNonce(M4) + EAPOL(M3) (APLESS)", |h| vec![h.m3.clone(), h.m4.clone()]),
        ("n3e4", "N3E4 -- ANonce(M3) + EAPOL(M4)", |h| vec![h.m3.clone(), h.m4.clone()]),
    ];
    let mut out = Vec::with_capacity(combos.len());
    for (i, (name, descr, frame_picker)) in combos.iter().enumerate() {
        let idx = IDX_COMBO_BASE + u8::try_from(i).unwrap_or(0);
        let ap = ap_mac(idx);
        let sta = sta_mac(idx);
        let inputs = Inputs {
            psk: PSK.to_vec(),
            ssid: format!("wpawolf-{name}").into_bytes(),
            ap,
            sta,
            kdf_family: HashFamily::Sha1,
            mic_family: HashFamily::Sha1,
            akm_byte: 2,
            a_nonce: ANONCE,
            s_nonce: SNONCE,
            replay_counter: 7,
            kdv: 2,
            wpa1: false,
        };
        let h = Handshake::all(&inputs)?;
        let beacon_frame = beacon(ap, &inputs.ssid, &rsn_ie(2, None));
        let mut frames = vec![beacon_frame];
        frames.extend(frame_picker(&h));
        // Per the per-fixture sweep: N1E2 / N1E4 carry M1 so they emit both
        // PMKID (Type 02) and EAPOL (Type 03); the M3-only / M4-only combos
        // (N3E2, N2E3, N4E3, N3E4) emit just the EAPOL hash because the
        // PMKID source frame is absent from the fixture's packet sequence.
        let expected =
            if matches!(*name, "n1e2" | "n1e4") { wpa2_baseline_prefixes() } else { vec!["WPA*03*".to_owned()] };
        out.push(Fixture {
            path: PathBuf::from(format!("6_combos/{name}.pcap")),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: (*descr).to_owned(),
            packets: wrap_with_radiotap(&frames),
            expected_hashes: expected,
            forbidden_hashes: Vec::new(),
        });
    }
    Ok(out)
}

/// One fixture per link-layer header wpawolf can strip.
///
/// Each fixture carries the same minimal `Beacon + M1 + M2` payload so the
/// emitted output should be identical across link-layer variants -- any
/// drift is a regression in `src/link/{radiotap,ppi,prism,avs}.rs`. All 7
/// variants intentionally share the same AP/STA pair (`IDX_LINK_LAYERS`) so
/// the cross-variant invariant test compares lines that differ only in the
/// link-layer header bytes the parser strips.
fn link_layers_section() -> Result<Vec<Fixture>> {
    let ap = ap_mac(IDX_LINK_LAYERS);
    let sta = sta_mac(IDX_LINK_LAYERS);
    let inputs = baseline_inputs(b"wpawolf-link", ap, sta);
    let h = Handshake::all(&inputs)?;
    let beacon_frame = beacon(ap, &inputs.ssid, &rsn_ie(2, None));
    let frames: Vec<Vec<u8>> = vec![beacon_frame, h.m1, h.m2];

    let variants: &[(&str, &str, LinkType, LinkWrap)] = &[
        ("ll_raw_802_11", "Raw 802.11 (DLT 105, no link-layer header)", LinkType::Raw, LinkWrap::Raw),
        ("ll_radiotap_no_fcs", "Radiotap (DLT 127), Flags FCS bit clear", LinkType::Radiotap, LinkWrap::RadiotapNoFcs),
        (
            "ll_radiotap_with_fcs",
            "Radiotap (DLT 127), Flags FCS bit set + 4-byte trailer",
            LinkType::Radiotap,
            LinkWrap::RadiotapWithFcs,
        ),
        ("ll_prism", "Prism monitor header (DLT 119)", LinkType::Prism, LinkWrap::Prism),
        ("ll_avs", "AVS / WLAN-NG header (DLT 163, BE-correct)", LinkType::Avs, LinkWrap::Avs),
        ("ll_ppi", "Per-Packet Information header (DLT 192)", LinkType::Ppi, LinkWrap::Ppi),
        (
            "ll_prism_wrapping_avs",
            "Prism outer + AVS inner (BE magic 0x80211xxx triggers AVS path)",
            LinkType::Prism,
            LinkWrap::PrismWrappingAvs,
        ),
    ];

    let mut out = Vec::with_capacity(variants.len());
    for (name, descr, dlt, wrap) in variants {
        let packets = wrap_with(&frames, *wrap);
        out.push(Fixture {
            path: PathBuf::from(format!("link_layers/{name}.pcap")),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: *dlt,
            description: (*descr).to_owned(),
            packets,
            expected_hashes: wpa2_baseline_prefixes(),
            forbidden_hashes: Vec::new(),
        });
    }
    Ok(out)
}

/// One fixture per container variant: 10 pcap magics + pcapng (LE / BE) +
/// gzipped pcap + gzipped pcapng. All 14 variants share the same AP/STA pair
/// (`IDX_CONTAINERS`) -- the cross-variant invariant test depends on
/// payload-identical output, and the container is the only thing changing.
fn containers_section() -> Result<Vec<Fixture>> {
    let ap = ap_mac(IDX_CONTAINERS);
    let sta = sta_mac(IDX_CONTAINERS);
    let inputs = baseline_inputs(b"wpawolf-cont", ap, sta);
    let h = Handshake::all(&inputs)?;
    let frames: Vec<Vec<u8>> = vec![beacon(ap, &inputs.ssid, &rsn_ie(2, None)), h.m1, h.m2];
    let packets = wrap_with(&frames, LinkWrap::RadiotapNoFcs);

    let pcap_variants: &[(&str, &str, PcapMagic)] = &[
        ("c_pcap_le_us", "Classic pcap, LE micro magic 0xA1B2C3D4 (libpcap default)", PcapMagic::LeMicro),
        ("c_pcap_be_us", "Classic pcap, BE micro magic", PcapMagic::BeMicro),
        ("c_pcap_le_ns", "Classic pcap, LE nano magic 0xA1B23C4D", PcapMagic::LeNano),
        ("c_pcap_be_ns", "Classic pcap, BE nano magic", PcapMagic::BeNano),
        ("c_pcap_kuz_le", "Kuznetzov-format pcap LE (0xA1B2CD34)", PcapMagic::KuzLe),
        ("c_pcap_kuz_be", "Kuznetzov-format pcap BE", PcapMagic::KuzBe),
        ("c_pcap_ixia_hw_le", "IXIA hardware-accelerated LE (0x1A2B3C4D)", PcapMagic::IxiaHwLe),
        ("c_pcap_ixia_hw_be", "IXIA hardware-accelerated BE", PcapMagic::IxiaHwBe),
        ("c_pcap_ixia_sw_le", "IXIA software LE (0x1A2B3C4E)", PcapMagic::IxiaSwLe),
        ("c_pcap_ixia_sw_be", "IXIA software BE", PcapMagic::IxiaSwBe),
    ];

    let mut out = Vec::with_capacity(pcap_variants.len() + 4);
    for (name, descr, magic) in pcap_variants {
        out.push(Fixture {
            path: PathBuf::from(format!("containers/{name}.pcap")),
            container: Container::Pcap(*magic),
            link_type: LinkType::Radiotap,
            description: (*descr).to_owned(),
            packets: packets.clone(),
            expected_hashes: wpa2_baseline_prefixes(),
            forbidden_hashes: Vec::new(),
        });
    }
    out.push(Fixture {
        path: PathBuf::from("containers/c_pcapng_le.pcapng"),
        container: Container::PcapNg,
        link_type: LinkType::Radiotap,
        description: "pcapng with LE section (BOM 0x1A2B3C4D)".to_owned(),
        packets: packets.clone(),
        expected_hashes: wpa2_baseline_prefixes(),
        forbidden_hashes: Vec::new(),
    });
    out.push(Fixture {
        path: PathBuf::from("containers/c_pcapng_be.pcapng"),
        container: Container::PcapNgBe,
        link_type: LinkType::Radiotap,
        description: "pcapng with BE section (BOM written big-endian)".to_owned(),
        packets: packets.clone(),
        expected_hashes: wpa2_baseline_prefixes(),
        forbidden_hashes: Vec::new(),
    });
    out.push(Fixture {
        path: PathBuf::from("containers/c_pcap_gz.pcap.gz"),
        container: Container::PcapGz(PcapMagic::LeMicro),
        link_type: LinkType::Radiotap,
        description: "Gzipped classic pcap".to_owned(),
        packets: packets.clone(),
        expected_hashes: wpa2_baseline_prefixes(),
        forbidden_hashes: Vec::new(),
    });
    out.push(Fixture {
        path: PathBuf::from("containers/c_pcapng_gz.pcapng.gz"),
        container: Container::PcapNgGz,
        link_type: LinkType::Radiotap,
        description: "Gzipped pcapng".to_owned(),
        packets,
        expected_hashes: wpa2_baseline_prefixes(),
        forbidden_hashes: Vec::new(),
    });
    Ok(out)
}

/// Edge cases: NULL / `0xFF` sentinels, link-layer / container variants. Each
/// edge fixture gets its own AP/STA pair (`IDX_EDGE_BASE + i`) so an invalid
/// frame in one fixture cannot pollute pairing on another fixture's MAC pair.
/// `multi_file_a` and `multi_file_b` deliberately share `IDX_EDGE_MULTI_FILE`
/// so wpawolf can pair their handshakes across files (FR-PAIR-CROSS-FILE).
fn edge_section() -> Result<Vec<Fixture>> {
    let mut out = Vec::new();
    let mut idx = IDX_EDGE_BASE;
    let mut next_idx = || -> u8 {
        let n = idx;
        idx = idx.wrapping_add(1);
        n
    };

    // Helper: build one edge fixture against fresh (ap, sta, ssid). The
    // baseline-handshake-driven fixtures (FCS strip, pcapng/raw, gzipped,
    // m4_zero_snonce, multi_file_*) all reuse the same Inputs shape; we
    // synthesise a Handshake per fixture so each has independent crypto.
    let baseline = |ap: [u8; 6], sta: [u8; 6], ssid: &[u8]| -> Result<(Handshake, Vec<u8>)> {
        let inputs = baseline_inputs(ssid, ap, sta);
        let h = Handshake::all(&inputs)?;
        let bcn = beacon(ap, ssid, &rsn_ie(2, None));
        Ok((h, bcn))
    };

    // FCS strip variant (radiotap with Flags byte bit 4).
    {
        let n = next_idx();
        let (ap, sta) = (ap_mac(n), sta_mac(n));
        let (h, bcn) = baseline(ap, sta, b"wpawolf-edge-fcs")?;
        out.push(Fixture {
            path: PathBuf::from("edge/radiotap_fcs.pcap"),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: "Radiotap with trailing FCS bit set (must be stripped)".to_owned(),
            packets: wrap_with(&[bcn, h.m1, h.m2], LinkWrap::RadiotapWithFcs),
            expected_hashes: wpa2_baseline_prefixes(),
            forbidden_hashes: Vec::new(),
        });
    }

    // pcapng + raw 802.11.
    {
        let n = next_idx();
        let (ap, sta) = (ap_mac(n), sta_mac(n));
        let (h, bcn) = baseline(ap, sta, b"wpawolf-edge-raw")?;
        out.push(Fixture {
            path: PathBuf::from("edge/pcapng_raw.pcapng"),
            container: Container::PcapNg,
            link_type: LinkType::Raw,
            description: "pcapng container with DLT 105 raw 802.11".to_owned(),
            packets: wrap_with(&[bcn, h.m1, h.m2], LinkWrap::Raw),
            expected_hashes: wpa2_baseline_prefixes(),
            forbidden_hashes: Vec::new(),
        });
    }

    // Gzipped classic pcap.
    {
        let n = next_idx();
        let (ap, sta) = (ap_mac(n), sta_mac(n));
        let (h, bcn) = baseline(ap, sta, b"wpawolf-edge-gz")?;
        out.push(Fixture {
            path: PathBuf::from("edge/gzipped.pcap.gz"),
            container: Container::PcapGz(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: "Gzipped classic pcap (pcap.gz round-trip)".to_owned(),
            packets: wrap_with_radiotap(&[bcn, h.m1, h.m2]),
            expected_hashes: wpa2_baseline_prefixes(),
            forbidden_hashes: Vec::new(),
        });
    }

    // --- Sentinel rejection paths (FR-EAPOL-NULL / FR-PMKID-NULL) ---
    {
        let n = next_idx();
        let (ap, sta) = (ap_mac(n), sta_mac(n));
        let bcn = beacon(ap, b"wpawolf-edge-null-nonce", &rsn_ie(2, None));
        out.push(Fixture {
            path: PathBuf::from("edge/null_nonce_m1.pcap"),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: "M1 with all-zero ANonce -- wpawolf must reject".to_owned(),
            packets: wrap_with_radiotap(&[bcn, build_m1_with_nonce(ap, sta, [0u8; 32])]),
            expected_hashes: Vec::new(),
            forbidden_hashes: vec!["WPA*".to_owned()],
        });
    }
    {
        let n = next_idx();
        let (ap, sta) = (ap_mac(n), sta_mac(n));
        let bcn = beacon(ap, b"wpawolf-edge-ff-nonce", &rsn_ie(2, None));
        out.push(Fixture {
            path: PathBuf::from("edge/ff_nonce_m1.pcap"),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: "M1 with all-0xFF ANonce -- wpawolf must reject".to_owned(),
            packets: wrap_with_radiotap(&[bcn, build_m1_with_nonce(ap, sta, [0xFFu8; 32])]),
            expected_hashes: Vec::new(),
            forbidden_hashes: vec!["WPA*".to_owned()],
        });
    }
    {
        let n = next_idx();
        let (ap, sta) = (ap_mac(n), sta_mac(n));
        let bcn = beacon(ap, b"wpawolf-edge-null-pmkid", &rsn_ie(2, None));
        out.push(Fixture {
            path: PathBuf::from("edge/null_pmkid_kde.pcap"),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: "M1 KDE with all-zero PMKID -- rejected (FR-PMKID-NULL)".to_owned(),
            packets: wrap_with_radiotap(&[bcn, build_m1_with_pmkid_kde(ap, sta, [0u8; 16])]),
            expected_hashes: Vec::new(),
            // The PMKID line must NOT emit; the rest of the M1 still contains
            // an ANonce so the message itself is not rejected -- only the
            // PMKID KDE is suppressed. Forbid the WPA*02* / WPA*04* prefixes
            // (PMKID lines) but allow the test to still see no EAPOL pair
            // (which would never form from a single M1 anyway).
            forbidden_hashes: vec!["WPA*02*".to_owned(), "WPA*04*".to_owned()],
        });
    }
    {
        let n = next_idx();
        let (ap, sta) = (ap_mac(n), sta_mac(n));
        let bcn = beacon(ap, b"wpawolf-edge-ff-pmkid", &rsn_ie(2, None));
        out.push(Fixture {
            path: PathBuf::from("edge/ff_pmkid_kde.pcap"),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: "M1 KDE with all-0xFF PMKID -- rejected".to_owned(),
            packets: wrap_with_radiotap(&[bcn, build_m1_with_pmkid_kde(ap, sta, [0xFFu8; 16])]),
            expected_hashes: Vec::new(),
            forbidden_hashes: vec!["WPA*02*".to_owned(), "WPA*04*".to_owned()],
        });
    }

    // --- M4 with zero SNonce (Table 12-10 NOTE 9) -- spec-valid, must NOT log ---
    {
        let n = next_idx();
        let (ap, sta) = (ap_mac(n), sta_mac(n));
        let (h, bcn) = baseline(ap, sta, b"wpawolf-edge-zsnonce")?;
        out.push(Fixture {
            path: PathBuf::from("edge/m4_zero_snonce.pcap"),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: "M4 with zero SNonce per [IEEE 802.11-2024] Table 12-10 NOTE 9".to_owned(),
            packets: wrap_with_radiotap(&[bcn, h.m1, h.m2, h.m3, build_m4_zero_snonce(ap, sta)]),
            expected_hashes: wpa2_baseline_prefixes(),
            forbidden_hashes: Vec::new(),
        });
    }

    // --- WDS 4-address relay: full M1-M4 ---
    // FR-RELAY-FIRST-CLASS in `ARCHITECTURE.md §8`: relay (`ToDS = FromDS = 1`)
    // frames must produce the same hash output as their 3-address equivalents.
    // Re-wrap each EAPOL body into a 4-address WDS data frame so the full
    // handshake pairs end-to-end and the fixture asserts a `WPA*02*` (PMKID)
    // and `WPA*03*` (EAPOL pair) in the manifest. AP -> STA frames carry
    // `RA=STA, TA=AP, DA=STA, SA=AP`; STA -> AP reverses it.
    {
        let n = next_idx();
        let (ap, sta) = (ap_mac(n), sta_mac(n));
        let (h, bcn) = baseline(ap, sta, b"wpawolf-edge-wds")?;
        let m1_eapol = strip_3addr_header(&h.m1);
        let m2_eapol = strip_3addr_header(&h.m2);
        let m3_eapol = strip_3addr_header(&h.m3);
        let m4_eapol = strip_3addr_header(&h.m4);
        let m1_wds = wds_data_frame(sta, ap, sta, ap, m1_eapol);
        let m2_wds = wds_data_frame(ap, sta, ap, sta, m2_eapol);
        let m3_wds = wds_data_frame(sta, ap, sta, ap, m3_eapol);
        let m4_wds = wds_data_frame(ap, sta, ap, sta, m4_eapol);
        out.push(Fixture {
            path: PathBuf::from("edge/wds_4addr.pcap"),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: "WDS 4-address EAPOL relay (ToDS=FromDS=1) -- full M1-M4".to_owned(),
            packets: wrap_with_radiotap(&[bcn, m1_wds, m2_wds, m3_wds, m4_wds]),
            expected_hashes: wpa2_baseline_prefixes(),
            forbidden_hashes: Vec::new(),
        });
    }

    // --- A-MSDU full handshake (each EAPOL body lives in subframe 2) ---
    // Promotes the older single-frame fixture to a full M1-M4 sequence so the
    // A-MSDU subframe-iteration path (`src/ieee80211/amsdu.rs`) is exercised
    // for every message in the four-way handshake, not just M1.
    {
        let n = next_idx();
        let (ap, sta) = (ap_mac(n), sta_mac(n));
        let (h, bcn) = baseline(ap, sta, b"wpawolf-edge-amsdu")?;
        let m1_amsdu = amsdu_data_frame(ap, sta, Direction::Downlink, strip_3addr_header(&h.m1));
        let m2_amsdu = amsdu_data_frame(ap, sta, Direction::Uplink, strip_3addr_header(&h.m2));
        let m3_amsdu = amsdu_data_frame(ap, sta, Direction::Downlink, strip_3addr_header(&h.m3));
        let m4_amsdu = amsdu_data_frame(ap, sta, Direction::Uplink, strip_3addr_header(&h.m4));
        out.push(Fixture {
            path: PathBuf::from("edge/amsdu_eapol_subframe2.pcap"),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: "A-MSDU subframe-2 EAPOL -- full M1-M4 handshake".to_owned(),
            packets: wrap_with_radiotap(&[bcn, m1_amsdu, m2_amsdu, m3_amsdu, m4_amsdu]),
            expected_hashes: wpa2_baseline_prefixes(),
            forbidden_hashes: Vec::new(),
        });
    }

    // --- MSDU fragmented EAPOL: full M1-M4 ---
    // `src/store/fragments.rs` reassembles MSDU fragments before EAPOL
    // parsing. Splitting every message of the handshake across two fragments
    // proves end-to-end pairing survives reassembly. Sequence numbers are
    // bumped per message so wpawolf does not collide buffers.
    {
        let n = next_idx();
        let (ap, sta) = (ap_mac(n), sta_mac(n));
        let (h, bcn) = baseline(ap, sta, b"wpawolf-edge-frag")?;
        let mut frag_pkts = vec![bcn];
        let frags: [(&Vec<u8>, Direction); 4] = [
            (&h.m1, Direction::Downlink),
            (&h.m2, Direction::Uplink),
            (&h.m3, Direction::Downlink),
            (&h.m4, Direction::Uplink),
        ];
        for (i, (msg, dir)) in frags.into_iter().enumerate() {
            let seq = 0x100 + u16::try_from(i).unwrap_or(0);
            frag_pkts.extend(fragmented_data_frames(ap, sta, dir, seq, strip_3addr_header(msg)));
        }
        out.push(Fixture {
            path: PathBuf::from("edge/eapol_fragmented.pcap"),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: "EAPOL fragmented across two MSDU fragments per msg -- full M1-M4".to_owned(),
            packets: wrap_with_radiotap(&frag_pkts),
            expected_hashes: wpa2_baseline_prefixes(),
            forbidden_hashes: Vec::new(),
        });
    }

    // --- Oversized EAPOL > 255 B in M1, full M1-M4 chain ---
    // FR-EAPOL-NO-SIZE-GATE: wpawolf must accept EAPOL bodies that exceed
    // upstream's `EAPOL_AUTHLEN_OLD_MAX` (255 B). Append 320 B of padding
    // bytes after the legitimate PMKID KDE so the M1 body is > 255 B; the
    // remaining M2/M3/M4 are unmodified. wpawolf must still pair the
    // handshake and emit both PMKID + EAPOL hashes.
    {
        let n = next_idx();
        let (ap, sta) = (ap_mac(n), sta_mac(n));
        let (h, bcn) = baseline(ap, sta, b"wpawolf-edge-oversize")?;
        // Replace M1 with a key-data-padded variant. The PMKID KDE comes
        // first so its TLV iteration still finds it; the trailing padding is
        // wrapped as a vendor KDE (`tag 0xDD`, opaque bytes) so the parser
        // skips over it cleanly.
        let pmkid_kde = h.pmkid.as_ref().map(|p| crate::frame::kde::pmkid(p)).unwrap_or_default();
        let mut padded_kd = pmkid_kde;
        let padding = vec![0xCDu8; 320];
        padded_kd.push(0xDD); // Vendor KDE tag.
        padded_kd.push(u8::try_from(padding.len() + 4).unwrap_or(u8::MAX));
        padded_kd.extend_from_slice(&[0x00, 0x0F, 0xAC, 0xFF]); // OUI + arbitrary type byte.
        padded_kd.extend_from_slice(&padding);
        let oversized_m1_body = build_eapol(&KeySpec {
            msg: EapolMsg::M1,
            kdv: 2,
            mic_len: 16,
            replay_counter: 1,
            nonce: ANONCE,
            mic: vec![0u8; 16],
            key_data: padded_kd,
            wpa1: false,
        });
        let oversized_m1 = data_frame(ap, sta, Direction::Downlink, &oversized_m1_body);
        out.push(Fixture {
            path: PathBuf::from("edge/oversized_eapol.pcap"),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: "EAPOL > 255 B Key Data on M1 -- full M1-M4 still pairs".to_owned(),
            packets: wrap_with_radiotap(&[bcn, oversized_m1, h.m2, h.m3, h.m4]),
            expected_hashes: wpa2_baseline_prefixes(),
            forbidden_hashes: Vec::new(),
        });
    }

    // --- Multi-file pairing (M1 in file A; M2/M3/M4 in file B) ---
    {
        let (ap, sta) = (ap_mac(IDX_EDGE_MULTI_FILE), sta_mac(IDX_EDGE_MULTI_FILE));
        let (h, bcn) = baseline(ap, sta, b"wpawolf-edge-multi")?;
        out.push(Fixture {
            path: PathBuf::from("edge/multi_file_a.pcap"),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: "Multi-file pairing -- file A: Beacon + M1".to_owned(),
            packets: wrap_with_radiotap(&[bcn, h.m1]),
            // File A on its own: only the M1 PMKID extraction fires; the
            // M2..M4 pair is in file B and only resolves when both files
            // are processed in one wpawolf invocation.
            expected_hashes: vec!["WPA*02*".to_owned()],
            // File A in isolation has no M2/M3/M4 -- no EAPOL pair line
            // (`WPA*03*`) should ever emit. The cross-file test asserts
            // this prefix appears only when file B is also present.
            forbidden_hashes: vec!["WPA*03*".to_owned()],
        });
        out.push(Fixture {
            path: PathBuf::from("edge/multi_file_b.pcap"),
            container: Container::Pcap(PcapMagic::LeMicro),
            link_type: LinkType::Radiotap,
            description: "Multi-file pairing -- file B: M2 + M3 + M4".to_owned(),
            packets: wrap_with_radiotap(&[h.m2, h.m3, h.m4]),
            // File B on its own carries no Beacon / Probe Response, so the AP's
            // SSID is unknown. wpawolf drops every uncrackable hash with no
            // resolved ESSID and reports them via `[essid_not_found_summary]`
            // in --log instead -- file B in isolation must therefore emit no
            // `WPA*` lines at all. The cross-file test asserts that `WPA*03*`
            // reappears once file A's Beacon supplies the SSID.
            expected_hashes: Vec::new(),
            forbidden_hashes: vec!["WPA*02*".to_owned(), "WPA*03*".to_owned()],
        });
    }

    Ok(out)
}

// --- Edge-fixture helpers ---

/// Strip the 24-byte 3-address 802.11 MAC header from a wire-encoded data
/// frame, returning just the payload bytes (LLC/SNAP + EAPOL body).
///
/// Used by the WDS / A-MSDU / fragment / oversized edge fixtures, which
/// re-wrap the EAPOL bodies produced by `Handshake::all` into their own
/// transport-specific MAC headers. The Handshake builder always emits
/// 3-address frames (24-byte header per `[IEEE 802.11-2024]` §9.3.2.1).
fn strip_3addr_header(frame: &[u8]) -> &[u8] {
    frame.get(24..).unwrap_or(&[])
}

/// Build the bare LLC/SNAP+EAPOL bytes for the given message + nonce, with
/// no MIC computed (suitable for sentinel-rejection fixtures).
fn eapol_body_only(msg: EapolMsg, nonce: [u8; 32], key_data: &[u8]) -> Vec<u8> {
    build_eapol(&KeySpec {
        msg,
        kdv: 2,
        mic_len: 16,
        replay_counter: 1,
        nonce,
        mic: vec![0u8; 16],
        key_data: key_data.to_vec(),
        wpa1: false,
    })
}

fn build_m1_with_nonce(ap: [u8; 6], sta: [u8; 6], nonce: [u8; 32]) -> Vec<u8> {
    let body = eapol_body_only(EapolMsg::M1, nonce, &[]);
    data_frame(ap, sta, Direction::Downlink, &body)
}

fn build_m1_with_pmkid_kde(ap: [u8; 6], sta: [u8; 6], pmkid: [u8; 16]) -> Vec<u8> {
    let kd = crate::frame::kde::pmkid(&pmkid);
    let body = eapol_body_only(EapolMsg::M1, ANONCE, &kd);
    data_frame(ap, sta, Direction::Downlink, &body)
}

fn build_m4_zero_snonce(ap: [u8; 6], sta: [u8; 6]) -> Vec<u8> {
    let body = eapol_body_only(EapolMsg::M4, [0u8; 32], &[]);
    data_frame(ap, sta, Direction::Uplink, &body)
}

// --- Builders for individual S-site fixtures ---

fn build_s3_assoc_req(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<u8> {
    let ssid = b"wpawolf-s03";
    assoc_request(ap, sta, ssid, &rsn_ie(2, Some(pmkid)), &[])
}

fn build_s4_reassoc_req(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<u8> {
    let ssid = b"wpawolf-s04";
    crate::frame::assoc::reassoc_request(ap, sta, ap, ssid, &rsn_ie(2, Some(pmkid)), &[])
}

/// Build the FT subelements (MDE + FTE with `R0KH-ID` + `R1KH-ID`) used by
/// every FT-Auth / FT-Action S-site fixture. `wpawolf` requires both the
/// `MDE` and the `FTE` (with non-zero `R0KH-ID-len`) to attach FT context to
/// the stored PMKID; without that context, the FR-OUT-3 emit gate
/// (`src/output/mod.rs:362`) drops the PMKID entry.
fn ft_pmkid_subelements() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&mde(0x1234, 0));
    let r0kh: &[u8] = b"r0kh";
    let r1kh: [u8; 6] = [0x06, 0x06, 0x06, 0x06, 0x06, 0x06];
    let mic: [u8; 16] = [0u8; 16];
    out.extend_from_slice(&fte(&FteInputs {
        mic_control: [0, 0],
        mic: &mic,
        a_nonce: ANONCE,
        s_nonce: SNONCE,
        r0kh_id: r0kh,
        r1kh_id: r1kh,
    }));
    out
}

/// FT Action body fixed header: `STA Address(6) || Target AP Address(6)`
/// per `[IEEE 802.11-2024]` §9.6.7.3 / §9.6.7.5. wpawolf's
/// `extract::action::process_action` reads the STA + Target AP from the first
/// 12 bytes, then parses IEs starting at `body[14..]` (Request / Confirm) or
/// `body[16..]` for Response (extra 2-byte status code). Without the fixed
/// header the IE iterator starts at the wrong offset and finds no PMKID.
fn ft_action_fixed_header(sta: [u8; 6], target_ap: [u8; 6]) -> Vec<u8> {
    let mut hdr = Vec::with_capacity(12);
    hdr.extend_from_slice(&sta);
    hdr.extend_from_slice(&target_ap);
    hdr
}

fn build_s5_ft_auth_1(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<Vec<u8>> {
    // FT context (MDE + FTE) is mandatory: without R0KH-ID the emit gate
    // drops the PMKID. Beacon prepended for AKM context.
    let bcn = beacon_for_akm(ap, b"wpawolf-s05", 4);
    let mut ies = Vec::new();
    ies.extend_from_slice(&rsn_ie(4, Some(pmkid)));
    ies.extend_from_slice(&ft_pmkid_subelements());
    vec![bcn, auth(ap, sta, ap, ALGO_FT, 1, &ies)]
}

fn build_s6_ft_auth_2(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<Vec<u8>> {
    let bcn = beacon_for_akm(ap, b"wpawolf-s06", 4);
    let mut ies = Vec::new();
    ies.extend_from_slice(&rsn_ie(4, Some(pmkid)));
    ies.extend_from_slice(&ft_pmkid_subelements());
    vec![bcn, auth(sta, ap, ap, ALGO_FT, 2, &ies)]
}

fn build_s11_ft_action(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<Vec<u8>> {
    let bcn = beacon_for_akm(ap, b"wpawolf-s11", 4);
    let mut body = ft_action_fixed_header(sta, ap);
    body.extend_from_slice(&rsn_ie(4, Some(pmkid)));
    body.extend_from_slice(&ft_pmkid_subelements());
    vec![bcn, action(ap, sta, ap, CATEGORY_FT, FT_ACTION_REQUEST, &body)]
}

fn build_s16_beacon(ap: [u8; 6], pmkid: &[u8; 16]) -> Vec<u8> {
    let ssid = b"wpawolf-s16";
    beacon(ap, ssid, &rsn_ie(2, Some(pmkid)))
}

fn build_s17_probe_resp(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<u8> {
    let ssid = b"wpawolf-s17";
    probe_response(ap, sta, ssid, &rsn_ie(2, Some(pmkid)))
}

fn build_s20_osen(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<Vec<u8>> {
    // OSEN PMKIDs are stored with akm=Unknown; the WPA2-PSK beacon for the
    // same BSSID promotes them to `Wpa2Psk` at emission time so the
    // `WPA*02*` line passes the FR-OUT-3 emit gate and is hashcat-crackable.
    let bcn = beacon_for_akm(ap, b"wpawolf-s20", 2);
    let ssid = b"wpawolf-s20";
    let mut ies = Vec::new();
    ies.extend_from_slice(&ssid_ie(ssid));
    ies.extend_from_slice(&osen_ie(Some(pmkid)));
    vec![bcn, assoc_request(ap, sta, ssid, &rsn_ie(2, None), &ies)]
}

// --- New PMKID-source builders (S1 / S2 / S7-S15 / S18 / S19) ---

fn beacon_for_akm(ap: [u8; 6], ssid: &[u8], akm_byte: u8) -> Vec<u8> {
    beacon(ap, ssid, &rsn_ie(akm_byte, None))
}

/// S1 -- PMKID inside the M1 EAPOL Key Data KDE. Beacon precedes M1 so the
/// AKM context is associated with the AP.
fn build_s1_m1_kde(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<Vec<u8>> {
    let ssid = b"wpawolf-s01";
    let bcn = beacon_for_akm(ap, ssid, 2);
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
    let m1_eapol = build_eapol(&spec);
    let m1 = data_frame(ap, sta, Direction::Downlink, &m1_eapol);
    vec![bcn, m1]
}

/// S2 -- PMKID inside an RSN IE living in M2's Key Data field. The MIC is
/// stuffed with a non-zero placeholder because wpawolf's FR-EAPOL-NULL-MIC
/// invariant rejects M2 frames whose Key MIC bit is set with an all-zero
/// MIC value (`stats::check_mic_invalid`); for an isolated S2 fixture we
/// don't have a paired M1's KCK to compute a real MIC, but a non-zero
/// placeholder is sufficient to bypass the rejection and let the PMKID
/// extractor see the M2's Key Data RSN IE.
fn build_s2_m2_rsn_ie(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<Vec<u8>> {
    let ssid = b"wpawolf-s02";
    let bcn = beacon_for_akm(ap, ssid, 2);
    let kd = rsn_ie(2, Some(pmkid));
    let spec = KeySpec {
        msg: EapolMsg::M2,
        kdv: 2,
        mic_len: 16,
        replay_counter: 1,
        nonce: SNONCE,
        mic: vec![0xCDu8; 16],
        key_data: kd,
        wpa1: false,
    };
    let m2_eapol = build_eapol(&spec);
    let m2 = data_frame(ap, sta, Direction::Uplink, &m2_eapol);
    vec![bcn, m2]
}

/// S7 -- FILS Authentication seq=1 STA->AP. AKM 14 / 15 / 16 / 17 are FILS
/// per `[IEEE 802.11-2024]` table 9-190; we use AKM 14 (FILS-SHA-256). FILS
/// PMKIDs are not PSK-crackable -- wpawolf parses them and increments the
/// per-source counter, but `HashType::from_akm_and_attack` returns `None`
/// for AKM 14 so no hashcat line ships. This fixture exercises the parser
/// path; assert non-emission via `expected_hashes = []`.
fn build_s7_fils_auth_1(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<Vec<u8>> {
    let bcn = beacon_for_akm(ap, b"wpawolf-s07", 14);
    let ies = rsn_ie(14, Some(pmkid));
    vec![bcn, auth(ap, sta, ap, ALGO_FILS_SK, 1, &ies)]
}

/// S8 -- FILS Authentication seq=2 AP->STA.
fn build_s8_fils_auth_2(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<Vec<u8>> {
    let bcn = beacon_for_akm(ap, b"wpawolf-s08", 14);
    let ies = rsn_ie(14, Some(pmkid));
    vec![bcn, auth(sta, ap, ap, ALGO_FILS_PK, 2, &ies)]
}

/// S9 -- PASN Authentication seq=1 STA->AP. PASN can wrap any base AKMP
/// per `[IEEE 802.11-2024]` §12.13.1; we use AKM 2 (WPA2-PSK) so the
/// extracted PMKID is `HMAC-SHA1(PMK, "PMK Name" || AA || SPA)` and lands
/// crackably in the legacy mode-22000 sink. AKM 4 (FT-PSK) would require
/// FTE subelements with non-zero R0KH-ID for the emit gate, which adds
/// noise unrelated to the PASN dispatch this fixture proves out.
fn build_s9_pasn_auth_1(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<Vec<u8>> {
    let bcn = beacon_for_akm(ap, b"wpawolf-s09", 2);
    let ies = rsn_ie(2, Some(pmkid));
    vec![bcn, auth(ap, sta, ap, ALGO_PASN, 1, &ies)]
}

/// S10 -- PASN Authentication seq=2 AP->STA.
fn build_s10_pasn_auth_2(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<Vec<u8>> {
    let bcn = beacon_for_akm(ap, b"wpawolf-s10", 2);
    let ies = rsn_ie(2, Some(pmkid));
    vec![bcn, auth(sta, ap, ap, ALGO_PASN, 2, &ies)]
}

/// S12 -- FT Action Response (cat=6, action=2).
fn build_s12_ft_action_response(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<Vec<u8>> {
    let bcn = beacon_for_akm(ap, b"wpawolf-s12", 4);
    let mut body = ft_action_fixed_header(sta, ap);
    // FT Response carries a 2-byte Status Code after the 12-byte fixed header
    // (`[IEEE 802.11-2024]` §9.6.7.4); wpawolf's parser reads IEs from
    // `body[16..]`. Pad with `0x0000` (success).
    body.extend_from_slice(&[0x00, 0x00]);
    body.extend_from_slice(&rsn_ie(4, Some(pmkid)));
    body.extend_from_slice(&ft_pmkid_subelements());
    vec![bcn, action(sta, ap, ap, CATEGORY_FT, FT_ACTION_RESPONSE, &body)]
}

/// S13 -- FT Action Confirm (cat=6, action=3).
fn build_s13_ft_action_confirm(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<Vec<u8>> {
    let bcn = beacon_for_akm(ap, b"wpawolf-s13", 4);
    let mut body = ft_action_fixed_header(sta, ap);
    body.extend_from_slice(&rsn_ie(4, Some(pmkid)));
    body.extend_from_slice(&ft_pmkid_subelements());
    vec![bcn, action(ap, sta, ap, CATEGORY_FT, FT_ACTION_CONFIRM, &body)]
}

/// S14 -- Probe Request directed at the AP, carrying RSN IE with PMKID.
/// Beacon must precede so `akm_map` records AKM 2 for the AP; without it
/// the Probe Request PMKID is stored with `AkmType::Unknown` and the emit
/// gate drops it (`src/types.rs::HashType::from_akm_and_attack`).
fn build_s14_probe_req_directed(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<Vec<u8>> {
    let bcn = beacon_for_akm(ap, b"wpawolf-s14", 2);
    let rsn = rsn_ie(2, Some(pmkid));
    vec![bcn, probe_request(ap, sta, b"wpawolf-s14", Some(&rsn))]
}

/// S15 -- Probe Request broadcast, carrying RSN IE with PMKID. RA is the
/// broadcast address (`FF:FF:FF:FF:FF:FF`) per `[IEEE 802.11-2024]` §11.1.4.
/// Like S14, requires a preceding beacon for AKM resolution.
fn build_s15_probe_req_broadcast(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<Vec<u8>> {
    let bcn = beacon_for_akm(ap, b"wpawolf-s15", 2);
    let rsn = rsn_ie(2, Some(pmkid));
    vec![bcn, probe_request_broadcast_to_ap(ap, sta, b"wpawolf-s15", Some(&rsn))]
}

/// S18 -- Mesh Peering Open (cat=15, action=1) with PMKID embedded in the
/// AMPE element (`tag 139`). Mesh PMKIDs use SAE; not PSK-crackable, so the
/// fixture asserts non-emission. Parser path coverage only.
fn build_s18_mesh_peering_open(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<Vec<u8>> {
    let bcn = beacon_for_akm(ap, b"wpawolf-s18", 8);
    let body = ampe_with_pmkid(pmkid);
    vec![bcn, action(sta, ap, ap, CATEGORY_MESH, MESH_PEERING_OPEN, &body)]
}

/// S19 -- Mesh Peering Confirm (cat=15, action=2).
fn build_s19_mesh_peering_confirm(ap: [u8; 6], sta: [u8; 6], pmkid: &[u8; 16]) -> Vec<Vec<u8>> {
    let bcn = beacon_for_akm(ap, b"wpawolf-s19", 8);
    let body = ampe_with_pmkid(pmkid);
    vec![bcn, action(ap, sta, ap, CATEGORY_MESH, MESH_PEERING_CONFIRM, &body)]
}

fn ft_extras() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&mde(0x1234, 0));
    let r0kh: &[u8] = b"r0kh";
    let r1kh: [u8; 6] = [0x06; 6];
    let mic = [0u8; 16];
    out.extend_from_slice(&fte(&FteInputs {
        mic_control: [0, 0],
        mic: &mic,
        a_nonce: ANONCE,
        s_nonce: SNONCE,
        r0kh_id: r0kh,
        r1kh_id: r1kh,
    }));
    out
}

/// Link-layer wrapping mode used by the catalog.
///
/// Decoupled from [`LinkType`] (the DLT) because two distinct wrappers
/// (`RadiotapNoFcs`, `RadiotapWithFcs`) share DLT 127 but produce different
/// byte sequences, and `PrismWrappingAvs` produces a Prism-DLT byte stream
/// that internally carries an AVS sub-header.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum LinkWrap {
    Raw,
    RadiotapNoFcs,
    RadiotapWithFcs,
    Prism,
    Avs,
    Ppi,
    PrismWrappingAvs,
}

/// Wrap a sequence of 802.11 frames in radiotap headers and convert them to
/// timestamped [`Packet`] records. Convenience for the default link layer.
fn wrap_with_radiotap(frames: &[Vec<u8>]) -> Vec<Packet> {
    wrap_with(frames, LinkWrap::RadiotapNoFcs)
}

/// Wrap each frame using the given [`LinkWrap`] and produce sequenced
/// [`Packet`] records 1us apart.
fn wrap_with(frames: &[Vec<u8>], wrap: LinkWrap) -> Vec<Packet> {
    frames
        .iter()
        .enumerate()
        .map(|(i, frame)| {
            let data = match wrap {
                LinkWrap::Raw => frame.clone(),
                LinkWrap::RadiotapNoFcs => radiotap(frame, false),
                LinkWrap::RadiotapWithFcs => radiotap(frame, true),
                LinkWrap::Prism => prism(frame),
                LinkWrap::Avs => avs(frame),
                LinkWrap::Ppi => ppi(frame),
                LinkWrap::PrismWrappingAvs => prism_wrapping_avs(frame),
            };
            Packet { ts_sec: TS_BASE_SEC, ts_subsec: u32::try_from(i).unwrap_or(0), data }
        })
        .collect()
}

/// Build a baseline `Inputs` for the link-layer / container sections -- the
/// simplest WPA2-PSK handshake against the supplied SSID, on the supplied
/// (AP, STA) MAC pair.
fn baseline_inputs(ssid: &[u8], ap: [u8; 6], sta: [u8; 6]) -> Inputs {
    Inputs {
        psk: PSK.to_vec(),
        ssid: ssid.to_vec(),
        ap,
        sta,
        kdf_family: HashFamily::Sha1,
        mic_family: HashFamily::Sha1,
        akm_byte: 2,
        a_nonce: ANONCE,
        s_nonce: SNONCE,
        replay_counter: 1,
        kdv: 2,
        wpa1: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Counts {
        types: usize,
        pmkid_canonical: usize,
        pmkid_akm_variants: usize,
        combo: usize,
        link: usize,
        container: usize,
        edge: usize,
    }

    #[test]
    fn catalog_emits_expected_sections() {
        let fixtures = all().expect("catalog::all");
        assert!(fixtures.len() >= 11 + 20 + 6 + 7 + 13, "fixture count too small: {}", fixtures.len());
        let counts = fixtures.iter().fold(Counts::default(), |mut acc, f| {
            let p = f.path.to_string_lossy();
            if p.starts_with("11_types/") {
                acc.types += 1;
            } else if p.starts_with("20_pmkid_sites/") {
                // The canonical S1-S20 fixtures land here; the per-AKM variant
                // fixtures (`pmkid_akm_variants_section`) reuse the same
                // directory but their stems carry the AKM suffix `_psk_sha256`
                // (or `_psk_sha384` / `_ft_psk_sha384` if those are added
                // later). Count them separately so a regression in one set
                // does not silently mask the other.
                if p.contains("_psk_sha256") || p.contains("_psk_sha384") || p.contains("_ft_psk_sha384") {
                    acc.pmkid_akm_variants += 1;
                } else {
                    acc.pmkid_canonical += 1;
                }
            } else if p.starts_with("6_combos/") {
                acc.combo += 1;
            } else if p.starts_with("link_layers/") {
                acc.link += 1;
            } else if p.starts_with("containers/") {
                acc.container += 1;
            } else if p.starts_with("edge/") {
                acc.edge += 1;
            }
            acc
        });
        assert_eq!(counts.types, 11, "11 hash-type fixtures");
        assert_eq!(counts.pmkid_canonical, 20, "20 PMKID-site fixtures (S1-S20)");
        // AKM-variant fixtures cover the S-sites that the type fixtures do
        // not implicitly exercise (S4 / S14 / S17 currently). Adding more is
        // additive; this assertion is a lower bound to catch accidental
        // removals.
        assert!(
            counts.pmkid_akm_variants >= 3,
            "at least 3 PMKID AKM-variant fixtures, got {}",
            counts.pmkid_akm_variants
        );
        assert_eq!(counts.combo, 6, "6 N#E# combo fixtures");
        assert_eq!(counts.link, 7, "7 link-layer fixtures");
        // 10 pcap magics + pcapng LE + pcapng BE + 2 gzipped variants.
        assert_eq!(counts.container, 14, "14 container fixtures");
        assert!(counts.edge > 0, "at least one edge fixture");
    }

    #[test]
    fn every_fixture_has_at_least_one_packet() {
        let fixtures = all().expect("catalog::all");
        for f in &fixtures {
            assert!(!f.packets.is_empty(), "fixture {} has no packets", f.path.display());
        }
    }
}
