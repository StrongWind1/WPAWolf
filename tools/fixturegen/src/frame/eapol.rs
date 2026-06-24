//! EAPOL-Key M1-M4 frame builder.
//!
//! `[IEEE 802.11-2024]` §12.7.2 figure 12-32: EAPOL-Key body layout is
//!
//! ```text
//! Descriptor Type | Key Information | Key Length | Replay Counter | Key Nonce |
//! Key IV | Key RSC | Reserved       | Key MIC    | Key Data Length | Key Data
//!   1 B  |        2 B               |    2 B     |     8 B         |   32 B    |
//!  16 B  |   8 B  |   8 B           |  16 / 24 B |       2 B       |   var
//! ```
//!
//! The MIC width is 16 bytes for KDV in {1,2,3} and 24 bytes for the
//! SHA-384-192 family (KDV=0 with AKM 19 / 20, `[IEEE 802.11-2024]`
//! §12.7.3 table 12-11).
//!
//! Key Information bit layout (big-endian on the wire, §12.7.2):
//!
//! | Bits  | Meaning                                                      |
//! | ----- | ------------------------------------------------------------ |
//! | 0-2   | Key Descriptor Version (KDV). 0 = AKM-defined, 1 = HMAC-MD5, |
//! |       | 2 = HMAC-SHA1, 3 = AES-CMAC.                                 |
//! | 3     | Key Type. 1 = Pairwise, 0 = GTK.                             |
//! | 4-5   | Reserved.                                                    |
//! | 6     | Install.                                                     |
//! | 7     | Key Ack.                                                     |
//! | 8     | Key MIC.                                                     |
//! | 9     | Secure.                                                      |
//! | 10-15 | Error / Request / Encrypted Key Data / `SMK` Message / reserved.|

/// LLC / SNAP header for EAPOL frames: `AA AA 03 00 00 00 88 8E`
/// (`[IEEE 802.2]` SNAP, `EtherType` `0x888E` per IANA).
pub const LLC_SNAP_EAPOL: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E];

/// EAPOL Protocol Version (`[IEEE 802.1X-2020]` §11.3).
pub const EAPOL_VERSION: u8 = 0x02;
/// EAPOL Packet Type: EAPOL-Key.
pub const EAPOL_TYPE_KEY: u8 = 0x03;
/// Key Descriptor Type: RSN (`[IEEE 802.11-2024]` §12.7.2).
pub const KEY_DESCRIPTOR_RSN: u8 = 0x02;
/// Key Descriptor Type: WPA1 legacy (vendor-specific).
pub const KEY_DESCRIPTOR_WPA1: u8 = 0xFE;

/// Key Information bit: Install.
pub const KI_INSTALL: u16 = 1 << 6;
/// Key Information bit: Key Ack.
pub const KI_ACK: u16 = 1 << 7;
/// Key Information bit: Key MIC.
pub const KI_MIC: u16 = 1 << 8;
/// Key Information bit: Secure.
pub const KI_SECURE: u16 = 1 << 9;
/// Key Information bit: Key Type. 1 = Pairwise (every message of the 4-way
/// handshake), 0 = Group (a separate GTK-rekey exchange, never one of M1-M4).
/// [IEEE 802.11-2024] §12.7.2, figure 12-33.
pub const KI_PAIRWISE: u16 = 1 << 3;
/// Key Information bit: Encrypted Key Data.
pub const KI_ENCRYPTED: u16 = 1 << 12;

/// EAPOL message type the fixture generator is producing.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Message {
    /// AP -> STA, `ANonce`, no MIC.
    M1,
    /// STA -> AP, `SNonce`, MIC, optional RSN IE in Key Data (S2 PMKID).
    M2,
    /// AP -> STA, `ANonce`, MIC, Install, Secure.
    M3,
    /// STA -> AP, MIC, Secure, Key Data Length = 0.
    M4,
}

/// Compose the Key Information field for a given message type.
#[must_use]
pub const fn key_info(msg: Message, kdv: u8) -> u16 {
    // Every message of the 4-way handshake is a Pairwise key exchange (bit 3 = 1).
    // Emitting Key Type = Group was the defect that made the fixtures
    // wire-unrealistic. [IEEE 802.11-2024] §12.7.2.
    let mut ki = ((kdv as u16) & 0x07) | KI_PAIRWISE;
    match msg {
        Message::M1 => ki |= KI_ACK,
        Message::M2 => ki |= KI_MIC,
        Message::M3 => {
            ki |= KI_ACK | KI_INSTALL | KI_MIC | KI_SECURE;
            // M3 carries the GTK in an encrypted Key Data field on RSN (WPA2+);
            // WPA1 (KDV=1) predates the Encrypted Key Data bit, so leave it clear.
            // [IEEE 802.11-2024] §12.7.6.4.
            if kdv != 1 {
                ki |= KI_ENCRYPTED;
            }
        },
        Message::M4 => ki |= KI_MIC | KI_SECURE,
    }
    ki
}

/// Spec for an EAPOL-Key frame to be built.
///
/// Bundling the parameters into a struct sidesteps the
/// `clippy::too_many_arguments` lint (limit = 12 in `clippy.toml`) and keeps
/// call sites self-documenting.
#[derive(Debug, Clone)]
pub struct KeySpec {
    /// Which of M1 / M2 / M3 / M4.
    pub msg: Message,
    /// Key Descriptor Version (0, 1, 2, or 3 per `[IEEE 802.11-2024]` §12.7.2).
    pub kdv: u8,
    /// MIC field width: 16 for KDV 1/2/3, 24 for SHA-384-192 (KDV=0 + AKM 19/20).
    pub mic_len: usize,
    /// Replay Counter (big-endian on the wire).
    pub replay_counter: u64,
    /// 32-byte `ANonce` (M1 / M3) or `SNonce` (M2 / M4).
    pub nonce: [u8; 32],
    /// Pre-computed MIC bytes. Caller zeroes the field first when computing.
    pub mic: Vec<u8>,
    /// Key Data payload (RSN IE for M2, KDEs for M1, FTE for FT M3, ...).
    pub key_data: Vec<u8>,
    /// Optional WPA1 descriptor flag -- swaps the descriptor byte to `0xFE`.
    pub wpa1: bool,
}

/// Build the LLC/SNAP + EAPOL-Key wire bytes from a [`KeySpec`].
///
/// `[IEEE 802.11-2024]` §12.7.2 figure 12-32: the EAPOL-Key body length
/// excludes the first 4 bytes of the EAPOL header (Version, Type, Length).
#[must_use]
pub fn build(spec: &KeySpec) -> Vec<u8> {
    let mut out = Vec::with_capacity(128 + spec.key_data.len());
    out.extend_from_slice(&LLC_SNAP_EAPOL);
    out.push(EAPOL_VERSION);
    out.push(EAPOL_TYPE_KEY);
    let body_len = 95 + (spec.mic_len - 16) + spec.key_data.len();
    out.extend_from_slice(&u16::try_from(body_len).unwrap_or(u16::MAX).to_be_bytes());
    out.push(if spec.wpa1 { KEY_DESCRIPTOR_WPA1 } else { KEY_DESCRIPTOR_RSN });
    out.extend_from_slice(&key_info(spec.msg, spec.kdv).to_be_bytes());
    out.extend_from_slice(&[0x00, 0x10]); // Key Length = 16 for CCMP PTK.
    out.extend_from_slice(&spec.replay_counter.to_be_bytes());
    out.extend_from_slice(&spec.nonce);
    out.extend_from_slice(&[0u8; 16]); // Key IV.
    out.extend_from_slice(&[0u8; 8]); // Key RSC.
    out.extend_from_slice(&[0u8; 8]); // Reserved.
    if spec.mic.len() == spec.mic_len {
        out.extend_from_slice(&spec.mic);
    } else {
        out.extend_from_slice(&vec![0u8; spec.mic_len]);
    }
    out.extend_from_slice(&u16::try_from(spec.key_data.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(&spec.key_data);
    out
}

/// Build the byte offsets of the MIC field in a built EAPOL-Key frame.
///
/// Used by the handshake orchestrator: the caller writes a MIC-zeroed frame,
/// computes the MIC over the EAPOL body, then patches it back in at this
/// offset.
#[must_use]
pub const fn mic_offset() -> usize {
    // LLC/SNAP (8) + EAPOL header (4) + Descriptor (1) + Key Info (2) +
    // Key Length (2) + Replay (8) + Nonce (32) + IV (16) + RSC (8) +
    // Reserved (8) = 89.
    8 + 4 + 1 + 2 + 2 + 8 + 32 + 16 + 8 + 8
}

/// Return the EAPOL body slice (the bytes the MIC is computed over).
///
/// `[IEEE 802.11-2024]` §12.7.2: the MIC covers the EAPOL header (Version,
/// Type, Length) through the end of Key Data, with the MIC field itself
/// zeroed during computation.
#[must_use]
pub fn body_for_mic(frame: &[u8]) -> &[u8] {
    let body_start = LLC_SNAP_EAPOL.len();
    frame.get(body_start..).unwrap_or(&[])
}

/// Build a wrapper data frame around an EAPOL body.
///
/// `direction` selects `ToDS` / `FromDS` bits and address ordering. The wrapper
/// uses a 24-byte 3-address header; A-MSDU and 4-address WDS variants live
/// in their own helpers.
#[must_use]
pub fn data_frame(ap: [u8; 6], sta: [u8; 6], direction: Direction, eapol_body: &[u8]) -> Vec<u8> {
    let (a1, a2, a3, to_ds, from_ds) = match direction {
        Direction::Uplink => (ap, sta, ap, true, false),
        Direction::Downlink => (sta, ap, ap, false, true),
    };
    let mut frame =
        crate::frame::mac::header_3addr(crate::frame::mac::TYPE_DATA, 0, to_ds, from_ds, a1, a2, a3).to_vec();
    frame.extend_from_slice(eapol_body);
    frame
}

/// Direction the EAPOL-Key data frame travels: STA->AP (uplink) or AP->STA.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Direction {
    /// STA -> AP. M2 / M4.
    Uplink,
    /// AP -> STA. M1 / M3.
    Downlink,
}

/// Wrap an EAPOL body in a 4-address WDS data frame (`ToDS = FromDS = 1`).
///
/// `[IEEE 802.11-2024]` §9.3.2.1: in WDS the four-address header carries
/// `RA = addr1`, `TA = addr2`, `DA = addr3`, `SA = addr4`. Used for the
/// `--all` / FR-RELAY-FIRST-CLASS invariant fixtures.
#[must_use]
pub fn wds_data_frame(ra: [u8; 6], ta: [u8; 6], da: [u8; 6], sa: [u8; 6], eapol_body: &[u8]) -> Vec<u8> {
    let mut frame = crate::frame::mac::header_4addr(crate::frame::mac::TYPE_DATA, 0, ra, ta, da, sa).to_vec();
    frame.extend_from_slice(eapol_body);
    frame
}

/// Wrap an EAPOL body in an A-MSDU data frame.
///
/// `[IEEE 802.11-2024]` §9.3.2.2.2: A-MSDU subframes are `DA(6) || SA(6) ||
/// Length(2 BE) || LLC/SNAP+payload(N) || pad(0-3 to 4-byte boundary)`.
/// The `QoS` Control field has bit 7 set to indicate A-MSDU. wpawolf walks
/// every subframe (`src/ieee80211/amsdu.rs`). The EAPOL payload becomes
/// the second of two MSDU subframes.
///
/// `direction` selects the outer MAC header `ToDS` / `FromDS` bits and
/// address ordering, which is what wpawolf's Tier 1 EAPOL classifier reads
/// to decide M1 vs M2 vs M3 vs M4. Using the wrong direction misclassifies
/// every message of the handshake.
#[must_use]
pub fn amsdu_data_frame(ap: [u8; 6], sta: [u8; 6], direction: Direction, eapol_body: &[u8]) -> Vec<u8> {
    // Build a 26-byte `QoS` data MAC header: 24 standard + 2 `QoS` Control.
    // `QoS` Control byte 0 bit 7 (0x80) signals A-MSDU. Subtype = 8 (`QoS`
    // Data) per `[IEEE 802.11-2024]` Table 9-1. Direction picks the address
    // ordering identically to `data_frame`.
    let (a1, a2, a3, to_ds, from_ds) = match direction {
        Direction::Uplink => (ap, sta, ap, true, false),
        Direction::Downlink => (sta, ap, ap, false, true),
    };
    let mut hdr = crate::frame::mac::header_3addr(crate::frame::mac::TYPE_DATA, 8, to_ds, from_ds, a1, a2, a3).to_vec();
    hdr.extend_from_slice(&[0x80, 0x00]); // QoS Control: A-MSDU bit set.

    // Subframe 1: filler payload addressed to outer DA / SA. Inner subframe
    // addresses are nominal -- wpawolf does not key on them.
    let filler = b"AMSDU-FILLER";
    let sf1 = build_amsdu_subframe(a1, a2, filler);
    // Subframe 2: the EAPOL payload. The EAPOL body already contains its
    // LLC/SNAP header so we strip it before wrapping into the subframe.
    let eapol_inner = eapol_body.get(LLC_SNAP_EAPOL.len()..).unwrap_or(&[]);
    let sf2 = build_amsdu_subframe(a1, a2, eapol_inner);

    let mut frame = hdr;
    frame.extend_from_slice(&sf1);
    frame.extend_from_slice(&sf2);
    frame
}

fn build_amsdu_subframe(da: [u8; 6], sa: [u8; 6], payload_after_llc: &[u8]) -> Vec<u8> {
    // Each subframe carries its own LLC/SNAP + EtherType (EAPOL = 0x888E)
    // followed by the inner payload. Per [IEEE 802.11-2024] §9.3.2.2.2,
    // padding aligns the *entire subframe* (14-byte header + payload) to a
    // 4-byte boundary. Confirmed by Wireshark (WS_ROUNDUP_4(14+msdu_length))
    // and Linux kernel (padding = (4 - (sizeof(ethhdr) + len)) & 0x3).
    let mut inner = Vec::with_capacity(LLC_SNAP_EAPOL.len() + payload_after_llc.len());
    inner.extend_from_slice(&LLC_SNAP_EAPOL);
    inner.extend_from_slice(payload_after_llc);
    let length = u16::try_from(inner.len()).unwrap_or(u16::MAX);
    let pad = (4 - ((14 + inner.len()) & 3)) & 3;
    let mut sub = Vec::with_capacity(14 + inner.len() + pad);
    sub.extend_from_slice(&da);
    sub.extend_from_slice(&sa);
    sub.extend_from_slice(&length.to_be_bytes());
    sub.extend_from_slice(&inner);
    sub.extend(std::iter::repeat_n(0u8, pad));
    sub
}

/// Wrap an EAPOL body in a sequence of MSDU fragments.
///
/// `[IEEE 802.11-2024]` §10.7: the More Fragments bit (`fc[1] & 0x04`) is
/// set on every fragment except the last; Sequence Control byte 0 carries
/// the fragment number (low nibble) and the upper bits of the sequence
/// number. wpawolf reassembles fragments before EAPOL parsing
/// (`src/store/fragments.rs`). `direction` selects the outer 802.11 MAC
/// header `ToDS` / `FromDS` bits and address ordering, which wpawolf's Tier 1
/// EAPOL classifier uses to decide M1/M2/M3/M4.
#[must_use]
pub fn fragmented_data_frames(
    ap: [u8; 6],
    sta: [u8; 6],
    direction: Direction,
    seq_num: u16,
    eapol_body: &[u8],
) -> Vec<Vec<u8>> {
    let mid = eapol_body.len() / 2;
    let (first_payload, second_payload) = eapol_body.split_at(mid);
    let (a1, a2, a3, to_ds, from_ds) = match direction {
        Direction::Uplink => (ap, sta, ap, true, false),
        Direction::Downlink => (sta, ap, ap, false, true),
    };

    let mut first =
        crate::frame::mac::header_3addr(crate::frame::mac::TYPE_DATA, 0, to_ds, from_ds, a1, a2, a3).to_vec();
    if let Some(b) = first.get_mut(1) {
        *b |= 0x04; // More Fragments.
    }
    write_seq_ctl(&mut first, seq_num, 0);
    first.extend_from_slice(first_payload);

    let mut second =
        crate::frame::mac::header_3addr(crate::frame::mac::TYPE_DATA, 0, to_ds, from_ds, a1, a2, a3).to_vec();
    write_seq_ctl(&mut second, seq_num, 1);
    second.extend_from_slice(second_payload);

    vec![first, second]
}

fn write_seq_ctl(mac_header: &mut [u8], seq_num: u16, frag_num: u8) {
    // Sequence Control occupies bytes 22-23 of the 24-byte MAC header.
    // Layout (LE): low nibble of byte 22 = fragment number, remaining 12
    // bits = sequence number.
    let raw = ((seq_num & 0x0FFF) << 4) | u16::from(frag_num & 0x0F);
    if let Some(slot) = mac_header.get_mut(22..24) {
        slot.copy_from_slice(&raw.to_le_bytes());
    }
}
