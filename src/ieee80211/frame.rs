//! Phase 2 -- Decode: 802.11 MAC header + address mapping. See ARCHITECTURE.md §3.2 + §8.3.
//!
//! Parses the Frame Control field (2 bytes, little-endian), extracts Type, Subtype,
//! ToDS/FromDS flags, and the Protected Frame bit. Derives AP and STA MAC addresses
//! from address fields 1-4 per the ToDS/FromDS combination table in IEEE 802.11-2024
//! §9.3.2.1.2, Table 9-60. Handles 3-address and 4-address (WDS relay) frames, and
//! `QoS` data frames (Subtype bit B7 = 1) which carry an extra 2-byte `QoS` Control field.
//! Relay frames (ToDS=1, FromDS=1) are always processed -- no `--all` gate.

use crate::types::MacAddr;

// --- Frame type constants ---

/// Management frame type (bits B2-B3 of FC = 0b00).
///
/// Per [IEEE 802.11-2024] §9.2.4.1.3, Table 9-2.
pub const TYPE_MANAGEMENT: u8 = 0;

/// Control frame type (bits B2-B3 of FC = 0b01).
///
/// Per [IEEE 802.11-2024] §9.2.4.1.3, Table 9-2.
pub const TYPE_CONTROL: u8 = 1;

/// Data frame type (bits B2-B3 of FC = 0b10).
///
/// Per [IEEE 802.11-2024] §9.2.4.1.3, Table 9-2.
pub const TYPE_DATA: u8 = 2;

/// Extension frame type (bits B2-B3 of FC = 0b11).
///
/// Reserved for 802.11 amendments (e.g., S1G, DMG); rare in mainstream captures.
/// Surfaced for stats accuracy so `TYPE_EXTENSION` frames are not miscounted as
/// control frames. Per [IEEE 802.11-2024] §9.2.4.1.3, Table 9-2.
pub const TYPE_EXTENSION: u8 = 3;

// --- Direction enum ---

/// Frame transmitter role derived from ToDS/FromDS flags.
///
/// For data frames, this determines who physically transmitted the frame on the radio,
/// which is critical for EAPOL M1/M2/M3/M4 classification: M1/M3 are always AP->STA,
/// M2/M4 are always STA->AP. [IEEE 802.11-2024] §9.3.2.1.2, Table 9-60.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameDirection {
    /// STA transmitted this frame to the AP (ToDS=1, FromDS=0) -- uplink data.
    FromSta,
    /// AP transmitted this frame to the STA (ToDS=0, FromDS=1) -- downlink data.
    FromAp,
    /// WDS relay frame (ToDS=1, FromDS=1) -- transmitter role is ambiguous.
    Wds,
    /// Management or IBSS frame (ToDS=0, FromDS=0).
    Ibss,
}

// --- Output type ---

/// Parsed IEEE 802.11 MAC header.
///
/// Produced by [`parse`]. Contains enough information to route a frame to the
/// correct EAPOL or management handler and to look up the (AP, STA) grouping key.
#[derive(Debug)]
pub struct MacHeader {
    /// AP MAC address (BSSID role), derived from ToDS/FromDS per Table 9-60.
    pub ap: MacAddr,
    /// STA MAC address (client role), derived from ToDS/FromDS per Table 9-60.
    pub sta: MacAddr,
    /// Frame type: 0=Management, 1=Control, 2=Data, 3=Extension.
    pub frame_type: u8,
    /// Frame subtype (4-bit value).
    pub subtype: u8,
    /// Whether the Protected Frame bit (B14) is set in Frame Control.
    pub protected: bool,
    /// Byte offset of the frame body within the original `data` slice.
    pub body_offset: usize,
    /// Frame direction derived from ToDS/FromDS. [IEEE 802.11-2024] §9.3.2.1.2.
    pub direction: FrameDirection,
    /// More Fragments flag (FC bit B10). Set on every fragment except the last.
    /// [IEEE 802.11-2024] §9.2.4.1.5.
    pub more_fragments: bool,
    /// Sequence Number (upper 12 bits of Sequence Control field at offset 22).
    /// All fragments of one MSDU share the same Sequence Number.
    /// [IEEE 802.11-2024] §9.2.4.4.
    pub sequence_number: u16,
    /// Fragment Number (low 4 bits of Sequence Control). 0 for the first
    /// fragment (or unfragmented MSDU); increments by 1 per subsequent fragment.
    /// [IEEE 802.11-2024] §9.2.4.4.
    pub fragment_number: u8,
    /// A-MSDU Present bit (B7 of the LE-low byte of `QoS` Control). When true,
    /// the frame body is a sequence of aggregated MSDU subframes rather than a
    /// single LLC/SNAP+payload. False when `QoS` Control is absent.
    /// [IEEE 802.11-2024] §9.2.4.5.9, §9.7.2.
    pub is_amsdu: bool,
    /// Mesh Control Present bit (B0 of the LE-high byte of `QoS` Control, i.e.
    /// bit 8 of the 16-bit `QoS` Control field) on a mesh BSS Data frame. When set,
    /// the frame body begins with a 6/12/18-byte Mesh Control header per
    /// [IEEE 802.11-2024] §9.2.4.8.3 that must be skipped before the LLC/SNAP.
    /// False when `QoS` Control is absent or the bit is clear.
    pub mesh_control_present: bool,
}

// --- Helper ---

/// Reads a 6-byte MAC address from `data` at `offset`.
///
/// Returns `None` if `data` is too short -- the caller skips the frame silently.
fn read_mac(data: &[u8], offset: usize) -> Option<MacAddr> {
    data.get(offset..offset + 6).and_then(|s| s.try_into().ok()).map(MacAddr::from_bytes)
}

// --- Parser ---

/// Outcome of [`parse`].
///
/// Splits the previous `Option<MacHeader>` into four states so the caller can
/// distinguish *intentionally skipped* frames (control frames are spec-valid --
/// `ACK`, `RTS`, `CTS`, `BlockACK` -- and deliberately ignored above this layer)
/// from *forgiven spec violations* (non-zero Protocol Version, but otherwise
/// well-formed -- tshark dissects these too) from *genuinely malformed* frames
/// (truncated headers).
///
/// Treating control frames as malformed produced ~38 M misleading `[malformed_frame]`
/// log lines on a 70 M-packet corpus. Treating non-zero Protocol Version frames as
/// hard malformed loses ~11.7 K frames per corpus that real-world dissectors accept;
/// they are now surfaced via [`ParseResult::Lenient`] with a stats counter for
/// operator visibility.
#[derive(Debug)]
pub enum ParseResult {
    /// Successfully parsed Management or Data frame, no spec violations.
    Frame(MacHeader),
    /// Parsed but the frame had a forgivable spec violation (currently:
    /// non-zero FC Protocol Version field, see [IEEE 802.11-2024] §9.2.4.1.1).
    /// The header is reliable -- only the version field was anomalous -- so the
    /// caller processes the frame normally and increments
    /// `stats.lenient_proto_version` for visibility.
    Lenient(MacHeader),
    /// Control frame (type=1). Spec-valid; skipped because it carries no EAPOL or IE
    /// content. Caller increments `stats.ctrl_frames` and moves on -- no log entry.
    Control,
    /// Genuinely malformed frame. The static reason string is what gets passed to
    /// `Logger::log_malformed_frame`; the caller appends the frame length.
    Malformed(&'static str),
}

/// Parses the IEEE 802.11 MAC header from `data` and classifies the frame.
///
/// See [`ParseResult`] for the four return states. Reasons recorded in the
/// `Malformed` variant cover every truly unrecoverable rejection path:
///
/// * `"truncated 802.11 MAC header"` -- shorter than the 24-byte 3-address minimum
///   (after FC type-classification, so spec-valid 10-byte ACK/CTS frames are
///   `Control`, not `Malformed`).
/// * `"truncated 4-address MAC header"` -- ToDS=FromDS=1 but `data.len() < 30`.
/// * `"truncated QoS data header"`   -- `QoS` data subtype but `data.len() < 26`.
/// * `"truncated Frame Control field"` -- `data.len() < 2`.
/// * `"truncated 802.11 address fields"` -- 24 B available but addr reads fail.
///
/// Non-zero Protocol Version is **not** rejected -- the same MAC layout has been
/// reused across every published 802.11 amendment through 2024, so a frame with
/// version=2 or 3 is parsed normally and surfaced as [`ParseResult::Lenient`].
/// This matches what tshark / wireshark do.
///
/// Order of checks matters: Frame Control is read first so that short control
/// frames (ACK = 10 B, CTS = 10 B without FCS) are classified by **type** before
/// the 24-byte minimum is enforced. Pre-fix this ordering produced ~33 M
/// `[malformed_frame]` log entries on a 70 M-packet corpus that were actually
/// spec-valid control frames.
#[must_use]
pub fn parse(data: &[u8]) -> ParseResult {
    // Frame Control is a 2-byte little-endian field. [IEEE 802.11-2024] §9.2.4.1.
    // Read it FIRST so type=Control short-circuits regardless of frame length --
    // ACK and CTS are only 10 bytes (FC + Duration + RA, no FCS).
    let Some(fc_slice) = data.get(0..2) else {
        return ParseResult::Malformed("truncated Frame Control field");
    };
    let Ok(fc_bytes) = <[u8; 2]>::try_from(fc_slice) else {
        return ParseResult::Malformed("truncated Frame Control field");
    };
    let fc = u16::from_le_bytes(fc_bytes);

    let proto = fc & 0x0003; // B0-B1: Protocol Version (reserved, see §9.2.4.1.1)
    let ftype = ((fc >> 2) & 0x0003) as u8; // B2-B3: Type
    let subtype = ((fc >> 4) & 0x000F) as u8; // B4-B7: Subtype
    let to_ds = (fc >> 8) & 1 != 0; // B8: To DS
    let from_ds = (fc >> 9) & 1 != 0; // B9: From DS
    let more_fragments = (fc >> 10) & 1 != 0; // B10: More Fragments [§9.2.4.1.5]
    let protected = (fc >> 14) & 1 != 0; // B14: Protected Frame

    // Control frames carry no EAPOL data or management IEs. Spec-valid skip.
    // Min size varies by subtype (ACK/CTS=10, RTS=16, BlockACK=variable); we don't
    // parse the body, so any length >= 2 (already verified above) is acceptable.
    // Done before the Protocol Version check so that short control frames with
    // garbage upper FC bits (rare but seen in radiotap-stripping edge cases) are
    // still classified correctly.
    if ftype == TYPE_CONTROL {
        return ParseResult::Control;
    }

    // Beyond this point we are committed to a Management / Data / Extension frame,
    // which always carries the full 3-address 24-byte header. [§9.3.2.1]
    if data.len() < 24 {
        return ParseResult::Malformed("truncated 802.11 MAC header");
    }

    // Addresses at fixed offsets per [IEEE 802.11-2024] §9.3.2.1, Figure 9-25.
    let (Some(addr1), Some(addr2), Some(addr3)) = (read_mac(data, 4), read_mac(data, 10), read_mac(data, 16)) else {
        return ParseResult::Malformed("truncated 802.11 address fields");
    };

    // 4-address frame: both ToDS and FromDS set. [IEEE 802.11-2024] §9.3.2.1.
    let four_addr = to_ds && from_ds;

    // Frame direction from ToDS/FromDS. [IEEE 802.11-2024] §9.3.2.1.2, Table 9-60.
    let direction = match (to_ds, from_ds) {
        (true, false) => FrameDirection::FromSta, // STA->AP uplink
        (false, true) => FrameDirection::FromAp,  // AP->STA downlink
        (true, true) => FrameDirection::Wds,      // WDS relay (ambiguous)
        (false, false) => FrameDirection::Ibss,   // Management / IBSS
    };

    // Derive AP and STA from ToDS/FromDS per [IEEE 802.11-2024] §9.3.2.1.2, Table 9-60.
    let (ap, sta) = match (to_ds, from_ds) {
        (false, false) => (addr3, addr2),       // IBSS / Mgmt: BSSID=Addr3, STA=Addr2
        (false | true, true) => (addr2, addr1), // DS->STA downlink / WDS relay: BSSID|TA=Addr2, STA|RA=Addr1
        (true, false) => (addr1, addr2),        // STA->DS uplink:   BSSID=Addr1, STA=Addr2
    };

    // Compute body offset.
    // Base is 24 bytes (3-address header). [IEEE 802.11-2024] §9.3.2.1.
    let mut body_offset: usize = 24;

    if four_addr {
        // Address 4 (bytes 24-29) present only in 4-address frames. [IEEE 802.11-2024] §9.3.2.1.
        if data.len() < 30 {
            return ParseResult::Malformed("truncated 4-address MAC header");
        }
        body_offset += 6;
    }

    // `QoS` Control field (2 bytes) is present when bit 3 of the subtype is set.
    // That bit is the MSB of the 4-bit subtype field, i.e. subtype & 0x08.
    // Applies to Data frames only. [IEEE 802.11-2024] §9.2.4.5.
    let qos_offset = body_offset; // first byte of `QoS` Control if present
    let mut is_amsdu = false;
    let mut mesh_control_present = false;
    if ftype == TYPE_DATA && (subtype & 0x08) != 0 {
        body_offset += 2;
        // A-MSDU Present bit (bit B7 of the LE-low byte of `QoS` Control) signals
        // that the frame body is a sequence of aggregated MSDU subframes rather
        // than a single LLC/SNAP+payload. [IEEE 802.11-2024] §9.2.4.5.9
        if let Some(&b) = data.get(qos_offset) {
            is_amsdu = (b & 0x80) != 0;
        }
        // Mesh Control Present bit (bit B0 of the LE-high byte of QoS Control,
        // i.e. bit 8 of the 16-bit field). Per [IEEE 802.11-2024] §9.2.4.5.7 this
        // subfield is defined for QoS Data frames "transmitted between mesh STAs"
        // only -- mesh BSS data frames use 4-address format. In 3-address
        // infrastructure frames the same bit position holds Queue Size LSB
        // (uplink, when bit B4 = 1), TXOP Duration Requested LSB (uplink, B4 = 0),
        // or AP-PS Buffer State / TXOP Limit LSB (downlink), per Tables 9-7 / 9-8.
        // Honoring B8 unconditionally caused 3-address EAPOL bodies whose Queue
        // Size happened to be odd to be misclassified as mesh frames and have a
        // phantom 6-byte mesh-control header stripped, mangling the EAPOL body.
        if four_addr {
            if let Some(&b_hi) = data.get(qos_offset + 1) {
                mesh_control_present = (b_hi & 0x01) != 0;
            }
        }
    }

    if data.len() < body_offset {
        return ParseResult::Malformed("truncated QoS data header");
    }

    // Sequence Control field at offset 22 (LE u16). Fragment Number = low 4 bits;
    // Sequence Number = upper 12 bits. [IEEE 802.11-2024] §9.2.4.4.
    let seq_ctrl_bytes: [u8; 2] = data.get(22..24).and_then(|s| s.try_into().ok()).unwrap_or([0u8; 2]);
    let seq_ctrl = u16::from_le_bytes(seq_ctrl_bytes);
    let fragment_number = (seq_ctrl & 0x000F) as u8;
    let sequence_number = (seq_ctrl >> 4) & 0x0FFF;

    let header = MacHeader {
        ap,
        sta,
        frame_type: ftype,
        subtype,
        protected,
        body_offset,
        direction,
        more_fragments,
        sequence_number,
        fragment_number,
        is_amsdu,
        mesh_control_present,
    };

    // Forgive non-zero Protocol Version: the field is reserved across every
    // 802.11 amendment through 2024 (§9.2.4.1.1), so the same MAC layout is in
    // force regardless of the version bits. tshark / wireshark parse these
    // frames; we do too, but flag them so the operator sees the count.
    if proto != 0 { ParseResult::Lenient(header) } else { ParseResult::Frame(header) }
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

    use super::*;

    // --- Test helpers ---

    /// Builds a 2-byte Frame Control value from its component fields.
    fn fc(ftype: u8, subtype: u8, to_ds: bool, from_ds: bool) -> [u8; 2] {
        let mut v: u16 = 0;
        v |= (u16::from(ftype)) << 2;
        v |= (u16::from(subtype)) << 4;
        if to_ds {
            v |= 1 << 8;
        }
        if from_ds {
            v |= 1 << 9;
        }
        v.to_le_bytes()
    }

    /// Returns a 6-byte MAC address filled with `b`.
    fn mac(b: u8) -> [u8; 6] {
        [b; 6]
    }

    /// Builds a minimal 24-byte 802.11 frame with the given FC and three addresses.
    fn build(fc_bytes: [u8; 2], addr1: [u8; 6], addr2: [u8; 6], addr3: [u8; 6]) -> Vec<u8> {
        let mut v = vec![0u8; 24];
        v[0..2].copy_from_slice(&fc_bytes);
        // Offset 2-3: Duration/ID (ignored)
        v[4..10].copy_from_slice(&addr1);
        v[10..16].copy_from_slice(&addr2);
        v[16..22].copy_from_slice(&addr3);
        // Offset 22-23: Sequence Control (ignored)
        v
    }

    // --- Tests ---

    /// Test helper: extract `MacHeader` from a `ParseResult::Frame`, panicking with a
    /// readable message for the other variants. Mirrors the old `.unwrap()` usage.
    fn unwrap_frame(r: ParseResult) -> MacHeader {
        match r {
            ParseResult::Frame(h) => h,
            ParseResult::Lenient(_) => panic!("expected Frame, got Lenient"),
            ParseResult::Control => panic!("expected Frame, got Control"),
            ParseResult::Malformed(reason) => panic!("expected Frame, got Malformed({reason})"),
        }
    }

    /// Test helper for the lenient-parse path.
    fn unwrap_lenient(r: ParseResult) -> MacHeader {
        match r {
            ParseResult::Lenient(h) => h,
            other => panic!("expected Lenient, got {other:?}"),
        }
    }

    #[test]
    fn mgmt_to_ds_0_from_ds_0() {
        // Management frame, ToDS=0, FromDS=0: AP=Addr3, STA=Addr2, body at 24.
        let frame = build(fc(TYPE_MANAGEMENT, 0, false, false), mac(0x01), mac(0x02), mac(0x03));
        let hdr = unwrap_frame(parse(&frame));
        assert_eq!(hdr.ap, MacAddr::from_bytes(mac(0x03)));
        assert_eq!(hdr.sta, MacAddr::from_bytes(mac(0x02)));
        assert_eq!(hdr.frame_type, TYPE_MANAGEMENT);
        assert_eq!(hdr.subtype, 0);
        assert!(!hdr.protected);
        assert_eq!(hdr.body_offset, 24);
        assert_eq!(hdr.direction, FrameDirection::Ibss);
    }

    #[test]
    fn data_to_ds_1_from_ds_0() {
        // Data frame, STA->AP uplink: AP=Addr1, STA=Addr2.
        let frame = build(fc(TYPE_DATA, 0, true, false), mac(0x01), mac(0x02), mac(0x03));
        let hdr = unwrap_frame(parse(&frame));
        assert_eq!(hdr.ap, MacAddr::from_bytes(mac(0x01)));
        assert_eq!(hdr.sta, MacAddr::from_bytes(mac(0x02)));
        assert_eq!(hdr.body_offset, 24);
        assert_eq!(hdr.direction, FrameDirection::FromSta);
    }

    #[test]
    fn data_to_ds_0_from_ds_1() {
        // Data frame, AP->STA downlink: AP=Addr2, STA=Addr1.
        let frame = build(fc(TYPE_DATA, 0, false, true), mac(0x01), mac(0x02), mac(0x03));
        let hdr = unwrap_frame(parse(&frame));
        assert_eq!(hdr.ap, MacAddr::from_bytes(mac(0x02)));
        assert_eq!(hdr.sta, MacAddr::from_bytes(mac(0x01)));
        assert_eq!(hdr.body_offset, 24);
        assert_eq!(hdr.direction, FrameDirection::FromAp);
    }

    #[test]
    fn data_wds_relay() {
        // 4-address WDS relay (ToDS=1, FromDS=1): AP=Addr2(TA), STA=Addr1(RA), body at 30.
        let mut frame = build(fc(TYPE_DATA, 0, true, true), mac(0x01), mac(0x02), mac(0x03));
        // Extend to 30+ bytes for Address 4.
        frame.extend_from_slice(&mac(0x04));
        frame.push(0x00);
        frame.push(0x00); // pad to 32 to satisfy body_offset check

        let hdr = unwrap_frame(parse(&frame));
        assert_eq!(hdr.ap, MacAddr::from_bytes(mac(0x02)));
        assert_eq!(hdr.sta, MacAddr::from_bytes(mac(0x01)));
        assert_eq!(hdr.body_offset, 30);
        assert_eq!(hdr.direction, FrameDirection::Wds);
    }

    #[test]
    fn data_qos() {
        // QoS Data: type=2, subtype=8 (subtype & 0x08 set), 3-address -> body at 26.
        // Frame must be at least 26 bytes (24 base + 2 `QoS` Control).
        let mut frame = build(fc(TYPE_DATA, 8, false, false), mac(0x01), mac(0x02), mac(0x03));
        frame.push(0x00);
        frame.push(0x00); // `QoS` Control placeholder
        let hdr = unwrap_frame(parse(&frame));
        assert_eq!(hdr.subtype, 8);
        assert_eq!(hdr.body_offset, 26);
    }

    #[test]
    fn data_qos_4addr() {
        // QoS Data, 4-address: body at 24 + 6 (Addr4) + 2 (QoS) = 32.
        let mut frame = build(fc(TYPE_DATA, 8, true, true), mac(0x01), mac(0x02), mac(0x03));
        // Extend to 32 bytes: 24 base + 6 Addr4 + 2 QoS.
        frame.resize(32, 0u8);

        let hdr = unwrap_frame(parse(&frame));
        assert_eq!(hdr.body_offset, 32);
    }

    #[test]
    fn qos_3addr_b8_set_is_not_mesh() {
        // Regression: a 3-address QoS Data uplink with QoS Control = 0x0b10 (Queue
        // Size = 11, bit B4 = 1) has bit B8 = 1 because B8-B15 carry Queue Size.
        // That is NOT Mesh Control Present -- mesh data frames are 4-address only.
        // Pre-fix: wpawolf stripped a phantom 6-byte mesh-control header from the
        // body, butchering the EAPOL inside and dropping the M2 / M4 of a real
        // WPA2 handshake (regression captured from a real-world sample where
        // 5x M2 + 5x M4 all had QoS Control = 0x0b10).
        let mut frame = build(fc(TYPE_DATA, 8, true, false), mac(0x01), mac(0x02), mac(0x03));
        frame.push(0x10); // QoS Control LE-low: TID=0, B4=1 (Queue-Size mode)
        frame.push(0x0b); // QoS Control LE-high: Queue Size = 11; B8 = 1
        let hdr = unwrap_frame(parse(&frame));
        assert!(!hdr.mesh_control_present, "3-address frame must never set mesh_control_present");
        assert_eq!(hdr.body_offset, 26);
    }

    #[test]
    fn qos_4addr_b8_set_is_mesh() {
        // 4-address QoS Data with bit B8 set: this is the only legitimate mesh
        // signal (mesh BSS data uses 4-address per [IEEE 802.11-2024] §9.3.2.1).
        let mut frame = build(fc(TYPE_DATA, 8, true, true), mac(0x01), mac(0x02), mac(0x03));
        frame.extend_from_slice(&mac(0x04)); // Address 4
        frame.push(0x00); // QoS Control LE-low
        frame.push(0x01); // QoS Control LE-high: B8 = 1
        let hdr = unwrap_frame(parse(&frame));
        assert!(hdr.mesh_control_present);
        assert_eq!(hdr.body_offset, 32);
    }

    #[test]
    fn control_frame_classified_as_control_not_malformed() {
        // Control frames (type=1) are spec-valid but uninteresting -- they must
        // surface as `ParseResult::Control`, NOT as `Malformed`. Conflating them
        // produced ~38 M misleading [malformed_frame] log entries in the regression
        // that motivated this enum split.
        let frame = build(fc(TYPE_CONTROL, 0, false, false), mac(0x01), mac(0x02), mac(0x03));
        assert!(matches!(parse(&frame), ParseResult::Control));
    }

    #[test]
    fn short_control_ack_frame_is_control_not_malformed() {
        // ACK (subtype 13) and CTS (subtype 12) are 10-byte frames per spec when the
        // capture lacks the FCS: FC(2) + Duration(2) + Receiver Address(6) = 10. The
        // parser must short-circuit on type=Control BEFORE enforcing the 24-byte
        // 3-address minimum -- otherwise these spec-valid frames flood the
        // `[malformed_frame]` log. Tested here for ACK; CTS works the same way.
        // FC[0] = 0xD4 -> type=Control(1), subtype=ACK(13), no flags.
        let ack_10b = vec![0xD4, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        assert_eq!(ack_10b.len(), 10);
        assert!(matches!(parse(&ack_10b), ParseResult::Control));

        // FC[0] = 0xC4 -> type=Control(1), subtype=CTS(12).
        let cts_10b = vec![0xC4, 0x00, 0x00, 0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        assert!(matches!(parse(&cts_10b), ParseResult::Control));
    }

    #[test]
    fn truncated_below_fc_is_malformed() {
        // 0 or 1 bytes is not enough to even read the FC field.
        assert!(matches!(parse(&[]), ParseResult::Malformed("truncated Frame Control field")));
        assert!(matches!(parse(&[0xD4]), ParseResult::Malformed("truncated Frame Control field")));
    }

    #[test]
    fn proto_version_nonzero_is_lenient_not_malformed() {
        // Bits B0-B1 of FC != 0 -> spec violation per §9.2.4.1.1, but every 802.11
        // amendment through 2024 reuses the same MAC layout, so we forgive the
        // version anomaly and surface the parsed header via `ParseResult::Lenient`.
        // This matches what tshark / wireshark do.
        //
        // Test frame uses TYPE_DATA, ToDS=1, FromDS=0 (STA->AP uplink); per Table
        // 9-60 that maps to AP=Addr1, STA=Addr2.
        let mut frame = build(fc(TYPE_DATA, 0, true, false), mac(0x01), mac(0x02), mac(0x03));
        frame[0] |= 0x01; // set B0 -> proto = 1
        let h = unwrap_lenient(parse(&frame));
        assert_eq!(h.frame_type, TYPE_DATA);
        assert_eq!(h.ap, MacAddr::from_bytes(mac(0x01)));
        assert_eq!(h.sta, MacAddr::from_bytes(mac(0x02)));

        // proto = 2
        let mut frame = build(fc(TYPE_DATA, 0, true, false), mac(0x01), mac(0x02), mac(0x03));
        frame[0] |= 0x02;
        assert!(matches!(parse(&frame), ParseResult::Lenient(_)));

        // proto = 3
        let mut frame = build(fc(TYPE_DATA, 0, true, false), mac(0x01), mac(0x02), mac(0x03));
        frame[0] |= 0x03;
        assert!(matches!(parse(&frame), ParseResult::Lenient(_)));
    }

    #[test]
    fn proto_version_nonzero_control_frame_still_classified_as_control() {
        // A control frame with bogus Protocol Version: type=Control wins because
        // we short-circuit on type before checking version. Empirically this is
        // the right call -- the corruption is in unrelated FC bits.
        let mut frame = build(fc(TYPE_CONTROL, 0, false, false), mac(0x01), mac(0x02), mac(0x03));
        frame[0] |= 0x02; // set proto = 2
        assert!(matches!(parse(&frame), ParseResult::Control));
    }

    #[test]
    fn too_short_is_malformed() {
        // A 10-byte buffer cannot contain a complete MAC header.
        let frame = vec![0u8; 10];
        assert!(matches!(parse(&frame), ParseResult::Malformed("truncated 802.11 MAC header")));
    }

    #[test]
    fn protected_bit_detected() {
        // B14 of FC is the Protected Frame bit.
        let mut frame = build(fc(TYPE_DATA, 0, false, false), mac(0x01), mac(0x02), mac(0x03));
        // B14 sits in byte 1 at bit 6 (byte 1 covers FC bits B8-B15, so B14 = bit 6 of byte 1).
        frame[1] |= 1 << 6;
        let hdr = unwrap_frame(parse(&frame));
        assert!(hdr.protected);
    }

    #[test]
    fn wds_relay_too_short_for_addr4_is_malformed() {
        // 4-address frame but buffer is exactly 24 bytes -- too short for Addr4 at 24-29.
        let frame = build(fc(TYPE_DATA, 0, true, true), mac(0x01), mac(0x02), mac(0x03));
        assert_eq!(frame.len(), 24);
        assert!(matches!(parse(&frame), ParseResult::Malformed("truncated 4-address MAC header")));
    }

    #[test]
    fn extension_frame_classified_as_frame() {
        // Type=3 (Extension) frames are rare but spec-defined. They must reach the
        // caller (so `stats.extension_frames` can count them) -- not be silently
        // dropped as `Control` or `Malformed`.
        let frame = build(fc(TYPE_EXTENSION, 0, false, false), mac(0x01), mac(0x02), mac(0x03));
        let hdr = unwrap_frame(parse(&frame));
        assert_eq!(hdr.frame_type, TYPE_EXTENSION);
    }
}
