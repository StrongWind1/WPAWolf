//! Phase 2 -- Decode: EAP frame parser (identity / inner-method username extraction). See ARCHITECTURE.md §3.2 + §8.3.
//!
//! Parses EAPOL frames with Packet Type 0 (EAP-Packet) per RFC 3748 §4. The EAP header
//! is 4 bytes: Code (1), Identifier (1), Length (2 BE). For Code 1 (Request) and Code 2
//! (Response), a Type byte follows. Extracts identity strings from both
//! EAP-Request/Identity (Code=1, Type=1 -- the prompt string the authenticator MAY
//! display to the user, e.g. `networkid=X,nasid=Y,portid=Z`) and EAP-Response/Identity
//! (Code=2, Type=1 -- the peer's claim of identity) frames per RFC 3748 §5.1.
//! Only Responses yield a `username` (the prompt is not a username). Used to populate
//! the `-I` (identity) and `-U` (username) output lists.

// --- LLC/SNAP EtherType bytes ---

/// High byte of EAPOL `EtherType` `0x888E`. [IEEE 802.11-2012 Annex P, Table P-2]
const ETHERTYPE_EAPOL_HIGH: u8 = 0x88;
/// Low byte of EAPOL `EtherType` `0x888E`. [IEEE 802.11-2012 Annex P, Table P-2]
const ETHERTYPE_EAPOL_LOW: u8 = 0x8E;

// --- EAPOL Packet Type constants ---

/// EAPOL Packet Type 0: EAP-Packet. [IEEE 802.11-2024] §12.6.3
const PACKET_TYPE_EAP: u8 = 0;

// --- EAP Code constants [RFC 3748 §4] ---

/// EAP Code 1: Request. [RFC 3748 §4]
const EAP_CODE_REQUEST: u8 = 1;
/// EAP Code 2: Response. [RFC 3748 §4]
const EAP_CODE_RESPONSE: u8 = 2;
/// EAP Code 3: Success. [RFC 3748 §4.2]
const EAP_CODE_SUCCESS: u8 = 3;
/// EAP Code 4: Failure. [RFC 3748 §4.2]
const EAP_CODE_FAILURE: u8 = 4;

// --- EAP Type constants [RFC 3748 §5] ---

/// EAP Type 1: Identity. [RFC 3748 §5.1]
const EAP_TYPE_IDENTITY: u8 = 1;

// --- Output types ---

/// Data extracted from an EAP frame.
///
/// EAP-Request (Code=1) and EAP-Response (Code=2) carry identity; EAP-Success (Code=3)
/// and EAP-Failure (Code=4) carry no Type field but their occurrence is counted via the
/// `outcome` field. [RFC 3748 §4]
#[derive(Debug, Default, Clone)]
pub struct EapInfo {
    /// EAP identity string, present for EAP-Identity frames (Type=1) on either Request
    /// (Code=1) or Response (Code=2). Raw bytes -- may contain any characters. On a
    /// Request this is the authenticator's prompt string; on a Response it is the peer's
    /// claimed identity. [RFC 3748 §5.1]
    pub identity: Option<Vec<u8>>,
    /// EAP username: populated only for EAP-Response/Identity (Code=2, Type=1) frames
    /// where the identity is non-empty. The authenticator-side Request prompt is not a
    /// username and does NOT populate this field.
    pub username: Option<Vec<u8>>,
    /// EAP outcome (Success or Failure) for Code 3 / 4 frames. `None` for
    /// Request/Response frames. Used by `extract::data` to drive the
    /// `stats.eap_success_frames` / `stats.eap_failure_frames` counters.
    pub outcome: Option<EapOutcome>,
}

/// Terminal EAP exchange outcome. [RFC 3748 §4.2]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EapOutcome {
    /// EAP-Success (Code 3) -- the authenticator accepted the peer's credentials.
    Success,
    /// EAP-Failure (Code 4) -- the authenticator rejected the peer or the exchange
    /// hit an unrecoverable error.
    Failure,
}

// --- Parser ---

/// Parses an EAP frame from the body of an IEEE 802.11 Data frame.
///
/// `data` is the frame body starting at the LLC/SNAP header (same as `eapol::parse`).
/// Returns `None` if the `EtherType` is not `0x888E`, if the EAPOL Packet Type is not
/// 0 (EAP-Packet), if the EAP Code is not 1 or 2 (only Request/Response carry identity),
/// or if the frame is too short. [RFC 3748 §4], [IEEE 802.11-2024] §12.6.3.
#[must_use]
pub fn parse(data: &[u8]) -> Option<EapInfo> {
    // LLC/SNAP header: DSAP(1) SSAP(1) Ctrl(1) OUI(3) EtherType(2) = 8 bytes.
    // Bytes 6-7 hold the EtherType. [IEEE 802.11-2012 Annex P, Table P-2]
    if data.get(6) != Some(&ETHERTYPE_EAPOL_HIGH) || data.get(7) != Some(&ETHERTYPE_EAPOL_LOW) {
        return None;
    }

    // EAPOL frame begins at offset 8:
    //   Protocol Version (1) + Packet Type (1) + Body Length (2) = 4 bytes header,
    //   then Body (Body Length bytes). [IEEE 802.11-2024] §12.6.3
    let eapol = data.get(8..)?;

    // Packet Type at EAPOL offset 1 must be 0 (EAP-Packet).
    if eapol.get(1) != Some(&PACKET_TYPE_EAP) {
        return None;
    }

    // EAP packet starts at EAPOL offset 4 (after the 4-byte EAPOL header).
    let eap = eapol.get(4..)?;

    // EAP Code at offset 0. [RFC 3748 §4]
    let code = *eap.first()?;

    // EAP-Success (3) and EAP-Failure (4) carry no Type byte or Data; surface the
    // outcome for stats counting and return early.
    if code == EAP_CODE_SUCCESS {
        return Some(EapInfo { outcome: Some(EapOutcome::Success), ..EapInfo::default() });
    }
    if code == EAP_CODE_FAILURE {
        return Some(EapInfo { outcome: Some(EapOutcome::Failure), ..EapInfo::default() });
    }
    if code != EAP_CODE_REQUEST && code != EAP_CODE_RESPONSE {
        return None;
    }

    // EAP Length (u16 BE) at EAP offset 2 -- total EAP packet length including header.
    // [RFC 3748 §4]: Length includes Code, Identifier, Length, and Data fields.
    let eap_len_bytes: [u8; 2] = eap.get(2..4).and_then(|s| s.try_into().ok())?;
    let eap_len = u16::from_be_bytes(eap_len_bytes) as usize; // BE per [RFC 3748 §4]

    // EAP Type byte at offset 4. [RFC 3748 §4]: Type is present for Code 1 and 2.
    let eap_type = *eap.get(4)?;

    let mut info = EapInfo::default();

    if eap_type == EAP_TYPE_IDENTITY {
        // Identity data: offsets 5..eap_len within the EAP packet. [RFC 3748 §5.1]
        // eap_len may exceed the actual slice length if the frame is truncated -- clamp.
        let id_end = eap_len.min(eap.len());
        // Raw Type-Data bytes preserved verbatim, including any Hotspot 2.0 /
        // NAI-Realm leading 0x00 prefix (IEEE 802.11u §8.5.11, RFC 4284). The
        // parser is faithful; the wordlist-style output writers in
        // `src/output/wordlists.rs` apply the project-wide leading/trailing
        // NUL-padding trim per `ARCHITECTURE.md §9` before emitting.
        // unwrap_or(&[]) uses unwrap_or, not unwrap -- no lint fires.
        let identity = eap.get(5..id_end).unwrap_or(&[]).to_vec();
        // Username only comes from Response/Identity (the peer's claim). The Request
        // carries the authenticator's prompt string, which is useful as an identity
        // (wordlist / -I output) but is NOT the peer's username.
        let username = if code == EAP_CODE_RESPONSE && !identity.is_empty() { Some(identity.clone()) } else { None };
        info.identity = Some(identity);
        info.username = username;
    }
    // All other EAP types carry no extractable identity.

    Some(info)
}

// --- Unit tests ---

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation, reason = "test fixtures use small literals that fit target types")]

    use super::*;

    /// Builds a complete LLC/SNAP + EAPOL + EAP frame for testing.
    fn make_eap_frame(eap_code: u8, eap_type: u8, identity: &[u8]) -> Vec<u8> {
        let mut v = vec![
            0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E, // LLC/SNAP
            0x02, 0x00, 0x00, 0x00, // EAPOL: version=2, type=0 (EAP), body_len placeholder
            // EAP packet:
            eap_code, // Code
            0x01,     // Identifier
        ];
        // EAP Length = Code(1) + Identifier(1) + Length(2) + Type(1) + Data(n) = 5 + n
        let eap_len = (5u16 + identity.len() as u16).to_be_bytes();
        v.extend_from_slice(&eap_len);
        v.push(eap_type);
        v.extend_from_slice(identity);
        v
    }

    #[test]
    fn parse_identity_response() {
        let frame = make_eap_frame(2, 1, b"user@realm");
        let info = parse(&frame).unwrap();
        assert_eq!(info.identity.as_deref(), Some(b"user@realm".as_ref()));
        assert_eq!(info.username.as_deref(), Some(b"user@realm".as_ref()));
    }

    #[test]
    fn parse_empty_identity() {
        // Code=2, Type=1, identity="" -> identity=Some([]), username=None
        let frame = make_eap_frame(2, 1, b"");
        let info = parse(&frame).unwrap();
        assert_eq!(info.identity.as_deref(), Some(b"".as_ref()));
        assert!(info.username.is_none());
    }

    #[test]
    fn parse_request_type1() {
        // Code=1 (Request) with Type=1 -- the authenticator's prompt string.
        // Populates `identity` (for -I / -W) but NOT `username` (for -U), since the
        // prompt is not a peer username. Mirrors hcxpcapngtool behaviour for
        // networkid=X,nasid=Y,portid=Z style prompts.
        let frame = make_eap_frame(1, 1, b"networkid=Foo,nasid=Bar,portid=1");
        let info = parse(&frame).unwrap();
        assert_eq!(info.identity.as_deref(), Some(b"networkid=Foo,nasid=Bar,portid=1".as_ref()));
        assert!(info.username.is_none());
    }

    #[test]
    fn parse_request_identity_empty() {
        // Code=1 Type=1 with zero-length data -> identity=Some([]), username=None.
        let frame = make_eap_frame(1, 1, b"");
        let info = parse(&frame).unwrap();
        assert_eq!(info.identity.as_deref(), Some(b"".as_ref()));
        assert!(info.username.is_none());
    }

    #[test]
    fn parse_wrong_ethertype() {
        let mut frame = make_eap_frame(2, 1, b"user");
        // Corrupt the EtherType high byte.
        frame[6] = 0x08;
        assert!(parse(&frame).is_none());
    }

    #[test]
    fn parse_wrong_packet_type() {
        let mut frame = make_eap_frame(2, 1, b"user");
        // EAPOL Packet Type is at frame[9] (LLC(8) + EAPOL offset 1).
        frame[9] = 3; // type 3 = EAPOL-Key, not EAP-Packet
        assert!(parse(&frame).is_none());
    }

    #[test]
    fn parse_success_code() {
        // EAP Code=3 (Success) -- no Type byte; parse() returns Some with outcome
        // set to Success and no identity/username so the caller can count it.
        let info = parse(&make_eap_frame(3, 0, b"")).unwrap();
        assert_eq!(info.outcome, Some(EapOutcome::Success));
        assert!(info.identity.is_none());
        assert!(info.username.is_none());
    }

    #[test]
    fn parse_failure_code() {
        // EAP Code=4 (Failure) -- mirrors parse_success_code with the Failure outcome.
        let info = parse(&make_eap_frame(4, 0, b"")).unwrap();
        assert_eq!(info.outcome, Some(EapOutcome::Failure));
        assert!(info.identity.is_none());
        assert!(info.username.is_none());
    }

    #[test]
    fn parse_request_outcome_none() {
        // Code=1 (Request) -- outcome must be None; only Success/Failure populate it.
        let info = parse(&make_eap_frame(1, 1, b"prompt")).unwrap();
        assert!(info.outcome.is_none());
    }

    #[test]
    fn parse_response_outcome_none() {
        // Code=2 (Response) -- outcome must be None; only Success/Failure populate it.
        let info = parse(&make_eap_frame(2, 1, b"alice")).unwrap();
        assert!(info.outcome.is_none());
    }

    #[test]
    fn parse_non_identity_type() {
        // Code=2 (Response), Type=4 (MD5-Challenge) -- valid EAP, no identity extracted.
        let frame = make_eap_frame(2, 4, b"\x10some-challenge");
        let info = parse(&frame).unwrap();
        assert!(info.identity.is_none());
        assert!(info.username.is_none());
    }

    #[test]
    fn parse_too_short_no_eap_code() {
        // Frame is only the LLC/SNAP header + partial EAPOL -- EAP code missing.
        let frame = [0xAAu8, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E, 0x02, 0x00, 0x00, 0x00];
        assert!(parse(&frame).is_none());
    }

    #[test]
    fn parse_identity_preserves_hotspot2_prefix() {
        // Hotspot 2.0 / NAI-Realm identity data begins with a single 0x00
        // type-prefix byte per RFC 4284 / IEEE 802.11u §8.5.11. The parser
        // stores the prefix byte verbatim; the wordlist-style output writers
        // trim the leading NUL before emitting per `ARCHITECTURE.md §9`.
        let mut payload = vec![0x00];
        payload.extend_from_slice(b"networkid=Foo,nasid=Bar,portid=1");
        let frame = make_eap_frame(1, 1, &payload);
        let info = parse(&frame).unwrap();
        let mut expected = vec![0x00];
        expected.extend_from_slice(b"networkid=Foo,nasid=Bar,portid=1");
        assert_eq!(info.identity.as_deref(), Some(expected.as_ref()));
        assert!(info.username.is_none(), "Request/Identity does not populate -U");
    }

    #[test]
    fn parse_identity_with_at_symbol() {
        // RFC 3748 §5.1: identity is typically "user@realm"; verify bytes pass through.
        let identity = b"alice@example.com";
        let frame = make_eap_frame(2, 1, identity);
        let info = parse(&frame).unwrap();
        assert_eq!(info.identity.as_deref(), Some(identity.as_ref()));
    }
}
