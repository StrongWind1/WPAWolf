//! Phase 2 -- Decode: ANQP (Access Network Query Protocol) element parser. See ARCHITECTURE.md §3.2.
//!
//! ANQP carries operator and network-identity metadata inside GAS (Generic Advertisement
//! Service) Public Action frames. The wire payload lives in the Query Response field of
//! GAS Initial Response (Category 4, Action 11) per [IEEE 802.11-2024] §9.6.7.14-15
//! after the GAS fixed fields (Dialog Token + Status Code + GAS Comeback Delay +
//! Advertisement Protocol element + Query Response Length).
//!
//! The top-level format inside the Query Response is a stream of
//! `ANQP-element := InfoID (u16 LE) + Length (u16 LE) + Data` TLVs per
//! [IEEE 802.11-2024] §9.4.5.1, Figure 9-769. The per-element payload format is
//! defined separately in §9.4.5.N.
//!
//! Scope in this module:
//!
//! - Venue Name (`InfoID` 258) -- [IEEE 802.11-2024] §9.4.5.4
//! - Domain Name List (`InfoID` 263) -- [IEEE 802.11-2024] §9.4.5.19
//! - NAI Realm (`InfoID` 268) -- [IEEE 802.11-2024] §9.4.5.10
//! - Vendor-Specific (`InfoID` 56797) with Wi-Fi Alliance OUI `50:6F:9A` and
//!   Hotspot 2.0 ANQP subtype 3 (Operator Friendly Name) per
//!   Hotspot 2.0 Technical Specification v3.2 §4.3
//!
//! All four parsers yield printable text fragments that feed `WordlistStore` only.
//! They do not populate `-E` / `-R`: these strings are not SSIDs and do not pass
//! the `fwriteessidstr` admission filter (len<=32, first byte != 0) by construction.
//!
//! Out of scope for v1:
//! - GAS Comeback Response fragment reassembly (Actions 12/13).
//! - NAI Realm EAP Method tuples (we store only the Realm string, not the per-
//!   realm EAP method / parameter subelements).
//! - Domain name normalisation (case-folding, punycode, trailing-dot trimming).

// --- ANQP Info ID constants ---
// [IEEE 802.11-2024] §9.4.5.1, Table 9-331.

/// ANQP Info ID: Venue Name (§9.4.5.4).
pub const INFO_ID_VENUE_NAME: u16 = 258;
/// ANQP Info ID: Domain Name List (§9.4.5.19).
pub const INFO_ID_DOMAIN_NAME_LIST: u16 = 263;
/// ANQP Info ID: NAI Realm (§9.4.5.10).
pub const INFO_ID_NAI_REALM: u16 = 268;
/// ANQP Info ID: ANQP Vendor Specific (§9.4.5.8). Carrier for Hotspot 2.0 subtypes.
pub const INFO_ID_VENDOR_SPECIFIC: u16 = 56797;

// --- Hotspot 2.0 vendor-specific ANQP constants ---
// Per Wi-Fi Alliance Hotspot 2.0 Technical Specification v3.2 §4.2, §4.3.

/// Wi-Fi Alliance OUI used by Hotspot 2.0 ANQP vendor-specific elements.
///
/// Hotspot 2.0 ANQP elements use the Wi-Fi Alliance OUI and a 1-byte ANQP subtype
/// immediately after the OUI, with no 4th "type" byte (unlike most other WFA IEs).
pub const OUI_WFA_HS20: [u8; 3] = [0x50, 0x6F, 0x9A];

/// Hotspot 2.0 ANQP subtype: Operator Friendly Name.
/// [Hotspot 2.0 Tech Spec v3.2] §4.3
pub const HS20_SUBTYPE_OP_FRIENDLY_NAME: u8 = 3;

// --- Per-element spec constants ---

/// Venue Name / Operator Friendly Name Duple fixed prefix length:
/// `Language Code` (3 bytes, ISO 639-2). [IEEE 802.11-2024] §9.4.5.4
pub const LANGUAGE_CODE_LEN: usize = 3;

/// Venue Name element fixed prefix: `Venue Info` (2 bytes: Group + Type).
/// [IEEE 802.11-2024] §9.4.5.4, Figure 9-770
pub const VENUE_INFO_LEN: usize = 2;

// --- Parse result counters ---

/// Summary of what a single `parse_query_response` call produced. Callers feed the
/// text fragments into `WordlistStore` and bump the matching stats counters.
///
/// A single GAS Initial Response can carry any combination of the four element
/// types; the caller reports counts back to `Stats` rather than this module
/// touching global state directly.
#[derive(Debug, Default)]
pub struct AnqpCounts {
    /// Venue Name elements successfully parsed.
    pub venue_name: u64,
    /// Domain Name List elements successfully parsed.
    pub domain_name: u64,
    /// NAI Realm elements successfully parsed.
    pub nai_realm: u64,
    /// Hotspot 2.0 Operator Friendly Name elements parsed.
    pub hs_operator_friendly_name: u64,
    /// ANQP Info IDs we have no parser for (incremented once per TLV).
    pub unknown_info_id: u64,
}

/// Parsed text fragments extracted from one GAS Query Response.
///
/// All fragments are raw wire bytes; the caller's `WordlistStore::insert` handles
/// NUL-trim / control-byte splitting / autohex rendering at output time.
/// Heap-allocated `Vec<u8>` entries (not borrowed slices) so callers can drop the
/// source buffer immediately after parsing.
#[derive(Debug, Default)]
pub struct AnqpFragments {
    /// Text strings suitable for `WordlistStore::insert`. Duplicates are allowed
    /// at this layer; the store dedups.
    pub wordlist_entries: Vec<Vec<u8>>,
}

/// Parses a GAS Query Response byte stream into ANQP text fragments and element counts.
///
/// `data` is the Query Response payload *after* the GAS fixed fields
/// (Dialog Token + Status Code + GAS Comeback Delay + Advertisement Protocol element +
/// Query Response Length). The caller is responsible for locating this offset; see
/// `strip_gas_fixed_fields` for a best-effort helper.
///
/// Iteration is defensive: a truncated TLV stops the walk without panicking. Unknown
/// Info IDs bump `counts.unknown_info_id` and are skipped. Never returns `Err`;
/// always returns what was successfully parsed up to the first truncation.
#[must_use]
pub fn parse_query_response(data: &[u8]) -> (AnqpFragments, AnqpCounts) {
    let mut fragments = AnqpFragments::default();
    let mut counts = AnqpCounts::default();
    let mut pos = 0usize;

    // ANQP-element TLV stream: `InfoID` (u16 LE) + `Length` (u16 LE) + Data(Length).
    // [IEEE 802.11-2024] §9.4.5.1, Figure 9-769.
    while pos + 4 <= data.len() {
        let Some(info_lo) = data.get(pos) else { break };
        let Some(info_hi) = data.get(pos + 1) else { break };
        let Some(len_lo) = data.get(pos + 2) else { break };
        let Some(len_hi) = data.get(pos + 3) else { break };
        let info_id = u16::from_le_bytes([*info_lo, *info_hi]);
        let length = usize::from(u16::from_le_bytes([*len_lo, *len_hi]));
        let value_start = pos + 4;
        let value_end = value_start.saturating_add(length);
        if value_end > data.len() {
            // Truncated element -- stop cleanly.
            break;
        }
        let Some(value) = data.get(value_start..value_end) else { break };

        match info_id {
            INFO_ID_VENUE_NAME => {
                let n = parse_venue_name(value, &mut fragments.wordlist_entries);
                counts.venue_name += n;
            },
            INFO_ID_DOMAIN_NAME_LIST => {
                let n = parse_domain_name_list(value, &mut fragments.wordlist_entries);
                counts.domain_name += n;
            },
            INFO_ID_NAI_REALM => {
                let n = parse_nai_realm(value, &mut fragments.wordlist_entries);
                counts.nai_realm += n;
            },
            INFO_ID_VENDOR_SPECIFIC => {
                let n = parse_vendor_specific(value, &mut fragments.wordlist_entries);
                counts.hs_operator_friendly_name += n;
            },
            _ => {
                counts.unknown_info_id += 1;
            },
        }

        pos = value_end;
    }

    (fragments, counts)
}

/// Parses a Venue Name ANQP element body into one or more text entries.
///
/// Body layout per [IEEE 802.11-2024] §9.4.5.4, Figure 9-770:
///   `Venue Info` (2 bytes) + 1..N x `Venue Name Duple`
///   where each Duple is `Length (1)` + `Language Code (3)` + `Venue Name (Length-3)`
///
/// Returns the number of successfully parsed duples. Only the Venue Name portion
/// (after the 3-byte language code) reaches the wordlist.
fn parse_venue_name(body: &[u8], out: &mut Vec<Vec<u8>>) -> u64 {
    if body.len() < VENUE_INFO_LEN {
        return 0;
    }
    parse_duples(body.get(VENUE_INFO_LEN..).unwrap_or(&[]), out)
}

/// Parses a Domain Name List ANQP element into one or more FQDN strings.
///
/// Body layout per [IEEE 802.11-2024] §9.4.5.19, Figure 9-785:
///   1..N x (`Domain Name Length (1)` + `Domain Name (Length)`)
///
/// Returns the count of domain names successfully parsed and pushed.
fn parse_domain_name_list(body: &[u8], out: &mut Vec<Vec<u8>>) -> u64 {
    let mut pos = 0usize;
    let mut count = 0u64;
    while pos < body.len() {
        let Some(&len_byte) = body.get(pos) else { break };
        let len = usize::from(len_byte);
        let value_start = pos + 1;
        let value_end = value_start.saturating_add(len);
        if value_end > body.len() {
            break; // truncated
        }
        if let Some(name) = body.get(value_start..value_end) {
            if !name.is_empty() {
                out.push(name.to_vec());
                count += 1;
            }
        }
        pos = value_end;
    }
    count
}

/// Parses an NAI Realm ANQP element into one or more Realm strings.
///
/// Body layout per [IEEE 802.11-2024] §9.4.5.10, Figure 9-779:
///   `NAI Realm Count (u16 LE)` + 1..N x `NAI Realm Data`
///
///   NAI Realm Data := `NAI Realm Data Length (u16 LE)`
///     + `Encoding (1)` + `NAI Realm Length (1)` + `NAI Realm (variable)`
///     + 1..N x EAP Method tuple (ignored in v1 -- we only surface the Realm).
///
/// Returns the count of realm strings pushed.
fn parse_nai_realm(body: &[u8], out: &mut Vec<Vec<u8>>) -> u64 {
    if body.len() < 2 {
        return 0;
    }
    let Some(cnt_lo) = body.first() else { return 0 };
    let Some(cnt_hi) = body.get(1) else { return 0 };
    let realm_count = usize::from(u16::from_le_bytes([*cnt_lo, *cnt_hi]));
    let mut pos = 2usize;
    let mut count = 0u64;
    for _ in 0..realm_count {
        if pos + 2 > body.len() {
            break;
        }
        let Some(rl_lo) = body.get(pos) else { break };
        let Some(rl_hi) = body.get(pos + 1) else { break };
        let data_len = usize::from(u16::from_le_bytes([*rl_lo, *rl_hi]));
        let data_start = pos + 2;
        let data_end = data_start.saturating_add(data_len);
        if data_end > body.len() {
            break;
        }
        // NAI Realm Data fixed head: Encoding (1) + Realm Length (1) + Realm.
        // [IEEE 802.11-2024] §9.4.5.10, Figure 9-780.
        let Some(realm_data) = body.get(data_start..data_end) else { break };
        if realm_data.len() >= 2 {
            // Skip Encoding byte at [0]; Realm Length at [1].
            let realm_len = usize::from(*realm_data.get(1).unwrap_or(&0));
            let realm_start = 2usize;
            let realm_end = realm_start.saturating_add(realm_len);
            if let Some(realm) = realm_data.get(realm_start..realm_end) {
                if !realm.is_empty() {
                    out.push(realm.to_vec());
                    count += 1;
                }
            }
        }
        pos = data_end;
    }
    count
}

/// Parses an ANQP Vendor Specific element, extracting Hotspot 2.0 Operator Friendly
/// Name duples when the OUI is Wi-Fi Alliance and the subtype is HS2 OFN (3).
///
/// Body layout per Hotspot 2.0 Tech Spec v3.2 §4.2, Figure 4-1:
///   `OUI (3 bytes)` + `ANQP Subtype (1 byte)` + `Reserved (1 byte)` + payload
///
/// For subtype 3 (Operator Friendly Name), the payload is a stream of Duples with
/// the same shape as Venue Name Duples (per HS2 spec §4.3). Returns the count of
/// Duples pushed to `out`; returns 0 for any other OUI or subtype.
fn parse_vendor_specific(body: &[u8], out: &mut Vec<Vec<u8>>) -> u64 {
    if body.len() < 5 {
        return 0;
    }
    let oui = body.get(0..3).unwrap_or(&[0, 0, 0]);
    if oui != OUI_WFA_HS20 {
        return 0;
    }
    let subtype = *body.get(3).unwrap_or(&0);
    if subtype != HS20_SUBTYPE_OP_FRIENDLY_NAME {
        return 0;
    }
    // Skip OUI(3) + Subtype(1) + Reserved(1) = 5 bytes; the remainder is Duples.
    parse_duples(body.get(5..).unwrap_or(&[]), out)
}

/// Parses a `Language-Code + Text` duple stream (shared by Venue Name and
/// Hotspot 2.0 Operator Friendly Name).
///
/// Each duple is `Length (1)` + `Language Code (3)` + `Text (Length-3)`.
/// Only the Text portion (after the language code) reaches `out` -- the language
/// code is metadata, not user-visible content. Returns the count of duples pushed.
fn parse_duples(body: &[u8], out: &mut Vec<Vec<u8>>) -> u64 {
    let mut pos = 0usize;
    let mut count = 0u64;
    while pos < body.len() {
        let Some(&len_byte) = body.get(pos) else { break };
        let total_len = usize::from(len_byte);
        if total_len < LANGUAGE_CODE_LEN {
            break; // malformed: duple must at least cover the language code
        }
        let value_start = pos + 1;
        let value_end = value_start.saturating_add(total_len);
        if value_end > body.len() {
            break;
        }
        let text_start = value_start + LANGUAGE_CODE_LEN;
        if let Some(text) = body.get(text_start..value_end) {
            if !text.is_empty() {
                out.push(text.to_vec());
                count += 1;
            }
        }
        pos = value_end;
    }
    count
}

/// Strips the GAS Initial Response fixed fields from an Action frame body and
/// returns the Query Response bytes.
///
/// Layout per [IEEE 802.11-2024] §9.6.7.14, Figure 9-1008:
///   `Category (1)` + `Action (1)` + `Dialog Token (1)` + `Status Code (u16 LE)`
///   + `GAS Comeback Delay (u16 LE)` + `Advertisement Protocol element (tag 108,
///     variable)` + `Query Response Length (u16 LE)` + `Query Response (Length bytes)`
///
/// Returns `None` when:
/// - The body is too short to even carry the fixed prefix.
/// - The Advertisement Protocol element TLV is truncated.
/// - The Status Code is non-zero (request refused; no Query Response).
/// - `GAS Comeback Delay` is non-zero (response is fragmented and the full payload
///   will arrive via GAS Comeback Response, which we do not reassemble in v1).
/// - The Query Response Length would read past the end of the body.
///
/// The caller is expected to bump `stats.anqp_fragmented_skipped` when the
/// GAS Comeback Delay reason triggered the `None` return.
#[must_use]
pub fn strip_gas_fixed_fields(action_body: &[u8]) -> Option<&[u8]> {
    // Offsets:
    //   [0]    Category
    //   [1]    Action
    //   [2]    Dialog Token
    //   [3..5] Status Code (u16 LE)
    //   [5..7] GAS Comeback Delay (u16 LE)
    //   [7..]  Advertisement Protocol element (tag 108, length, value)
    //   then   Query Response Length (u16 LE) + Query Response bytes
    if action_body.len() < 7 {
        return None;
    }
    let status = u16::from_le_bytes([*action_body.get(3)?, *action_body.get(4)?]);
    if status != 0 {
        return None;
    }
    let comeback_delay = u16::from_le_bytes([*action_body.get(5)?, *action_body.get(6)?]);
    if comeback_delay != 0 {
        return None;
    }
    // Advertisement Protocol element: tag (1) + length (1) + value (length).
    // [IEEE 802.11-2024] §9.4.2.93. We do not validate tag==108 here; we only need
    // to skip past the element to reach Query Response Length.
    let adv_len = usize::from(*action_body.get(8)?);
    let qrl_start = 7 + 2 + adv_len; // 7 fixed + (tag+len = 2) + value
    if qrl_start + 2 > action_body.len() {
        return None;
    }
    let qrl_lo = *action_body.get(qrl_start)?;
    let qrl_hi = *action_body.get(qrl_start + 1)?;
    let qrl = usize::from(u16::from_le_bytes([qrl_lo, qrl_hi]));
    let payload_start = qrl_start + 2;
    let payload_end = payload_start.checked_add(qrl)?;
    if payload_end > action_body.len() {
        return None;
    }
    action_body.get(payload_start..payload_end)
}

/// Returns `true` when the Action-frame body is a GAS Initial Response with a
/// non-zero GAS Comeback Delay (fragmented response deferred to a Comeback frame).
///
/// Caller uses this to distinguish the "skipped because fragmented" case from the
/// "skipped because truncated / malformed" case so `stats.anqp_fragmented_skipped`
/// is only bumped for the former.
#[must_use]
pub fn is_fragmented_response(action_body: &[u8]) -> bool {
    if action_body.len() < 7 {
        return false;
    }
    let Some(lo) = action_body.get(5) else { return false };
    let Some(hi) = action_body.get(6) else { return false };
    u16::from_le_bytes([*lo, *hi]) != 0
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

    /// Build a Venue Name ANQP element body with one English duple.
    fn venue_name_body(venue: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x00, 0x02]); // Venue Info: Group=0, Type=2 (arbitrary)
        // Duple: Length = 3 + venue.len(), LangCode "eng", Text
        let total_len = 3 + venue.len();
        v.push(total_len as u8);
        v.extend_from_slice(b"eng");
        v.extend_from_slice(venue);
        v
    }

    /// Build a Domain Name List body with the given FQDNs.
    fn domain_name_body(names: &[&[u8]]) -> Vec<u8> {
        let mut v = Vec::new();
        for n in names {
            v.push(n.len() as u8);
            v.extend_from_slice(n);
        }
        v
    }

    /// Build an NAI Realm body with a single realm and zero EAP method tuples.
    fn nai_realm_body(realm: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0x01, 0x00]); // Realm Count = 1
        // NAI Realm Data: Encoding(1) + RealmLen(1) + Realm + EAPMethodCount(1)=0
        let data_len = 1 + 1 + realm.len() + 1;
        v.extend_from_slice(&u16::try_from(data_len).unwrap().to_le_bytes());
        v.push(0x00); // Encoding: RFC 4282
        v.push(realm.len() as u8);
        v.extend_from_slice(realm);
        v.push(0x00); // EAP Method Count = 0
        v
    }

    /// Build a Hotspot 2.0 Operator Friendly Name vendor-specific body.
    fn hs_operator_friendly_name_body(text: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&OUI_WFA_HS20); // OUI
        v.push(HS20_SUBTYPE_OP_FRIENDLY_NAME); // Subtype = 3
        v.push(0x00); // Reserved
        // Duple: Length=3+text, LangCode="eng", Text
        let total_len = 3 + text.len();
        v.push(total_len as u8);
        v.extend_from_slice(b"eng");
        v.extend_from_slice(text);
        v
    }

    /// Wrap an ANQP-element body in the TLV header.
    fn anqp_tlv(info_id: u16, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&info_id.to_le_bytes());
        v.extend_from_slice(&u16::try_from(body.len()).unwrap().to_le_bytes());
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn venue_name_single_duple() {
        let tlv = anqp_tlv(INFO_ID_VENUE_NAME, &venue_name_body(b"Cafe Kyoto"));
        let (frags, counts) = parse_query_response(&tlv);
        assert_eq!(counts.venue_name, 1);
        assert_eq!(frags.wordlist_entries, vec![b"Cafe Kyoto".to_vec()]);
    }

    #[test]
    fn domain_name_list_multiple() {
        let body = domain_name_body(&[b"example.com", b"wlan.acme.co"]);
        let tlv = anqp_tlv(INFO_ID_DOMAIN_NAME_LIST, &body);
        let (frags, counts) = parse_query_response(&tlv);
        assert_eq!(counts.domain_name, 2);
        assert_eq!(frags.wordlist_entries, vec![b"example.com".to_vec(), b"wlan.acme.co".to_vec()]);
    }

    #[test]
    fn nai_realm_single() {
        let tlv = anqp_tlv(INFO_ID_NAI_REALM, &nai_realm_body(b"example.com"));
        let (frags, counts) = parse_query_response(&tlv);
        assert_eq!(counts.nai_realm, 1);
        assert_eq!(frags.wordlist_entries, vec![b"example.com".to_vec()]);
    }

    #[test]
    fn hs_operator_friendly_name_single() {
        let tlv = anqp_tlv(INFO_ID_VENDOR_SPECIFIC, &hs_operator_friendly_name_body(b"Acme Telco"));
        let (frags, counts) = parse_query_response(&tlv);
        assert_eq!(counts.hs_operator_friendly_name, 1);
        assert_eq!(frags.wordlist_entries, vec![b"Acme Telco".to_vec()]);
    }

    #[test]
    fn vendor_specific_wrong_oui_ignored() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x00, 0x11, 0x22]); // not WFA
        body.push(0x03); // subtype (would-be OFN)
        body.push(0x00); // reserved
        body.push(6);
        body.extend_from_slice(b"eng");
        body.extend_from_slice(b"foo");
        let tlv = anqp_tlv(INFO_ID_VENDOR_SPECIFIC, &body);
        let (frags, counts) = parse_query_response(&tlv);
        assert_eq!(counts.hs_operator_friendly_name, 0);
        assert!(frags.wordlist_entries.is_empty());
    }

    #[test]
    fn vendor_specific_wrong_subtype_ignored() {
        let mut body = Vec::new();
        body.extend_from_slice(&OUI_WFA_HS20);
        body.push(0x01); // HS2 Capability List subtype, not OFN
        body.push(0x00);
        body.extend_from_slice(&[0x01, 0x02, 0x03]);
        let tlv = anqp_tlv(INFO_ID_VENDOR_SPECIFIC, &body);
        let (_, counts) = parse_query_response(&tlv);
        assert_eq!(counts.hs_operator_friendly_name, 0);
        assert_eq!(counts.unknown_info_id, 0); // Vendor-Specific still parsed, just no OFN
    }

    #[test]
    fn unknown_info_id_counted() {
        // InfoID 261 (3GPP Cellular Network) is defined but we don't parse it.
        let tlv = anqp_tlv(261, &[0xAA, 0xBB, 0xCC]);
        let (frags, counts) = parse_query_response(&tlv);
        assert_eq!(counts.unknown_info_id, 1);
        assert!(frags.wordlist_entries.is_empty());
    }

    #[test]
    fn multiple_elements_in_one_response() {
        // Venue Name + Domain Name List + NAI Realm + HS2 OFN, all four present.
        let mut stream = Vec::new();
        stream.extend_from_slice(&anqp_tlv(INFO_ID_VENUE_NAME, &venue_name_body(b"Cafe Kyoto")));
        stream.extend_from_slice(&anqp_tlv(INFO_ID_DOMAIN_NAME_LIST, &domain_name_body(&[b"example.com"])));
        stream.extend_from_slice(&anqp_tlv(INFO_ID_NAI_REALM, &nai_realm_body(b"example.org")));
        stream.extend_from_slice(&anqp_tlv(INFO_ID_VENDOR_SPECIFIC, &hs_operator_friendly_name_body(b"Acme Telco")));
        let (frags, counts) = parse_query_response(&stream);
        assert_eq!(counts.venue_name, 1);
        assert_eq!(counts.domain_name, 1);
        assert_eq!(counts.nai_realm, 1);
        assert_eq!(counts.hs_operator_friendly_name, 1);
        assert_eq!(
            frags.wordlist_entries,
            vec![b"Cafe Kyoto".to_vec(), b"example.com".to_vec(), b"example.org".to_vec(), b"Acme Telco".to_vec(),]
        );
    }

    #[test]
    fn truncated_tlv_stops_cleanly() {
        // Info ID + Length say "20 bytes" but only 3 bytes follow.
        let mut buf = Vec::new();
        buf.extend_from_slice(&INFO_ID_VENUE_NAME.to_le_bytes());
        buf.extend_from_slice(&20_u16.to_le_bytes());
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let (frags, counts) = parse_query_response(&buf);
        assert_eq!(counts.venue_name, 0);
        assert!(frags.wordlist_entries.is_empty());
    }

    #[test]
    fn domain_name_empty_entry_skipped() {
        // Length byte 0 -> zero-length domain -> not pushed.
        let body = vec![0u8]; // domain length = 0
        let tlv = anqp_tlv(INFO_ID_DOMAIN_NAME_LIST, &body);
        let (frags, counts) = parse_query_response(&tlv);
        assert_eq!(counts.domain_name, 0);
        assert!(frags.wordlist_entries.is_empty());
    }

    #[test]
    fn strip_gas_fixed_fields_ok() {
        // Category(4) + Action(11) + DialogToken(1) + Status(0,0) + Comeback(0,0)
        // + AdvProto IE (tag=108, len=2, value [0x7F, 0x00])
        // + Query Response Length(3, 0) + payload "ABC"
        let mut frame = vec![4, 11, 1, 0x00, 0x00, 0x00, 0x00, 108, 2, 0x7F, 0x00, 3, 0];
        frame.extend_from_slice(b"ABC");
        let qr = strip_gas_fixed_fields(&frame).unwrap();
        assert_eq!(qr, b"ABC");
    }

    #[test]
    fn strip_gas_fixed_fields_rejects_non_zero_status() {
        let frame = vec![4, 11, 1, 0x01, 0x00, 0x00, 0x00, 108, 0, 0, 0];
        assert!(strip_gas_fixed_fields(&frame).is_none());
    }

    #[test]
    fn strip_gas_fixed_fields_rejects_fragmented() {
        let frame = vec![4, 11, 1, 0x00, 0x00, 0x0A, 0x00, 108, 0, 0, 0];
        assert!(strip_gas_fixed_fields(&frame).is_none());
        assert!(is_fragmented_response(&frame));
    }

    #[test]
    fn is_fragmented_false_when_delay_zero() {
        let frame = vec![4, 11, 1, 0x00, 0x00, 0x00, 0x00, 108, 0, 0, 0];
        assert!(!is_fragmented_response(&frame));
    }
}
