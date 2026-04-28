//! Phase 2 -- Decode: A-MSDU (Aggregate MSDU) subframe iterator. See ARCHITECTURE.md §3.2.
//!
//! IEEE 802.11n introduced A-MSDU aggregation: a single `QoS` Data MPDU can carry
//! multiple MSDUs back-to-back in its body, each prefixed with its own DA + SA +
//! Length + LLC/SNAP. Without subframe-level parsing, EAPOL hidden in subframes
//! 2..N is invisible to the EAPOL classifier, which expects LLC/SNAP at offset 0
//! of the body. This module exposes that hidden traffic.
//!
//! # Subframe layout
//!
//! Per IEEE 802.11-2024 §9.7.2, an A-MSDU body is a sequence of subframes:
//!
//! ```text
//!  +---------------+
//!  | DA (6 bytes)  |
//!  | SA (6 bytes)  |
//!  | Length (2 BE) |  <-- length of `payload` only, not including padding
//!  | payload       |  <-- typically LLC/SNAP (8 B) + actual MSDU body
//!  | padding       |  <-- 0..3 bytes to align next subframe header to 4 B
//!  +---------------+
//!  | DA SA Length  |
//!  | payload ...   |
//!  +---------------+
//! ```
//!
//! No padding is added after the last subframe. A subframe whose declared
//! `Length` would overrun the remaining body is rejected (the iterator stops).
//!
//! # What we yield
//!
//! Each iteration yields a `&[u8]` slice that is *just the payload* (the bytes
//! after DA + SA + Length, length = declared `Length`). The caller treats each
//! payload as a regular MSDU body -- LLC/SNAP at offset 0, EAPOL at offset 8 if
//! the `EtherType` matches. The DA / SA inner addresses are intentionally
//! discarded: for our purposes the outer MAC header's (`ap`, `sta`) is the
//! authoritative session key, and re-keying on subframe DA/SA would split a
//! single (`AP`, `STA`) handshake across two `MessageStore` groups.
//!
//! # Out of scope
//!
//! Mesh A-MSDU and DMG A-MSDU variants reuse the same wire format. WDS A-MSDU
//! technically exists but is rare; the caller is free to skip A-MSDU on WDS
//! frames (the outer (ap, sta) ambiguity makes per-subframe attribution
//! unreliable).

/// Iterator over the payloads of A-MSDU subframes.
///
/// Constructed from the body of a `QoS` Data frame whose A-MSDU Present bit
/// (`is_amsdu`) is set. Each `next()` returns one payload slice or `None` when
/// the body is exhausted / a subframe is malformed.
#[derive(Debug)]
pub struct AmsduIter<'a> {
    rest: &'a [u8],
}

impl<'a> AmsduIter<'a> {
    /// Wraps a body slice for subframe iteration. Caller must have verified
    /// the outer frame's A-MSDU Present bit.
    #[must_use]
    pub const fn new(body: &'a [u8]) -> Self {
        Self { rest: body }
    }
}

impl<'a> Iterator for AmsduIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        // Each subframe header is DA(6) + SA(6) + Length(2 BE) = 14 bytes.
        // [IEEE 802.11-2024] §9.7.2
        if self.rest.len() < 14 {
            return None;
        }
        let len_bytes: [u8; 2] = self.rest.get(12..14)?.try_into().ok()?;
        let payload_len = u16::from_be_bytes(len_bytes) as usize;
        let total_with_payload = 14usize.checked_add(payload_len)?;
        if total_with_payload > self.rest.len() {
            // Declared length overruns the body: subframe is truncated. Stop
            // iteration so the caller does not see partial garbage.
            return None;
        }
        let payload = self.rest.get(14..total_with_payload)?;
        // Skip padding to next 4-byte boundary. No padding is added after the
        // *last* subframe; if the remainder is shorter than the padding, just
        // exhaust the rest and the next call returns None naturally. Use
        // `wrapping_add` of `(4 - n) & 3` so a value already aligned adds 0.
        let pad = (4usize - (payload_len & 3)) & 3;
        let next_offset = total_with_payload.saturating_add(pad).min(self.rest.len());
        self.rest = self.rest.get(next_offset..).unwrap_or(&[]);
        Some(payload)
    }
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

    /// Builds one A-MSDU subframe: DA(6) + SA(6) + Length(2 BE) + payload + padding.
    fn build_subframe(da: [u8; 6], sa: [u8; 6], payload: &[u8], with_padding: bool) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&da);
        v.extend_from_slice(&sa);
        v.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        v.extend_from_slice(payload);
        if with_padding {
            let pad = (4 - (payload.len() & 3)) & 3;
            v.extend(std::iter::repeat_n(0u8, pad));
        }
        v
    }

    #[test]
    fn empty_body_yields_nothing() {
        assert!(AmsduIter::new(&[]).next().is_none());
    }

    #[test]
    fn body_too_short_for_subframe_header_yields_nothing() {
        // 13 bytes is one less than the 14-byte subframe header.
        let buf = vec![0u8; 13];
        assert!(AmsduIter::new(&buf).next().is_none());
    }

    #[test]
    fn single_subframe_yields_payload_only() {
        let payload = b"hello world!"; // 12 bytes -- already 4-aligned
        let body = build_subframe([0xAA; 6], [0xBB; 6], payload, true);
        let mut it = AmsduIter::new(&body);
        let got = it.next().unwrap();
        assert_eq!(got, payload);
        assert!(it.next().is_none(), "single subframe -> exactly one payload");
    }

    #[test]
    fn two_subframes_yield_each_payload() {
        // First subframe with 13-byte payload requires 3 bytes of padding to
        // align the next subframe header to 4 bytes.
        let p1 = b"thirteen-byts"; // 13 bytes
        let p2 = b"second"; // 6 bytes (last subframe -- no padding required)
        let mut body = build_subframe([0xAA; 6], [0xBB; 6], p1, true);
        body.extend_from_slice(&build_subframe([0xCC; 6], [0xDD; 6], p2, false));
        let mut it = AmsduIter::new(&body);
        assert_eq!(it.next().unwrap(), p1);
        assert_eq!(it.next().unwrap(), p2);
        assert!(it.next().is_none());
    }

    #[test]
    fn truncated_payload_terminates_iteration() {
        // Header claims Length=20 but body has only 16 bytes total (header + 2
        // bytes of payload). The iterator must stop without returning a partial
        // subframe.
        let mut body = Vec::new();
        body.extend_from_slice(&[0xAA; 6]); // DA
        body.extend_from_slice(&[0xBB; 6]); // SA
        body.extend_from_slice(&20u16.to_be_bytes()); // Length=20
        body.extend_from_slice(&[0xFFu8; 2]); // 2 bytes of "payload"
        let mut it = AmsduIter::new(&body);
        assert!(it.next().is_none(), "truncated subframe must yield nothing");
    }

    #[test]
    fn three_subframes_with_mixed_alignments() {
        // Verifies padding handling across a sequence: 5-byte payload (3 pad),
        // 4-byte payload (0 pad), 7-byte payload (last -> no pad).
        let p1 = b"abcde"; // 5 bytes
        let p2 = b"WXYZ"; // 4 bytes (aligned -- 0 padding)
        let p3 = b"trailer"; // 7 bytes
        let mut body = build_subframe([1; 6], [2; 6], p1, true);
        body.extend_from_slice(&build_subframe([3; 6], [4; 6], p2, true));
        body.extend_from_slice(&build_subframe([5; 6], [6; 6], p3, false));
        let mut it = AmsduIter::new(&body);
        assert_eq!(it.next().unwrap(), p1);
        assert_eq!(it.next().unwrap(), p2);
        assert_eq!(it.next().unwrap(), p3);
        assert!(it.next().is_none());
    }

    #[test]
    fn zero_length_subframe_skipped_cleanly() {
        // Spec-rare but possible: declared Length=0 means an "empty payload"
        // subframe. Our iterator yields the empty slice and continues; the
        // EAPOL parser will discard the 0-byte body harmlessly.
        let mut body = Vec::new();
        body.extend_from_slice(&[0; 6]);
        body.extend_from_slice(&[0; 6]);
        body.extend_from_slice(&0u16.to_be_bytes());
        // Padding for a 0-byte payload: (4 - 0) & 3 = 0, no pad added.
        // Then a real subframe.
        body.extend_from_slice(&build_subframe([1; 6], [2; 6], b"data", false));
        let mut it = AmsduIter::new(&body);
        assert_eq!(it.next().unwrap(), b""); // empty payload
        assert_eq!(it.next().unwrap(), b"data");
        assert!(it.next().is_none());
    }
}
