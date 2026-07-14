//! Shared -- printable-ASCII run scanner used by the wordlist (-W) sink. See ARCHITECTURE.md §9.
//!
//! Classic `strings(1)` style: walk an arbitrary byte slice and yield every
//! contiguous run of printable ASCII bytes (0x20..=0x7E) whose length
//! meets or exceeds a caller-specified minimum. Runs interrupted by a
//! non-printable byte are split. Non-printable bytes themselves are
//! discarded.
//!
//! This is the mechanism behind the `-W` invariant that wpawolf's combined
//! wordlist output captures every ASCII string leaked in the capture,
//! without requiring per-IE / per-protocol extractors for each vendor
//! proprietary element. Management-frame IEs that wolf already parses
//! (SSID, WPS, country code, Mesh ID, vendor AP names, etc.) continue to
//! feed `WordlistStore` through their dedicated paths -- this scan runs on
//! every frame body in addition, catching the tail end of any vendor IE,
//! the plaintext payload of unencrypted data frames (EAPOL identity
//! strings, ARP, unencrypted DHCP), ANQP / Hotspot 2.0 elements that wolf
//! does not parse structurally, and any other printable ASCII fragment
//! that appears anywhere on the wire.
//!
//! Cost is O(n) in the scanned bytes with zero allocations for non-run
//! spans; per-run cost is the `WordlistStore::insert` dedup and one heap
//! allocation per unique run value. Encrypted Data frame payloads produce
//! essentially no runs (ciphertext avoids the printable band by design)
//! and are therefore cheap to sweep.

/// Minimum length in bytes for a printable-ASCII run to be yielded.
///
/// Tuned to match GNU `strings(1)` default. Four bytes is the shortest
/// length at which runs reliably distinguish signal (short words, short
/// identifiers) from random printable-ASCII-looking noise in binary
/// payloads (MAC prefixes, length fields that happen to fall in the
/// printable band, etc.).
pub const DEFAULT_MIN_RUN: usize = 4;

/// Returns every contiguous printable-ASCII run of length `>= min_len`
/// found in `buf`.
///
/// A "printable ASCII byte" is `0x20..=0x7E` (space through tilde, exactly
/// the `isprint()` set without DEL / 0x7F). Non-printable bytes (controls
/// 0x00-0x1F, 0x7F, and 0x80-0xFF high-bit) act as run terminators and are
/// themselves dropped.
///
/// Returns a `Vec<&[u8]>` borrowing into `buf` rather than an iterator
/// because the caller's typical use-case (`WordlistStore::insert` with
/// `.to_vec()` on each run) already heap-allocates per unique run and the
/// intermediate `Vec` wrapper is negligible by comparison. The
/// zero-allocation no-runs-found case is the common one for encrypted /
/// binary payloads.
#[must_use]
pub fn extract_ascii_runs(buf: &[u8], min_len: usize) -> Vec<&[u8]> {
    let mut runs: Vec<&[u8]> = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in buf.iter().enumerate() {
        if (0x20..=0x7E).contains(&b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take()
            && let Some(run) = buf.get(s..i)
            && run.len() >= min_len
        {
            runs.push(run);
        }
    }
    if let Some(s) = start.take()
        && let Some(run) = buf.get(s..)
        && run.len() >= min_len
    {
        runs.push(run);
    }
    runs
}

// --- Unit tests ---

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn empty_input() {
        assert!(extract_ascii_runs(b"", 4).is_empty());
    }

    #[test]
    fn single_short_run_dropped() {
        assert!(extract_ascii_runs(b"abc", 4).is_empty());
    }

    #[test]
    fn single_long_run_returned() {
        let r = extract_ascii_runs(b"hello", 4);
        assert_eq!(r, vec![b"hello".as_slice()]);
    }

    #[test]
    fn two_runs_split_by_nul() {
        let r = extract_ascii_runs(b"Acme\x00Router", 4);
        assert_eq!(r, vec![b"Acme".as_slice(), b"Router".as_slice()]);
    }

    #[test]
    fn runs_split_by_high_byte() {
        // 0xC3 is a UTF-8 continuation-leader, classed as non-printable.
        let r = extract_ascii_runs(b"foo\xc3bar", 3);
        assert_eq!(r, vec![b"foo".as_slice(), b"bar".as_slice()]);
    }

    #[test]
    fn short_runs_between_long_ones_dropped() {
        // "abc" is 3 bytes and falls below min_len=4; only "longrun" survives.
        let r = extract_ascii_runs(b"abc\x01longrun\x02xy", 4);
        assert_eq!(r, vec![b"longrun".as_slice()]);
    }

    #[test]
    fn run_at_very_end_of_buffer() {
        let r = extract_ascii_runs(b"\x00\x00tail", 4);
        assert_eq!(r, vec![b"tail".as_slice()]);
    }

    #[test]
    fn space_and_tilde_boundary_are_printable() {
        let buf = b"\x00 hello~world\xff";
        let r = extract_ascii_runs(buf, 4);
        assert_eq!(r, vec![b" hello~world".as_slice()]);
    }

    #[test]
    fn del_is_non_printable() {
        // 0x7F (DEL) terminates runs per the isprint() convention.
        let r = extract_ascii_runs(b"abcd\x7fefgh", 4);
        assert_eq!(r, vec![b"abcd".as_slice(), b"efgh".as_slice()]);
    }

    #[test]
    fn min_len_zero_emits_every_printable_byte_as_run() {
        // min_len=0 lets 1-byte runs pass; useful for debug tests only.
        let r = extract_ascii_runs(b"a\x00b\x00c", 1);
        assert_eq!(r, vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()]);
    }

    #[test]
    fn min_len_eight_filters_short_runs() {
        // `--wordlist-scan-ies` uses min_len=8 to suppress vendor-IE noise. Only the
        // 8+ byte run survives; the 7-byte run is dropped.
        let r = extract_ascii_runs(b"short7x\x00VendorFirmware\xffshort7a", 8);
        assert_eq!(r, vec![b"VendorFirmware".as_slice()]);
    }
}
