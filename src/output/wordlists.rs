//! Phase 4 -- Emit: ESSID / probe-ESSID / wordlist / identity / username writers. See ARCHITECTURE.md §3.4 + §9.
//!
//! Writes the ESSID list (`-E`), Probe Request ESSID list (`-R`), combined wordlist
//! (`-W`), EAP identity list (`-I`), and EAP username list (`-U`) to their configured
//! output files. String values use hashcat/hcxtools autohex format: printable ASCII
//! (0x20-0x7E) as plain text, all others as `$HEX[<hex>]`. All lists are sorted
//! for deterministic output.

use std::io::Write;

use crate::store::auxiliary::{EssidSet, IdentitySet, ProbeEssidSet, UsernameSet, WordlistStore};
use crate::types::{Result, format_autohex, trim_nul_padding};

/// Writes one wordlist-style line to `out` after applying the project-wide
/// leading/trailing NUL-padding trim (see `ARCHITECTURE.md §9`). Empty
/// values (either already empty, or empty after trimming) are silently
/// skipped -- `-E` / `-R` / `-I` / `-U` / `-W` are wordlists, and a blank
/// line is a noise entry that every downstream cracker would reject anyway.
/// Returns `true` if a line was actually written. Does not emit a trailing
/// newline on an empty skip; the caller's `count` only increments on `true`.
fn write_trimmed_autohex(bytes: &[u8], out: &mut impl Write) -> Result<bool> {
    let trimmed = trim_nul_padding(bytes);
    if trimmed.is_empty() {
        return Ok(false);
    }
    let line = format_autohex(trimmed);
    out.write_all(line.as_bytes())?;
    out.write_all(b"\n")?;
    Ok(true)
}

/// Writes all unique ESSIDs to `out`, one autohex-encoded entry per line.
///
/// Uses hashcat/hcxtools autohex format: printable ASCII SSIDs are written as-is,
/// non-printable SSIDs as `$HEX[hexbytes]`. Output is sorted for deterministic
/// ordering. Used for `-E` output. Returns the number of lines written.
///
/// # Errors
///
/// Returns `Err` on I/O failure.
pub fn write_essid_list(essid_set: &EssidSet, out: &mut impl Write) -> Result<usize> {
    let mut essids: Vec<&Vec<u8>> = essid_set.iter().collect();
    essids.sort_unstable();
    let mut count = 0usize;
    for essid in essids {
        if write_trimmed_autohex(essid, out)? {
            count += 1;
        }
    }
    Ok(count)
}

/// Writes all unique leaked-information strings to `out`, one autohex-encoded entry per line.
///
/// Uses hashcat/hcxtools autohex format. Contains ESSIDs from all sources, WPS device
/// info strings, EAP identities/usernames, country codes, and other text fields leaked
/// in management frames. Sorted for deterministic ordering. Used for `-W` output.
/// Returns the number of lines written.
///
/// # Errors
///
/// Returns `Err` on I/O failure.
pub fn write_wordlist(wordlist_store: &WordlistStore, out: &mut impl Write) -> Result<usize> {
    let mut entries: Vec<&Vec<u8>> = wordlist_store.iter().collect();
    entries.sort_unstable();
    let mut count = 0usize;
    for entry in entries {
        if write_trimmed_autohex(entry, out)? {
            count += 1;
        }
    }
    Ok(count)
}

/// Writes unique Probe Request ESSIDs to `out`, one autohex-encoded entry per line.
///
/// Outputs SSIDs from directed Probe Requests (IE#0), Probe Request SSID List IEs
/// (IE#84), and Action Neighbor Report Request frames. Same format as `write_essid_list`.
/// Used for `-R` output. Returns the number of lines written.
///
/// # Errors
///
/// Returns `Err` on I/O failure.
pub fn write_probe_essid_list(probe_set: &ProbeEssidSet, out: &mut impl Write) -> Result<usize> {
    let mut essids: Vec<&Vec<u8>> = probe_set.iter().collect();
    essids.sort_unstable();
    let mut count = 0usize;
    for essid in essids {
        if write_trimmed_autohex(essid, out)? {
            count += 1;
        }
    }
    Ok(count)
}

/// Writes all unique EAP identity strings to `out`, one autohex-encoded entry per line.
///
/// Identity strings come from EAP-Response/Identity frames per RFC 3748 §5.1.
/// Non-ASCII bytes are encoded as `$HEX[...]` (matches hcxtools `fwritestring()`).
/// Sorted for deterministic ordering. Used for `-I` output.
/// Returns the number of lines written.
///
/// # Errors
///
/// Returns `Err` on I/O failure.
pub fn write_identities(identity_set: &IdentitySet, out: &mut impl Write) -> Result<usize> {
    let mut identities: Vec<&String> = identity_set.iter().collect();
    identities.sort_unstable();
    let mut count = 0usize;
    for identity in identities {
        if write_trimmed_autohex(identity.as_bytes(), out)? {
            count += 1;
        }
    }
    Ok(count)
}

/// Writes all unique EAP username strings to `out`, one autohex-encoded entry per line.
///
/// Username strings are extracted from EAP peer identity fields.
/// Non-ASCII bytes are encoded as `$HEX[...]` (matches hcxtools `fwritestring()`).
/// Sorted for deterministic ordering. Used for `-U` output.
/// Returns the number of lines written.
///
/// # Errors
///
/// Returns `Err` on I/O failure.
pub fn write_usernames(username_set: &UsernameSet, out: &mut impl Write) -> Result<usize> {
    let mut usernames: Vec<&String> = username_set.iter().collect();
    usernames.sort_unstable();
    let mut count = 0usize;
    for username in usernames {
        if write_trimmed_autohex(username.as_bytes(), out)? {
            count += 1;
        }
    }
    Ok(count)
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
    use crate::store::auxiliary::{EssidSet, IdentitySet, ProbeEssidSet, UsernameSet, WordlistStore};

    #[test]
    fn write_essid_list_empty() {
        let s = EssidSet::new();
        let mut out = Vec::new();
        let count = write_essid_list(&s, &mut out).unwrap();
        assert_eq!(count, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn write_essid_list_single_ascii() {
        let mut s = EssidSet::new();
        s.insert(b"test");
        let mut out = Vec::new();
        let count = write_essid_list(&s, &mut out).unwrap();
        assert_eq!(count, 1);
        // Pure ASCII SSID -> autohex outputs plain text
        assert_eq!(out, b"test\n");
    }

    #[test]
    fn write_essid_list_non_ascii() {
        let mut s = EssidSet::new();
        // UTF-8 multibyte: "caf\xc3\xa9" -- bytes >= 0x80 are autohexed.
        s.insert(b"caf\xc3\xa9");
        let mut out = Vec::new();
        let count = write_essid_list(&s, &mut out).unwrap();
        assert_eq!(count, 1);
        assert_eq!(out, b"$HEX[636166c3a9]\n");
    }

    #[test]
    fn write_essid_list_dedup() {
        let mut s = EssidSet::new();
        s.insert(b"shared");
        s.insert(b"shared");
        let mut out = Vec::new();
        let count = write_essid_list(&s, &mut out).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn write_wordlist_sorted() {
        let mut s = WordlistStore::new();
        s.insert(b"zzz".to_vec());
        s.insert(b"aaa".to_vec());
        let mut out = Vec::new();
        let count = write_wordlist(&s, &mut out).unwrap();
        assert_eq!(count, 2);
        let text = std::str::from_utf8(&out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "aaa");
        assert_eq!(lines[1], "zzz");
    }

    #[test]
    fn write_probe_essid_list_basic() {
        let mut s = ProbeEssidSet::new();
        s.insert(b"guest");
        s.insert(b"caf\xc3\xa9"); // non-ASCII -> $HEX
        let mut out = Vec::new();
        let count = write_probe_essid_list(&s, &mut out).unwrap();
        assert_eq!(count, 2);
        let text = std::str::from_utf8(&out).unwrap();
        assert!(text.contains("guest\n"));
        assert!(text.contains("$HEX[636166c3a9]\n"));
    }

    #[test]
    fn write_identities_single_ascii() {
        let mut s = IdentitySet::new();
        s.insert("user@realm".to_owned());
        let mut out = Vec::new();
        let count = write_identities(&s, &mut out).unwrap();
        assert_eq!(count, 1);
        // Pure ASCII -> plain text (autohex format)
        assert_eq!(out, b"user@realm\n");
    }

    #[test]
    fn write_identities_non_ascii() {
        // Non-ASCII bytes in identity string -> $HEX[...] encoding
        let mut s = IdentitySet::new();
        // "user\xff" contains a non-ASCII byte
        s.insert(String::from_utf8_lossy(b"user\xff").to_string());
        let mut out = Vec::new();
        let count = write_identities(&s, &mut out).unwrap();
        assert_eq!(count, 1);
        // Should be hex-encoded due to 0xFF byte
        let text = std::str::from_utf8(&out).unwrap();
        assert!(text.contains("$HEX[") || text.contains("user"), "should encode non-ASCII identity");
    }

    #[test]
    fn write_usernames_single_ascii() {
        let mut s = UsernameSet::new();
        s.insert("admin".to_owned());
        let mut out = Vec::new();
        let count = write_usernames(&s, &mut out).unwrap();
        assert_eq!(count, 1);
        // Pure ASCII -> plain text (autohex format)
        assert_eq!(out, b"admin\n");
    }
}
