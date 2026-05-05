//! Phase 4 -- Emit: WPS device info (-D) writer. See ARCHITECTURE.md §3.4 + §9.
//!
//! Writes device metadata entries collected from WPS vendor IEs (tag 221, OUI `00:50:F2`,
//! type 4) to the configured output file (`-D`). Column order matches hcxpcapngtool:
//! MAC, manufacturer, model name, serial number, device name, UUID-E (if present), ESSID.
//! All string fields use autohex encoding (printable ASCII as-is, else `$HEX[...]`).
//! Entries are sorted by manufacturer and deduplicated by AP MAC.
//!

use std::io::Write;

use crate::store::auxiliary::DeviceInfoStore;
use crate::types::{Result, bytes_to_hex_string, format_autohex, trim_nul_padding};

/// Writes a single tab-prefixed device info string field using autohex encoding.
///
/// Writes `\t` first, then the autohex-encoded value after the project-wide
/// wordlist NUL-padding trim (`trim_nul_padding`, see `ARCHITECTURE.md §9`).
/// Both leading and trailing 0x00 bytes are dropped; embedded NULs are
/// preserved. The leading-NUL arm covers vendor-specific WPS type-prefix
/// bytes (uncommon but present in some Hotspot 2.0 embedded-client WPS
/// stacks), and the trailing arm covers fixed-width-buffer padding (HP
/// printers, TP-Link routers, and similar per Wi-Fi Protected Setup §12).
/// Values that become empty after trimming produce a tab with no body,
/// matching hcxpcapngtool's "first byte zero" skip in
/// `hcxtools/include/fileops.c:88-102`. Does not write a newline.
fn write_device_field(bytes: &[u8], out: &mut impl Write) -> Result<()> {
    out.write_all(b"\t")?;
    let trimmed = trim_nul_padding(bytes);
    if trimmed.is_empty() {
        return Ok(());
    }
    let encoded = format_autohex(trimmed);
    out.write_all(encoded.as_bytes())?;
    Ok(())
}

/// Writes device info entries to `out`, one per line.
///
/// Column order (tab-separated, matching hcxpcapngtool `outputdeviceinfolist()`):
/// `{mac_hex}\t{manufacturer}\t{model_name}\t{serial}\t{device_name}[\t{uuid_hex}]\t{essid}\n`
///
/// String fields use autohex encoding. UUID is written as raw hex (no `$HEX[]` wrapper)
/// only when present. ESSID uses autohex encoding. Entries with no non-empty string
/// fields are skipped. Sorted by manufacturer. Returns the number of lines written.
///
/// # Errors
///
/// Returns `Err` on I/O failure.
pub fn write_device_info(store: &DeviceInfoStore, out: &mut impl Write) -> Result<usize> {
    // Collect and sort by manufacturer (autohex-encoded for consistent ordering).
    let mut entries: Vec<&crate::store::auxiliary::DeviceInfoEntry> = store.iter().collect();
    entries.sort_unstable_by_key(|e| format_autohex(&e.manufacturer));

    let mut count = 0usize;
    for entry in entries {
        // Skip entries where all string fields are empty (matches hcxpcapngtool guard).
        if entry.manufacturer.is_empty()
            && entry.model_name.is_empty()
            && entry.serial_number.is_empty()
            && entry.device_name.is_empty()
        {
            continue;
        }

        let mac_hex = bytes_to_hex_string(&entry.mac.0);
        out.write_all(mac_hex.as_bytes())?;
        write_device_field(&entry.manufacturer, out)?;
        write_device_field(&entry.model_name, out)?; // model name only (no model_number column)
        write_device_field(&entry.serial_number, out)?;
        write_device_field(&entry.device_name, out)?;
        // UUID-E: written as raw hex (no $HEX[] wrapper), tab-prefixed, only if present.
        // Matches hcxpcapngtool enrollee field. [Wi-Fi Protected Setup spec attr 0x1047]
        if let Some(uuid) = &entry.uuid_e {
            out.write_all(b"\t")?;
            out.write_all(bytes_to_hex_string(uuid).as_bytes())?;
        }
        write_device_field(&entry.essid, out)?;
        out.write_all(b"\n")?;
        count += 1;
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
    use crate::store::auxiliary::{DeviceInfoEntry, DeviceInfoStore};
    use crate::types::MacAddr;

    fn make_entry(mac_byte: u8, uuid_e: Option<[u8; 16]>) -> DeviceInfoEntry {
        DeviceInfoEntry {
            mac: MacAddr::from_bytes([mac_byte; 6]),
            manufacturer: b"Acme".to_vec(),
            model_name: b"Router9000".to_vec(),
            model_number: b"R9K".to_vec(), // not in -D output, but stored for -W
            serial_number: b"SN123".to_vec(),
            device_name: b"HomeAP".to_vec(),
            uuid_e,
            essid: b"MyNet".to_vec(),
        }
    }

    #[test]
    fn write_device_info_empty() {
        let store = DeviceInfoStore::new();
        let mut out = Vec::new();
        let count = write_device_info(&store, &mut out).unwrap();
        assert_eq!(count, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn write_device_info_single() {
        let mut store = DeviceInfoStore::new();
        store.push(make_entry(0x11, Some([0xAB; 16])));
        let mut out = Vec::new();
        let count = write_device_info(&store, &mut out).unwrap();
        assert_eq!(count, 1);
        let text = std::str::from_utf8(&out).unwrap();
        // MAC: 111111111111
        assert!(text.starts_with("111111111111\t"), "MAC should be first field: {text:?}");
        // manufacturer (autohex: plain ASCII)
        assert!(text.contains("\tAcme\t"), "manufacturer field: {text:?}");
        // model_name (no model_number column in -D output)
        assert!(text.contains("\tRouter9000\t"), "model_name field: {text:?}");
        // No model_number column - serial follows model_name directly
        assert!(text.contains("\tRouter9000\tSN123\t"), "serial follows model_name: {text:?}");
        // UUID: 16 bytes of 0xAB -> 32 hex chars "ab" x 16 (no $HEX[] wrapper)
        let uuid_hex = "ab".repeat(16);
        let uuid_field = format!("\t{uuid_hex}\t");
        assert!(text.contains(&uuid_field), "UUID raw hex: {text:?}");
        // ESSID: "MyNet" = autohex (pure ASCII) = "MyNet"
        assert!(text.trim_end().ends_with("\tMyNet"), "ESSID autohex: {text:?}");
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn write_device_info_uuid_absent() {
        let mut store = DeviceInfoStore::new();
        store.push(make_entry(0x22, None));
        let mut out = Vec::new();
        let count = write_device_info(&store, &mut out).unwrap();
        assert_eq!(count, 1);
        let text = std::str::from_utf8(&out).unwrap();
        // When UUID is absent, no UUID field is written at all (no empty tab pair).
        // Fields: mac \t mfr \t model_name \t serial \t dev_name \t essid
        // dev_name then ESSID directly (no uuid tab).
        assert!(text.contains("\tHomeAP\tMyNet"), "no UUID tab when absent: {text:?}");
    }

    #[test]
    fn write_device_info_non_ascii_manufacturer() {
        let mut store = DeviceInfoStore::new();
        let mut entry = make_entry(0x33, None);
        entry.manufacturer = vec![0xC3, 0xA9]; // UTF-8 two-byte sequence (non-ASCII) -> $HEX
        let mut out = Vec::new();
        write_device_info(&store, &mut out).unwrap();
        // entry not pushed yet - empty store
        store.push(entry);
        let mut out = Vec::new();
        let count = write_device_info(&store, &mut out).unwrap();
        assert_eq!(count, 1);
        let text = std::str::from_utf8(&out).unwrap();
        assert!(text.contains("$HEX[c3a9]"), "non-ASCII manufacturer: {text:?}");
    }

    #[test]
    fn write_device_field_trims_trailing_nul_padding() {
        // Per `ARCHITECTURE.md §9`, wordlist-style outputs (including `-D`
        // string columns) trim leading and trailing 0x00 bytes -- the trailing
        // NULs are WSC §12 fixed-width-buffer padding, not content. Embedded
        // NULs are preserved (see `trim_nul_padding_preserves_embedded`).
        let mut store = DeviceInfoStore::new();
        let mut entry = make_entry(0x44, None);
        entry.model_name = b"ENVY 4510 series\x00".to_vec();
        entry.serial_number = b"TH77B4G3GB068H\x00\x00".to_vec();
        store.push(entry);
        let mut out = Vec::new();
        write_device_info(&store, &mut out).unwrap();
        let text = std::str::from_utf8(&out).unwrap();
        // Trimmed model_name has a space (0x20) so lands in the $HEX[] form
        // under wpawolf's stricter plain-ASCII rule. No trailing 00 byte in
        // the hex payload.
        assert!(
            text.contains("\t$HEX[454e5659203435313020736572696573]\t"),
            "trailing NUL trimmed on model_name: {text:?}"
        );
        // Trimmed serial is pure plain ASCII -- no wrapper at all.
        assert!(text.contains("\tTH77B4G3GB068H\t"), "trailing NULs trimmed on serial: {text:?}");
    }

    #[test]
    fn write_device_field_preserves_embedded_nul() {
        // An embedded 0x00 between non-zero bytes is either binary data, an
        // in-band delimiter, or corruption -- the per-design rule preserves
        // it as a signal rather than silently dropping it.
        let mut store = DeviceInfoStore::new();
        let mut entry = make_entry(0x55, None);
        entry.model_name = b"AB\x00CD".to_vec();
        store.push(entry);
        let mut out = Vec::new();
        write_device_info(&store, &mut out).unwrap();
        let text = std::str::from_utf8(&out).unwrap();
        // 4 bytes preserved, with the embedded NUL intact -> $HEX[...].
        assert!(text.contains("$HEX[41420043 44]".replace(' ', "").as_str()), "embedded NUL preserved: {text:?}");
    }

    #[test]
    fn write_device_info_keeps_distinct_rows_under_same_mac() {
        // Two pushes for the same MAC but different manufacturer -> distinct
        // dedup keys (full-row equality), both retained. This is the safety
        // contract: same-MAC observations only collapse when the whole rendered
        // row is byte-identical.
        let mut store = DeviceInfoStore::new();
        let mut e1 = make_entry(0x11, None);
        e1.manufacturer = b"First".to_vec();
        let mut e2 = make_entry(0x11, None); // same MAC
        e2.manufacturer = b"Second".to_vec();
        store.push(e1);
        store.push(e2);
        let mut out = Vec::new();
        let count = write_device_info(&store, &mut out).unwrap();
        assert_eq!(count, 2, "distinct rows under one MAC must both render");
        let text = std::str::from_utf8(&out).unwrap();
        assert!(text.contains("First"), "first entry retained: {text:?}");
        assert!(text.contains("Second"), "second entry retained: {text:?}");
    }

    #[test]
    fn write_device_info_dedupes_byte_identical_rows() {
        // Two byte-identical pushes -> one rendered line. Mirrors what `sort -u`
        // would do on the post-fix output -- the store now does it eagerly to
        // save memory.
        let mut store = DeviceInfoStore::new();
        store.push(make_entry(0x11, Some([0xAB; 16])));
        store.push(make_entry(0x11, Some([0xAB; 16])));
        let mut out = Vec::new();
        let count = write_device_info(&store, &mut out).unwrap();
        assert_eq!(count, 1, "byte-identical rows must collapse to one rendered line");
    }
}
