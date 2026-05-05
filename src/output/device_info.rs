//! Phase 4 -- Emit: WPS device info (-D) writer. See ARCHITECTURE.md §3.4 + §9.
//!
//! Writes device metadata entries collected from WPS vendor IEs (tag 221, OUI `00:50:F2`,
//! type 4) to the configured output file (`-D`). Column order:
//!
//! `MAC \t manufacturer \t model_name \t model_number \t serial_number \t
//!   device_name \t os_version \t primary_device_type \t
//!   secondary_device_type_list [\t uuid_e] \t essid`
//!
//! Four columns are wpawolf additions over hcxpcapngtool's `-D`, which only
//! emits `MAC / manufacturer / model_name / serial_number / device_name /
//! [uuid_e] / essid`:
//! * `model_number` (WPS attr 0x1024) -- hcxtools does not even parse this attribute.
//! * `os_version` (WPS attr 0x102D) -- 4-byte big-endian uint32 rendered as 8 lowercase hex.
//! * `primary_device_type` (WPS attr 0x1054) -- 8-byte structured value rendered as 16 lowercase hex.
//! * `secondary_device_type_list` (WPS attr 0x1055) -- variable list of 8-byte
//!   entries rendered as concatenated lowercase hex.
//!
//! All string fields use autohex encoding (printable ASCII as-is, else `$HEX[...]`).
//! Binary fields (UUID-E, OS Version, Primary Device Type, Secondary Device Type
//! List) use raw lowercase hex without the `$HEX[...]` wrapper. An absent
//! optional field renders as an empty cell (just the leading `\t`); UUID-E
//! remains conditional (no tab when absent) for back-compat with prior `-D`
//! parsers. Entries are sorted by manufacturer; row-level dedup happens at the
//! store layer (see `store::auxiliary::DeviceInfoStore`).
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

/// Writes a single tab-prefixed binary field as raw lowercase hex.
///
/// Always writes a leading `\t`. When `bytes` is empty the cell ends up empty
/// (just the tab); when populated it writes the hex form without any
/// `$HEX[...]` wrapper. Used for OS Version, Primary Device Type, and
/// Secondary Device Type List, all of which are spec-defined as binary blobs
/// with no printable-ASCII semantics.
fn write_device_hex_field(bytes: &[u8], out: &mut impl Write) -> Result<()> {
    out.write_all(b"\t")?;
    if !bytes.is_empty() {
        out.write_all(bytes_to_hex_string(bytes).as_bytes())?;
    }
    Ok(())
}

/// Writes device info entries to `out`, one per line.
///
/// Column order (tab-separated):
/// `{mac}\t{mfr}\t{model_name}\t{model_number}\t{serial}\t{device_name}\t{os_version}\t{primary_device_type}\t{secondary_device_type_list}[\t{uuid_hex}]\t{essid}\n`
///
/// String fields use autohex encoding. Binary fields (OS Version, Primary
/// Device Type, Secondary Device Type List) use raw lowercase hex without the
/// `$HEX[...]` wrapper; an absent value renders as an empty cell. UUID-E uses
/// raw hex too but its tab is conditional (only emitted when present), kept
/// that way for back-compat with prior `-D` parsers.
///
/// Entries with every primary content field empty are skipped. Sorted by
/// manufacturer. Returns the number of lines written.
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
        // Skip entries where every primary content field is empty. Mirrors the
        // store-layer guard so a writer never sees an all-empty entry, but kept
        // here defensively for direct callers (tests, other consumers).
        if entry.manufacturer.is_empty()
            && entry.model_name.is_empty()
            && entry.model_number.is_empty()
            && entry.serial_number.is_empty()
            && entry.device_name.is_empty()
            && entry.os_version.is_none()
            && entry.primary_device_type.is_none()
            && entry.secondary_device_type_list.is_empty()
        {
            continue;
        }

        let mac_hex = bytes_to_hex_string(&entry.mac.0);
        out.write_all(mac_hex.as_bytes())?;
        write_device_field(&entry.manufacturer, out)?;
        write_device_field(&entry.model_name, out)?;
        write_device_field(&entry.model_number, out)?; // wpawolf addition: WPS attr 0x1024
        write_device_field(&entry.serial_number, out)?;
        write_device_field(&entry.device_name, out)?;
        // OS Version: 4-byte big-endian uint32 rendered as 8 hex chars (or empty when absent).
        // [WSC §12 attr 0x102D]
        write_device_hex_field(entry.os_version.as_ref().map_or(&[][..], |v| v.as_slice()), out)?;
        // Primary Device Type: 8 bytes (category | OUI | sub-category) -> 16 hex chars.
        // [WSC §12 attr 0x1054]
        write_device_hex_field(entry.primary_device_type.as_ref().map_or(&[][..], |v| v.as_slice()), out)?;
        // Secondary Device Type List: concatenated 8-byte entries; empty when absent.
        // [WSC §12 attr 0x1055]
        write_device_hex_field(&entry.secondary_device_type_list, out)?;
        // UUID-E: written as raw hex (no $HEX[] wrapper), tab-prefixed, only if present.
        // The conditional tab is kept for back-compat with parsers built against the
        // pre-T-15.1 column set; new optional fields above always emit their tab.
        // [Wi-Fi Protected Setup spec attr 0x1047]
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
            model_number: b"R9K".to_vec(),
            serial_number: b"SN123".to_vec(),
            device_name: b"HomeAP".to_vec(),
            os_version: None,
            primary_device_type: None,
            secondary_device_type_list: vec![],
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
        // Column order: mac \t mfr \t model_name \t model_number \t serial \t
        //   dev_name \t os_ver \t prim_dt \t sec_dt_list \t uuid \t essid
        // make_entry leaves os_version / primary_device_type / sec_dt_list empty,
        // so columns 7-9 render as three empty cells (just tabs).
        assert!(text.starts_with("111111111111\t"), "MAC should be first field: {text:?}");
        assert!(text.contains("\tAcme\t"), "manufacturer field: {text:?}");
        // model_name then model_number then serial: triplet must appear in order.
        assert!(text.contains("\tRouter9000\tR9K\tSN123\t"), "model_name -> model_number -> serial sequence: {text:?}");
        // device_name then three empty new-column tabs then UUID then ESSID at the end.
        let uuid_hex = "ab".repeat(16);
        let tail = format!("\tHomeAP\t\t\t\t{uuid_hex}\tMyNet\n");
        assert!(text.ends_with(&tail), "device_name -> 3 empty WPS-extra tabs -> uuid -> essid tail: {text:?}");
    }

    #[test]
    fn write_device_info_uuid_absent() {
        let mut store = DeviceInfoStore::new();
        store.push(make_entry(0x22, None));
        let mut out = Vec::new();
        let count = write_device_info(&store, &mut out).unwrap();
        assert_eq!(count, 1);
        let text = std::str::from_utf8(&out).unwrap();
        // Column order with UUID absent:
        // mac \t mfr \t model_name \t model_number \t serial \t dev_name \t
        //   os_ver \t prim_dt \t sec_dt_list \t essid
        // device_name then three empty new-column tabs then ESSID directly (no uuid tab pair).
        assert!(text.ends_with("\tHomeAP\t\t\t\tMyNet\n"), "no UUID tab when absent: {text:?}");
    }

    #[test]
    fn write_device_info_emits_os_version_and_device_type_columns() {
        // OS Version + Primary Device Type set; Secondary Device Type List
        // empty. The row must show the populated binary fields as raw lowercase
        // hex (no $HEX[] wrapper) and the empty list as an empty cell.
        let mut store = DeviceInfoStore::new();
        let mut e = make_entry(0x33, None);
        e.os_version = Some([0x80, 0x00, 0x00, 0x10]);
        // Standard WFA Network Infrastructure / AP: category=6, OUI=00:50:F2:04, sub=1.
        e.primary_device_type = Some([0x00, 0x06, 0x00, 0x50, 0xF2, 0x04, 0x00, 0x01]);
        store.push(e);
        let mut out = Vec::new();
        write_device_info(&store, &mut out).unwrap();
        let text = std::str::from_utf8(&out).unwrap();
        assert!(text.contains("\t80000010\t"), "os_version rendered as raw hex: {text:?}");
        assert!(
            text.contains("\t000600 50f2040001".replace(' ', "").as_str()),
            "primary_device_type rendered as raw hex: {text:?}"
        );
        // Secondary list is empty, then ESSID closes the row.
        assert!(text.ends_with("\tMyNet\n"), "row ends with ESSID: {text:?}");
    }

    #[test]
    fn write_device_info_emits_secondary_device_type_list_column() {
        // Two-entry secondary list (16 bytes total). Renders as 32 hex chars
        // (concatenation of two 16-hex entries).
        let mut store = DeviceInfoStore::new();
        let mut e = make_entry(0x44, None);
        let mut list = vec![];
        list.extend_from_slice(&[0x00, 0x06, 0x00, 0x50, 0xF2, 0x04, 0x00, 0x01]);
        list.extend_from_slice(&[0x00, 0x07, 0x00, 0x50, 0xF2, 0x04, 0x00, 0x02]);
        e.secondary_device_type_list = list;
        store.push(e);
        let mut out = Vec::new();
        write_device_info(&store, &mut out).unwrap();
        let text = std::str::from_utf8(&out).unwrap();
        assert!(
            text.contains("\t000600 50f2040001 000700 50f2040002".replace(' ', "").as_str()),
            "secondary_device_type_list rendered as concatenated hex: {text:?}"
        );
    }

    #[test]
    fn write_device_info_emits_model_number_column() {
        // Two entries that share everything except model_number must produce two
        // distinct lines, and each line must carry its own model_number value.
        // Direct guard against accidentally dropping the column back to hcx parity.
        let mut store = DeviceInfoStore::new();
        let mut e1 = make_entry(0x11, None);
        e1.model_number = b"v1".to_vec();
        let mut e2 = make_entry(0x11, None);
        e2.model_number = b"v2".to_vec();
        store.push(e1);
        store.push(e2);
        let mut out = Vec::new();
        let count = write_device_info(&store, &mut out).unwrap();
        assert_eq!(count, 2, "differing model_number must render two lines");
        let text = std::str::from_utf8(&out).unwrap();
        assert!(text.contains("\tRouter9000\tv1\tSN123\t"), "v1 model_number rendered: {text:?}");
        assert!(text.contains("\tRouter9000\tv2\tSN123\t"), "v2 model_number rendered: {text:?}");
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
