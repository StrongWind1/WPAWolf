//! Phase 1 -- Ingest: input format detection and reader dispatch. See ARCHITECTURE.md §3.1.
//!
//! Reads the first bytes of a file to identify whether it is a pcapng capture
//! (magic `0x0A0D0D0A`), a classic pcap (various magic numbers per libpcap), or a
//! gzip-compressed variant (magic `0x1F8B`), then returns the appropriate reader.
//! `ARCHITECTURE.md §3.1`.

pub mod gzip;
pub mod pcap;
pub mod pcapng;

use crate::types::Result;

// --- Allocation safety cap ---

/// Maximum packet data size we will allocate for a single capture record (1 MiB).
///
/// The largest legitimate 802.11 frame is ~7991 bytes (max A-MSDU in an MPDU).
/// With radiotap headers, FCS, and generous margin, nothing real exceeds 64 KiB.
/// 1 MiB is the paranoid backstop: large enough to never reject a real capture,
/// small enough that a malicious file claiming `incl_len = u32::MAX` cannot OOM
/// the process. Records exceeding this cap are skipped with a counter increment.
pub(crate) const MAX_PACKET_BYTES: usize = 1_048_576;

// --- Shared packet type ---

/// A single captured packet yielded by any reader type.
///
/// The `data` field contains raw frame bytes beginning at the link-layer header.
/// The link type (from `PacketReader::link_type`) determines the header format.
#[derive(Debug)]
pub struct Packet {
    /// Capture timestamp in microseconds since the Unix epoch.
    ///
    /// Nanosecond-resolution pcap files (`0xA1B23C4D` magic) are truncated to
    /// microseconds so all callers see a uniform unit.
    pub timestamp_us: u64,
    /// Zero-based interface index within the capture session.
    ///
    /// Always 0 in classic pcap; in pcapng it is the IDB position in the section.
    pub interface_id: u32,
    /// Raw frame data beginning at the link-layer header.
    pub data: Vec<u8>,
}

/// Byte order for a capture file or pcapng section, detected from the magic/BOM field.
///
/// Pcap files are byte-order-homogeneous. Pcapng files reset byte order per section
/// via the SHB BOM field. Per draft-ietf-opsawg-pcapng-05 §4.1.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ByteOrder {
    /// All multi-byte fields are little-endian.
    Little,
    /// All multi-byte fields are big-endian.
    Big,
}

impl ByteOrder {
    /// Decodes a 2-byte field in this byte order.
    pub(crate) const fn u16(self, b: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(b), // [pcapng §4] LE section
            Self::Big => u16::from_be_bytes(b),    // [pcapng §4] BE section
        }
    }

    /// Decodes a 4-byte unsigned field in this byte order.
    pub(crate) const fn u32(self, b: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(b),
            Self::Big => u32::from_be_bytes(b),
        }
    }

    /// Decodes an 8-byte signed field in this byte order.
    ///
    /// Used for `if_tsoffset` (IDB option 14), which is signed seconds.
    pub(crate) const fn i64(self, b: [u8; 8]) -> i64 {
        match self {
            Self::Little => i64::from_le_bytes(b),
            Self::Big => i64::from_be_bytes(b),
        }
    }
}

/// Human-readable metadata about the opened capture file.
///
/// Returned by `PacketReader::file_metadata()` to populate the stats summary header,
/// matching the first block of hcxpcapngtool's output.
#[derive(Debug, Clone)]
pub struct FileMetadata {
    /// Human-readable format string, e.g. `"pcap 2.4"` or `"pcapng 1.0"`.
    pub format: String,
    /// Endianness label, e.g. `"little endian"` or `"big endian"`.
    pub endian: &'static str,
    /// DLT value of the first (or only) interface.
    pub dlt: u16,
    /// Human-readable DLT name, e.g. `"DLT_IEEE802_11_RADIO (127)"`.
    pub dlt_desc: String,
}

/// Returns a human-readable DLT name for the most common 802.11 link types.
///
/// Matches the naming used by hcxpcapngtool and Wireshark.
/// [libpcap pcap/dlt.h]
#[must_use]
pub const fn dlt_name(dlt: u16) -> &'static str {
    match dlt {
        105 => "DLT_IEEE802_11",
        127 => "DLT_IEEE802_11_RADIO",
        119 => "DLT_PRISM_HEADER",
        163 => "DLT_IEEE802_11_RADIO_AVS",
        192 => "DLT_PPI",
        _ => "DLT_UNKNOWN",
    }
}

/// Unified interface for pcap, pcapng, and gzip-wrapped packet readers.
pub trait PacketReader {
    /// Returns the next captured packet, or `None` at end-of-file.
    ///
    /// Malformed blocks that can be skipped are handled internally; only hard I/O
    /// failures surface to the caller.
    ///
    /// # Errors
    ///
    /// Returns `Err` on I/O failure.
    fn next_packet(&mut self) -> Result<Option<Packet>>;

    /// Returns the DLT (Data Link Type) for the given interface index.
    ///
    /// `None` if `interface_id` was never registered. In classic pcap, only 0 is valid.
    fn link_type(&self, interface_id: u32) -> Option<u16>;

    /// Returns file metadata for display in the stats summary header.
    fn file_metadata(&self) -> FileMetadata;

    /// Returns a previously-owned packet data buffer for reuse by the next
    /// `next_packet` call, avoiding a heap allocation per packet.
    ///
    /// Callers should pass the `Packet::data` Vec back after processing each
    /// packet. Readers that support recycling keep the buffer's heap allocation
    /// alive and reuse it for the next read. Readers that do not override this
    /// method simply drop the buffer (no-op default).
    fn recycle_buffer(&mut self, _buf: Vec<u8>) {}
}

// --- Format detection and dispatch ---

use std::io::{Cursor, Read};
use std::path::Path;

use crate::types::Error;

// All ten pcap-family magic values as u32::from_le_bytes.
// [libpcap sf-pcap.c] -- detected by reading 4 bytes and comparing.
const MAGIC_PCAP_LE_US: u32 = 0xA1B2_C3D4; // little-endian microsecond
const MAGIC_PCAP_BE_US: u32 = 0xD4C3_B2A1; // big-endian microsecond
const MAGIC_PCAP_LE_NS: u32 = 0xA1B2_3C4D; // little-endian nanosecond
const MAGIC_PCAP_BE_NS: u32 = 0x4D3C_B2A1; // big-endian nanosecond
const MAGIC_PCAP_LE_KUZ: u32 = 0xA1B2_CD34; // little-endian Kuznetzov (24-byte pkt hdr)
const MAGIC_PCAP_BE_KUZ: u32 = 0x34CD_B2A1; // big-endian Kuznetzov
// IXIA `lcap` extends standard pcap with one trailing 4-byte field in the file
// header. Hardware-capture variants are nanosecond-resolution; software-capture
// variants are microsecond. [wireshark wiretap/libpcap.h, issue #14073]
const MAGIC_PCAP_LE_IXIAHW: u32 = 0x1C00_01AC; // little-endian IXIA HW (nanosecond)
const MAGIC_PCAP_BE_IXIAHW: u32 = 0xAC01_001C; // big-endian IXIA HW
const MAGIC_PCAP_LE_IXIASW: u32 = 0x1C00_01AB; // little-endian IXIA SW (microsecond)
const MAGIC_PCAP_BE_IXIASW: u32 = 0xAB01_001C; // big-endian IXIA SW

// Pcapng SHB magic -- a palindrome, byte-order-independent.
// [draft-ietf-opsawg-pcapng-05 §4.1]
const MAGIC_PCAPNG: [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A];

// Gzip ID bytes (RFC 1952 §2.3).
const GZIP_ID1: u8 = 0x1F;
const GZIP_ID2: u8 = 0x8B;

/// Detects the capture format from the first bytes of `reader` and returns the
/// appropriate packet reader.
///
/// Reads exactly 4 bytes from `reader` to identify the format:
/// - Pcapng (magic `0x0A0D0D0A`): those 4 bytes are prepended back before constructing
///   `PcapngReader`, which re-reads them as the SHB block type.
/// - Classic pcap (6 magic variants): those 4 bytes are passed separately to
///   `PcapReader::new`; `reader` is left positioned immediately after them.
///
/// Gzip is not re-detected here -- `gzip::open` calls this on the decompressed stream
/// and gzip-within-gzip is not supported.
pub(super) fn detect_format<R: Read + 'static>(mut reader: R) -> Result<Box<dyn PacketReader>> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::UnknownFormat("file too short to detect format (< 4 bytes)".to_owned())
        } else {
            Error::Io(e)
        }
    })?;

    // Pcapng: prepend the 4 magic bytes back so PcapngReader::new sees the full SHB.
    if magic == MAGIC_PCAPNG {
        let full = Cursor::new(magic).chain(reader);
        return Ok(Box::new(pcapng::PcapngReader::new(full)?));
    }

    // Classic pcap and IXIA `lcap`: magic goes to PcapReader separately; reader is positioned after it.
    let magic_u32 = u32::from_le_bytes(magic);
    match magic_u32 {
        MAGIC_PCAP_LE_US | MAGIC_PCAP_BE_US | MAGIC_PCAP_LE_NS | MAGIC_PCAP_BE_NS | MAGIC_PCAP_LE_KUZ
        | MAGIC_PCAP_BE_KUZ | MAGIC_PCAP_LE_IXIAHW | MAGIC_PCAP_BE_IXIAHW | MAGIC_PCAP_LE_IXIASW
        | MAGIC_PCAP_BE_IXIASW => Ok(Box::new(pcap::PcapReader::new(reader, magic)?)),

        _ => Err(Error::UnknownFormat(crate::types::bytes_to_hex_string(&magic))),
    }
}

/// Tests a 4-byte file prefix against every supported capture-file magic.
///
/// File-format identification is purely magic-byte-driven; file extensions are
/// never consulted. The accepted set, with citations:
///
/// | Format                      | On-disk bytes (LE writer / BE writer)   | Source                                   |
/// |-----------------------------|------------------------------------------|------------------------------------------|
/// | pcap, microsecond resolution | `D4 C3 B2 A1` / `A1 B2 C3 D4`           | libpcap `TCPDUMP_MAGIC` (`0xa1b2c3d4`)   |
/// | pcap, nanosecond resolution  | `4D 3C B2 A1` / `A1 B2 3C 4D`           | libpcap `NSEC_TCPDUMP_MAGIC` (`0xa1b23c4d`) |
/// | pcap, Kuznetzov 24-byte hdr  | `34 CD B2 A1` / `A1 B2 CD 34`           | libpcap `KUZNETZOV_TCPDUMP_MAGIC` (`0xa1b2cd34`) |
/// | IXIA `lcap` HW (nanosecond)  | `AC 01 00 1C` / `1C 00 01 AC`           | wireshark `PCAP_IXIAHW_MAGIC` (`0x1c0001ac`) |
/// | IXIA `lcap` SW (microsecond) | `AB 01 00 1C` / `1C 00 01 AB`           | wireshark `PCAP_IXIASW_MAGIC` (`0x1c0001ab`) |
/// | pcapng SHB block-type        | `0A 0D 0D 0A` (palindrome, BO-independent) | draft-ietf-opsawg-pcapng-05 §4.1       |
/// | gzip wrapper                 | `1F 8B` (first two bytes; CM/FLG follow)| RFC 1952 §2.3                           |
///
/// The pcap rows match libpcap's `pcap_check_header()` exactly (3 variants by 2
/// byte orders). The IXIA rows extend that set with wireshark's `lcap` variants:
/// otherwise standard pcap, but the file header carries one extra 4-byte field
/// after the usual 20-byte tail. Other libpcap-defined constants
/// (`FMESQUITA_TCPDUMP_MAGIC`, `NAVTEL_TCPDUMP_MAGIC`, `CBPF_SAVEFILE_MAGIC`) are
/// reserved/rejected by libpcap itself and are deliberately not accepted here.
#[must_use]
pub(crate) fn is_capture_magic(head: [u8; 4]) -> bool {
    // pcapng SHB block-type: byte-order-independent palindrome.
    // [draft-ietf-opsawg-pcapng-05] §4.1
    if head == MAGIC_PCAPNG {
        return true;
    }
    // gzip: ID1, ID2; remaining 2 bytes are CM and FLG and vary by file. [RFC 1952] §2.3
    if head[0] == GZIP_ID1 && head[1] == GZIP_ID2 {
        return true;
    }
    // pcap savefile + IXIA `lcap`: 10 magic variants total (5 magics x 2 byte orders).
    // [libpcap sf-pcap.c pcap_check_header()] + [wireshark wiretap/libpcap.c IXIA cases]
    let m = u32::from_le_bytes(head);
    matches!(
        m,
        MAGIC_PCAP_LE_US
            | MAGIC_PCAP_BE_US
            | MAGIC_PCAP_LE_NS
            | MAGIC_PCAP_BE_NS
            | MAGIC_PCAP_LE_KUZ
            | MAGIC_PCAP_BE_KUZ
            | MAGIC_PCAP_LE_IXIAHW
            | MAGIC_PCAP_BE_IXIAHW
            | MAGIC_PCAP_LE_IXIASW
            | MAGIC_PCAP_BE_IXIASW
    )
}

/// Returns `true` if `path` is a regular file whose first 4 bytes match a
/// supported capture-file magic. See `is_capture_magic` for the accepted set.
///
/// Errors (permission denied, file shorter than 4 bytes) yield `false` -- the
/// file is silently skipped during directory walks rather than aborting the
/// run, matching the "parse errors log-and-continue" pipeline policy.
fn has_capture_magic(path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 4];
    if file.read_exact(&mut head).is_err() {
        return false;
    }
    is_capture_magic(head)
}

/// Recursively collects capture files under `dir`, appending them to `out`.
///
/// Each candidate file's first 4 bytes are read and tested via
/// `has_capture_magic`; only files whose magic matches a supported capture
/// format are included. Extensions are never consulted -- a `.bin` named
/// pcap is picked up, a `.pcap` named JSON is not.
///
/// Symlinks are not followed (avoids cycles and surprise inclusion of files
/// outside the tree the operator pointed at). Within each directory, files
/// are sorted lexicographically and emitted before subdirectories are
/// descended -- this gives a deterministic traversal that does not depend
/// on filesystem iteration order. Entries that cannot be `stat`'d are
/// reported as warnings on stderr and skipped.
fn collect_capture_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    let mut subdirs: Vec<std::path::PathBuf> = Vec::new();

    let entries = std::fs::read_dir(dir).map_err(Error::Io)?;
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                println!("warning: cannot read entry in {}: {e}", dir.display());
                continue;
            },
        };
        let path = entry.path();
        // Use file_type() (does not follow symlinks) so cycles cannot loop us.
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(e) => {
                println!("warning: cannot stat {}: {e}", path.display());
                continue;
            },
        };
        if ft.is_dir() {
            subdirs.push(path);
        } else if ft.is_file() && has_capture_magic(&path) {
            files.push(path);
        }
    }

    files.sort();
    subdirs.sort();
    out.append(&mut files);
    for sub in subdirs {
        collect_capture_files(&sub, out)?;
    }
    Ok(())
}

/// Expands CLI input arguments into a flat list of capture file paths.
///
/// Each argument is one of:
/// - a regular file -- passed through unchanged. Magic is not checked here:
///   if the operator named the file explicitly, `open_reader` runs the same
///   magic-byte detection during Phase 1 and emits a warning for unrecognised
///   formats so the operator hears about typos.
/// - a directory -- walked recursively; files whose first 4 bytes match a
///   supported capture magic (see `is_capture_magic`) are collected in
///   deterministic order (sorted within each directory, files before
///   subdirectories). Filename extensions are ignored.
/// - missing / unreadable -- a warning is printed on stderr and the argument
///   is skipped, matching the existing per-file open-failure behaviour.
///
/// Symlinks are not followed during directory traversal.
///
/// # Errors
///
/// Returns `Err` only on I/O failures while reading a directory's contents.
/// Missing top-level paths and unreadable individual entries are warnings.
pub fn expand_inputs(inputs: &[std::path::PathBuf]) -> Result<Vec<std::path::PathBuf>> {
    let mut out: Vec<std::path::PathBuf> = Vec::new();
    for path in inputs {
        let meta = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                println!("warning: cannot stat {}: {e}", path.display());
                continue;
            },
        };
        if meta.is_dir() {
            collect_capture_files(path, &mut out)?;
        } else {
            // Regular file (or symlink to one): pass through verbatim. Don't filter by
            // extension -- an explicitly named argument has already been chosen by the
            // operator and may legitimately have a non-standard suffix.
            out.push(path.clone());
        }
    }
    Ok(out)
}

/// Opens a capture file at `path` and returns the appropriate packet reader.
///
/// Reads the first 4 bytes to detect the format:
/// - Gzip (`ID1=0x1F`, `ID2=0x8B`): the full file (with the 4 bytes prepended) is
///   passed to `gzip::open`, which wraps it in `GzDecoder` and detects the inner format.
/// - Everything else: delegated to `detect_format`, which identifies pcap or pcapng.
///
/// Returns `Err(Error::UnknownFormat(...))` for unrecognised magic bytes.
///
/// # Errors
///
/// Returns `Err` if the file cannot be opened or its format is unrecognised.
pub fn open_reader(path: &Path) -> Result<Box<dyn PacketReader>> {
    let mut file = std::fs::File::open(path)?;

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            Error::UnknownFormat("file too short to detect format (< 4 bytes)".to_owned())
        } else {
            Error::Io(e)
        }
    })?;

    // Gzip detection: RFC 1952 §2.3 -- first two bytes are ID1=0x1F, ID2=0x8B.
    // Prepend the 4 already-read bytes back so GzDecoder sees the complete gzip header.
    if magic[0] == GZIP_ID1 && magic[1] == GZIP_ID2 {
        let full = Cursor::new(magic).chain(file);
        return gzip::open(full);
    }

    // For pcap/pcapng: prepend the magic back and let detect_format read them.
    let restored = Cursor::new(magic).chain(file);
    detect_format(restored)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::cast_possible_truncation,
        missing_docs,
        clippy::wildcard_imports,
        reason = "test module"
    )]

    use std::io::Cursor;

    use super::*;

    /// Minimal LE-microsecond pcap blob: global header + one 4-byte packet.
    fn minimal_pcap_le() -> Vec<u8> {
        let mut v = Vec::new();
        // Global header
        v.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes()); // magic
        v.extend_from_slice(&2u16.to_le_bytes()); // version_major
        v.extend_from_slice(&4u16.to_le_bytes()); // version_minor
        v.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        v.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        v.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        v.extend_from_slice(&127u32.to_le_bytes()); // network = DLT_IEEE802_11_RADIO
        // Packet record
        v.extend_from_slice(&1u32.to_le_bytes()); // ts_sec
        v.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        v.extend_from_slice(&4u32.to_le_bytes()); // incl_len
        v.extend_from_slice(&4u32.to_le_bytes()); // orig_len
        v.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // data
        v
    }

    #[test]
    fn detect_format_pcap_le() {
        let blob = minimal_pcap_le();
        let mut reader = detect_format(Cursor::new(blob)).unwrap();
        let pkt = reader.next_packet().unwrap().unwrap();
        assert_eq!(pkt.timestamp_us, 1_000_000);
        assert_eq!(pkt.data, &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(reader.link_type(0), Some(127));
    }

    #[test]
    fn detect_format_unknown_magic() {
        let blob = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
        let result = detect_format(Cursor::new(blob));
        assert!(matches!(result, Err(Error::UnknownFormat(_))));
    }

    /// End-to-end IXIA `lcap` detection through `detect_format`: the dispatcher reads
    /// the 4 magic bytes, identifies an IXIA HW magic, hands construction to `PcapReader`,
    /// which then reads 20 bytes of standard tail plus 4 bytes of IXIA extra and parses
    /// one packet. Asserts that the IXIA-HW timestamp resolution (nanoseconds) is honored.
    #[test]
    fn detect_format_ixia_hardware_le() {
        let payload = [0xAA, 0xBB, 0xCC, 0xDD];
        let mut blob = Vec::new();
        // Magic (PCAP_IXIAHW_MAGIC, LE writer): bytes ac 01 00 1c.
        blob.extend_from_slice(&0x1C00_01ACu32.to_le_bytes());
        // Standard 20-byte tail, LE.
        blob.extend_from_slice(&2u16.to_le_bytes()); // version_major
        blob.extend_from_slice(&4u16.to_le_bytes()); // version_minor
        blob.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        blob.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        blob.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        blob.extend_from_slice(&127u32.to_le_bytes()); // network = DLT_IEEE802_11_RADIO
        // IXIA extra 4 bytes (informational; never inspected).
        blob.extend_from_slice(&0u32.to_le_bytes());
        // Single packet: ts_sec=3, ts_usec=750_000_000 ns -> 3.75 s.
        blob.extend_from_slice(&3u32.to_le_bytes());
        blob.extend_from_slice(&750_000_000u32.to_le_bytes());
        blob.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        blob.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        blob.extend_from_slice(&payload);

        let mut reader = detect_format(Cursor::new(blob)).unwrap();
        assert_eq!(reader.link_type(0), Some(127));
        let pkt = reader.next_packet().unwrap().unwrap();
        assert_eq!(pkt.timestamp_us, 3_000_000 + 750_000); // ns -> us truncation
        assert_eq!(pkt.data, payload);
        assert!(reader.next_packet().unwrap().is_none());

        let meta = reader.file_metadata();
        assert!(meta.format.starts_with("IXIA HW lcap"));
    }

    // --- expand_inputs / is_capture_magic tests ---

    // On-disk byte sequences for every supported capture magic, used to seed
    // test files. The `is_capture_magic` table doc-comment is the source of truth.
    const PCAP_LE_US_BYTES: [u8; 4] = [0xD4, 0xC3, 0xB2, 0xA1]; // TCPDUMP_MAGIC, LE writer
    const PCAP_BE_US_BYTES: [u8; 4] = [0xA1, 0xB2, 0xC3, 0xD4]; // TCPDUMP_MAGIC, BE writer
    const PCAP_LE_NS_BYTES: [u8; 4] = [0x4D, 0x3C, 0xB2, 0xA1]; // NSEC_TCPDUMP_MAGIC, LE writer
    const PCAP_BE_NS_BYTES: [u8; 4] = [0xA1, 0xB2, 0x3C, 0x4D]; // NSEC_TCPDUMP_MAGIC, BE writer
    const PCAP_LE_KUZ_BYTES: [u8; 4] = [0x34, 0xCD, 0xB2, 0xA1]; // KUZNETZOV_TCPDUMP_MAGIC, LE
    const PCAP_BE_KUZ_BYTES: [u8; 4] = [0xA1, 0xB2, 0xCD, 0x34]; // KUZNETZOV_TCPDUMP_MAGIC, BE
    const PCAPNG_BYTES: [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A]; // SHB block-type, palindrome
    const GZIP_BYTES: [u8; 4] = [0x1F, 0x8B, 0x08, 0x00]; // ID1 ID2 CM FLG (deflate, no flags)

    #[test]
    fn is_capture_magic_accepts_every_pcap_variant() {
        assert!(is_capture_magic(PCAP_LE_US_BYTES));
        assert!(is_capture_magic(PCAP_BE_US_BYTES));
        assert!(is_capture_magic(PCAP_LE_NS_BYTES));
        assert!(is_capture_magic(PCAP_BE_NS_BYTES));
        assert!(is_capture_magic(PCAP_LE_KUZ_BYTES));
        assert!(is_capture_magic(PCAP_BE_KUZ_BYTES));
    }

    #[test]
    fn is_capture_magic_accepts_pcapng_and_gzip() {
        assert!(is_capture_magic(PCAPNG_BYTES));
        assert!(is_capture_magic(GZIP_BYTES));
        // Different gzip CM/FLG values still match -- only the first two bytes are checked.
        assert!(is_capture_magic([0x1F, 0x8B, 0x00, 0xFF]));
    }

    #[test]
    fn is_capture_magic_rejects_unrelated_prefixes() {
        // Plaintext "TEST", a JPEG, and the libpcap-defined-but-rejected
        // FMESQUITA / NAVTEL / CBPF magics (we mirror libpcap's actual
        // check_header behaviour, not its full set of #defines).
        assert!(!is_capture_magic(*b"TEST"));
        assert!(!is_capture_magic([0xFF, 0xD8, 0xFF, 0xE0])); // JPEG SOI + APP0
        assert!(!is_capture_magic([0xCD, 0x34, 0xB2, 0xA1])); // FMESQUITA, LE writer
        assert!(!is_capture_magic([0x4D, 0x3C, 0x2B, 0xA1])); // NAVTEL, LE writer
        assert!(!is_capture_magic([0xCB, 0xC3, 0xB2, 0xA1])); // CBPF, LE writer
    }

    #[test]
    fn is_capture_magic_accepts_ixia_lcap_variants() {
        // Wireshark IXIA lcap magics: PCAP_IXIAHW (nanosecond) and PCAP_IXIASW
        // (microsecond), each in either byte order.
        assert!(is_capture_magic([0xAC, 0x01, 0x00, 0x1C])); // IXIA HW, LE writer
        assert!(is_capture_magic([0x1C, 0x00, 0x01, 0xAC])); // IXIA HW, BE writer
        assert!(is_capture_magic([0xAB, 0x01, 0x00, 0x1C])); // IXIA SW, LE writer
        assert!(is_capture_magic([0x1C, 0x00, 0x01, 0xAB])); // IXIA SW, BE writer
    }

    /// Helper: create a file at `path` with the given prefix bytes, creating parents as needed.
    fn write_with_prefix(path: &Path, prefix: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, prefix).unwrap();
    }

    #[test]
    fn expand_inputs_passes_through_regular_files_without_magic_check() {
        // Explicitly named files are passed through verbatim; magic is checked
        // later by open_reader. This lets the operator hear about typos.
        let tmp = std::env::temp_dir().join(format!("wpawolf_expand_pass_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let pcap_named = tmp.join("real.pcap");
        let bogus_named = tmp.join("garbage.bin"); // not a capture, but explicit
        write_with_prefix(&pcap_named, &PCAP_LE_US_BYTES);
        write_with_prefix(&bogus_named, b"NOT_A_CAP");

        let out = expand_inputs(&[pcap_named.clone(), bogus_named.clone()]).unwrap();
        assert_eq!(out, vec![pcap_named, bogus_named]);

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn expand_inputs_filters_directory_contents_by_magic_bytes_not_extension() {
        let tmp = std::env::temp_dir().join(format!("wpawolf_expand_magic_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        // Layout exercising the magic check independent of filename:
        //   tmp/captureA.bin     valid pcap content, non-capture-looking name -- INCLUDED
        //   tmp/notes.pcap       text content, capture-looking name           -- SKIPPED
        //   tmp/empty.pcap       0 bytes, capture-looking name                -- SKIPPED
        //   tmp/loc1/01          pcapng content, no extension at all          -- INCLUDED
        //   tmp/loc1/02.txt      gzip content, txt extension                  -- INCLUDED
        //   tmp/loc2/sub/9.cap   nanosecond pcap                              -- INCLUDED
        //   tmp/loc2/sub/x.pcap  Kuznetzov pcap                               -- INCLUDED
        let bin_pcap = tmp.join("captureA.bin");
        let fake_pcap = tmp.join("notes.pcap");
        let empty_pcap = tmp.join("empty.pcap");
        let no_ext_pcapng = tmp.join("loc1/01");
        let gz_as_txt = tmp.join("loc1/02.txt");
        let ns_pcap = tmp.join("loc2/sub/9.cap");
        let kuz_pcap = tmp.join("loc2/sub/x.pcap");

        write_with_prefix(&bin_pcap, &PCAP_LE_US_BYTES);
        write_with_prefix(&fake_pcap, b"This file is not actually a pcap");
        write_with_prefix(&empty_pcap, b"");
        write_with_prefix(&no_ext_pcapng, &PCAPNG_BYTES);
        write_with_prefix(&gz_as_txt, &GZIP_BYTES);
        write_with_prefix(&ns_pcap, &PCAP_BE_NS_BYTES);
        write_with_prefix(&kuz_pcap, &PCAP_LE_KUZ_BYTES);

        let out = expand_inputs(std::slice::from_ref(&tmp)).unwrap();

        // Within each directory: files sorted, then subdirectories descended in sorted order.
        // notes.pcap and empty.pcap are filtered by the magic check.
        assert_eq!(out, vec![bin_pcap, no_ext_pcapng, gz_as_txt, ns_pcap, kuz_pcap]);

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn expand_inputs_mixes_files_and_dirs_in_argument_order() {
        let tmp = std::env::temp_dir().join(format!("wpawolf_expand_mix_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let standalone = tmp.join("standalone.pcap");
        let dir = tmp.join("d");
        let inside = dir.join("inside.pcap");
        write_with_prefix(&standalone, &PCAP_LE_US_BYTES);
        write_with_prefix(&inside, &PCAP_LE_US_BYTES);

        // Argument order is preserved: standalone file first, then dir contents.
        let out = expand_inputs(&[standalone.clone(), dir]).unwrap();
        assert_eq!(out, vec![standalone, inside]);

        std::fs::remove_dir_all(&tmp).unwrap();
    }

    #[test]
    fn expand_inputs_warns_and_skips_missing_paths() {
        let missing = std::path::PathBuf::from("/nonexistent/wpawolf/should-not-exist");
        let out = expand_inputs(&[missing]).unwrap();
        assert!(out.is_empty());
    }
}
