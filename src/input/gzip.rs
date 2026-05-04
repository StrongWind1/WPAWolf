//! Phase 1 -- Ingest: transparent gzip-decompression wrapper. See ARCHITECTURE.md §3.1.
//!
//! Wraps `flate2::read::GzDecoder` around any `Read` source and delegates format
//! detection to the parent module. The inner format (pcap or pcapng) is auto-detected
//! from the decompressed byte stream, making gzip handling transparent to callers.
//! Per IETF RFC 1952 §2 -- ID1=`0x1F`, ID2=`0x8B`.

use std::io::Read;

use flate2::read::GzDecoder;

use crate::types::Result;

use super::PacketReader;

/// Opens a gzip-compressed capture stream and returns a reader for the inner format.
///
/// `inner` must be positioned at byte 0 of the gzip stream so `GzDecoder` can parse
/// the gzip header. The decompressed output is passed to `super::detect_format`,
/// which identifies pcap vs pcapng and constructs the appropriate reader.
///
/// All deflate compression variants supported by `flate2` are handled transparently.
///
/// # Errors
///
/// Returns `Err` on I/O failure.
pub fn open<R: Read + 'static>(inner: R) -> Result<Box<dyn PacketReader>> {
    // GzDecoder::new parses the gzip header eagerly and decompresses on each read.
    // [RFC 1952 §2.3] gzip header: ID1 0x1F, ID2 0x8B, compression method 8 (deflate).
    let gz = GzDecoder::new(inner);
    super::detect_format(gz)
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

    use std::io::{Cursor, Write as _};

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    /// Minimal libpcap microsecond-magic header followed by zero packet records.
    /// `0xA1B2C3D4` little-endian, version 2.4, 4 bytes of timezone+sigfigs+snaplen+linktype each.
    fn empty_pcap_bytes() -> Vec<u8> {
        let mut hdr = Vec::with_capacity(24);
        hdr.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes()); // magic
        hdr.extend_from_slice(&2u16.to_le_bytes()); // major
        hdr.extend_from_slice(&4u16.to_le_bytes()); // minor
        hdr.extend_from_slice(&0u32.to_le_bytes()); // thiszone
        hdr.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        hdr.extend_from_slice(&65_535u32.to_le_bytes()); // snaplen
        hdr.extend_from_slice(&127u32.to_le_bytes()); // linktype radiotap
        hdr
    }

    fn gzip(payload: &[u8]) -> Vec<u8> {
        let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
        enc.write_all(payload).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn open_accepts_gzip_wrapped_pcap_header() {
        // Round-trip: gzip -> open() -> reader of the inner pcap. The inner format
        // detection path runs against the decompressed bytes, so a valid pcap
        // header inside the gzip stream produces a working reader (zero packets,
        // but no error).
        let bytes = gzip(&empty_pcap_bytes());
        let reader = open(Cursor::new(bytes));
        assert!(reader.is_ok(), "valid gzip-wrapped pcap header must produce a reader");
    }

    #[test]
    fn open_rejects_non_gzip_payload() {
        // Cursor over plain (un-gzipped) bytes: the gzip header parse fails with
        // an `Io` error. We only assert `is_err`; the specific kind depends on
        // `flate2` version and is not part of our contract.
        let plain = b"not a gzip stream at all".to_vec();
        let reader = open(Cursor::new(plain));
        assert!(reader.is_err(), "non-gzip input must surface an error");
    }

    #[test]
    fn open_rejects_gzip_wrapping_garbage_inner_format() {
        // A valid gzip stream wrapping bytes that are neither pcap nor pcapng
        // must be rejected by `detect_format`, not silently accepted.
        let inner_garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
        let bytes = gzip(&inner_garbage);
        let reader = open(Cursor::new(bytes));
        assert!(reader.is_err(), "gzip-wrapped non-pcap bytes must error at format detection");
    }
}
