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
