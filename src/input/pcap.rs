//! Phase 1 -- Ingest: classic pcap (all 10 magic variants) parser. See ARCHITECTURE.md §3.1 + §8.1.
//!
//! Handles ten magic number variants: standard microsecond LE/BE (`0xA1B2C3D4` /
//! `0xD4C3B2A1`), nanosecond LE/BE (`0xA1B23C4D` / `0x4D3CB2A1`), Kuznetzov-patched
//! microsecond LE/BE (`0xA1B2CD34` / `0x34CDB2A1`, which uses 24-byte packet headers),
//! and IXIA `lcap` hardware-capture LE/BE (`0x1C0001AC` / `0xAC01001C`, nanosecond)
//! and software-capture LE/BE (`0x1C0001AB` / `0xAB01001C`, microsecond). The IXIA
//! variants extend the standard pcap file header with one trailing 4-byte field
//! holding the total packet-record size; aside from that, records are standard pcap.
//! Per libpcap `pcap/pcap.h`, `sf-pcap.c`, and wireshark `wiretap/libpcap.c`.

use std::io::{BufReader, Read};

use crate::types::{Error, Result};

use super::{ByteOrder, FileMetadata, Packet, PacketReader, dlt_name};

// --- Magic number constants ---

/// Standard microsecond LE magic. [libpcap sf-pcap.c, `TCPDUMP_MAGIC`]
const MAGIC_LE_US: u32 = 0xA1B2_C3D4;
/// Standard microsecond BE magic (byte-swapped form of `MAGIC_LE_US`). [libpcap sf-pcap.c]
const MAGIC_BE_US: u32 = 0xD4C3_B2A1;
/// Nanosecond LE magic. [libpcap sf-pcap.c, `NSEC_TCPDUMP_MAGIC`]
const MAGIC_LE_NS: u32 = 0xA1B2_3C4D;
/// Nanosecond BE magic (byte-swapped form of `MAGIC_LE_NS`). [libpcap sf-pcap.c]
const MAGIC_BE_NS: u32 = 0x4D3C_B2A1;
/// Kuznetzov LE magic -- 24-byte packet headers. [libpcap sf-pcap.c:71-99]
const MAGIC_LE_KUZ: u32 = 0xA1B2_CD34;
/// Kuznetzov BE magic (byte-swapped form of `MAGIC_LE_KUZ`). [libpcap sf-pcap.c:71-99]
const MAGIC_BE_KUZ: u32 = 0x34CD_B2A1;
/// IXIA hardware-capture `lcap` LE magic, nanosecond timestamps.
///
/// Otherwise standard pcap, but the file header carries an extra 4-byte field after
/// the usual 20-byte tail. That field holds the total packet-record size (file size
/// minus header size); we skip it.
/// [wireshark wiretap/libpcap.h `PCAP_IXIAHW_MAGIC`, issue #14073]
const MAGIC_LE_IXIAHW: u32 = 0x1C00_01AC;
/// IXIA hardware-capture `lcap` BE magic (byte-swapped form of `MAGIC_LE_IXIAHW`).
/// [wireshark wiretap/libpcap.h `PCAP_SWAPPED_IXIAHW_MAGIC`]
const MAGIC_BE_IXIAHW: u32 = 0xAC01_001C;
/// IXIA software-capture `lcap` LE magic, microsecond timestamps.
///
/// Same 4-byte file-header extension as `MAGIC_LE_IXIAHW`; only the timestamp
/// resolution differs. [wireshark wiretap/libpcap.h `PCAP_IXIASW_MAGIC`]
const MAGIC_LE_IXIASW: u32 = 0x1C00_01AB;
/// IXIA software-capture `lcap` BE magic (byte-swapped form of `MAGIC_LE_IXIASW`).
/// [wireshark wiretap/libpcap.h `PCAP_SWAPPED_IXIASW_MAGIC`]
const MAGIC_BE_IXIASW: u32 = 0xAB01_001C;

/// Global header length excluding the 4-byte magic: 20 bytes.
///
/// `version_major`(2) + `version_minor`(2) + thiszone(4) + sigfigs(4) + snaplen(4) + network(4).
/// [libpcap pcap/pcap.h struct `pcap_file_header`]
const GLOBAL_HDR_TAIL: usize = 20;

/// Length of the IXIA `lcap` extra file-header field appended after the standard
/// 20-byte global-header tail. Holds the total packet-record byte count and is
/// purely informational for our purposes -- we read and discard it.
/// [wireshark wiretap/libpcap.c, issue #14073]
const IXIA_EXTRA_HDR_LEN: usize = 4;

/// Standard packet record header length. [libpcap pcap/pcap.h struct `pcap_pkthdr`]
const PKT_HDR_LEN: usize = 16;

/// Extra bytes in the Kuznetzov packet record beyond the standard 16-byte header.
///
/// Bytes 17-24: index(4) + protocol(2) + `pkt_type`(1) + pad(1). [libpcap sf-pcap.c:167-174]
const KUZ_EXTRA_LEN: usize = 8;

// --- Reader ---

/// IXIA `lcap` sub-variant detected from the magic, used purely for `file_metadata`
/// labelling -- the parsing path is identical aside from skipping the 4-byte file-header
/// extension once during construction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum IxiaVariant {
    /// Hardware-capture variant (`PCAP_IXIAHW_MAGIC`); timestamps are nanoseconds.
    Hardware,
    /// Software-capture variant (`PCAP_IXIASW_MAGIC`); timestamps are microseconds.
    Software,
}

/// Classic pcap file reader supporting all ten magic number variants (standard /
/// nanosecond / Kuznetzov / IXIA-HW / IXIA-SW, each LE and BE).
///
/// Constructed via `PcapReader::new`; thereafter `PacketReader::next_packet` yields
/// one frame per call until EOF. In classic pcap there is a single interface (id 0)
/// with the DLT from the global header; `link_type(0)` returns that DLT.
#[derive(Debug)]
pub struct PcapReader<R: Read> {
    reader: BufReader<R>,
    byte_order: ByteOrder,
    /// DLT value from the global header (low 16 bits of the `network` field).
    ///
    /// `network & 0xFFFF` strips the upper 16 bits that some tools set to
    /// non-zero values for vendor extensions. [libpcap pcap/pcap.h]
    dlt: u16,
    /// True if timestamps are nanosecond resolution (NSEC and IXIA-HW magic variants).
    ///
    /// When true, `ts_usec` fields hold nanoseconds and are divided by 1 000 to
    /// produce the microsecond-resolution `timestamp_us` exposed to callers.
    nanosecond: bool,
    /// True if packet headers are 24 bytes (Kuznetzov patched format).
    ///
    /// When true, 8 extra bytes (index, protocol, `pkt_type`, pad) are consumed
    /// and discarded after the standard 16-byte header. [libpcap sf-pcap.c:167-174]
    kuznetzov: bool,
    /// `Some` if the file is an IXIA `lcap` variant. Captured for `file_metadata`
    /// labelling only -- the 4-byte file-header extension is read and discarded
    /// in `new()` so per-packet parsing is unaffected.
    ixia: Option<IxiaVariant>,
    /// pcap global header `version_major`. [libpcap pcap/pcap.h]
    version_major: u16,
    /// pcap global header `version_minor`. [libpcap pcap/pcap.h]
    version_minor: u16,
}

impl<R: Read> PcapReader<R> {
    /// Parses the global header and constructs a reader ready to yield packets.
    ///
    /// `magic_bytes` is the already-read first 4 bytes of the file. The caller
    /// (format dispatcher in `input/mod.rs`) reads them for format detection and
    /// passes them here so the global header can be completed without seeking.
    ///
    /// Returns `Error::UnknownFormat` if the magic does not match any of the six
    /// known variants. Returns `Error::Io` or `Error::Truncated` on read failure.
    /// # Errors
    ///
    /// Returns `Err` if the magic bytes are unrecognised, or reading the global header fails.
    pub fn new(inner: R, magic_bytes: [u8; 4]) -> Result<Self> {
        // Detect byte order, nanosecond flag, and Kuznetzov flag from the raw magic.
        // The 4 bytes are interpreted as a LE u32 and compared to the six known constants.
        // This works because each constant is unique in both its LE and BE representation.
        let magic = u32::from_le_bytes(magic_bytes); // treat raw bytes as LE u32 for comparison
        // IXIA-HW behaves as a nanosecond pcap; IXIA-SW behaves as a microsecond pcap.
        // Both add a 4-byte file-header extension we read and discard below.
        // [wireshark wiretap/libpcap.c]
        let (byte_order, nanosecond, kuznetzov, ixia) = match magic {
            MAGIC_LE_US => (ByteOrder::Little, false, false, None),
            MAGIC_BE_US => (ByteOrder::Big, false, false, None),
            MAGIC_LE_NS => (ByteOrder::Little, true, false, None),
            MAGIC_BE_NS => (ByteOrder::Big, true, false, None),
            MAGIC_LE_KUZ => (ByteOrder::Little, false, true, None),
            MAGIC_BE_KUZ => (ByteOrder::Big, false, true, None),
            MAGIC_LE_IXIAHW => (ByteOrder::Little, true, false, Some(IxiaVariant::Hardware)),
            MAGIC_BE_IXIAHW => (ByteOrder::Big, true, false, Some(IxiaVariant::Hardware)),
            MAGIC_LE_IXIASW => (ByteOrder::Little, false, false, Some(IxiaVariant::Software)),
            MAGIC_BE_IXIASW => (ByteOrder::Big, false, false, Some(IxiaVariant::Software)),
            _ => {
                return Err(Error::UnknownFormat(format!(
                    "{:02x}{:02x}{:02x}{:02x}",
                    magic_bytes[0], magic_bytes[1], magic_bytes[2], magic_bytes[3]
                )));
            },
        };

        let mut reader = BufReader::new(inner);

        // Read the remaining 20 bytes of the global header.
        // Layout: version_major(2) version_minor(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
        // [libpcap pcap/pcap.h struct pcap_file_header]
        let mut tail = [0u8; GLOBAL_HDR_TAIL];
        reader.read_exact(&mut tail).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::Truncated { context: "pcap global header", needed: GLOBAL_HDR_TAIL, got: 0 }
            } else {
                Error::Io(e)
            }
        })?;

        // version_major[0..2], version_minor[2..4], thiszone[4..8], sigfigs[8..12] -- ignored
        // for stream positioning but stored for metadata display.
        let version_major = byte_order.u16(tail.get(0..2).and_then(|s| s.try_into().ok()).unwrap_or([0u8; 2]));
        let version_minor = byte_order.u16(tail.get(2..4).and_then(|s| s.try_into().ok()).unwrap_or([0u8; 2]));
        // snaplen[12..16] -- ignored (we read exactly incl_len bytes from each record).
        // network[16..20] -- DLT value; we take only the low 16 bits. [libpcap pcap/pcap.h]
        let network_bytes: [u8; 4] = tail.get(16..20).and_then(|s| s.try_into().ok()).ok_or(Error::Truncated {
            context: "pcap global header network field",
            needed: 20,
            got: 16,
        })?;
        let dlt = (byte_order.u32(network_bytes) & 0xFFFF) as u16;

        // IXIA `lcap` variants append a 4-byte total-record-size field after the
        // standard 20-byte header tail. The value is informational; we read it to
        // advance the stream to the first packet record and otherwise discard it.
        // [wireshark wiretap/libpcap.c, issue #14073]
        if ixia.is_some() {
            let mut extra = [0u8; IXIA_EXTRA_HDR_LEN];
            reader.read_exact(&mut extra).map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    Error::Truncated {
                        context: "pcap IXIA lcap extra header field",
                        needed: IXIA_EXTRA_HDR_LEN,
                        got: 0,
                    }
                } else {
                    Error::Io(e)
                }
            })?;
        }

        Ok(Self { reader, byte_order, dlt, nanosecond, kuznetzov, ixia, version_major, version_minor })
    }
}

impl<R: Read> PacketReader for PcapReader<R> {
    /// Reads the next packet record and returns it, or `Ok(None)` at EOF.
    ///
    /// Standard packet records are 16 bytes; Kuznetzov records are 24 bytes.
    /// Nanosecond timestamps are truncated to microsecond precision (integer divide by 1 000).
    /// Interface id is always 0 -- classic pcap has exactly one interface.
    #[allow(clippy::similar_names, reason = "ts_sec/ts_usec are pcap protocol-standard field names")]
    fn next_packet(&mut self) -> Result<Option<Packet>> {
        // --- Read the 16-byte packet record header ---
        let mut hdr = [0u8; PKT_HDR_LEN];
        match self.reader.read_exact(&mut hdr) {
            Ok(()) => {},
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }

        // ts_sec[0..4], ts_usec[4..8], incl_len[8..12], orig_len[12..16]
        // [libpcap pcap/pcap.h struct pcap_pkthdr]
        let ts_sec_bytes: [u8; 4] = hdr.get(0..4).and_then(|s| s.try_into().ok()).ok_or(Error::Truncated {
            context: "pcap packet header ts_sec",
            needed: 4,
            got: 0,
        })?;
        let ts_usec_bytes: [u8; 4] = hdr.get(4..8).and_then(|s| s.try_into().ok()).ok_or(Error::Truncated {
            context: "pcap packet header ts_usec",
            needed: 8,
            got: 4,
        })?;
        let incl_len_bytes: [u8; 4] = hdr.get(8..12).and_then(|s| s.try_into().ok()).ok_or(Error::Truncated {
            context: "pcap packet header incl_len",
            needed: 12,
            got: 8,
        })?;
        // orig_len bytes[12..16] are parsed but not used; incl_len is what was captured.

        let ts_sec = self.byte_order.u32(ts_sec_bytes);
        let ts_usec = self.byte_order.u32(ts_usec_bytes);
        let incl_len = self.byte_order.u32(incl_len_bytes);

        // --- Consume Kuznetzov extra bytes (index, protocol, pkt_type, pad) ---
        // [libpcap sf-pcap.c:167-174] The 8 bytes after orig_len are discarded.
        if self.kuznetzov {
            let mut kuz = [0u8; KUZ_EXTRA_LEN];
            self.reader.read_exact(&mut kuz).map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    Error::Truncated { context: "pcap Kuznetzov extra header", needed: KUZ_EXTRA_LEN, got: 0 }
                } else {
                    Error::Io(e)
                }
            })?;
        }

        // --- Read packet data ---
        let caplen = incl_len as usize;
        if caplen > super::MAX_PACKET_BYTES {
            // Skip this record: consume caplen bytes from the stream so the next
            // record header is at the correct offset, then recurse to the next packet.
            std::io::copy(&mut (&mut self.reader).take(incl_len.into()), &mut std::io::sink())?;
            return self.next_packet();
        }
        let mut data = vec![0u8; caplen];
        self.reader.read_exact(&mut data).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::Truncated { context: "pcap packet data", needed: caplen, got: 0 }
            } else {
                Error::Io(e)
            }
        })?;

        // --- Compute timestamp in microseconds ---
        // Standard/Kuznetzov: ts_usec is already microseconds.
        // Nanosecond: ts_usec is nanoseconds; divide by 1 000 (integer, truncating).
        // [libpcap sf-pcap.c, pcap_next_ex(3pcap)]
        let timestamp_us = if self.nanosecond {
            u64::from(ts_sec) * 1_000_000 + u64::from(ts_usec) / 1_000
        } else {
            u64::from(ts_sec) * 1_000_000 + u64::from(ts_usec)
        };

        Ok(Some(Packet { timestamp_us, interface_id: 0, data }))
    }

    /// Returns the DLT for the given interface id.
    ///
    /// Classic pcap has exactly one interface (id 0) with the DLT from the global
    /// header. Any other id returns `None`.
    fn link_type(&self, interface_id: u32) -> Option<u16> {
        if interface_id == 0 { Some(self.dlt) } else { None }
    }

    fn file_metadata(&self) -> FileMetadata {
        let endian = if self.byte_order == ByteOrder::Little { "little endian" } else { "big endian" };
        let kind = match self.ixia {
            Some(IxiaVariant::Hardware) => "IXIA HW lcap",
            Some(IxiaVariant::Software) => "IXIA SW lcap",
            None if self.kuznetzov => "Kuznetzov patched pcap",
            None => "pcap",
        };
        FileMetadata {
            format: format!("{} {}.{}", kind, self.version_major, self.version_minor),
            endian,
            dlt: self.dlt,
            dlt_desc: format!("{} ({})", dlt_name(self.dlt), self.dlt),
        }
    }
}

// --- Unit tests ---

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::similar_names,
        missing_docs,
        clippy::wildcard_imports,
        reason = "test module -- ts_sec/ts_usec are pcap protocol-standard field names"
    )]

    use std::io::Cursor;

    use super::*;

    // --- Helpers ---

    /// Builds the byte content passed to `PcapReader::new` as `inner`.
    ///
    /// The real format dispatcher reads the 4-byte magic from the file, then passes
    /// the same reader (now positioned after the magic) to `PcapReader::new`. So
    /// `inner` starts with the global header *tail* (20 bytes after the magic) followed
    /// by packet records. The magic is passed separately as `magic_bytes`.
    ///
    /// All multi-byte fields are LE, consistent with LE magic constants.
    fn build_inner_le(ts_sec: u32, ts_usec: u32, payload: &[u8], kuznetzov: bool) -> Vec<u8> {
        let mut v = Vec::new();
        // Global header tail: version_major(2) version_minor(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
        v.extend_from_slice(&2u16.to_le_bytes()); // version_major = 2
        v.extend_from_slice(&4u16.to_le_bytes()); // version_minor = 4
        v.extend_from_slice(&0i32.to_le_bytes()); // thiszone = 0
        v.extend_from_slice(&0u32.to_le_bytes()); // sigfigs = 0
        v.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        v.extend_from_slice(&105u32.to_le_bytes()); // network = DLT_IEEE802_11 (105)
        // Packet record header: ts_sec(4) ts_usec(4) incl_len(4) orig_len(4)
        v.extend_from_slice(&ts_sec.to_le_bytes());
        v.extend_from_slice(&ts_usec.to_le_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        if kuznetzov {
            // Extra Kuznetzov bytes: index(4) + protocol(2) + pkt_type(1) + pad(1)
            v.extend_from_slice(&[0u8; 8]);
        }
        v.extend_from_slice(payload);
        v
    }

    /// Same as `build_inner_le` but all multi-byte fields are BE, for BE magic tests.
    fn build_inner_be(ts_sec: u32, ts_usec: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&2u16.to_be_bytes());
        v.extend_from_slice(&4u16.to_be_bytes());
        v.extend_from_slice(&0i32.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&65535u32.to_be_bytes());
        v.extend_from_slice(&105u32.to_be_bytes());
        v.extend_from_slice(&ts_sec.to_be_bytes());
        v.extend_from_slice(&ts_usec.to_be_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    // --- Test 1: LE microsecond pcap ---

    #[test]
    fn le_microsecond_single_packet() {
        let payload = b"hello pcap";
        // inner is positioned after the magic, so pass only the tail + packet data.
        let inner = build_inner_le(1_700_000_000, 500_000, payload, false);
        let mut r = PcapReader::new(Cursor::new(inner), MAGIC_LE_US.to_le_bytes()).unwrap();

        assert_eq!(r.link_type(0), Some(105));
        assert_eq!(r.link_type(1), None);

        let pkt = r.next_packet().unwrap().unwrap();
        assert_eq!(pkt.timestamp_us, 1_700_000_000 * 1_000_000 + 500_000);
        assert_eq!(pkt.interface_id, 0);
        assert_eq!(pkt.data, payload);

        // No more packets.
        assert!(r.next_packet().unwrap().is_none());
    }

    // --- Test 2: BE microsecond pcap ---

    #[test]
    fn be_microsecond_single_packet() {
        let payload = b"big endian";
        let inner = build_inner_be(1_000, 250, payload);
        let mut r = PcapReader::new(Cursor::new(inner), MAGIC_BE_US.to_le_bytes()).unwrap();

        assert_eq!(r.link_type(0), Some(105));

        let pkt = r.next_packet().unwrap().unwrap();
        // Verify byte order was detected correctly: ts = 1_000 * 1_000_000 + 250
        assert_eq!(pkt.timestamp_us, 1_000 * 1_000_000 + 250);
        assert_eq!(pkt.data, payload);
    }

    // --- Test 3: Nanosecond timestamp truncation ---

    #[test]
    fn nanosecond_timestamp_truncation() {
        // 1_999_999_999 ns -> 1_999_999 us (integer division, sub-us part dropped)
        let payload = b"ns";
        let inner = build_inner_le(1, 1_999_999_999, payload, false);
        let mut r = PcapReader::new(Cursor::new(inner), MAGIC_LE_NS.to_le_bytes()).unwrap();

        let pkt = r.next_packet().unwrap().unwrap();
        // ts_sec=1, ts_usec=1_999_999_999 ns -> ts_sec*1_000_000 + ns/1_000 = 1_000_000 + 1_999_999
        assert_eq!(pkt.timestamp_us, 1_000_000 + 1_999_999);
    }

    // --- Test 4: Kuznetzov 24-byte packet header ---

    #[test]
    fn kuznetzov_packet_header_consumed() {
        let payload = b"kuz frame";
        let inner = build_inner_le(42, 0, payload, true);
        let mut r = PcapReader::new(Cursor::new(inner), MAGIC_LE_KUZ.to_le_bytes()).unwrap();

        let pkt = r.next_packet().unwrap().unwrap();
        assert_eq!(pkt.timestamp_us, 42 * 1_000_000);
        assert_eq!(pkt.data, payload);

        // EOF after single packet -- confirms the 8 extra Kuznetzov bytes were consumed.
        assert!(r.next_packet().unwrap().is_none());
    }

    // --- Test 5: EOF with no packets ---

    #[test]
    fn empty_pcap_returns_none() {
        // Build only the global header tail with no packet records following it.
        let mut inner = Vec::new();
        inner.extend_from_slice(&2u16.to_le_bytes()); // version_major
        inner.extend_from_slice(&4u16.to_le_bytes()); // version_minor
        inner.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        inner.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        inner.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        inner.extend_from_slice(&1u32.to_le_bytes()); // network = DLT_EN10MB

        let mut r = PcapReader::new(Cursor::new(inner), MAGIC_LE_US.to_le_bytes()).unwrap();
        assert!(r.next_packet().unwrap().is_none());
    }

    // --- Test 6: Unknown magic ---

    #[test]
    fn unknown_magic_returns_error() {
        let bad_magic = [0xDE, 0xAD, 0xBE, 0xEF];
        // inner content doesn't matter -- magic is rejected before reading it.
        let result = PcapReader::new(Cursor::new(Vec::<u8>::new()), bad_magic);
        assert!(matches!(result, Err(Error::UnknownFormat(_))));
    }

    // --- IXIA `lcap` variants ---

    /// Like `build_inner_le` but inserts a 4-byte IXIA `lcap` extra field between the
    /// 20-byte global-header tail and the first packet record. The extra field's
    /// content doesn't matter for parsing; we use a recognisable sentinel.
    fn build_inner_le_ixia(ts_sec: u32, ts_usec: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        // Global header tail (20 bytes).
        v.extend_from_slice(&2u16.to_le_bytes()); // version_major
        v.extend_from_slice(&4u16.to_le_bytes()); // version_minor
        v.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        v.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        v.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        v.extend_from_slice(&105u32.to_le_bytes()); // network = DLT_IEEE802_11 (105)
        // IXIA extra: 4-byte total-records-size field. Sentinel value, never inspected.
        v.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        // Packet record header.
        v.extend_from_slice(&ts_sec.to_le_bytes());
        v.extend_from_slice(&ts_usec.to_le_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// BE variant of `build_inner_le_ixia`.
    fn build_inner_be_ixia(ts_sec: u32, ts_usec: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&2u16.to_be_bytes());
        v.extend_from_slice(&4u16.to_be_bytes());
        v.extend_from_slice(&0i32.to_be_bytes());
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&65535u32.to_be_bytes());
        v.extend_from_slice(&105u32.to_be_bytes());
        v.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // IXIA extra
        v.extend_from_slice(&ts_sec.to_be_bytes());
        v.extend_from_slice(&ts_usec.to_be_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn ixia_hardware_le_nanosecond() {
        // IXIA-HW = nanosecond resolution. ts_usec field actually carries nanoseconds.
        let payload = b"ixia hw le";
        let inner = build_inner_le_ixia(7, 1_500_000_000, payload);
        let mut r = PcapReader::new(Cursor::new(inner), MAGIC_LE_IXIAHW.to_le_bytes()).unwrap();

        assert_eq!(r.link_type(0), Some(105));
        let pkt = r.next_packet().unwrap().unwrap();
        // 7 s + 1_500_000_000 ns = 7_000_000 us + 1_500_000 us = 8_500_000 us.
        assert_eq!(pkt.timestamp_us, 8_500_000);
        assert_eq!(pkt.data, payload);
        assert!(r.next_packet().unwrap().is_none());

        let meta = r.file_metadata();
        assert!(meta.format.starts_with("IXIA HW lcap"), "got {}", meta.format);
        assert_eq!(meta.endian, "little endian");
    }

    #[test]
    fn ixia_hardware_be_nanosecond() {
        let payload = b"ixia hw be";
        let inner = build_inner_be_ixia(2, 250_000_000, payload);
        let mut r = PcapReader::new(Cursor::new(inner), MAGIC_BE_IXIAHW.to_le_bytes()).unwrap();

        let pkt = r.next_packet().unwrap().unwrap();
        // 2 s + 250_000_000 ns = 2_000_000 us + 250_000 us = 2_250_000 us.
        assert_eq!(pkt.timestamp_us, 2_250_000);
        assert_eq!(pkt.data, payload);

        let meta = r.file_metadata();
        assert!(meta.format.starts_with("IXIA HW lcap"));
        assert_eq!(meta.endian, "big endian");
    }

    #[test]
    fn ixia_software_le_microsecond() {
        // IXIA-SW = microsecond resolution like standard pcap.
        let payload = b"ixia sw le";
        let inner = build_inner_le_ixia(100, 333_444, payload);
        let mut r = PcapReader::new(Cursor::new(inner), MAGIC_LE_IXIASW.to_le_bytes()).unwrap();

        let pkt = r.next_packet().unwrap().unwrap();
        assert_eq!(pkt.timestamp_us, 100 * 1_000_000 + 333_444);
        assert_eq!(pkt.data, payload);

        let meta = r.file_metadata();
        assert!(meta.format.starts_with("IXIA SW lcap"));
        assert_eq!(meta.endian, "little endian");
    }

    #[test]
    fn ixia_software_be_microsecond() {
        let payload = b"ixia sw be";
        let inner = build_inner_be_ixia(50, 12_345, payload);
        let mut r = PcapReader::new(Cursor::new(inner), MAGIC_BE_IXIASW.to_le_bytes()).unwrap();

        let pkt = r.next_packet().unwrap().unwrap();
        assert_eq!(pkt.timestamp_us, 50 * 1_000_000 + 12_345);
        assert_eq!(pkt.data, payload);

        let meta = r.file_metadata();
        assert!(meta.format.starts_with("IXIA SW lcap"));
        assert_eq!(meta.endian, "big endian");
    }

    #[test]
    fn ixia_truncated_extra_field_returns_truncated_error() {
        // Header tail ends after 20 bytes with no IXIA extra field present.
        let mut inner = Vec::new();
        inner.extend_from_slice(&2u16.to_le_bytes());
        inner.extend_from_slice(&4u16.to_le_bytes());
        inner.extend_from_slice(&0i32.to_le_bytes());
        inner.extend_from_slice(&0u32.to_le_bytes());
        inner.extend_from_slice(&65535u32.to_le_bytes());
        inner.extend_from_slice(&105u32.to_le_bytes());
        // No 4-byte IXIA extra; reader should report Truncated.

        let result = PcapReader::new(Cursor::new(inner), MAGIC_LE_IXIAHW.to_le_bytes());
        assert!(matches!(result, Err(Error::Truncated { context, .. }) if context.contains("IXIA")));
    }
}
