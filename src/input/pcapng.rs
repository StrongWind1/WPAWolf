//! Phase 1 -- Ingest: streaming pcapng block parser. See ARCHITECTURE.md §3.1 + §8.1.
//!
//! Handles Section Header Blocks (SHB, type `0x0A0D0D0A`), Interface Description
//! Blocks (IDB, type `0x00000001`), and Enhanced Packet Blocks (EPB, type `0x00000006`).
//! Per draft-ietf-opsawg-pcapng-05 §4. Supports both little-endian and big-endian
//! sections (byte order detected from the BOM field in the SHB).
//!
//! All other block types (SPB, NRB, ISB, Custom) are skipped transparently. The SHB
//! resets all interface state and re-establishes byte order; IDBs are registered in
//! sequential order to form the interface table. EPBs are the primary packet source.

use std::io::{BufReader, Read};

use crate::types::{Error, Result};

use super::{ByteOrder, FileMetadata, Packet, PacketReader, dlt_name};

// --- Wire constants ([draft-ietf-opsawg-pcapng-05]) ---

/// SHB block type. Also the file magic (`0x0A0D0D0A`).
/// [draft-ietf-opsawg-pcapng-05] §4.1
const BLOCK_TYPE_SHB: u32 = 0x0A0D_0D0A;

/// IDB block type -- Interface Description Block.
/// [draft-ietf-opsawg-pcapng-05] §4.2
const BLOCK_TYPE_IDB: u32 = 0x0000_0001;

/// EPB block type -- Enhanced Packet Block.
/// [draft-ietf-opsawg-pcapng-05] §4.3
const BLOCK_TYPE_EPB: u32 = 0x0000_0006;

/// Byte Order Magic bytes as they appear in a LITTLE-ENDIAN pcapng section.
/// The integer 0x1A2B3C4D stored in little-endian byte order in the file.
/// [draft-ietf-opsawg-pcapng-05] §4.1
const BOM_LITTLE_ENDIAN: [u8; 4] = [0x4D, 0x3C, 0x2B, 0x1A];

/// Byte Order Magic bytes as they appear in a BIG-ENDIAN pcapng section.
/// The integer 0x1A2B3C4D stored in big-endian byte order in the file.
/// [draft-ietf-opsawg-pcapng-05] §4.1
const BOM_BIG_ENDIAN: [u8; 4] = [0x1A, 0x2B, 0x3C, 0x4D];

/// IDB option code: end-of-options sentinel.
/// [draft-ietf-opsawg-pcapng-05] §3.5
const OPT_END_OF_OPT: u16 = 0;

/// IDB option code `if_tsresol` -- timestamp resolution.
/// [draft-ietf-opsawg-pcapng-05] §4.2, option 9
const OPT_IF_TSRESOL: u16 = 9;

/// IDB option code `if_tsoffset` -- seconds to add to all timestamps.
/// [draft-ietf-opsawg-pcapng-05] §4.2, option 14
const OPT_IF_TSOFFSET: u16 = 14;

/// Default timestamp units per second when `if_tsresol` is absent.
/// Equals 10^6 = 1 us resolution. [draft-ietf-opsawg-pcapng-05] §4.2
const DEFAULT_TS_UNITS_PER_SEC: u64 = 1_000_000;

/// Minimum bytes for a valid block: type(4) + `total_len`(4) + `trailing_len`(4).
const MIN_BLOCK_BYTES: u32 = 12;

/// Minimum body bytes required for an SHB (BOM + major + minor + `section_len`).
const SHB_BODY_MIN: usize = 12;

/// Minimum body bytes required for an IDB (`link_type` + reserved + snaplen).
const IDB_BODY_MIN: usize = 8;

/// Minimum body bytes required for an EPB fixed header.
/// (`interface_id` + `ts_high` + `ts_low` + caplen + origlen = 5 x 4 bytes)
const EPB_HEADER_LEN: usize = 20;

/// Required SHB major version. Minor is ignored.
/// [draft-ietf-opsawg-pcapng-05] §4.1
const SHB_MAJOR_VERSION: u16 = 1;

// --- Interface state ---

/// Timestamp resolution and offset for one registered pcapng interface.
///
/// Created from each IDB in order of appearance within the current section.
/// Interface IDs (`EPB.interface_id`) index into the `PcapngReader::interfaces` vec.
struct Interface {
    /// DLT (Data Link Type) from the IDB `LinkType` field.
    link_type: u16,
    /// Number of timestamp units per second. Default `1_000_000` (microseconds).
    /// Derived from IDB option `if_tsresol` (code 9). [draft-ietf-opsawg-pcapng-05] §4.2
    ts_units_per_sec: u64,
    /// Signed seconds to add to every timestamp on this interface. Default 0.
    /// Derived from IDB option `if_tsoffset` (code 14). [draft-ietf-opsawg-pcapng-05] §4.2
    ts_offset_sec: i64,
}

impl std::fmt::Debug for Interface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Interface")
            .field("link_type", &self.link_type)
            .field("ts_units_per_sec", &self.ts_units_per_sec)
            .field("ts_offset_sec", &self.ts_offset_sec)
            .finish()
    }
}

// --- Tri-state block outcome ---

/// Result of reading one block from the stream.
///
/// Used internally by `read_next_block` to distinguish clean EOF from a
/// successfully-processed non-EPB block (SHB/IDB/other). The `next_packet`
/// loop continues on `Skip`, stops on `Eof`, and returns immediately on `Packet`.
enum BlockOutcome {
    /// An EPB was parsed successfully; the packet is ready to return.
    Packet(Packet),
    /// The block was non-EPB (or an EPB with an unregistered interface).
    /// State has been updated (SHB/IDB) or the block was skipped. Keep looping.
    Skip,
    /// The underlying reader returned 0 bytes -- clean end-of-file.
    Eof,
}

// --- Slice reading helper ---

/// Reads exactly `N` bytes from `buf` at `offset`, returning them as a fixed-size array.
///
/// Avoids direct indexing (which triggers `clippy::indexing_slicing`) by using `.get()`.
/// Returns `Error::Truncated` if the slice is too short.
fn read_array<const N: usize>(buf: &[u8], offset: usize, context: &'static str) -> Result<[u8; N]> {
    buf.get(offset..offset + N).and_then(|s| s.try_into().ok()).ok_or(Error::Truncated {
        context,
        needed: offset + N,
        got: buf.len(),
    })
}

// --- Reader ---

/// Streaming pcapng reader. Maintains one reusable body buffer to avoid per-block allocation.
///
/// Processes one block at a time: SHBs reset interface state and byte order; IDBs register
/// interfaces; EPBs yield `Packet` values. All other block types are transparently skipped.
///
/// Constructed via `PcapngReader::new`, which reads and validates the mandatory first SHB.
pub struct PcapngReader<R: Read> {
    reader: BufReader<R>,
    /// Current section byte order, updated on each SHB.
    byte_order: ByteOrder,
    /// Interfaces registered by IDB order within the current section.
    interfaces: Vec<Interface>,
    /// Reusable heap buffer for block bodies. Grows as needed, never shrinks.
    block_buf: Vec<u8>,
    /// Major/minor version from the first SHB. [draft-ietf-opsawg-pcapng-05] §4.1
    version: (u16, u16),
}

impl<R: Read> std::fmt::Debug for PcapngReader<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PcapngReader")
            .field("byte_order", &self.byte_order)
            .field("interfaces", &self.interfaces)
            .finish_non_exhaustive()
    }
}

impl<R: Read> PcapngReader<R> {
    /// Opens a pcapng stream and reads the mandatory first Section Header Block.
    ///
    /// # Errors
    ///
    /// Returns `Error::Io` for underlying read failures, or `Error::UnknownFormat`
    /// if the first block is not a valid SHB.
    pub fn new(inner: R) -> Result<Self> {
        let mut reader = BufReader::new(inner);

        // Strategy: read 12 bytes (type + total_len + first 4 body bytes = BOM).
        // The SHB block type `0x0A0D0D0A` is a byte-order palindrome so it reads
        // identically in both endiannesses. The BOM (first 4 bytes of the SHB body)
        // tells us the byte order, which we then apply to correctly interpret total_len.
        // We must read the BOM before interpreting total_len because for a BE file the
        // LE interpretation of total_len would be a wild garbage value.
        // [draft-ietf-opsawg-pcapng-05] §4.1
        let mut prefix = [0u8; 12]; // type(4) + total_len(4) + bom(4)
        reader.read_exact(&mut prefix)?;

        // Block type: palindrome, reads same in both byte orders.
        let block_type = u32::from_le_bytes(read_array(&prefix, 0, "pcapng initial block type")?);
        if block_type != BLOCK_TYPE_SHB {
            return Err(Error::UnknownFormat(format!("first block type is not SHB: 0x{block_type:08X}")));
        }

        // BOM is at bytes 8..12 (the very start of the SHB body).
        // [draft-ietf-opsawg-pcapng-05] §4.1
        let bom_bytes: [u8; 4] = read_array(&prefix, 8, "pcapng SHB BOM")?;
        let byte_order = match bom_bytes {
            BOM_LITTLE_ENDIAN => ByteOrder::Little,
            BOM_BIG_ENDIAN => ByteOrder::Big,
            _ => {
                eprintln!("wpawolf: pcapng SHB BOM unrecognised ({bom_bytes:02X?}), assuming little-endian");
                ByteOrder::Little
            },
        };

        // Now decode total_len with the correct byte order.
        let total_len_raw: [u8; 4] = read_array(&prefix, 4, "pcapng SHB block_total_length")?;
        let block_total_len = byte_order.u32(total_len_raw);
        if block_total_len < MIN_BLOCK_BYTES {
            return Err(Error::Truncated {
                context: "pcapng SHB block_total_length",
                needed: MIN_BLOCK_BYTES as usize,
                got: block_total_len as usize,
            });
        }

        // The full body length is (block_total_len - 12). We already read the first 4 bytes
        // (the BOM) as part of the prefix; read the remaining (body_len - 4) bytes.
        let body_len = (block_total_len - MIN_BLOCK_BYTES) as usize;
        if body_len < 4 {
            // We need at least the 4 BOM bytes (already read) -- this should be >= 4 for
            // any well-formed SHB (BOM + major + minor + section_len = 12), but guard anyway.
            return Err(Error::Truncated { context: "pcapng SHB body (need BOM)", needed: 4, got: body_len });
        }

        // Assemble the full body buffer: BOM bytes already read + rest of body.
        let mut block_buf = vec![0u8; body_len];
        // Copy the 4 BOM bytes we already have into the start of block_buf.
        // Capture len before the mutable borrow to satisfy the borrow checker.
        {
            let buf_len = block_buf.len();
            block_buf
                .get_mut(0..4)
                .ok_or(Error::Truncated { context: "pcapng SHB BOM copy", needed: 4, got: buf_len })?
                .copy_from_slice(&bom_bytes);
        }

        // Read the remaining body bytes starting at offset 4.
        let rest_len = body_len - 4;
        if rest_len > 0 {
            let buf_len = block_buf.len();
            let dest = block_buf.get_mut(4..).ok_or(Error::Truncated {
                context: "pcapng SHB body rest",
                needed: body_len,
                got: buf_len,
            })?;
            reader.read_exact(dest)?;
        }

        // Trailing block total length -- read and discard.
        let mut trail = [0u8; 4];
        reader.read_exact(&mut trail)?;

        // Validate major version (offset 4 in body = bytes after BOM).
        // [draft-ietf-opsawg-pcapng-05] §4.1
        let major = byte_order.u16(read_array(&block_buf, 4, "pcapng SHB major version")?);
        if major != SHB_MAJOR_VERSION {
            eprintln!("wpawolf: pcapng SHB major version {major} != {SHB_MAJOR_VERSION}, continuing anyway");
        }
        let minor = byte_order.u16(read_array(&block_buf, 6, "pcapng SHB minor version")?);

        Ok(Self { reader, byte_order, interfaces: Vec::new(), block_buf, version: (major, minor) })
    }

    // --- Block reading ---

    /// Reads one complete block from the stream and returns a `BlockOutcome`.
    ///
    /// `BlockOutcome::Eof` signals a clean end-of-file (0-byte read on the block header).
    /// `BlockOutcome::Skip` means the block was consumed (SHB/IDB processed, or unknown
    /// block type skipped) but yielded no packet -- the caller should loop.
    /// `BlockOutcome::Packet` delivers a parsed EPB.
    ///
    /// I/O errors and structurally fatal parse errors propagate as `Err`.
    fn read_next_block(&mut self) -> Result<BlockOutcome> {
        // Read block type (4 bytes) + block total length (4 bytes).
        //
        // BufReader::read() may return fewer bytes than requested when the internal 8 KiB
        // buffer is nearly exhausted (e.g., returns 4 of 8 requested bytes at a block
        // boundary). Using a single read() for the 8-byte header would then mis-report
        // the file as truncated. Work around this by:
        //   1. Read exactly 1 byte with read() -- this distinguishes clean EOF (Ok(0))
        //      from a real partial read (Ok(1)). read_exact returns UnexpectedEof for both.
        //   2. Use read_exact() for the remaining 7 bytes so BufReader refills as needed.
        // [Rust std::io::BufReader -- read() may return less than buf.len()]
        let mut hdr = [0u8; 8];
        match self.reader.read(&mut hdr[..1]) {
            Ok(0) => return Ok(BlockOutcome::Eof), // clean EOF at block boundary
            Ok(_) => {},
            Err(e) => return Err(e.into()),
        }
        // Read the remaining 7 bytes; propagate UnexpectedEof as a truncation error.
        if let Err(e) = self.reader.read_exact(&mut hdr[1..]) {
            return Err(e.into());
        }

        let block_type = self.byte_order.u32(read_array(&hdr, 0, "pcapng block type")?);
        let block_total_len = self.byte_order.u32(read_array(&hdr, 4, "pcapng block total length")?);

        if block_total_len < MIN_BLOCK_BYTES {
            eprintln!(
                "wpawolf: pcapng block type 0x{block_type:08X} has block_total_length {block_total_len} < {MIN_BLOCK_BYTES}, skipping"
            );
            return Ok(BlockOutcome::Skip);
        }

        let body_len = (block_total_len - MIN_BLOCK_BYTES) as usize;

        // Grow the reusable body buffer if necessary, then fill the exact prefix.
        if self.block_buf.len() < body_len {
            self.block_buf.resize(body_len, 0);
        }

        // Read into an explicit prefix slice. Capture buf_len before the mutable borrow
        // so the borrow checker does not see block_buf.len() aliasing the get_mut() borrow.
        {
            let buf_len = self.block_buf.len(); // captured before get_mut
            let dest = self.block_buf.get_mut(..body_len).ok_or(Error::Truncated {
                context: "pcapng block body dest",
                needed: body_len,
                got: buf_len,
            })?;
            self.reader.read_exact(dest)?;
        }

        // Read and discard the trailing block total length field.
        let mut trail = [0u8; 4];
        self.reader.read_exact(&mut trail)?;

        // Dispatch on block type.
        // For blocks where the parse method needs &mut self (SHB, IDB), we clone the
        // relevant body bytes out of block_buf first to release the immutable borrow.
        // block_buf is a reusable scratch space -- cloning the body on these infrequent
        // control-plane blocks costs ~8-64 bytes per IDB and is negligible.
        match block_type {
            BLOCK_TYPE_SHB => {
                // SHB body is already in self.block_buf; parse_shb_body reads from it.
                self.parse_shb_body(body_len)?;
                Ok(BlockOutcome::Skip)
            },
            BLOCK_TYPE_IDB => {
                let body = self
                    .block_buf
                    .get(..body_len)
                    .ok_or(Error::Truncated {
                        context: "pcapng IDB body slice",
                        needed: body_len,
                        got: self.block_buf.len(),
                    })?
                    .to_vec(); // clone to free the borrow so parse_idb_body can take &mut self
                self.parse_idb_body(&body)?;
                Ok(BlockOutcome::Skip)
            },
            BLOCK_TYPE_EPB => {
                let body = self
                    .block_buf
                    .get(..body_len)
                    .ok_or(Error::Truncated {
                        context: "pcapng EPB body slice",
                        needed: body_len,
                        got: self.block_buf.len(),
                    })?
                    .to_vec(); // clone so parse_epb_body can borrow self.interfaces
                self.parse_epb_body(&body)?.map_or(Ok(BlockOutcome::Skip), |pkt| Ok(BlockOutcome::Packet(pkt)))
            },
            _ => {
                // SPB, NRB, ISB, Custom, and any future block types are transparently skipped.
                Ok(BlockOutcome::Skip)
            },
        }
    }

    // --- SHB parsing ---

    /// Parses an SHB body already loaded into `self.block_buf[..body_len]`.
    ///
    /// Resets `self.interfaces` and updates `self.byte_order` from the BOM.
    /// Validates the major version; logs a warning if it is not 1 but continues.
    /// [draft-ietf-opsawg-pcapng-05] §4.1
    fn parse_shb_body(&mut self, body_len: usize) -> Result<()> {
        if body_len < SHB_BODY_MIN {
            // Truncated SHB: reset state and continue.
            eprintln!(
                "wpawolf: pcapng SHB body too short ({body_len} bytes, need {SHB_BODY_MIN}), resetting interfaces"
            );
            self.interfaces.clear();
            return Ok(());
        }

        // BOM at offset 0 of the SHB body.
        // [draft-ietf-opsawg-pcapng-05] §4.1
        let bom_bytes: [u8; 4] = read_array(&self.block_buf, 0, "pcapng SHB BOM")?;
        self.byte_order = match bom_bytes {
            BOM_LITTLE_ENDIAN => ByteOrder::Little,
            BOM_BIG_ENDIAN => ByteOrder::Big,
            _ => {
                eprintln!("wpawolf: pcapng SHB BOM unrecognised ({bom_bytes:02X?}), keeping current byte order");
                self.byte_order
            },
        };

        // Major version at offset 4 (2 bytes); minor at offset 6.
        // [draft-ietf-opsawg-pcapng-05] §4.1
        let major = self.byte_order.u16(read_array(&self.block_buf, 4, "pcapng SHB major version")?);
        if major != SHB_MAJOR_VERSION {
            eprintln!("wpawolf: pcapng SHB major version {major} != {SHB_MAJOR_VERSION}, continuing anyway");
        }
        let minor = self.byte_order.u16(read_array(&self.block_buf, 6, "pcapng SHB minor version")?);
        self.version = (major, minor);

        // Section Length at offset 8 (i64): -1 means unspecified; ignored.
        // [draft-ietf-opsawg-pcapng-05] §4.1

        self.interfaces.clear();
        Ok(())
    }

    // --- IDB parsing ---

    /// Parses an IDB body and appends the resulting `Interface` to `self.interfaces`.
    ///
    /// Assigns the interface ID as the current `interfaces.len()` (zero-based).
    /// Processes `if_tsresol` and `if_tsoffset` options; all others are skipped.
    /// [draft-ietf-opsawg-pcapng-05] §4.2
    fn parse_idb_body(&mut self, body: &[u8]) -> Result<()> {
        if body.len() < IDB_BODY_MIN {
            eprintln!(
                "wpawolf: pcapng IDB body too short ({} bytes, need {IDB_BODY_MIN}), skipping interface",
                body.len()
            );
            return Ok(());
        }

        // IDB fixed header:
        // offset 0: LinkType (u16)
        // offset 2: Reserved (u16, skip)
        // offset 4: SnapLen (u32, not needed for extraction)
        // [draft-ietf-opsawg-pcapng-05] §4.2
        let link_type = self.byte_order.u16(read_array(body, 0, "pcapng IDB link_type")?);

        let mut iface = Interface { link_type, ts_units_per_sec: DEFAULT_TS_UNITS_PER_SEC, ts_offset_sec: 0 };

        // Options begin at offset 8 (after link_type(2) + reserved(2) + snaplen(4)).
        Self::parse_idb_options(self.byte_order, body, 8, &mut iface)?;

        self.interfaces.push(iface);
        Ok(())
    }

    /// Parses IDB TLV options from `body[offset..]`, updating `iface`.
    ///
    /// Options use TLV encoding: code(u16) + length(u16) + value, padded to 4-byte boundary.
    /// Stops at `opt_endofopt` (code 0) or when the buffer is exhausted.
    /// [draft-ietf-opsawg-pcapng-05] §3.5, §4.2
    ///
    /// Takes `byte_order` as an explicit parameter (rather than `&self`) so the borrow
    /// checker does not see `self` borrowed when `parse_idb_body` calls this.
    fn parse_idb_options(byte_order: ByteOrder, body: &[u8], mut offset: usize, iface: &mut Interface) -> Result<()> {
        loop {
            // Need at least 4 bytes for code (u16) + length (u16).
            if offset + 4 > body.len() {
                break;
            }

            let code = byte_order.u16(read_array(body, offset, "pcapng IDB option code")?);
            let length = byte_order.u16(read_array(body, offset + 2, "pcapng IDB option length")?);
            offset += 4;

            if code == OPT_END_OF_OPT {
                break;
            }

            let value_len = length as usize;
            // Advance past the value including 4-byte padding.
            // [draft-ietf-opsawg-pcapng-05] §3.5: "options shall be padded to a 32-bit boundary"
            let padded_len = (value_len + 3) & !3;

            match code {
                OPT_IF_TSRESOL if value_len >= 1 => {
                    // if_tsresol byte encodes resolution:
                    // MSB=0 -> decimal: units/sec = 10^value
                    // MSB=1 -> binary:  units/sec = 2^(value & 0x7F)
                    // [draft-ietf-opsawg-pcapng-05] §4.2, option 9
                    let resol_byte = body.get(offset).copied().ok_or(Error::Truncated {
                        context: "pcapng IDB if_tsresol byte",
                        needed: offset + 1,
                        got: body.len(),
                    })?;
                    iface.ts_units_per_sec = if resol_byte & 0x80 != 0 {
                        // [pcapng §4.2] MSB=1: binary resolution, 2^(value & 0x7F)
                        let exp = u32::from(resol_byte & 0x7F);
                        1u64.checked_shl(exp).unwrap_or(u64::MAX)
                    } else {
                        // [pcapng §4.2] MSB=0: decimal resolution, 10^value.
                        // A pathological capture advertising exp >= 20 would overflow
                        // `10u64.pow(exp)` and panic under `overflow-checks = true`.
                        // Saturate to u64::MAX to match the binary branch above.
                        let exp = u32::from(resol_byte);
                        10u64.checked_pow(exp).unwrap_or(u64::MAX)
                    };
                },
                OPT_IF_TSOFFSET if value_len == 8 => {
                    // if_tsoffset (option 14): signed seconds offset.
                    // [draft-ietf-opsawg-pcapng-05] §4.2, option 14
                    let raw: [u8; 8] = read_array(body, offset, "pcapng IDB if_tsoffset")?;
                    iface.ts_offset_sec = byte_order.i64(raw);
                },
                _ => {}, // Unknown or irrelevant option -- skip value bytes.
            }

            offset += padded_len;
        }
        Ok(())
    }

    // --- EPB parsing ---

    /// Parses an EPB body and returns the contained packet, or `None` for a skippable error.
    ///
    /// Returns `None` (not `Err`) when the `interface_id` is unregistered -- a parse-level
    /// error that does not abort the run per the "log-and-continue" policy.
    /// [draft-ietf-opsawg-pcapng-05] §4.3
    fn parse_epb_body(&self, body: &[u8]) -> Result<Option<Packet>> {
        if body.len() < EPB_HEADER_LEN {
            eprintln!("wpawolf: pcapng EPB body too short ({} bytes, need {EPB_HEADER_LEN}), skipping", body.len());
            return Ok(None);
        }

        // EPB fixed header layout (all fields in section byte order):
        // offset  0: Interface ID (u32)
        // offset  4: Timestamp High (u32)
        // offset  8: Timestamp Low (u32)
        // offset 12: Captured Packet Length (u32)
        // offset 16: Original Packet Length (u32, not used)
        // [draft-ietf-opsawg-pcapng-05] §4.3
        let interface_id = self.byte_order.u32(read_array(body, 0, "pcapng EPB interface_id")?);
        let ts_high = self.byte_order.u32(read_array(body, 4, "pcapng EPB ts_high")?);
        let ts_low = self.byte_order.u32(read_array(body, 8, "pcapng EPB ts_low")?);
        let caplen = self.byte_order.u32(read_array(body, 12, "pcapng EPB caplen")?);
        // Original Packet Length at offset 16 is not used for packet extraction; skip.

        // EPB referencing an unregistered interface: surface the packet (with empty
        // data, since we have no DLT to interpret it) so the ingest loop can route
        // it through `log_unknown_linktype(interface_id)` (main.rs Phase 1) and
        // skip cleanly. The body is left unread; `caplen` is informational here.
        let Some(iface) = self.interfaces.get(interface_id as usize) else {
            let _ = caplen; // intentional: payload not parsed for missing IDB
            return Ok(Some(Packet { timestamp_us: 0, interface_id, data: Vec::new() }));
        };

        // Combine high and low 32-bit halves into the 64-bit raw timestamp.
        // [draft-ietf-opsawg-pcapng-05] §4.3: timestamp = (ts_high << 32) | ts_low
        let ts_raw = (u64::from(ts_high) << 32) | u64::from(ts_low);

        // Convert raw timestamp to microseconds using u128 arithmetic to avoid overflow.
        // ts_raw * 1_000_000 could exceed u64::MAX for nanosecond-resolution timestamps.
        let ts_us: u64 = if iface.ts_units_per_sec == 0 {
            0 // guard against malformed IDB (division by zero)
        } else {
            // u128 intermediate avoids overflow; result always fits in u64 for realistic
            // timestamps (microsecond values < 2^64). Saturate on overflow.
            let wide = (u128::from(ts_raw) * 1_000_000_u128) / u128::from(iface.ts_units_per_sec);
            u64::try_from(wide).unwrap_or(u64::MAX)
        };

        // Apply the signed seconds offset from if_tsoffset.
        // [draft-ietf-opsawg-pcapng-05] §4.2, option 14
        // Use i128 to avoid wrap on u64->i64 cast and sign loss on i64->u64 cast.
        let offset_us = i128::from(iface.ts_offset_sec) * 1_000_000_i128;
        let timestamp_us = u64::try_from(i128::from(ts_us) + offset_us).unwrap_or(0);

        // Packet data immediately follows the 20-byte fixed header, unpadded to caplen bytes.
        let caplen_usize = caplen as usize;
        let data_end = EPB_HEADER_LEN + caplen_usize;
        let data = body.get(EPB_HEADER_LEN..data_end).ok_or(Error::Truncated {
            context: "pcapng EPB packet data",
            needed: data_end,
            got: body.len(),
        })?;

        Ok(Some(Packet { timestamp_us, interface_id, data: data.to_vec() }))
    }
}

impl<R: Read> PacketReader for PcapngReader<R> {
    /// Returns the next captured packet, skipping over SHB/IDB/unknown blocks internally.
    ///
    /// Returns `Ok(None)` only at clean EOF. I/O errors propagate as `Err`. Malformed
    /// blocks that can be skipped (short IDB, unregistered EPB interface) are logged to
    /// stderr and the loop continues.
    fn next_packet(&mut self) -> Result<Option<Packet>> {
        loop {
            match self.read_next_block()? {
                BlockOutcome::Packet(pkt) => return Ok(Some(pkt)),
                BlockOutcome::Eof => return Ok(None),
                BlockOutcome::Skip => {}, // non-EPB block processed or skipped -- keep looping
            }
        }
    }

    /// Returns the DLT for the given interface index, or `None` if not yet registered.
    fn link_type(&self, interface_id: u32) -> Option<u16> {
        self.interfaces.get(interface_id as usize).map(|i| i.link_type)
    }

    fn file_metadata(&self) -> FileMetadata {
        let endian = if self.byte_order == ByteOrder::Little { "little endian" } else { "big endian" };
        let dlt = self.interfaces.first().map_or(0, |i| i.link_type);
        FileMetadata {
            format: format!("pcapng {}.{}", self.version.0, self.version.1),
            endian,
            dlt,
            dlt_desc: format!("{} ({})", dlt_name(dlt), dlt),
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
        missing_docs,
        clippy::wildcard_imports,
        clippy::panic,
        reason = "test module -- relaxed lint policy"
    )]

    use super::*;

    // --- Binary blob helpers ---

    /// Pads `body` to a 4-byte boundary and wraps it in a complete block.
    fn make_block_le(block_type: u32, body: &[u8]) -> Vec<u8> {
        let padded_body_len = (body.len() + 3) & !3;
        let total_len = 12u32 + padded_body_len as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&block_type.to_le_bytes());
        out.extend_from_slice(&total_len.to_le_bytes());
        out.extend_from_slice(body);
        out.resize(8 + padded_body_len, 0); // zero-pad body to 4-byte boundary
        out.extend_from_slice(&total_len.to_le_bytes());
        out
    }

    /// Same as `make_block_le` but in big-endian byte order.
    fn make_block_be(block_type: u32, body: &[u8]) -> Vec<u8> {
        let padded_body_len = (body.len() + 3) & !3;
        let total_len = 12u32 + padded_body_len as u32;
        let mut out = Vec::new();
        out.extend_from_slice(&block_type.to_be_bytes());
        out.extend_from_slice(&total_len.to_be_bytes());
        out.extend_from_slice(body);
        out.resize(8 + padded_body_len, 0);
        out.extend_from_slice(&total_len.to_be_bytes());
        out
    }

    /// Minimal SHB body in little-endian layout.
    fn shb_body_le() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&BOM_LITTLE_ENDIAN);
        body.extend_from_slice(&1u16.to_le_bytes()); // major version
        body.extend_from_slice(&0u16.to_le_bytes()); // minor version
        body.extend_from_slice(&(-1i64).to_le_bytes()); // section length = unspecified
        body
    }

    /// Minimal SHB body in big-endian layout.
    fn shb_body_be() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&BOM_BIG_ENDIAN);
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&(-1i64).to_be_bytes());
        body
    }

    /// Minimal IDB body in little-endian layout with default options.
    fn idb_body_le(link_type: u16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&link_type.to_le_bytes()); // LinkType
        body.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        body.extend_from_slice(&65535u32.to_le_bytes()); // SnapLen
        body
    }

    /// IDB body in little-endian layout with an `if_tsresol` option.
    fn idb_body_le_with_tsresol(link_type: u16, resol_byte: u8) -> Vec<u8> {
        let mut body = idb_body_le(link_type);
        // Option TLV: code=9, length=1, value=resol_byte, pad to 4.
        body.extend_from_slice(&OPT_IF_TSRESOL.to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes()); // length
        body.push(resol_byte);
        body.extend_from_slice(&[0u8; 3]); // 3 bytes of padding
        // opt_endofopt
        body.extend_from_slice(&OPT_END_OF_OPT.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body
    }

    /// EPB body in little-endian layout.
    fn epb_body_le(interface_id: u32, ts_high: u32, ts_low: u32, data: &[u8]) -> Vec<u8> {
        let caplen = data.len() as u32;
        let mut body = Vec::new();
        body.extend_from_slice(&interface_id.to_le_bytes());
        body.extend_from_slice(&ts_high.to_le_bytes());
        body.extend_from_slice(&ts_low.to_le_bytes());
        body.extend_from_slice(&caplen.to_le_bytes());
        body.extend_from_slice(&caplen.to_le_bytes()); // origlen == caplen
        body.extend_from_slice(data);
        // Pad packet data to 4-byte boundary.
        let pad = (4 - (data.len() % 4)) % 4;
        body.extend(std::iter::repeat_n(0u8, pad));
        body
    }

    /// Assembles a minimal LE pcapng stream: SHB + IDB[`link_type`] + any extra blocks.
    fn make_pcapng_le(link_type: u16, extra_blocks: &[Vec<u8>]) -> Vec<u8> {
        let mut stream = Vec::new();
        stream.extend(make_block_le(BLOCK_TYPE_SHB, &shb_body_le()));
        stream.extend(make_block_le(BLOCK_TYPE_IDB, &idb_body_le(link_type)));
        for block in extra_blocks {
            stream.extend_from_slice(block);
        }
        stream
    }

    // --- Tests ---

    #[test]
    fn shb_little_endian_detection() {
        let stream = make_pcapng_le(1, &[]);
        let reader = PcapngReader::new(stream.as_slice()).unwrap();
        assert_eq!(reader.byte_order, ByteOrder::Little);
    }

    #[test]
    fn shb_big_endian_detection() {
        // Build a BE pcapng stream: SHB in BE byte order.
        // The SHB block type is a palindrome so make_block_be writes it correctly.
        let mut stream = Vec::new();
        stream.extend(make_block_be(BLOCK_TYPE_SHB, &shb_body_be()));

        let reader = PcapngReader::new(stream.as_slice()).unwrap();
        assert_eq!(reader.byte_order, ByteOrder::Big);
    }

    #[test]
    fn idb_registers_link_type() {
        // Drive the reader past the IDB by calling next_packet (which returns None = EOF).
        let stream = make_pcapng_le(105, &[]); // 105 = LINKTYPE_IEEE802_11
        let mut reader = PcapngReader::new(stream.as_slice()).unwrap();
        // next_packet consumes the IDB then hits EOF.
        assert!(reader.next_packet().unwrap().is_none());
        assert_eq!(reader.link_type(0), Some(105));
        assert_eq!(reader.link_type(1), None);
    }

    #[test]
    fn idb_default_ts_units() {
        let stream = make_pcapng_le(1, &[]);
        let mut reader = PcapngReader::new(stream.as_slice()).unwrap();
        reader.next_packet().unwrap(); // consume IDB
        assert_eq!(reader.interfaces[0].ts_units_per_sec, 1_000_000);
        assert_eq!(reader.interfaces[0].ts_offset_sec, 0);
    }

    #[test]
    fn idb_tsresol_decimal() {
        // resol_byte=9: 10^9 units/sec (nanosecond resolution)
        let mut stream = Vec::new();
        stream.extend(make_block_le(BLOCK_TYPE_SHB, &shb_body_le()));
        stream.extend(make_block_le(BLOCK_TYPE_IDB, &idb_body_le_with_tsresol(1, 9)));
        let mut reader = PcapngReader::new(stream.as_slice()).unwrap();
        reader.next_packet().unwrap(); // consume IDB
        assert_eq!(reader.interfaces[0].ts_units_per_sec, 1_000_000_000);
    }

    #[test]
    fn idb_tsresol_binary() {
        // resol_byte = 0x80 | 10 = 0x8A: 2^10 = 1024 units/sec
        let resol_byte = 0x80u8 | 0x0Au8;
        let mut stream = Vec::new();
        stream.extend(make_block_le(BLOCK_TYPE_SHB, &shb_body_le()));
        stream.extend(make_block_le(BLOCK_TYPE_IDB, &idb_body_le_with_tsresol(1, resol_byte)));
        let mut reader = PcapngReader::new(stream.as_slice()).unwrap();
        reader.next_packet().unwrap(); // consume IDB
        assert_eq!(reader.interfaces[0].ts_units_per_sec, 1024);
    }

    #[test]
    fn idb_tsresol_decimal_overflow_saturates() {
        // resol_byte=20: 10^20 overflows u64. Must saturate to u64::MAX rather than
        // panicking under debug overflow-checks. Regression test for a pcapng with
        // a nonsense if_tsresol value aborting the whole run.
        let mut stream = Vec::new();
        stream.extend(make_block_le(BLOCK_TYPE_SHB, &shb_body_le()));
        stream.extend(make_block_le(BLOCK_TYPE_IDB, &idb_body_le_with_tsresol(1, 20)));
        let mut reader = PcapngReader::new(stream.as_slice()).unwrap();
        reader.next_packet().unwrap();
        assert_eq!(reader.interfaces[0].ts_units_per_sec, u64::MAX);
    }

    #[test]
    fn idb_tsresol_decimal_max_byte_saturates() {
        // resol_byte=0x7F (127, MSB=0 so decimal): 10^127 overflows u64, must saturate.
        let mut stream = Vec::new();
        stream.extend(make_block_le(BLOCK_TYPE_SHB, &shb_body_le()));
        stream.extend(make_block_le(BLOCK_TYPE_IDB, &idb_body_le_with_tsresol(1, 0x7F)));
        let mut reader = PcapngReader::new(stream.as_slice()).unwrap();
        reader.next_packet().unwrap();
        assert_eq!(reader.interfaces[0].ts_units_per_sec, u64::MAX);
    }

    #[test]
    fn epb_correct_timestamp_and_data() {
        let payload = b"\x01\x02\x03\x04";
        // ts_high=0, ts_low=1_000_000: ts_raw = 1_000_000 us -> timestamp_us = 1_000_000
        let epb_body = epb_body_le(0, 0, 1_000_000, payload);
        let epb_block = make_block_le(BLOCK_TYPE_EPB, &epb_body);

        let stream = make_pcapng_le(1, &[epb_block]);
        let mut reader = PcapngReader::new(stream.as_slice()).unwrap();
        let pkt = reader.next_packet().unwrap().unwrap(); // skips IDB, returns EPB

        assert_eq!(pkt.timestamp_us, 1_000_000);
        assert_eq!(pkt.interface_id, 0);
        assert_eq!(pkt.data, payload);
    }

    #[test]
    fn epb_eof_returns_none() {
        let stream = make_pcapng_le(1, &[]);
        let mut reader = PcapngReader::new(stream.as_slice()).unwrap();
        // Skips IDB, reaches EOF.
        assert!(reader.next_packet().unwrap().is_none());
    }

    #[test]
    fn epb_unknown_interface_surfaced_with_empty_data() {
        let payload = b"\xAA\xBB";
        // interface_id=99 -- only interface 0 is registered.
        let epb_body = epb_body_le(99, 0, 42, payload);
        let epb_block = make_block_le(BLOCK_TYPE_EPB, &epb_body);

        let stream = make_pcapng_le(1, &[epb_block]);
        let mut reader = PcapngReader::new(stream.as_slice()).unwrap();
        // The reader surfaces the EPB so the ingest loop can route it through
        // `Logger::log_unknown_linktype(interface_id)`. Data is empty (no DLT
        // to interpret it) and `link_type(99)` is None so the loop will skip.
        let pkt = reader.next_packet().unwrap().expect("EPB must surface even when its IDB is missing");
        assert_eq!(pkt.interface_id, 99);
        assert!(pkt.data.is_empty(), "data must be empty without a known DLT");
        assert_eq!(reader.link_type(99), None);
        // Then EOF.
        assert!(reader.next_packet().unwrap().is_none());
    }

    #[test]
    fn multiple_interfaces_registered() {
        let mut stream = Vec::new();
        stream.extend(make_block_le(BLOCK_TYPE_SHB, &shb_body_le()));
        stream.extend(make_block_le(BLOCK_TYPE_IDB, &idb_body_le(105)));
        stream.extend(make_block_le(BLOCK_TYPE_IDB, &idb_body_le(1)));

        let mut reader = PcapngReader::new(stream.as_slice()).unwrap();
        reader.next_packet().unwrap(); // consume both IDBs and reach EOF
        assert_eq!(reader.link_type(0), Some(105));
        assert_eq!(reader.link_type(1), Some(1));
        assert_eq!(reader.link_type(2), None);
    }

    #[test]
    fn second_shb_clears_interfaces() {
        let mut stream = Vec::new();
        stream.extend(make_block_le(BLOCK_TYPE_SHB, &shb_body_le()));
        stream.extend(make_block_le(BLOCK_TYPE_IDB, &idb_body_le(105)));
        // Second SHB resets the interface table.
        stream.extend(make_block_le(BLOCK_TYPE_SHB, &shb_body_le()));
        // New IDB after the second SHB -- only this one should be registered.
        stream.extend(make_block_le(BLOCK_TYPE_IDB, &idb_body_le(1)));

        let mut reader = PcapngReader::new(stream.as_slice()).unwrap();
        reader.next_packet().unwrap(); // processes IDB(105) + SHB + IDB(1) then EOF
        // After the second SHB cleared the table, only link_type=1 (id=0) remains.
        assert_eq!(reader.link_type(0), Some(1));
        assert_eq!(reader.link_type(1), None);
    }

    #[test]
    fn epb_high_ts_combined_correctly() {
        // ts_high=1, ts_low=0: ts_raw = 2^32 = 4_294_967_296
        // ts_us = 4_294_967_296 * 1_000_000 / 1_000_000 = 4_294_967_296 us
        let payload = b"\xDE\xAD\xBE\xEF";
        let epb_body = epb_body_le(0, 1, 0, payload);
        let epb_block = make_block_le(BLOCK_TYPE_EPB, &epb_body);

        let stream = make_pcapng_le(1, &[epb_block]);
        let mut reader = PcapngReader::new(stream.as_slice()).unwrap();
        let pkt = reader.next_packet().unwrap().unwrap();
        assert_eq!(pkt.timestamp_us, 4_294_967_296);
        assert_eq!(pkt.data, payload);
    }

    #[test]
    fn epb_nanosecond_resolution_converted() {
        // IDB with if_tsresol=9: 10^9 units/sec (nanoseconds).
        // ts_raw=2_000_000_000 ns -> should become 2_000_000 us.
        let mut stream = Vec::new();
        stream.extend(make_block_le(BLOCK_TYPE_SHB, &shb_body_le()));
        stream.extend(make_block_le(BLOCK_TYPE_IDB, &idb_body_le_with_tsresol(1, 9)));

        let payload = b"\x01";
        let epb_body = epb_body_le(0, 0, 2_000_000_000, payload);
        let epb_block = make_block_le(BLOCK_TYPE_EPB, &epb_body);
        stream.extend(epb_block);

        let mut reader = PcapngReader::new(stream.as_slice()).unwrap();
        let pkt = reader.next_packet().unwrap().unwrap();
        assert_eq!(pkt.timestamp_us, 2_000_000);
    }
}
