//! pcap and pcapng container writers.
//!
//! Mirrors what `wpawolf::input::{pcap, pcapng, gzip}` accepts. The 10 pcap
//! magic numbers and the pcapng block layout are quoted from
//! `draft-ietf-opsawg-pcapng-05` and the libpcap `savefile.c` source.

use std::io::Write;

use flate2::Compression;
use flate2::write::GzEncoder;

use crate::Result;

/// Wrap an in-memory pcap / pcapng buffer in gzip for `.pcap.gz` /
/// `.pcapng.gz` fixtures. wpawolf's input dispatcher detects gzip via the
/// `1F 8B` magic (RFC 1952) -- see `wpawolf::input::gzip`.
///
/// # Errors
///
/// Propagates any I/O failure from the gzip encoder.
pub fn gzip(buf: &[u8]) -> Result<Vec<u8>> {
    let mut enc = GzEncoder::new(Vec::with_capacity(buf.len()), Compression::default());
    enc.write_all(buf)?;
    Ok(enc.finish()?)
}

/// Pcap file-header magic numbers.
///
/// `LE_US` = `0xA1B2C3D4` little-endian + microseconds (libpcap default);
/// `LE_NS` = `0xA1B23C4D` little-endian + nanoseconds; the Kuznetzov and IXIA
/// variants are extensions used by Russian-locale and IXIA capture stacks.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PcapMagic {
    /// Little-endian, microsecond timestamps.
    LeMicro,
    /// Big-endian, microsecond timestamps.
    BeMicro,
    /// Little-endian, nanosecond timestamps.
    LeNano,
    /// Big-endian, nanosecond timestamps.
    BeNano,
    /// Kuznetzov-format little-endian (`0xA1B2CD34`).
    KuzLe,
    /// Kuznetzov-format big-endian.
    KuzBe,
    /// IXIA hardware-accelerated little-endian (`0x1A2B3C4D`).
    IxiaHwLe,
    /// IXIA hardware-accelerated big-endian.
    IxiaHwBe,
    /// IXIA software little-endian (`0x1A2B3C4E`).
    IxiaSwLe,
    /// IXIA software big-endian.
    IxiaSwBe,
}

impl PcapMagic {
    /// Returns the 4-byte magic for this variant.
    ///
    /// Magic values mirrored from wpawolf's `src/input/pcap.rs` constants.
    #[must_use]
    pub const fn bytes(self) -> [u8; 4] {
        match self {
            Self::LeMicro => 0xA1B2_C3D4u32.to_le_bytes(),
            Self::BeMicro => 0xA1B2_C3D4u32.to_be_bytes(),
            Self::LeNano => 0xA1B2_3C4Du32.to_le_bytes(),
            Self::BeNano => 0xA1B2_3C4Du32.to_be_bytes(),
            Self::KuzLe => 0xA1B2_CD34u32.to_le_bytes(),
            Self::KuzBe => 0xA1B2_CD34u32.to_be_bytes(),
            // IXIA hardware-capture (`lcap` nanosecond) magic.
            Self::IxiaHwLe => 0x1C00_01ACu32.to_le_bytes(),
            Self::IxiaHwBe => 0x1C00_01ACu32.to_be_bytes(),
            // IXIA software-capture (`lcap` microsecond) magic.
            Self::IxiaSwLe => 0x1C00_01ABu32.to_le_bytes(),
            Self::IxiaSwBe => 0x1C00_01ABu32.to_be_bytes(),
        }
    }

    /// Returns `true` if this variant uses big-endian byte order.
    #[must_use]
    pub const fn is_be(self) -> bool {
        matches!(self, Self::BeMicro | Self::BeNano | Self::KuzBe | Self::IxiaHwBe | Self::IxiaSwBe)
    }

    /// Returns `true` if this variant uses the Kuznetzov 24-byte record header.
    #[must_use]
    pub const fn is_kuznetzov(self) -> bool {
        matches!(self, Self::KuzLe | Self::KuzBe)
    }

    /// Returns `true` if this variant carries the IXIA 4-byte extra
    /// file-header field after the standard 24-byte pcap header.
    #[must_use]
    pub const fn is_ixia(self) -> bool {
        matches!(self, Self::IxiaHwLe | Self::IxiaHwBe | Self::IxiaSwLe | Self::IxiaSwBe)
    }
}

/// One captured packet, ready to serialise.
#[derive(Debug, Clone)]
pub struct Packet {
    /// Seconds part of the capture timestamp.
    pub ts_sec: u32,
    /// Microsecond (or nanosecond, depending on magic) part of the timestamp.
    pub ts_subsec: u32,
    /// Wire bytes (link-layer header + 802.11 frame).
    pub data: Vec<u8>,
}

/// Write a classic pcap file (24-byte file header + N record headers).
///
/// # Errors
///
/// Propagates any I/O failure from the supplied writer.
pub fn write_pcap<W: Write>(w: &mut W, magic: PcapMagic, dlt: u32, packets: &[Packet]) -> Result<()> {
    let to_bytes_u16 = |x: u16| if magic.is_be() { x.to_be_bytes() } else { x.to_le_bytes() };
    let to_bytes_u32 = |x: u32| if magic.is_be() { x.to_be_bytes() } else { x.to_le_bytes() };
    w.write_all(&magic.bytes())?;
    w.write_all(&to_bytes_u16(2))?; // version_major.
    w.write_all(&to_bytes_u16(4))?; // version_minor.
    w.write_all(&to_bytes_u32(0))?; // thiszone.
    w.write_all(&to_bytes_u32(0))?; // sigfigs.
    w.write_all(&to_bytes_u32(65_535))?; // snaplen.
    w.write_all(&to_bytes_u32(dlt))?;
    if magic.is_ixia() {
        // IXIA `lcap` variants carry a 4-byte total-record-size field after
        // the standard 24-byte pcap header. The value is informational; we
        // emit zero so wpawolf advances the stream past it.
        w.write_all(&to_bytes_u32(0))?;
    }
    for p in packets {
        let len = u32::try_from(p.data.len()).unwrap_or(u32::MAX);
        w.write_all(&to_bytes_u32(p.ts_sec))?;
        w.write_all(&to_bytes_u32(p.ts_subsec))?;
        w.write_all(&to_bytes_u32(len))?; // incl_len.
        w.write_all(&to_bytes_u32(len))?; // orig_len.
        if magic.is_kuznetzov() {
            // Kuznetzov-patched format appends 8 bytes per record:
            // index(4) + protocol(2) + pkt_type(1) + pad(1).
            // [libpcap sf-pcap.c:167-174]
            w.write_all(&to_bytes_u32(0))?; // index.
            w.write_all(&to_bytes_u16(0))?; // protocol.
            w.write_all(&[0u8, 0u8])?; // pkt_type + pad.
        }
        w.write_all(&p.data)?;
    }
    Ok(())
}

/// Byte order of a pcapng section (BOM in the SHB).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PcapNgEndian {
    /// Little-endian section -- BOM `0x1A2B3C4D` written LE on the wire.
    Little,
    /// Big-endian section -- same BOM written BE on the wire.
    Big,
}

/// Write a minimal pcapng file: SHB + IDB + N EPBs.
///
/// LE section per `draft-ietf-opsawg-pcapng-05` §4. For BE sections call
/// [`write_pcapng_with_endian`] directly.
///
/// # Errors
///
/// Propagates any I/O failure from the supplied writer.
pub fn write_pcapng<W: Write>(w: &mut W, dlt: u16, packets: &[Packet]) -> Result<()> {
    write_pcapng_with_endian(w, PcapNgEndian::Little, dlt, packets)
}

/// Write a pcapng file with the chosen section byte order.
///
/// `draft-ietf-opsawg-pcapng-05` §4: blocks have a 4-byte type, 4-byte total
/// length, body padded to 32-bit alignment, trailing copy of the total
/// length. The byte order of every multi-byte field follows the SHB BOM.
///
/// # Errors
///
/// Propagates any I/O failure from the supplied writer.
pub fn write_pcapng_with_endian<W: Write>(w: &mut W, endian: PcapNgEndian, dlt: u16, packets: &[Packet]) -> Result<()> {
    let pack_u16 = |x: u16| match endian {
        PcapNgEndian::Little => x.to_le_bytes(),
        PcapNgEndian::Big => x.to_be_bytes(),
    };
    let pack_u32 = |x: u32| match endian {
        PcapNgEndian::Little => x.to_le_bytes(),
        PcapNgEndian::Big => x.to_be_bytes(),
    };
    let pack_section_length = |x: i64| match endian {
        PcapNgEndian::Little => x.to_le_bytes(),
        PcapNgEndian::Big => x.to_be_bytes(),
    };

    // SHB: type 0x0A0D0D0A, body = BOM + version (2x u16) + section length.
    let bom = match endian {
        PcapNgEndian::Little => 0x1A2B_3C4Du32.to_le_bytes(),
        PcapNgEndian::Big => 0x1A2B_3C4Du32.to_be_bytes(),
    };
    let mut shb = Vec::new();
    shb.extend_from_slice(&bom);
    shb.extend_from_slice(&pack_u16(1));
    shb.extend_from_slice(&pack_u16(0));
    shb.extend_from_slice(&pack_section_length(-1));
    write_block(w, endian, 0x0A0D_0D0A, &shb)?;

    // IDB: type 0x00000001, body = LinkType (u16) + reserved (u16) + SnapLen.
    let mut idb = Vec::new();
    idb.extend_from_slice(&pack_u16(dlt));
    idb.extend_from_slice(&pack_u16(0));
    idb.extend_from_slice(&pack_u32(65_535));
    write_block(w, endian, 0x0000_0001, &idb)?;

    for p in packets {
        // EPB: type 0x00000006, body = InterfaceID + ts_high + ts_low +
        // caplen + origlen + packet data (padded to 4-byte boundary).
        let mut epb = Vec::new();
        epb.extend_from_slice(&pack_u32(0));
        let ts = (u64::from(p.ts_sec) * 1_000_000) + u64::from(p.ts_subsec);
        epb.extend_from_slice(&pack_u32(u32::try_from(ts >> 32).unwrap_or(u32::MAX)));
        #[expect(clippy::cast_possible_truncation, reason = "lower 32 bits of microsecond timestamp")]
        epb.extend_from_slice(&pack_u32(ts as u32));
        let len = u32::try_from(p.data.len()).unwrap_or(u32::MAX);
        epb.extend_from_slice(&pack_u32(len));
        epb.extend_from_slice(&pack_u32(len));
        epb.extend_from_slice(&p.data);
        while epb.len() % 4 != 0 {
            epb.push(0);
        }
        write_block(w, endian, 0x0000_0006, &epb)?;
    }
    Ok(())
}

/// Helper: write one pcapng block with type, total length, body, trailing length.
fn write_block<W: Write>(w: &mut W, endian: PcapNgEndian, block_type: u32, body: &[u8]) -> Result<()> {
    let total = u32::try_from(body.len() + 12).unwrap_or(u32::MAX);
    let (type_bytes, total_bytes) = match endian {
        PcapNgEndian::Little => (block_type.to_le_bytes(), total.to_le_bytes()),
        PcapNgEndian::Big => (block_type.to_be_bytes(), total.to_be_bytes()),
    };
    w.write_all(&type_bytes)?;
    w.write_all(&total_bytes)?;
    w.write_all(body)?;
    w.write_all(&total_bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_packets() -> Vec<Packet> {
        vec![
            Packet { ts_sec: 1_700_000_000, ts_subsec: 123_456, data: b"raw-frame-1".to_vec() },
            Packet { ts_sec: 1_700_000_001, ts_subsec: 654_321, data: b"raw-frame-second".to_vec() },
        ]
    }

    #[test]
    fn pcap_le_micro_round_trip() {
        let mut buf = Vec::new();
        write_pcap(&mut buf, PcapMagic::LeMicro, 105, &sample_packets()).expect("write_pcap");
        // Magic.
        assert_eq!(&buf[..4], &PcapMagic::LeMicro.bytes());
        // Major / minor / dlt.
        assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), 2);
        assert_eq!(u16::from_le_bytes([buf[6], buf[7]]), 4);
        let dlt = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
        assert_eq!(dlt, 105);
        // First packet starts at offset 24 (file hdr) + 16 (record hdr).
        assert_eq!(&buf[40..40 + b"raw-frame-1".len()], b"raw-frame-1");
    }

    #[test]
    fn pcap_be_nano_uses_be_byte_order() {
        let mut buf = Vec::new();
        write_pcap(&mut buf, PcapMagic::BeNano, 127, &sample_packets()).expect("write_pcap be");
        assert_eq!(u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]), 127);
    }

    #[test]
    fn pcap_all_ten_magics_round_trip() {
        for magic in [
            PcapMagic::LeMicro,
            PcapMagic::BeMicro,
            PcapMagic::LeNano,
            PcapMagic::BeNano,
            PcapMagic::KuzLe,
            PcapMagic::KuzBe,
            PcapMagic::IxiaHwLe,
            PcapMagic::IxiaHwBe,
            PcapMagic::IxiaSwLe,
            PcapMagic::IxiaSwBe,
        ] {
            let mut buf = Vec::new();
            write_pcap(&mut buf, magic, 105, &sample_packets()).expect("write_pcap variant");
            assert_eq!(&buf[..4], &magic.bytes());
        }
    }

    #[test]
    fn pcapng_round_trip() {
        let mut buf = Vec::new();
        write_pcapng(&mut buf, 105, &sample_packets()).expect("write_pcapng");
        // SHB block type is 0x0A0D0D0A.
        assert_eq!(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), 0x0A0D_0D0A);
        // Followed by IDB (0x00000001).
        let shb_total = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
        let idb_off = shb_total;
        assert_eq!(
            u32::from_le_bytes([buf[idb_off], buf[idb_off + 1], buf[idb_off + 2], buf[idb_off + 3]]),
            0x0000_0001
        );
    }

    #[test]
    fn pcapng_be_section_uses_be_byte_order() {
        let mut buf = Vec::new();
        write_pcapng_with_endian(&mut buf, PcapNgEndian::Big, 127, &sample_packets()).expect("write_pcapng be");
        // SHB block type is BOM-independent (always 0x0A0D0D0A) but the
        // total-length and BOM fields after it must be BE.
        assert_eq!(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]), 0x0A0D_0D0A);
        // Bytes 8-11 are the BOM, written BE.
        assert_eq!(u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]), 0x1A2B_3C4D);
    }

    #[test]
    fn gzip_wrapper_starts_with_magic() {
        let payload = vec![0x42u8; 64];
        let gz = gzip(&payload).expect("gzip");
        assert_eq!(&gz[..2], &[0x1F, 0x8B]);
        assert!(gz.len() < payload.len() + 32, "gzip frame should not balloon for trivial input");
    }
}
