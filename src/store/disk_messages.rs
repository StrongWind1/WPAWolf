//! Disk-backed binary serialization for [`EapolMessage`] and [`PmkidEntry`].
//!
//! Used by the disk fallback to spill messages to a temp file during Phase 1
//! and read them back one group at a time during Phase 4. No serde -- the
//! format is a fixed header followed by variable-length frame bytes.
//!
//! # Wire format (`EapolMessage`)
//!
//! ```text
//! offset  len  field
//! 0       8    timestamp (u64 LE)
//! 8       1    msg_type (u8: 1=M1, 2=M2, 3=M3, 4=M4)
//! 9       1    key_version (u8)
//! 10      8    replay_counter (u64 LE)
//! 18      32   nonce ([u8; 32])
//! 50      1    mic_len (u8: 16 or 24)
//! 51      24   mic_data ([u8; 24], zero-padded if mic_len < 24)
//! 75      1    has_pmkid (0 or 1)
//! 76      16   pmkid ([u8; 16], zeroed if has_pmkid == 0)
//! 92      1    akm (u8)
//! 93      1    is_rsn (0 or 1)
//! 94      1    has_ft (0 or 1)
//! 95      4    frame_len (u32 LE)
//! --- 99 bytes fixed header ---
//! 99      57   ft_fields (only when has_ft == 1)
//!              mdid(2 LE) + r0khid_len(1) + r0khid(48) + r1khid(6)
//! 99|156  N    eapol_frame bytes (frame_len bytes)
//! ```

use std::io::{Read, Write};
use std::sync::Arc;

use crate::store::messages::EapolMessage;
use crate::store::pmkid::PmkidEntry;
use crate::types::{AkmType, FtFields, MacAddr, MicBytes, MsgType, PmkidSource};

/// Fixed header size for `EapolMessage` serialization.
const EAPOL_HEADER_LEN: usize = 99;

/// `FtFields` serialized size.
const FT_FIELDS_LEN: usize = 57;

/// Fixed header size for `PmkidEntry` serialization.
const PMKID_HEADER_LEN: usize = 46;

/// Serializes an `EapolMessage` to `writer`. Returns the number of bytes written.
///
/// # Errors
///
/// Returns `Err` on I/O failure.
#[expect(
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    reason = "compile-time-constant buffer layout; MIC len max 24 fits u8; header sizes fit u32"
)]
pub fn write_eapol_message(w: &mut impl Write, msg: &EapolMessage) -> std::io::Result<u32> {
    let mut buf = [0u8; EAPOL_HEADER_LEN];
    buf[0..8].copy_from_slice(&msg.timestamp.to_le_bytes());
    buf[8] = msg.msg_type as u8;
    buf[9] = msg.key_version;
    buf[10..18].copy_from_slice(&msg.replay_counter.to_le_bytes());
    buf[18..50].copy_from_slice(&msg.nonce);
    let mic_len = msg.mic.len() as u8;
    buf[50] = mic_len;
    buf[51..51 + msg.mic.len()].copy_from_slice(msg.mic.as_slice());
    if let Some(pmkid) = &msg.pmkid {
        buf[75] = 1;
        buf[76..92].copy_from_slice(pmkid);
    }
    buf[92] = msg.akm.to_byte();
    buf[93] = u8::from(msg.is_rsn);
    buf[94] = u8::from(msg.ft.is_some());
    let frame = msg.eapol_frame.as_ref();
    let frame_len = u32::try_from(frame.len()).unwrap_or(u32::MAX);
    buf[95..99].copy_from_slice(&frame_len.to_le_bytes());
    w.write_all(&buf)?;

    let mut total = EAPOL_HEADER_LEN as u32;
    if let Some(ft) = &msg.ft {
        let ft_buf = serialize_ft_fields(ft);
        w.write_all(&ft_buf)?;
        total += FT_FIELDS_LEN as u32;
    }
    w.write_all(frame)?;
    total += frame_len;
    Ok(total)
}

/// Deserializes an `EapolMessage` from `reader`.
///
/// # Errors
///
/// Returns `Err` on I/O failure or if the data is malformed.
pub fn read_eapol_message(r: &mut impl Read) -> std::io::Result<EapolMessage> {
    let mut buf = [0u8; EAPOL_HEADER_LEN];
    r.read_exact(&mut buf)?;

    let timestamp = u64::from_le_bytes(buf[0..8].try_into().unwrap_or([0; 8]));
    let msg_type = match buf[8] {
        1 => MsgType::M1,
        2 => MsgType::M2,
        3 => MsgType::M3,
        4 => MsgType::M4,
        _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad msg_type")),
    };
    let key_version = buf[9];
    let replay_counter = u64::from_le_bytes(buf[10..18].try_into().unwrap_or([0; 8]));
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&buf[18..50]);
    let mic_len = buf[50];
    let mic = if mic_len == 24 {
        MicBytes::from_24(buf[51..75].try_into().unwrap_or([0; 24]))
    } else {
        MicBytes::from_16(buf[51..67].try_into().unwrap_or([0; 16]))
    };
    let pmkid = if buf[75] != 0 {
        let mut p = [0u8; 16];
        p.copy_from_slice(&buf[76..92]);
        Some(p)
    } else {
        None
    };
    let akm = AkmType::from_byte(buf[92]);
    let is_rsn = buf[93] != 0;
    let has_ft = buf[94] != 0;
    let frame_len = u32::from_le_bytes(buf[95..99].try_into().unwrap_or([0; 4])) as usize;

    let ft = if has_ft {
        let mut ft_buf = [0u8; FT_FIELDS_LEN];
        r.read_exact(&mut ft_buf)?;
        Some(Box::new(deserialize_ft_fields(&ft_buf)))
    } else {
        None
    };

    let mut frame_bytes = vec![0u8; frame_len];
    r.read_exact(&mut frame_bytes)?;
    let eapol_frame: Arc<[u8]> = frame_bytes.into();

    Ok(EapolMessage {
        timestamp,
        msg_type,
        key_version,
        replay_counter,
        nonce,
        mic,
        pmkid,
        eapol_frame,
        ft,
        akm,
        is_rsn,
    })
}

/// Serializes an `FtFields` to a fixed 57-byte buffer.
fn serialize_ft_fields(ft: &FtFields) -> [u8; FT_FIELDS_LEN] {
    let mut buf = [0u8; FT_FIELDS_LEN];
    buf[0..2].copy_from_slice(&ft.mdid);
    buf[2] = ft.r0khid_len;
    buf[3..51].copy_from_slice(&ft.r0khid);
    buf[51..57].copy_from_slice(&ft.r1khid);
    buf
}

/// Deserializes an `FtFields` from a 57-byte buffer.
fn deserialize_ft_fields(buf: &[u8; FT_FIELDS_LEN]) -> FtFields {
    let mut mdid = [0u8; 2];
    mdid.copy_from_slice(&buf[0..2]);
    let r0khid_len = buf[2];
    let mut r0khid = [0u8; 48];
    r0khid.copy_from_slice(&buf[3..51]);
    let mut r1khid = [0u8; 6];
    r1khid.copy_from_slice(&buf[51..57]);
    FtFields { mdid, r0khid_len, r0khid, r1khid }
}

// --- PmkidEntry serialization ---

/// Serializes a `PmkidEntry` to `writer`. Returns the number of bytes written.
///
/// # Errors
///
/// Returns `Err` on I/O failure.
#[expect(clippy::cast_possible_truncation, reason = "PMKID_HEADER_LEN=46 and FT_FIELDS_LEN=57 fit u32")]
pub fn write_pmkid_entry(w: &mut impl Write, entry: &PmkidEntry) -> std::io::Result<u32> {
    let mut buf = [0u8; PMKID_HEADER_LEN];
    buf[0..8].copy_from_slice(&entry.timestamp.to_le_bytes());
    buf[8..14].copy_from_slice(&entry.ap.0);
    buf[14..20].copy_from_slice(&entry.sta.0);
    buf[20..36].copy_from_slice(&entry.pmkid);
    buf[36] = entry.source.to_byte();
    buf[37] = entry.akm.to_byte();
    buf[38] = u8::from(entry.ft.is_some());
    // 7 bytes reserved (39..46) for future fields
    w.write_all(&buf)?;

    let mut total = PMKID_HEADER_LEN as u32;
    if let Some(ft) = &entry.ft {
        let ft_buf = serialize_ft_fields(ft);
        w.write_all(&ft_buf)?;
        total += FT_FIELDS_LEN as u32;
    }
    Ok(total)
}

/// Deserializes a `PmkidEntry` from `reader`.
///
/// # Errors
///
/// Returns `Err` on I/O failure.
pub fn read_pmkid_entry(r: &mut impl Read) -> std::io::Result<PmkidEntry> {
    let mut buf = [0u8; PMKID_HEADER_LEN];
    r.read_exact(&mut buf)?;

    let timestamp = u64::from_le_bytes(buf[0..8].try_into().unwrap_or([0; 8]));
    let ap = MacAddr(buf[8..14].try_into().unwrap_or([0; 6]));
    let sta = MacAddr(buf[14..20].try_into().unwrap_or([0; 6]));
    let mut pmkid = [0u8; 16];
    pmkid.copy_from_slice(&buf[20..36]);
    let source = PmkidSource::from_byte(buf[36]);
    let akm = AkmType::from_byte(buf[37]);
    let has_ft = buf[38] != 0;

    let ft = if has_ft {
        let mut ft_buf = [0u8; FT_FIELDS_LEN];
        r.read_exact(&mut ft_buf)?;
        Some(Box::new(deserialize_ft_fields(&ft_buf)))
    } else {
        None
    };

    Ok(PmkidEntry { timestamp, ap, sta, pmkid, source, akm, ft })
}

// --- Unit tests ---

#[cfg(test)]
mod tests {

    use super::*;

    fn make_test_message(msg_type: MsgType, with_ft: bool, with_pmkid: bool) -> EapolMessage {
        let ft = if with_ft {
            Some(Box::new(FtFields {
                mdid: [0x12, 0x34],
                r0khid_len: 6,
                r0khid: {
                    let mut r = [0u8; 48];
                    r[..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
                    r
                },
                r1khid: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            }))
        } else {
            None
        };
        let pmkid = if with_pmkid { Some([0x42u8; 16]) } else { None };

        EapolMessage {
            timestamp: 1_700_000_000_000_000,
            msg_type,
            key_version: 2,
            replay_counter: 42,
            nonce: {
                let mut n = [0u8; 32];
                n[0] = 0xA5;
                n[31] = 0x5A;
                n
            },
            mic: MicBytes::from_16([0x11; 16]),
            pmkid,
            eapol_frame: Arc::from(vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE].as_slice()),
            ft,
            akm: AkmType::Wpa2Psk,
            is_rsn: true,
        }
    }

    #[test]
    fn eapol_round_trip_no_ft_no_pmkid() {
        let msg = make_test_message(MsgType::M2, false, false);
        let mut buf = Vec::new();
        let written = write_eapol_message(&mut buf, &msg).unwrap();
        assert_eq!(written as usize, buf.len());

        let mut cursor = std::io::Cursor::new(&buf);
        let restored = read_eapol_message(&mut cursor).unwrap();

        assert_eq!(restored.timestamp, msg.timestamp);
        assert_eq!(restored.msg_type, msg.msg_type);
        assert_eq!(restored.key_version, msg.key_version);
        assert_eq!(restored.replay_counter, msg.replay_counter);
        assert_eq!(restored.nonce, msg.nonce);
        assert_eq!(restored.mic.as_slice(), msg.mic.as_slice());
        assert_eq!(restored.pmkid, msg.pmkid);
        assert_eq!(restored.eapol_frame.as_ref(), msg.eapol_frame.as_ref());
        assert!(restored.ft.is_none());
        assert_eq!(restored.akm, msg.akm);
        assert_eq!(restored.is_rsn, msg.is_rsn);
    }

    #[test]
    fn eapol_round_trip_with_ft_and_pmkid() {
        let msg = make_test_message(MsgType::M1, true, true);
        let mut buf = Vec::new();
        write_eapol_message(&mut buf, &msg).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let restored = read_eapol_message(&mut cursor).unwrap();

        assert_eq!(restored.pmkid, Some([0x42; 16]));
        let ft = restored.ft.as_ref().unwrap();
        assert_eq!(ft.mdid, [0x12, 0x34]);
        assert_eq!(ft.r0khid_len, 6);
        assert_eq!(ft.r1khid, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn eapol_round_trip_24_byte_mic() {
        let mut msg = make_test_message(MsgType::M3, false, false);
        msg.mic = MicBytes::from_24([0xCC; 24]);
        let mut buf = Vec::new();
        write_eapol_message(&mut buf, &msg).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let restored = read_eapol_message(&mut cursor).unwrap();
        assert_eq!(restored.mic.len(), 24);
        assert_eq!(restored.mic.as_slice(), &[0xCC; 24]);
    }

    #[test]
    fn multiple_messages_sequential() {
        let msgs = vec![
            make_test_message(MsgType::M1, false, true),
            make_test_message(MsgType::M2, false, false),
            make_test_message(MsgType::M3, true, false),
            make_test_message(MsgType::M4, false, false),
        ];

        let mut buf = Vec::new();
        for msg in &msgs {
            write_eapol_message(&mut buf, msg).unwrap();
        }

        let mut cursor = std::io::Cursor::new(&buf);
        for original in &msgs {
            let restored = read_eapol_message(&mut cursor).unwrap();
            assert_eq!(restored.msg_type, original.msg_type);
            assert_eq!(restored.timestamp, original.timestamp);
            assert_eq!(restored.eapol_frame.as_ref(), original.eapol_frame.as_ref());
        }
    }

    #[test]
    fn pmkid_round_trip_no_ft() {
        let entry = PmkidEntry {
            timestamp: 999_000,
            ap: MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0xAA]),
            sta: MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0xBB]),
            pmkid: [0x55; 16],
            source: PmkidSource::M1KeyData,
            akm: AkmType::Wpa2Psk,
            ft: None,
        };

        let mut buf = Vec::new();
        write_pmkid_entry(&mut buf, &entry).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let restored = read_pmkid_entry(&mut cursor).unwrap();
        assert_eq!(restored.timestamp, entry.timestamp);
        assert_eq!(restored.ap, entry.ap);
        assert_eq!(restored.sta, entry.sta);
        assert_eq!(restored.pmkid, entry.pmkid);
        assert_eq!(restored.akm, entry.akm);
        assert!(restored.ft.is_none());
    }

    #[test]
    fn pmkid_round_trip_with_ft() {
        let entry = PmkidEntry {
            timestamp: 42,
            ap: MacAddr([0xFF; 6]),
            sta: MacAddr([0x11; 6]),
            pmkid: [0xAB; 16],
            source: PmkidSource::FtAuthStaToAp,
            akm: AkmType::FtPsk,
            ft: Some(Box::new(FtFields { mdid: [0x56, 0x78], r0khid_len: 3, r0khid: [0u8; 48], r1khid: [0xDE; 6] })),
        };

        let mut buf = Vec::new();
        write_pmkid_entry(&mut buf, &entry).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let restored = read_pmkid_entry(&mut cursor).unwrap();
        assert_eq!(restored.akm, AkmType::FtPsk);
        let ft = restored.ft.unwrap();
        assert_eq!(ft.mdid, [0x56, 0x78]);
        assert_eq!(ft.r1khid, [0xDE; 6]);
    }
}
