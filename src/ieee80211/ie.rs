//! Phase 2 -- Decode: 802.11 Information Element (tagged parameter) parser. See ARCHITECTURE.md §3.2 + §8.3.
//!
//! Each IE is a TLV triplet: tag (u8), length (u8), value (length bytes). The parser
//! iterates IEs defensively -- a truncated or length-overrun IE stops iteration rather
//! than panicking or skipping to the wrong offset. Also handles WPS vendor IEs
//! (tag 221, OUI 00:50:F2, type 4) for device metadata extraction. Per IEEE 802.11-2024
//! §9.4.2.

// --- IE TLV iterator ---

/// A single parsed Information Element from a 802.11 tagged parameter block.
///
/// Per IEEE 802.11-2024 §9.4.2, every IE is a 1-byte Element ID, 1-byte length, and
/// `length` value bytes. Common Element IDs: 0=SSID, 48=RSN, 54=MDE, 55=FTE, 221=Vendor.
#[derive(Debug, Clone, Copy)]
pub struct Ie<'a> {
    /// Element ID (tag byte). Common values: 0=SSID, 48=RSN, 54=MDE, 55=FTE, 221=Vendor.
    pub id: u8,
    /// Element value bytes (length bytes, not including the ID or Length fields).
    pub value: &'a [u8],
}

/// Iterator over Information Elements in a 802.11 tagged parameter block.
///
/// Stops cleanly at end-of-data or on a truncated IE (does not panic). Callers
/// typically iterate once and filter by `ie.id`. Per IEEE 802.11-2024 §9.4.2.
pub struct IeIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl core::fmt::Debug for IeIter<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IeIter")
            .field("pos", &self.pos)
            .field("remaining", &self.data.len().saturating_sub(self.pos))
            .finish()
    }
}

impl<'a> IeIter<'a> {
    /// Creates an iterator over the tagged parameter block starting at `data[0]`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl<'a> Iterator for IeIter<'a> {
    type Item = Ie<'a>;

    fn next(&mut self) -> Option<Ie<'a>> {
        // Per IEEE 802.11-2024 §9.4.2: each IE is [ID (1 byte)][Length (1 byte)][Value (Length bytes)].
        // If fewer than 2 bytes remain, there is no complete IE header -- stop.
        let id = *self.data.get(self.pos)?; // 1 byte: Element ID
        let len = *self.data.get(self.pos + 1)? as usize; // 1 byte: Length field
        let value_start = self.pos + 2;
        let value_end = value_start + len;
        // If value_end overruns the buffer the IE is truncated -- stop rather than panic.
        let value = self.data.get(value_start..value_end)?;
        self.pos = value_end;
        Some(Ie { id, value })
    }
}

/// Creates an iterator over Information Elements in `data`.
///
/// `data` should be the tagged parameter block -- the part of a Beacon, `ProbeResponse`,
/// Association Request, etc. that follows the fixed fields. Iteration stops cleanly
/// on truncated or missing IEs. Per IEEE 802.11-2024 §9.4.2.
#[must_use]
pub const fn iter_ies(data: &[u8]) -> IeIter<'_> {
    IeIter::new(data)
}

// --- Vendor IE helper ---

/// OUI for Wi-Fi Alliance vendor IEs (Microsoft/WFA): `00:50:F2`.
/// Used by WPA (type 1) and WPS (type 4) vendor IEs.
const OUI_WFA: [u8; 3] = [0x00, 0x50, 0xF2]; // [IEEE 802.11-2024] §9.4.2.25, Wi-Fi Alliance OUI

/// Element ID for Vendor-Specific IEs. Per IEEE 802.11-2024 §9.4.2.25.
const IE_ID_VENDOR: u8 = 221; // [IEEE 802.11-2024] §9.4.2.25, Table 9-92

/// Returns `Some(body)` if `ie` is a vendor IE matching the given 3-byte OUI and 1-byte type.
///
/// Vendor IEs (Element ID 221) per IEEE 802.11-2024 §9.4.2.25 have the format:
/// OUI (3 bytes) + Type (1 byte) + body. Returns the body bytes after the OUI+Type
/// prefix, or `None` if the IE is too short or OUI/type don't match.
#[must_use]
pub fn vendor_ie_body<'a>(ie: &Ie<'a>, oui: [u8; 3], ie_type: u8) -> Option<&'a [u8]> {
    if ie.id != IE_ID_VENDOR {
        return None;
    }
    // value must be at least 4 bytes: 3 OUI + 1 type
    let prefix = ie.value.get(0..4)?;
    if prefix.get(0..3)? != oui {
        return None;
    }
    if *prefix.get(3)? != ie_type {
        return None;
    }
    ie.value.get(4..)
}

// --- WPS IE parser ---

/// WPS attribute type: Manufacturer string. [Wi-Fi Protected Setup spec] §12 attribute 0x1021.
const WPS_ATTR_MANUFACTURER: u16 = 0x1021;
/// WPS attribute type: Model Name string. [Wi-Fi Protected Setup spec] §12 attribute 0x1023.
const WPS_ATTR_MODEL_NAME: u16 = 0x1023;
/// WPS attribute type: Model Number string. [Wi-Fi Protected Setup spec] §12 attribute 0x1024.
const WPS_ATTR_MODEL_NUMBER: u16 = 0x1024;
/// WPS attribute type: Serial Number string. [Wi-Fi Protected Setup spec] §12 attribute 0x1042.
const WPS_ATTR_SERIAL_NUMBER: u16 = 0x1042;
/// WPS attribute type: Device Name (friendly name). [Wi-Fi Protected Setup spec] §12 attribute 0x1011.
const WPS_ATTR_DEVICE_NAME: u16 = 0x1011;
/// WPS attribute type: UUID-E (Enrollee UUID, 16 bytes). [Wi-Fi Protected Setup spec] §12 attribute 0x1047.
const WPS_ATTR_UUID_E: u16 = 0x1047;

/// WPS IE type byte within the Wi-Fi Alliance OUI namespace.
/// Vendor IE OUI=`00:50:F2`, type=4 identifies a WPS IE. [Wi-Fi Protected Setup spec] §12.
pub const WPS_IE_TYPE: u8 = 4;

/// Device metadata extracted from a WPS vendor IE.
///
/// All string fields are raw bytes -- WPS strings are ASCII in practice but the spec
/// allows arbitrary bytes. `uuid_e` is `None` if the attribute was absent or not
/// exactly 16 bytes. [Wi-Fi Protected Setup spec] §12.
#[derive(Debug, Default, Clone)]
pub struct WpsInfo {
    /// Device manufacturer name. [Wi-Fi Protected Setup spec] attribute 0x1021.
    pub manufacturer: Vec<u8>,
    /// Device model name. [Wi-Fi Protected Setup spec] attribute 0x1023.
    pub model_name: Vec<u8>,
    /// Device model number string. [Wi-Fi Protected Setup spec] attribute 0x1024.
    pub model_number: Vec<u8>,
    /// Device serial number string. [Wi-Fi Protected Setup spec] attribute 0x1042.
    pub serial_number: Vec<u8>,
    /// Device name (friendly name). [Wi-Fi Protected Setup spec] attribute 0x1011.
    pub device_name: Vec<u8>,
    /// UUID-E (Enrollee UUID), 16 bytes. [Wi-Fi Protected Setup spec] attribute 0x1047.
    pub uuid_e: Option<[u8; 16]>,
}

/// Parses a WPS IE body and extracts device metadata attributes.
///
/// `body` is the WPS IE data after the OUI+type prefix (i.e., the output of
/// `vendor_ie_body(ie, [0x00, 0x50, 0xF2], 4)`). Attributes in unrecognised
/// positions are skipped. A truncated attribute stops iteration. [Wi-Fi Protected
/// Setup spec] §12 TLV attribute format.
#[must_use]
pub fn parse_wps_body(body: &[u8]) -> WpsInfo {
    let mut info = WpsInfo::default();
    let mut pos = 0usize;
    while pos + 4 <= body.len() {
        // WPS TLV: Type (2 bytes BE) + Length (2 bytes BE) + Value (Length bytes).
        // All WPS attribute fields are big-endian. [Wi-Fi Protected Setup spec] §12.
        let type_bytes: [u8; 2] = match body.get(pos..pos + 2).and_then(|s| s.try_into().ok()) {
            Some(b) => b,
            None => break,
        };
        let len_bytes: [u8; 2] = match body.get(pos + 2..pos + 4).and_then(|s| s.try_into().ok()) {
            Some(b) => b,
            None => break,
        };
        let attr_type = u16::from_be_bytes(type_bytes); // big-endian per [Wi-Fi Protected Setup spec] §12
        let attr_len = u16::from_be_bytes(len_bytes) as usize; // big-endian per [Wi-Fi Protected Setup spec] §12
        let value_start = pos + 4;
        let value_end = value_start + attr_len;
        // Truncated attribute (attr_len > remaining body) -- stop cleanly.
        let Some(value) = body.get(value_start..value_end) else { break };
        match attr_type {
            WPS_ATTR_MANUFACTURER => info.manufacturer = value.to_vec(),
            WPS_ATTR_MODEL_NAME => info.model_name = value.to_vec(),
            WPS_ATTR_MODEL_NUMBER => info.model_number = value.to_vec(),
            WPS_ATTR_SERIAL_NUMBER => info.serial_number = value.to_vec(),
            WPS_ATTR_DEVICE_NAME => info.device_name = value.to_vec(),
            WPS_ATTR_UUID_E => {
                // UUID-E must be exactly 16 bytes; discard if wrong length.
                if let Ok(uuid) = value.try_into() {
                    info.uuid_e = Some(uuid);
                }
            },
            _ => {}, // unknown/unneeded attribute -- skip and continue
        }
        pos = value_end;
    }
    info
}

/// Searches `tagged_params` for the first WPS vendor IE and parses its body.
///
/// Returns `None` if no WPS IE is present. This is a convenience wrapper that
/// combines `iter_ies`, `vendor_ie_body`, and `parse_wps_body`.
#[must_use]
pub fn extract_wps_info(tagged_params: &[u8]) -> Option<WpsInfo> {
    for ie in iter_ies(tagged_params) {
        if let Some(body) = vendor_ie_body(&ie, OUI_WFA, WPS_IE_TYPE) {
            return Some(parse_wps_body(body));
        }
    }
    None
}

// --- SSID List IE (tag 84) ---

/// Element ID for SSID List. [IEEE 802.11-2024] §9.4.2.71
///
/// The SSID List element body contains zero or more embedded SSID sub-elements,
/// each formatted as a standard IE: `[tag=0][length][value]`. Used in Probe Requests
/// to solicit responses from multiple specific SSIDs simultaneously.
pub const IE_SSID_LIST: u8 = 84; // [IEEE 802.11-2024] §9.4.2.71, Table 9-92

/// Extracts SSIDs from an SSID List IE (tag 84) body.
///
/// The body is a sequence of embedded SSID elements, each with tag=0. Non-SSID
/// sub-elements (tag != 0) and empty SSIDs are skipped. Returns an empty `Vec` if
/// no valid SSIDs are found. [IEEE 802.11-2024] §9.4.2.71.
#[must_use]
pub fn extract_ssid_list(value: &[u8]) -> Vec<Vec<u8>> {
    let mut ssids = Vec::new();
    for ie in iter_ies(value) {
        if ie.id == 0 && !ie.value.is_empty() {
            ssids.push(ie.value.to_vec());
        }
    }
    ssids
}

// --- Country IE (tag 7) ---

/// Element ID for Country element. [IEEE 802.11-2024] §9.4.2.9
///
/// The Country element begins with a 3-byte Country String: 2 ASCII letters
/// (ISO 3166-1 country code) followed by a 1-byte Environment field.
pub const IE_COUNTRY: u8 = 7; // [IEEE 802.11-2024] §9.4.2.9, Table 9-92

/// Extracts the 2-letter country code from a Country IE (tag 7) value.
///
/// The Country IE value starts with 3 bytes: `[CC1][CC2][Environment]`.
/// Returns `Some([CC1, CC2])` if both bytes are ASCII uppercase letters (A-Z).
/// Returns `None` if the value is too short or the bytes are not valid country
/// code characters. [IEEE 802.11-2024] §9.4.2.9.
#[must_use]
pub fn extract_country_code(value: &[u8]) -> Option<[u8; 2]> {
    // Country String is at least 3 bytes: CC1, CC2, Environment.
    let cc1 = *value.first()?; // first country code byte
    let cc2 = *value.get(1)?; // second country code byte
    // Per IEEE 802.11-2024 §9.4.2.9: country code bytes are ASCII letters.
    // Accept uppercase (A-Z). Some implementations use lowercase; accept those too.
    if cc1.is_ascii_alphabetic() && cc2.is_ascii_alphabetic() { Some([cc1, cc2]) } else { None }
}

// --- Mesh ID IE (tag 114) ---

/// Element ID for Mesh ID element. [IEEE 802.11-2024] §9.4.2.97
///
/// The Mesh ID element body is 0-32 UTF-8 bytes identifying a Mesh Basic Service Set
/// (MBSS). Structurally identical to the SSID element (tag 0). Only present in
/// Beacon/ProbeResponse frames from mesh APs.
pub const IE_MESH_ID: u8 = 114; // [IEEE 802.11-2024] §9.4.2.97, Table 9-92

// --- Time Zone IE (tag 98) ---

/// Element ID for Time Zone element. [IEEE 802.11-2024] §9.4.2.85
///
/// Contains an ASCII POSIX timezone string (e.g., `"EST5EDT4,M3.2.0/02:00,M11.1.0/02:00"`).
/// Per IEEE Std 1003.1-2004 timezone format. Present in some Beacon frames from APs
/// that support 802.11v Time Advertisement.
pub const IE_TIME_ZONE: u8 = 98; // [IEEE 802.11-2024] §9.4.2.85, Table 9-92

// --- Cisco CCX1 IE (tag 133) ---

/// Element ID for Cisco CCX1 CKIP/AP Name IE. [Cisco CCX v1 Specification] §A.3
///
/// The IE body is at least 26 bytes: 10 bytes of fixed fields (unknown + AP IP)
/// followed by a 16-byte null-padded AP name. Non-standard IE used by Cisco
/// WLC and Meraki APs.
pub const IE_CISCO_CCX1: u8 = 133; // 0x85, [Cisco CCX v1] §A.3; Wireshark packet-ieee80211.c

/// Offset of the AP name within the Cisco CCX1 IE body.
/// Fixed fields: Unknown(4) + `AP_IP`(4) + `AP_Name_Offset`(2) = 10 bytes.
const CCX1_AP_NAME_OFFSET: usize = 10;

/// Maximum AP name length in Cisco CCX1 IE.
const CCX1_AP_NAME_MAX: usize = 16;

/// Extracts the AP name from a Cisco CCX1 IE (tag 133) body.
///
/// The IE body is at least 26 bytes: 10 bytes of fixed fields followed by
/// a 16-byte null-padded AP name. Returns `None` if the IE is too short or
/// the name is entirely null bytes. [Cisco CCX v1] §A.3.
#[must_use]
pub fn extract_ccx1_ap_name(value: &[u8]) -> Option<Vec<u8>> {
    let name_raw = value.get(CCX1_AP_NAME_OFFSET..CCX1_AP_NAME_OFFSET + CCX1_AP_NAME_MAX)?;
    let trimmed = trim_trailing_nulls(name_raw);
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_vec())
}

// --- Vendor AP name extraction ---

/// OUI for Aruba Networks vendor IEs: `00:0B:86`. [Wireshark oui.h]
const OUI_ARUBA: [u8; 3] = [0x00, 0x0B, 0x86];
/// OUI for Ubiquiti vendor IEs: `00:15:6D`. [Wireshark oui.h]
const OUI_UBIQUITI: [u8; 3] = [0x00, 0x15, 0x6D];
/// OUI for Aerohive vendor IEs: `00:19:77`. [Wireshark oui.h]
const OUI_AEROHIVE: [u8; 3] = [0x00, 0x19, 0x77];
/// OUI for Cisco Aironet vendor IEs: `00:40:96`. [Wireshark oui.h]
const OUI_CISCO_AIRONET: [u8; 3] = [0x00, 0x40, 0x96];
/// OUI for Huawei vendor IEs: `00:E0:FC`. [Wireshark oui.h]
const OUI_HUAWEI: [u8; 3] = [0x00, 0xE0, 0xFC];
/// OUI for Mist/Juniper vendor IEs: `5C:5B:35`. [Wireshark oui.h]
const OUI_MIST: [u8; 3] = [0x5C, 0x5B, 0x35];
/// OUI for Ruckus Wireless vendor IEs: `00:13:92`. [Wireshark oui.h]
const OUI_RUCKUS: [u8; 3] = [0x00, 0x13, 0x92];
/// OUI for Alcatel-Lucent Enterprise vendor IEs: `DC:08:56`. [Wireshark oui.h]
const OUI_ALE: [u8; 3] = [0xDC, 0x08, 0x56];
/// OUI for Fortinet vendor IEs: `00:09:0F`. [Wireshark oui.h]
const OUI_FORTINET: [u8; 3] = [0x00, 0x09, 0x0F];
/// OUI for Meter vendor IEs: `84:80:94`. [Wireshark oui.h]
const OUI_METER: [u8; 3] = [0x84, 0x80, 0x94];
/// OUI for Telecom Infra Project vendor IEs: `48:D0:17`. [Wireshark oui.h]
const OUI_TIP: [u8; 3] = [0x48, 0xD0, 0x17];

/// Extracts a vendor-specific AP name from a vendor IE (tag 221) value.
///
/// Checks 12 known vendor OUI+subtype combinations used by enterprise AP vendors
/// to embed the admin-configured AP hostname in Beacon/ProbeResponse IEs.
///
/// Format for most vendors: `OUI(3) + Type(1) + Subtype(1) + Name(variable)`.
/// Returns `None` if the IE doesn't match any known vendor AP name pattern, the
/// body is too short, or the name is entirely null bytes.
///
/// Sources: Wireshark `packet-ieee80211.c` dissector functions
/// `dissect_vendor_ie_aruba`, `dissect_vendor_ie_ubiquiti`, etc.
#[must_use]
pub fn extract_vendor_ap_name(ie_value: &[u8]) -> Option<Vec<u8>> {
    // Minimum: OUI(3) + Type(1) + Subtype(1) = 5 bytes before any name data.
    if ie_value.len() < 5 {
        return None;
    }
    let oui: [u8; 3] = ie_value.get(0..3)?.try_into().ok()?;
    let subtype = *ie_value.get(4)?;
    let after_subtype = ie_value.get(5..)?;

    // Cisco Aironet AP Name v2: OUI(3) + type=0xF5 + name(variable).
    // Different format -- no subtype byte, entire body after type is the name.
    // [Wireshark packet-ieee80211.c dissect_vendor_ie_aironet]
    if oui == OUI_CISCO_AIRONET {
        let ie_type = *ie_value.get(3)?;
        if ie_type == 0xF5 {
            let name = ie_value.get(4..)?;
            let trimmed = trim_trailing_nulls(name);
            if !trimmed.is_empty() {
                return Some(trimmed.to_vec());
            }
        }
        return None;
    }

    // Standard format: OUI(3) + Type(1) + Subtype(1) + Name(variable).
    // Match on (OUI, Subtype) -- Type varies by vendor but Subtype identifies the AP name.
    let name = match (oui, subtype) {
        (OUI_AEROHIVE, 33) => {
            // Aerohive: subtype(1) + hostname_len(1) + hostname(variable)
            // [Wireshark: AEROHIVE_HOSTNAME = 33]
            let hostname_len = *after_subtype.first()? as usize;
            after_subtype.get(1..1 + hostname_len)?
        },
        // Standard format vendors: OUI(3) + Type(1) + Subtype(1) + Name(variable)
        // Grouped by subtype value for nested or-pattern compliance:
        (OUI_METER, 0)                                                                  // METER_APNAME
        | (OUI_UBIQUITI | OUI_HUAWEI | OUI_MIST | OUI_ALE | OUI_FORTINET, 1)           // *_APNAME subtypes
        | (OUI_FORTINET | OUI_TIP, 2)                                                   // Fortinet model / TIP AP
        | (OUI_ARUBA | OUI_RUCKUS | OUI_FORTINET, 3)                                    // *_APNAME / Fortinet serial
        => after_subtype,
        _ => return None,
    };

    let trimmed = trim_trailing_nulls(name);
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_vec())
}

// --- OWE Transition Mode SSID ---

/// OUI for Wi-Fi Alliance vendor IEs (P2P, HS2.0, OWE, etc): `50:6F:9A`.
///
/// Distinct from `OUI_WFA` (`00:50:F2`) used by WPA/WPS/WMM. The two OUI namespaces
/// serve different WFA programs. [Wi-Fi Alliance vendor IE assignments]
pub const OUI_WFA_NEW: [u8; 3] = [0x50, 0x6F, 0x9A];

/// OWE Transition Mode IE type within `OUI_WFA_NEW` namespace.
/// [Wi-Fi Alliance OWE Specification §4]
pub const WFA_OWE_TRANSITION_TYPE: u8 = 28;

// --- Wi-Fi Direct (P2P) Device Name (OUI 50:6F:9A type 9, attribute 3) ---

/// WFA P2P (Wi-Fi Direct) IE type within the `OUI_WFA_NEW` namespace.
/// [Wi-Fi Alliance Wi-Fi Direct Technical Specification, Table 8]
pub const WFA_P2P_TYPE: u8 = 9;
/// Attribute ID for "P2P Device Info" within a P2P IE; the Device Name sits inside
/// at offset 19+ as a TLV with attribute ID 3 ("Device Name"). Per Wi-Fi Direct
/// Technical Specification §4.1.15.
const P2P_ATTR_DEVICE_INFO: u8 = 13;
/// TLV attribute ID for "Device Name" inside the P2P Device Info attribute body.
const P2P_DEV_NAME_TLV_ID: u16 = 0x1011;

/// Extracts the Device Name from a P2P (Wi-Fi Direct) vendor IE.
///
/// The IE must have OUI `50:6F:9A` and type `9`. The body is a sequence of P2P
/// attribute TLVs `[id u8][len u16 LE][value]`. Inside the "P2P Device Info"
/// attribute (id 13) the value contains a Device Name sub-TLV whose attribute ID
/// is the WPS-style 16-bit big-endian value `0x1011` followed by a 2-byte BE length
/// and the UTF-8 device name string. Returns `None` for non-P2P IEs, missing
/// device-info attributes, or truncated TLVs.
/// [Wi-Fi Alliance Wi-Fi Direct Technical Specification §4.1.15]
#[must_use]
pub fn extract_p2p_device_name(ie: &Ie<'_>) -> Option<Vec<u8>> {
    let body = vendor_ie_body(ie, OUI_WFA_NEW, WFA_P2P_TYPE)?;
    // Walk P2P attribute TLVs: [attr_id u8][attr_len u16 LE][value].
    let mut pos = 0usize;
    while pos + 3 <= body.len() {
        let attr_id = *body.get(pos)?;
        let len_bytes: [u8; 2] = body.get(pos + 1..pos + 3)?.try_into().ok()?;
        let attr_len = u16::from_le_bytes(len_bytes) as usize;
        let attr_end = pos.checked_add(3)?.checked_add(attr_len)?;
        if attr_end > body.len() {
            return None;
        }
        let attr_body = body.get(pos + 3..attr_end)?;
        if attr_id == P2P_ATTR_DEVICE_INFO {
            // Device Info layout: P2P Device Address(6) + Config Methods(2) +
            // Primary Device Type(8) + Number of Secondary Device Types(1) +
            // (Secondary Device Type List) + Device Name TLV (id 0x1011 BE +
            // length 2 BE + name).
            // Skip past the fixed-prefix and any secondary device-type list to
            // find the Device Name TLV.
            // Prefix: 6 + 2 + 8 + 1 = 17. After that, N * 8 bytes of secondary
            // device types (N = byte at offset 16), then the Device Name TLV.
            let n_secondary = usize::from(*attr_body.get(16)?);
            let dev_name_off = 17usize.checked_add(n_secondary.checked_mul(8)?)?;
            let dn_id_bytes: [u8; 2] = attr_body.get(dev_name_off..dev_name_off + 2)?.try_into().ok()?;
            if u16::from_be_bytes(dn_id_bytes) != P2P_DEV_NAME_TLV_ID {
                return None;
            }
            let dn_len_bytes: [u8; 2] = attr_body.get(dev_name_off + 2..dev_name_off + 4)?.try_into().ok()?;
            let dn_len = u16::from_be_bytes(dn_len_bytes) as usize;
            let dn = attr_body.get(dev_name_off + 4..dev_name_off + 4 + dn_len)?;
            let trimmed = trim_trailing_nulls(dn);
            if trimmed.is_empty() {
                return None;
            }
            return Some(trimmed.to_vec());
        }
        pos = attr_end;
    }
    None
}

/// Extracts the paired SSID from an OWE Transition Mode vendor IE body.
///
/// OWE Transition Mode IE (OUI `50:6F:9A`, type 28) body layout after OUI+type:
///   `BSSID(6) + SSID_Len(1) + SSID(variable) + [Band_Info(1)]`
///
/// Returns the SSID bytes, or `None` if the body is too short, SSID length is zero,
/// or the body is truncated. [Wi-Fi Alliance OWE Specification §4]
#[must_use]
pub fn extract_owe_transition_ssid(body: &[u8]) -> Option<Vec<u8>> {
    // body: BSSID(6) + SSID_Len(1) + SSID(ssid_len) + [Band(1)]
    if body.len() < 7 {
        return None;
    }
    let ssid_len = *body.get(6)? as usize;
    if ssid_len == 0 {
        return None;
    }
    let ssid = body.get(7..7 + ssid_len)?;
    if ssid.is_empty() {
        return None;
    }
    Some(ssid.to_vec())
}

// --- Utility ---

/// Trims trailing null (`0x00`) bytes from a byte slice.
///
/// Returns the prefix up to and including the last non-null byte. Returns an
/// empty slice if all bytes are null. Used by vendor AP name extractors that
/// return null-padded fixed-length name fields.
fn trim_trailing_nulls(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    bytes.get(..end).unwrap_or(bytes)
}

// --- Multi-Link Element (MLE, Extension Element ID 107) ---

/// Element ID 255 for Extension elements. [IEEE 802.11-2024] §9.4.2.1
pub const IE_ELEMENT_EXTENSION: u8 = 255;

/// Element ID Extension = 107: Multi-Link Element (802.11be).
/// [IEEE 802.11be / IEEE 802.11-2024] §9.4.2.321
pub const IE_EXT_MULTI_LINK: u8 = 107;

/// Multi-Link Element type codes in the Multi-Link Control field bits 0-2.
/// [IEEE 802.11be] §9.4.2.321, Table 9-401e
const MLE_TYPE_BASIC: u8 = 0;

/// Multi-Link Element summary -- decoded from a Basic Multi-Link Element (type 0).
///
/// The Basic MLE carries the Multi-Link Device (MLD) MAC address of the advertising
/// station. When present in a Beacon, the MLD MAC is the AP's logical identity; when
/// present in an Association Request, it is the client's MLD identity. Used to
/// canonicalize link MAC addresses to a single MLD address for `MacPair` keying.
/// [IEEE 802.11be / IEEE 802.11-2024] §9.4.2.321
#[derive(Debug, Clone, Copy)]
pub struct MleBasicInfo {
    /// MLD MAC Address from the Common Info field (bytes 4..10 of the element body).
    pub mld_mac: [u8; 6],
}

/// Parses an Extension Element body (the bytes after Element ID Extension) as a Basic MLE.
///
/// `value` is `ie.value` for an element with Element ID 255 -- that is, the first byte
/// is the Element ID Extension (107 for Multi-Link). Returns `None` if the ext ID is not
/// 107, the Multi-Link Type is not Basic (0), or the body is too short to hold the MLD
/// MAC address at bytes 4..10.
///
/// Element body layout [IEEE 802.11be] §9.4.2.321, Figure 9-1002a:
/// ```text
///   [0]     Element ID Extension (107 for MLE)
///   [1..3]  Multi-Link Control (2 bytes, little-endian):
///             bits 0-2: Type (0 = Basic, 1 = Probe Request, 2 = Reconfig, 3 = TDLS, 4 = Priority Access)
///             bits 3-15: Presence Bitmap + flags
///   [3]     Common Info Length (includes this byte; varies by Type)
///   [4..10] MLD MAC Address (Basic Type, always present)
///   ...     Optional Common Info fields gated by Presence Bitmap
///   ...     Link Info (subelement format)
/// ```
#[must_use]
pub fn parse_mle_basic(value: &[u8]) -> Option<MleBasicInfo> {
    // ie.value[0] must be ExtID 107.
    if value.first().copied()? != IE_EXT_MULTI_LINK {
        return None;
    }
    // Multi-Link Control bits 0-2 carry the Type.
    let ctrl_lo = *value.get(1)?;
    let mle_type = ctrl_lo & 0x07;
    if mle_type != MLE_TYPE_BASIC {
        return None;
    }
    // Common Info Length at byte 3 -- we don't gate on its exact value here, but the
    // MLD MAC is always at bytes 4..10 of the Basic MLE per §9.4.2.321, Figure 9-1002c.
    let mld_slice = value.get(4..10)?;
    let mld_mac: [u8; 6] = mld_slice.try_into().ok()?;
    Some(MleBasicInfo { mld_mac })
}

/// Finds the Basic Multi-Link Element in a tagged parameter block, if present.
///
/// Walks IEs looking for Element ID 255 with Element ID Extension 107 and returns the
/// first Basic MLE parse result. Returns `None` if no MLE is present or the MLE is
/// non-Basic. [IEEE 802.11be] §9.4.2.321
#[must_use]
pub fn extract_mle_basic(tagged_params: &[u8]) -> Option<MleBasicInfo> {
    for ie in iter_ies(tagged_params) {
        if ie.id == IE_ELEMENT_EXTENSION {
            if let Some(info) = parse_mle_basic(ie.value) {
                return Some(info);
            }
        }
    }
    None
}

// --- Multiple BSSID Element (tag 71) and Nontransmitted BSSID Profile (subelement 0) ---

/// Element ID for the Multiple BSSID element. [IEEE 802.11-2024] §9.4.2.45a
pub const IE_MULTIPLE_BSSID: u8 = 71;
/// Element ID for the Multiple BSSID-Index element (carried inside a Nontransmitted
/// BSSID Profile subelement to identify which sub-BSSID a profile applies to).
/// [IEEE 802.11-2024] §9.4.2.74
pub const IE_MULTIPLE_BSSID_INDEX: u8 = 83;
/// Subelement ID for "Nontransmitted BSSID Profile" inside a Multiple BSSID element.
/// [IEEE 802.11-2024] §9.4.2.45a, Table 9-220
const SUBE_NONTRANSMITTED_PROFILE: u8 = 0;

/// One nontransmitted-BSSID profile recovered from a Multiple BSSID element.
///
/// `bssid` is the synthesized sub-BSSID derived from the transmitted BSSID and the
/// profile's `Multiple BSSID-Index` subelement per [IEEE 802.11-2024] §35.2.2:
/// the low `MaxBSSID Indicator` bits of the BSSID byte 5 are replaced with
/// `((transmitted[5] & ~mask) + index) & mask`. `ssid` is the SSID element nested
/// inside the profile (IE tag 0); empty when the SSID was hidden or absent.
#[derive(Debug, Clone)]
pub struct MultipleBssidProfile {
    /// Synthesized sub-BSSID per §35.2.2.
    pub bssid: [u8; 6],
    /// Sub-BSSID's SSID, or empty when absent / hidden.
    pub ssid: Vec<u8>,
}

/// Parses a Multiple BSSID element body and returns one profile per
/// Nontransmitted BSSID Profile subelement.
///
/// Body layout per [IEEE 802.11-2024] §9.4.2.45a:
/// ```text
///   MaxBSSID Indicator (1 byte)   -- N; total max sub-BSSIDs = 2^N
///   Subelements                   -- zero or more (id, len, value)
/// ```
/// Each Nontransmitted BSSID Profile subelement (id = 0) contains nested IEs:
/// SSID (tag 0), Multiple BSSID-Index (tag 83), optional RSN IE (tag 48), etc.
/// Profiles missing the index or with mode-`11` reserved bits are skipped silently.
#[must_use]
pub fn parse_multiple_bssid(value: &[u8], transmitted_bssid: [u8; 6]) -> Vec<MultipleBssidProfile> {
    let Some(&max_indicator) = value.first() else { return Vec::new() };
    if max_indicator == 0 || max_indicator > 6 {
        // Spec caps MaxBSSID Indicator at 8 bits, but values >6 do not fit in the
        // low 6-byte BSSID byte; reject as malformed to avoid wrap/aliasing.
        return Vec::new();
    }
    let mask: u8 = (1u8 << max_indicator).saturating_sub(1);
    let mut out = Vec::new();
    // Subelement walker over the body after MaxBSSID Indicator (1 byte).
    let mut pos = 1usize;
    while pos + 2 <= value.len() {
        let sub_id = *value.get(pos).unwrap_or(&0);
        let sub_len = usize::from(*value.get(pos + 1).unwrap_or(&0));
        let sub_end = pos.saturating_add(2).saturating_add(sub_len);
        if sub_end > value.len() {
            break;
        }
        let sub_body = value.get(pos + 2..sub_end).unwrap_or(&[]);
        if sub_id == SUBE_NONTRANSMITTED_PROFILE {
            // Walk nested IEs to find SSID (tag 0) and Multiple BSSID-Index (tag 83).
            let mut ssid: Vec<u8> = Vec::new();
            let mut index: Option<u8> = None;
            for ie in iter_ies(sub_body) {
                if ie.id == 0 {
                    ssid = ie.value.to_vec();
                } else if ie.id == IE_MULTIPLE_BSSID_INDEX {
                    index = ie.value.first().copied();
                }
            }
            if let Some(idx) = index {
                // Per §35.2.2: replace low N bits of byte 5 with `((tx & ~mask) + idx) & mask`.
                let high = transmitted_bssid[5] & !mask;
                let low = (transmitted_bssid[5].wrapping_add(idx)) & mask;
                let mut bssid = transmitted_bssid;
                bssid[5] = high | low;
                out.push(MultipleBssidProfile { bssid, ssid });
            }
        }
        pos = sub_end;
    }
    out
}

// --- Reduced Neighbor Report (RNR, tag 201) ---

/// Element ID for the Reduced Neighbor Report element. [IEEE 802.11-2024] §9.4.2.170
pub const IE_REDUCED_NEIGHBOR_REPORT: u8 = 201;

/// Lowest operating class value in the 6 GHz band per IEEE 802.11-2024 Annex E, Table E-4.
///
/// Operating classes 131 through 137 are defined for the 6 GHz band (UNII-5 through
/// UNII-8). Any operating class at or above this threshold is considered 6 GHz for
/// diagnostic purposes.
const RNR_OP_CLASS_6GHZ_MIN: u8 = 131;

/// Summary of a single RNR "Neighbor AP Information" block.
///
/// Each block advertises one or more co-located or neighboring BSSIDs operating on a
/// specific channel and operating class. Used by the stats path to count 6 GHz
/// co-located BSSIDs advertised by legacy-band beacons. [IEEE 802.11-2024] §9.4.2.170.
#[derive(Debug, Clone, Copy)]
pub struct RnrNeighborInfo {
    /// Operating class per Annex E, Table E-4. Values >= 131 indicate 6 GHz.
    pub operating_class: u8,
    /// Primary channel number within the operating class.
    pub channel: u8,
    /// Number of TBTT Information fields in the block (from header bits 4-7 + 1).
    pub tbtt_count: u8,
    /// Length of each TBTT Information field in bytes (from header bits 8-15).
    pub tbtt_length: u8,
}

/// Parses an RNR IE body into a list of `RnrNeighborInfo` summaries.
///
/// Each "Neighbor AP Information" block has the layout per [IEEE 802.11-2024] §9.4.2.170,
/// Figure 9-632:
/// ```text
///   TBTT Information Header (2 bytes, little-endian):
///     bits  0-1  : TBTT Information Field Type
///     bit   2    : Filtered Neighbor AP
///     bit   3    : Reserved
///     bits  4-7  : TBTT Information Count (N) -- actual count = N + 1
///     bits  8-15 : TBTT Information Length (in bytes)
///   Operating Class (1 byte)
///   Channel Number (1 byte)
///   TBTT Information Field x (N+1)   -- each `TBTT Information Length` bytes
/// ```
///
/// Stops cleanly on truncation without panicking. Returns an empty `Vec` for an
/// empty or malformed body. Per [IEEE 802.11-2024] §9.4.2.170.
#[must_use]
pub fn parse_rnr(value: &[u8]) -> Vec<RnrNeighborInfo> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= value.len() {
        // TBTT Information Header (2 bytes LE) + Operating Class (1) + Channel (1).
        let Some(hdr_bytes) = value.get(pos..pos + 2) else { break };
        let Some(&op_class) = value.get(pos + 2) else { break };
        let Some(&channel) = value.get(pos + 3) else { break };
        let hdr_arr: [u8; 2] = match hdr_bytes.try_into() {
            Ok(a) => a,
            Err(_) => break,
        };
        let hdr = u16::from_le_bytes(hdr_arr);
        // bits 4-7: count field (N); actual number of entries = N + 1.
        let count_field = ((hdr >> 4) & 0x0F) as u8;
        let tbtt_count = count_field.saturating_add(1);
        // bits 8-15: TBTT Info Length in bytes (per-entry size).
        let tbtt_length = ((hdr >> 8) & 0xFF) as u8;
        out.push(RnrNeighborInfo { operating_class: op_class, channel, tbtt_count, tbtt_length });

        // Advance past header + op class + channel + tbtt_count * tbtt_length bytes.
        // Use checked arithmetic so a malformed length does not wrap.
        let payload = usize::from(tbtt_count).checked_mul(usize::from(tbtt_length)).unwrap_or(0);
        let step = 4usize.checked_add(payload).unwrap_or(0);
        if step == 0 || step > value.len().saturating_sub(pos) {
            break;
        }
        pos += step;
    }
    out
}

/// Extracts every BSSID embedded in an RNR IE body.
///
/// Walks each Neighbor AP Information block's TBTT Information fields. The BSSID's
/// position depends on the TBTT Information Length per [IEEE 802.11-2024] §9.4.2.170,
/// Table 9-309:
///
/// | Length | Layout                                            | BSSID at offset |
/// |--------|---------------------------------------------------|------------------|
/// | 1, 2   | TBTT Offset (+ BSS Params)                        | (none)           |
/// | 4, 5   | Short SSID (+ TBTT Offset)                        | (none)           |
/// | 6      | BSSID                                             | 0                |
/// | 7      | TBTT Offset + BSSID                               | 1                |
/// | 8      | TBTT Offset + BSSID + BSS Params                  | 1                |
/// | 9, 11+ | TBTT Offset + BSSID + Short SSID + ...            | 1                |
///
/// Returns an empty `Vec` for an empty or malformed body.
#[must_use]
pub fn extract_rnr_bssids(value: &[u8]) -> Vec<[u8; 6]> {
    let mut out: Vec<[u8; 6]> = Vec::new();
    let mut pos = 0usize;
    while pos + 4 <= value.len() {
        let Some(hdr_bytes) = value.get(pos..pos + 2) else { break };
        let hdr_arr: [u8; 2] = match hdr_bytes.try_into() {
            Ok(a) => a,
            Err(_) => break,
        };
        let hdr = u16::from_le_bytes(hdr_arr);
        let count_field = ((hdr >> 4) & 0x0F) as u8;
        let tbtt_count = count_field.saturating_add(1);
        let tbtt_length = ((hdr >> 8) & 0xFF) as usize;
        // Skip the 4-byte block header (TBTT Header + Op Class + Channel) before
        // the TBTT Information fields.
        let mut entry_pos = pos.saturating_add(4);
        for _ in 0..tbtt_count {
            let entry_end = entry_pos.saturating_add(tbtt_length);
            if entry_end > value.len() {
                break;
            }
            let entry = value.get(entry_pos..entry_end).unwrap_or(&[]);
            // BSSID position depends on TBTT Information Length (see table above).
            let bssid_off = match tbtt_length {
                6 => Some(0usize),
                n if n >= 7 => Some(1usize),
                _ => None,
            };
            if let Some(off) = bssid_off {
                if let Some(slice) = entry.get(off..off + 6) {
                    if let Ok(arr) = <[u8; 6]>::try_from(slice) {
                        out.push(arr);
                    }
                }
            }
            entry_pos = entry_end;
        }
        let payload = usize::from(tbtt_count).checked_mul(tbtt_length).unwrap_or(0);
        let step = 4usize.checked_add(payload).unwrap_or(0);
        if step == 0 || step > value.len().saturating_sub(pos) {
            break;
        }
        pos += step;
    }
    out
}

/// Returns `true` if the operating class falls in the 6 GHz band per Annex E, Table E-4.
///
/// 6 GHz operating classes are 131 through 137 (UNII-5 through UNII-8). Used for
/// diagnostic counters. [IEEE 802.11-2024] Annex E, Table E-4.
#[must_use]
pub const fn rnr_is_6ghz_class(op_class: u8) -> bool {
    op_class >= RNR_OP_CLASS_6GHZ_MIN
}

/// Returns the operating channel number from the DS Parameter Set IE (tag 3), if present.
///
/// The DS Parameter Set is a 1-byte IE carrying the current channel number: 1-14 for
/// 2.4 GHz and 36-165 for 5 GHz. Absent on some captures (AP relies on channel in radio
/// header instead). Per [IEEE 802.11-2024] §9.4.2.4.
#[must_use]
pub fn extract_ds_channel(ies: &[u8]) -> Option<u8> {
    for ie in iter_ies(ies) {
        if ie.id == 3 {
            // DS Parameter Set: 1-byte channel number. [IEEE 802.11-2024] §9.4.2.4
            return ie.value.first().copied();
        }
    }
    None
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
        reason = "test module"
    )]

    use super::*;

    // --- IeIter tests ---

    #[test]
    fn ie_iter_empty() {
        // Empty slice must produce zero items without panicking.
        assert_eq!(iter_ies(&[]).count(), 0);
    }

    #[test]
    fn ie_iter_single() {
        // [ID=0, Length=4, 1, 2, 3, 4] -> one IE with the expected id and value.
        let data = [0u8, 4, 1, 2, 3, 4];
        let ies: Vec<_> = iter_ies(&data).collect();
        assert_eq!(ies.len(), 1);
        assert_eq!(ies[0].id, 0);
        assert_eq!(ies[0].value, &[1u8, 2, 3, 4]);
    }

    #[test]
    fn ie_iter_two() {
        // Two back-to-back IEs must both be returned.
        // IE1: ID=0, len=2, value=[0xAA, 0xBB]
        // IE2: ID=48, len=3, value=[0x01, 0x02, 0x03]
        let data = [0u8, 2, 0xAA, 0xBB, 48, 3, 0x01, 0x02, 0x03];
        let ies: Vec<_> = iter_ies(&data).collect();
        assert_eq!(ies.len(), 2);
        assert_eq!(ies[0].id, 0);
        assert_eq!(ies[0].value, &[0xAAu8, 0xBB]);
        assert_eq!(ies[1].id, 48);
        assert_eq!(ies[1].value, &[0x01u8, 0x02, 0x03]);
    }

    #[test]
    fn ie_iter_truncated_stops() {
        // IE claims length=10 but only 2 value bytes are present -- must stop, not panic.
        let data = [0u8, 10, 0x01, 0x02];
        assert_eq!(iter_ies(&data).count(), 0, "truncated IE must yield nothing");
    }

    #[test]
    fn ie_iter_missing_length_byte() {
        // Only 1 byte remaining (ID only, no length byte) -- must stop cleanly.
        let data = [42u8];
        assert_eq!(iter_ies(&data).count(), 0);
    }

    #[test]
    fn ie_iter_ssid_and_rsn() {
        // Two IEs: SSID (ID=0) and RSN (ID=48) with known values.
        let ssid = b"testnet";
        let rsn_body = [0x01u8, 0x00]; // minimal RSN body for test purposes
        let mut data = Vec::new();
        data.push(0u8); // ID: SSID
        data.push(ssid.len() as u8);
        data.extend_from_slice(ssid);
        data.push(48u8); // ID: RSN
        data.push(rsn_body.len() as u8);
        data.extend_from_slice(&rsn_body);

        let ies: Vec<_> = iter_ies(&data).collect();
        assert_eq!(ies.len(), 2);
        assert_eq!(ies[0].id, 0);
        assert_eq!(ies[0].value, ssid.as_ref());
        assert_eq!(ies[1].id, 48);
        assert_eq!(ies[1].value, &rsn_body);
    }

    // --- vendor_ie_body tests ---

    #[test]
    fn vendor_ie_body_match() {
        // Correct OUI + type -> returns the body slice after the 4-byte prefix.
        let oui = [0x00u8, 0x50, 0xF2];
        let ie_type = 4u8;
        let body_payload = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let mut value = Vec::new();
        value.extend_from_slice(&oui);
        value.push(ie_type);
        value.extend_from_slice(&body_payload);
        let ie = Ie { id: 221, value: &value };
        let result = vendor_ie_body(&ie, oui, ie_type);
        assert_eq!(result, Some(body_payload.as_ref()));
    }

    #[test]
    fn vendor_ie_body_wrong_oui() {
        // Different OUI -> None.
        let value = [0x00u8, 0x0F, 0xAC, 0x04, 0xAA, 0xBB];
        let ie = Ie { id: 221, value: &value };
        assert!(vendor_ie_body(&ie, [0x00, 0x50, 0xF2], 4).is_none());
    }

    #[test]
    fn vendor_ie_body_wrong_type() {
        // Correct OUI but wrong type byte -> None.
        let value = [0x00u8, 0x50, 0xF2, 0x01, 0xAA, 0xBB]; // type 1, not 4
        let ie = Ie { id: 221, value: &value };
        assert!(vendor_ie_body(&ie, [0x00, 0x50, 0xF2], 4).is_none());
    }

    #[test]
    fn vendor_ie_body_not_vendor() {
        // Element ID is not 221 -> None regardless of value content.
        let value = [0x00u8, 0x50, 0xF2, 0x04, 0xAA];
        let ie = Ie { id: 48, value: &value }; // RSN IE, not vendor
        assert!(vendor_ie_body(&ie, [0x00, 0x50, 0xF2], 4).is_none());
    }

    // --- WPS parser tests ---

    /// Builds a raw WPS attribute TLV for test use.
    fn wps_attr(attr_type: u16, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&attr_type.to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    #[test]
    fn wps_parse_manufacturer() {
        // Body containing only a Manufacturer attribute -> WpsInfo.manufacturer is set correctly.
        let mfr = b"Acme Corp";
        let body = wps_attr(WPS_ATTR_MANUFACTURER, mfr);
        let info = parse_wps_body(&body);
        assert_eq!(info.manufacturer, mfr.as_ref());
        assert!(info.model_name.is_empty());
        assert!(info.uuid_e.is_none());
    }

    #[test]
    fn wps_parse_uuid_e() {
        // Body containing a 16-byte UUID-E attribute -> WpsInfo.uuid_e = Some([...]).
        let uuid: [u8; 16] =
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let body = wps_attr(WPS_ATTR_UUID_E, &uuid);
        let info = parse_wps_body(&body);
        assert_eq!(info.uuid_e, Some(uuid));
    }

    #[test]
    fn wps_parse_truncated_attr() {
        // attr_len > remaining body -> iteration stops without panic.
        // Attribute claims 100 bytes but body is only the 4-byte header with 2 bytes of value.
        let mut body = Vec::new();
        body.extend_from_slice(&WPS_ATTR_MANUFACTURER.to_be_bytes());
        body.extend_from_slice(&100u16.to_be_bytes()); // claims 100 bytes
        body.extend_from_slice(&[0xAAu8, 0xBB]); // only 2 bytes present
        let info = parse_wps_body(&body);
        // Truncated attribute must not be stored.
        assert!(info.manufacturer.is_empty(), "truncated attribute must not be stored");
    }

    #[test]
    fn wps_parse_unknown_attr() {
        // Unknown attribute type is skipped; attributes after it are still parsed.
        let mut body = Vec::new();
        // Unknown attribute 0xFFFF with 2-byte value.
        body.extend_from_slice(&0xFFFFu16.to_be_bytes());
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0xAAu8, 0xBB]);
        // Known: Model Name after the unknown attr.
        let model = b"RouterX";
        body.extend_from_slice(&wps_attr(WPS_ATTR_MODEL_NAME, model));

        let info = parse_wps_body(&body);
        assert!(info.manufacturer.is_empty(), "unknown attr must not populate manufacturer");
        assert_eq!(info.model_name, model.as_ref(), "model_name must be parsed after unknown attr");
    }

    // --- extract_ssid_list tests ---

    #[test]
    fn ssid_list_empty() {
        assert!(extract_ssid_list(&[]).is_empty());
    }

    #[test]
    fn ssid_list_single() {
        // One embedded SSID element: [tag=0, len=4, "test"]
        let data = [0u8, 4, b't', b'e', b's', b't'];
        let result = extract_ssid_list(&data);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], b"test");
    }

    #[test]
    fn ssid_list_two() {
        // Two embedded SSID elements back-to-back.
        let mut data = Vec::new();
        data.extend_from_slice(&[0, 3, b'a', b'a', b'a']); // "aaa"
        data.extend_from_slice(&[0, 3, b'b', b'b', b'b']); // "bbb"
        let result = extract_ssid_list(&data);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], b"aaa");
        assert_eq!(result[1], b"bbb");
    }

    #[test]
    fn ssid_list_skips_empty_ssid() {
        // Empty SSID (len=0) is skipped per wildcard SSID semantics.
        let data = [0u8, 0]; // tag=0, len=0
        assert!(extract_ssid_list(&data).is_empty());
    }

    #[test]
    fn ssid_list_truncated() {
        // Embedded SSID claims 10 bytes but only 2 present -- stops cleanly.
        let data = [0u8, 10, b'x', b'y'];
        assert!(extract_ssid_list(&data).is_empty());
    }

    // --- extract_country_code tests ---

    #[test]
    fn country_code_valid() {
        // "US" + environment byte
        let value = [b'U', b'S', 0x20];
        assert_eq!(extract_country_code(&value), Some([b'U', b'S']));
    }

    #[test]
    fn country_code_lowercase() {
        // "de" -- some implementations use lowercase
        let value = [b'd', b'e', 0x20];
        assert_eq!(extract_country_code(&value), Some([b'd', b'e']));
    }

    #[test]
    fn country_code_too_short() {
        assert_eq!(extract_country_code(b"U"), None);
        assert_eq!(extract_country_code(&[]), None);
    }

    #[test]
    fn country_code_non_alpha() {
        // Non-alphabetic bytes
        let value = [0x00, 0x01, 0x20];
        assert_eq!(extract_country_code(&value), None);
    }

    // --- Mesh ID tests ---

    #[test]
    fn mesh_id_constant() {
        assert_eq!(IE_MESH_ID, 114);
    }

    // --- CCX1 AP name tests ---

    #[test]
    fn ccx1_ap_name_valid() {
        // 10 bytes of fixed fields + 16-byte null-padded AP name "lobby-ap-01"
        let mut body = vec![0u8; 10]; // fixed fields
        let name = b"lobby-ap-01\0\0\0\0\0";
        body.extend_from_slice(name);
        assert_eq!(extract_ccx1_ap_name(&body), Some(b"lobby-ap-01".to_vec()));
    }

    #[test]
    fn ccx1_ap_name_too_short() {
        // Body shorter than 26 bytes -> None
        let body = vec![0u8; 20];
        assert_eq!(extract_ccx1_ap_name(&body), None);
    }

    #[test]
    fn ccx1_ap_name_all_null() {
        // AP name is all nulls -> None
        let body = vec![0u8; 26];
        assert_eq!(extract_ccx1_ap_name(&body), None);
    }

    // --- vendor AP name tests ---

    #[test]
    fn vendor_ap_name_aruba() {
        // Aruba: OUI(3) + Type(1) + Subtype=3(1) + "ap-lobby"
        let mut value = Vec::new();
        value.extend_from_slice(&OUI_ARUBA);
        value.push(0x01); // type
        value.push(3); // subtype = ARUBA_APNAME
        value.extend_from_slice(b"ap-lobby");
        assert_eq!(extract_vendor_ap_name(&value), Some(b"ap-lobby".to_vec()));
    }

    #[test]
    fn vendor_ap_name_ubiquiti() {
        let mut value = Vec::new();
        value.extend_from_slice(&OUI_UBIQUITI);
        value.push(0x06); // type
        value.push(1); // subtype = UBIQUITI_APNAME
        value.extend_from_slice(b"unifi-corridor");
        assert_eq!(extract_vendor_ap_name(&value), Some(b"unifi-corridor".to_vec()));
    }

    #[test]
    fn vendor_ap_name_fortinet_name_model_serial() {
        // Fortinet subtypes 1 (name), 2 (model), 3 (serial) all extract
        for subtype in [1u8, 2, 3] {
            let mut value = Vec::new();
            value.extend_from_slice(&OUI_FORTINET);
            value.push(0x00); // type
            value.push(subtype);
            value.extend_from_slice(b"FAP-231F");
            assert_eq!(extract_vendor_ap_name(&value), Some(b"FAP-231F".to_vec()));
        }
    }

    #[test]
    fn vendor_ap_name_cisco_aironet_v2() {
        // Cisco Aironet AP Name v2: OUI(3) + type=0xF5 + name
        let mut value = Vec::new();
        value.extend_from_slice(&OUI_CISCO_AIRONET);
        value.push(0xF5); // AP name v2 type
        value.extend_from_slice(b"cisco-ap-3f\0\0\0\0");
        assert_eq!(extract_vendor_ap_name(&value), Some(b"cisco-ap-3f".to_vec()));
    }

    #[test]
    fn vendor_ap_name_unknown_oui() {
        // Unknown OUI -> None
        let value = [0xAA, 0xBB, 0xCC, 0x01, 0x03, b'x', b'y'];
        assert_eq!(extract_vendor_ap_name(&value), None);
    }

    #[test]
    fn vendor_ap_name_too_short() {
        // Only 4 bytes -> None (need at least 5)
        let value = [0x00, 0x0B, 0x86, 0x01];
        assert_eq!(extract_vendor_ap_name(&value), None);
    }

    #[test]
    fn vendor_ap_name_null_trimmed() {
        // Name with trailing nulls gets trimmed
        let mut value = Vec::new();
        value.extend_from_slice(&OUI_MIST);
        value.push(0x01); // type
        value.push(1); // subtype = MIST_APNAME
        value.extend_from_slice(b"mist-ap\0\0\0");
        assert_eq!(extract_vendor_ap_name(&value), Some(b"mist-ap".to_vec()));
    }

    #[test]
    fn vendor_ap_name_aerohive_hostname() {
        // Aerohive: OUI(3) + Type(1) + Subtype=33(1) + hostname_len(1) + hostname
        let mut value = Vec::new();
        value.extend_from_slice(&OUI_AEROHIVE);
        value.push(0x01); // type
        value.push(33); // subtype = AEROHIVE_HOSTNAME
        value.push(7); // hostname length
        value.extend_from_slice(b"hive-01");
        assert_eq!(extract_vendor_ap_name(&value), Some(b"hive-01".to_vec()));
    }

    // --- OWE Transition Mode SSID tests ---

    #[test]
    fn owe_transition_ssid_valid() {
        // BSSID(6) + SSID_Len(7) + "OpenNet"
        let mut body = Vec::new();
        body.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // BSSID
        body.push(7); // SSID length
        body.extend_from_slice(b"OpenNet");
        assert_eq!(extract_owe_transition_ssid(&body), Some(b"OpenNet".to_vec()));
    }

    #[test]
    fn owe_transition_ssid_too_short() {
        let body = [0u8; 5]; // need at least 7
        assert_eq!(extract_owe_transition_ssid(&body), None);
    }

    #[test]
    fn owe_transition_ssid_zero_len() {
        let mut body = vec![0u8; 6]; // BSSID
        body.push(0); // SSID length = 0
        assert_eq!(extract_owe_transition_ssid(&body), None);
    }

    #[test]
    fn owe_transition_ssid_truncated() {
        // SSID_Len claims 10 but only 3 bytes available
        let mut body = vec![0u8; 6]; // BSSID
        body.push(10); // SSID length = 10
        body.extend_from_slice(b"abc"); // only 3 bytes
        assert_eq!(extract_owe_transition_ssid(&body), None);
    }

    // --- trim_trailing_nulls tests ---

    #[test]
    fn trim_nulls_no_nulls() {
        assert_eq!(trim_trailing_nulls(b"hello"), b"hello");
    }

    #[test]
    fn trim_nulls_trailing() {
        assert_eq!(trim_trailing_nulls(b"hello\0\0\0"), b"hello");
    }

    #[test]
    fn trim_nulls_all_null() {
        assert_eq!(trim_trailing_nulls(&[0u8; 5]), b"");
    }

    #[test]
    fn trim_nulls_empty() {
        assert_eq!(trim_trailing_nulls(&[]), b"");
    }

    // --- extract_ds_channel tests ---

    #[test]
    fn ds_channel_ch6() {
        // DS Parameter Set IE: tag=3, len=1, value=6 (2.4 GHz ch 6)
        let ies = [3u8, 1, 6];
        assert_eq!(extract_ds_channel(&ies), Some(6));
    }

    #[test]
    fn ds_channel_ch36() {
        // DS Parameter Set IE: 5 GHz channel 36
        let ies = [3u8, 1, 36];
        assert_eq!(extract_ds_channel(&ies), Some(36));
    }

    #[test]
    fn ds_channel_ch11() {
        // Channel 11 (2.4 GHz, North America high end)
        let ies = [3u8, 1, 11];
        assert_eq!(extract_ds_channel(&ies), Some(11));
    }

    #[test]
    fn ds_channel_absent() {
        // Only an SSID IE (tag 0); no DS Parameter Set -> None
        let ies = [0u8, 4, b'w', b'i', b'f', b'i'];
        assert_eq!(extract_ds_channel(&ies), None);
    }

    #[test]
    fn ds_channel_empty_ies() {
        assert_eq!(extract_ds_channel(&[]), None);
    }

    #[test]
    fn ds_channel_zero_length_value() {
        // Tag 3 present but length 0 -- no channel byte -> None
        let ies = [3u8, 0];
        assert_eq!(extract_ds_channel(&ies), None);
    }

    #[test]
    fn ds_channel_after_other_ie() {
        // SSID IE followed by DS Parameter Set IE -- iterator must reach tag 3
        let mut ies = vec![0u8, 4, b't', b'e', b's', b't'];
        ies.extend_from_slice(&[3, 1, 11]);
        assert_eq!(extract_ds_channel(&ies), Some(11));
    }

    // --- MLE (ext tag 107) tests ---

    /// Builds an Extension Element value for a minimal Basic MLE (type 0).
    fn basic_mle_value(mld_mac: [u8; 6]) -> Vec<u8> {
        // [ExtID=107] [Ctrl LE = 0x0000 -> Basic type] [Common Info Length=7] [MLD MAC x6]
        let mut v = vec![IE_EXT_MULTI_LINK];
        v.extend_from_slice(&[0x00, 0x00]); // Multi-Link Control -> type = 0 (Basic)
        v.push(0x07); // Common Info Length (includes itself + 6 bytes of MAC)
        v.extend_from_slice(&mld_mac);
        v
    }

    #[test]
    fn mle_basic_parse_mld_mac() {
        let mld = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let value = basic_mle_value(mld);
        let info = parse_mle_basic(&value).unwrap();
        assert_eq!(info.mld_mac, mld);
    }

    #[test]
    fn mle_basic_wrong_extension_id_returns_none() {
        // Extension ID other than 107 -> not an MLE.
        let mut value = basic_mle_value([0u8; 6]);
        value[0] = 42; // some other ext element
        assert!(parse_mle_basic(&value).is_none());
    }

    #[test]
    fn mle_basic_non_basic_type_returns_none() {
        // Control byte bits 0-2 = 1 (Probe Request MLE) -> we only parse Basic.
        let mut value = basic_mle_value([0u8; 6]);
        value[1] = 0x01; // type = 1 (Probe Request)
        assert!(parse_mle_basic(&value).is_none());
    }

    #[test]
    fn mle_basic_truncated_no_mld_mac_returns_none() {
        // Value ends before the MLD MAC field.
        let truncated = [IE_EXT_MULTI_LINK, 0x00, 0x00, 0x07, 0xAA];
        assert!(parse_mle_basic(&truncated).is_none());
    }

    #[test]
    fn mle_basic_empty_body_returns_none() {
        assert!(parse_mle_basic(&[]).is_none());
    }

    #[test]
    fn extract_mle_basic_in_tagged_params() {
        // Build a tagged block: SSID IE (tag 0) followed by the Extension IE (tag 255).
        let mld = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let mle_value = basic_mle_value(mld);
        let mut tagged = vec![0u8, 4, b't', b'e', b's', b't']; // SSID "test"
        tagged.push(IE_ELEMENT_EXTENSION);
        tagged.push(mle_value.len() as u8);
        tagged.extend_from_slice(&mle_value);
        let info = extract_mle_basic(&tagged).unwrap();
        assert_eq!(info.mld_mac, mld);
    }

    #[test]
    fn extract_mle_basic_absent_returns_none() {
        // Only an SSID IE -> no MLE.
        let tagged = [0u8, 4, b't', b'e', b's', b't'];
        assert!(extract_mle_basic(&tagged).is_none());
    }

    // --- RNR (tag 201) tests ---

    /// Builds a single "Neighbor AP Information" block with `count` TBTT entries of `length` bytes each.
    fn rnr_block(op_class: u8, channel: u8, count: u8, length: u8, entries_payload: &[u8]) -> Vec<u8> {
        // count_field (bits 4-7) = count - 1; length_field (bits 8-15) = length.
        let count_nibble = u16::from((count.saturating_sub(1)) & 0x0F);
        let length_byte = u16::from(length);
        let hdr: u16 = (count_nibble << 4) | (length_byte << 8);
        let mut buf = Vec::new();
        buf.extend_from_slice(&hdr.to_le_bytes());
        buf.push(op_class);
        buf.push(channel);
        buf.extend_from_slice(entries_payload);
        buf
    }

    #[test]
    fn rnr_parse_single_block_minimal() {
        // One block, one TBTT entry, TBTT length = 1 (TBTT Offset only).
        let block = rnr_block(81, 6, 1, 1, &[0u8]);
        let out = parse_rnr(&block);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].operating_class, 81);
        assert_eq!(out[0].channel, 6);
        assert_eq!(out[0].tbtt_count, 1);
        assert_eq!(out[0].tbtt_length, 1);
    }

    #[test]
    fn rnr_parse_6ghz_co_located() {
        // 6 GHz channel advertised by a 2.4 GHz beacon. Operating class 131 = UNII-5 6 GHz.
        // TBTT length = 7 (Offset + BSSID).
        let bssid = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut payload = vec![0u8]; // TBTT Offset
        payload.extend_from_slice(&bssid);
        let block = rnr_block(131, 5, 1, 7, &payload);
        let out = parse_rnr(&block);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].operating_class, 131);
        assert!(rnr_is_6ghz_class(out[0].operating_class));
    }

    #[test]
    fn rnr_parse_two_blocks() {
        // Block 1: class 115 (5 GHz) with 2 TBTT entries of length 1.
        let b1 = rnr_block(115, 36, 2, 1, &[0u8, 1u8]);
        // Block 2: class 131 (6 GHz) with 1 TBTT entry of length 7.
        let mut p2 = vec![0u8];
        p2.extend_from_slice(&[0xAAu8; 6]);
        let b2 = rnr_block(131, 5, 1, 7, &p2);

        let mut combined = Vec::new();
        combined.extend_from_slice(&b1);
        combined.extend_from_slice(&b2);
        let out = parse_rnr(&combined);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].operating_class, 115);
        assert_eq!(out[0].tbtt_count, 2);
        assert_eq!(out[1].operating_class, 131);
    }

    #[test]
    fn rnr_parse_truncated_stops_cleanly() {
        // Header + op_class + channel is only 4 bytes, and the block advertises
        // 3 TBTT entries of length 7 bytes each = 21 bytes of payload expected, but only 2 bytes provided.
        let mut block = rnr_block(115, 36, 3, 7, &[0xAAu8, 0xBBu8]);
        // Truncate the trailing payload to leave only the 4-byte block header visible.
        block.truncate(6);
        let out = parse_rnr(&block);
        // First block is parsed (we accept the header) but iteration stops when the payload overruns.
        // The parser currently stops cleanly after registering the block if the payload is short;
        // either outcome (0 or 1 blocks) is acceptable as long as there is no panic.
        assert!(out.len() <= 1);
    }

    #[test]
    fn rnr_parse_empty_body() {
        assert!(parse_rnr(&[]).is_empty());
    }

    #[test]
    fn rnr_is_6ghz_class_boundaries() {
        assert!(!rnr_is_6ghz_class(81)); // 2.4 GHz
        assert!(!rnr_is_6ghz_class(115)); // 5 GHz
        assert!(!rnr_is_6ghz_class(130)); // still 5 GHz
        assert!(rnr_is_6ghz_class(131)); // UNII-5
        assert!(rnr_is_6ghz_class(137)); // UNII-8
    }

    // --- Multiple BSSID (tag 71) ---

    #[test]
    fn multiple_bssid_single_profile() {
        // MaxBSSID Indicator = 2 -> mask = 0b11. Index 1 -> sub-BSSID byte 5
        // becomes (tx[5] & ~0b11) | ((tx[5] + 1) & 0b11).
        // Body: MaxBSSID(1) | sube_id(0) | sube_len(N) | nested IEs
        //   nested IEs: SSID(tag=0, len=4, "test") | BSSID-Index(tag=83, len=1, val=1)
        let mut sube = vec![0u8, 4, b't', b'e', b's', b't']; // SSID "test"
        sube.extend_from_slice(&[83u8, 1, 1]); // Multiple BSSID-Index = 1
        let body = {
            let mut v = vec![2u8, 0, sube.len() as u8];
            v.extend_from_slice(&sube);
            v
        };
        let tx = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00];
        let profiles = parse_multiple_bssid(&body, tx);
        assert_eq!(profiles.len(), 1);
        // mask = 0b11; high = 0x00; low = (0x00 + 1) & 0b11 = 1; byte 5 = 0x01.
        assert_eq!(profiles[0].bssid[5], 0x01);
        assert_eq!(profiles[0].bssid[..5], tx[..5]);
        assert_eq!(profiles[0].ssid, b"test");
    }

    #[test]
    fn multiple_bssid_invalid_max_indicator() {
        // MaxBSSID = 0 (per spec >= 1) -> empty result. MaxBSSID = 7 (>6 bits) -> empty.
        assert!(parse_multiple_bssid(&[0u8], [0; 6]).is_empty());
        assert!(parse_multiple_bssid(&[7u8], [0; 6]).is_empty());
    }

    #[test]
    fn multiple_bssid_skip_profile_without_index() {
        // Subelement that lacks a Multiple BSSID-Index nested IE must be silently skipped.
        let sube = vec![0u8, 4, b'n', b'o', b'i', b'x']; // SSID only, no index
        let body = {
            let mut v = vec![1u8, 0, sube.len() as u8];
            v.extend_from_slice(&sube);
            v
        };
        let profiles = parse_multiple_bssid(&body, [0xAA; 6]);
        assert!(profiles.is_empty());
    }

    // --- RNR BSSID extraction ---

    #[test]
    fn rnr_extract_bssids_length_7() {
        // One Neighbor AP block: TBTT Header (count=0 -> 1 entry, len=7),
        // Op Class, Channel, then 1 entry: TBTT Offset(1) + BSSID(6).
        let mut body: Vec<u8> = Vec::new();
        // TBTT Information Header LE: count=0(<<4), length=7(<<8) -> 0x0700
        body.extend_from_slice(&0x0700u16.to_le_bytes());
        body.push(81); // op class (2.4 GHz)
        body.push(6); // channel
        body.push(0x10); // TBTT Offset
        body.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34]); // BSSID
        let bssids = extract_rnr_bssids(&body);
        assert_eq!(bssids, vec![[0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34]]);
    }

    #[test]
    fn rnr_extract_bssids_length_6_at_offset_zero() {
        // Length-6 entry: BSSID at offset 0 (no TBTT Offset prefix).
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&0x0600u16.to_le_bytes()); // count=1, length=6
        body.push(81);
        body.push(6);
        body.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let bssids = extract_rnr_bssids(&body);
        assert_eq!(bssids, vec![[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]]);
    }

    #[test]
    fn rnr_extract_bssids_no_bssid_for_length_2() {
        // Length-2 entries (TBTT Offset + BSS Params) carry no BSSID.
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&0x0200u16.to_le_bytes());
        body.push(81);
        body.push(6);
        body.extend_from_slice(&[0xAA, 0xBB]);
        assert!(extract_rnr_bssids(&body).is_empty());
    }

    // --- P2P Device Name ---

    #[test]
    fn extract_p2p_device_name_present() {
        // Build: WFA P2P vendor IE (OUI 50:6F:9A type 9) with one Device Info attribute.
        // Device Info: dev_addr(6) + cfg_methods(2) + primary_dev_type(8) + 0 sec_dev_types
        //              + Device Name TLV (id 0x1011 BE + len BE + name).
        let name = b"MyPhone";
        let mut dev_info = Vec::new();
        dev_info.extend_from_slice(&[0u8; 6]); // P2P Device Address
        dev_info.extend_from_slice(&[0u8; 2]); // Config Methods
        dev_info.extend_from_slice(&[0u8; 8]); // Primary Device Type
        dev_info.push(0); // 0 Secondary Device Types
        dev_info.extend_from_slice(&0x1011u16.to_be_bytes()); // Device Name TLV id (BE)
        dev_info.extend_from_slice(&(name.len() as u16).to_be_bytes()); // length BE
        dev_info.extend_from_slice(name);

        // P2P attribute TLV: [id=13][len LE u16][value]
        let mut p2p_body = Vec::new();
        p2p_body.push(13u8);
        p2p_body.extend_from_slice(&(dev_info.len() as u16).to_le_bytes());
        p2p_body.extend_from_slice(&dev_info);

        // Vendor IE: [tag=221][len][OUI 50:6F:9A][type=9][p2p_body]
        let mut ie_value = Vec::new();
        ie_value.extend_from_slice(&[0x50, 0x6F, 0x9A, 9]);
        ie_value.extend_from_slice(&p2p_body);
        let ie = Ie { id: 221, value: &ie_value };
        let result = extract_p2p_device_name(&ie);
        assert_eq!(result.as_deref(), Some(name.as_ref()));
    }

    #[test]
    fn extract_p2p_device_name_wrong_oui_returns_none() {
        let ie = Ie { id: 221, value: &[0x00, 0x50, 0xF2, 9, 0, 0, 0] };
        assert!(extract_p2p_device_name(&ie).is_none());
    }

    #[test]
    fn extract_p2p_device_name_no_device_info_attr() {
        // Vendor IE with WFA P2P OUI/type but no attribute id 13 -> None.
        let mut ie_value = vec![0x50, 0x6F, 0x9A, 9];
        // Add a different attribute (id=14) with empty body.
        ie_value.extend_from_slice(&[14u8, 0, 0]);
        let ie = Ie { id: 221, value: &ie_value };
        assert!(extract_p2p_device_name(&ie).is_none());
    }
}
