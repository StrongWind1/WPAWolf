//! Shared -- types and primitives. `HashType` encodes the 11-type classification in ARCHITECTURE.md §2.
//!
//! This module sits at the bottom of the dependency DAG -- it imports only from `std`.
//! All public types implement `Send + Sync` (enforced by `Copy` / `#[derive]`) so the
//! Phase 4 multi-threaded pairing engine (`std::thread::scope`, `--threads N`) shares
//! them across worker threads without locks.

// --- MAC addresses ---

/// 6-byte IEEE 802.11 MAC address.
///
/// Stored as a fixed-size byte array for cheap `Copy` semantics and use as a
/// `HashMap` key without heap allocation. `MacAddr::from_bytes` is the canonical
/// constructor; `Display` formats as lowercase colon-separated hex.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// Constructs a `MacAddr` from a raw 6-byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Returns a `Display`-implementing wrapper that formats the MAC as 12 lowercase
    /// hex characters with no separators (e.g. `aabbccddeeff`).
    ///
    /// Allocation-free in `write!` / `format_args!` / log-line `format!` contexts:
    /// the wrapper writes directly into the formatter rather than building an
    /// intermediate `String`. Call `.to_string()` on the result if an owned
    /// `String` is genuinely required.
    #[must_use]
    pub const fn hex_lower(&self) -> MacHexLower<'_> {
        MacHexLower(self)
    }
}

impl std::fmt::Display for MacAddr {
    /// Formats as lowercase colon-separated hex, e.g. `"aa:bb:cc:dd:ee:ff"`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = &self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
    }
}

impl std::fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

/// Display wrapper for the compact, no-separator hex form of a `MacAddr`.
///
/// Formats as 12 lowercase hex characters (e.g. `aabbccddeeff`). Used in
/// hashcat hash-line fields and structured-log lines where the compact form
/// is required. Returned by `MacAddr::hex_lower`; never constructed directly
/// outside this module.
#[derive(Clone, Copy, Debug)]
pub struct MacHexLower<'a>(&'a MacAddr);

impl std::fmt::Display for MacHexLower<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = &self.0.0;
        write!(f, "{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3], b[4], b[5])
    }
}

// --- AP/STA grouping key ---

/// (AP, STA) pair used as the primary grouping key for `MessageStore` and `PmkidStore`.
///
/// Derived from the To DS / From DS fields of the 802.11 MAC header per
/// IEEE 802.11-2024 §9.3.2.1.2, Table 9-60. 12 bytes, `Copy`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct MacPair {
    /// The access point MAC address (BSSID role).
    pub ap: MacAddr,
    /// The station MAC address (client role).
    pub sta: MacAddr,
}

impl MacPair {
    /// Constructs a `MacPair` from AP and STA addresses.
    #[must_use]
    pub const fn new(ap: MacAddr, sta: MacAddr) -> Self {
        Self { ap, sta }
    }
}

// --- EAPOL message classification ---

/// EAPOL-Key message type within the 4-way handshake.
///
/// Message identity is determined from the Key Information bit fields per
/// IEEE 802.11-2024 §12.7.2, Figure 12-36:
/// - M1: ACK=1, MIC=0
/// - M2: ACK=0, MIC=1, Secure=0
/// - M3: ACK=1, MIC=1, Install=1, Secure=1
/// - M4: ACK=0, MIC=1, Secure=1, Nonce=all-zeros (per spec; some implementations deviate)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum MsgType {
    /// EAPOL-Key Message 1: AP -> STA, carries `ANonce`.
    M1 = 1,
    /// EAPOL-Key Message 2: STA -> AP, carries `SNonce` + MIC.
    M2 = 2,
    /// EAPOL-Key Message 3: AP -> STA, carries `ANonce` + GTK (encrypted).
    M3 = 3,
    /// EAPOL-Key Message 4: STA -> AP, confirms PTK installation.
    M4 = 4,
}

impl std::fmt::Display for MsgType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::M1 => f.write_str("m1"),
            Self::M2 => f.write_str("m2"),
            Self::M3 => f.write_str("m3"),
            Self::M4 => f.write_str("m4"),
        }
    }
}

// --- AKM suite types ---

/// AKM (Authentication and Key Management) suite type detected from RSN IE, WPA1
/// vendor IE, or Beacon.
///
/// AKM type bytes are read from the RSN IE AKM Suite List (OUI `00:0F:AC`) per
/// IEEE 802.11-2024 §9.4.2.24, Table 9-190; the WPA1 vendor IE (OUI `00:50:F2`,
/// type 1) is treated equivalently for the legacy WPA1-PSK case. The AKM
/// determines both the PMKID derivation algorithm and the hashcat output mode
/// (22000 vs 37100).
///
/// Each variant maps to one row of the 11-type classification in `ARCHITECTURE.md §2`
/// via `HashType::from_akm_and_attack`. Splitting `Psk` into `Wpa1` (legacy WPA1
/// PSK) and `Wpa2Psk` (WPA2 AKM 2), and splitting the SHA-256 / SHA-384 variants
/// (`FtPsk` vs `FtPskSha384`, `PskSha256` vs `PskSha384`) keeps each row pinned
/// to a single hash family even when two suites share an output mode today.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AkmType {
    /// Legacy WPA1 PSK (Wi-Fi Alliance WPA vendor IE OUI `00:50:F2`, type 1, AKM 2).
    /// HMAC-MD5 MIC, PRF-SHA1 PTK, no PMKID. Outputs to hashcat mode 22000 as type 1.
    Wpa1,
    /// AKM suite type 2: WPA2-Personal (HMAC-SHA1 PMKID, PRF-SHA1 PTK).
    /// Outputs to hashcat mode 22000.
    Wpa2Psk,
    /// AKM suite type 4: FT-PSK / 802.11r Fast Transition over PSK (SHA-256 chain PMKID).
    /// Outputs to hashcat mode 37100.
    FtPsk,
    /// AKM suite type 19: FT-PSK-SHA384 / 802.11r Fast Transition over PSK with SHA-384.
    /// SHA-384 chain PMKID, HMAC-SHA384-192 MIC. No dedicated hashcat module today;
    /// routed through 37100 alongside `FtPsk` until a SHA-384 sink is wired up.
    FtPskSha384,
    /// AKM suite type 6: PSK-SHA256 (HMAC-SHA256 PMKID, KDF-SHA256 PTK, AES-CMAC MIC).
    /// Outputs to hashcat mode 22000.
    PskSha256,
    /// AKM suite type 20: PSK-SHA384 (HMAC-SHA384-192 MIC, KDF-SHA384 PTK).
    /// No dedicated hashcat module today; routed through 22000 alongside `PskSha256`
    /// until a SHA-384 sink is wired up.
    PskSha384,
    /// A non-PSK AKM was *observed* on the wire: enterprise (802.1X / FT-802.1X /
    /// 802.1X-SHA256 / Suite-B, vendor CCKM), SAE, OWE, FILS, or PASN. These derive the
    /// PMK from an EAP / SAE / public-key exchange, not `PBKDF2(PSK, SSID)`, so no mode
    /// 22000 / 37100 line built from such a handshake can ever crack.
    ///
    /// Deliberately distinct from `Unknown`: `Unknown` means "no AKM evidence at all"
    /// and is still optimistically treated as `Wpa2Psk` (the never-miss-a-hash default),
    /// whereas `NotPsk` means "we saw an AKM and it is not PSK." The KDV override in
    /// `store_eapol_key` never promotes `NotPsk` to a PSK type, and
    /// `HashType::from_akm_and_attack` returns `None` for it, so the line is dropped at
    /// emit. [IEEE 802.11-2024] §9.4.2.24.3, Table 9-190.
    NotPsk,
    /// AKM could not be determined from context (no Beacon/ProbeResponse/Assoc RSN IE
    /// seen, and no non-PSK AKM observed either). Treated as `Wpa2Psk` for output
    /// routing -- the optimistic "never miss a hash" default. Contrast `NotPsk`, which
    /// is an observed non-PSK AKM and is dropped.
    Unknown,
}

impl AkmType {
    /// Returns `true` for FT (802.11r) PSK suites: AKM 4 (`FtPsk`) and AKM 19
    /// (`FtPskSha384`).
    ///
    /// FT handshakes route to hashcat mode 37100 regardless of the underlying hash
    /// family; consumers who care only about the FT-vs-non-FT split should call this
    /// method instead of comparing against `FtPsk` directly so that AKM 19 is not
    /// silently dropped from the FT path.
    #[must_use]
    pub const fn is_ft(self) -> bool {
        matches!(self, Self::FtPsk | Self::FtPskSha384)
    }

    /// Returns `true` for `PskSha256` (AKM 6, `00:0F:AC:06`).
    #[must_use]
    pub const fn is_psk_sha256(self) -> bool {
        matches!(self, Self::PskSha256)
    }

    /// Encodes as a `u8` for binary serialization.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Wpa1 => 0,
            Self::Wpa2Psk => 1,
            Self::FtPsk => 2,
            Self::FtPskSha384 => 3,
            Self::PskSha256 => 4,
            Self::PskSha384 => 5,
            Self::NotPsk => 6,
            Self::Unknown => 255,
        }
    }

    /// Decodes from a `u8` produced by [`Self::to_byte`].
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Wpa1,
            1 => Self::Wpa2Psk,
            2 => Self::FtPsk,
            3 => Self::FtPskSha384,
            4 => Self::PskSha256,
            5 => Self::PskSha384,
            6 => Self::NotPsk,
            _ => Self::Unknown,
        }
    }
}

// --- Hash type (11-type classification) ---

/// One of the eleven distinct PSK-crackable hash types per `ARCHITECTURE.md §2`.
///
/// The naming follows the IEEE 802.11-2024 AKM suite labels (Table 9-190) joined with
/// the attack surface (PMKID vs EAPOL). Each variant pins down a unique combination of
/// (AKM, hash family, attack surface) so that a stats counter or log line can be
/// understood without reading the EAPOL frame body.
///
/// Discriminant values match the `Type` column of the 11-type table, 1 through 11. Use
/// `name()` for the human-readable label, `is_pmkid()` / `is_ft()` for routing checks,
/// and `from_akm_and_attack()` to classify a captured handshake.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum HashType {
    /// Type 1: WPA1 EAPOL. Vendor IE `00:50:F2:01`, KDV 1, HMAC-MD5 MIC.
    Wpa1Eapol = 1,
    /// Type 2: WPA2-PSK PMKID. AKM 2, HMAC-SHA1-128 PMKID.
    Wpa2PskPmkid = 2,
    /// Type 3: WPA2-PSK EAPOL. AKM 2, KDV 2, HMAC-SHA1-128 MIC.
    Wpa2PskEapol = 3,
    /// Type 4: PSK-SHA256 PMKID. AKM 6, HMAC-SHA256-128 PMKID.
    PskSha256Pmkid = 4,
    /// Type 5: PSK-SHA256 EAPOL. AKM 6, KDV 3, AES-128-CMAC MIC.
    PskSha256Eapol = 5,
    /// Type 6: FT-PSK PMKID. AKM 4, SHA-256 PMKR0Name->PMKR1Name chain.
    FtPskPmkid = 6,
    /// Type 7: FT-PSK EAPOL. AKM 4, KDV 3, AES-128-CMAC MIC.
    FtPskEapol = 7,
    /// Type 8: PSK-SHA384 PMKID. AKM 20, HMAC-SHA384-128 PMKID.
    PskSha384Pmkid = 8,
    /// Type 9: PSK-SHA384 EAPOL. AKM 20, HMAC-SHA384-192 MIC (24 B), KDF-SHA384.
    PskSha384Eapol = 9,
    /// Type 10: FT-PSK-SHA384 PMKID. AKM 19, SHA-384 PMKR0Name->PMKR1Name chain.
    FtPskSha384Pmkid = 10,
    /// Type 11: FT-PSK-SHA384 EAPOL. AKM 19, HMAC-SHA384-192 MIC (24 B), FT-KDF-SHA384.
    FtPskSha384Eapol = 11,
}

impl HashType {
    /// Returns the 11-type-table name, e.g. `"WPA2-PSK-EAPOL"`.
    ///
    /// Stable string identifier used for stats summary rows, log messages, and any
    /// other operator-facing surface. Matches the Name column in `ARCHITECTURE.md §2`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Wpa1Eapol => "WPA1-PSK-EAPOL",
            Self::Wpa2PskPmkid => "WPA2-PSK-PMKID",
            Self::Wpa2PskEapol => "WPA2-PSK-EAPOL",
            Self::PskSha256Pmkid => "PSK-SHA256-PMKID",
            Self::PskSha256Eapol => "PSK-SHA256-EAPOL",
            Self::FtPskPmkid => "FT-PSK-PMKID",
            Self::FtPskEapol => "FT-PSK-EAPOL",
            Self::PskSha384Pmkid => "PSK-SHA384-PMKID",
            Self::PskSha384Eapol => "PSK-SHA384-EAPOL",
            Self::FtPskSha384Pmkid => "FT-PSK-SHA384-PMKID",
            Self::FtPskSha384Eapol => "FT-PSK-SHA384-EAPOL",
        }
    }

    /// Returns the numeric type code (1-11) per the 11-type table.
    #[must_use]
    pub const fn type_code(self) -> u8 {
        self as u8
    }

    /// Returns `true` for PMKID-attack types (even-numbered except 1).
    #[must_use]
    pub const fn is_pmkid(self) -> bool {
        matches!(
            self,
            Self::Wpa2PskPmkid
                | Self::PskSha256Pmkid
                | Self::FtPskPmkid
                | Self::PskSha384Pmkid
                | Self::FtPskSha384Pmkid
        )
    }

    /// Returns `true` for FT (802.11r) types (6, 7, 10, 11). Used for hashcat-mode
    /// 22000-vs-37100 routing.
    #[must_use]
    pub const fn is_ft(self) -> bool {
        matches!(self, Self::FtPskPmkid | Self::FtPskEapol | Self::FtPskSha384Pmkid | Self::FtPskSha384Eapol)
    }

    /// Returns `true` for SHA-384 types (8-11). Lines route through the dedicated
    /// `--psk-sha384-out` (types 8/9) and `--ft-psk-sha384-out` (types 10/11) sinks;
    /// cracking awaits a hashcat kernel that supports the 24-byte MIC.
    #[must_use]
    pub const fn is_sha384(self) -> bool {
        matches!(self, Self::PskSha384Pmkid | Self::PskSha384Eapol | Self::FtPskSha384Pmkid | Self::FtPskSha384Eapol)
    }

    /// Classifies a captured handshake into one of the 11 types.
    ///
    /// `is_pmkid = true` for PMKID-only attacks; `false` for EAPOL-pair attacks. Returns
    /// `None` for `AkmType::Unknown` and `AkmType::NotPsk` (no PSK-cracking path) and for
    /// the WPA1+PMKID combination (WPA1 has no PMKID field).
    #[must_use]
    pub const fn from_akm_and_attack(akm: AkmType, is_pmkid: bool) -> Option<Self> {
        // WPA1 has no PMKID field in its IE; AkmType::Unknown and AkmType::NotPsk have no
        // PSK-crack path for either attack surface. All collapse to None.
        match (akm, is_pmkid) {
            (AkmType::Wpa1, false) => Some(Self::Wpa1Eapol),
            (AkmType::Wpa2Psk, true) => Some(Self::Wpa2PskPmkid),
            (AkmType::Wpa2Psk, false) => Some(Self::Wpa2PskEapol),
            (AkmType::PskSha256, true) => Some(Self::PskSha256Pmkid),
            (AkmType::PskSha256, false) => Some(Self::PskSha256Eapol),
            (AkmType::FtPsk, true) => Some(Self::FtPskPmkid),
            (AkmType::FtPsk, false) => Some(Self::FtPskEapol),
            (AkmType::PskSha384, true) => Some(Self::PskSha384Pmkid),
            (AkmType::PskSha384, false) => Some(Self::PskSha384Eapol),
            (AkmType::FtPskSha384, true) => Some(Self::FtPskSha384Pmkid),
            (AkmType::FtPskSha384, false) => Some(Self::FtPskSha384Eapol),
            (AkmType::Wpa1, true) | (AkmType::Unknown | AkmType::NotPsk, _) => None,
        }
    }

    /// Hashcat mode this hash type maps to today, or `None` if no kernel exists yet.
    ///
    /// Types 1-5 and 8-9 use mode 22000 (legacy 4-byte WPA*NN* prefix scheme); types 6-7
    /// use mode 37100 (FT extra fields appended). The SHA-384 family (8-11) has no
    /// hashcat module yet -- type 8/9 still get a best-effort 22000 routing for
    /// PSK-SHA384 PMKIDs / EAPOL frames so the lines are not lost; types 10/11 (FT
    /// SHA-384) are detected and counted but cannot be routed without a 24 B MIC sink.
    #[must_use]
    pub const fn hashcat_mode(self) -> Option<u32> {
        match self {
            Self::Wpa1Eapol | Self::Wpa2PskPmkid | Self::Wpa2PskEapol | Self::PskSha256Pmkid | Self::PskSha256Eapol => {
                Some(22000)
            },
            Self::FtPskPmkid | Self::FtPskEapol => Some(37100),
            Self::PskSha384Pmkid | Self::PskSha384Eapol | Self::FtPskSha384Pmkid | Self::FtPskSha384Eapol => None,
        }
    }

    /// Legacy `WPA*NN*` line prefix used when this hash type is written to
    /// `--22000-out` / `--37100-out`. Returns `(prefix_bytes, is_ft)` so the writer
    /// knows which legacy file handle to pick.
    ///
    /// The legacy 4-prefix scheme (`WPA*01*` PMKID, `WPA*02*` EAPOL, `WPA*03*` FT-PMKID,
    /// `WPA*04*` FT-EAPOL) cannot disambiguate AKM/MIC variants -- hashcat reads the
    /// `keyver` byte from inside the EAPOL frame to decide between WPA2-PSK and
    /// PSK-SHA256, and SHA-384 lines route through the 16 B MIC slot best-effort.
    #[must_use]
    pub const fn legacy_prefix(self) -> (&'static [u8], bool) {
        match self {
            // keyver=1 inside the body distinguishes WPA1 from WPA2 for hashcat.
            // SHA-384 PMKID/EAPOL ride through the legacy 16 B MIC slot best-effort
            // (no dedicated kernel yet); they collapse onto the WPA*01*/WPA*02* arms.
            Self::Wpa1Eapol | Self::Wpa2PskEapol | Self::PskSha256Eapol | Self::PskSha384Eapol => (b"WPA*02*", false),
            Self::Wpa2PskPmkid | Self::PskSha256Pmkid | Self::PskSha384Pmkid => (b"WPA*01*", false),
            Self::FtPskPmkid | Self::FtPskSha384Pmkid => (b"WPA*03*", true),
            Self::FtPskEapol | Self::FtPskSha384Eapol => (b"WPA*04*", true),
        }
    }

    /// New 11-type classification line prefix: `b"WPA*<type-code>*"` with the type-code as
    /// 2-digit decimal. Used by every per-AKM sink (`--wpa1-out`, `--wpa2-out`, ...)
    /// and the combined `-o` sink. See `ARCHITECTURE.md §2`.
    #[must_use]
    pub const fn extended_prefix(self) -> &'static [u8] {
        match self {
            Self::Wpa1Eapol => b"WPA*01*",
            Self::Wpa2PskPmkid => b"WPA*02*",
            Self::Wpa2PskEapol => b"WPA*03*",
            Self::PskSha256Pmkid => b"WPA*04*",
            Self::PskSha256Eapol => b"WPA*05*",
            Self::FtPskPmkid => b"WPA*06*",
            Self::FtPskEapol => b"WPA*07*",
            Self::PskSha384Pmkid => b"WPA*08*",
            Self::PskSha384Eapol => b"WPA*09*",
            Self::FtPskSha384Pmkid => b"WPA*10*",
            Self::FtPskSha384Eapol => b"WPA*11*",
        }
    }

    /// Iterates every variant in numeric order. Used by stats summary to print all
    /// 11 rows even when their counters are zero.
    pub fn all() -> impl Iterator<Item = Self> {
        [
            Self::Wpa1Eapol,
            Self::Wpa2PskPmkid,
            Self::Wpa2PskEapol,
            Self::PskSha256Pmkid,
            Self::PskSha256Eapol,
            Self::FtPskPmkid,
            Self::FtPskEapol,
            Self::PskSha384Pmkid,
            Self::PskSha384Eapol,
            Self::FtPskSha384Pmkid,
            Self::FtPskSha384Eapol,
        ]
        .into_iter()
    }
}

// --- PMKID source tracking ---

/// Where a PMKID was extracted from.
///
/// The source is recorded for statistics and log output; it does not affect the
/// hash line format. The same PMKID value may appear in multiple sources across
/// a capture -- `PmkidStore` deduplicates by value within each `(AP, STA)` pair.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PmkidSource {
    /// Extracted from the Key Data KDE in an M1 EAPOL-Key frame.
    /// KDE tag `0xDD`, length `0x14`, OUI `00:0F:AC`, type `0x04`.
    M1KeyData,
    /// Extracted from an RSN IE embedded in the M2 EAPOL-Key Data field.
    /// Element ID 48 per IEEE 802.11-2024 §9.4.2.24.
    M2RsnIe,
    /// Extracted from the RSN IE in an Association Request frame.
    AssocRequest,
    /// Extracted from the RSN IE in a Reassociation Request frame.
    ReassocRequest,
    /// S5: `PMKR0Name` from STA->AP FT Authentication frame (algo=2, seq=1). [§13.8.3]
    FtAuthStaToAp,
    /// S6: `PMKR1Name` from AP->STA FT Authentication frame (algo=2, seq=2). [§13.8.3]
    FtAuthApToSta,
    /// S7: PMKID from STA->AP FILS Authentication frame (algo=4 or 5). [§12.11.2.3.2]
    FilsAuthStaToAp,
    /// S8: PMKID from AP->STA FILS Authentication frame (algo=4 or 5). [§12.11.2.3.4]
    FilsAuthApToSta,
    /// S9: PMKID from STA->AP PASN Authentication frame. [§12.13.2]
    PasnAuthStaToAp,
    /// S10: PMKID from AP->STA PASN Authentication frame. [§12.13.2]
    PasnAuthApToSta,
    /// S11: `PMKR0Name`/`PMKR1Name` from FT Request Action frame (cat=6, action=1). [§13.8.5]
    FtActionRequest,
    /// S12: `PMKR1Name` from FT Response Action frame (cat=6, action=2). [§13.8.5]
    FtActionResponse,
    /// S13: `PMKR1Name` from FT Confirm Action frame (cat=6, action=3). [§13.8.5]
    FtActionConfirm,
    /// S14+S15: PMKID from Probe Request RSN IE (directed or broadcast). [§9.4.2.24.5]
    ProbeRequest,
    /// S16: PMKID from Beacon RSN IE (non-zero; vendor firmware deviation). [§9.4.2.24.5]
    BeaconRsnIe,
    /// S17: PMKID from Probe Response RSN IE (non-zero; vendor firmware deviation). [§9.4.2.24.5]
    ProbeRespRsnIe,
    /// S18: PMKID from Mesh Peering Open AMPE "Chosen PMK" field. [§9.6.15.2, §14.3.5]
    MeshPeeringOpen,
    /// S19: PMKID from Mesh Peering Confirm AMPE "Chosen PMK" field. [§9.6.15.3, §14.3.5]
    MeshPeeringConfirm,
    /// S20: PMKID from OSEN IE in Association Request. [Hotspot 2.0 OSEN spec]
    OsenIe,
}

impl PmkidSource {
    /// Encodes as a `u8` for binary serialization.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::M1KeyData => 0,
            Self::M2RsnIe => 1,
            Self::AssocRequest => 2,
            Self::ReassocRequest => 3,
            Self::FtAuthStaToAp => 4,
            Self::FtAuthApToSta => 5,
            Self::FilsAuthStaToAp => 6,
            Self::FilsAuthApToSta => 7,
            Self::PasnAuthStaToAp => 8,
            Self::PasnAuthApToSta => 9,
            Self::FtActionRequest => 10,
            Self::FtActionResponse => 11,
            Self::FtActionConfirm => 12,
            Self::ProbeRequest => 13,
            Self::BeaconRsnIe => 14,
            Self::ProbeRespRsnIe => 15,
            Self::MeshPeeringOpen => 16,
            Self::MeshPeeringConfirm => 17,
            Self::OsenIe => 18,
        }
    }

    /// Decodes from a `u8` produced by [`Self::to_byte`].
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::M2RsnIe,
            2 => Self::AssocRequest,
            3 => Self::ReassocRequest,
            4 => Self::FtAuthStaToAp,
            5 => Self::FtAuthApToSta,
            6 => Self::FilsAuthStaToAp,
            7 => Self::FilsAuthApToSta,
            8 => Self::PasnAuthStaToAp,
            9 => Self::PasnAuthApToSta,
            10 => Self::FtActionRequest,
            11 => Self::FtActionResponse,
            12 => Self::FtActionConfirm,
            13 => Self::ProbeRequest,
            14 => Self::BeaconRsnIe,
            15 => Self::ProbeRespRsnIe,
            16 => Self::MeshPeeringOpen,
            17 => Self::MeshPeeringConfirm,
            18 => Self::OsenIe,
            _ => Self::M1KeyData, // fallback for unknown bytes
        }
    }
}

// --- Error type ---

/// All errors produced by wpawolf.
///
/// Uses a plain enum with manual `Display` and `std::error::Error` impls -- no `anyhow`
/// or `thiserror` crates. I/O errors abort the run (`main` converts to exit code 1);
/// parse errors are logged and the offending frame is skipped. See `ARCHITECTURE.md §4`.
#[derive(Debug)]
pub enum Error {
    /// An underlying I/O operation failed.
    Io(std::io::Error),
    /// An I/O operation failed, carrying the path and operation that triggered
    /// it. Preferred over [`Self::Io`] at file open / create sites so the message
    /// names *which* path and *what* operation failed -- a bare `std::io::Error`
    /// carries neither, which left a post-Phase-4 EACCES on an aux file
    /// undiagnosable in the field.
    IoWithContext {
        /// The filesystem path the operation targeted.
        path: std::path::PathBuf,
        /// Short verb phrase naming the operation, e.g. `"create ESSID list"`.
        operation: &'static str,
        /// The underlying OS error.
        source: std::io::Error,
    },
    /// The file's magic bytes do not match any supported format.
    UnknownFormat(String),
    /// An unknown CLI flag was passed.
    UnknownOption(String),
    /// A CLI flag that requires an argument was supplied without one.
    MissingArgument(String),
    /// A numeric CLI argument could not be parsed.
    InvalidNumber {
        /// The flag name.
        arg: String,
        /// The value that was not numeric.
        value: String,
    },
    /// A buffer was shorter than required to parse a structure.
    Truncated {
        /// Human-readable description of the structure being parsed.
        context: &'static str,
        /// Bytes needed.
        needed: usize,
        /// Bytes available.
        got: usize,
    },
}

impl Error {
    /// Wraps an [`std::io::Error`] with the path and operation that produced it,
    /// so the operator-facing message is actionable. Use at `File::create` /
    /// `create_dir_all` sites where the path is known but would otherwise be lost.
    #[must_use]
    pub fn io(source: std::io::Error, path: impl Into<std::path::PathBuf>, operation: &'static str) -> Self {
        Self::IoWithContext { path: path.into(), operation, source }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::IoWithContext { path, operation, source } => {
                write!(f, "I/O error: {operation} {}: {source}", path.display())
            },
            Self::UnknownFormat(hex) => write!(f, "unrecognised file format (magic bytes: {hex})"),
            Self::UnknownOption(flag) => write!(f, "unknown option: {flag}"),
            Self::MissingArgument(flag) => write!(f, "{flag} requires an argument"),
            Self::InvalidNumber { arg, value } => {
                write!(f, "{arg}: {value:?} is not a valid number")
            },
            Self::Truncated { context, needed, got } => {
                write!(f, "{context}: need {needed} bytes, got {got}")
            },
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) | Self::IoWithContext { source: e, .. } => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Convenience alias so callers can write `Result<T>` instead of `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

// --- EAPOL-Key MIC bytes (variable width per AKM) ---

/// Variable-width EAPOL-Key MIC field.
///
/// Per [IEEE 802.11-2024] §12.7.2 Table 12-11, the Key MIC is 16 bytes for AKMs
/// 1, 2, 3, 4, 5, 6, 8, 9, 11 and **24 bytes** for AKMs 12, 13, 19, 20, 22, 23
/// (the SHA-384 / Suite-B family). Storing the MIC as a fixed `[u8; 16]` would
/// silently truncate the trailing 8 bytes of a SHA-384 MIC; storing it as a
/// `[u8; 24]` plus an 8-bit `len` discriminant lets every downstream consumer
/// (parser, store, dedup, output formatter) read the canonical slice without
/// branching on the AKM at every site.
///
/// Hash output uses [`Self::as_slice`]; sentinel-rejection (`is_zero`, `is_ff`)
/// considers only the active prefix so a 16-byte MIC frame is not falsely flagged
/// as null because the unused 8 trailing bytes are zero.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct MicBytes {
    /// Up to 24 bytes of MIC; bytes beyond `len` are zero.
    bytes: [u8; 24],
    /// Active prefix length in bytes: 16 (AKMs with 16 B MIC) or 24 (SHA-384 family).
    len: u8,
}

impl MicBytes {
    /// All-zero 16-byte MIC, the canonical M1 placeholder.
    pub const ZERO_16: Self = Self { bytes: [0u8; 24], len: 16 };
    /// All-zero 24-byte MIC, the canonical M1 placeholder for SHA-384 AKMs.
    pub const ZERO_24: Self = Self { bytes: [0u8; 24], len: 24 };

    /// Builds a `MicBytes` from a 16-byte array (AKMs 1-6, 8, 9, 11).
    #[must_use]
    pub const fn from_16(bytes16: [u8; 16]) -> Self {
        let bytes = [
            bytes16[0],
            bytes16[1],
            bytes16[2],
            bytes16[3],
            bytes16[4],
            bytes16[5],
            bytes16[6],
            bytes16[7],
            bytes16[8],
            bytes16[9],
            bytes16[10],
            bytes16[11],
            bytes16[12],
            bytes16[13],
            bytes16[14],
            bytes16[15],
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        Self { bytes, len: 16 }
    }

    /// Builds a `MicBytes` from a 24-byte array (SHA-384 family AKMs).
    #[must_use]
    pub const fn from_24(bytes24: [u8; 24]) -> Self {
        Self { bytes: bytes24, len: 24 }
    }

    /// Builds a `MicBytes` from a slice of length 16 or 24; returns `None` otherwise.
    ///
    /// Used by the parser when copying out of the EAPOL-Key buffer with the MIC width
    /// already determined from the body-length / KDV disambiguation.
    #[must_use]
    pub fn from_slice(s: &[u8]) -> Option<Self> {
        match s.len() {
            16 => {
                let mut bytes = [0u8; 24];
                if let Some(dst) = bytes.get_mut(..16) {
                    dst.copy_from_slice(s);
                }
                Some(Self { bytes, len: 16 })
            },
            24 => {
                let mut bytes = [0u8; 24];
                if let Some(dst) = bytes.get_mut(..24) {
                    dst.copy_from_slice(s);
                }
                Some(Self { bytes, len: 24 })
            },
            _ => None,
        }
    }

    /// Returns the active MIC bytes as a slice of length `self.len()`.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // self.len is always 16 or 24, both within the 24-byte buffer.
        self.bytes.get(..self.len as usize).unwrap_or(&[])
    }

    /// Returns the active MIC width in bytes (16 or 24).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns `true` for a zero-length MIC. Always `false` in practice: every constructor
    /// produces a 16- or 24-byte MIC.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns `true` if every active byte is `0x00`. Used for the M2/M3/M4 NULL-MIC
    /// rejection (M1 has no MIC and is never checked). The trailing 8 bytes for a
    /// 16-byte MIC are excluded so a valid 16-B MIC is not falsely flagged.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.as_slice().iter().all(|&b| b == 0)
    }

    /// Returns `true` if every active byte is `0xFF` (firmware sentinel value).
    #[must_use]
    pub fn is_ff(&self) -> bool {
        self.as_slice().iter().all(|&b| b == 0xFF)
    }

    /// Returns the garbage-pattern kind detected in the active MIC bytes, or
    /// `None` when the MIC is structurally clean. Forwards to the byte-slice
    /// [`garbage_pattern_kind`] helper. The trailing 8 unused bytes of a 16-B
    /// MIC stored in the 24-B inline buffer are excluded by `as_slice`.
    #[must_use]
    pub fn garbage_pattern_kind(&self) -> Option<&'static str> {
        garbage_pattern_kind(self.as_slice())
    }
}

impl Default for MicBytes {
    /// All-zero 16-byte MIC -- the canonical M1 placeholder.
    fn default() -> Self {
        Self::ZERO_16
    }
}

// --- Fast BSS Transition (802.11r) fields ---

/// Fast BSS Transition fields needed for hashcat mode 37100 (FT-PSK) output.
///
/// Extracted from the FT IEs in Association/Reassociation frames and from the
/// EAPOL-Key FTE subelements during the FT 4-way handshake. Per IEEE 802.11-2024
/// §9.4.2.45 (MDE) and §9.4.2.46 (FTE).
#[derive(Clone, Copy, Debug)]
pub struct FtFields {
    /// Mobility Domain Identifier (2 bytes). [IEEE 802.11-2024] §9.4.2.45
    pub mdid: [u8; 2],
    /// Actual length of `r0khid` (1-48 bytes). [IEEE 802.11-2024] §9.4.2.46
    pub r0khid_len: u8,
    /// R0 Key Holder Identifier (up to 48 bytes, padded with zeros).
    /// Subelement type 3 in FTE. [IEEE 802.11-2024] §9.4.2.46
    pub r0khid: [u8; 48],
    /// R1 Key Holder Identifier (6 bytes, MAC address form).
    /// Subelement type 1 in FTE. [IEEE 802.11-2024] §9.4.2.46
    pub r1khid: [u8; 6],
}

// --- Hex encoding ---

/// Byte-to-hex-pair lookup table (256 entries, 512 bytes).
///
/// Indexed by an arbitrary `u8` value, returns the two ASCII hex characters that
/// encode it. Computed at compile time so the runtime cost is a single 16-bit load
/// per input byte.
#[allow(clippy::indexing_slicing, reason = "const-eval only; all indices proven in-bounds at compile time")]
const HEX_LUT: [[u8; 2]; 256] = {
    let hex = b"0123456789abcdef";
    let mut table = [[0u8; 2]; 256];
    let mut i: usize = 0;
    while i < 256 {
        table[i] = [hex[i >> 4], hex[i & 0x0f]];
        i += 1;
    }
    table
};

/// Appends the lowercase hex encoding of `bytes` to `out`.
///
/// Each input byte becomes two ASCII hex characters via a 256-entry lookup table.
/// `out` is never truncated; only bytes are appended.
///
/// The iterator form (`flat_map` yielding `[u8; 2]` into `Vec::extend`) allows LLVM
/// to fuse the entire operation: it proves the total write length from `reserve`,
/// auto-unrolls 4x, emits direct 16-bit stores from the LUT, and updates `Vec::len`
/// exactly once at the end -- no per-byte capacity checks or length increments.
/// Benchmarked at 2.38x faster than the per-nibble `push` loop on mixed-size fields
/// (the real `format_eapol_line` call pattern).
pub fn encode_hex(bytes: &[u8], out: &mut Vec<u8>) {
    out.reserve(bytes.len() * 2);
    #[allow(clippy::indexing_slicing, reason = "usize::from(u8) is always 0..=255, in-bounds for 256-entry HEX_LUT")]
    out.extend(bytes.iter().flat_map(|&b| HEX_LUT[usize::from(b)]));
}

/// Hex-encodes an EAPOL frame with the MIC field zeroed, without cloning the frame.
///
/// Writes three segments: bytes before the MIC (offset 81), zero bytes for the MIC
/// window, and bytes after the MIC. Equivalent to `eapol_with_mic_zeroed` + `encode_hex`
/// but avoids the heap allocation for the cloned frame.
/// Per [IEEE 802.11-2024] §12.7.2 Table 12-11: MIC starts at EAPOL-Key byte 81.
pub fn encode_hex_mic_zeroed(frame: &[u8], mic_len: usize, out: &mut Vec<u8>) {
    let mic_start = 81;
    let mic_end = mic_start + mic_len;
    out.reserve(frame.len() * 2);
    let before_end = mic_start.min(frame.len());
    #[allow(clippy::indexing_slicing, reason = "usize::from(u8) always in-bounds for 256-entry HEX_LUT")]
    out.extend(frame.get(..before_end).unwrap_or_default().iter().flat_map(|&b| HEX_LUT[usize::from(b)]));
    let zero_count = mic_len.min(frame.len().saturating_sub(mic_start));
    for _ in 0..zero_count {
        out.extend_from_slice(b"00");
    }
    if let Some(after) = frame.get(mic_end..) {
        #[allow(clippy::indexing_slicing, reason = "usize::from(u8) always in-bounds for 256-entry HEX_LUT")]
        out.extend(after.iter().flat_map(|&b| HEX_LUT[usize::from(b)]));
    }
}

/// Returns the lowercase hex encoding of `bytes` as an owned `String`.
///
/// Allocates a new `String` of length `bytes.len() * 2`. Prefer `encode_hex` when
/// appending to an existing buffer.
#[must_use]
pub fn bytes_to_hex_string(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    encode_hex(bytes, &mut out);
    // encode_hex writes only ASCII bytes from HEX_TABLE (b"0123456789abcdef"),
    // so out is always valid UTF-8. unwrap_or_default returns "" on the unreachable Err branch.
    String::from_utf8(out).unwrap_or_default()
}

// --- NUL trimming (wordlist-style output invariant) ---

/// Trims leading and trailing 0x00 bytes from `bytes`, preserving embedded NULs.
///
/// Applied by every wordlist-style output writer (`-E`, `-R`, `-I`, `-U`, `-D`,
/// `-W`) before autohex encoding. The justification is field-semantic, not
/// heuristic:
///
/// - **Leading NULs** are format-marker bytes: the Hotspot 2.0 / NAI-Realm
///   EAP-Identity prefix (IEEE 802.11u §8.5.11, RFC 4284), and occasional
///   vendor-specific type-prefix bytes in WPS attributes. They are metadata,
///   not user-visible content.
/// - **Trailing NULs** are fixed-width-buffer padding: WPS vendors (HP
///   printers, TP-Link routers, etc.) allocate a larger attribute length than
///   the string they store and pad with `\x00` to the allocated width per
///   the Wi-Fi Protected Setup spec §12 ("variable length" fields carry the
///   allocated buffer length, not the string length). They are allocation
///   artifacts, not content.
/// - **Embedded NULs** ARE preserved. An embedded NUL in a string field is
///   either binary data masquerading as text, protocol corruption, or a real
///   in-band delimiter. All three are interesting signals that deserve
///   surfacing rather than silent loss.
///
/// Hash-oracle outputs (`-o` / `-f` hashcat modes 22000 / 37100) never call
/// this function -- the ESSID bytes there feed the PMK / PTK derivation and
/// must be byte-exact with the wire representation, regardless of NUL
/// padding or prefix markers. See `ARCHITECTURE.md §9`.
#[must_use]
pub const fn trim_nul_padding(bytes: &[u8]) -> &[u8] {
    // Strip leading 0x00 bytes.
    let mut rest = bytes;
    while let Some((&0x00, tail)) = rest.split_first() {
        rest = tail;
    }
    // Strip trailing 0x00 bytes.
    while let Some((&0x00, head)) = rest.split_last() {
        rest = head;
    }
    rest
}

// --- Control-byte splitting (wordlist candidate generation) ---

/// Splits `bytes` on ASCII control bytes (`0x00..=0x1F` and `0x7F`) and
/// returns every non-empty chunk as a sub-slice of the input.
///
/// Used exclusively by `WordlistStore::insert` (`-W`) to expand a single
/// observed string value into additional PSK-crack candidates when the
/// value contains control bytes from a bit-flipped IE, a fragment-boundary
/// artefact, or a vendor's in-band delimiter convention. The full
/// untransformed value is still stored alongside the split chunks -- the
/// splitter *adds* entries, never replaces them.
///
/// Not called by the `-E`, `-R`, `-I`, `-U`, or `-D` writers -- those are
/// strict factual records whose admission rule comes from the relevant
/// spec (see `ARCHITECTURE.md §9`). See `ARCHITECTURE.md §9`
/// for the project-wide per-output contract that keeps this split
/// confined to `-W`.
#[must_use]
pub fn split_on_control_bytes(bytes: &[u8]) -> Vec<&[u8]> {
    bytes.split(|&b| b < 0x20 || b == 0x7F).filter(|c| !c.is_empty()).collect()
}

// --- Autohex encoding ---

/// Returns `true` if every byte is in the wpawolf "plain-text" set.
///
/// The plain-text set is `0x21..=0x7E \ {0x3A}` -- printable ASCII, excluding
/// space (0x20), excluding DEL (0x7F), and excluding the colon (0x3A). Any byte
/// outside this set -- controls, space, colon, DEL, or high-bit bytes 0x80-0xFF
/// (UTF-8 continuation bytes or latin-1) -- triggers `$HEX[...]` encoding in
/// `format_autohex`. An empty slice returns `true` (empty strings have no
/// offending bytes).
///
/// Rationale for the colon exclusion: several downstream hashcat tooling
/// pipelines (pot files, wordlist formats) use `:` as a field separator, so
/// plain-text SSIDs containing colons would corrupt the parse. Rationale for
/// the space exclusion: operators routinely paste the wpawolf output into
/// shell pipelines; unquoted SSIDs with embedded spaces would be split into
/// multiple arguments. The rule is intentionally stricter than hcxpcapngtool's
/// `isasciistring`; the `$HEX[...]` form is always unambiguously parseable and
/// hashcat treats it identically to the raw form when cracking.
#[must_use]
pub fn is_printable_ascii(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| (0x21..=0x7E).contains(&b) && b != 0x3A)
}

// --- Garbage-pattern detector ---

/// Classifies a fixed-width cryptographic field (nonce, MIC, PMKID, ...) against
/// common firmware-stub or test-pattern shapes that have no cracking value.
///
/// Returns the matched-pattern kind (a stable string identifier suitable for
/// stats and log lines) when `bytes` is structurally suspect, or `None` when
/// the run shows no obvious garbage shape. Empty input always returns `None`
/// since there is nothing to judge.
///
/// Patterns, in priority order:
///   * `"null"`     -- every byte is `0x00`. Firmware uninitialised / spec NULL sentinel.
///     Fires at any length (a single `0x00` byte is still a NULL sentinel).
///   * `"ff"`       -- every byte is `0xFF`. NOR-flash erase value, never spec-valid.
///     Fires at any length.
///   * `"repeat_1"` -- every byte equals the first byte (and is neither `0x00`
///     nor `0xFF`, which already returned earlier). Catches firmware patterns
///     like all-`0x55`, all-`0xAA`, all-`0x01`. Length must be `>= 4` so that
///     short legitimate SSIDs (`"X"`, `"AB"`, `"LAN"`) are never flagged.
///   * `"repeat_2"` -- bytes form a 2-byte repeating period (e.g. `5555AAAA`,
///     `01010101...`, `0102 0102 0102`). Length must be a multiple of 2 and `>= 4`.
///   * `"repeat_4"` -- bytes form a 4-byte repeating period. Length must be a
///     multiple of 4 and `>= 8`.
///
/// Cryptographic nonces / MICs / PMKIDs from a healthy stack are uniformly
/// random, so any of these patterns indicates a synthetic / sentinel / firmware
/// stub value rather than crackable material. The fixed widths used by 802.11
/// (32 B nonce, 16 / 24 B MIC, 16 B PMKID) are all multiples of 4, so all three
/// period checks apply.
#[must_use]
pub fn garbage_pattern_kind(bytes: &[u8]) -> Option<&'static str> {
    let &first = bytes.first()?;
    if bytes.iter().all(|&b| b == 0x00) {
        return Some("null");
    }
    if bytes.iter().all(|&b| b == 0xFF) {
        return Some("ff");
    }
    // Length >= 4 minimum so single-byte (`"X"`) and short (`"AB"`, `"LAN"`)
    // SSIDs do not flag as `repeat_1`. Cryptographic fields (nonce 32, MIC
    // 16/24, PMKID 16) all clear this floor, so the gate is operationally
    // ESSID-only.
    if bytes.len() >= 4 && bytes.iter().all(|&b| b == first) {
        return Some("repeat_1");
    }
    if bytes.len() >= 4
        && bytes.len().is_multiple_of(2)
        && let Some(p2) = bytes.get(..2)
        && bytes.chunks_exact(2).all(|c| c == p2)
    {
        return Some("repeat_2");
    }
    if bytes.len() >= 8
        && bytes.len().is_multiple_of(4)
        && let Some(p4) = bytes.get(..4)
        && bytes.chunks_exact(4).all(|c| c == p4)
    {
        return Some("repeat_4");
    }
    None
}

/// Formats `bytes` using the wpawolf autohex convention.
///
/// If every byte is in the plain-text set (see `is_printable_ascii`), the raw
/// string is returned. Otherwise the output is `$HEX[<lowercase hex of every
/// byte>]`. Empty input produces an empty string.
#[must_use]
pub fn format_autohex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    if is_printable_ascii(bytes) {
        // Every byte is in 0x21..=0x7E \ {0x3A}, which is a subset of ASCII,
        // so the bytes form valid UTF-8 by construction.
        String::from_utf8(bytes.to_vec()).unwrap_or_default()
    } else {
        let hex = bytes_to_hex_string(bytes);
        format!("$HEX[{hex}]")
    }
}

// --- Timestamp plausibility ---

/// Upper bound on a plausible capture timestamp, in epoch microseconds.
///
/// `2100-01-01T00:00:00Z`. Capture-tool / container corruption can yield a
/// timestamp near `u64::MAX` (e.g. a pcapng `ts_high` / `ts_low` underflow);
/// feeding such a value into the duration and session-gap statistics renders
/// nonsense like `duration 18445039995104`. Frames carrying an implausible
/// timestamp are still parsed and paired -- only the stats min / max / gap
/// accumulators ignore them.
pub const SANE_EPOCH_CEILING_US: u64 = 4_102_444_800_000_000;

/// Returns `true` when `ts_us` is a usable capture epoch.
///
/// "Usable" means non-zero and below [`SANE_EPOCH_CEILING_US`]. Zero is excluded
/// because a zeroed timestamp is a capture-tool artifact, not a real clock
/// reading, and pairing it against a real timestamp would manufacture a
/// multi-decade gap.
#[must_use]
pub const fn is_plausible_epoch_us(ts_us: u64) -> bool {
    ts_us > 0 && ts_us < SANE_EPOCH_CEILING_US
}

// --- Display helpers ---

/// Formats a byte count as a human-readable string (B / KiB / MiB / GiB) with
/// one decimal place, using integer-only arithmetic (no float cast).
#[must_use]
pub fn human_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = KIB * 1024;
    const GIB: u64 = MIB * 1024;
    if bytes >= GIB {
        let tenths = bytes / (GIB / 10);
        format!("{}.{} GiB", tenths / 10, tenths % 10)
    } else if bytes >= MIB {
        let tenths = bytes / (MIB / 10);
        format!("{}.{} MiB", tenths / 10, tenths % 10)
    } else if bytes >= KIB {
        let tenths = bytes / (KIB / 10);
        format!("{}.{} KiB", tenths / 10, tenths % 10)
    } else {
        format!("{bytes} B")
    }
}

/// Formats an integer percentage with one decimal place using integer-only
/// arithmetic. `pct_tenths` is the percentage times 10 (e.g. 852 = 85.2%).
#[must_use]
pub fn format_pct_tenths(pct_tenths: u64) -> String {
    format!("{}.{}", pct_tenths / 10, pct_tenths % 10)
}

// --- Fingerprint helper ---

/// Hashes a sequence of byte slices into a single `u64` fingerprint.
///
/// `kind` is mixed in first so that two payloads with the same bytes but different
/// semantic categories (e.g. a PMKID vs an EAPOL pair) cannot collide. The underlying
/// `DefaultHasher` is `SipHash`-1-3 on stable Rust; cross-run stability is not
/// required because the caller treats fingerprints as per-invocation identities.
///
/// Lives in `types` so that both `pair` (per-group inline dedup) and `output::dedup`
/// (cross-group final dedup) can import it without introducing a `pair -> output`
/// back-edge in the module DAG. See `ARCHITECTURE.md §3`.
#[must_use]
pub fn hash_slices(kind: u8, slices: &[&[u8]]) -> u64 {
    use std::hash::Hasher as _;

    let mut h = std::collections::hash_map::DefaultHasher::new();
    h.write_u8(kind);
    for s in slices {
        h.write(s);
    }
    h.finish()
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

    #[test]
    fn akm_type_byte_round_trip_includes_notpsk() {
        // Every variant must survive to_byte -> from_byte. This is load-bearing for the
        // disk-spill path (src/store/disk_messages.rs): a NotPsk handshake that spilled to
        // disk must read back as NotPsk, not Unknown -- otherwise it would be re-promoted
        // to Wpa2Psk at emit and resurrect the dropped non-PSK line.
        for akm in [
            AkmType::Wpa1,
            AkmType::Wpa2Psk,
            AkmType::FtPsk,
            AkmType::FtPskSha384,
            AkmType::PskSha256,
            AkmType::PskSha384,
            AkmType::NotPsk,
            AkmType::Unknown,
        ] {
            assert_eq!(AkmType::from_byte(akm.to_byte()), akm, "round-trip failed for {akm:?}");
        }
        assert_eq!(AkmType::NotPsk.to_byte(), 6, "NotPsk must encode as byte 6");
    }

    #[test]
    fn notpsk_never_classifies_to_a_hash_type() {
        // The drop gate: NotPsk has no PSK-crack path on either attack surface.
        assert!(HashType::from_akm_and_attack(AkmType::NotPsk, true).is_none());
        assert!(HashType::from_akm_and_attack(AkmType::NotPsk, false).is_none());
    }

    #[test]
    fn io_with_context_display_and_source() {
        let inner = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Permission denied (os error 13)");
        let err = Error::io(inner, std::path::Path::new("/out/wwE.txt"), "create ESSID list");
        let msg = err.to_string();
        assert!(msg.contains("create ESSID list"), "operation in message: {msg}");
        assert!(msg.contains("/out/wwE.txt"), "path in message: {msg}");
        assert!(msg.contains("Permission denied"), "source in message: {msg}");
        assert!(std::error::Error::source(&err).is_some(), "source() must expose the inner io::Error");
    }

    #[test]
    fn is_plausible_epoch_us_bounds() {
        assert!(!is_plausible_epoch_us(0), "zero (zeroed clock) is implausible");
        assert!(is_plausible_epoch_us(1_700_000_000_000_000), "a 2023-era epoch-us is plausible");
        assert!(!is_plausible_epoch_us(SANE_EPOCH_CEILING_US), "the ceiling itself is excluded");
        assert!(!is_plausible_epoch_us(u64::MAX), "near-2^64 container corruption is implausible");
    }

    #[test]
    fn encode_hex_empty() {
        let mut out = Vec::new();
        encode_hex(&[], &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn encode_hex_known_values() {
        let mut out = Vec::new();
        encode_hex(&[0x00, 0xff, 0xab, 0x12], &mut out);
        assert_eq!(out, b"00ffab12");
    }

    #[test]
    fn bytes_to_hex_string_known() {
        assert_eq!(bytes_to_hex_string(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn bytes_to_hex_string_all_bytes() {
        let all: Vec<u8> = (0u8..=255).collect();
        let hex = bytes_to_hex_string(&all);
        assert_eq!(hex.len(), 512);
        assert!(hex.starts_with("000102"));
        assert!(hex.ends_with("feff"));
    }

    #[test]
    fn macaddr_display() {
        let mac = MacAddr::from_bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(mac.to_string(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn macaddr_display_leading_zeros() {
        let mac = MacAddr::from_bytes([0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e]);
        assert_eq!(mac.to_string(), "00:0a:0b:0c:0d:0e");
    }

    #[test]
    fn macaddr_hex_lower() {
        let mac = MacAddr::from_bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        // Display through format_args! / format!: no intermediate allocation.
        assert_eq!(format!("{}", mac.hex_lower()), "112233445566");
        // Leading-zero handling matches the `Display` colon form.
        let zero_lead = MacAddr::from_bytes([0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0c]);
        assert_eq!(format!("{}", zero_lead.hex_lower()), "000a000b000c");
    }

    #[test]
    fn macpair_hash_equality() {
        use std::collections::HashMap;
        let ap = MacAddr::from_bytes([0x11; 6]);
        let sta = MacAddr::from_bytes([0x22; 6]);
        let pair1 = MacPair::new(ap, sta);
        let pair2 = MacPair::new(ap, sta);
        let mut map: HashMap<MacPair, u32> = HashMap::new();
        map.insert(pair1, 42);
        assert_eq!(map.get(&pair2), Some(&42));
    }

    #[test]
    fn macpair_different_order_not_equal() {
        let a = MacAddr::from_bytes([0x11; 6]);
        let b = MacAddr::from_bytes([0x22; 6]);
        assert_ne!(MacPair::new(a, b), MacPair::new(b, a));
    }

    #[test]
    fn msgtype_repr_values() {
        assert_eq!(MsgType::M1 as u8, 1);
        assert_eq!(MsgType::M2 as u8, 2);
        assert_eq!(MsgType::M3 as u8, 3);
        assert_eq!(MsgType::M4 as u8, 4);
    }

    #[test]
    fn error_truncated_display() {
        let e = Error::Truncated { context: "pcapng EPB", needed: 20, got: 8 };
        assert_eq!(e.to_string(), "pcapng EPB: need 20 bytes, got 8");
    }

    #[test]
    fn error_unknown_format_display() {
        let e = Error::UnknownFormat("deadbeef".to_owned());
        assert!(e.to_string().contains("deadbeef"));
    }

    #[test]
    fn error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "test");
        let e: Error = io_err.into();
        assert!(matches!(e, Error::Io(_)));
        assert!(e.to_string().contains("I/O error"));
    }

    #[test]
    fn error_source_io() {
        use std::error::Error as StdError;
        let e = Error::Io(std::io::Error::other("src"));
        assert!(e.source().is_some());
    }

    #[test]
    fn error_source_non_io() {
        use std::error::Error as StdError;
        let e = Error::UnknownOption("--foo".to_owned());
        assert!(e.source().is_none());
    }

    // --- is_printable_ascii tests ---

    #[test]
    fn printable_ascii_pure() {
        // The plain-text set is 0x21..=0x7E minus 0x3A. Space and colon excluded.
        assert!(is_printable_ascii(b"test"));
        assert!(is_printable_ascii(b"HelloWorld!"));
        assert!(is_printable_ascii(b"!~")); // 0x21 and 0x7E boundaries
        assert!(is_printable_ascii(b"Guest_42"));
    }

    #[test]
    fn printable_ascii_empty() {
        assert!(is_printable_ascii(b""));
    }

    #[test]
    fn trim_nul_padding_leading() {
        assert_eq!(trim_nul_padding(b"\x00Andrew"), b"Andrew");
        assert_eq!(trim_nul_padding(b"\x00\x00\x00foo"), b"foo");
    }

    #[test]
    fn trim_nul_padding_trailing() {
        assert_eq!(trim_nul_padding(b"ENVY 4510 series\x00"), b"ENVY 4510 series");
        assert_eq!(trim_nul_padding(b"TH77B4G3GB068H\x00\x00"), b"TH77B4G3GB068H");
    }

    #[test]
    fn trim_nul_padding_both_ends() {
        assert_eq!(trim_nul_padding(b"\x00\x00name\x00\x00"), b"name");
    }

    #[test]
    fn trim_nul_padding_preserves_embedded() {
        // Embedded NULs are interesting signals (binary data, in-band delimiter,
        // or protocol corruption) and must not be silently dropped.
        assert_eq!(trim_nul_padding(b"foo\x00bar"), b"foo\x00bar");
        assert_eq!(trim_nul_padding(b"\x00foo\x00bar\x00"), b"foo\x00bar");
    }

    #[test]
    fn trim_nul_padding_all_nuls() {
        assert_eq!(trim_nul_padding(b"\x00\x00\x00"), b"");
    }

    #[test]
    fn trim_nul_padding_empty_and_no_nuls() {
        assert_eq!(trim_nul_padding(b""), b"");
        assert_eq!(trim_nul_padding(b"hello"), b"hello");
    }

    #[test]
    fn split_on_control_bytes_no_controls() {
        // No control bytes -> single chunk equal to the input.
        let out = split_on_control_bytes(b"HomeWiFi");
        assert_eq!(out, vec![b"HomeWiFi".as_slice()]);
    }

    #[test]
    fn split_on_control_bytes_embedded_nul() {
        // A NUL in the middle produces two chunks.
        let out = split_on_control_bytes(b"HomeWiFi\x00Guest");
        assert_eq!(out, vec![b"HomeWiFi".as_slice(), b"Guest".as_slice()]);
    }

    #[test]
    fn split_on_control_bytes_leading_and_trailing() {
        // Control runs at the edges are dropped along with any internal runs.
        let out = split_on_control_bytes(b"\x01\x02name\x00\x00tail\x1f");
        assert_eq!(out, vec![b"name".as_slice(), b"tail".as_slice()]);
    }

    #[test]
    fn split_on_control_bytes_del_included() {
        // 0x7F (DEL) is a control byte for this purpose.
        let out = split_on_control_bytes(b"ab\x7fcd");
        assert_eq!(out, vec![b"ab".as_slice(), b"cd".as_slice()]);
    }

    #[test]
    fn split_on_control_bytes_preserves_high_bytes() {
        // 0x80-0xFF are not control bytes -- they stay inside a chunk.
        let out = split_on_control_bytes(b"caf\xc3\xa9");
        assert_eq!(out, vec![b"caf\xc3\xa9".as_slice()]);
    }

    #[test]
    fn split_on_control_bytes_all_controls_returns_empty() {
        assert!(split_on_control_bytes(b"\x00\x01\x02\x03").is_empty());
    }

    #[test]
    fn split_on_control_bytes_empty_input() {
        assert!(split_on_control_bytes(b"").is_empty());
    }

    #[test]
    fn printable_ascii_control_chars_autohex() {
        // Any C0 control or DEL triggers autohex.
        assert!(!is_printable_ascii(b"\x00"));
        assert!(!is_printable_ascii(b"\x1f"));
        assert!(!is_printable_ascii(b"test\n"));
        assert!(!is_printable_ascii(b"\t"));
        assert!(!is_printable_ascii(b"\x7f"));
        assert!(!is_printable_ascii(b"text\x01more"));
    }

    #[test]
    fn printable_ascii_space_autohexes() {
        // Space (0x20) is NOT in the plain-text set; embedded spaces trigger autohex
        // so the output is always safe to paste into a shell pipeline.
        assert!(!is_printable_ascii(b"hello world"));
        assert!(!is_printable_ascii(b" "));
    }

    #[test]
    fn printable_ascii_colon_autohexes() {
        // Colon (0x3A) is reserved as a downstream field separator and always
        // triggers autohex.
        assert!(!is_printable_ascii(b"foo:bar"));
        assert!(!is_printable_ascii(b":"));
    }

    #[test]
    fn printable_ascii_high_bytes_autohex() {
        // Bytes 0x80-0xFF (UTF-8 continuation, latin-1) always trigger autohex.
        assert!(!is_printable_ascii(b"\x80"));
        assert!(!is_printable_ascii(b"\xff"));
        assert!(!is_printable_ascii("Andrew\u{2019}s".as_bytes()));
        assert!(!is_printable_ascii("caf\u{00e9}".as_bytes()));
    }

    #[test]
    fn printable_ascii_accepts_plain_text_set() {
        // Every byte in the plain-text set is accepted.
        assert!(is_printable_ascii(b""));
        assert!(is_printable_ascii(b"test"));
        assert!(is_printable_ascii(b"MyNetwork"));
        assert!(is_printable_ascii(b"Guest-WiFi_42"));
        assert!(is_printable_ascii(
            b"!\"#$%&'()*+,-./0123456789;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
        ));
    }

    // --- format_autohex tests ---

    #[test]
    fn autohex_empty() {
        assert_eq!(format_autohex(b""), "");
    }

    #[test]
    fn autohex_plain_text_passes_through() {
        assert_eq!(format_autohex(b"test"), "test");
        assert_eq!(format_autohex(b"MyNetwork"), "MyNetwork");
        assert_eq!(format_autohex(b"Guest_42"), "Guest_42");
    }

    #[test]
    fn autohex_space_triggers_hex() {
        // "hello world" -> every byte hex-encoded, including the space.
        assert_eq!(format_autohex(b"hello world"), "$HEX[68656c6c6f20776f726c64]");
    }

    #[test]
    fn autohex_colon_triggers_hex() {
        assert_eq!(format_autohex(b"foo:bar"), "$HEX[666f6f3a626172]");
    }

    #[test]
    fn autohex_control_byte_triggers_hex() {
        assert_eq!(format_autohex(&[0x41, 0x01, 0x42]), "$HEX[410142]");
    }

    #[test]
    fn autohex_utf8_multibyte_triggers_hex() {
        // "Andrew's iPhone" with U+2019 -> autohex.
        let encoded = format_autohex("Andrew\u{2019}s".as_bytes());
        assert!(encoded.starts_with("$HEX["), "{encoded}");
        assert!(encoded.contains("e28099"), "{encoded}");
    }

    #[test]
    fn autohex_latin1_high_bytes_trigger_hex() {
        assert_eq!(format_autohex(&[b'a', 0xe9, b'b']), "$HEX[61e962]");
    }

    #[test]
    fn autohex_all_binary() {
        assert_eq!(format_autohex(&[0xff, 0xfe, 0x01]), "$HEX[fffe01]");
    }

    #[test]
    fn autohex_null_byte() {
        assert_eq!(format_autohex(&[0x00]), "$HEX[00]");
    }

    // --- HashType tests ---

    #[test]
    fn hash_type_codes_are_one_through_eleven() {
        let codes: Vec<u8> = HashType::all().map(HashType::type_code).collect();
        assert_eq!(codes, (1u8..=11).collect::<Vec<_>>());
    }

    #[test]
    fn hash_type_names_match_table() {
        assert_eq!(HashType::Wpa1Eapol.name(), "WPA1-PSK-EAPOL");
        assert_eq!(HashType::Wpa2PskEapol.name(), "WPA2-PSK-EAPOL");
        assert_eq!(HashType::Wpa2PskPmkid.name(), "WPA2-PSK-PMKID");
        assert_eq!(HashType::PskSha256Eapol.name(), "PSK-SHA256-EAPOL");
        assert_eq!(HashType::FtPskPmkid.name(), "FT-PSK-PMKID");
        assert_eq!(HashType::PskSha384Eapol.name(), "PSK-SHA384-EAPOL");
        assert_eq!(HashType::FtPskSha384Eapol.name(), "FT-PSK-SHA384-EAPOL");
    }

    #[test]
    fn hash_type_is_pmkid_split() {
        for ht in HashType::all() {
            let expected = matches!(ht.type_code(), 2 | 4 | 6 | 8 | 10);
            assert_eq!(ht.is_pmkid(), expected, "{}", ht.name());
        }
    }

    #[test]
    fn hash_type_is_ft_split() {
        for ht in HashType::all() {
            let expected = matches!(ht.type_code(), 6 | 7 | 10 | 11);
            assert_eq!(ht.is_ft(), expected, "{}", ht.name());
        }
    }

    #[test]
    fn hash_type_from_akm_covers_all_eleven_rows() {
        // Each (AkmType, is_pmkid) pair from the 11-type table must classify uniquely.
        let cases: &[(AkmType, bool, HashType)] = &[
            (AkmType::Wpa1, false, HashType::Wpa1Eapol),
            (AkmType::Wpa2Psk, true, HashType::Wpa2PskPmkid),
            (AkmType::Wpa2Psk, false, HashType::Wpa2PskEapol),
            (AkmType::PskSha256, true, HashType::PskSha256Pmkid),
            (AkmType::PskSha256, false, HashType::PskSha256Eapol),
            (AkmType::FtPsk, true, HashType::FtPskPmkid),
            (AkmType::FtPsk, false, HashType::FtPskEapol),
            (AkmType::PskSha384, true, HashType::PskSha384Pmkid),
            (AkmType::PskSha384, false, HashType::PskSha384Eapol),
            (AkmType::FtPskSha384, true, HashType::FtPskSha384Pmkid),
            (AkmType::FtPskSha384, false, HashType::FtPskSha384Eapol),
        ];
        for &(akm, pmkid, expected) in cases {
            assert_eq!(HashType::from_akm_and_attack(akm, pmkid), Some(expected));
        }
    }

    #[test]
    fn hash_type_from_akm_returns_none_for_invalid_combinations() {
        // WPA1 has no PMKID field; Unknown AKM has no crackable path.
        assert_eq!(HashType::from_akm_and_attack(AkmType::Wpa1, true), None);
        assert_eq!(HashType::from_akm_and_attack(AkmType::Unknown, true), None);
        assert_eq!(HashType::from_akm_and_attack(AkmType::Unknown, false), None);
    }

    #[test]
    fn hash_type_hashcat_mode_routing() {
        // Types 1-5 -> 22000 (legacy 16 B MIC), 6-7 -> 37100 (FT extras), 8-11 -> none.
        for ht in HashType::all() {
            let expected = match ht.type_code() {
                1..=5 => Some(22000),
                6 | 7 => Some(37100),
                _ => None,
            };
            assert_eq!(ht.hashcat_mode(), expected, "{}", ht.name());
        }
    }

    #[test]
    fn hash_type_legacy_prefix_pmkid_vs_eapol() {
        // PMKID -> WPA*01* / WPA*03*; EAPOL -> WPA*02* / WPA*04*; FT bool tracks is_ft().
        for ht in HashType::all() {
            let (prefix, is_ft) = ht.legacy_prefix();
            assert_eq!(is_ft, ht.is_ft(), "{}", ht.name());
            let expected: &[u8] = match (ht.is_pmkid(), ht.is_ft()) {
                (true, false) => b"WPA*01*",
                (false, false) => b"WPA*02*",
                (true, true) => b"WPA*03*",
                (false, true) => b"WPA*04*",
            };
            assert_eq!(prefix, expected, "{}", ht.name());
        }
    }

    #[test]
    fn hash_type_extended_prefix_matches_type_code() {
        // The extended prefix encodes the 1-11 type code as 2-digit decimal.
        for ht in HashType::all() {
            let expected = format!("WPA*{:02}*", ht.type_code());
            assert_eq!(ht.extended_prefix(), expected.as_bytes(), "{}", ht.name());
        }
    }

    #[test]
    fn akmtype_is_ft_covers_both_ft_variants() {
        assert!(AkmType::FtPsk.is_ft());
        assert!(AkmType::FtPskSha384.is_ft());
        assert!(!AkmType::Wpa1.is_ft());
        assert!(!AkmType::Wpa2Psk.is_ft());
        assert!(!AkmType::PskSha256.is_ft());
        assert!(!AkmType::PskSha384.is_ft());
        assert!(!AkmType::Unknown.is_ft());
    }

    // --- garbage_pattern_kind ---

    #[test]
    fn garbage_pattern_empty_returns_none() {
        assert_eq!(garbage_pattern_kind(&[]), None);
    }

    #[test]
    fn garbage_pattern_null_at_any_length() {
        assert_eq!(garbage_pattern_kind(&[0]), Some("null"));
        assert_eq!(garbage_pattern_kind(&[0; 16]), Some("null"));
        assert_eq!(garbage_pattern_kind(&[0; 32]), Some("null"));
    }

    #[test]
    fn garbage_pattern_ff_at_any_length() {
        assert_eq!(garbage_pattern_kind(&[0xFF]), Some("ff"));
        assert_eq!(garbage_pattern_kind(&[0xFF; 16]), Some("ff"));
        assert_eq!(garbage_pattern_kind(&[0xFF; 32]), Some("ff"));
    }

    #[test]
    fn garbage_pattern_repeat_1_only_at_or_above_4_bytes() {
        // Short SSIDs ("X", "AB", "LAN") must not flag.
        assert_eq!(garbage_pattern_kind(b"X"), None);
        assert_eq!(garbage_pattern_kind(b"AB"), None);
        assert_eq!(garbage_pattern_kind(b"AAA"), None);
        // 4 bytes of the same value triggers repeat_1.
        assert_eq!(garbage_pattern_kind(b"AAAA"), Some("repeat_1"));
        assert_eq!(garbage_pattern_kind(&[0x55; 16]), Some("repeat_1"));
        assert_eq!(garbage_pattern_kind(&[0xAB; 32]), Some("repeat_1"));
    }

    #[test]
    fn garbage_pattern_repeat_2_alternating_bytes() {
        // 5555AAAA-style alternation across 32 bytes (16 cycles of 0x55, 0xAA).
        let mut nonce = [0u8; 32];
        for chunk in nonce.chunks_exact_mut(2) {
            chunk[0] = 0x55;
            chunk[1] = 0xAA;
        }
        assert_eq!(garbage_pattern_kind(&nonce), Some("repeat_2"));
    }

    #[test]
    fn garbage_pattern_repeat_4_period() {
        // 4-byte period 01020304 repeated 8 times.
        let mut nonce = [0u8; 32];
        for chunk in nonce.chunks_exact_mut(4) {
            chunk[0] = 0x01;
            chunk[1] = 0x02;
            chunk[2] = 0x03;
            chunk[3] = 0x04;
        }
        assert_eq!(garbage_pattern_kind(&nonce), Some("repeat_4"));
    }

    #[test]
    fn garbage_pattern_random_bytes_pass() {
        // A non-uniform 32-byte run mirrors what the parser sees from a real
        // EAPOL Key Nonce; must not flag.
        let nonce: [u8; 32] = [
            0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xA0, 0xA1,
            0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        ];
        assert_eq!(garbage_pattern_kind(&nonce), None);
    }

    #[test]
    fn garbage_pattern_priority_null_before_repeat() {
        // All-zero is also trivially repeat_1 / repeat_2 / repeat_4 -- the helper
        // must return the most specific identifier ("null") so callers route
        // the rejection into `null_*_rejected` rather than a generic counter.
        assert_eq!(garbage_pattern_kind(&[0; 16]), Some("null"));
    }
}
