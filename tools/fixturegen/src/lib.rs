//! `wpawolf-fixturegen` -- standalone test-capture generator for wpawolf.
//!
//! This crate emits pcap and pcapng files containing 802.11 management and
//! EAPOL frames that exercise every code path in the wpawolf parser. Each
//! fixture is built from a deterministic `(PSK, SSID, AP_MAC, STA_MAC, AKM)`
//! tuple so the embedded PMKIDs and MICs are cryptographically valid -- the
//! same fixtures double as inputs to `hashcat -m 22000` / `-m 37100` for
//! end-to-end smoke testing.
//!
//! ## Module map
//!
//! - [`crypto`] -- PMK / PTK / PMKID / MIC primitives. Every AKM family in
//!   `[IEEE 802.11-2024]` table 12-11 is implemented.
//! - [`frame`] -- typed builders for 802.11 management frames, EAPOL-Key
//!   M1-M4, KDEs, and FT subelements.
//! - [`linklayer`] -- radiotap, PPI, Prism, AVS, raw 802.11 wrappers.
//! - [`pcap_writer`] -- pcap (10 magic variants) and pcapng (LE/BE sections)
//!   serialisers, plus gzip-wrapping for `.pcap.gz` / `.pcapng.gz`.
//! - [`handshake`] -- orchestrates a full M1-M4 sequence with valid crypto.
//! - [`catalog`] -- the cross-product enumerator that drives the corpus.
//!
//! The crate forbids `unsafe` code, mirrors the workspace lint policy, and
//! reuses `wpawolf::types::{AkmType, HashType, PmkidSource, MacAddr}` so the
//! generator and the parser stay locked to a single enum layout.

#![forbid(unsafe_code)]

// `clap` is consumed exclusively by the binary target (`src/main.rs`). The
// `unused_crate_dependencies` lint is checked per crate root, so we mark the
// dep as intentionally library-unused here.
use clap as _;

pub mod catalog;
pub mod crypto;
pub mod frame;
pub mod handshake;
pub mod linklayer;
pub mod pcap_writer;

/// Re-export of the wpawolf type surface the generator builds against.
///
/// Keeping the re-export shallow (one path per type) means downstream call
/// sites read `fixturegen::types::AkmType` rather than reaching across the
/// workspace into `wpawolf::types::AkmType` directly.
pub mod types {
    pub use wpawolf::types::{AkmType, HashType, MacAddr, MacPair, MicBytes, MsgType, PmkidSource};
}

/// Crate-local error type.
///
/// The generator uses a small custom enum -- in line with the project rule
/// against `anyhow` / `thiserror` -- so callers can pattern-match failures
/// (a malformed fixture spec is recoverable; a disk-full write is not).
#[derive(Debug)]
pub enum Error {
    /// I/O failure while writing a fixture file.
    Io(std::io::Error),
    /// A fixture spec referenced an unsupported `(AkmType, HashType)`
    /// combination -- e.g. asking for a WPA1 PMKID (WPA1 has none).
    UnsupportedSpec(&'static str),
    /// A wire-format constraint was violated -- e.g. an FT fixture without
    /// the required `MDID / R0KH-ID / R1KH-ID` triple.
    InvalidWireFormat(&'static str),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o error: {e}"),
            Self::UnsupportedSpec(m) => write!(f, "unsupported fixture spec: {m}"),
            Self::InvalidWireFormat(m) => write!(f, "invalid wire format: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::UnsupportedSpec(_) | Self::InvalidWireFormat(_) => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// Crate-local `Result` alias.
pub type Result<T> = core::result::Result<T, Error>;
