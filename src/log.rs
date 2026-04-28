//! Shared -- structured logger for malformed-frame events. See ARCHITECTURE.md §4.
//!
//! Appends categorised log lines to the file specified by `--log`. Nine categories,
//! every one wired to a distinct call site:
//!
//! - `malformed_frame`    -- truncated or structurally invalid 802.11 / EAPOL data.
//! - `plcp_error`         -- link-layer header validation failed (radiotap / PPI /
//!   Prism / AVS error, or an unsupported DLT).
//! - `unknown_linktype`   -- a pcapng EPB referenced an `interface_id` for which no
//!   preceding IDB exists.
//! - `unknown_akm`        -- AKM suite type outside IEEE 802.11-2024 Table 9-190.
//! - `essid_not_found`    -- a hash line was emitted for an AP whose SSID was never
//!   observed on the wire.
//! - `capture_read_error` -- per-file ingest error, typically a truncated trailing
//!   packet record (FR-IN-10).
//! - `invalid_nonce`      -- EAPOL frame discarded: nonce was NULL (M1/M2/M3) or
//!   all-`0xFF` (any).
//! - `invalid_mic`        -- EAPOL frame discarded: MIC was NULL or all-`0xFF` with
//!   the Key MIC flag set (M2/M3/M4).
//! - `invalid_pmkid`      -- PMKID discarded: NULL or all-`0xFF`.
//!
//! Line format: `[category] <category-specific fields...>`. Each `Logger::log_*`
//! method defines its own field layout -- frame-bearing categories
//! (`malformed_frame`, `plcp_error`, `invalid_nonce`, `invalid_mic`,
//! `invalid_pmkid`) lead with `timestamp_us`; the rest carry only the field(s)
//! relevant to the event (e.g. `unknown_akm` carries just the AKM byte).
//! Only opened when `--log` is specified on the CLI; otherwise every method is
//! a no-op.

use std::io::{BufWriter, Write as _};

use crate::types::Result;

/// Structured log writer. No-ops silently when no log path is configured.
pub struct Logger {
    writer: Option<BufWriter<std::fs::File>>,
}

impl std::fmt::Debug for Logger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Logger").field("active", &self.writer.is_some()).finish()
    }
}

impl Logger {
    /// Opens the log file at `path`, or creates a no-op logger if `path` is `None`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the log file cannot be created.
    pub fn new(path: Option<&std::path::Path>) -> Result<Self> {
        let writer = match path {
            Some(p) => Some(BufWriter::new(std::fs::File::create(p)?)),
            None => None,
        };
        Ok(Self { writer })
    }

    /// Logs a malformed or truncated 802.11/EAPOL frame.
    pub fn log_malformed_frame(&mut self, timestamp_us: u64, interface_id: u32, details: &str) {
        self.write_line(&format!("[malformed_frame] {timestamp_us} {interface_id} {details}"));
    }

    /// Logs a link-layer header validation failure (radiotap, PPI, Prism, AVS errors).
    pub fn log_plcp_error(&mut self, timestamp_us: u64, interface_id: u32, details: &str) {
        self.write_line(&format!("[plcp_error] {timestamp_us} {interface_id} {details}"));
    }

    /// Logs a packet whose `interface_id` has no IDB-registered DLT.
    ///
    /// In classic pcap there is exactly one interface (id 0) and the global header
    /// DLT always resolves, so this category cannot fire. In pcapng it fires when an
    /// EPB carries an `interface_id` for which no preceding IDB exists -- a malformed
    /// or out-of-order capture. The packet is dropped without further parsing.
    pub fn log_unknown_linktype(&mut self, interface_id: u32) {
        self.write_line(&format!("[unknown_linktype] interface_id={interface_id}"));
    }

    /// Logs an uncharacterised AKM suite type.
    pub fn log_unknown_akm(&mut self, akm_byte: u8) {
        self.write_line(&format!("[unknown_akm] type={akm_byte}"));
    }

    /// Logs when no ESSID could be resolved for a hash line's AP.
    pub fn log_essid_not_found(&mut self, ap_hex: &str) {
        self.write_line(&format!("[essid_not_found] ap={ap_hex}"));
    }

    /// Logs an EAPOL-Key frame whose Key Nonce was rejected as a sentinel value.
    ///
    /// `kind` is `"null"` (all-`0x00` nonce in M1/M2/M3 -- spec violation) or
    /// `"ff"` (all-`0xFF` nonce in any message -- firmware flash-erase pattern).
    /// M4 NULL nonce is spec-valid per [IEEE 802.11-2024] §12.7.6.5 and is NOT logged.
    pub fn log_invalid_nonce(&mut self, timestamp_us: u64, ap_hex: &str, sta_hex: &str, kind: &str) {
        self.write_line(&format!("[invalid_nonce] {timestamp_us} ap={ap_hex} sta={sta_hex} kind={kind}"));
    }

    /// Logs an EAPOL-Key frame whose Key MIC was rejected as a sentinel value.
    ///
    /// `kind` is `"null"` (all-`0x00`) or `"ff"` (all-`0xFF`). Only fires when the Key
    /// MIC flag (Key Information bit B8) is set, i.e. M2 / M3 / M4. M1 has no MIC by
    /// spec and is never logged here.
    pub fn log_invalid_mic(&mut self, timestamp_us: u64, ap_hex: &str, sta_hex: &str, kind: &str) {
        self.write_line(&format!("[invalid_mic] {timestamp_us} ap={ap_hex} sta={sta_hex} kind={kind}"));
    }

    /// Logs a PMKID rejected as a sentinel value (all-NULL or all-`0xFF`).
    ///
    /// `kind` is `"null"` (AP placeholder meaning "no cached PMK") or `"ff"` (firmware
    /// flash-erase sentinel). Both have no cracking value. Fires from every PMKID
    /// extraction site (M1 KDE, M2 RSN IE, `AssocReq`, `ReassocReq`, FT/FILS/PASN Auth,
    /// FT Action frames, Probe Request, Beacon, `ProbeResp`, Mesh Peering, OSEN IE).
    pub fn log_invalid_pmkid(&mut self, timestamp_us: u64, ap_hex: &str, sta_hex: &str, kind: &str) {
        self.write_line(&format!("[invalid_pmkid] {timestamp_us} ap={ap_hex} sta={sta_hex} kind={kind}"));
    }

    /// Logs a per-file capture read error.
    ///
    /// Emitted from the Phase 1 ingest loop when a `next_packet()` call fails after
    /// the file has already been opened successfully -- almost always a truncated
    /// trailing record (file ended mid-packet) or a corrupt `incl_len` field. Per
    /// FR-IN-10 the file is closed and the run continues with the next input.
    pub fn log_capture_read_error(&mut self, path: &std::path::Path, reason: &str) {
        self.write_line(&format!("[capture_read_error] path={} reason={reason}", path.display()));
    }

    /// Flushes the log buffer to disk.
    ///
    /// # Errors
    ///
    /// Returns `Err` on I/O failure.
    pub fn flush(&mut self) -> Result<()> {
        if let Some(w) = &mut self.writer {
            w.flush()?;
        }
        Ok(())
    }

    /// Appends `line` followed by a newline to the log file, if one is open.
    ///
    /// Write errors are silently discarded -- log failures must not abort a run
    /// that is otherwise producing valid output.
    fn write_line(&mut self, line: &str) {
        if let Some(w) = &mut self.writer {
            let _ = writeln!(w, "{line}");
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
        missing_docs,
        clippy::wildcard_imports,
        reason = "test module"
    )]

    use super::*;

    #[test]
    fn new_no_path_creates_noop() {
        let logger = Logger::new(None);
        assert!(logger.is_ok());
        let logger = logger.unwrap();
        assert!(logger.writer.is_none());
    }

    #[test]
    fn no_op_logger_does_not_write_or_panic() {
        // Exercise every log method on a path-less (no-op) Logger. The real file-write
        // behaviour is covered by `writes_to_file` below; this test guards the no-op
        // branch of write_line() against future regressions (e.g. someone deciding to
        // println! on a nil writer).
        let mut logger = Logger::new(None).unwrap();
        logger.log_malformed_frame(123_456, 0, "truncated radiotap header");
        logger.log_plcp_error(999, 1, "AVS length mismatch");
        logger.log_unknown_linktype(0xDEAD_u32);
        logger.log_unknown_akm(0xFF);
        logger.log_essid_not_found("aabbccddeeff");
        logger.log_capture_read_error(std::path::Path::new("/tmp/example.pcap"), "truncated");
        assert!(logger.flush().is_ok());
        assert!(logger.writer.is_none(), "no-op logger must keep writer absent");
    }

    #[test]
    fn debug_format_inactive() {
        let logger = Logger::new(None).unwrap();
        let s = format!("{logger:?}");
        assert!(s.contains("active: false"));
    }

    #[test]
    fn writes_to_file() {
        use std::io::Read as _;
        let tmp = std::env::temp_dir().join("wpawolf_log_test.log");
        {
            let mut logger = Logger::new(Some(&tmp)).unwrap();
            logger.log_malformed_frame(1_000, 0, "test detail");
            logger.log_unknown_linktype(7);
            logger.flush().unwrap();
        }
        let mut contents = String::new();
        std::fs::File::open(&tmp).unwrap().read_to_string(&mut contents).unwrap();
        assert!(contents.contains("[malformed_frame] 1000 0 test detail"));
        assert!(contents.contains("[unknown_linktype] interface_id=7"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn writes_capture_read_error() {
        use std::io::Read as _;
        let tmp = std::env::temp_dir().join("wpawolf_log_capture_read_error.log");
        {
            let mut logger = Logger::new(Some(&tmp)).unwrap();
            logger.log_capture_read_error(
                std::path::Path::new("/captures/304.pcap"),
                "pcap packet data: need 30 bytes, got 0",
            );
            logger.flush().unwrap();
        }
        let mut contents = String::new();
        std::fs::File::open(&tmp).unwrap().read_to_string(&mut contents).unwrap();
        assert!(
            contents
                .contains("[capture_read_error] path=/captures/304.pcap reason=pcap packet data: need 30 bytes, got 0"),
            "missing capture_read_error line; got: {contents}"
        );
        let _ = std::fs::remove_file(&tmp);
    }
}
