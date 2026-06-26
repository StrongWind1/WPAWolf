//! Shared -- structured triage logger. See ARCHITECTURE.md §4.
//!
//! Appends categorised log lines to the file specified by `--log`. The log is a
//! **triage tool**: it records events where wpawolf dropped, skipped, or rejected
//! data for non-obvious reasons. Obvious high-volume rejections (null PMKID, null
//! M4 nonce, out-of-sequence timestamps) are already counted in the stats banner
//! on stdout and do NOT appear in the log.
//!
//! ## Per-event categories (written immediately, low volume)
//!
//! - `capture_read_error`       -- file-level ingest failure (truncated record).
//! - `skipped_input`            -- file could not be classified (bad magic bytes).
//! - `unknown_linktype`         -- pcapng EPB referenced a missing IDB.
//! - `eapol_key_rejected`       -- EAPOL-Key passed LLC/EtherType but failed
//!   structural validation (truncation, bad descriptor, bad KDV).
//! - `essid_not_found_summary`  -- per-AP summary for hashes dropped because no
//!   ESSID was ever observed.
//! - `invalid_nonce`            -- nonce rejected for a non-obvious garbage pattern
//!   (`ff`, `repeat_1`, `repeat_2`, `repeat_4`). Null nonces are suppressed.
//! - `invalid_mic`              -- MIC rejected for a non-obvious garbage pattern.
//!   Null MICs are suppressed.
//! - `invalid_pmkid`            -- PMKID rejected for a non-obvious garbage pattern.
//!   Null PMKIDs are suppressed.
//!
//! ## Aggregated categories (accumulated during run, summary at flush)
//!
//! - `plcp_error`               -- link-layer strip failed after all recovery tiers
//!   exhausted. One summary line per (reason, DLT) pair with a count.
//! - `malformed_frame`          -- 802.11 MAC header truncated or invalid. One
//!   summary line per reason with a count.
//! - `essid_control_bytes`      -- SSIDs containing ASCII C0 control characters.
//!   Single summary line with a total count.
//! - `unknown_akm`              -- AKM suite type outside IEEE 802.11-2024 Table
//!   9-190. One summary line per AKM byte with a count.
//!
//! ## Removed categories (stats-only, no log line)
//!
//! These events are counted in the stats banner but do NOT produce log lines:
//! radiotap version recovery, FCS detection/mismatch, frame recovery tiers 2/3,
//! out-of-sequence timestamps, null-kind garbage patterns (nonce/MIC/PMKID).
//!
//! ## Line format
//!
//! `[category] key=value key=value ...`. Per-frame categories carry `file=` and
//! `frame=` context from the stored Logger state. MAC addresses are bare
//! lowercase hex (12 chars, no separators). Hex byte fields use `render_lower_hex`
//! (contiguous lowercase, no separators).

use std::collections::HashMap;
use std::io::{BufWriter, Write as _};

use crate::types::Result;

/// Structured triage logger. No-ops silently when no log path is configured.
///
/// Per-frame log methods automatically include `file=` and `frame=` fields
/// from the stored context. The main loop calls [`Self::set_file`] when
/// starting a new input file and [`Self::set_frame`] for each packet.
pub struct Logger {
    writer: Option<BufWriter<std::fs::File>>,
    current_file: String,
    current_frame: u64,
    plcp_counts: HashMap<PlcpKey, u64>,
    malformed_counts: HashMap<String, u64>,
    essid_control_count: u64,
    unknown_akm_counts: HashMap<u8, u64>,
}

/// Aggregation key for link-layer errors: the reason string plus the DLT that
/// produced it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PlcpKey {
    reason: String,
    dlt: u16,
}

impl std::fmt::Debug for Logger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Logger").field("active", &self.writer.is_some()).finish_non_exhaustive()
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
            Some(p) => Some(BufWriter::new(
                std::fs::File::create(p).map_err(|e| crate::types::Error::io(e, p, "create log file"))?,
            )),
            None => None,
        };
        Ok(Self {
            writer,
            current_file: String::new(),
            current_frame: 0,
            plcp_counts: HashMap::new(),
            malformed_counts: HashMap::new(),
            essid_control_count: 0,
            unknown_akm_counts: HashMap::new(),
        })
    }

    // --- Context ---

    /// Sets the current input file path. Called from the main loop when
    /// starting a new file. Resets the frame counter to 0.
    pub fn set_file(&mut self, path: &str) {
        self.current_file.clear();
        self.current_file.push_str(path);
        self.current_frame = 0;
    }

    /// Sets the current frame number within the current file. Called from
    /// the main loop for each packet.
    pub const fn set_frame(&mut self, frame: u64) {
        self.current_frame = frame;
    }

    // --- Per-event methods (written immediately) ---

    /// Logs an EAPOL-Key frame that passed the LLC/packet-type gate but was rejected
    /// by the EAPOL-Key parser for a structural reason.
    pub fn log_eapol_key_rejected(
        &mut self,
        ap_hex: impl std::fmt::Display,
        sta_hex: impl std::fmt::Display,
        reason: &str,
        raw: &[u8],
    ) {
        let file = &self.current_file;
        let frame = self.current_frame;
        let bytes_hex = render_lower_hex(raw.get(..32).unwrap_or(raw));
        self.write_line(&format!(
            "[eapol_key_rejected] file=\"{file}\" frame={frame} ap={ap_hex} sta={sta_hex} reason=\"{reason}\" bytes={bytes_hex}"
        ));
    }

    /// Logs an EAPOL-Key frame whose Key Nonce was a non-obvious garbage pattern.
    pub fn log_invalid_nonce(
        &mut self,
        ap_hex: impl std::fmt::Display,
        sta_hex: impl std::fmt::Display,
        msg_type: Option<crate::types::MsgType>,
        kind: &str,
        nonce: &[u8],
    ) {
        let file = &self.current_file;
        let frame = self.current_frame;
        let nonce_hex = render_lower_hex(nonce);
        let mt = msg_type_label(msg_type);
        self.write_line(&format!(
            "[invalid_nonce] file=\"{file}\" frame={frame} ap={ap_hex} sta={sta_hex} msg_type=\"{mt}\" kind=\"{kind}\" nonce_hex={nonce_hex}"
        ));
    }

    /// Logs an EAPOL-Key frame whose Key MIC was a non-obvious garbage pattern.
    pub fn log_invalid_mic(
        &mut self,
        ap_hex: impl std::fmt::Display,
        sta_hex: impl std::fmt::Display,
        msg_type: Option<crate::types::MsgType>,
        kind: &str,
        mic: &[u8],
    ) {
        let file = &self.current_file;
        let frame = self.current_frame;
        let mic_hex = render_lower_hex(mic);
        let mt = msg_type_label(msg_type);
        self.write_line(&format!(
            "[invalid_mic] file=\"{file}\" frame={frame} ap={ap_hex} sta={sta_hex} msg_type=\"{mt}\" kind=\"{kind}\" mic_hex={mic_hex}"
        ));
    }

    /// Logs a PMKID rejected as a non-obvious garbage pattern.
    pub fn log_invalid_pmkid(
        &mut self,
        ap_hex: impl std::fmt::Display,
        sta_hex: impl std::fmt::Display,
        kind: &str,
        pmkid: &[u8],
    ) {
        let file = &self.current_file;
        let frame = self.current_frame;
        let pmkid_hex = render_lower_hex(pmkid);
        self.write_line(&format!(
            "[invalid_pmkid] file=\"{file}\" frame={frame} ap={ap_hex} sta={sta_hex} kind=\"{kind}\" pmkid_hex={pmkid_hex}"
        ));
    }

    /// Logs a per-AP summary for hashes dropped due to a missing ESSID (end-of-run).
    pub fn log_essid_not_found_summary(
        &mut self,
        ap_hex: impl std::fmt::Display,
        dropped: u64,
        first_us: u64,
        last_us: u64,
    ) {
        self.write_line(&format!(
            "[essid_not_found_summary] ap={ap_hex} dropped={dropped} first_seen_us={first_us} last_seen_us={last_us}"
        ));
    }

    /// Logs a per-file capture read error.
    pub fn log_capture_read_error(&mut self, path: &std::path::Path, reason: &str) {
        self.write_line(&format!(
            "[capture_read_error] file=\"{}\" frame={} reason=\"{reason}\"",
            path.display(),
            self.current_frame
        ));
    }

    /// Logs an input file that could not be classified.
    pub fn log_skipped_input(&mut self, path: &std::path::Path, reason: &str) {
        self.write_line(&format!("[skipped_input] file=\"{}\" reason=\"{reason}\"", path.display()));
    }

    /// Logs a packet whose `interface_id` has no IDB-registered DLT.
    pub fn log_unknown_linktype(&mut self, interface_id: u32) {
        let file = &self.current_file;
        let frame = self.current_frame;
        self.write_line(&format!("[unknown_linktype] file=\"{file}\" frame={frame} interface_id={interface_id}"));
    }

    // --- Aggregated methods (accumulated, written at flush) ---

    /// Accumulates a link-layer error for end-of-run summary.
    pub fn log_plcp_error(&mut self, reason: &str, dlt: u16) {
        if self.writer.is_some() {
            *self.plcp_counts.entry(PlcpKey { reason: reason.to_owned(), dlt }).or_insert(0) += 1;
        }
    }

    /// Accumulates a malformed MAC header for end-of-run summary.
    pub fn log_malformed_frame(&mut self, reason: &str) {
        if self.writer.is_some() {
            *self.malformed_counts.entry(reason.to_owned()).or_insert(0) += 1;
        }
    }

    /// Accumulates an SSID-with-control-bytes event for end-of-run summary.
    pub const fn log_essid_control_bytes(&mut self) {
        self.essid_control_count += 1;
    }

    /// Accumulates an unknown AKM type for end-of-run summary.
    pub fn log_unknown_akm(&mut self, akm_byte: u8) {
        if self.writer.is_some() {
            *self.unknown_akm_counts.entry(akm_byte).or_insert(0) += 1;
        }
    }

    // --- End-of-run cap alarm ---

    /// Mirrors the loud `--max-eapol-per-type` cap-hit warning into the `--log`
    /// file. Capping bounds rotating-ANonce fan-out but can drop crackable hashes
    /// (a documented never-miss exception, see `ARCHITECTURE.md §8.8` FR-CLI-3), so
    /// the same alarm the main loop prints to stdout is written here too. Call
    /// before [`Self::flush`]; no-ops when no log path is configured or `dropped`
    /// is 0.
    pub fn log_max_eapol_cap(&mut self, cap: usize, dropped: u64) {
        if dropped == 0 {
            return;
        }
        for line in max_eapol_cap_warning_lines(cap, dropped) {
            self.write_line_raw(&line);
        }
    }

    // --- Flush ---

    /// Writes aggregated summaries and flushes the log buffer to disk.
    ///
    /// # Errors
    ///
    /// Returns `Err` on I/O failure.
    pub fn flush(&mut self) -> Result<()> {
        self.write_summaries();
        if let Some(w) = &mut self.writer {
            w.flush()?;
        }
        Ok(())
    }

    /// Writes accumulated summary lines for aggregated categories.
    fn write_summaries(&mut self) {
        if !self.plcp_counts.is_empty() {
            let mut entries: Vec<_> = self.plcp_counts.drain().collect();
            entries.sort_by_key(|e| std::cmp::Reverse(e.1));
            for (key, count) in &entries {
                self.write_line_raw(&format!("[plcp_error] reason=\"{}\" dlt={} count={count}", key.reason, key.dlt));
            }
        }
        if !self.malformed_counts.is_empty() {
            let mut entries: Vec<_> = self.malformed_counts.drain().collect();
            entries.sort_by_key(|e| std::cmp::Reverse(e.1));
            for (reason, count) in &entries {
                self.write_line_raw(&format!("[malformed_frame] reason=\"{reason}\" count={count}"));
            }
        }
        if self.essid_control_count > 0 {
            self.write_line_raw(&format!("[essid_control_bytes] count={}", self.essid_control_count));
        }
        if !self.unknown_akm_counts.is_empty() {
            let mut entries: Vec<_> = self.unknown_akm_counts.drain().collect();
            entries.sort_by_key(|e| std::cmp::Reverse(e.1));
            for (akm_byte, count) in &entries {
                self.write_line_raw(&format!("[unknown_akm] type={akm_byte} count={count}"));
            }
        }
    }

    /// Appends `line` followed by a newline. Used by per-event methods.
    fn write_line(&mut self, line: &str) {
        if let Some(w) = &mut self.writer {
            let _ = writeln!(w, "{line}");
        }
    }

    /// Appends `line` followed by a newline. Used by `write_summaries`.
    fn write_line_raw(&mut self, line: &str) {
        if let Some(w) = &mut self.writer {
            let _ = writeln!(w, "{line}");
        }
    }
}

/// Renders an `Option<MsgType>` as a short label for log fields.
const fn msg_type_label(mt: Option<crate::types::MsgType>) -> &'static str {
    match mt {
        Some(crate::types::MsgType::M1) => "m1",
        Some(crate::types::MsgType::M2) => "m2",
        Some(crate::types::MsgType::M3) => "m3",
        Some(crate::types::MsgType::M4) => "m4",
        None => "unknown",
    }
}

/// Renders `bytes` as a lowercase-hex `String` (two chars per byte, no separators).
fn render_lower_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        hex.push(nibble_to_hex(b >> 4));
        hex.push(nibble_to_hex(b & 0x0F));
    }
    hex
}

/// Converts a 4-bit nibble (0..=15) to its lowercase hex ASCII character.
const fn nibble_to_hex(n: u8) -> char {
    (match n {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }) as char
}

/// Builds the multi-line `--max-eapol-per-type` cap-hit warning.
///
/// Shared by the stdout alarm (printed by the main loop after the stats banner)
/// and the `--log` file (written by [`Logger::log_max_eapol_cap`]), so both carry
/// byte-identical text from a single source. `cap` is the active per-type limit;
/// `dropped` is the number of messages excluded from pairing. Returns one
/// `String` per line, no trailing newline. The `[max_eapol_cap]` marker line
/// keeps the block greppable in the log.
#[must_use]
pub fn max_eapol_cap_warning_lines(cap: usize, dropped: u64) -> Vec<String> {
    vec![
        "================================ WARNING ================================".to_owned(),
        "[max_eapol_cap] --max-eapol-per-type cap was HIT".to_owned(),
        format!("  dropped={dropped} message(s) excluded from pairing; cap={cap} per EAPOL type per (AP, STA)"),
        "  the store still holds every message, but capping can DROP CRACKABLE HASHES".to_owned(),
        "  on rotating-ANonce groups. re-run without --max-eapol-per-type (or --strict),".to_owned(),
        "  or raise the cap, to guarantee every handshake is paired.".to_owned(),
        "========================================================================".to_owned(),
    ]
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
        let mut logger = Logger::new(None).unwrap();
        logger.log_eapol_key_rejected("aabbccddeeff", "112233445566", "truncated_short", b"test");
        logger.log_plcp_error("radiotap it_version 43", 127);
        logger.log_malformed_frame("truncated 802.11 MAC header");
        logger.log_unknown_linktype(0xDEAD_u32);
        logger.log_unknown_akm(0xFF);
        logger.log_essid_not_found_summary("aabbccddeeff", 3, 1_000, 9_000);
        logger.log_capture_read_error(std::path::Path::new("/tmp/example.pcap"), "truncated");
        logger.log_essid_control_bytes();
        assert!(logger.flush().is_ok());
        assert!(logger.writer.is_none());
    }

    #[test]
    fn debug_format_inactive() {
        let logger = Logger::new(None).unwrap();
        let s = format!("{logger:?}");
        assert!(s.contains("active: false"));
    }

    #[test]
    fn per_event_includes_file_and_frame_context() {
        use std::io::Read as _;
        let tmp = std::env::temp_dir().join("wpawolf_log_per_event.log");
        {
            let mut logger = Logger::new(Some(&tmp)).unwrap();
            logger.set_file("../cap/test.pcap");
            logger.set_frame(42);
            logger.log_eapol_key_rejected("aabbccddeeff", "112233445566", "bad_kdv", b"\xaa\xbb");
            logger.log_unknown_linktype(7);
            logger.set_frame(100);
            logger.log_capture_read_error(std::path::Path::new("../cap/test.pcap"), "need 30 bytes, got 0");
            logger.flush().unwrap();
        }
        let mut contents = String::new();
        std::fs::File::open(&tmp).unwrap().read_to_string(&mut contents).unwrap();
        assert!(
            contents.contains("file=\"../cap/test.pcap\" frame=42 ap=aabbccddeeff"),
            "eapol_key_rejected missing context; got: {contents}"
        );
        assert!(
            contents.contains("[unknown_linktype] file=\"../cap/test.pcap\" frame=42"),
            "unknown_linktype missing context; got: {contents}"
        );
        assert!(
            contents.contains("[capture_read_error] file=\"../cap/test.pcap\" frame=100"),
            "capture_read_error missing frame; got: {contents}"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn aggregated_summaries_appear_at_flush() {
        use std::io::Read as _;
        let tmp = std::env::temp_dir().join("wpawolf_log_aggregated.log");
        {
            let mut logger = Logger::new(Some(&tmp)).unwrap();
            logger.log_plcp_error("radiotap it_version 43", 127);
            logger.log_plcp_error("radiotap it_version 43", 127);
            logger.log_plcp_error("PPI header length 0", 192);
            logger.log_malformed_frame("truncated 802.11 MAC header");
            logger.log_malformed_frame("truncated 802.11 MAC header");
            logger.log_malformed_frame("truncated 4-address MAC header");
            logger.log_essid_control_bytes();
            logger.log_essid_control_bytes();
            logger.log_essid_control_bytes();
            logger.log_unknown_akm(255);
            logger.log_unknown_akm(255);
            logger.log_unknown_akm(42);
            logger.flush().unwrap();
        }
        let mut contents = String::new();
        std::fs::File::open(&tmp).unwrap().read_to_string(&mut contents).unwrap();
        assert!(contents.contains("[plcp_error] reason=\"radiotap it_version 43\" dlt=127 count=2"));
        assert!(contents.contains("[plcp_error] reason=\"PPI header length 0\" dlt=192 count=1"));
        assert!(contents.contains("[malformed_frame] reason=\"truncated 802.11 MAC header\" count=2"));
        assert!(contents.contains("[malformed_frame] reason=\"truncated 4-address MAC header\" count=1"));
        assert!(contents.contains("[essid_control_bytes] count=3"));
        assert!(contents.contains("[unknown_akm] type=255 count=2"));
        assert!(contents.contains("[unknown_akm] type=42 count=1"));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn render_lower_hex_empty_returns_empty() {
        assert_eq!(render_lower_hex(&[]), "");
    }

    #[test]
    fn render_lower_hex_known_bytes() {
        assert_eq!(render_lower_hex(&[0x00, 0x0F, 0xF0, 0xFF]), "000ff0ff");
        assert_eq!(render_lower_hex(b"AB"), "4142");
    }

    #[test]
    fn eapol_key_rejected_uses_bare_hex() {
        use std::io::Read as _;
        let tmp = std::env::temp_dir().join("wpawolf_log_eapol_bare_hex.log");
        {
            let mut logger = Logger::new(Some(&tmp)).unwrap();
            logger.set_file("test.pcap");
            logger.set_frame(1);
            logger.log_eapol_key_rejected("aabbccddeeff", "112233445566", "bad_kdv", &[0xAA, 0xBB, 0x03]);
            logger.flush().unwrap();
        }
        let mut contents = String::new();
        std::fs::File::open(&tmp).unwrap().read_to_string(&mut contents).unwrap();
        assert!(contents.contains("bytes=aabb03"), "expected unquoted bare hex; got: {contents}");
        assert!(!contents.contains("bytes=aa:"), "found colon-separated hex; got: {contents}");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn no_op_aggregation_does_not_allocate() {
        let mut logger = Logger::new(None).unwrap();
        logger.log_plcp_error("test", 127);
        logger.log_malformed_frame("test");
        logger.log_unknown_akm(42);
        assert!(logger.plcp_counts.is_empty());
        assert!(logger.malformed_counts.is_empty());
        assert!(logger.unknown_akm_counts.is_empty());
    }

    #[test]
    fn max_eapol_cap_warning_carries_cap_and_dropped() {
        let lines = max_eapol_cap_warning_lines(500, 1426);
        let blob = lines.join("\n");
        assert!(blob.contains("[max_eapol_cap]"), "missing greppable marker; got: {blob}");
        assert!(blob.contains("cap=500"), "missing cap value; got: {blob}");
        assert!(blob.contains("dropped=1426"), "missing dropped count; got: {blob}");
        assert!(blob.contains("DROP CRACKABLE HASHES"), "missing the loud warning; got: {blob}");
        assert!(blob.contains("WARNING"), "missing the banner border; got: {blob}");
    }

    #[test]
    fn log_max_eapol_cap_writes_block_to_file() {
        use std::io::Read as _;
        let tmp = std::env::temp_dir().join("wpawolf_log_max_eapol_cap.log");
        {
            let mut logger = Logger::new(Some(&tmp)).unwrap();
            logger.log_max_eapol_cap(500, 1426);
            logger.flush().unwrap();
        }
        let mut contents = String::new();
        std::fs::File::open(&tmp).unwrap().read_to_string(&mut contents).unwrap();
        assert!(contents.contains("[max_eapol_cap] --max-eapol-per-type cap was HIT"), "got: {contents}");
        assert!(contents.contains("cap=500"), "got: {contents}");
        assert!(contents.contains("dropped=1426"), "got: {contents}");
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn log_max_eapol_cap_zero_is_silent() {
        use std::io::Read as _;
        let tmp = std::env::temp_dir().join("wpawolf_log_max_eapol_cap_zero.log");
        {
            let mut logger = Logger::new(Some(&tmp)).unwrap();
            logger.log_max_eapol_cap(500, 0);
            logger.flush().unwrap();
        }
        let mut contents = String::new();
        std::fs::File::open(&tmp).unwrap().read_to_string(&mut contents).unwrap();
        assert!(!contents.contains("max_eapol_cap"), "zero-drop run must not warn; got: {contents}");
        let _ = std::fs::remove_file(&tmp);
    }
}
