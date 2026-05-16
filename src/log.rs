//! Shared -- structured logger for malformed-frame events. See ARCHITECTURE.md §4.
//!
//! Appends categorised log lines to the file specified by `--log`. Ten categories,
//! every one wired to a distinct call site:
//!
//! - `malformed_frame`    -- truncated or structurally invalid 802.11 / EAPOL data.
//! - `plcp_error`         -- link-layer header validation failed (radiotap / PPI /
//!   Prism / AVS error, or an unsupported DLT).
//! - `unknown_linktype`   -- a pcapng EPB referenced an `interface_id` for which no
//!   preceding IDB exists.
//! - `unknown_akm`        -- AKM suite type outside IEEE 802.11-2024 Table 9-190.
//! - `essid_not_found_summary` -- per-AP summary line for hashes dropped because
//!   no ESSID was ever observed for the AP. Carries the AP MAC, the count of
//!   would-have-been-emitted lines, and the earliest / latest packet timestamps
//!   the AP appeared in. Emitted once per affected AP at end of run.
//! - `capture_read_error` -- per-file ingest error, typically a truncated trailing
//!   packet record (FR-IN-10).
//! - `skipped_input`      -- file passed to the ingest loop whose magic bytes did
//!   not match any supported capture format (typically a sub-4-byte stub or a
//!   non-capture file slipped through). Counted in stats and silenced on stderr;
//!   triage detail goes here.
//! - `out_of_sequence_timestamp` -- informational: a packet's pcap timestamp went
//!   backward relative to the previous packet in the same file. Capture-tool
//!   artifact (typically aircrack-ng deadly-clean or mergecap with strict
//!   time-stamps disabled); wpawolf processes the packet normally. Capped at the
//!   first 10 inversions per file to keep tampered captures from flooding the
//!   log; the `Stats::out_of_sequence_timestamps` counter still tallies every
//!   inversion across the run.
//! - `invalid_nonce`      -- EAPOL frame discarded: nonce was NULL, all-`0xFF`,
//!   or a short-period repeating pattern (`repeat_1` / `repeat_2` / `repeat_4`).
//!   Applies to every message type including M4: M4 NULL nonce is spec-valid on
//!   the wire per [IEEE 802.11-2024] §12.7.6.5 but the resulting EAPOL hash
//!   line is cryptographically dead because the live PTK requires M2's `SNonce`,
//!   which the M4 frame does not carry. The line carries `nonce_hex=` (32
//!   bytes lowercase hex) so the rejected bytes are preserved for forensic
//!   triage.
//! - `invalid_mic`        -- EAPOL frame discarded: MIC was NULL, all-`0xFF`, or
//!   a short-period repeating pattern when the Key MIC flag was set (M2/M3/M4).
//!   The line carries `mic_hex=` (16 or 24 bytes lowercase hex per AKM).
//! - `invalid_pmkid`      -- PMKID discarded: NULL, all-`0xFF`, or short-period
//!   repeating pattern. The line carries `pmkid_hex=` (16 bytes lowercase hex).
//! - `essid_control_bytes` -- SSID informational notice, **not a discard and
//!   not a warning about wpawolf's behaviour**: the SSID byte run contained at
//!   least one byte in `0x00..=0x1F` (the full ASCII C0 control range, NUL
//!   through US -- every control character). Per [IEEE 802.11-2024] §9.4.2.2
//!   the SSID element is "an arbitrary sequence of 0-32 octets" with no
//!   encoding restriction, so a control-byte SSID is valid on the wire and
//!   wpawolf is required to handle it. The SSID is shipped to hashcat
//!   byte-for-byte unchanged (`extract::common::insert_essid`); the line is
//!   emitted only so an operator triaging a capture can locate the source
//!   frame, with `essid_hex=` carrying the raw bytes in lowercase hex. SSIDs
//!   that fail the spec-driven length / first-byte-zero gate are discarded
//!   silently by upstream counters and are NOT logged here.
//!
//! Line format: `[category] <category-specific fields...>`. Each `Logger::log_*`
//! method defines its own field layout -- frame-bearing categories
//! (`malformed_frame`, `plcp_error`, `invalid_nonce`, `invalid_mic`,
//! `invalid_pmkid`, `essid_control_bytes`) lead with `timestamp_us`; the rest
//! carry only the field(s) relevant to the event (e.g. `unknown_akm` carries
//! just the AKM byte). Discard categories (`invalid_nonce`, `invalid_mic`,
//! `invalid_pmkid`) end with a `*_hex=` field carrying the rejected bytes in
//! lowercase hex so an operator can grep the source capture for the exact
//! value; `essid_control_bytes` carries `essid_hex=` for the same triage
//! reason despite not being a discard category.
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

    /// Logs a per-AP summary for hashes dropped due to a missing ESSID.
    ///
    /// Emitted once per AP at the end of the output run with the count of
    /// would-have-been-emitted hash lines and the earliest / latest packet
    /// timestamps the AP appeared in. The timestamps let an operator open the
    /// originating capture and locate the AP's traffic without scrubbing the
    /// whole file.
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

    /// Logs an EAPOL-Key frame whose Key Nonce was rejected as a sentinel value.
    ///
    /// `kind` is one of `"null"` (all-`0x00` nonce, applies to every message type
    /// including M4), `"ff"` (all-`0xFF` nonce, firmware flash-erase pattern),
    /// or `"repeat_1"` / `"repeat_2"` / `"repeat_4"` (short-period repeating
    /// patterns indicative of firmware stub or test-fixture data). M4 NULL
    /// nonce is spec-valid on the wire per [IEEE 802.11-2024] §12.7.6.5 but
    /// the resulting EAPOL hash line is mathematically uncrackable -- the
    /// live PTK depends on M2's `SNonce`, which the M4 frame does not carry --
    /// so it is dropped and logged like any other garbage nonce. `msg_type` is
    /// the pre-parse EAPOL-Key classification (M1 / M2 / M3 / M4 or `None`
    /// when truncation prevented it); rendered as `msg_type=mN` (or
    /// `msg_type=unknown`) so the operator can grep for an M4 spec-zero
    /// rejection (expected) vs an M1 / M2 / M3 NULL nonce (abnormal). `nonce`
    /// is the rejected 32-byte Key Nonce; the line carries it as `nonce_hex=`
    /// in lowercase hex so the operator can grep the source capture for the
    /// exact bytes.
    pub fn log_invalid_nonce(
        &mut self,
        timestamp_us: u64,
        ap_hex: impl std::fmt::Display,
        sta_hex: impl std::fmt::Display,
        msg_type: Option<crate::types::MsgType>,
        kind: &str,
        nonce: &[u8],
    ) {
        let nonce_hex = render_lower_hex(nonce);
        let mt = msg_type_label(msg_type);
        self.write_line(&format!(
            "[invalid_nonce] {timestamp_us} ap={ap_hex} sta={sta_hex} msg_type={mt} kind={kind} nonce_hex={nonce_hex}"
        ));
    }

    /// Logs an EAPOL-Key frame whose Key MIC was rejected as a sentinel value.
    ///
    /// `kind` is one of `"null"` / `"ff"` / `"repeat_1"` / `"repeat_2"` /
    /// `"repeat_4"` (see [`Self::log_invalid_nonce`]). Only fires when the Key
    /// MIC flag (Key Information bit B8) is set, i.e. M2 / M3 / M4. M1 has no
    /// MIC by spec and is never logged here. `msg_type` is the pre-parse
    /// classification rendered as `msg_type=mN` so the operator can filter the
    /// log by message type. `mic` is the rejected MIC bytes (16 or 24 wide
    /// per AKM); rendered as `mic_hex=` in lowercase hex.
    pub fn log_invalid_mic(
        &mut self,
        timestamp_us: u64,
        ap_hex: impl std::fmt::Display,
        sta_hex: impl std::fmt::Display,
        msg_type: Option<crate::types::MsgType>,
        kind: &str,
        mic: &[u8],
    ) {
        let mic_hex = render_lower_hex(mic);
        let mt = msg_type_label(msg_type);
        self.write_line(&format!(
            "[invalid_mic] {timestamp_us} ap={ap_hex} sta={sta_hex} msg_type={mt} kind={kind} mic_hex={mic_hex}"
        ));
    }

    /// Logs an EAPOL-Key frame that passed the LLC/packet-type gate but was rejected
    /// by the EAPOL-Key parser for a reason other than a garbage nonce or MIC
    /// (those are already captured by `[invalid_nonce]` / `[invalid_mic]`).
    ///
    /// `reason` is the string returned by `eapol::parse_rejection_reason`.
    /// `raw` is the full MSDU body; the first 32 bytes are rendered as lowercase
    /// hex in the `bytes=` field for cross-referencing with tshark / Wireshark.
    pub fn log_eapol_key_rejected(
        &mut self,
        timestamp_us: u64,
        ap_hex: impl std::fmt::Display,
        sta_hex: impl std::fmt::Display,
        reason: &str,
        raw: &[u8],
    ) {
        let bytes_hex: String = raw.iter().take(32).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
        self.write_line(&format!(
            "[eapol_key_rejected] {timestamp_us} ap={ap_hex} sta={sta_hex} reason={reason} bytes={bytes_hex}"
        ));
    }

    /// Logs a PMKID rejected as a sentinel or repeating-pattern value.
    ///
    /// `kind` is one of `"null"` (AP placeholder meaning "no cached PMK"),
    /// `"ff"` (firmware flash-erase sentinel), or `"repeat_1"` / `"repeat_2"`
    /// / `"repeat_4"` (short-period repeating patterns). Fires from every
    /// PMKID extraction site (M1 KDE, M2 RSN IE, `AssocReq`, `ReassocReq`,
    /// FT/FILS/PASN Auth, FT Action frames, Probe Request, Beacon,
    /// `ProbeResp`, Mesh Peering, OSEN IE). `pmkid` is the rejected 16-byte
    /// PMKID; rendered as `pmkid_hex=` in lowercase hex.
    pub fn log_invalid_pmkid(
        &mut self,
        timestamp_us: u64,
        ap_hex: impl std::fmt::Display,
        sta_hex: impl std::fmt::Display,
        kind: &str,
        pmkid: &[u8],
    ) {
        let pmkid_hex = render_lower_hex(pmkid);
        self.write_line(&format!(
            "[invalid_pmkid] {timestamp_us} ap={ap_hex} sta={sta_hex} kind={kind} pmkid_hex={pmkid_hex}"
        ));
    }

    /// Logs an SSID informational notice when the byte run contains at least
    /// one byte in the `0x00..=0x1F` ASCII C0 control range (NUL through US --
    /// every control character). **This is not a discard and not a warning
    /// that wpawolf altered the SSID.** Per [IEEE 802.11-2024] §9.4.2.2 the
    /// SSID element is "an arbitrary sequence of 0-32 octets" with no
    /// printable-character requirement, so a control-byte SSID is valid on
    /// the wire and wpawolf is required to handle it; the cracker may still
    /// recover the right PMK from such an SSID. The SSID is shipped to
    /// hashcat byte-for-byte unchanged. The line is emitted only so an
    /// operator triaging a capture can locate the source frame (such bytes
    /// are rare in production network names and may correlate with a
    /// bit-flipped or test-injected SSID worth a closer look). It carries
    /// `essid_hex=...` in lowercase hex so the source frame can be located
    /// by raw byte sequence rather than by potentially-unprintable
    /// rendering. Fires from every SSID-extract site (Beacon, Probe Request
    /// / Response, Association / Reassociation Request, Action Measurement
    /// IE, OWE Transition Mode).
    /// Logs the first time a `(AP, STA, msg_type)` group hits the per-type EAPOL cap.
    ///
    /// Only called once per `(AP, STA, type)` combo (`is_new_saturation = true` from
    /// `MessageStore::add`). Subsequent drops for the same combo only increment the
    /// stats counter. The `cap` field is the configured `--max-eapol-per-type` value
    /// so the operator knows what threshold was hit. `msg_type` is the string label
    /// (`m1` / `m2` / `m3` / `m4`) matching the `[invalid_nonce]` convention.
    pub fn log_eapol_group_saturated(
        &mut self,
        timestamp_us: u64,
        ap_hex: impl std::fmt::Display,
        sta_hex: impl std::fmt::Display,
        msg_type: crate::types::MsgType,
        cap: usize,
    ) {
        let mt = msg_type_label(Some(msg_type));
        self.write_line(&format!(
            "[eapol_group_saturated] {timestamp_us} ap={ap_hex} sta={sta_hex} msg_type={mt} cap={cap}"
        ));
    }

    /// Logs an SSID that contains at least one ASCII C0 control byte (`0x00..=0x1F`). See the field doc in `Stats`.
    pub fn log_essid_control_bytes(&mut self, timestamp_us: u64, ap_hex: impl std::fmt::Display, essid: &[u8]) {
        let essid_hex = render_lower_hex(essid);
        self.write_line(&format!("[essid_control_bytes] {timestamp_us} ap={ap_hex} essid_hex={essid_hex}"));
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

    /// Logs an input file that the ingest loop opened but could not classify.
    ///
    /// Emitted when `open_reader` returns `Error::UnknownFormat`: the file does
    /// not start with a recognised capture-file magic. Typical causes are
    /// sub-4-byte stub files in a watch directory, or a regular non-capture
    /// file that slipped through directory-walk magic filtering due to a TOCTOU
    /// race (the file shrunk between the walk and the open). The ingest loop
    /// continues with the next input; the operator's stderr stays clean.
    /// `reason` is the `Error`'s `Display` form so the magic bytes / cause are
    /// preserved for triage.
    pub fn log_skipped_input(&mut self, path: &std::path::Path, reason: &str) {
        self.write_line(&format!("[skipped_input] path={} reason={reason}", path.display()));
    }

    /// Logs a packet whose pcap timestamp went backward relative to the
    /// previous packet in the same input file.
    ///
    /// Informational diagnostic, not a discard. A monotonic packet sequence is
    /// what any well-behaved capture tool produces; inversions almost always
    /// indicate the file has been post-processed (aircrack-ng deadly-clean,
    /// mergecap with `--strict-time-stamps=false`, hand-edited). wpawolf
    /// itself does not care -- the pairing engine works on `(AP, STA)`
    /// groups, not on file order. Matches the
    /// `Warning: out of sequence timestamps!` line that hcxpcapngtool 7.1.2
    /// prints on the same input. Call sites cap the number of log lines per
    /// file (default: first 10 inversions per file) so a deeply-shuffled
    /// capture does not flood the log; the `Stats::out_of_sequence_timestamps`
    /// counter still tallies every inversion across the whole run.
    pub fn log_out_of_sequence_timestamp(&mut self, path: &std::path::Path, previous_ts_us: u64, current_ts_us: u64) {
        self.write_line(&format!(
            "[out_of_sequence_timestamp] path={} previous_ts_us={previous_ts_us} current_ts_us={current_ts_us}",
            path.display()
        ));
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

/// Renders an `Option<MsgType>` as a short label suitable for the
/// `msg_type=` field in `[invalid_nonce]` / `[invalid_mic]` log lines. M1 / M2
/// / M3 / M4 -> `m1` / `m2` / `m3` / `m4`; `None` -> `unknown` (the pre-parse
/// classifier could not determine the message type, typically because the
/// frame is truncated).
const fn msg_type_label(mt: Option<crate::types::MsgType>) -> &'static str {
    match mt {
        Some(crate::types::MsgType::M1) => "m1",
        Some(crate::types::MsgType::M2) => "m2",
        Some(crate::types::MsgType::M3) => "m3",
        Some(crate::types::MsgType::M4) => "m4",
        None => "unknown",
    }
}

/// Renders `bytes` as a lowercase-hex `String` (two chars per byte, no
/// separators). Used by every discard-category logger so an operator can grep
/// the source capture for the exact byte sequence that triggered the drop.
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
        logger.log_essid_not_found_summary("aabbccddeeff", 3, 1_000, 9_000);
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

    #[test]
    fn render_lower_hex_empty_returns_empty() {
        assert_eq!(render_lower_hex(&[]), "");
    }

    #[test]
    fn render_lower_hex_known_bytes() {
        // Round-trips every nibble pair through the lookup table; locks the
        // exact byte ordering callers grep for.
        assert_eq!(render_lower_hex(&[0x00, 0x0F, 0xF0, 0xFF]), "000ff0ff");
        assert_eq!(render_lower_hex(b"AB"), "4142");
    }

    #[test]
    fn writes_invalid_nonce_with_hex() {
        use std::io::Read as _;
        let tmp = std::env::temp_dir().join("wpawolf_log_invalid_nonce.log");
        {
            let mut logger = Logger::new(Some(&tmp)).unwrap();
            // Sample garbage nonce: alternating 0x12 / 0x34 -- the test covers
            // the line layout, not the rejection logic (which is tested in
            // ieee80211::eapol).
            let nonce = [0x12u8, 0x34, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34];
            logger.log_invalid_nonce(
                7_000,
                "aabbccddeeff",
                "112233445566",
                Some(crate::types::MsgType::M2),
                "repeat_2",
                &nonce,
            );
            logger.flush().unwrap();
        }
        let mut contents = String::new();
        std::fs::File::open(&tmp).unwrap().read_to_string(&mut contents).unwrap();
        assert!(
            contents.contains(
                "[invalid_nonce] 7000 ap=aabbccddeeff sta=112233445566 msg_type=m2 kind=repeat_2 nonce_hex=1234123412341234"
            ),
            "missing invalid_nonce line with msg_type + nonce_hex; got: {contents}"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn writes_invalid_nonce_with_unknown_msg_type() {
        // When the pre-parse classifier could not determine the message type
        // (truncated frame, malformed Key Info), `None` renders as `unknown` so
        // an operator can still grep the log line consistently.
        use std::io::Read as _;
        let tmp = std::env::temp_dir().join("wpawolf_log_invalid_nonce_unknown.log");
        {
            let mut logger = Logger::new(Some(&tmp)).unwrap();
            let nonce = [0u8; 8];
            logger.log_invalid_nonce(1_000, "aabbccddeeff", "112233445566", None, "null", &nonce);
            logger.flush().unwrap();
        }
        let mut contents = String::new();
        std::fs::File::open(&tmp).unwrap().read_to_string(&mut contents).unwrap();
        assert!(
            contents.contains("msg_type=unknown"),
            "expected msg_type=unknown when classifier returned None; got: {contents}"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn writes_invalid_mic_with_hex() {
        use std::io::Read as _;
        let tmp = std::env::temp_dir().join("wpawolf_log_invalid_mic.log");
        {
            let mut logger = Logger::new(Some(&tmp)).unwrap();
            let mic = [0xFFu8; 16];
            logger.log_invalid_mic(8_000, "aabbccddeeff", "112233445566", Some(crate::types::MsgType::M3), "ff", &mic);
            logger.flush().unwrap();
        }
        let mut contents = String::new();
        std::fs::File::open(&tmp).unwrap().read_to_string(&mut contents).unwrap();
        assert!(
            contents.contains(
                "[invalid_mic] 8000 ap=aabbccddeeff sta=112233445566 msg_type=m3 kind=ff \
                 mic_hex=ffffffffffffffffffffffffffffffff"
            ),
            "missing invalid_mic line with mic_hex; got: {contents}"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn writes_invalid_pmkid_with_hex() {
        use std::io::Read as _;
        let tmp = std::env::temp_dir().join("wpawolf_log_invalid_pmkid.log");
        {
            let mut logger = Logger::new(Some(&tmp)).unwrap();
            let pmkid = [0u8; 16];
            logger.log_invalid_pmkid(9_000, "aabbccddeeff", "112233445566", "null", &pmkid);
            logger.flush().unwrap();
        }
        let mut contents = String::new();
        std::fs::File::open(&tmp).unwrap().read_to_string(&mut contents).unwrap();
        assert!(
            contents.contains(
                "[invalid_pmkid] 9000 ap=aabbccddeeff sta=112233445566 kind=null \
                 pmkid_hex=00000000000000000000000000000000"
            ),
            "missing invalid_pmkid line with pmkid_hex; got: {contents}"
        );
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn writes_skipped_input() {
        use std::io::Read as _;
        let tmp = std::env::temp_dir().join("wpawolf_log_skipped_input.log");
        {
            let mut logger = Logger::new(Some(&tmp)).unwrap();
            logger.log_skipped_input(
                std::path::Path::new("/srv/captures/staging/sample-stub"),
                "unrecognised file format (magic bytes: file too short to detect format (< 4 bytes))",
            );
            logger.flush().unwrap();
        }
        let mut contents = String::new();
        std::fs::File::open(&tmp).unwrap().read_to_string(&mut contents).unwrap();
        assert!(
            contents.contains(
                "[skipped_input] path=/srv/captures/staging/sample-stub reason=unrecognised file format \
                 (magic bytes: file too short to detect format (< 4 bytes))"
            ),
            "missing skipped_input line; got: {contents}"
        );
        let _ = std::fs::remove_file(&tmp);
    }
}
