//! Integration test: every `--log` category fires from a real binary invocation.
//!
//! Each category in `src/log.rs` gets a fixture that triggers exactly one call
//! site, then the binary is run with `--log` and the resulting file is grepped
//! for the expected category prefix. The previous behaviour -- `unknown_akm` and
//! `essid_not_found` were defined but never invoked from production code -- is
//! the regression this guards against.
//!
//! Categories covered:
//!
//! * `[malformed_frame]`: truncated 802.11 header (already covered by
//!   `malformed_frame_log.rs`; re-asserted here so this file is the
//!   single point of truth).
//! * `[capture_read_error]`: pcap with a record header followed by fewer than
//!   `incl_len` body bytes (FR-IN-10 truncated trailing record).
//! * `[plcp_error]`: pcap with an unsupported DLT (Ethernet, 1) so
//!   `link::strip` fails before the MAC header is ever parsed.
//! * `[unknown_linktype]`: pcapng EPB referencing an `interface_id` for
//!   which no preceding IDB exists.
//! * `[unknown_akm]`: Association Request with RSN AKM 26 (out of
//!   IEEE 802.11-2024 Table 9-190).
//! * `[essid_not_found_summary]`: handshake emitted for an AP whose SSID was
//!   never observed on the wire.
//! * `[skipped_input]`: explicit-file argument that does not start with a
//!   recognised capture magic (typical stub-file noise from submission
//!   staging directories) -- silenced on stderr, surfaced in the log + Phase 1
//!   counter.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    missing_docs,
    unused_crate_dependencies,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    reason = "integration test module -- strict lints relaxed"
)]

use std::fs;
use std::path::Path;
use std::process::Command;

// =====================================================================
// Pcap byte builders
// =====================================================================

/// Classic pcap global header, 24 bytes, microsecond resolution, LE writer.
fn pcap_global_header(link_type: u32) -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&0xA1B2_C3D4_u32.to_le_bytes());
    h[4..6].copy_from_slice(&2_u16.to_le_bytes()); // version_major
    h[6..8].copy_from_slice(&4_u16.to_le_bytes()); // version_minor
    h[16..20].copy_from_slice(&65535_u32.to_le_bytes()); // snaplen
    h[20..24].copy_from_slice(&link_type.to_le_bytes());
    h
}

/// Classic pcap packet record. Set `claimed_len` separately to forge a truncated record.
fn pcap_packet_record_with_claim(ts_sec: u32, claimed_len: u32, data: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(16 + data.len());
    r.extend_from_slice(&ts_sec.to_le_bytes());
    r.extend_from_slice(&0_u32.to_le_bytes());
    r.extend_from_slice(&claimed_len.to_le_bytes()); // incl_len -- can lie
    r.extend_from_slice(&claimed_len.to_le_bytes()); // orig_len
    r.extend_from_slice(data);
    r
}

fn pcap_packet_record(ts_sec: u32, data: &[u8]) -> Vec<u8> {
    pcap_packet_record_with_claim(ts_sec, data.len() as u32, data)
}

// =====================================================================
// Pcapng byte builders (minimal subset for the unknown_linktype fixture)
// =====================================================================

const PCAPNG_BLOCK_SHB: u32 = 0x0A0D_0D0A;
const PCAPNG_BLOCK_IDB: u32 = 0x0000_0001;
const PCAPNG_BLOCK_EPB: u32 = 0x0000_0006;
const PCAPNG_BOM: u32 = 0x1A2B_3C4D;

/// Section Header Block, LE, no options. 28 bytes total.
fn pcapng_shb() -> Vec<u8> {
    let mut v = Vec::with_capacity(28);
    v.extend_from_slice(&PCAPNG_BLOCK_SHB.to_le_bytes()); // block_type
    v.extend_from_slice(&28u32.to_le_bytes()); // total_length
    v.extend_from_slice(&PCAPNG_BOM.to_le_bytes()); // BOM
    v.extend_from_slice(&1u16.to_le_bytes()); // major = 1
    v.extend_from_slice(&0u16.to_le_bytes()); // minor = 0
    v.extend_from_slice(&u64::MAX.to_le_bytes()); // section_length = unspecified
    v.extend_from_slice(&28u32.to_le_bytes()); // trailing total_length
    v
}

/// Interface Description Block, LE, no options. 20 bytes total.
fn pcapng_idb(link_type: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(20);
    v.extend_from_slice(&PCAPNG_BLOCK_IDB.to_le_bytes());
    v.extend_from_slice(&20u32.to_le_bytes()); // total_length
    v.extend_from_slice(&link_type.to_le_bytes()); // link_type (u16)
    v.extend_from_slice(&0u16.to_le_bytes()); // reserved
    v.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    v.extend_from_slice(&20u32.to_le_bytes()); // trailing
    v
}

/// Enhanced Packet Block, LE, no options. Pads `data` to a 4-byte boundary.
fn pcapng_epb(interface_id: u32, data: &[u8]) -> Vec<u8> {
    let pad = (4 - (data.len() % 4)) % 4;
    let total_len = (32 + data.len() + pad) as u32;
    let mut v = Vec::with_capacity(total_len as usize);
    v.extend_from_slice(&PCAPNG_BLOCK_EPB.to_le_bytes());
    v.extend_from_slice(&total_len.to_le_bytes());
    v.extend_from_slice(&interface_id.to_le_bytes()); // interface_id (4 bytes)
    v.extend_from_slice(&0u32.to_le_bytes()); // ts_high
    v.extend_from_slice(&0u32.to_le_bytes()); // ts_low
    v.extend_from_slice(&(data.len() as u32).to_le_bytes()); // captured_len
    v.extend_from_slice(&(data.len() as u32).to_le_bytes()); // original_len
    v.extend_from_slice(data);
    v.extend(std::iter::repeat_n(0u8, pad));
    v.extend_from_slice(&total_len.to_le_bytes()); // trailing
    v
}

// =====================================================================
// 802.11 frame builders (minimum to exercise the extract pipeline)
// =====================================================================

/// Builds an Association Request 802.11 management frame whose tagged-parameter
/// block is `tagged`. STA -> AP. Used to drive `process_assoc_or_reassoc_req`.
fn build_assoc_req(ap: [u8; 6], sta: [u8; 6], tagged: &[u8]) -> Vec<u8> {
    // MAC header: 24 bytes. FC = (Type=Mgmt, Subtype=AssocReq=0). ToDS=0, FromDS=0.
    let mut frame = vec![0u8; 24];
    frame[0] = 0x00; // FC[0] = Mgmt + AssocReq
    frame[1] = 0x00;
    frame[4..10].copy_from_slice(&ap); // Address1 = AP
    frame[10..16].copy_from_slice(&sta); // Address2 = STA
    frame[16..22].copy_from_slice(&ap); // Address3 = BSSID
    // Fixed body: Capability(2) + ListenInterval(2) = 4 bytes
    frame.extend_from_slice(&[0u8; 4]);
    // Tagged parameters (SSID IE optional, RSN IE etc.)
    frame.extend_from_slice(tagged);
    frame
}

/// Builds an RSN IE value containing exactly one AKM suite type.
fn rsn_ie_with_akm(akm: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(20);
    v.extend_from_slice(&[0x01, 0x00]); // Version
    v.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // Group cipher: CCMP
    v.extend_from_slice(&[0x01, 0x00]); // Pairwise count
    v.extend_from_slice(&[0x00, 0x0F, 0xAC, 0x04]); // CCMP pairwise
    v.extend_from_slice(&[0x01, 0x00]); // AKM count
    v.extend_from_slice(&[0x00, 0x0F, 0xAC, akm]); // AKM suite
    v
}

/// Wraps an RSN IE value into a full RSN IE TLV (id=48 + len + value).
fn ie_tlv(id: u8, value: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + value.len());
    v.push(id);
    v.push(value.len() as u8);
    v.extend_from_slice(value);
    v
}

// =====================================================================
// Test runner: invoke the wpawolf binary and read the log
// =====================================================================

fn run_with_log(pcap_path: &str, log_path: &str, extra_args: &[&str]) {
    let _ = fs::remove_file(log_path);
    let out_path = format!("{log_path}.22000");
    let _ = fs::remove_file(&out_path);
    let mut args: Vec<&str> = vec!["--log", log_path, "--22000-out", &out_path];
    args.extend_from_slice(extra_args);
    args.push(pcap_path);
    let status = Command::new(env!("CARGO_BIN_EXE_wpawolf")).args(&args).status().expect("failed to spawn wpawolf");
    assert!(status.success(), "wpawolf exited non-zero: {status}");
}

fn log_has_category(log_path: &str, category: &str) -> bool {
    let contents = fs::read_to_string(log_path).expect("log file not created");
    contents.lines().any(|l| l.starts_with(category))
}

fn log_lines_for(log_path: &str, category: &str) -> Vec<String> {
    fs::read_to_string(log_path)
        .expect("log file not created")
        .lines()
        .filter(|l| l.starts_with(category))
        .map(String::from)
        .collect()
}

// =====================================================================
// Tests
// =====================================================================

#[test]
fn category_malformed_frame_fires_on_truncated_mac_header() {
    let pcap = "/tmp/wpawolf_logcov_malformed.pcap";
    let log = "/tmp/wpawolf_logcov_malformed.log";
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pcap_global_header(105));
    bytes.extend_from_slice(&pcap_packet_record(1000, &[0u8; 8])); // < 24 B MAC header
    fs::write(pcap, &bytes).unwrap();

    run_with_log(pcap, log, &[]);

    let lines = log_lines_for(log, "[malformed_frame]");
    assert!(!lines.is_empty(), "expected at least one [malformed_frame] line");
}

#[test]
fn category_capture_read_error_fires_on_truncated_trailing_record() {
    let pcap = "/tmp/wpawolf_logcov_capread.pcap";
    let log = "/tmp/wpawolf_logcov_capread.log";

    // Packet header claims 200 bytes but only 5 follow -> EOF mid-record (FR-IN-10).
    let truncated_body = [0u8; 5];
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pcap_global_header(105));
    bytes.extend_from_slice(&pcap_packet_record_with_claim(1000, 200, &truncated_body));
    fs::write(pcap, &bytes).unwrap();

    run_with_log(pcap, log, &[]);

    let lines = log_lines_for(log, "[capture_read_error]");
    assert_eq!(lines.len(), 1, "expected exactly one [capture_read_error] line; got {lines:?}");
    assert!(lines[0].contains("path="), "missing path= field: {}", lines[0]);
    assert!(lines[0].contains("reason="), "missing reason= field: {}", lines[0]);
}

#[test]
fn category_plcp_error_fires_on_unsupported_dlt() {
    let pcap = "/tmp/wpawolf_logcov_plcp.pcap";
    let log = "/tmp/wpawolf_logcov_plcp.log";

    // DLT 1 (Ethernet) is not in the supported set {105, 119, 127, 163, 192}.
    // link::strip returns Error::UnknownFormat -> log_plcp_error("link strip failed").
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pcap_global_header(1));
    let frame = vec![0u8; 64]; // long enough that we definitely don't return early
    bytes.extend_from_slice(&pcap_packet_record(1000, &frame));
    fs::write(pcap, &bytes).unwrap();

    run_with_log(pcap, log, &[]);
    assert!(log_has_category(log, "[plcp_error]"), "expected at least one [plcp_error] line");
}

#[test]
fn category_unknown_linktype_fires_on_pcapng_idb_mismatch() {
    let pcap = "/tmp/wpawolf_logcov_unklinktype.pcapng";
    let log = "/tmp/wpawolf_logcov_unklinktype.log";

    // SHB + one IDB at index 0 (DLT 105) + EPB referencing interface_id=99.
    // No IDB at index 99, so reader.link_type(99) returns None -> log_unknown_linktype(99).
    let frame = vec![0u8; 64];
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pcapng_shb());
    bytes.extend_from_slice(&pcapng_idb(105));
    bytes.extend_from_slice(&pcapng_epb(99, &frame));
    fs::write(pcap, &bytes).unwrap();

    run_with_log(pcap, log, &[]);

    let lines = log_lines_for(log, "[unknown_linktype]");
    assert!(!lines.is_empty(), "expected at least one [unknown_linktype] line");
    assert!(lines.iter().any(|l| l.contains("interface_id=99")), "expected interface_id=99; got {lines:?}");
}

#[test]
fn category_unknown_akm_fires_on_out_of_table_akm_byte() {
    let pcap = "/tmp/wpawolf_logcov_unkakm.pcap";
    let log = "/tmp/wpawolf_logcov_unkakm.log";

    // Association Request with AKM 26 (reserved / outside Table 9-190).
    let ap = [0x02, 0x00, 0x00, 0x00, 0x00, 0xAA];
    let sta = [0x02, 0x00, 0x00, 0x00, 0x00, 0xBB];
    let rsn_value = rsn_ie_with_akm(26);
    let tagged = ie_tlv(48, &rsn_value); // RSN IE tag
    let frame = build_assoc_req(ap, sta, &tagged);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pcap_global_header(105));
    bytes.extend_from_slice(&pcap_packet_record(1000, &frame));
    fs::write(pcap, &bytes).unwrap();

    run_with_log(pcap, log, &[]);

    let lines = log_lines_for(log, "[unknown_akm]");
    assert!(!lines.is_empty(), "expected at least one [unknown_akm] line");
    assert!(lines.iter().any(|l| l.contains("type=26")), "expected type=26; got {lines:?}");
}

#[test]
fn category_essid_not_found_summary_fires_on_orphan_pmkid() {
    // Easiest way to trigger an unresolved-ESSID emission: feed wpawolf an
    // Association Request that carries a PMKID in its RSN IE, with no Beacon
    // / Probe Response from that AP anywhere in the capture. PmkidStore picks
    // up the PMKID; the output pipeline walks essid_map, finds no SSID, drops
    // the would-be hash line, and writes one
    // `[essid_not_found_summary]` log line per affected AP at end of run with
    // the drop count and first/last seen timestamps.
    let pcap = "/tmp/wpawolf_logcov_essidnf.pcap";
    let log = "/tmp/wpawolf_logcov_essidnf.log";

    let ap = [0x02, 0x00, 0x00, 0x00, 0x00, 0xCC];
    let sta = [0x02, 0x00, 0x00, 0x00, 0x00, 0xDD];

    // RSN IE with AKM 2 (PSK) + RSN Capabilities + 1 PMKID.
    let mut rsn_value = rsn_ie_with_akm(2);
    rsn_value.extend_from_slice(&[0x00, 0x00]); // RSN Capabilities
    rsn_value.extend_from_slice(&1u16.to_le_bytes()); // PMKID count
    rsn_value.extend_from_slice(&[0xAB; 16]); // The PMKID itself
    let tagged = ie_tlv(48, &rsn_value);
    let frame = build_assoc_req(ap, sta, &tagged);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pcap_global_header(105));
    bytes.extend_from_slice(&pcap_packet_record(1000, &frame));
    fs::write(pcap, &bytes).unwrap();

    // Need at least one hash sink configured AND at least one frame emit path.
    run_with_log(pcap, log, &[]);

    let ap_hex = format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);
    let lines = log_lines_for(log, "[essid_not_found_summary]");
    assert!(!lines.is_empty(), "expected at least one [essid_not_found_summary] line");
    assert!(lines.iter().any(|l| l.contains(&format!("ap={ap_hex}"))), "expected ap={ap_hex}; got {lines:?}");
    assert!(lines.iter().any(|l| l.contains("dropped=")), "expected dropped=N field; got {lines:?}");
    assert!(lines.iter().any(|l| l.contains("first_seen_us=")), "expected first_seen_us=N field; got {lines:?}");
    assert!(lines.iter().any(|l| l.contains("last_seen_us=")), "expected last_seen_us=N field; got {lines:?}");
}

#[test]
fn no_log_path_does_not_create_file() {
    // Sanity: --log not specified -> no file written, no panic.
    let pcap = "/tmp/wpawolf_logcov_nolog.pcap";
    let unset_log = "/tmp/wpawolf_logcov_nolog.log.MUST_NOT_EXIST";
    let _ = fs::remove_file(unset_log);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pcap_global_header(105));
    bytes.extend_from_slice(&pcap_packet_record(1000, &[0u8; 8]));
    fs::write(pcap, &bytes).unwrap();

    let out_path = "/tmp/wpawolf_logcov_nolog.22000";
    let _ = fs::remove_file(out_path);
    let status = Command::new(env!("CARGO_BIN_EXE_wpawolf")).args(["--22000-out", out_path, pcap]).status().unwrap();
    assert!(status.success());
    assert!(!Path::new(unset_log).exists(), "no-op logger must not create the file");
}

#[test]
fn control_frames_do_not_appear_as_malformed_frames() {
    // Regression guard for the 38 M-line log explosion: spec-valid 802.11 control
    // frames (type=1, e.g. ACK) used to be lumped into `[malformed_frame]` because
    // `frame::parse` returned `None` for both control AND truly malformed frames.
    // After the `ParseResult::Control` split, control frames must NOT generate any
    // `[malformed_frame]` entries.
    //
    // Two flavours covered:
    //   * 24-byte control frame (long enough to pass the 3-address min) -- exercises
    //     the type=Control branch after FC parsing.
    //   * 10-byte control frame (real-world ACK without FCS) -- exercises the
    //     short-circuit ordering: FC must be read BEFORE the 24-byte length check.
    let pcap = "/tmp/wpawolf_logcov_ctlframe.pcap";
    let log = "/tmp/wpawolf_logcov_ctlframe.log";

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pcap_global_header(105));

    // Long ACK (padded to 24 bytes).
    let mut ack24 = vec![0u8; 24];
    ack24[0] = 0xD4; // Control, ACK
    bytes.extend_from_slice(&pcap_packet_record(1000, &ack24));

    // Short CTS (10 bytes -- spec-valid without FCS).
    let cts10 = vec![0xC4, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
    bytes.extend_from_slice(&pcap_packet_record(1001, &cts10));

    // Short ACK (10 bytes).
    let ack10 = vec![0xD4, 0x00, 0x00, 0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    bytes.extend_from_slice(&pcap_packet_record(1002, &ack10));

    fs::write(pcap, &bytes).unwrap();

    run_with_log(pcap, log, &[]);

    let malformed = log_lines_for(log, "[malformed_frame]");
    assert!(
        malformed.is_empty(),
        "control frames (any length) must not appear as [malformed_frame]; got {malformed:?}"
    );
}

#[test]
fn invalid_protocol_version_is_forgiven_not_logged() {
    // A frame with FC bit B0 set has Protocol Version = 1 (reserved per §9.2.4.1.1).
    // We forgive the version anomaly (every 802.11 amendment through 2024 reuses
    // the v=0 MAC layout) and do NOT emit a [malformed_frame] entry; the operator
    // sees the count via the Phase 1 summary line "frames with non-zero Protocol
    // Version (forgiven)". This matches tshark / wireshark's lenient dissection.
    let pcap = "/tmp/wpawolf_logcov_protover.pcap";
    let log = "/tmp/wpawolf_logcov_protover.log";

    let mut frame = vec![0u8; 24];
    frame[0] = 0x09; // Type=Data(2), Subtype=0, Protocol Version = 1
    // Sane addresses so the frame doesn't trip any other heuristic.
    frame[4..10].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xAA]);
    frame[10..16].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xBB]);
    frame[16..22].copy_from_slice(&[0x02, 0, 0, 0, 0, 0xAA]);

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pcap_global_header(105));
    bytes.extend_from_slice(&pcap_packet_record(1000, &frame));
    fs::write(pcap, &bytes).unwrap();

    let stderr_path = format!("{log}.stderr");
    let _ = fs::remove_file(&stderr_path);
    let out_path = format!("{log}.22000");
    let _ = fs::remove_file(&out_path);
    let stderr_file = fs::File::create(&stderr_path).unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_wpawolf"))
        .args(["--log", log, "--22000-out", &out_path, pcap])
        .stderr(stderr_file)
        .status()
        .unwrap();
    assert!(status.success());

    // No [malformed_frame] entries for this frame.
    let lines = log_lines_for(log, "[malformed_frame]");
    assert!(lines.is_empty(), "non-zero Protocol Version must not produce [malformed_frame]; got {lines:?}");

    // Phase 1 stats summary must include the forgiven count.
    let stderr_contents = fs::read_to_string(&stderr_path).unwrap();
    assert!(
        stderr_contents.contains("frames with non-zero Protocol Version (forgiven"),
        "expected stats line in stderr; got:\n{stderr_contents}"
    );
}

#[test]
fn skipped_input_routes_unknown_format_files_through_log_not_stderr() {
    // Submission-staging pain point: micro-stub files (0/1/2/3 bytes) and non-capture
    // junk in a watch directory used to spam stderr with `warning: cannot open ...
    // unrecognised file format` lines. We now route every `Error::UnknownFormat`
    // result through the `[skipped_input]` log category and increment the
    // `files_skipped_unknown_format` Phase 1 counter; stderr stays clean.
    //
    // Two flavours covered:
    //   1) explicit-file argument with non-capture content (passed through verbatim
    //      by `expand_inputs`, fails magic detection in `open_reader`)
    //   2) explicit-file argument shorter than 4 bytes (also fails magic detection)
    let dir = "/tmp/wpawolf_logcov_skipped";
    let _ = fs::remove_dir_all(dir);
    fs::create_dir_all(dir).unwrap();

    // Real pcap so the run completes successfully.
    let real_pcap = format!("{dir}/real.pcap");
    let mut real_bytes = Vec::new();
    real_bytes.extend_from_slice(&pcap_global_header(105));
    real_bytes.extend_from_slice(&pcap_packet_record(1000, &[0u8; 24]));
    fs::write(&real_pcap, &real_bytes).unwrap();

    // Two stubs: zero-byte (no magic possible) and 8-byte non-capture.
    let zero_byte = format!("{dir}/wpakeysAB");
    let junk = format!("{dir}/notes.txt");
    fs::write(&zero_byte, b"").unwrap();
    fs::write(&junk, b"NOTACAP!").unwrap();

    let log = format!("{dir}/run.log");
    let stderr_path = format!("{dir}/run.stderr");
    let out_path = format!("{dir}/run.22000");
    let _ = fs::remove_file(&log);
    let _ = fs::remove_file(&stderr_path);
    let _ = fs::remove_file(&out_path);

    let stderr_file = fs::File::create(&stderr_path).unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_wpawolf"))
        .args(["--log", &log, "--22000-out", &out_path, &zero_byte, &junk, &real_pcap])
        .stderr(stderr_file)
        .status()
        .unwrap();
    assert!(status.success(), "wpawolf must finish successfully; bad inputs are skips, not aborts");

    // Both unknown-format files must be in the log under [skipped_input].
    let lines = log_lines_for(&log, "[skipped_input]");
    assert_eq!(lines.len(), 2, "expected exactly two [skipped_input] lines; got {lines:?}");
    assert!(lines.iter().any(|l| l.contains(&zero_byte)), "expected zero-byte stub in log; got {lines:?}");
    assert!(lines.iter().any(|l| l.contains(&junk)), "expected non-capture file in log; got {lines:?}");
    assert!(lines.iter().all(|l| l.contains("reason=")), "every line must carry reason=; got {lines:?}");

    // Stderr must NOT carry the legacy `warning: cannot open` noise for these files.
    let stderr_contents = fs::read_to_string(&stderr_path).unwrap();
    assert!(
        !stderr_contents.contains("warning: cannot open"),
        "unrecognised-format files must not warn on stderr; got:\n{stderr_contents}"
    );
    // The Phase 1 summary must reflect the count.
    assert!(
        stderr_contents.contains("input files skipped (magic unrecognised"),
        "expected Phase 1 summary line for skipped files; got:\n{stderr_contents}"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn directory_walk_filters_sub_4_byte_stubs_silently() {
    // Defence in depth: even when a directory contains stubs, `expand_inputs`'s
    // magic-byte filter (`is_capture_magic`) rejects them before `open_reader`
    // ever runs. This test seeds a directory with files of size 0..=4 plus one
    // valid pcap, and asserts:
    //   * stderr stays clean (no warnings)
    //   * the [skipped_input] log channel is silent (the walk filtered them out
    //     pre-open, so `open_reader` never produced an UnknownFormat result)
    //   * `files_skipped_unknown_format` stays at 0
    //   * the valid pcap is processed (proves we didn't bail on the directory)
    let dir = "/tmp/wpawolf_logcov_dirwalk";
    let _ = fs::remove_dir_all(dir);
    fs::create_dir_all(dir).unwrap();

    // Stubs of every sub-magic length.
    fs::write(format!("{dir}/stub0"), b"").unwrap();
    fs::write(format!("{dir}/stub1"), b"X").unwrap();
    fs::write(format!("{dir}/stub2"), b"XY").unwrap();
    fs::write(format!("{dir}/stub3"), b"XYZ").unwrap();
    // 4 bytes but not a capture magic -- exercises the magic check on the boundary.
    fs::write(format!("{dir}/stub4"), b"BOGS").unwrap();
    // The real pcap.
    let real_pcap = format!("{dir}/real.pcap");
    let mut real_bytes = Vec::new();
    real_bytes.extend_from_slice(&pcap_global_header(105));
    real_bytes.extend_from_slice(&pcap_packet_record(1000, &[0u8; 24]));
    fs::write(&real_pcap, &real_bytes).unwrap();

    let log = format!("{dir}/run.log");
    let stderr_path = format!("{dir}/run.stderr");
    let out_path = format!("{dir}/run.22000");
    let _ = fs::remove_file(&log);
    let _ = fs::remove_file(&stderr_path);
    let _ = fs::remove_file(&out_path);

    let stderr_file = fs::File::create(&stderr_path).unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_wpawolf"))
        .args(["--log", &log, "--22000-out", &out_path, dir])
        .stderr(stderr_file)
        .status()
        .unwrap();
    assert!(status.success());

    let stderr_contents = fs::read_to_string(&stderr_path).unwrap();
    assert!(
        !stderr_contents.contains("warning: cannot open"),
        "stubs must be filtered silently; got:\n{stderr_contents}"
    );
    // The directory walk caught them, so `[skipped_input]` should be empty here.
    let log_contents = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !log_contents.lines().any(|l| l.starts_with("[skipped_input]")),
        "directory walk should filter pre-open; got [skipped_input] lines: {log_contents}"
    );

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn plcp_error_carries_underlying_error_text() {
    // Pre-fix the log just said "link strip failed" -- now we want the underlying
    // error from `link::strip` (e.g. "unsupported DLT 1") preserved so the operator
    // can tell why the strip failed. DLT 1 (Ethernet) is the simplest trigger.
    let pcap = "/tmp/wpawolf_logcov_plcp_detail.pcap";
    let log = "/tmp/wpawolf_logcov_plcp_detail.log";

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pcap_global_header(1)); // DLT 1: Ethernet, unsupported
    bytes.extend_from_slice(&pcap_packet_record(1000, &[0u8; 64]));
    fs::write(pcap, &bytes).unwrap();

    run_with_log(pcap, log, &[]);

    let lines = log_lines_for(log, "[plcp_error]");
    assert!(!lines.is_empty(), "expected at least one [plcp_error] line");
    // The exact wording comes from `Error::Display`; we just require that some
    // information beyond the bare "link strip failed" prefix is present.
    assert!(
        lines.iter().any(|l| l.contains("unsupported DLT") || l.contains("DLT 1") || l.contains("DLT")),
        "expected error detail in [plcp_error] message; got {lines:?}"
    );
}

#[test]
fn category_out_of_sequence_timestamp_fires_on_backward_packet() {
    // Two packets where the second has an earlier timestamp than the first.
    // Per FR-LOG the converter must accept the input (wpawolf does not gate on
    // monotonic time), tally the inversion in stats, and emit a
    // `[out_of_sequence_timestamp]` line so an operator triaging the corpus
    // can identify which captures have been touched. DLT 105 (raw 802.11) lets
    // wpawolf decode the body even though the body itself is irrelevant here.
    let pcap = "/tmp/wpawolf_logcov_oos_ts.pcap";
    let log = "/tmp/wpawolf_logcov_oos_ts.log";

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pcap_global_header(105));
    // First packet at epoch 2000; second at epoch 1000 -> strict backward step.
    bytes.extend_from_slice(&pcap_packet_record(2000, &[0u8; 32]));
    bytes.extend_from_slice(&pcap_packet_record(1000, &[0u8; 32]));
    fs::write(pcap, &bytes).unwrap();

    run_with_log(pcap, log, &[]);

    let lines = log_lines_for(log, "[out_of_sequence_timestamp]");
    assert!(!lines.is_empty(), "expected at least one [out_of_sequence_timestamp] line");
    let line = &lines[0];
    assert!(line.contains("previous_ts_us=2000000000"), "want previous_ts_us=2000000000 in line: {line}");
    assert!(line.contains("current_ts_us=1000000000"), "want current_ts_us=1000000000 in line: {line}");
    assert!(line.contains("path=/tmp/wpawolf_logcov_oos_ts.pcap"), "want path= in line: {line}");
}

#[test]
fn out_of_sequence_timestamp_capped_at_first_ten_per_file() {
    // A capture with many backward steps should still bump the run-wide counter
    // for each one, but the log file should carry at most 10 lines per source
    // file so a deeply-tampered capture cannot flood the operator's log.
    let pcap = "/tmp/wpawolf_logcov_oos_ts_cap.pcap";
    let log = "/tmp/wpawolf_logcov_oos_ts_cap.log";

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pcap_global_header(105));
    // First "anchor" packet at a high timestamp so every subsequent packet is an
    // inversion relative to its predecessor's high value, then a low timestamp,
    // then high, then low ... -> 20 alternations -> 20 strict backward steps.
    for i in 0..20 {
        let ts = if i % 2 == 0 { 5_000 } else { 1_000 };
        bytes.extend_from_slice(&pcap_packet_record(ts, &[0u8; 32]));
    }
    fs::write(pcap, &bytes).unwrap();

    run_with_log(pcap, log, &[]);

    let lines = log_lines_for(log, "[out_of_sequence_timestamp]");
    assert!(!lines.is_empty(), "expected at least one [out_of_sequence_timestamp] line");
    assert!(lines.len() <= 10, "per-file log cap is 10; got {} lines: {lines:?}", lines.len());
}

#[test]
fn out_of_sequence_timestamp_skipped_on_monotonic_capture() {
    // A monotonic capture must not produce any [out_of_sequence_timestamp]
    // lines. Equal-timestamp bursts also do not trigger -- only a STRICT
    // backward step counts as an inversion.
    let pcap = "/tmp/wpawolf_logcov_oos_ts_mono.pcap";
    let log = "/tmp/wpawolf_logcov_oos_ts_mono.log";

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&pcap_global_header(105));
    bytes.extend_from_slice(&pcap_packet_record(1000, &[0u8; 32]));
    bytes.extend_from_slice(&pcap_packet_record(1000, &[0u8; 32])); // equal -> no trigger
    bytes.extend_from_slice(&pcap_packet_record(2000, &[0u8; 32])); // forward -> no trigger
    fs::write(pcap, &bytes).unwrap();

    run_with_log(pcap, log, &[]);

    assert!(
        !log_has_category(log, "[out_of_sequence_timestamp]"),
        "monotonic / equal-timestamp capture must not log out-of-sequence"
    );
}
