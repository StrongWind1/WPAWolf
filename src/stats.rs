//! Phase 5 -- operator-facing statistics summary. See ARCHITECTURE.md §3.5 + §9.
//!
//! Tracks packet counts by frame type, EAPOL M1/M2/M3/M4 message counts, PMKID counts
//! by AKM suite, handshake pairs by combo type and equivalence class, relay frame count,
//! dedup stats (generated vs written), AKM distribution, and ESSID count. Prints a
//! formatted summary to stdout unconditionally at the end of every run.

use std::collections::{BTreeMap, HashMap};

use crate::types::{HashType, MacAddr, MsgType};

/// Counters accumulated during a capture processing run.
#[derive(Debug, Default)]
pub struct Stats {
    /// Total packets seen (all types, all interfaces).
    pub total_packets: u64,
    /// IEEE 802.11 management frames processed.
    pub mgmt_frames: u64,
    /// IEEE 802.11 data frames processed.
    pub data_frames: u64,
    /// IEEE 802.11 control frames counted (but not parsed).
    ///
    /// Populated from `frame::ParseResult::Control`; covers all type=1 subtypes
    /// (`ACK`, `RTS`, `CTS`, `BlockACK`, etc.). Spec-valid frames -- not malformed.
    pub ctrl_frames: u64,
    /// IEEE 802.11 extension frames (type=3) -- 802.11 amendments such as S1G/DMG.
    ///
    /// Rare in mainstream captures; surfaced separately so the `ctrl_frames`
    /// counter is not contaminated by extension frames hitting an unspecific
    /// fallback arm. Per [IEEE 802.11-2024] §9.2.4.1.3, Table 9-2.
    pub extension_frames: u64,
    /// EAPOL-Key M1 frames stored.
    pub eapol_m1: u64,
    /// EAPOL-Key M2 frames stored.
    pub eapol_m2: u64,
    /// EAPOL-Key M3 frames stored.
    pub eapol_m3: u64,
    /// EAPOL-Key M4 frames stored.
    pub eapol_m4: u64,
    /// PMKID store insertions (pre-dedup). Counts every insertion across all
    /// input files, so the same PMKID appearing in N files is counted N times.
    /// The emitted line count (after global dedup) is the authoritative
    /// unique-PMKID number.
    pub pmkids_found: u64,
    /// Relay (WDS) data frames with EAPOL deferred for Phase 1.5 resolution.
    pub relay_frames: u64,
    /// EAPOL frames classified by Tier 1 (direction from MAC header ToDS/FromDS).
    pub eapol_tier1_direction: u64,
    /// WDS EAPOL frames resolved by Tier 1b (`essid_map` AP lookup).
    pub eapol_tier1b_essid: u64,
    /// WDS EAPOL frames resolved by Tier 2 (ACK-based AP discovery).
    pub eapol_tier2_ack_discovery: u64,
    /// WDS EAPOL frames classified by Tier 3 (flag-based fallback).
    pub eapol_tier3_flag_fallback: u64,
    /// EAPOL frames where MAC header direction disagrees with Key ACK flag.
    pub eapol_ack_mismatches: u64,
    /// MSDU bodies whose LLC/SNAP gate accepted the `EtherType` but the EAPOL-Key
    /// parse rejected the body (missing fixed fields, bad descriptor type, sentinel-
    /// rejected nonce/MIC). Counted at parser entry so silent drops at the LLC/EAPOL
    /// boundary are surfaced. See `ARCHITECTURE.md §9.3` and `extract::data`.
    pub eapol_llc_invalid: u64,
    /// MSDUs whose LLC/SNAP `EtherType` was `0x88C7` (IEEE 802.11 preauthentication
    /// carrier per [IEEE 802.11-2024] §12.3.2). Counted alongside standard `0x888E`
    /// so an operator can distinguish on-channel preauth from regular handshakes.
    pub eapol_preauth_frames: u64,
    /// 802.11 mesh data frames whose Mesh Control header was successfully skipped to
    /// reach the inner LLC/SNAP. Each increment corresponds to one MSDU recovered
    /// for downstream EAPOL/EAP processing. [IEEE 802.11-2024] §9.2.4.8.3
    pub mesh_control_frames: u64,
    /// Mesh Data frames dropped because the Mesh Control header could not be
    /// skipped: the Address Extension Mode field was the reserved value `11`, or
    /// the body was shorter than the header it claimed. [IEEE 802.11-2024]
    /// §9.2.4.8.3. The inner MSDU (and any EAPOL it carried) is lost.
    pub mesh_control_malformed: u64,
    /// EAP-Success frames (Code 3) seen in EAPOL EAP-Packet payloads. RFC 3748 §4.2.
    /// Stats-only; carries no identity data so it never affects hash extraction. A
    /// non-zero count alongside zero EAP-Failure indicates a successful enterprise
    /// authentication corpus -- useful when triaging captures that mix WPA/WPA2-PSK
    /// with WPA-Enterprise traffic.
    pub eap_success_frames: u64,
    /// EAP-Failure frames (Code 4) seen in EAPOL EAP-Packet payloads. RFC 3748 §4.2.
    /// Counterpart to `eap_success_frames`; a high failure count next to identity
    /// extractions hints at brute-force or misconfigured supplicant traffic.
    pub eap_failure_frames: u64,
    /// Frames skipped due to unsupported or malformed link-layer headers.
    pub link_errors: u64,
    /// 802.11 MAC headers that failed to parse (frame too short, address fields
    /// truncated, or QoS/4-address body not present). Per `frame::ParseResult::Malformed`.
    pub malformed_mac_hdr: u64,
    /// 802.11 frames with FC Protocol Version != 0 (reserved per §9.2.4.1.1) that
    /// were parsed leniently. Every published 802.11 amendment through 2024 reuses
    /// the v=0 MAC layout, so the version anomaly is forgiven and the frame is
    /// processed normally. Surfaced for operator visibility of capture quality;
    /// matches tshark / wireshark behaviour.
    pub lenient_proto_version: u64,
    /// Counters for the MSDU fragmentation reassembler (`store::fragments`).
    ///
    /// Surfaced as a single Phase 2 stats group when any field is non-zero.
    /// EAPOL fragmentation is rare in modern WPA2/WPA3 captures but occurs for
    /// FT-PSK M2 with extended IEs that exceed the radio MTU. See
    /// `store::fragments::FragmentStats` for field meaning.
    pub fragment_stats: crate::store::fragments::FragmentStats,
    /// Capture files whose trailing packet record was truncated or had a corrupt header.
    ///
    /// Per the FR-IN-10 architecture rule (`ARCHITECTURE.md` §3.1), an EOF mid-record
    /// logs the offset and stops the file -- previously-read packets from the same file
    /// are kept and processed. Counted once per affected file. Per-file detail goes to
    /// the `--log` sink under the `[capture_read_error]` category.
    pub truncated_capture_files: u64,
    /// Trailing packets in `truncated_capture_files` that could not be read.
    ///
    /// Pcap and pcapng records have no resync marker, so once a record header is
    /// short or carries a bogus `incl_len`, the rest of the file is unreachable.
    /// In practice this counter equals `truncated_capture_files` (one trailing
    /// unread packet per affected file); the separate counter is kept so future
    /// resync support can show a higher value without changing the file count.
    pub unreadable_packets: u64,
    /// Input files the ingest loop opened but skipped because their magic bytes
    /// did not match any supported capture format.
    ///
    /// Typical causes: sub-4-byte stub files in a watch directory (typical
    /// shape: submission-staging trees that leave zero-byte placeholders)
    /// and explicitly-named non-capture files. The directory-walk filter
    /// (`is_capture_magic`) catches these
    /// before they reach `open_reader`, so a non-zero count here usually means
    /// either an explicit-file argument with the wrong content or a TOCTOU
    /// race (file shrunk between the walk and the open). Per-file detail goes
    /// to the `--log` sink under the `[skipped_input]` category.
    pub files_skipped_unknown_format: u64,
    /// Number of packets whose pcap timestamp went backward relative to the
    /// previous packet in the same input file. A monotonic sequence is what
    /// any well-behaved capture tool produces; inversions almost always
    /// indicate the file has been post-processed (aircrack-ng deadly-clean,
    /// mergecap with `--strict-time-stamps=false`, hand-edited). wpawolf
    /// itself does not care -- the pairing engine works on `(AP, STA)`
    /// groups, not on file order -- but an operator triaging a corpus may
    /// want to identify which captures have been touched. Matches the
    /// `Warning: out of sequence timestamps!` diagnostic that hcxpcapngtool
    /// 7.1.2 prints on the same input. Counter is per-run (sum across all
    /// input files); per-file detail goes to the `--log` sink under the
    /// `[out_of_sequence_timestamp]` category, capped at the first 10
    /// inversions per file so a deeply-shuffled capture does not flood the
    /// log.
    pub out_of_sequence_timestamps: u64,
    /// Packets whose capture timestamp was zero (capture-tool artifact; the
    /// frame is still processed). Counterpart of `out_of_sequence_timestamps`.
    pub packets_zeroed_timestamp: u64,
    /// Packets dropped because their pcapng `interface_id` had no IDB-registered
    /// DLT (a missing-interface reference); also logged via `[unknown_linktype]`.
    /// [draft-ietf-opsawg-pcapng-05 §4.2]
    pub packets_unknown_linktype: u64,
    /// Frames dropped after a successful MAC-header parse because the header's
    /// `body_offset` ran past the captured frame length (snaplen-truncated or
    /// corrupt length). The header parsed but the body slice was unavailable.
    pub truncated_after_header: u64,
    /// Total bytes of capture files opened by the ingest loop (file sizes, not
    /// decompressed payload). Feeds the Phase 5 throughput row.
    pub bytes_ingested: u64,
    /// Logical PMKID hashes written (post-dedup), from `OutputStats::pmkids_written`.
    pub pmkids_written: u64,
    /// Hash lines dropped by the dedup filter (pairs + PMKIDs).
    pub dedup_dropped: u64,
    /// EAPOL-pair share of `dedup_dropped`.
    pub dedup_dropped_pairs: u64,
    /// PMKID share of `dedup_dropped`.
    pub dedup_dropped_pmkids: u64,
    /// Hashes dropped at emit because the AKM could not be mapped to one of the
    /// 11 types (`HashType::from_akm_and_attack` returned None even after AKM-map
    /// inference for PMKIDs) and the AKM was not a recognised non-PSK suite. A
    /// genuinely unclassifiable / `Unknown` residue we extracted but cannot format.
    pub emit_dropped_unclassified_akm: u64,
    /// Handshakes / PMKIDs dropped at emit because the AKM is a recognised non-PSK
    /// suite (`AkmType::NotPsk`: enterprise 802.1X / FT-802.1X / SAE / OWE / FILS /
    /// PASN). Out of v1 scope -- the PMK is not `PBKDF2(PSK)`, so no crackable mode
    /// 22000 / 37100 line exists. [ARCHITECTURE.md §2.3, §8.6 FR-OUT-*]
    pub emit_dropped_notpsk_akm: u64,
    /// FT hashes (types 6/7/10/11) dropped at emit because the FT context was
    /// incomplete (no R0KH-ID), so the `WPA*03*`/`WPA*04*` FT line could not be
    /// built. [ARCHITECTURE.md §7 FT line format]
    pub emit_dropped_ft_no_context: u64,
    /// Unique AP ESSIDs seen.
    pub essid_count: u64,
    /// Largest number of SSID changes recorded for any single AP (distinct
    /// SSID variants minus the initial one). Capture-quality signal: a high
    /// value on one AP usually means RF-rotted duplicate beacons.
    pub essid_changes_max: u64,

    // --- Per-subtype management frame counters ---
    // [IEEE 802.11-2024] §9.2.4.1.3, Table 9-1
    /// Beacon frames (subtype 8).
    pub beacon_frames: u64,
    /// Probe Response frames (subtype 5).
    pub probe_resp_frames: u64,
    /// Probe Responses whose SSID IE was zero-length (unset). A Probe Response
    /// answering a directed probe should carry the SSID; an empty one is a
    /// capture-quality signal. Mirrors hcxpcapngtool's `PROBERESPONSE (SSID unset)`.
    pub probe_resp_ssid_unset: u64,
    /// Probe Responses whose SSID IE bytes were all `0x00` (zeroed).
    pub probe_resp_ssid_zeroed: u64,
    /// Probe Request frames -- directed (unicast DA, subtype 4).
    pub probe_req_directed: u64,
    /// Probe Request frames -- undirected (broadcast DA, subtype 4).
    pub probe_req_undirected: u64,
    /// Association Request frames (subtype 0).
    pub assoc_req_frames: u64,
    /// Association Response frames (subtype 1).
    pub assoc_resp_frames: u64,
    /// Reassociation Request frames (subtype 2).
    pub reassoc_req_frames: u64,
    /// Reassociation Response frames (subtype 3).
    pub reassoc_resp_frames: u64,
    /// Authentication frames (subtype 11).
    pub auth_frames: u64,
    /// Deauthentication frames (subtype 12).
    pub deauth_frames: u64,
    /// Deauthentication frames carrying Reason Code 14 ("Message integrity
    /// code (MIC) failure"). [IEEE 802.11-2024] §9.4.1.7 Table 9-90. The
    /// canonical "this handshake will never pair cleanly" signal.
    pub mic_failure_deauths: u64,
    /// Disassociation frames (subtype 10).
    pub disassoc_frames: u64,
    /// Action frames (subtype 13).
    pub action_frames: u64,
    /// Action No Ack frames (subtype 14).
    pub action_no_ack_frames: u64,
    /// Management frames whose subtype is reserved (7, 15) per Table 9-1 -- counted
    /// in `mgmt_frames` but not in any named subtype counter. Diagnostic; lets the
    /// management subtype children reconcile against the management total.
    pub mgmt_reserved_subtype: u64,
    /// ATIM frames (subtype 9).
    pub atim_frames: u64,
    /// Measurement Pilot frames (subtype 6).
    pub measurement_pilot_frames: u64,
    /// Timing Advertisement frames (subtype 15).
    pub timing_advert_frames: u64,

    // --- Per-AKM assoc/reassoc counters ---
    // Populated by parsing the RSN IE in each Assoc/Reassoc Request frame.
    // A single frame may set multiple flags (e.g., both PSK and FT-PSK).
    // [IEEE 802.11-2024] §9.4.2.24.3, Table 9-190
    /// Association Requests with AKM 2 (WPA2-PSK; hashcat mode 22000).
    pub assoc_req_wpa2_psk: u64,
    /// Association Requests with AKM 4 only (FT-PSK, SHA-256 chain; hashcat mode 37100).
    pub assoc_req_ft_psk: u64,
    /// Association Requests with AKM 19 only (FT-PSK-SHA384; no hashcat module).
    pub assoc_req_ft_psk_sha384: u64,
    /// Association Requests with AKM 6 only (PSK-SHA256; hashcat mode 22000).
    pub assoc_req_psk_sha256: u64,
    /// Association Requests with AKM 20 only (PSK-SHA384; no hashcat module).
    pub assoc_req_psk_sha384: u64,
    /// Association Requests with AKM 8, 24, or 25 (WPA3-SAE / SAE-EXT-KEY).
    pub assoc_req_sae: u64,
    /// Association Requests with AKM 18 (OWE).
    pub assoc_req_owe: u64,
    /// Association Requests with AKM 14-17 (FILS variants). [§12.11]
    pub assoc_req_fils: u64,
    /// Association Requests with AKM 21 (PASN). [§12.13]
    pub assoc_req_pasn: u64,
    /// Association Requests with AKM 1 or 3 (802.1X / FT-802.1X, SHA-1 family).
    pub assoc_req_enterprise_sha1: u64,
    /// Association Requests with AKM 5 or 11 (802.1X-SHA256 / 802.1X Suite B SHA-256).
    pub assoc_req_enterprise_sha256: u64,
    /// Association Requests with AKM 12, 13, 22, or 23 (802.1X SHA-384 family).
    pub assoc_req_enterprise_sha384: u64,
    /// Association Requests with AKM 7 (TDLS).
    pub assoc_req_tdls: u64,
    /// Association Requests with AKM 10 (`APPeerKey`, deprecated).
    pub assoc_req_appeerkey: u64,
    /// Association Requests with an `00:0F:AC` AKM suite type outside Table 9-190.
    /// Catches reserved / future / vendor-divergent suite numbers so they never drop silently.
    pub assoc_req_akm_unknown: u64,
    /// Association Requests carrying the legacy WPA1 vendor IE (OUI `00:50:F2`, type 1).
    /// WPA1-PSK-EAPOL is type 1 in the 11-type classification (ARCHITECTURE.md §2).
    pub assoc_req_wpa1: u64,
    /// Reassociation Requests with AKM 2 (WPA2-PSK; hashcat mode 22000).
    pub reassoc_req_wpa2_psk: u64,
    /// Reassociation Requests with AKM 4 only (FT-PSK, SHA-256 chain; hashcat mode 37100).
    pub reassoc_req_ft_psk: u64,
    /// Reassociation Requests with AKM 19 only (FT-PSK-SHA384; no hashcat module).
    pub reassoc_req_ft_psk_sha384: u64,
    /// Reassociation Requests with AKM 6 only (PSK-SHA256; hashcat mode 22000).
    pub reassoc_req_psk_sha256: u64,
    /// Reassociation Requests with AKM 20 only (PSK-SHA384; no hashcat module).
    pub reassoc_req_psk_sha384: u64,
    /// Reassociation Requests with AKM 8, 24, or 25 (WPA3-SAE / SAE-EXT-KEY).
    pub reassoc_req_sae: u64,
    /// Reassociation Requests with AKM 18 (OWE).
    pub reassoc_req_owe: u64,
    /// Reassociation Requests with AKM 14-17 (FILS variants). [§12.11]
    pub reassoc_req_fils: u64,
    /// Reassociation Requests with AKM 21 (PASN). [§12.13]
    pub reassoc_req_pasn: u64,
    /// Reassociation Requests with AKM 1 or 3 (802.1X / FT-802.1X, SHA-1 family).
    pub reassoc_req_enterprise_sha1: u64,
    /// Reassociation Requests with AKM 5 or 11 (802.1X-SHA256 / 802.1X Suite B SHA-256).
    pub reassoc_req_enterprise_sha256: u64,
    /// Reassociation Requests with AKM 12, 13, 22, or 23 (802.1X SHA-384 family).
    pub reassoc_req_enterprise_sha384: u64,
    /// Reassociation Requests with AKM 7 (TDLS).
    pub reassoc_req_tdls: u64,
    /// Reassociation Requests with AKM 10 (`APPeerKey`, deprecated).
    pub reassoc_req_appeerkey: u64,
    /// Reassociation Requests with an `00:0F:AC` AKM suite type outside Table 9-190.
    pub reassoc_req_akm_unknown: u64,
    /// Reassociation Requests carrying the legacy WPA1 vendor IE (OUI `00:50:F2`, type 1).
    /// WPA1-PSK-EAPOL is type 1 in the 11-type classification (ARCHITECTURE.md §2).
    pub reassoc_req_wpa1: u64,

    // --- Per-band packet counts (from radiotap Channel field) ---
    /// Packets with channel frequency in the 2.4 GHz band (2412-2484 MHz).
    pub band_24ghz: u64,
    /// Packets with channel frequency in the 5 GHz band (5180-5825 MHz).
    pub band_5ghz: u64,
    /// Packets with channel frequency in the 6 GHz band (5925-7125 MHz).
    pub band_6ghz: u64,
    /// Packets carrying a radiotap Channel frequency that fell outside the three
    /// known Wi-Fi bands above (sub-GHz 802.11ah, 60 GHz DMG, or a corrupt field).
    /// Informational only -- the frame is processed normally; this just makes the
    /// per-band split account for every channel-bearing packet.
    pub band_other: u64,

    // --- Beacon channel distribution (from DS Parameter Set IE, tag 3) ---
    // Populated only for Beacon frames. Key = channel number (1 byte from the IE).
    // Channels 1-14 = 2.4 GHz; >14 = 5 GHz (standard DS Parameter Set convention).
    // [IEEE 802.11-2024] §9.4.2.4
    /// Per-channel Beacon count. Key = channel number, Value = Beacon count on that channel.
    pub beacon_channels: HashMap<u8, u64>,

    // --- Extraction counters ---
    /// SSIDs extracted from Action Neighbor Report Request frames.
    pub action_nr_req_ssids: u64,
    /// SSIDs extracted from FILS Discovery frames (Public Action, action 34).
    pub fils_discovery_ssids: u64,
    /// SSIDs extracted from SSID List IEs (tag 84).
    pub ssid_list_entries: u64,
    /// Country codes extracted from Country IEs (tag 7).
    pub country_codes_extracted: u64,
    /// Mesh IDs extracted from Mesh ID IEs (tag 114).
    pub mesh_ids_extracted: u64,
    /// WPS IEs extracted from Probe Request frames.
    pub wps_probe_req_extracted: u64,
    /// Vendor-specific AP names extracted (IE 221, various OUIs).
    pub vendor_ap_names_extracted: u64,
    /// OWE Transition Mode SSIDs extracted (WFA IE type 28).
    pub owe_transition_ssids: u64,
    /// Cisco CCX1 AP names extracted (IE tag 133).
    pub ccx1_ap_names_extracted: u64,
    /// Time Zone strings extracted (IE tag 98).
    pub time_zones_extracted: u64,
    /// Nontransmitted BSSID profiles recovered from Multiple BSSID elements (tag 71).
    /// Each profile registers a synthesized sub-BSSID + sub-SSID into the ESSID map
    /// per [IEEE 802.11-2024] §9.4.2.45a + §35.2.2.
    pub multiple_bssid_profiles: u64,
    /// Neighboring BSSIDs harvested from Reduced Neighbor Report elements (tag 201).
    pub rnr_bssids_extracted: u64,
    /// Wi-Fi Direct (P2P) device names extracted from WFA P2P vendor IEs
    /// (OUI `50:6F:9A`, type 9). [Wi-Fi Alliance Wi-Fi Direct Specification]
    pub p2p_device_names_extracted: u64,

    /// EAPOL pairs generated (before dedup) -- includes PMKIDs in the denominator.
    pub eapol_pairs_generated: u64,
    /// Last input file path processed (shown in summary as the most recent file).
    pub last_file: String,
    /// Number of input capture files actually opened by the ingest loop.
    ///
    /// Increments once per file that was successfully opened, regardless of how
    /// many packets it contained. Combined with `file_formats_seen`,
    /// `endians_seen`, and `dlt_descs_seen`, lets the Phase 1 banner reflect
    /// every file processed when a directory is walked, not just the last one.
    pub input_file_count: u64,
    /// Histogram of capture file formats observed across the input set.
    /// Key is the human-readable format string (e.g. "pcap 2.4" or "pcapng 1.0");
    /// value is the count of files reporting that format. `BTreeMap` for
    /// deterministic ordering in the summary output.
    pub file_formats_seen: BTreeMap<String, u64>,
    /// Histogram of capture file endianness values observed (e.g. "little endian").
    pub endians_seen: BTreeMap<String, u64>,
    /// Histogram of capture file link-types observed
    /// (e.g. "`DLT_IEEE802_11_RADIO` (127)").
    pub dlt_descs_seen: BTreeMap<String, u64>,

    // --- EAPOL auth-length maximums (body length = eapol_frame.len()) ---
    // hcxpcapngtool prints these as "authlen (authlen + EAPAUTH_SIZE)" where EAPAUTH_SIZE = 4.
    /// Maximum M1 EAPOL body length seen across all frames.
    pub m1_auth_len_max: u16,
    /// Maximum M2 EAPOL body length seen across all frames.
    pub m2_auth_len_max: u16,
    /// Maximum M3 EAPOL body length seen across all frames.
    pub m3_auth_len_max: u16,
    /// Maximum M4 EAPOL body length seen across all frames.
    pub m4_auth_len_max: u16,

    // --- Per-combo written pair counts ---
    /// N1E2 pairs written (`ANonce` from M1, EAPOL from M2 -- challenge).
    pub pairs_written_n1e2: u64,
    /// N3E2 pairs written (`ANonce` from M3, EAPOL from M2 -- authorized).
    pub pairs_written_n3e2: u64,
    /// N1E4 pairs written (`ANonce` from M1, EAPOL from M4 -- authorized).
    pub pairs_written_n1e4: u64,
    /// N2E3 pairs written (`SNonce` from M2, EAPOL from M3 -- AP-less authorized).
    pub pairs_written_n2e3: u64,
    /// N4E3 pairs written (`SNonce` from M4, EAPOL from M3 -- AP-less authorized).
    pub pairs_written_n4e3: u64,
    /// N3E4 pairs written (`ANonce` from M3, EAPOL from M4 -- authorized).
    pub pairs_written_n3e4: u64,

    // --- Pairing output-filter drops (opt-in; zero in WIDE mode) ---
    /// Candidate pairs discarded by the `--eapoltimeout` session-window filter
    /// (the two messages fell more than the window apart). Off by default; only
    /// nonzero when `--eapoltimeout` / `--strict` is set. [ARCHITECTURE.md §8 FR-PAIR-3]
    pub pairs_time_filtered: u64,
    /// Candidate pairs discarded by the `--rc-drift` replay-counter filter (the
    /// per-combo RC relationship exceeded the tolerance). Off by default; only
    /// nonzero when `--rc-drift` / `--strict` is set. [ARCHITECTURE.md §8 FR-PAIR-4]
    pub pairs_rc_filtered: u64,
    /// Messages excluded from pairing by the opt-in `--max-eapol-per-type` cap,
    /// summed across all groups. Off by default (the store always keeps every
    /// message); only nonzero when the operator sets a cap on a rotating-ANonce
    /// corpus. [ARCHITECTURE.md §8 FR-CLI]
    pub eapol_messages_capped: u64,
    /// `--smart`: distinct handshake instances partitioned across multi-instance
    /// `(AP, STA)` groups (informational). Zero in WIDE mode. [smart-pairing-design.md §6.2]
    pub smart_instances_attributed: u64,
    /// `--smart`: candidate pairs pruned as provably uncrackable -- cross-instance
    /// `ANonces` unreachable (by hashcat NC) from a uniquely-RC-linked MIC's instance.
    /// Standalone Phase-4 drop, OUTSIDE Reconciliation Identity 3 (like
    /// `nc_dedup_collapsed_lines`). Zero in WIDE mode. [smart-pairing-design.md §6.2]
    pub smart_uncrackable_dropped: u64,
    /// `--smart`: MIC-frames kept against all candidates because the MIC did not
    /// uniquely RC-link to one instance (rc=1-pinned / cross-seed; never-miss
    /// keep-all). Informational. [smart-pairing-design.md §6.2]
    pub smart_ambiguous_kept: u64,
    /// `--smart`: FT (mode 37100) MIC-frames retaining a non-APLESS survivor after
    /// pruning, satisfying clause F. Informational. [smart-pairing-design.md §6.2]
    pub smart_ft_nonapless_kept: u64,

    // --- RC / NC / endianness stats ---
    /// Maximum actual RC gap magnitude seen across useful pairs written to output.
    pub rc_gap_max: u64,
    /// Whether `--rc-drift` was enabled for this run. Controls `rc_gap_max` display.
    pub rc_drift_enabled: bool,

    /// EAPOL pairs written with `FLAG_NC` set (nonce-error-corrections active).
    pub pairs_nc: u64,
    /// EAPOL pairs written with `FLAG_LE` set (LE endianness correction applied).
    pub pairs_le: u64,
    /// EAPOL pairs written with `FLAG_BE` set (BE endianness correction applied).
    pub pairs_be: u64,
    /// Lines collapsed away by NC-dedup (`--nc-dedup`): sum across all clusters of
    /// `cluster_size - 1`. Zero when `--nc-dedup` is absent. See `ARCHITECTURE.md §5.8.1`.
    pub nc_dedup_collapsed_lines: u64,
    /// Number of NC-dedup clusters with at least two members. Zero when `--nc-dedup`
    /// is absent.
    pub nc_dedup_cluster_count: u64,
    /// Largest NC-dedup cluster observed across all (AP, STA) groups. Zero when
    /// `--nc-dedup` is absent.
    pub nc_dedup_max_cluster_size: u64,
    /// EAPOL pairs that passed the dedup filter and were written (useful pairs).
    pub eapol_pairs_useful: u64,

    // --- hcxpcapngtool parity stats ---

    // File metadata is now aggregated across the whole input set via
    // `file_formats_seen` / `endians_seen` / `dlt_descs_seen` and the
    // `input_file_count` counter. See those fields for details.
    /// Timestamp of the first packet seen (microseconds since Unix epoch).
    pub timestamp_first_us: u64,
    /// Timestamp of the last packet seen (microseconds since Unix epoch).
    pub timestamp_last_us: u64,

    // Authentication frame algorithm breakdown.
    // [IEEE 802.11-2024] §9.4.1.1 Authentication Algorithm Number field.
    /// Authentication frames using Open System algorithm (algorithm = 0).
    pub auth_open_system: u64,
    /// Authentication frames using Shared Key algorithm (algorithm = 1, WEP legacy).
    pub auth_shared_key: u64,
    /// Authentication frames using Fast BSS Transition (algorithm = 2, 802.11r).
    pub auth_fbt: u64,
    /// Authentication frames using SAE (algorithm = 3, WPA3-Personal).
    pub auth_sae: u64,
    /// Authentication frames using FILS (algorithm = 4/5/6).
    pub auth_fils: u64,
    /// Authentication frames using Network EAP / Cisco LEAP (algorithm = 128).
    pub auth_network_eap: u64,
    /// Authentication frames using PASN. Per `[IEEE 802.11-2024]` Table 9-43
    /// algo=7 is Pre-Association Security Negotiation; §12.13.1 also reserves
    /// any unrecognised algorithm value as a potential PASN base-AKMP. Both
    /// dispatch through `process_auth_pasn` and increment this single
    /// counter.
    pub auth_pasn: u64,
    /// Authentication responses with Status Code 52 ("R0KH unreachable").
    /// [IEEE 802.11-2024] §9.4.1.9 Table 9-92. Each one explains a missing
    /// FT-PSK handshake: the AP refused the FT authentication.
    pub ft_status_r0kh_unreachable: u64,
    /// Authentication responses with Status Code 53 ("Invalid PMKID"). Table 9-92.
    pub ft_status_invalid_pmkid: u64,
    /// Authentication responses with Status Code 54 ("Invalid MDE"). Table 9-92.
    pub ft_status_invalid_mde: u64,
    /// Authentication responses with Status Code 55 ("Invalid FTE"). Table 9-92.
    pub ft_status_invalid_fte: u64,

    // EAPOL descriptor type breakdown.
    /// EAPOL-Key frames with RSN descriptor type (0x02). [IEEE 802.11-2024] §12.7.2
    pub eapol_rsn: u64,
    /// EAPOL-Key frames with WPA (legacy) descriptor type (0xFE). [hcxpcapngtool `EAP_KDT_WPA`]
    pub eapol_wpa: u64,
    /// EAPOL-Key frames with Key Descriptor Version 1 (HMAC-MD5 / ARC4; WPA legacy).
    /// [IEEE 802.11-2024] §12.7.2, Key Information bits 0-2.
    pub eapol_kdv1: u64,
    /// EAPOL-Key frames with Key Descriptor Version 2 (HMAC-SHA1 / AES; WPA2-PSK).
    pub eapol_kdv2: u64,
    /// EAPOL-Key frames with Key Descriptor Version 3 (AES-128-CMAC; PSK-SHA256 / FT-PSK).
    pub eapol_kdv3: u64,
    /// EAPOL-Key frames with Key Descriptor Version 0 ("AKM-defined"). Spec-legitimate
    /// for the SHA-384 AKM families (19/20) and other post-KDV suites, NOT an anomaly.
    /// [IEEE 802.11-2024] §12.7.2 Table 12-11.
    pub eapol_kdv0: u64,
    /// EAPOL-Key frames with Key Descriptor Version 4-7 (reserved / non-standard).
    pub eapol_kdv_other: u64,
    /// EAPOL frames rejected because the Key Nonce was all-NULL (`0x00...00`). Applies to
    /// every message type including M4. M4 NULL nonce is spec-valid on the wire per
    /// [IEEE 802.11-2024] §12.7.6.5, but the resulting EAPOL hash line is mathematically
    /// uncrackable -- the live PTK depends on M2's `SNonce`, which the M4 frame does not
    /// carry. Matches hcxpcapngtool's `eapolm4zeroedcount++; return;` drop at
    /// hcxpcapngtool.c:3636.
    pub null_nonce_rejected: u64,
    /// M4-specific subset of `null_nonce_rejected`. Useful to distinguish the
    /// spec-zero case (expected per [IEEE 802.11-2024] §12.7.6.5; hcxpcapngtool
    /// counts these as `eapolm4zeroedcount`) from a NULL nonce on M1 / M2 / M3
    /// (abnormal -- entropy starvation, firmware bug, capture tampering). The
    /// difference `null_nonce_rejected - null_nonce_rejected_on_m4` is the
    /// abnormal subset worth a closer look.
    pub null_nonce_rejected_on_m4: u64,
    /// EAPOL frames rejected because the Key Nonce was all-`0xFF`. Applies to all msg types
    /// including M4 (firmware flash-erase sentinel, never spec-valid).
    pub ff_nonce_rejected: u64,
    /// M4-specific subset of `ff_nonce_rejected`. Tracked symmetrically with
    /// `null_nonce_rejected_on_m4`; an all-`0xFF` nonce is never spec-valid on
    /// any message type, but the split exists so the banner can render every
    /// rejection counter with a consistent on-M4 vs on-other breakdown.
    pub ff_nonce_rejected_on_m4: u64,
    /// EAPOL frames rejected because the Key Nonce was a non-NULL non-FF garbage pattern
    /// (all-same-byte, 2-byte period, or 4-byte period). Catches firmware stub nonces such
    /// as all-`0x55`, `5555AAAA`-style alternations, and `01020304` repeating slabs.
    pub repeat_nonce_rejected: u64,
    /// M4-specific subset of `repeat_nonce_rejected`. Tracked symmetrically
    /// with `null_nonce_rejected_on_m4`.
    pub repeat_nonce_rejected_on_m4: u64,
    /// EAPOL frames rejected because the Key MIC was all-NULL (`0x00...00`) with the Key MIC
    /// flag set (M2/M3/M4). NULL MIC means the frame is unauthenticated. M1 NULL MIC is
    /// spec-valid and is never counted.
    pub null_mic_rejected: u64,
    /// EAPOL frames rejected because the Key MIC was all-`0xFF` with the Key MIC flag set.
    pub ff_mic_rejected: u64,
    /// EAPOL frames rejected because the Key MIC carried a non-NULL non-FF garbage pattern
    /// (all-same-byte, 2-byte period, or 4-byte period). MICs from a healthy stack are
    /// uniformly random; any of these patterns indicates a synthetic / sentinel value.
    pub repeat_mic_rejected: u64,
    /// PMKIDs rejected because the value was all-NULL (`0x00...00`). These are placeholder
    /// entries (AP signalling "no cached PMK") with no cracking value.
    pub null_pmkid_rejected: u64,
    /// PMKIDs rejected because the value was all-`0xFF` (firmware flash-erase sentinel).
    pub ff_pmkid_rejected: u64,
    /// PMKIDs rejected because the value was a non-NULL non-FF garbage pattern (all-same-byte,
    /// 2-byte period, or 4-byte period). PMKIDs from a healthy stack are HMAC-SHA1 / HMAC-SHA256
    /// outputs, which are uniformly random.
    pub repeat_pmkid_rejected: u64,
    /// SSIDs that passed the spec-driven admission gate (length 1-32, first byte
    /// non-zero) but contained at least one byte in `0x00..=0x1F` (the full
    /// ASCII C0 control range, NUL through US -- every control character).
    /// **This is an informational counter, not a rejection.** Per
    /// [IEEE 802.11-2024] §9.4.2.2 the SSID element is "an arbitrary sequence
    /// of 0-32 octets" with no printable-character requirement, so a
    /// control-byte SSID is valid on the wire and wpawolf is required to
    /// handle it. The SSID is shipped to hashcat byte-for-byte unchanged; the
    /// counter and the matching `[essid_control_bytes]` log line exist only
    /// so an operator triaging a capture can locate the source frame (such
    /// bytes are rare in production network names and may correlate with
    /// bit-flipped or test-injected SSIDs worth a closer look). SSIDs are
    /// NOT garbage-filtered the way nonces / MICs / PMKIDs are.
    pub essid_control_bytes_warned: u64,
    /// Maximum time gap between any two EAPOL messages in the same (AP, STA) session (microseconds).
    /// Displayed in milliseconds. [hcxpcapngtool EAPOLTIME gap]
    pub eapol_time_gap_max_us: u64,
    /// (AP, STA) sessions where an M1 `ANonce` differs from an M3 `ANonce` under the same key.
    /// Per IEEE 802.11-2024 §12.7.6.4 the `ANonce` in M3 must equal the `ANonce` in M1; a
    /// mismatch indicates interleaved sessions, buggy AP firmware, or an injected M3.
    /// Diagnostic only -- output correctness is unaffected. [ARCHITECTURE.md §4]
    pub anonce_m1_m3_mismatch_sessions: u64,
    // WPA/WEP encrypted data frame counts.
    /// Data frames with the Protected Frame bit set whose `KeyID` octet carries
    /// ExtIV=1 (TKIP/CCMP/GCMP -- the WPA family), or whose body is too short
    /// to expose the `KeyID` octet. [IEEE 802.11-2024] §9.2.4.1.1 bit B14, §12.5.2.2.
    pub wpa_encrypted_data: u64,
    /// Data frames with the Protected Frame bit set and ExtIV=0 in the `KeyID`
    /// octet (legacy WEP encapsulation). [IEEE 802.11-2024] §12.3.4.2.
    pub wep_encrypted_data: u64,

    /// Management frames with the Protected Frame bit set (PMF / 802.11w).
    /// [IEEE 802.11-2024] §11.13. Covers Disassoc, Deauth, and Robust Action frames
    /// when the BSS has PMF enabled. `Beacon` / `ProbeResp` / `ProbeReq` / `Auth`
    /// and `AssocReq` / `ReassocReq` are spec-excluded from PMF; if the bit is
    /// set on those it is always a hardware glitch. Surfaced so operators
    /// understand why FT-PSK PMKIDs from FT Action frames may be missing on
    /// PMF-enabled networks (the Action body is encrypted and we cannot
    /// decrypt without the PTK).
    pub mgmt_protected_frames: u64,
    /// Subset of `mgmt_protected_frames`: Action subtype (13) frames whose body
    /// parse was skipped because the Protected bit was set. The handler returns
    /// without walking IEs, preventing the encrypted payload from being parsed
    /// as random tag/length pairs and stored as garbage PMKIDs.
    pub mgmt_protected_action_skipped: u64,

    /// Data frames carrying the `QoS` Control A-MSDU Present bit. Each one
    /// contains 2..N aggregated subframes, every subframe potentially holding
    /// its own LLC/SNAP+EAPOL. [IEEE 802.11-2024] §9.2.4.5.9, §9.7.2
    pub amsdu_frames_seen: u64,
    /// Total A-MSDU subframes successfully iterated across all
    /// `amsdu_frames_seen`. A frame with N subframes contributes N here. Lower
    /// bound on the EAPOL search space the legacy single-MSDU code path missed.
    pub amsdu_subframes_total: u64,

    /// Frames whose 4-byte 802.11 FCS was stripped before parsing because the
    /// Radiotap frames where `it_version` was non-zero but parsing succeeded
    /// via the relaxed version gate (Tier 1 recovery).
    pub radiotap_version_nonzero: u64,
    /// Frames recovered via Tier 2 (radiotap offset computed from `it_present`).
    pub recovered_tier2: u64,
    /// Frames recovered via Tier 3 (CRC-32 multi-offset scan).
    pub recovered_tier3: u64,
    /// Frames recovered from a DLT-0 (unspecified link type) packet via the light
    /// radiotap / raw-802.11 attempt in `link::recover`.
    pub recovered_dlt0: u64,

    /// FCS outcome: header said FCS present, CRC-32 confirmed. Stripped.
    pub fcs_header_and_crc_agree: u64,
    /// FCS outcome: header said no FCS, but CRC-32 proved FCS present. Stripped.
    /// Indicates the capture driver included FCS but the link-layer header
    /// didn't announce it (common for Prism, AVS, PPI, SLL which lack a
    /// per-frame FCS flag).
    pub fcs_detected_by_crc: u64,
    /// FCS outcome: header said FCS present, CRC-32 does not confirm, AND the
    /// radiotap BADFCS flag (Flags bit 6, 0x40) is set. The radio received this
    /// frame with a failed checksum on the air. FCS bytes are present but corrupt.
    pub fcs_badfcs_flagged: u64,
    /// FCS outcome: header said FCS present, CRC-32 does not confirm, but NO
    /// BADFCS flag. Unexpected -- corruption during capture or processing, not
    /// on the air.
    pub fcs_crc_mismatch_no_flag: u64,
    /// FCS outcome: neither header nor CRC-32 indicates FCS. Not stripped.
    pub fcs_neither: u64,

    /// Radiotap-encapsulated frames whose header advertises the A-MPDU Status
    /// field (`it_present` bit 20). Surfaced for visibility of raw-aggregation
    /// captures. See `ARCHITECTURE.md §3.3` transport-vector inventory item 6:
    /// modern capture stacks pre-split A-MPDUs into individual MPDUs before
    /// delivery, so a non-zero count here normally means each MPDU carries the
    /// flag rather than that wpawolf is missing inner frames. If a future
    /// reproducer pcap demonstrates raw delimiter streams, the delimiter walker
    /// gates off this counter.
    pub ampdu_status_frames: u64,

    // AWDL (Apple Wireless Direct Link).
    /// Vendor-specific Action frames with the Apple OUI (00:17:F2) -- AWDL.
    pub awdl_frames: u64,

    // Beacon SSID quality counters.
    /// Beacon frames with a zero-length SSID (hidden network / wildcard).
    pub beacon_ssid_wildcard: u64,
    /// Beacon frames where all SSID bytes are 0x00 (zeroed SSID).
    pub beacon_ssid_zeroed: u64,
    /// Beacon frames where the SSID IE length exceeds 32 bytes (malformed).
    pub beacon_ssid_oversized: u64,

    // --- RSN Extension IE (RSNXE, tag 244) capability flags ---
    // Counted once per Beacon/Probe Response observed with each flag set.
    // [IEEE 802.11-2024] §9.4.2.241
    /// Beacons / Probe Responses advertising SAE Hash-to-Element required (WPA3-H2E).
    pub rsnxe_sae_h2e: u64,
    /// Beacons / Probe Responses advertising SAE Public Key (SAE-PK).
    pub rsnxe_sae_pk: u64,
    /// Beacons / Probe Responses advertising Secure LTF (11az Enhanced Ranging).
    pub rsnxe_secure_ltf: u64,
    /// Beacons / Probe Responses advertising Protected TWT Operations.
    pub rsnxe_protected_twt: u64,

    // --- Reduced Neighbor Report (RNR, tag 201) ---
    // [IEEE 802.11-2024] §9.4.2.170
    /// Total "Neighbor AP Information" blocks observed across all Beacons / Probe Responses.
    pub rnr_blocks_parsed: u64,
    /// RNR blocks advertising a 6 GHz co-located BSSID (operating class >= 131 per Annex E, Table E-4).
    pub rnr_6ghz_colocated: u64,

    // --- Multi-Link Element (MLE, ext tag 107) ---
    // [IEEE 802.11be / IEEE 802.11-2024] §9.4.2.321
    /// Basic Multi-Link Elements observed in Beacons / Probe Responses / Association Requests.
    pub mle_basic_seen: u64,
    /// Distinct link -> MLD MAC mappings learned from MLE bodies.
    pub mle_mld_addrs_learned: u64,
    /// `(AP, STA)` groups that received an additional MLD-keyed copy during MLD
    /// canonicalization in `message_store` (the original link-keyed group is kept).
    pub mld_groups_merged: u64,
    /// Link-MAC SSID entries that received an MLD-keyed copy during `essid_map`
    /// canonicalization (the original link entry is kept). The copy lets a
    /// handshake emitted under the MLD key resolve its SSID; the original lets a
    /// single-link handshake emitted under the link key resolve its SSID.
    pub essid_link_macs_merged: u64,
    /// Hash lines suppressed because no Beacon, Probe Response, `AssocReq` /
    /// `ReassocReq`, directed Probe Request, nor MLD link-MAC fallback yielded
    /// an SSID for the AP. Hashcat derives the PMK from PSK + SSID so an empty
    /// SSID is uncrackable; we drop the line and emit a per-AP
    /// `[essid_not_found_summary]` entry to `--log` instead. Counts every
    /// would-have-been-emitted line, including the multi-SSID fan-out hits.
    pub essid_unresolved_emissions: u64,
    /// Distinct AP MACs that contributed to `essid_unresolved_emissions`.
    /// Lower bound on the count of "truly hidden" APs in the capture.
    pub essid_unresolved_aps: u64,

    // PMKID by-source counters (where in the capture each PMKID came from).
    /// PMKIDs from M1 Key Data KDE (S1). [§12.7.2]
    pub pmkid_m1: u64,
    /// PMKIDs from M2 RSN IE in Key Data (S2). [§12.7.2]
    pub pmkid_m2: u64,
    /// PMKIDs from Association Request RSN IE (S3). [§9.4.2.24.5]
    pub pmkid_assoc_req: u64,
    /// PMKIDs from Reassociation Request RSN IE (S4). [§9.4.2.24.5]
    pub pmkid_reassoc_req: u64,
    /// PMKIDs from FT Authentication frames (S5 + S6, algo=2). [§13.8.3]
    pub pmkid_ft_auth: u64,
    /// PMKIDs from FILS Authentication frames (S7 + S8, algo=4/5/6). [§12.11.2]
    pub pmkid_fils_auth: u64,
    /// PMKIDs from PASN Authentication frames (S9 + S10, unknown algo). [§12.13.1]
    pub pmkid_pasn_auth: u64,
    /// PMKIDs from FT Action frames (S11 + S12 + S13, cat=6). [§13.8.5]
    pub pmkid_ft_action: u64,
    /// PMKIDs from Probe Request RSN IE (S14 + S15). [§9.4.2.24.5]
    pub pmkid_probe_req: u64,
    /// PMKIDs from Beacon RSN IE (S16; vendor firmware deviation). [§9.4.2.24.5]
    pub pmkid_beacon: u64,
    /// PMKIDs from Probe Response RSN IE (S17; vendor firmware deviation). [§9.4.2.24.5]
    pub pmkid_probe_resp: u64,
    /// PMKIDs from Mesh Peering Open/Confirm AMPE element (S18 + S19). [§14.3.5]
    pub pmkid_mesh: u64,
    /// PMKIDs from OSEN IE in Association Request (S20). [Hotspot 2.0 OSEN spec]
    pub pmkid_osen: u64,

    // PMKID by-AKM counters (determines hashcat mode).
    /// PMKIDs from non-FT PSK suites (WPA2-PSK / PSK-SHA256 / PSK-SHA384).
    /// Routed to hashcat mode 22000 (`--22000-out`); SHA-384 lines (Type 8)
    /// also reach the dedicated `--psk-sha384-out` sink. Cracking SHA-384
    /// awaits a hashcat kernel that supports the 24-byte MIC.
    pub pmkid_wpa2_psk: u64,
    /// PMKIDs from FT-PSK suites (FT-PSK / FT-PSK-SHA384).
    /// Routed to hashcat mode 37100 (`--37100-out`); SHA-384 lines (Type 10)
    /// also reach the dedicated `--ft-psk-sha384-out` sink. Cracking SHA-384
    /// awaits a hashcat kernel that supports the 24-byte MIC.
    pub pmkid_ft_psk: u64,

    // Frame-level action counters.
    /// FT Action frames seen (category=6, actions 1-3), regardless of PMKID presence.
    pub action_ft_frames: u64,
    /// Mesh Peering Action frames seen (category=15, action 1 or 2).
    pub action_mesh_peering: u64,
    /// ANQP-bearing Public Action frames seen (Category 4, Actions 10/11/12/13).
    ///
    /// A non-zero value means the capture contained Hotspot 2.0 / 802.11u query traffic.
    pub anqp_gas_frames: u64,
    /// ANQP Venue Name elements parsed (Info ID 258). [IEEE 802.11-2024] §9.4.5.4
    pub anqp_venue_name: u64,
    /// ANQP Domain Name List elements parsed (Info ID 263). [IEEE 802.11-2024] §9.4.5.19
    pub anqp_domain_name: u64,
    /// ANQP NAI Realm elements parsed (Info ID 268). [IEEE 802.11-2024] §9.4.5.10
    pub anqp_nai_realm: u64,
    /// Hotspot 2.0 Operator Friendly Name elements parsed (vendor-specific Info ID 56797
    /// with HS subtype 3). Per the Hotspot 2.0 Technical Specification §4.
    pub anqp_hs_operator_friendly_name: u64,
    /// ANQP Info ID values we do not have a dedicated parser for. Incremented once per
    /// TLV so operators can see whether unimplemented elements dominate a capture.
    pub anqp_unknown_info_id: u64,
    /// GAS Comeback / fragmented ANQP responses skipped. ANQP fragment reassembly is out
    /// of scope for v1 (see open task list).
    pub anqp_fragmented_skipped: u64,
    /// Printable-ASCII runs of length >= 8 inserted into `WordlistStore` by the
    /// optional `--wordlist-scan-ies` sweep.
    pub wordlist_scan_ie_runs: u64,

    // --- Per-sink output counts (set by main after run_output) ---
    //
    // Each `lines_<sink>` is the count of hash lines that survived that sink's dedup
    // and were written to the configured file. `dropped_<sink>` is the count of lines
    // suppressed by that sink's dedup. A single logical hash fans out to up to three
    // sinks (legacy + per-AKM-family + combined), so the per-sink counters do not sum
    // to the Phase 5 logical hash total. See `ARCHITECTURE.md §7`.
    /// `--22000-out` lines written.
    pub lines_22000: u64,
    /// `--37100-out` lines written.
    pub lines_37100: u64,
    /// `-o`/`--out` (combined per-AKM) lines written.
    pub lines_combined: u64,
    /// `--wpa1-out` lines written.
    pub lines_wpa1: u64,
    /// `--wpa2-out` lines written.
    pub lines_wpa2: u64,
    /// `--psk-sha256-out` lines written.
    pub lines_psk_sha256: u64,
    /// `--ft-out` lines written.
    pub lines_ft: u64,
    /// `--psk-sha384-out` lines written.
    pub lines_psk_sha384: u64,
    /// `--ft-psk-sha384-out` lines written.
    pub lines_ft_psk_sha384: u64,

    /// `--22000-out` lines suppressed by dedup.
    pub dropped_22000: u64,
    /// `--37100-out` lines suppressed by dedup.
    pub dropped_37100: u64,
    /// `-o`/`--out` lines suppressed by dedup.
    pub dropped_combined: u64,
    /// `--wpa1-out` lines suppressed by dedup.
    pub dropped_wpa1: u64,
    /// `--wpa2-out` lines suppressed by dedup.
    pub dropped_wpa2: u64,
    /// `--psk-sha256-out` lines suppressed by dedup.
    pub dropped_psk_sha256: u64,
    /// `--ft-out` lines suppressed by dedup.
    pub dropped_ft: u64,
    /// `--psk-sha384-out` lines suppressed by dedup.
    pub dropped_psk_sha384: u64,
    /// `--ft-psk-sha384-out` lines suppressed by dedup.
    pub dropped_ft_psk_sha384: u64,

    // --- Output file configuration (set by main before run_output) ---
    /// Path for `--22000-out`, or empty when not configured.
    pub path_22000: String,
    /// Path for `--37100-out`, or empty when not configured.
    pub path_37100: String,
    /// Path for `-o`/`--out` combined per-AKM, or empty when not configured.
    pub path_combined: String,
    /// Path for `--wpa1-out`, or empty when not configured.
    pub path_wpa1: String,
    /// Path for `--wpa2-out`, or empty when not configured.
    pub path_wpa2: String,
    /// Path for `--psk-sha256-out`, or empty when not configured.
    pub path_psk_sha256: String,
    /// Path for `--ft-out`, or empty when not configured.
    pub path_ft: String,
    /// Path for `--psk-sha384-out`, or empty when not configured.
    pub path_psk_sha384: String,
    /// Path for `--ft-psk-sha384-out`, or empty when not configured.
    pub path_ft_psk_sha384: String,
    /// Path for ESSID list output, or empty when -E was not given.
    pub essid_list_path: String,
    /// Path for probe-request ESSID list output, or empty when -R was not given.
    pub probe_list_path: String,
    /// Path for wordlist output, or empty when -W was not given.
    pub wordlist_path: String,
    /// Path for identity list output, or empty when -I was not given.
    pub identity_list_path: String,
    /// Path for username list output, or empty when -U was not given.
    pub username_list_path: String,
    /// Path for device info output, or empty when -D was not given.
    pub device_info_path: String,
    /// Path for the `--wordlist-scan` IE-scan output, or empty when not given.
    pub wordlist_scan_path: String,

    // --- Per-hash-type breakdown (the 11-row per-AKM) ---
    // Counts the number of hash lines emitted for each row of the table in
    // `ARCHITECTURE.md §2`. Populated by `record_hash_emitted()` from the
    // output writer, after dedup and FT-context filtering. Lets the summary
    // distinguish e.g. WPA2-PSK-EAPOL from PSK-SHA384-EAPOL even though they
    // currently share a hashcat mode.
    /// Hash lines written, keyed by `HashType`.
    pub hash_type_emitted: HashMap<HashType, u64>,
    /// Unique crackable hashes *found* in the capture, keyed by `HashType`,
    /// independent of which output sinks were configured. Equals
    /// `hash_type_emitted` for any type with a configured accepting sink; for a
    /// type with no configured sink (e.g. the SHA-384 family with only
    /// `--22000-out`) `hash_type_emitted` is 0 but this still counts what the
    /// capture contained. Drives the per-type "found / written" rows and the
    /// "distinct hash types observed" count.
    pub hash_type_found: HashMap<HashType, u64>,

    // --- Extraction-side identity tallies ---
    /// Unique EAP identity strings extracted (RFC 3748 §5.1). Printed in Phase 3
    /// even when the `-I` sink is not configured.
    pub identities_extracted: u64,
    /// Unique EAP peer-identity (username) strings extracted. Printed in Phase 3
    /// even when the `-U` sink is not configured.
    pub usernames_extracted: u64,

    // --- Auxiliary sink entry counts (lines actually written by `finalize`) ---
    /// Entries written to the `-E` ESSID list.
    pub entries_essid_list: u64,
    /// Entries written to the `-R` probe-ESSID list.
    pub entries_probe_list: u64,
    /// Entries written to the `-W` combined wordlist.
    pub entries_wordlist: u64,
    /// Entries written to the `--wordlist-scan` IE-scan wordlist.
    pub entries_wordlist_scan: u64,
    /// Entries written to the `-I` identity list.
    pub entries_identity_list: u64,
    /// Entries written to the `-U` username list.
    pub entries_username_list: u64,
    /// Entries written to the `-D` device-info table.
    pub entries_device_info: u64,

    // --- Phase 4 run context + Phase 5 cost block ---
    /// Echo of the resolved output-filter state ("none (WIDE mode)" or the
    /// active flag list), so a WIDE run and a --strict run are distinguishable
    /// from the banner alone.
    pub filters_active: String,
    /// Wallclock of the Phase 1-3 streaming pass in milliseconds.
    pub wallclock_p13_ms: u64,
    /// Wallclock of the Phase 4 pairing + emit pass in milliseconds.
    pub wallclock_p4_ms: u64,
    /// Peak RSS sample in MiB (lower bound; sampled at the `MemMonitor` cadence).
    pub peak_rss_mib: u64,
    /// True when the disk-backed fallback engaged at any point during the run.
    pub disk_mode_engaged: bool,

    // --- Scratch / derived state (not printed directly) ---
    /// Per-(AP,STA) timestamp of the most recently stored EAPOL message.
    /// Accumulated during Phase 1 to compute `eapol_time_gap_max_us`. Not printed.
    eapol_last_seen: HashMap<(MacAddr, MacAddr), u64>,
}

impl Stats {
    /// Creates a zeroed `Stats`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a new EAPOL message timestamp for the given `(ap, sta)` pair and updates
    /// `eapol_time_gap_max_us` if the gap to the previous message for that pair is larger.
    ///
    /// Call this once per stored EAPOL-Key message (M1/M2/M3/M4). The map is never cleared;
    /// it holds the most recent timestamp per `(AP, STA)` pair across all input files.
    pub fn update_eapol_time_gap(&mut self, ap: MacAddr, sta: MacAddr, timestamp_us: u64) {
        // Skip implausible timestamps (zeroed clock or container corruption near
        // 2^64): pairing one against a real timestamp would manufacture a
        // multi-decade gap and poison `eapol_time_gap_max_us`. The frame itself is
        // still stored and paired; only this statistic ignores it.
        if !crate::types::is_plausible_epoch_us(timestamp_us) {
            return;
        }
        let key = (ap, sta);
        if let Some(&last_ts) = self.eapol_last_seen.get(&key) {
            let gap = timestamp_us.saturating_sub(last_ts);
            if gap > self.eapol_time_gap_max_us {
                self.eapol_time_gap_max_us = gap;
            }
        }
        self.eapol_last_seen.insert(key, timestamp_us);
    }

    /// Checks a PMKID value before inserting into the store and increments the
    /// appropriate counter, returning the rejection kind (or `None` if the PMKID is
    /// structurally clean). Catches NULL placeholders, `0xFF` flash-erase
    /// sentinels, and non-cryptographic repeating-byte patterns (all-same-byte,
    /// 2-byte period, 4-byte period). PMKIDs from a healthy stack are uniformly
    /// random HMAC outputs; any such pattern indicates a firmware stub or test
    /// fixture rather than a crackable PMK fingerprint.
    ///
    /// Call this before `PmkidStore::add()`; the store independently rejects all
    /// these forms, so there is no risk of double-insertion. Pass the returned
    /// kind to `Logger::log_invalid_pmkid` when a logger is in scope.
    pub fn check_pmkid_invalid(&mut self, pmkid: &[u8; 16]) -> Option<&'static str> {
        let kind = crate::types::garbage_pattern_kind(pmkid)?;
        match kind {
            "null" => self.null_pmkid_rejected += 1,
            "ff" => self.ff_pmkid_rejected += 1,
            _ => self.repeat_pmkid_rejected += 1,
        }
        Some(kind)
    }

    /// Bumps the per-pattern nonce-rejection counter, plus the M4-specific
    /// sibling when the rejected frame was an M4. Pass the kind string
    /// returned by [`check_invalid_fields`](crate::ieee80211::eapol::check_invalid_fields)
    /// (`"null"`, `"ff"`, `"repeat_1"`, `"repeat_2"`, `"repeat_4"`) and the
    /// pre-parse message classification from the same source. The on-M4
    /// breakdown lets the banner distinguish the spec-zero M4 case (expected,
    /// harmless, hcxpcapngtool calls it `eapolm4zeroedcount`) from an
    /// abnormal NULL nonce on M1 / M2 / M3 (entropy starvation, firmware bug).
    pub const fn record_invalid_nonce(&mut self, kind: &str, msg_type: Option<MsgType>) {
        match kind.as_bytes() {
            b"null" => self.null_nonce_rejected += 1,
            b"ff" => self.ff_nonce_rejected += 1,
            _ => self.repeat_nonce_rejected += 1,
        }
        if matches!(msg_type, Some(MsgType::M4)) {
            match kind.as_bytes() {
                b"null" => self.null_nonce_rejected_on_m4 += 1,
                b"ff" => self.ff_nonce_rejected_on_m4 += 1,
                _ => self.repeat_nonce_rejected_on_m4 += 1,
            }
        }
    }

    /// Bumps the per-pattern MIC-rejection counter. See [`Self::record_invalid_nonce`]
    /// for the kind-string vocabulary.
    pub const fn record_invalid_mic(&mut self, kind: &str) {
        match kind.as_bytes() {
            b"null" => self.null_mic_rejected += 1,
            b"ff" => self.ff_mic_rejected += 1,
            _ => self.repeat_mic_rejected += 1,
        }
    }

    /// Records an EAPOL-Key frame's Key Descriptor Version into the appropriate counter.
    ///
    /// Called once per stored EAPOL-Key message. KDV 1 = HMAC-MD5 (WPA legacy),
    /// KDV 2 = HMAC-SHA1 (WPA2-PSK), KDV 3 = AES-CMAC (PSK-SHA256 / FT-PSK),
    /// KDV 0 = "AKM-defined" (spec-legitimate for the SHA-384 AKM families,
    /// counted separately so the banner does not flag it as an anomaly);
    /// 4-7 are reserved and counted under `eapol_kdv_other`.
    /// [IEEE 802.11-2024] §12.7.2, Key Information bits 0-2, Table 12-11.
    pub const fn record_key_descriptor_version(&mut self, key_version: u8) {
        match key_version {
            0 => self.eapol_kdv0 += 1,
            1 => self.eapol_kdv1 += 1,
            2 => self.eapol_kdv2 += 1,
            3 => self.eapol_kdv3 += 1,
            _ => self.eapol_kdv_other += 1,
        }
    }

    /// Updates the per-type maximum authentication length from a newly stored EAPOL message.
    ///
    /// `len` is `eapol_frame.len()` (body bytes only, not including the 4-byte EAPOL header).
    /// hcxpcapngtool reports these as `authlen (authlen+4)`.
    pub fn update_auth_len(&mut self, msg_type: MsgType, len: u16) {
        match msg_type {
            MsgType::M1 => self.m1_auth_len_max = self.m1_auth_len_max.max(len),
            MsgType::M2 => self.m2_auth_len_max = self.m2_auth_len_max.max(len),
            MsgType::M3 => self.m3_auth_len_max = self.m3_auth_len_max.max(len),
            MsgType::M4 => self.m4_auth_len_max = self.m4_auth_len_max.max(len),
        }
    }

    /// Formats beacon channel distribution as two strings: 2.4 GHz channels and 5/6 GHz
    /// channels. Returns `(Option<String>, Option<String>)` where each `Some` value is a
    /// space-separated list like `"ch1(x5) ch6(x12)"`. Returns `None` for each band when
    /// no beacons were seen on that band. Called only from `print_summary()`.
    fn format_beacon_channels(&self) -> (Option<String>, Option<String>) {
        let mut ch_24: Vec<(u8, u64)> = Vec::new();
        let mut ch_56: Vec<(u8, u64)> = Vec::new();
        for (&ch, &n) in &self.beacon_channels {
            if ch <= 14 {
                ch_24.push((ch, n));
            } else {
                ch_56.push((ch, n));
            }
        }
        ch_24.sort_by_key(|&(ch, _)| ch);
        ch_56.sort_by_key(|&(ch, _)| ch);
        let s24 = if ch_24.is_empty() {
            None
        } else {
            Some(ch_24.iter().map(|(ch, n)| format!("ch{ch}(x{n})")).collect::<Vec<_>>().join(" "))
        };
        let s56 = if ch_56.is_empty() {
            None
        } else {
            Some(ch_56.iter().map(|(ch, n)| format!("ch{ch}(x{n})")).collect::<Vec<_>>().join(" "))
        };
        (s24, s56)
    }

    /// Renders a histogram map as `"key1 (n1), key2 (n2)"`, sorted by descending
    /// count then by key for deterministic, eyeball-friendly output.
    fn format_histogram_self(map: &BTreeMap<String, u64>) -> String {
        let mut entries: Vec<(&String, &u64)> = map.iter().collect();
        entries.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        entries.iter().map(|(k, n)| format!("{k} ({n})")).collect::<Vec<_>>().join(", ")
    }

    /// Sum of the eight terminal per-packet dispositions from Phase 1 + 2.
    ///
    /// Every packet counted in `total_packets` follows the main loop to exactly
    /// one of these outcomes: dropped for an unknown link type, dropped when the
    /// link strip failed all recovery tiers, counted as a control frame, dropped
    /// as a malformed MAC header, dropped when truncated past the header, counted
    /// as an extension frame, or handed to extraction as a management or data
    /// frame. This therefore must equal `total_packets` -- STATS.md reconciliation
    /// identity 1. The banner surfaces any discrepancy as a "packets unaccounted"
    /// / "frames multi-counted" BUG row, and `run()` debug-asserts the equality so
    /// a future silent `continue` cannot pass the test suite.
    #[must_use]
    pub const fn packets_accounted(&self) -> u64 {
        self.packets_unknown_linktype
            + self.link_errors
            + self.ctrl_frames
            + self.malformed_mac_hdr
            + self.truncated_after_header
            + self.extension_frames
            + self.mgmt_frames
            + self.data_frames
    }

    /// Prints the five-section closing banner to stdout.
    ///
    /// Called unconditionally at the end of every run. The banner layout is the
    /// contract documented in `ARCHITECTURE.md §9`: one section per pipeline
    /// phase, dotted-leader rows at a fixed value column, `nz!` suppression for
    /// quiet runs, and a drop/recovered/diagnostic/informational suffix on every
    /// issue row.
    pub fn print_summary(&self) {
        print!("{}", self.summary_string());
    }

    /// Renders the closing banner as a string.
    ///
    /// Separated from [`Self::print_summary`] so tests can assert on the rendered
    /// rows (label width, row presence, parent/child sums) without capturing stdout.
    #[must_use]
    pub fn summary_string(&self) -> String {
        // W: dot-padding width for the label column. Longest label is 45 chars;
        // W must exceed every label so each row gets at least two dots before ": ".
        const W: usize = 60;
        // Hard cap on label width (W minus the two-dot minimum). Enforced by the
        // debug_assert in the row macros and the `banner_labels_fit_column` test.
        const LABEL_MAX: usize = W - 2;
        // Section header total width (header text + fill dashes).
        const SW: usize = 70;
        // EAPOL header overhead shown in auth-length display (matches hcxpcapngtool).
        const EAPAUTH_SIZE: u16 = 4;

        use std::fmt::Write as _;
        let mut out = String::with_capacity(8 * 1024);

        macro_rules! stat {
            ($label:expr, $val:expr) => {{
                let label = $label;
                debug_assert!(label.chars().count() <= LABEL_MAX, "banner label exceeds {LABEL_MAX} chars: {label}");
                let _ = writeln!(out, "{:.<W$}: {}", label, $val);
            }};
        }
        macro_rules! nz {
            ($label:expr, $val:expr) => {
                if $val > 0 {
                    stat!($label, $val);
                }
            };
        }
        macro_rules! section {
            ($num:expr, $name:expr) => {{
                let hdr = format!("=== Phase {}: {} ", $num, $name);
                let fill = "=".repeat(SW.saturating_sub(hdr.len()).max(4));
                let _ = writeln!(out, "{hdr}{fill}");
            }};
        }

        let _ = writeln!(out, "---");
        let _ =
            writeln!(out, "wpawolf {} ({})", env!("CARGO_PKG_VERSION"), option_env!("GIT_HASH").unwrap_or("release"));
        let _ = writeln!(out, "---");

        // ======================================================================
        // Phase 1 -- Ingest: file metadata + raw packet/byte ingestion
        // (See ARCHITECTURE.md §3.1.)
        // ======================================================================
        section!(1, "Ingest");

        // File metadata: when more than one file was processed (directory walk),
        // surface a count + histogram of formats / endians / DLTs so the operator
        // can spot a mixed-format input set. Single-file runs keep the original
        // one-line layout for hcxpcapngtool parity.
        if self.input_file_count > 1 {
            stat!("input files processed", self.input_file_count);
            if !self.file_formats_seen.is_empty() {
                stat!("file formats seen", Self::format_histogram_self(&self.file_formats_seen));
            }
            if !self.endians_seen.is_empty() {
                stat!("endians seen", Self::format_histogram_self(&self.endians_seen));
            }
            if !self.dlt_descs_seen.is_empty() {
                stat!("network types seen", Self::format_histogram_self(&self.dlt_descs_seen));
            }
            if !self.last_file.is_empty() {
                stat!("last file processed", self.last_file);
            }
        } else {
            if !self.last_file.is_empty() {
                stat!("file name", self.last_file);
            }
            if let Some(fmt) = self.file_formats_seen.keys().next() {
                stat!("file format", fmt);
            }
            if let Some(en) = self.endians_seen.keys().next() {
                stat!("endian", en);
            }
            if let Some(d) = self.dlt_descs_seen.keys().next() {
                stat!("network type", d);
            }
        }
        if self.timestamp_first_us > 0 {
            stat!("first packet (epoch s)", self.timestamp_first_us / 1_000_000);
            stat!("last packet (epoch s)", self.timestamp_last_us / 1_000_000);
            let dur_s = self.timestamp_last_us.saturating_sub(self.timestamp_first_us) / 1_000_000;
            stat!("duration (s)", dur_s);
        }
        nz!("bytes ingested (MiB)", self.bytes_ingested / (1024 * 1024));
        stat!("packets total", self.total_packets);
        nz!("link/parse errors (frames dropped)", self.link_errors);
        nz!("  MAC header malformed (frame dropped)", self.malformed_mac_hdr);
        nz!("non-zero Protocol Version (forgiven; processed)", self.lenient_proto_version);
        nz!("files with truncated trailing record (earlier kept)", self.truncated_capture_files);
        nz!("  trailing packets unread (dropped; see --log)", self.unreadable_packets);
        nz!("input files skipped (magic unrecognised; see --log)", self.files_skipped_unknown_format);
        nz!("packets dropped (unknown link type; no IDB)", self.packets_unknown_linktype);
        nz!("packets dropped (truncated past MAC header)", self.truncated_after_header);
        nz!("packets with zeroed timestamps (informational)", self.packets_zeroed_timestamp);
        nz!("timestamps out of sequence (informational)", self.out_of_sequence_timestamps);

        // ======================================================================
        // Phase 2 -- Decode: link/802.11 frame classification, per-band
        // (See ARCHITECTURE.md §3.2.)
        // ======================================================================
        section!(2, "Decode");

        stat!("management frames", self.mgmt_frames);
        stat!("data frames", self.data_frames);
        stat!("control frames", self.ctrl_frames);
        nz!("extension frames (802.11 amendments)", self.extension_frames);
        // Packet-accounting self-check (STATS.md identity 1). By this point all
        // eight terminal per-packet dispositions are final, so the two rows below
        // are 0 on every correct run -- they only ever appear if a future change
        // drops a packet without a counter (unaccounted) or counts one twice
        // (multi-counted). `run()` debug-asserts the same equality.
        let accounted = self.packets_accounted();
        nz!("packets unaccounted (BUG; report this)", self.total_packets.saturating_sub(accounted));
        nz!("frames multi-counted (BUG; report this)", accounted.saturating_sub(self.total_packets));
        nz!("relay (WDS) frames", self.relay_frames);
        nz!("WPA encrypted data frames", self.wpa_encrypted_data);
        nz!("WEP encrypted data frames", self.wep_encrypted_data);
        nz!("PMF-encrypted management frames (802.11w)", self.mgmt_protected_frames);
        nz!("  Action body dropped (PMF; FT/Mesh PMKIDs unavailable)", self.mgmt_protected_action_skipped);
        nz!("A-MSDU aggregated Data frames (802.11n)", self.amsdu_frames_seen);
        nz!("  subframes recovered for hidden EAPOL", self.amsdu_subframes_total);
        nz!("radiotap it_version != 0 (Tier 1 recovered)", self.radiotap_version_nonzero);
        nz!("frames recovered via it_present computation (Tier 2)", self.recovered_tier2);
        nz!("frames recovered via CRC-32 offset scan (Tier 3)", self.recovered_tier3);
        nz!("frames recovered from DLT 0 (unspecified link type)", self.recovered_dlt0);
        nz!("FCS stripped (header + CRC-32 agree)", self.fcs_header_and_crc_agree);
        nz!("FCS stripped (CRC-32 detected, header silent)", self.fcs_detected_by_crc);
        nz!("FCS stripped (BADFCS flagged; corrupt on air)", self.fcs_badfcs_flagged);
        nz!("FCS stripped (CRC-32 mismatch; no BADFCS flag)", self.fcs_crc_mismatch_no_flag);
        nz!("no FCS present (frame left untouched)", self.fcs_neither);
        nz!("radiotap A-MPDU Status field present (it_present bit 20)", self.ampdu_status_frames);
        nz!("fragments buffered for reassembly", self.fragment_stats.fragments_seen);
        nz!("  reassembled MSDUs (all fragments present)", self.fragment_stats.fragments_reassembled);
        nz!("  incomplete MSDUs (missing fragments in capture)", self.fragment_stats.fragments_incomplete);
        nz!("  fragments evicted (safety cap; expect 0)", self.fragment_stats.fragments_dropped_safety_cap);
        nz!("AWDL frames (Apple AWDL)", self.awdl_frames);
        nz!("on 2.4 GHz band (from radiotap)", self.band_24ghz);
        nz!("on 5 GHz band (from radiotap)", self.band_5ghz);
        nz!("on 6 GHz band (from radiotap)", self.band_6ghz);
        nz!("on other/unknown band (from radiotap)", self.band_other);
        // Beacon channel distribution from DS Parameter Set IE (tag 3). [§9.4.2.4]
        let (ch24_str, ch56_str) = self.format_beacon_channels();
        if let Some(s) = ch24_str {
            stat!("beacon channels 2.4 GHz (DS Parameter Set)", s);
        }
        if let Some(s) = ch56_str {
            stat!("beacon channels 5/6 GHz (DS Parameter Set)", s);
        }
        // EAPOL Key Descriptor Version mix is a decode-time classification.
        // KDV 0 is split from the reserved bucket: it is the spec-legitimate
        // "AKM-defined" value for the SHA-384 families, not an anomaly.
        nz!("EAPOL KDV 1 (HMAC-MD5 / ARC4; WPA legacy)", self.eapol_kdv1);
        nz!("EAPOL KDV 2 (HMAC-SHA1 / AES; WPA2-PSK)", self.eapol_kdv2);
        nz!("EAPOL KDV 3 (AES-CMAC; PSK-SHA256 / FT-PSK)", self.eapol_kdv3);
        nz!("EAPOL KDV 0 (AKM-defined; SHA-384 families)", self.eapol_kdv0);
        nz!("EAPOL KDV reserved (4-7; non-standard)", self.eapol_kdv_other);
        nz!("EAPOL RSN descriptor", self.eapol_rsn);
        nz!("EAPOL WPA (legacy) descriptor", self.eapol_wpa);

        // ======================================================================
        // Phase 3 -- Extract: store population (per-subtype, per-AKM, EAPOL,
        // PMKID, auxiliary metadata). See ARCHITECTURE.md §3.3.
        // ======================================================================
        section!(3, "Extract");

        // Management subtype counts -- everything captured into stores.
        nz!("BEACON (total)", self.beacon_frames);
        nz!("  SSID wildcard (hidden; beacon retained)", self.beacon_ssid_wildcard);
        nz!("  SSID zeroed (beacon retained)", self.beacon_ssid_zeroed);
        nz!("  SSID oversized (SSID rejected; beacon retained)", self.beacon_ssid_oversized);
        nz!("  RSNXE SAE-H2E required (WPA3)", self.rsnxe_sae_h2e);
        nz!("  RSNXE SAE-PK supported", self.rsnxe_sae_pk);
        nz!("  RSNXE Secure LTF (11az)", self.rsnxe_secure_ltf);
        nz!("  RSNXE Protected TWT", self.rsnxe_protected_twt);
        nz!("  RNR blocks parsed (tag 201)", self.rnr_blocks_parsed);
        nz!("    6 GHz co-located BSSIDs (RNR)", self.rnr_6ghz_colocated);
        nz!("  Multi-Link Elements observed (11be)", self.mle_basic_seen);
        nz!("    MLD addresses learned", self.mle_mld_addrs_learned);
        nz!("    (AP,STA) groups also keyed under MLD (link kept)", self.mld_groups_merged);
        nz!("    SSID entries also keyed under MLD (link kept)", self.essid_link_macs_merged);
        nz!("PROBE RESPONSE (total)", self.probe_resp_frames);
        nz!("  SSID unset (probe response retained)", self.probe_resp_ssid_unset);
        nz!("  SSID zeroed (probe response retained)", self.probe_resp_ssid_zeroed);
        nz!("PROBE REQUEST (undirected)", self.probe_req_undirected);
        nz!("PROBE REQUEST (directed)", self.probe_req_directed);
        nz!("ASSOCIATION REQUEST (total)", self.assoc_req_frames);
        nz!("  WPA1 (vendor IE 00:50:F2:01, mode 22000)", self.assoc_req_wpa1);
        nz!("  WPA2-PSK (AKM 2, mode 22000)", self.assoc_req_wpa2_psk);
        nz!("  FT-PSK (AKM 4, mode 37100)", self.assoc_req_ft_psk);
        nz!("  FT-PSK-SHA384 (AKM 19, no module)", self.assoc_req_ft_psk_sha384);
        nz!("  PSK-SHA256 (AKM 6, mode 22000)", self.assoc_req_psk_sha256);
        nz!("  PSK-SHA384 (AKM 20, no module)", self.assoc_req_psk_sha384);
        nz!("  SAE (AKM 8/9/24/25)", self.assoc_req_sae);
        nz!("  OWE (AKM 18)", self.assoc_req_owe);
        nz!("  FILS (AKM 14-17)", self.assoc_req_fils);
        nz!("  PASN (AKM 21)", self.assoc_req_pasn);
        nz!("  Enterprise 802.1X SHA-1 (AKM 1/3)", self.assoc_req_enterprise_sha1);
        nz!("  Enterprise 802.1X SHA-256 (AKM 5/11)", self.assoc_req_enterprise_sha256);
        nz!("  Enterprise 802.1X SHA-384 (AKM 12/13/22/23)", self.assoc_req_enterprise_sha384);
        nz!("  TDLS (AKM 7)", self.assoc_req_tdls);
        nz!("  APPeerKey (AKM 10, deprecated)", self.assoc_req_appeerkey);
        nz!("  UNKNOWN AKM (00:0F:AC outside Table 9-190)", self.assoc_req_akm_unknown);
        nz!("ASSOCIATION RESPONSE (total)", self.assoc_resp_frames);
        nz!("REASSOCIATION REQUEST (total)", self.reassoc_req_frames);
        nz!("  WPA1 (vendor IE 00:50:F2:01, mode 22000)", self.reassoc_req_wpa1);
        nz!("  WPA2-PSK (AKM 2, mode 22000)", self.reassoc_req_wpa2_psk);
        nz!("  FT-PSK (AKM 4, mode 37100)", self.reassoc_req_ft_psk);
        nz!("  FT-PSK-SHA384 (AKM 19, no module)", self.reassoc_req_ft_psk_sha384);
        nz!("  PSK-SHA256 (AKM 6, mode 22000)", self.reassoc_req_psk_sha256);
        nz!("  PSK-SHA384 (AKM 20, no module)", self.reassoc_req_psk_sha384);
        nz!("  SAE (AKM 8/9/24/25)", self.reassoc_req_sae);
        nz!("  OWE (AKM 18)", self.reassoc_req_owe);
        nz!("  FILS (AKM 14-17)", self.reassoc_req_fils);
        nz!("  PASN (AKM 21)", self.reassoc_req_pasn);
        nz!("  Enterprise 802.1X SHA-1 (AKM 1/3)", self.reassoc_req_enterprise_sha1);
        nz!("  Enterprise 802.1X SHA-256 (AKM 5/11)", self.reassoc_req_enterprise_sha256);
        nz!("  Enterprise 802.1X SHA-384 (AKM 12/13/22/23)", self.reassoc_req_enterprise_sha384);
        nz!("  TDLS (AKM 7)", self.reassoc_req_tdls);
        nz!("  APPeerKey (AKM 10, deprecated)", self.reassoc_req_appeerkey);
        nz!("  UNKNOWN AKM (00:0F:AC outside Table 9-190)", self.reassoc_req_akm_unknown);
        nz!("REASSOCIATION RESPONSE (total)", self.reassoc_resp_frames);
        nz!("AUTHENTICATION (total)", self.auth_frames);
        nz!("  OPEN SYSTEM", self.auth_open_system);
        nz!("  SHARED KEY (WEP)", self.auth_shared_key);
        nz!("  FAST BSS TRANSITION", self.auth_fbt);
        nz!("    FT status 52 R0KH unreachable (diagnostic)", self.ft_status_r0kh_unreachable);
        nz!("    FT status 53 invalid PMKID (diagnostic)", self.ft_status_invalid_pmkid);
        nz!("    FT status 54 invalid MDE (diagnostic)", self.ft_status_invalid_mde);
        nz!("    FT status 55 invalid FTE (diagnostic)", self.ft_status_invalid_fte);
        nz!("  SAE (WPA3)", self.auth_sae);
        nz!("  FILS", self.auth_fils);
        nz!("  NETWORK EAP (Cisco LEAP)", self.auth_network_eap);
        nz!("  PASN (unknown algo)", self.auth_pasn);
        nz!("DEAUTHENTICATION (total)", self.deauth_frames);
        nz!("  MIC failure, reason 14 (handshake-quality signal)", self.mic_failure_deauths);
        nz!("DISASSOCIATION (total)", self.disassoc_frames);
        nz!("ACTION (total)", self.action_frames);
        nz!("  NR REQUEST (containing ESSID)", self.action_nr_req_ssids);
        nz!("  FILS DISCOVERY (containing ESSID)", self.fils_discovery_ssids);
        nz!("  FT Action frames seen", self.action_ft_frames);
        nz!("  Mesh Peering frames seen", self.action_mesh_peering);
        nz!("  GAS/ANQP frames seen", self.anqp_gas_frames);
        nz!("  ANQP Venue Name parsed", self.anqp_venue_name);
        nz!("  ANQP Domain Name List parsed", self.anqp_domain_name);
        nz!("  ANQP NAI Realm parsed", self.anqp_nai_realm);
        nz!("  ANQP HS2 Operator Friendly Name parsed", self.anqp_hs_operator_friendly_name);
        nz!("  ANQP unknown Info ID (parser skipped)", self.anqp_unknown_info_id);
        nz!("  ANQP fragmented (dropped; reassembly not implemented)", self.anqp_fragmented_skipped);
        nz!("ACTION NO ACK (total)", self.action_no_ack_frames);
        nz!("ATIM (total)", self.atim_frames);
        nz!("MEASUREMENT PILOT (total)", self.measurement_pilot_frames);
        nz!("TIMING ADVERTISEMENT (total)", self.timing_advert_frames);
        nz!("RESERVED subtype (7/15; counted, not extracted)", self.mgmt_reserved_subtype);

        // Auxiliary extracted metadata.
        stat!("ESSID (unique APs seen)", self.essid_count);
        nz!("  ESSID changes (per-AP maximum)", self.essid_changes_max);
        nz!("  hash lines dropped (no SSID resolved; not crackable)", self.essid_unresolved_emissions);
        nz!("    distinct APs affected (detail in --log)", self.essid_unresolved_aps);
        nz!("SSID List IE entries extracted", self.ssid_list_entries);
        nz!("Country codes extracted", self.country_codes_extracted);
        nz!("Mesh IDs extracted", self.mesh_ids_extracted);
        nz!("WPS from Probe Requests", self.wps_probe_req_extracted);
        nz!("Vendor AP names extracted", self.vendor_ap_names_extracted);
        nz!("OWE Transition SSIDs extracted", self.owe_transition_ssids);
        nz!("Cisco CCX1 AP names extracted", self.ccx1_ap_names_extracted);
        nz!("Time Zone strings extracted", self.time_zones_extracted);
        nz!("Multiple BSSID profiles extracted", self.multiple_bssid_profiles);
        nz!("RNR BSSIDs extracted", self.rnr_bssids_extracted);
        nz!("P2P device names extracted", self.p2p_device_names_extracted);
        nz!("Wordlist IE-scan runs inserted (--wordlist-scan)", self.wordlist_scan_ie_runs);
        nz!("EAP identities extracted", self.identities_extracted);
        nz!("EAP usernames extracted", self.usernames_extracted);

        // EAPOL message counts and validity rejects.
        let eapol_total = self.eapol_m1 + self.eapol_m2 + self.eapol_m3 + self.eapol_m4;
        stat!("EAPOL messages (total)", eapol_total);
        if self.m1_auth_len_max > 0 {
            stat!(
                "  M1 auth len max (body / frame)",
                format!("{} / {}", self.m1_auth_len_max, self.m1_auth_len_max + EAPAUTH_SIZE)
            );
        }
        stat!("  M1 messages", self.eapol_m1);
        if self.m2_auth_len_max > 0 {
            stat!(
                "  M2 auth len max (body / frame)",
                format!("{} / {}", self.m2_auth_len_max, self.m2_auth_len_max + EAPAUTH_SIZE)
            );
        }
        stat!("  M2 messages", self.eapol_m2);
        if self.m3_auth_len_max > 0 {
            stat!(
                "  M3 auth len max (body / frame)",
                format!("{} / {}", self.m3_auth_len_max, self.m3_auth_len_max + EAPAUTH_SIZE)
            );
        }
        stat!("  M3 messages", self.eapol_m3);
        if self.m4_auth_len_max > 0 {
            stat!(
                "  M4 auth len max (body / frame)",
                format!("{} / {}", self.m4_auth_len_max, self.m4_auth_len_max + EAPAUTH_SIZE)
            );
        }
        stat!("  M4 messages", self.eapol_m4);
        // Garbage-pattern rejections. The M4-vs-rest split prints only its
        // non-zero sides: the M4 row is the spec-zero expected case (matches
        // hcxpcapngtool's eapolm4zeroedcount), the M1/M2/M3 row is the abnormal
        // case worth a closer look. Zero sides are suppressed.
        nz!("  NULL nonce rejected (frame dropped)", self.null_nonce_rejected);
        if self.null_nonce_rejected > 0 {
            nz!("    on M4 (spec-zero per §12.7.6.5; expected)", self.null_nonce_rejected_on_m4);
            nz!(
                "    on M1 / M2 / M3 (abnormal; firmware or entropy bug)",
                self.null_nonce_rejected - self.null_nonce_rejected_on_m4
            );
        }
        nz!("  0xFF nonce rejected (frame dropped)", self.ff_nonce_rejected);
        if self.ff_nonce_rejected > 0 {
            nz!("    on M4", self.ff_nonce_rejected_on_m4);
            nz!("    on M1 / M2 / M3", self.ff_nonce_rejected - self.ff_nonce_rejected_on_m4);
        }
        nz!("  repeating-pattern nonce rejected (frame dropped)", self.repeat_nonce_rejected);
        if self.repeat_nonce_rejected > 0 {
            nz!("    on M4", self.repeat_nonce_rejected_on_m4);
            nz!("    on M1 / M2 / M3", self.repeat_nonce_rejected - self.repeat_nonce_rejected_on_m4);
        }
        nz!("  NULL MIC rejected (frame dropped; M2/M3/M4)", self.null_mic_rejected);
        nz!("  0xFF MIC rejected (frame dropped; M2/M3/M4)", self.ff_mic_rejected);
        nz!("  repeating-pattern MIC rejected (M2/M3/M4; dropped)", self.repeat_mic_rejected);
        nz!("  NULL PMKID rejected (placeholder; PMKID dropped)", self.null_pmkid_rejected);
        nz!("  0xFF PMKID rejected (PMKID dropped)", self.ff_pmkid_rejected);
        nz!("  repeating-pattern PMKID rejected (PMKID dropped)", self.repeat_pmkid_rejected);
        nz!("  ESSID control bytes (informational; shipped unchanged)", self.essid_control_bytes_warned);
        // Sub-millisecond gaps print in microseconds instead of a misleading 0 ms.
        if self.eapol_time_gap_max_us >= 1_000 {
            stat!("  session time gap max (ms)", self.eapol_time_gap_max_us / 1_000);
        } else {
            nz!("  session time gap max (us)", self.eapol_time_gap_max_us);
        }
        nz!("  ANonce M1/M3 mismatch sessions (diagnostic; §12.7.6.4)", self.anonce_m1_m3_mismatch_sessions);

        // EAPOL direction classification (WDS tier breakdown).
        nz!("EAPOL classified by direction (Tier 1)", self.eapol_tier1_direction);
        nz!("  WDS via essid_map (Tier 1b; recovered)", self.eapol_tier1b_essid);
        nz!("  WDS via ACK discovery (Tier 2; recovered)", self.eapol_tier2_ack_discovery);
        nz!("  WDS flag-based fallback (Tier 3; recovered)", self.eapol_tier3_flag_fallback);
        nz!("  direction/ACK mismatches (diagnostic; still paired)", self.eapol_ack_mismatches);
        nz!("  preauthentication frames (EtherType 0x88C7)", self.eapol_preauth_frames);
        nz!("  LLC accepted but EAPOL parse rejected (frame dropped)", self.eapol_llc_invalid);
        nz!("  Mesh Data frames recovered (Mesh Control unwrapped)", self.mesh_control_frames);
        nz!("  Mesh Data dropped (bad Mesh Control header)", self.mesh_control_malformed);
        nz!("  EAP-Success frames (RFC 3748 §4.2)", self.eap_success_frames);
        nz!("  EAP-Failure frames (RFC 3748 §4.2)", self.eap_failure_frames);

        // PMKID extraction by source (S1-S20 from ARCHITECTURE.md §6).
        // The total counts every insertion across all input files (the same
        // PMKID re-seen across files is counted again). The emitted line count in
        // Phase 4 is the authoritative unique number after global dedup.
        stat!("PMKID store insertions (total, pre-dedup)", self.pmkids_found);
        nz!("  M1 Key Data KDE", self.pmkid_m1);
        nz!("  M2 RSN IE in Key Data", self.pmkid_m2);
        nz!("  Association Request RSN IE", self.pmkid_assoc_req);
        nz!("  Reassociation Request RSN IE", self.pmkid_reassoc_req);
        nz!("  FT Authentication (S5/S6, algo=2)", self.pmkid_ft_auth);
        nz!("  FILS Authentication (S7/S8, algo=4/5)", self.pmkid_fils_auth);
        nz!("  PASN Authentication (S9/S10)", self.pmkid_pasn_auth);
        nz!("  FT Action frame (S11-S13, cat=6)", self.pmkid_ft_action);
        nz!("  Probe Request RSN IE (S14/S15)", self.pmkid_probe_req);
        nz!("  Beacon RSN IE (S16, vendor deviation)", self.pmkid_beacon);
        nz!("  Probe Response RSN IE (S17, vendor deviation)", self.pmkid_probe_resp);
        nz!("  Mesh Peering AMPE (S18/S19)", self.pmkid_mesh);
        nz!("  OSEN IE (S20, Hotspot 2.0)", self.pmkid_osen);
        // Second child dimension of the same insertion total: by AKM family.
        // Per ARCHITECTURE.md §2: non-FT = WPA2-PSK / PSK-SHA256 / PSK-SHA384;
        // FT = FT-PSK / FT-PSK-SHA384. Labels avoid an embedded ": " so the
        // first ": " on any banner row is always the label/value separator.
        nz!("  by AKM family (non-FT PSK/SHA256/SHA384)", self.pmkid_wpa2_psk);
        nz!("  by AKM family (FT-PSK/FT-PSK-SHA384)", self.pmkid_ft_psk);

        // ======================================================================
        // Phase 4 -- Emit: hashes written, files produced, dedup decisions.
        // (See ARCHITECTURE.md §3.4.) The 11-row per-hash-type breakdown leads.
        // ======================================================================
        section!(4, "Emit");

        // Run context: which output filters were active. A WIDE run and a
        // --strict run must be distinguishable from the banner alone.
        if !self.filters_active.is_empty() {
            stat!("output filters active", self.filters_active);
        }

        // Per-hash-type breakdown -- one row per `HashType` variant from the
        // 11-type classification in ARCHITECTURE.md §2. The "found" column is the
        // sink-independent inventory (what the capture contains); the "written"
        // column is what reached a configured output file. They differ when a type
        // has no configured accepting sink -- e.g. the SHA-384 family with only
        // `--22000-out` shows "14 / 0": found in the capture, not written.
        if self.hash_type_found.values().any(|&n| n > 0) {
            let _ = writeln!(out, "per-hash-type found / written (per ARCHITECTURE.md §2):");
            for ht in HashType::all() {
                let found = self.hash_type_found.get(&ht).copied().unwrap_or(0);
                if found > 0 {
                    let written = self.hash_type_emitted.get(&ht).copied().unwrap_or(0);
                    let label = format!("  {:>2}. {}", ht.type_code(), ht.name());
                    stat!(label, format!("{found} / {written}"));
                }
            }
        }

        // Pairing engine results (Phase 4 first half: pair/ -> output/). The
        // generated total is pre-dedup; the written total and its combo children
        // are post-dedup, so the children sum to the written row, not the
        // generated one.
        stat!("EAPOL pairs generated (total, pre-dedup)", self.eapol_pairs_generated);
        stat!("EAPOL pairs written (post-dedup)", self.eapol_pairs_useful);
        nz!("  N1E2 challenge (ANonce from M1, EAPOL from M2)", self.pairs_written_n1e2);
        nz!("  N3E2 authorized (ANonce from M3, EAPOL from M2)", self.pairs_written_n3e2);
        nz!("  N1E4 authorized (ANonce from M1, EAPOL from M4)", self.pairs_written_n1e4);
        nz!("  N2E3 authorized (SNonce from M2, EAPOL from M3, AP-less)", self.pairs_written_n2e3);
        nz!("  N4E3 authorized (SNonce from M4, EAPOL from M3, AP-less)", self.pairs_written_n4e3);
        nz!("  N3E4 authorized (ANonce from M3, EAPOL from M4)", self.pairs_written_n3e4);
        nz!("  NC flag set (nonce-error-correction hint for hashcat)", self.pairs_nc);
        nz!("  LE endianness flag set (LE-router hint for hashcat)", self.pairs_le);
        nz!("  BE endianness flag set (BE-router hint for hashcat)", self.pairs_be);
        nz!("  NC-dedup lines collapsed (--nc-dedup)", self.nc_dedup_collapsed_lines);
        nz!("  NC-dedup cluster count (--nc-dedup)", self.nc_dedup_cluster_count);
        nz!("  NC-dedup max cluster size (--nc-dedup)", self.nc_dedup_max_cluster_size);
        // Opt-in output-filter drops (zero in WIDE mode). These reduce the
        // candidate set BEFORE the generated total above, so they are reported
        // as their own lines rather than folded into the generated/written gap.
        nz!("  candidates dropped (--eapoltimeout filter)", self.pairs_time_filtered);
        nz!("  candidates dropped (--rc-drift filter)", self.pairs_rc_filtered);
        nz!("  messages dropped (--max-eapol-per-type cap)", self.eapol_messages_capped);
        nz!("  instances attributed (--smart)", self.smart_instances_attributed);
        nz!("  candidates dropped (--smart, unique-RC redundant)", self.smart_uncrackable_dropped);
        nz!("  MICs kept, no unique RC link (--smart)", self.smart_ambiguous_kept);
        nz!("  FT non-APLESS survivors retained (--smart)", self.smart_ft_nonapless_kept);
        if self.rc_drift_enabled && self.rc_gap_max > 0 {
            // Firmware bugs and replay-counter corruption in wild captures produce
            // values like 2^56. Cap the display at 2^32 so the "suggested threshold"
            // remains useful; show the raw max separately when it exceeds the cap.
            const RC_GAP_SANE_LIMIT: u64 = 1 << 32;
            if self.rc_gap_max <= RC_GAP_SANE_LIMIT {
                stat!("  RC gap max (suggested NC threshold)", self.rc_gap_max);
            } else {
                stat!("  RC gap max (raw; firmware outlier)", self.rc_gap_max);
                stat!("  RC gap max (suggested NC threshold)", "see --log for outlier source");
            }
        }

        // PMKID emission (post-dedup logical count). The extraction-time totals
        // and the per-AKM-family split live in Phase 3 under "PMKID store
        // insertions"; this is what survived dedup at least once.
        stat!("PMKIDs written (post-dedup)", self.pmkids_written);

        // Global dedup accounting. Total plus the per-kind children, so the
        // pre-dedup totals above reconcile: pairs generated = pairs written +
        // EAPOL pair duplicates; PMKID insertions >= PMKIDs written + PMKID
        // duplicates (insertions also shed garbage-pattern and unresolved-SSID
        // drops counted in Phase 3).
        nz!("dedup dropped (total; duplicate hashes not written)", self.dedup_dropped);
        nz!("  EAPOL pair duplicates", self.dedup_dropped_pairs);
        nz!("  PMKID duplicates", self.dedup_dropped_pmkids);
        // Emit-time drops of crack material we extracted but could not format.
        nz!("hashes dropped (unclassified AKM; no 11-type)", self.emit_dropped_unclassified_akm);
        nz!("hashes dropped (non-PSK AKM; out of scope)", self.emit_dropped_notpsk_akm);
        nz!("hashes dropped (FT context missing; no R0KH-ID)", self.emit_dropped_ft_no_context);

        // Per-sink hash output rows. Only configured sinks render (decision:
        // banner space goes to what the run actually produced); the trailing
        // one-liner counts the rest so the full sink surface stays discoverable.
        // The legacy 22000 / 37100 sinks remain hashcat-compatible via the
        // 4-prefix scheme; the per-AKM-family and combined sinks emit the
        // 11-type classification prefixes from `ARCHITECTURE.md §2`.
        let sinks: [(&str, &str, u64, u64); 9] = [
            ("--22000-out (legacy mode 22000)", &self.path_22000, self.lines_22000, self.dropped_22000),
            ("--37100-out (legacy mode 37100)", &self.path_37100, self.lines_37100, self.dropped_37100),
            ("-o / --out (combined per-AKM)", &self.path_combined, self.lines_combined, self.dropped_combined),
            ("--wpa1-out (type 1)", &self.path_wpa1, self.lines_wpa1, self.dropped_wpa1),
            ("--wpa2-out (types 2+3)", &self.path_wpa2, self.lines_wpa2, self.dropped_wpa2),
            ("--psk-sha256-out (types 4+5)", &self.path_psk_sha256, self.lines_psk_sha256, self.dropped_psk_sha256),
            ("--ft-out (types 6+7)", &self.path_ft, self.lines_ft, self.dropped_ft),
            ("--psk-sha384-out (types 8+9)", &self.path_psk_sha384, self.lines_psk_sha384, self.dropped_psk_sha384),
            (
                "--ft-psk-sha384-out (types 10+11)",
                &self.path_ft_psk_sha384,
                self.lines_ft_psk_sha384,
                self.dropped_ft_psk_sha384,
            ),
        ];
        let mut hash_sinks_unconfigured = 0u64;
        for (label, path, lines, dropped) in sinks {
            if path.is_empty() {
                hash_sinks_unconfigured += 1;
            } else {
                stat!(label, path);
                stat!("  lines written", lines);
                nz!("  dedup dropped (duplicate hashes; not written)", dropped);
            }
        }
        nz!("hash sinks not configured", hash_sinks_unconfigured);

        // Auxiliary output files (Phase 4 tail). Same configured-only rule, and
        // each configured sink reports the entries it actually wrote -- parity
        // with the hash sinks' "lines written" rows.
        let aux_sinks: [(&str, &str, u64); 7] = [
            ("ESSID list (-E)", &self.essid_list_path, self.entries_essid_list),
            ("probe ESSID list (-R)", &self.probe_list_path, self.entries_probe_list),
            ("wordlist (-W)", &self.wordlist_path, self.entries_wordlist),
            ("IE-scan wordlist (--wordlist-scan)", &self.wordlist_scan_path, self.entries_wordlist_scan),
            ("identity list (-I)", &self.identity_list_path, self.entries_identity_list),
            ("username list (-U)", &self.username_list_path, self.entries_username_list),
            ("device info (-D)", &self.device_info_path, self.entries_device_info),
        ];
        let mut aux_sinks_unconfigured = 0u64;
        for (label, path, entries) in aux_sinks {
            if path.is_empty() {
                aux_sinks_unconfigured += 1;
            } else {
                stat!(label, path);
                stat!("  entries written", entries);
            }
        }
        nz!("auxiliary sinks not configured", aux_sinks_unconfigured);

        // ======================================================================
        // Phase 5 -- Report: closing one-liner. (See ARCHITECTURE.md §3.5.)
        // ======================================================================
        section!(5, "Report");

        // "emitted" = written to a configured sink; the EAPOL/PMKID children split
        // it by odd/even type code per the ARCHITECTURE.md §2 encoding rule, so they
        // always sum to the total. "found" = the sink-independent inventory of what
        // the capture contained, so it can exceed "emitted" when a type had no
        // configured accepting sink. "distinct hash types observed" counts the
        // inventory (found), not just what was written.
        let total_hashes: u64 = HashType::all().map(|ht| self.hash_type_emitted.get(&ht).copied().unwrap_or(0)).sum();
        let eapol_lines: u64 = HashType::all()
            .filter(|ht| ht.type_code() % 2 == 1)
            .map(|ht| self.hash_type_emitted.get(&ht).copied().unwrap_or(0))
            .sum();
        let pmkid_lines: u64 = total_hashes - eapol_lines;
        let found_types = HashType::all().filter(|ht| self.hash_type_found.get(ht).copied().unwrap_or(0) > 0).count();
        // Types present in the capture but not written anywhere -- the operator
        // can add `-o` (or the matching per-AKM sink) to capture them.
        let found_not_written = HashType::all()
            .filter(|ht| {
                self.hash_type_found.get(ht).copied().unwrap_or(0) > 0
                    && self.hash_type_emitted.get(ht).copied().unwrap_or(0) == 0
            })
            .count() as u64;
        stat!("hashes emitted (total)", total_hashes);
        nz!("  EAPOL hash lines", eapol_lines);
        nz!("  PMKID hash lines", pmkid_lines);
        stat!("distinct hash types observed", found_types);
        nz!("hash types found but not written (add -o to capture)", found_not_written);

        // Run cost. Wallclock is split at the Phase 3 / Phase 4 boundary (the
        // streaming pass vs the pairing + emit pass); throughput is file bytes
        // over the streaming pass. One decimal place via integer math -- no
        // float casts under the cast-lint policy.
        let fmt_s = |ms: u64| format!("{}.{}", ms / 1000, (ms % 1000) / 100);
        if self.wallclock_p13_ms > 0 || self.wallclock_p4_ms > 0 {
            stat!("wallclock Phase 1-3 streaming pass (s)", fmt_s(self.wallclock_p13_ms));
            stat!("wallclock Phase 4 emit (s)", fmt_s(self.wallclock_p4_ms));
            stat!("wallclock total (s)", fmt_s(self.wallclock_p13_ms + self.wallclock_p4_ms));
        }
        if self.bytes_ingested > 0 && self.wallclock_p13_ms > 0 {
            // tenths of MiB/s = bytes * 10_000 / (1 MiB * ms). Saturating guards
            // the petabyte-scale corner instead of wrapping.
            let tenths = self.bytes_ingested.saturating_mul(10_000)
                / (1_048_576u64.saturating_mul(self.wallclock_p13_ms).max(1));
            stat!("throughput (MiB/s)", format!("{}.{}", tenths / 10, tenths % 10));
        }
        nz!("peak RSS (MiB)", self.peak_rss_mib);
        stat!("disk-backed fallback engaged", if self.disk_mode_engaged { "yes" } else { "no" });

        // Zero-hash hint: one line naming the single largest drop counter so the
        // operator knows where to look first. No advice paragraphs (terse banner
        // is a feature); the named counter's own row carries the detail.
        if total_hashes == 0 && self.total_packets > 0 {
            let candidates: [(&str, u64); 6] = [
                ("NULL nonce rejected", self.null_nonce_rejected),
                ("LLC accepted but EAPOL parse rejected", self.eapol_llc_invalid),
                ("hash lines dropped (no SSID resolved)", self.essid_unresolved_emissions),
                ("link/parse errors", self.link_errors),
                ("MAC header malformed", self.malformed_mac_hdr),
                ("input files skipped", self.files_skipped_unknown_format),
            ];
            let largest = candidates.iter().max_by_key(|(_, n)| *n).filter(|(_, n)| *n > 0);
            if let Some((label, n)) = largest {
                stat!("hint (no hashes)", format!("largest drop is \"{label}\" ({n})"));
            } else {
                stat!("hint (no hashes)", "no EAPOL or PMKID material found in capture");
            }
        }

        let _ = writeln!(out, "---");
        out
    }
}

// --- Unit tests ---

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn default_is_zero() {
        let s = Stats::default();
        assert_eq!(s.total_packets, 0);
        assert_eq!(s.mgmt_frames, 0);
        assert_eq!(s.data_frames, 0);
        assert_eq!(s.ctrl_frames, 0);
        assert_eq!(s.extension_frames, 0);
        assert_eq!(s.eapol_m1, 0);
        assert_eq!(s.eapol_m2, 0);
        assert_eq!(s.eapol_m3, 0);
        assert_eq!(s.eapol_m4, 0);
        assert_eq!(s.pmkids_found, 0);
        assert_eq!(s.relay_frames, 0);
        assert_eq!(s.mgmt_protected_frames, 0);
        assert_eq!(s.mgmt_protected_action_skipped, 0);
        assert_eq!(s.eapol_tier1_direction, 0);
        assert_eq!(s.eapol_tier1b_essid, 0);
        assert_eq!(s.eapol_tier2_ack_discovery, 0);
        assert_eq!(s.eapol_tier3_flag_fallback, 0);
        assert_eq!(s.eapol_ack_mismatches, 0);
        assert_eq!(s.link_errors, 0);
        assert_eq!(s.lenient_proto_version, 0);
        assert_eq!(s.fragment_stats.fragments_seen, 0);
        assert_eq!(s.fragment_stats.fragments_reassembled, 0);
        assert_eq!(s.fragment_stats.fragments_incomplete, 0);
        assert_eq!(s.fragment_stats.fragments_dropped_safety_cap, 0);
        assert_eq!(s.truncated_capture_files, 0);
        assert_eq!(s.unreadable_packets, 0);
        assert_eq!(s.files_skipped_unknown_format, 0);
        assert_eq!(s.out_of_sequence_timestamps, 0);
        assert_eq!(s.pmkids_written, 0);
        assert_eq!(s.dedup_dropped, 0);
        assert_eq!(s.dedup_dropped_pairs, 0);
        assert_eq!(s.dedup_dropped_pmkids, 0);
        assert_eq!(s.essid_count, 0);
        assert_eq!(s.beacon_frames, 0);
        assert_eq!(s.probe_resp_frames, 0);
        assert_eq!(s.probe_req_directed, 0);
        assert_eq!(s.probe_req_undirected, 0);
        assert_eq!(s.assoc_req_frames, 0);
        assert_eq!(s.assoc_resp_frames, 0);
        assert_eq!(s.reassoc_req_frames, 0);
        assert_eq!(s.reassoc_resp_frames, 0);
        assert_eq!(s.auth_frames, 0);
        assert_eq!(s.deauth_frames, 0);
        assert_eq!(s.disassoc_frames, 0);
        assert_eq!(s.action_frames, 0);
        assert_eq!(s.action_no_ack_frames, 0);
        assert_eq!(s.atim_frames, 0);
        assert_eq!(s.measurement_pilot_frames, 0);
        assert_eq!(s.timing_advert_frames, 0);
        assert_eq!(s.action_nr_req_ssids, 0);
        assert_eq!(s.fils_discovery_ssids, 0);
        assert_eq!(s.ssid_list_entries, 0);
        assert_eq!(s.country_codes_extracted, 0);
        assert_eq!(s.mesh_ids_extracted, 0);
        assert_eq!(s.wps_probe_req_extracted, 0);
        assert_eq!(s.vendor_ap_names_extracted, 0);
        assert_eq!(s.owe_transition_ssids, 0);
        assert_eq!(s.ccx1_ap_names_extracted, 0);
        assert_eq!(s.time_zones_extracted, 0);
        assert_eq!(s.eapol_pairs_generated, 0);
        assert_eq!(s.null_nonce_rejected, 0);
        assert_eq!(s.null_nonce_rejected_on_m4, 0);
        assert_eq!(s.ff_nonce_rejected, 0);
        assert_eq!(s.ff_nonce_rejected_on_m4, 0);
        assert_eq!(s.repeat_nonce_rejected, 0);
        assert_eq!(s.repeat_nonce_rejected_on_m4, 0);
        assert_eq!(s.null_mic_rejected, 0);
        assert_eq!(s.ff_mic_rejected, 0);
        assert_eq!(s.repeat_mic_rejected, 0);
        assert_eq!(s.null_pmkid_rejected, 0);
        assert_eq!(s.ff_pmkid_rejected, 0);
        assert_eq!(s.repeat_pmkid_rejected, 0);
        assert_eq!(s.essid_control_bytes_warned, 0);
        assert!(s.last_file.is_empty());
        assert_eq!(s.input_file_count, 0);
        assert!(s.file_formats_seen.is_empty());
        assert!(s.endians_seen.is_empty());
        assert!(s.dlt_descs_seen.is_empty());
        assert_eq!(s.m1_auth_len_max, 0);
        assert_eq!(s.m2_auth_len_max, 0);
        assert_eq!(s.m3_auth_len_max, 0);
        assert_eq!(s.m4_auth_len_max, 0);
        assert_eq!(s.pairs_written_n1e2, 0);
        assert_eq!(s.pairs_written_n3e2, 0);
        assert_eq!(s.pairs_written_n1e4, 0);
        assert_eq!(s.pairs_written_n2e3, 0);
        assert_eq!(s.pairs_written_n4e3, 0);
        assert_eq!(s.pairs_written_n3e4, 0);
        assert_eq!(s.rc_gap_max, 0);
        assert_eq!(s.pairs_nc, 0);
        assert_eq!(s.pairs_le, 0);
        assert_eq!(s.pairs_be, 0);
        assert_eq!(s.nc_dedup_collapsed_lines, 0);
        assert_eq!(s.nc_dedup_cluster_count, 0);
        assert_eq!(s.nc_dedup_max_cluster_size, 0);
        assert_eq!(s.eapol_pairs_useful, 0);
    }

    #[test]
    fn update_auth_len_tracks_max() {
        let mut s = Stats::new();
        s.update_auth_len(MsgType::M1, 95);
        s.update_auth_len(MsgType::M1, 119);
        s.update_auth_len(MsgType::M1, 100);
        assert_eq!(s.m1_auth_len_max, 119);
        s.update_auth_len(MsgType::M2, 117);
        assert_eq!(s.m2_auth_len_max, 117);
        s.update_auth_len(MsgType::M3, 175);
        assert_eq!(s.m3_auth_len_max, 175);
        s.update_auth_len(MsgType::M4, 95);
        assert_eq!(s.m4_auth_len_max, 95);
    }

    #[test]
    fn record_kdv_routes_each_value() {
        let mut s = Stats::new();
        s.record_key_descriptor_version(1);
        s.record_key_descriptor_version(1);
        s.record_key_descriptor_version(2);
        s.record_key_descriptor_version(3);
        s.record_key_descriptor_version(3);
        s.record_key_descriptor_version(3);
        s.record_key_descriptor_version(0); // AKM-defined (SHA-384 families) -> kdv0
        s.record_key_descriptor_version(7); // reserved -> other
        assert_eq!(s.eapol_kdv0, 1);
        assert_eq!(s.eapol_kdv1, 2);
        assert_eq!(s.eapol_kdv2, 1);
        assert_eq!(s.eapol_kdv3, 3);
        assert_eq!(s.eapol_kdv_other, 1);
    }

    #[test]
    fn record_kdv_starts_at_zero() {
        let s = Stats::new();
        assert_eq!(s.eapol_kdv0, 0);
        assert_eq!(s.eapol_kdv1, 0);
        assert_eq!(s.eapol_kdv2, 0);
        assert_eq!(s.eapol_kdv3, 0);
        assert_eq!(s.eapol_kdv_other, 0);
    }

    #[test]
    fn check_pmkid_invalid_routes_repeat_to_repeat_counter() {
        // All-`0x55` PMKID is `repeat_1` garbage (HMAC outputs are never uniform).
        let mut s = Stats::new();
        let kind = s.check_pmkid_invalid(&[0x55u8; 16]);
        assert_eq!(kind, Some("repeat_1"));
        assert_eq!(s.null_pmkid_rejected, 0);
        assert_eq!(s.ff_pmkid_rejected, 0);
        assert_eq!(s.repeat_pmkid_rejected, 1);
    }

    #[test]
    fn check_pmkid_invalid_period_2_routes_to_repeat() {
        // 5555AAAA-style 2-byte period.
        let mut pmkid = [0u8; 16];
        for chunk in pmkid.chunks_exact_mut(2) {
            chunk[0] = 0x55;
            chunk[1] = 0xAA;
        }
        let mut s = Stats::new();
        let kind = s.check_pmkid_invalid(&pmkid);
        assert_eq!(kind, Some("repeat_2"));
        assert_eq!(s.repeat_pmkid_rejected, 1);
    }

    #[test]
    fn check_pmkid_invalid_clean_returns_none() {
        // A non-uniform 16-byte run mirrors a real HMAC output -- no rejection.
        let pmkid = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90];
        let mut s = Stats::new();
        let kind = s.check_pmkid_invalid(&pmkid);
        assert_eq!(kind, None);
        assert_eq!(s.null_pmkid_rejected, 0);
        assert_eq!(s.ff_pmkid_rejected, 0);
        assert_eq!(s.repeat_pmkid_rejected, 0);
    }

    #[test]
    fn record_invalid_nonce_routes_kind_to_correct_counter() {
        let mut s = Stats::new();
        s.record_invalid_nonce("null", None);
        s.record_invalid_nonce("ff", None);
        s.record_invalid_nonce("repeat_1", None);
        s.record_invalid_nonce("repeat_2", None);
        s.record_invalid_nonce("repeat_4", None);
        assert_eq!(s.null_nonce_rejected, 1);
        assert_eq!(s.ff_nonce_rejected, 1);
        assert_eq!(s.repeat_nonce_rejected, 3, "repeat_1, repeat_2, repeat_4 all flow to repeat counter");
        assert_eq!(s.null_nonce_rejected_on_m4, 0, "no msg_type -> M4 split stays at 0");
        assert_eq!(s.ff_nonce_rejected_on_m4, 0);
        assert_eq!(s.repeat_nonce_rejected_on_m4, 0);
    }

    #[test]
    fn record_invalid_nonce_splits_m4_subset_when_msg_type_is_m4() {
        let mut s = Stats::new();
        // Three M4 rejections, three non-M4 rejections, same kinds.
        s.record_invalid_nonce("null", Some(MsgType::M4));
        s.record_invalid_nonce("null", Some(MsgType::M2));
        s.record_invalid_nonce("ff", Some(MsgType::M4));
        s.record_invalid_nonce("ff", Some(MsgType::M1));
        s.record_invalid_nonce("repeat_1", Some(MsgType::M4));
        s.record_invalid_nonce("repeat_2", Some(MsgType::M3));
        // Aggregate counters reflect every rejection regardless of msg_type.
        assert_eq!(s.null_nonce_rejected, 2);
        assert_eq!(s.ff_nonce_rejected, 2);
        assert_eq!(s.repeat_nonce_rejected, 2);
        // On-M4 subset only counts the three M4 rejections.
        assert_eq!(s.null_nonce_rejected_on_m4, 1, "the M4 null is in the subset");
        assert_eq!(s.ff_nonce_rejected_on_m4, 1, "the M4 ff is in the subset");
        assert_eq!(s.repeat_nonce_rejected_on_m4, 1, "the M4 repeat_1 is in the subset");
    }

    #[test]
    fn record_invalid_mic_routes_kind_to_correct_counter() {
        let mut s = Stats::new();
        s.record_invalid_mic("null");
        s.record_invalid_mic("ff");
        s.record_invalid_mic("repeat_1");
        assert_eq!(s.null_mic_rejected, 1);
        assert_eq!(s.ff_mic_rejected, 1);
        assert_eq!(s.repeat_mic_rejected, 1);
    }

    #[test]
    fn print_summary_does_not_panic() {
        let mut s = Stats::new();
        s.total_packets = 1_000_000;
        s.mgmt_frames = 500;
        s.data_frames = 400;
        s.ctrl_frames = 100;
        s.relay_frames = 50;
        s.eapol_m1 = 10;
        s.eapol_m2 = 10;
        s.eapol_m3 = 9;
        s.eapol_m4 = 9;
        s.m1_auth_len_max = 95;
        s.m2_auth_len_max = 117;
        s.m3_auth_len_max = 175;
        s.m4_auth_len_max = 95;
        s.pmkids_found = 5;
        s.essid_count = 3;
        s.pmkids_written = 4;
        s.dedup_dropped = 2;
        s.dedup_dropped_pairs = 2;
        s.link_errors = 1;
        s.truncated_capture_files = 2;
        s.unreadable_packets = 2;
        s.eapol_pairs_generated = 28;
        s.eapol_pairs_useful = 14;
        s.pairs_written_n1e2 = 8;
        s.pairs_written_n3e2 = 4;
        s.pairs_written_n1e4 = 2;
        s.pairs_nc = 10;
        s.pairs_le = 2;
        s.nc_dedup_collapsed_lines = 6;
        s.nc_dedup_cluster_count = 2;
        s.nc_dedup_max_cluster_size = 4;
        s.rc_gap_max = 3;
        s.last_file = "example.pcap".to_owned();
        s.input_file_count = 1;
        *s.file_formats_seen.entry("pcap 2.4".to_owned()).or_insert(0) += 1;
        *s.endians_seen.entry("little endian".to_owned()).or_insert(0) += 1;
        *s.dlt_descs_seen.entry("DLT_IEEE802_11_RADIO (127)".to_owned()).or_insert(0) += 1;
        s.print_summary(); // must not panic (single-file branch)
    }

    #[test]
    fn print_summary_multi_file_branch_does_not_panic() {
        // Exercises the directory-walk display: count > 1 with mixed formats /
        // endians / DLTs across the input set.
        let mut s = Stats::new();
        s.input_file_count = 17;
        *s.file_formats_seen.entry("pcap 2.4".to_owned()).or_insert(0) += 14;
        *s.file_formats_seen.entry("pcapng 1.0".to_owned()).or_insert(0) += 3;
        *s.endians_seen.entry("little endian".to_owned()).or_insert(0) += 16;
        *s.endians_seen.entry("big endian".to_owned()).or_insert(0) += 1;
        *s.dlt_descs_seen.entry("DLT_IEEE802_11_RADIO (127)".to_owned()).or_insert(0) += 12;
        *s.dlt_descs_seen.entry("DLT_IEEE802_11 (105)".to_owned()).or_insert(0) += 5;
        s.last_file = "/captures/last.pcap".to_owned();
        s.print_summary();
    }

    #[test]
    fn eapol_time_gap_ignores_implausible_timestamps() {
        let mut s = Stats::new();
        let ap = MacAddr::from_bytes([0x11; 6]);
        let sta = MacAddr::from_bytes([0x22; 6]);
        // A real first reading, then a near-2^64 corrupt clock. The gap must NOT
        // be computed against the garbage value -- that manufactured ~1.8e16 ms
        // session gaps in the field. The implausible reading is ignored.
        s.update_eapol_time_gap(ap, sta, 1_700_000_000_000_000);
        s.update_eapol_time_gap(ap, sta, u64::MAX);
        assert_eq!(s.eapol_time_gap_max_us, 0, "implausible timestamp must not poison the gap");
    }

    #[test]
    fn eapol_time_gap_records_plausible_gap() {
        let mut s = Stats::new();
        let ap = MacAddr::from_bytes([0x11; 6]);
        let sta = MacAddr::from_bytes([0x22; 6]);
        s.update_eapol_time_gap(ap, sta, 1_700_000_000_000_000);
        s.update_eapol_time_gap(ap, sta, 1_700_000_000_500_000);
        assert_eq!(s.eapol_time_gap_max_us, 500_000, "a plausible gap must still be recorded");
    }

    /// Lights up every banner row, then asserts each rendered row keeps at
    /// least two leader dots before the value column -- i.e. every label fits
    /// the W=60 contract from `ARCHITECTURE.md §9`. A new row whose label
    /// exceeds the cap fails here (and trips the `debug_assert` in the row
    /// macros) instead of silently breaking the column alignment.
    #[test]
    fn banner_labels_fit_column() {
        let mut s = Stats::new();
        // Phase 1.
        s.input_file_count = 2;
        *s.file_formats_seen.entry("pcap 2.4".to_owned()).or_insert(0) += 2;
        *s.endians_seen.entry("little endian".to_owned()).or_insert(0) += 2;
        *s.dlt_descs_seen.entry("DLT_IEEE802_11_RADIO (127)".to_owned()).or_insert(0) += 2;
        s.last_file = "b.pcap".to_owned();
        s.timestamp_first_us = 1_000_000;
        s.timestamp_last_us = 2_000_000;
        s.bytes_ingested = 10 * 1024 * 1024;
        s.total_packets = 100;
        s.link_errors = 1;
        s.malformed_mac_hdr = 1;
        s.lenient_proto_version = 1;
        s.truncated_capture_files = 1;
        s.unreadable_packets = 1;
        s.files_skipped_unknown_format = 1;
        s.packets_unknown_linktype = 1;
        s.truncated_after_header = 1;
        s.packets_zeroed_timestamp = 1;
        s.out_of_sequence_timestamps = 1;
        // Phase 2.
        s.mgmt_frames = 50;
        s.data_frames = 40;
        s.ctrl_frames = 10;
        s.extension_frames = 1;
        s.relay_frames = 1;
        s.wpa_encrypted_data = 1;
        s.wep_encrypted_data = 1;
        s.mgmt_protected_frames = 1;
        s.mgmt_protected_action_skipped = 1;
        s.amsdu_frames_seen = 1;
        s.amsdu_subframes_total = 1;
        s.radiotap_version_nonzero = 1;
        s.recovered_tier2 = 1;
        s.recovered_tier3 = 1;
        s.fcs_header_and_crc_agree = 1;
        s.fcs_detected_by_crc = 1;
        s.fcs_badfcs_flagged = 1;
        s.fcs_crc_mismatch_no_flag = 1;
        s.fcs_neither = 1;
        s.ampdu_status_frames = 1;
        s.fragment_stats.fragments_seen = 1;
        s.fragment_stats.fragments_reassembled = 1;
        s.fragment_stats.fragments_incomplete = 1;
        s.fragment_stats.fragments_dropped_safety_cap = 1;
        s.awdl_frames = 1;
        s.band_24ghz = 1;
        s.band_5ghz = 1;
        s.band_6ghz = 1;
        s.band_other = 1;
        *s.beacon_channels.entry(6).or_insert(0) += 1;
        *s.beacon_channels.entry(36).or_insert(0) += 1;
        s.eapol_kdv0 = 1;
        s.eapol_kdv1 = 1;
        s.eapol_kdv2 = 1;
        s.eapol_kdv3 = 1;
        s.eapol_kdv_other = 1;
        s.eapol_rsn = 1;
        s.eapol_wpa = 1;
        // Phase 3: management subtype tree.
        s.beacon_frames = 1;
        s.beacon_ssid_wildcard = 1;
        s.beacon_ssid_zeroed = 1;
        s.beacon_ssid_oversized = 1;
        s.rsnxe_sae_h2e = 1;
        s.rsnxe_sae_pk = 1;
        s.rsnxe_secure_ltf = 1;
        s.rsnxe_protected_twt = 1;
        s.rnr_blocks_parsed = 1;
        s.rnr_6ghz_colocated = 1;
        s.mle_basic_seen = 1;
        s.mle_mld_addrs_learned = 1;
        s.mld_groups_merged = 1;
        s.essid_link_macs_merged = 1;
        s.probe_resp_frames = 1;
        s.probe_resp_ssid_unset = 1;
        s.probe_resp_ssid_zeroed = 1;
        s.probe_req_undirected = 1;
        s.probe_req_directed = 1;
        s.assoc_req_frames = 1;
        s.assoc_req_wpa1 = 1;
        s.assoc_req_wpa2_psk = 1;
        s.assoc_req_ft_psk = 1;
        s.assoc_req_ft_psk_sha384 = 1;
        s.assoc_req_psk_sha256 = 1;
        s.assoc_req_psk_sha384 = 1;
        s.assoc_req_sae = 1;
        s.assoc_req_owe = 1;
        s.assoc_req_fils = 1;
        s.assoc_req_pasn = 1;
        s.assoc_req_enterprise_sha1 = 1;
        s.assoc_req_enterprise_sha256 = 1;
        s.assoc_req_enterprise_sha384 = 1;
        s.assoc_req_tdls = 1;
        s.assoc_req_appeerkey = 1;
        s.assoc_req_akm_unknown = 1;
        s.assoc_resp_frames = 1;
        s.reassoc_req_frames = 1;
        s.reassoc_req_wpa1 = 1;
        s.reassoc_req_wpa2_psk = 1;
        s.reassoc_req_ft_psk = 1;
        s.reassoc_req_ft_psk_sha384 = 1;
        s.reassoc_req_psk_sha256 = 1;
        s.reassoc_req_psk_sha384 = 1;
        s.reassoc_req_sae = 1;
        s.reassoc_req_owe = 1;
        s.reassoc_req_fils = 1;
        s.reassoc_req_pasn = 1;
        s.reassoc_req_enterprise_sha1 = 1;
        s.reassoc_req_enterprise_sha256 = 1;
        s.reassoc_req_enterprise_sha384 = 1;
        s.reassoc_req_tdls = 1;
        s.reassoc_req_appeerkey = 1;
        s.reassoc_req_akm_unknown = 1;
        s.reassoc_resp_frames = 1;
        s.auth_frames = 1;
        s.auth_open_system = 1;
        s.auth_shared_key = 1;
        s.auth_fbt = 1;
        s.ft_status_r0kh_unreachable = 1;
        s.ft_status_invalid_pmkid = 1;
        s.ft_status_invalid_mde = 1;
        s.ft_status_invalid_fte = 1;
        s.auth_sae = 1;
        s.auth_fils = 1;
        s.auth_network_eap = 1;
        s.auth_pasn = 1;
        s.deauth_frames = 1;
        s.mic_failure_deauths = 1;
        s.disassoc_frames = 1;
        s.action_frames = 1;
        s.action_nr_req_ssids = 1;
        s.fils_discovery_ssids = 1;
        s.action_ft_frames = 1;
        s.action_mesh_peering = 1;
        s.anqp_gas_frames = 1;
        s.anqp_venue_name = 1;
        s.anqp_domain_name = 1;
        s.anqp_nai_realm = 1;
        s.anqp_hs_operator_friendly_name = 1;
        s.anqp_unknown_info_id = 1;
        s.anqp_fragmented_skipped = 1;
        s.action_no_ack_frames = 1;
        s.atim_frames = 1;
        s.measurement_pilot_frames = 1;
        s.timing_advert_frames = 1;
        s.mgmt_reserved_subtype = 1;
        // Phase 3: ESSID + plaintext surfaces.
        s.essid_count = 1;
        s.essid_changes_max = 1;
        s.essid_unresolved_emissions = 1;
        s.essid_unresolved_aps = 1;
        s.ssid_list_entries = 1;
        s.country_codes_extracted = 1;
        s.mesh_ids_extracted = 1;
        s.wps_probe_req_extracted = 1;
        s.vendor_ap_names_extracted = 1;
        s.owe_transition_ssids = 1;
        s.ccx1_ap_names_extracted = 1;
        s.time_zones_extracted = 1;
        s.multiple_bssid_profiles = 1;
        s.rnr_bssids_extracted = 1;
        s.p2p_device_names_extracted = 1;
        s.wordlist_scan_ie_runs = 1;
        s.identities_extracted = 1;
        s.usernames_extracted = 1;
        // Phase 3: EAPOL block.
        s.eapol_m1 = 1;
        s.eapol_m2 = 1;
        s.eapol_m3 = 1;
        s.eapol_m4 = 1;
        s.m1_auth_len_max = 95;
        s.m2_auth_len_max = 121;
        s.m3_auth_len_max = 151;
        s.m4_auth_len_max = 95;
        s.null_nonce_rejected = 2;
        s.null_nonce_rejected_on_m4 = 1;
        s.ff_nonce_rejected = 2;
        s.ff_nonce_rejected_on_m4 = 1;
        s.repeat_nonce_rejected = 2;
        s.repeat_nonce_rejected_on_m4 = 1;
        s.null_mic_rejected = 1;
        s.ff_mic_rejected = 1;
        s.repeat_mic_rejected = 1;
        s.null_pmkid_rejected = 1;
        s.ff_pmkid_rejected = 1;
        s.repeat_pmkid_rejected = 1;
        s.essid_control_bytes_warned = 1;
        s.eapol_time_gap_max_us = 1_500_000;
        s.anonce_m1_m3_mismatch_sessions = 1;
        s.eapol_tier1_direction = 1;
        s.eapol_tier1b_essid = 1;
        s.eapol_tier2_ack_discovery = 1;
        s.eapol_tier3_flag_fallback = 1;
        s.eapol_ack_mismatches = 1;
        s.eapol_preauth_frames = 1;
        s.eapol_llc_invalid = 1;
        s.mesh_control_frames = 1;
        s.mesh_control_malformed = 1;
        s.eap_success_frames = 1;
        s.eap_failure_frames = 1;
        // Phase 3: PMKID sources.
        s.pmkids_found = 13;
        s.pmkid_m1 = 1;
        s.pmkid_m2 = 1;
        s.pmkid_assoc_req = 1;
        s.pmkid_reassoc_req = 1;
        s.pmkid_ft_auth = 1;
        s.pmkid_fils_auth = 1;
        s.pmkid_pasn_auth = 1;
        s.pmkid_ft_action = 1;
        s.pmkid_probe_req = 1;
        s.pmkid_beacon = 1;
        s.pmkid_probe_resp = 1;
        s.pmkid_mesh = 1;
        s.pmkid_osen = 1;
        s.pmkid_wpa2_psk = 1;
        s.pmkid_ft_psk = 1;
        // Phase 4. Every type is found; one type is left written=0 so the
        // per-type "found / written" rows and the "found but not written" row
        // both render for the label-width check.
        s.filters_active = "eapoltimeout=5, rc-drift=8, dedup-hash-combos, nc-dedup (tolerance 8)".to_owned();
        for ht in HashType::all() {
            *s.hash_type_found.entry(ht).or_insert(0) += 1;
            if ht != HashType::FtPskSha384Eapol {
                *s.hash_type_emitted.entry(ht).or_insert(0) += 1;
            }
        }
        s.eapol_pairs_generated = 8;
        s.eapol_pairs_useful = 6;
        s.pairs_written_n1e2 = 1;
        s.pairs_written_n3e2 = 1;
        s.pairs_written_n1e4 = 1;
        s.pairs_written_n2e3 = 1;
        s.pairs_written_n4e3 = 1;
        s.pairs_written_n3e4 = 1;
        s.pairs_nc = 1;
        s.pairs_le = 1;
        s.pairs_be = 1;
        s.pairs_time_filtered = 1;
        s.pairs_rc_filtered = 1;
        s.nc_dedup_collapsed_lines = 1;
        s.nc_dedup_cluster_count = 1;
        s.nc_dedup_max_cluster_size = 1;
        s.rc_drift_enabled = true;
        s.rc_gap_max = 3;
        s.pmkids_written = 5;
        s.dedup_dropped = 3;
        s.dedup_dropped_pairs = 2;
        s.dedup_dropped_pmkids = 1;
        s.emit_dropped_unclassified_akm = 1;
        s.emit_dropped_ft_no_context = 1;
        s.path_22000 = "h.22000".to_owned();
        s.lines_22000 = 1;
        s.dropped_22000 = 1;
        s.path_37100 = "h.37100".to_owned();
        s.lines_37100 = 1;
        s.path_combined = "h.all".to_owned();
        s.lines_combined = 1;
        s.path_wpa1 = "h.wpa1".to_owned();
        s.path_wpa2 = "h.wpa2".to_owned();
        s.path_psk_sha256 = "h.s256".to_owned();
        s.path_ft = "h.ft".to_owned();
        s.path_psk_sha384 = "h.s384".to_owned();
        s.path_ft_psk_sha384 = "h.fts384".to_owned();
        s.essid_list_path = "essids.txt".to_owned();
        s.entries_essid_list = 1;
        s.probe_list_path = "probes.txt".to_owned();
        s.entries_probe_list = 1;
        s.wordlist_path = "wl.txt".to_owned();
        s.entries_wordlist = 1;
        s.identity_list_path = "ids.txt".to_owned();
        s.entries_identity_list = 1;
        s.username_list_path = "users.txt".to_owned();
        s.entries_username_list = 1;
        s.device_info_path = "devs.tsv".to_owned();
        s.entries_device_info = 1;
        s.wordlist_scan_path = "scan.txt".to_owned();
        s.entries_wordlist_scan = 1;
        // Phase 5.
        s.wallclock_p13_ms = 1_500;
        s.wallclock_p4_ms = 200;
        s.peak_rss_mib = 10;
        s.disk_mode_engaged = true;

        let rendered = s.summary_string();
        let mut rows_checked = 0usize;
        for line in rendered.lines() {
            if line.starts_with("===") || line == "---" || line.starts_with("wpawolf ") || line.ends_with(':') {
                continue;
            }
            let Some(idx) = line.find(": ") else { continue };
            let label_part = &line[..idx];
            assert!(label_part.ends_with(".."), "banner row label too wide (no dot leader): {line}");
            rows_checked += 1;
        }
        // Guard against the test silently checking nothing if the layout changes.
        assert!(rows_checked > 150, "expected the lit-up banner to render >150 rows, got {rows_checked}");
    }

    /// `packets_accounted` sums exactly the eight terminal dispositions, so a
    /// consistent run reconciles to `total_packets` (identity 1) and neither BUG
    /// row renders; an inconsistent run surfaces the discrepancy.
    #[test]
    fn packet_accounting_identity_reconciles_and_surfaces_breaks() {
        let mut s = Stats::new();
        s.total_packets = 12;
        s.mgmt_frames = 4;
        s.data_frames = 3;
        s.ctrl_frames = 2;
        s.extension_frames = 1;
        s.link_errors = 1;
        s.malformed_mac_hdr = 0;
        s.truncated_after_header = 1;
        s.packets_unknown_linktype = 0;
        assert_eq!(s.packets_accounted(), 12, "the eight terminal buckets must sum to total");
        let rendered = s.summary_string();
        assert!(!rendered.contains("unaccounted (BUG"), "consistent run must not show the BUG row:\n{rendered}");
        assert!(!rendered.contains("multi-counted (BUG"), "{rendered}");

        // Drop a packet without a counter -> unaccounted surfaces.
        s.total_packets = 13;
        assert_eq!(s.total_packets - s.packets_accounted(), 1);
        assert!(s.summary_string().contains("packets unaccounted (BUG; report this)"));

        // Count one twice -> multi-counted surfaces.
        s.total_packets = 11;
        assert!(s.summary_string().contains("frames multi-counted (BUG; report this)"));
    }

    /// Zero-hash runs print a one-line hint naming the largest drop counter.
    #[test]
    fn zero_hash_hint_names_largest_drop() {
        let mut s = Stats::new();
        s.total_packets = 10;
        s.null_nonce_rejected = 7;
        s.filters_active = "none (WIDE mode)".to_owned();
        let rendered = s.summary_string();
        assert!(rendered.contains("hint (no hashes)"), "missing hint row:\n{rendered}");
        assert!(rendered.contains("NULL nonce rejected"), "hint must name the largest drop:\n{rendered}");

        // And when nothing was dropped either, the hint says so explicitly.
        let mut empty = Stats::new();
        empty.total_packets = 10;
        let rendered_empty = empty.summary_string();
        assert!(rendered_empty.contains("no EAPOL or PMKID material found in capture"), "{rendered_empty}");
    }
}
