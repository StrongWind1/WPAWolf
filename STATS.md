# STATS.md: the stats banner contract

This file is the **authoritative, line-by-line catalogue** of wpawolf's closing stats banner. It supersedes the old `ARCHITECTURE.md §9` catalogue; `ARCHITECTURE.md §9` is now a one-paragraph pointer here. The contract is machine-checked: `make audit-stats` (`tools/audit_stats.sh`, wired into `make check-all`) asserts that every public field of `Stats` (`src/stats.rs`) and `FragmentStats` (`src/store/fragments.rs`) is named in backticks in this file, and that every `stats.<field>` reference in the docs is a real field. A counter cannot be added, renamed, or removed without this file moving in lockstep.

The banner is rendered by `Stats::summary_string` and printed by `Stats::print_summary`. Every run prints it unconditionally to stdout (FR-CLI-4); stderr stays silent.

## Design principle

Every packet wpawolf reads, and every classification it makes, lands in a counter. The banner is built so an operator can **account for every packet** and **see every drop**: nothing the tool decides about a frame is thrown away silently. The four reconciliation identities in the next section are the formal statement of that principle, and `tools/audit_stats.sh` plus the `banner_labels_fit_column` unit test keep the catalogue and the code from drifting apart.

## Reconciliation identities

These are the sums an operator can check against the banner. They hold by construction; a future change that breaks one is a bug.

1. **Packet accounting (Phase 1 + 2).** Every packet that `next_packet` yielded reaches exactly one terminal disposition:

   ```
   total_packets =   packets_unknown_linktype        (dropped: no IDB)
                   + link_errors                       (dropped: link strip failed all recovery tiers)
                   + ctrl_frames                        (control frames: not body-parsed)
                   + malformed_mac_hdr                  (dropped: MAC header unparseable)
                   + truncated_after_header             (dropped: body past captured length)
                   + extension_frames                   (802.11 extension frames: not body-parsed)
                   + mgmt_frames + data_frames          (handed to Phase 3 extraction)
   ```

   `unreadable_packets` is the count of records that errored on read; those never entered `total_packets` (the counter increments only on a successful `next_packet`). `recovered_tier2` / `recovered_tier3` / `recovered_dlt0`, `lenient_proto_version`, the FCS outcomes, and the per-band counts are *sub-classifications* of frames that did reach `mgmt`/`data`/`ctrl`; they overlap those buckets and are not separate terminal states.

   **This identity is enforced, not just asserted.** `Stats::packets_accounted()` sums the eight terminal buckets; the banner prints `packets unaccounted (BUG; report this)` (= `total_packets - accounted`) and `frames multi-counted (BUG; report this)` (= `accounted - total_packets`); both 0 on every correct run, so neither renders. The pipeline `run()` debug-asserts the equality, and `tests/integration/generated_corpus.rs::packet_accounting_holds_across_generated_corpus` drives the whole fixture corpus through the binary and fails if either BUG row appears. A future silent `continue` that drops a packet without a counter therefore cannot pass the test suite.

2. **Management subtype accounting (Phase 3).** `mgmt_frames` equals the sum of all named management subtype counters plus `mgmt_reserved_subtype`. (PMF-protected Action frames are counted in `action_frames` and then short-circuited; see `mgmt_protected_action_skipped`.)

3. **Pair accounting (Phase 4).** `eapol_pairs_generated = eapol_pairs_useful + dedup_dropped_pairs`. The opt-in filters reduce the candidate set *before* generation, so `pairs_time_filtered` / `pairs_rc_filtered` are reported as their own lines, not folded into the gap. The per-combo `pairs_written_n*` children sum to `eapol_pairs_useful` (the written total), not to the generated total.

4. **Hash accounting (Phase 5).** `hashes emitted (total)` is the sum of *written* hashes over the 11-type table (`hash_type_emitted`). Its `EAPOL hash lines` / `PMKID hash lines` children are the odd-code / even-code halves of that same table, so they always sum to the total. `hash_type_found` is the parallel *found* inventory, counted independently of which sinks were configured (so `found >= written` per type), and it drives `distinct hash types observed` and the `found but not written` row. PMKID material that did not reach a sink is accounted by `dedup_dropped_pmkids`, `emit_dropped_unclassified_akm`, `emit_dropped_notpsk_akm`, `emit_dropped_ft_no_context`, and the Phase-3 garbage/`essid_unresolved` drops.

## Formatting contract

- Rows render as `{label:.<60}: {value}`: dotted leaders to a fixed value column at **W=60**; section headers fill to 70.
- Every label is **at most 58 characters** including indent (so at least two leader dots always render) and contains **no embedded `": "`** (the first `": "` on any row is always the label/value separator, so `awk -F': '` is unambiguous). Both rules are enforced by the `banner_labels_fit_column` unit test and a `debug_assert` in the row macros.
- Indentation (0 / 2 / 4 spaces) expresses hierarchy: children sum to their parent unless a label says `pre-dedup` / `post-dedup`.
- Skeleton rows (`stat!`) always print; everything else (`nz!`) prints only when nonzero, and split rows never print a bare-zero side.
- Values are raw integers, no separators. Wallclock and throughput are the only one-decimal values.

## Disposition classes

Every row carries exactly one disposition, signalled in its label suffix and tabulated in the **Disposition** column below:

| Class | Meaning | Drops a packet/hash? |
|---|---|---|
| **skeleton** | Always-printed structural total. | no |
| **informational** | Something observed; no data impact and not even an anomaly. | no |
| **diagnostic** | An anomaly worth noting; the frame was still processed. | no |
| **recovered** | A problem was worked around and the data was kept. | no |
| **dropped** | A frame, PMKID, or hash line was lost. **The label always says so.** | **yes** |

---

## Phase 1: Ingest

File-container reading and packet integrity. Source specs: pcapng = draft-ietf-opsawg-pcapng-05; pcap magic / DLT = libpcap `sf-pcap.c` / `dlt.h`.

| Line | Field(s) | Source | Why we care | Disposition |
|---|---|---|---|---|
| input files processed / file name | `input_file_count`, `last_file` | pcapng §4 / pcap header | How many captures were actually opened; single-file runs keep the hcxpcapngtool one-line layout. | skeleton |
| file formats / endians / network types seen | `file_formats_seen`, `endians_seen`, `dlt_descs_seen` | pcap/pcapng headers | Spot one odd file (wrong format/endian/DLT) in a large directory walk. | informational |
| first / last packet (epoch s), duration | `timestamp_first_us`, `timestamp_last_us` | pcapng §4.3 EPB / pcap record ts | Capture span; a near-zero duration on a big file flags a clock problem. | informational |
| bytes ingested (MiB) | `bytes_ingested` | file sizes | Denominator for the Phase 5 throughput row. | informational |
| packets total | `total_packets` | per-record | The packet-accounting denominator (identity 1). | skeleton |
| link/parse errors (frames dropped) | `link_errors` | §9 link-layer | Link-layer strip failed after every recovery tier; the 802.11 frame was never exposed. | **dropped** |
| MAC header malformed (frame dropped) | `malformed_mac_hdr` | §9.2.4.1 | Frame Control / addresses unparseable; cannot dissect. | **dropped** |
| non-zero Protocol Version (forgiven; processed) | `lenient_proto_version` | §9.2.4.1.1 | FC version != 0 (reserved) but the v0 MAC layout still parses (matches tshark); the frame is kept. | diagnostic |
| files with truncated trailing record | `truncated_capture_files`, `unreadable_packets` | FR-IN-10 | A capture ended mid-record; earlier records are kept, the partial tail is lost. | **dropped** (tail) |
| input files skipped (magic unrecognised) | `files_skipped_unknown_format` | pcap magic | A non-capture file (sub-4-byte stub, junk) in the input set; routed to `[skipped_input]`. | **dropped** (file) |
| packets dropped (unknown link type; no IDB) | `packets_unknown_linktype` | pcapng §4.2 | A pcapng EPB referenced an `interface_id` with no preceding IDB, so the DLT is unknown and the packet cannot be decoded. | **dropped** |
| packets dropped (truncated past MAC header) | `truncated_after_header` | snaplen | The MAC header parsed but its `body_offset` ran past the captured bytes (snaplen truncation / corrupt length); the body and any EAPOL/IE it held are gone. | **dropped** |
| packets with zeroed timestamps (informational) | `packets_zeroed_timestamp` | pcapng §4.3 | Capture-tool artifact (no clock); the frame is processed normally. | informational |
| timestamps out of sequence (informational) | `out_of_sequence_timestamps` | per-record ts | A packet's timestamp went strictly backward within a file (mergecap / hand-edit); processing is order-independent. | informational |

---

## Phase 2: Decode

Link-layer strip, FCS resolution, tiered recovery, 802.11 frame-type split, RF context, EAPOL wire mix. Source specs: radiotap.org; IEEE 802.11-2024 §9.2.4 (Frame Control), §9.2.4.7 (FCS), §9.3.2.2.2 (A-MSDU), §9.2.4.4 (fragmentation), §12.7.2 (EAPOL-Key).

| Line | Field(s) | Source | Why we care | Disposition |
|---|---|---|---|---|
| management / data / control frames | `mgmt_frames`, `data_frames`, `ctrl_frames` | §9.2.4.1.3 Table 9-1 | The frame-type skeleton; mgmt+data feed extraction, control is terminal. | skeleton |
| extension frames (802.11 amendments) | `extension_frames` | Table 9-1 type 3 | Type-3 (DMG/S1G) frames; counted and not body-parsed. | informational |
| packets unaccounted (BUG; report this) | derived (`total_packets - packets_accounted()`) | identity 1 | Self-check: a packet was dropped without a counter. Always 0; a nonzero value is a silent-drop regression. | **dropped** (BUG) |
| frames multi-counted (BUG; report this) | derived (`packets_accounted() - total_packets`) | identity 1 | Self-check: a packet was counted in two terminal buckets. Always 0; nonzero is a double-count regression. | diagnostic (BUG) |
| relay (WDS) frames | `relay_frames` | §9.3.2.1 Table 9-60 | 4-address relay frames carrying EAPOL, deferred to Phase 1.5 for direction resolution; wpawolf processes WDS unconditionally (invariant 4). | informational |
| WPA / WEP encrypted data frames | `wpa_encrypted_data`, `wep_encrypted_data` | §9.2.4.1.1 B14; §12.5.2.2 / §12.3.4.2 | Protected data frames, split on the KeyID-octet ExtIV bit (1 = TKIP/CCMP/GCMP, 0 = legacy WEP). Capture-quality / cipher-mix signal. | informational |
| PMF-encrypted management frames (802.11w) | `mgmt_protected_frames` | §11.13 | Encrypted Action/mgmt bodies; we have no PTK to decrypt them. | informational |
| Action body dropped (PMF; FT/Mesh PMKIDs unavailable) | `mgmt_protected_action_skipped` | §11.13 | A PMF-protected Action frame whose body (possibly an FT/Mesh PMKID) we cannot read. | **dropped** (body) |
| A-MSDU aggregated Data frames / subframes recovered | `amsdu_frames_seen`, `amsdu_subframes_total` | §9.3.2.2.2 | EAPOL hidden in A-MSDU subframes 2..N would be missed without subframe iteration. | recovered |
| radiotap it_version != 0 (Tier 1 recovered) | `radiotap_version_nonzero` | radiotap.org | A firmware emits non-zero `it_version`; we read `it_len` regardless instead of dropping (1.5M frames in one corpus). | recovered |
| frames recovered via it_present computation (Tier 2) | `recovered_tier2` | radiotap.org | Corrupt `it_len`; header length recomputed from the `it_present` bitmask. | recovered |
| frames recovered via CRC-32 offset scan (Tier 3) | `recovered_tier3` | ISO 3309 CRC-32 | All header fields corrupt; the 802.11 frame located by scanning for the FCS residue `0x2144DF1C`. | recovered |
| frames recovered from DLT 0 (unspecified link type) | `recovered_dlt0` | libpcap `dlt.h` | A pcapng IDB declared link type 0 over genuine 802.11; recovered by a light radiotap / raw-802.11 attempt instead of being dropped as `link_errors`. | recovered |
| FCS stripped (header + CRC-32 agree) | `fcs_header_and_crc_agree` | §9.2.4.7 | Both the radiotap flag and the CRC confirm a trailing FCS; stripped before IE walking. | recovered |
| FCS stripped (CRC-32 detected, header silent) | `fcs_detected_by_crc` | §9.2.4.7 | The header never announced an FCS but the CRC found one; without this those 4 bytes would mis-parse as IE data. | recovered |
| FCS stripped (BADFCS flagged; corrupt on air) | `fcs_badfcs_flagged` | radiotap Flags 0x40 | Radio received the frame with a failed checksum; stripped anyway. | diagnostic |
| FCS stripped (CRC-32 mismatch; no BADFCS flag) | `fcs_crc_mismatch_no_flag` | §9.2.4.7 | Header claimed an FCS, CRC disagreed, no BADFCS flag; trust the header and strip. | diagnostic |
| no FCS present (frame left untouched) | `fcs_neither` | §9.2.4.7 | No trailing FCS; makes the five FCS outcomes account for every frame reaching the resolver. | informational |
| radiotap A-MPDU Status field present | `ampdu_status_frames` | radiotap A-MPDU | A-MPDU aggregation context observed; parser-health signal. | informational |
| fragments buffered for reassembly | `fragment_stats.fragments_seen` | §9.2.4.4 | Non-final MSDU fragments held for out-of-order reassembly. | informational |
| reassembled MSDUs (all fragments present) | `fragment_stats.fragments_reassembled` | §9.2.4.4 | An FT-PSK M2 split across the radio MTU was rebuilt. | recovered |
| incomplete MSDUs (missing fragments in capture) | `fragment_stats.fragments_incomplete` | §9.2.4.4 | Fragments whose siblings never appeared; the MSDU is lost. | **dropped** |
| fragments evicted (safety cap; expect 0) | `fragment_stats.fragments_dropped_safety_cap` | n/a | Paranoid 1 M backstop on the in-flight buffer; nonzero means the cap is sized wrong. | **dropped** |
| AWDL frames (Apple AWDL) | `awdl_frames` | Apple AWDL | Apple peer-to-peer traffic; capture-environment signal. | informational |
| on 2.4 / 5 / 6 / other band | `band_24ghz`, `band_5ghz`, `band_6ghz`, `band_other` | radiotap Channel | Band distribution from the radiotap channel field; `band_other` keeps the split accounting for every channel-bearing packet. | informational |
| beacon channels 2.4 / 5-6 GHz | `beacon_channels` | §9.4.2.4 DS Param | Channel histogram from Beacons (DS Parameter Set IE). | informational |
| EAPOL KDV 1 / 2 / 3 / 0 / reserved | `eapol_kdv1`, `eapol_kdv2`, `eapol_kdv3`, `eapol_kdv0`, `eapol_kdv_other` | §12.7.2 Table 12-11 | Key Descriptor Version mix; drives KDV-first AKM reconciliation. KDV 0 is the legitimate "AKM-defined" value for the SHA-384 families, split out so it is not flagged as an anomaly. | informational |
| EAPOL RSN / WPA (legacy) descriptor | `eapol_rsn`, `eapol_wpa` | §12.7.2 | Descriptor-type byte (0x02 RSN vs 0xFE WPA legacy). | informational |

---

## Phase 3: Extract

Store population. The management subtype tree, the ESSID block, plaintext surfaces, the EAPOL store block, and the PMKID S1-S20 sources.

### Management subtype tree

Source: IEEE 802.11-2024 §9.4.1 (mgmt body fields), Table 9-1 (subtypes), §9.4.2 (IEs). Each is a per-subtype total or a sub-field of one; together with `mgmt_reserved_subtype` they reconcile to `mgmt_frames` (identity 2).

| Line | Field(s) | Source | Why we care | Disposition |
|---|---|---|---|---|
| BEACON (total) | `beacon_frames` | §9.3.3.3 | AP presence; SSID/AKM/PMKID source. | informational |
| SSID wildcard / zeroed / oversized | `beacon_ssid_wildcard`, `beacon_ssid_zeroed`, `beacon_ssid_oversized` | §9.4.2.2 | Hidden/blanked/malformed SSIDs; oversized SSID is rejected, the beacon kept. | informational / **dropped** (oversized SSID only) |
| RSNXE SAE-H2E / SAE-PK / Secure LTF / Protected TWT | `rsnxe_sae_h2e`, `rsnxe_sae_pk`, `rsnxe_secure_ltf`, `rsnxe_protected_twt` | §9.4.2.241 | WPA3 / 11az / 11ax capability bits; capture-feature signal. | informational |
| RNR blocks / 6 GHz co-located BSSIDs | `rnr_blocks_parsed`, `rnr_6ghz_colocated` | §9.4.2.170 | Reduced Neighbor Report; 6 GHz co-location discovery. | informational |
| Multi-Link Elements / MLD addrs / groups+SSIDs also keyed under MLD | `mle_basic_seen`, `mle_mld_addrs_learned`, `mld_groups_merged`, `essid_link_macs_merged` | §9.4.2.321, §35.3 | 802.11be MLO: each link-keyed handshake / SSID also gets an MLD-keyed copy (the link form is kept). A multi-link handshake cracks under the MLD MAC; a single-link association to one BSSID of an MLD cracks under the link MAC; both are emitted so the crackable one is always present. | recovered |
| PROBE RESPONSE (total) / SSID unset / zeroed | `probe_resp_frames`, `probe_resp_ssid_unset`, `probe_resp_ssid_zeroed` | §9.3.3.10 / §9.4.2.2 | Probe Responses answer directed probes; an empty/zeroed SSID there is a capture-quality signal. | informational |
| PROBE REQUEST (undirected / directed) | `probe_req_undirected`, `probe_req_directed` | §9.3.3.9 | Directed probes name an SSID the client has joined before: wordlist material. | informational |
| ASSOCIATION REQUEST (total) + per-AKM | `assoc_req_frames`, `assoc_req_wpa1`, `assoc_req_wpa2_psk`, `assoc_req_ft_psk`, `assoc_req_ft_psk_sha384`, `assoc_req_psk_sha256`, `assoc_req_psk_sha384`, `assoc_req_sae`, `assoc_req_owe`, `assoc_req_fils`, `assoc_req_pasn`, `assoc_req_enterprise_sha1`, `assoc_req_enterprise_sha256`, `assoc_req_enterprise_sha384`, `assoc_req_tdls`, `assoc_req_appeerkey`, `assoc_req_akm_unknown` | §9.3.3.6, §9.4.2.24 Table 9-190 | Which AKM suites clients negotiated; tells the operator whether a capture even contains crackable PSK/FT-PSK material. | informational |
| ASSOCIATION RESPONSE (total) | `assoc_resp_frames` | §9.3.3.7 | AP-side association acceptance count. | informational |
| REASSOCIATION REQUEST (total) + per-AKM | `reassoc_req_frames`, `reassoc_req_*` (same AKM set as `assoc_req_*`) | §9.3.3.8, Table 9-190 | Roaming clients; FT-PSK reassociations are the FT crack source. | informational |
| REASSOCIATION RESPONSE (total) | `reassoc_resp_frames` | §9.3.3.9 | AP-side reassociation acceptance count. | informational |
| AUTHENTICATION (total) + per-algorithm | `auth_frames`, `auth_open_system`, `auth_shared_key`, `auth_fbt`, `auth_sae`, `auth_fils`, `auth_network_eap`, `auth_pasn` | §9.4.1.1 Table 9-43 | Authentication algorithm mix; FBT/SAE/FILS presence shapes what hashes are possible. | informational |
| FT status 52 / 53 / 54 / 55 | `ft_status_r0kh_unreachable`, `ft_status_invalid_pmkid`, `ft_status_invalid_mde`, `ft_status_invalid_fte` | §9.4.1.9 Table 9-92 | Each promoted FT failure status explains a *missing* FT-PSK handshake: the AP refused the FT auth, so no M2/M3 followed. | diagnostic |
| DEAUTHENTICATION (total) | `deauth_frames` | §9.3.3.12 | Session teardown volume. | informational |
| MIC failure, reason 14 | `mic_failure_deauths` | §9.4.1.7 Table 9-90 | The canonical "this handshake will never pair cleanly" signal for a session. | diagnostic |
| DISASSOCIATION (total) | `disassoc_frames` | §9.3.3.11 | Session-end volume. | informational |
| ACTION (total) + children | `action_frames`, `action_nr_req_ssids`, `fils_discovery_ssids`, `action_ft_frames`, `action_mesh_peering`, `anqp_gas_frames`, `anqp_venue_name`, `anqp_domain_name`, `anqp_nai_realm`, `anqp_hs_operator_friendly_name`, `anqp_unknown_info_id` | §9.6, §9.4.5 | Action frames carry FT/Mesh PMKIDs, FILS Discovery / NR-request SSIDs, and ANQP plaintext (venue, domain, realm, operator name): all extraction surfaces. | informational |
| ANQP fragmented (dropped) | `anqp_fragmented_skipped` | §9.4.5 | A fragmented ANQP element; reassembly is not implemented, so its plaintext is lost. | **dropped** (element) |
| ACTION NO ACK / ATIM / MEASUREMENT PILOT / TIMING ADVERTISEMENT | `action_no_ack_frames`, `atim_frames`, `measurement_pilot_frames`, `timing_advert_frames` | Table 9-1 | Remaining management subtypes, counted for completeness. | informational |
| RESERVED subtype (7/15) | `mgmt_reserved_subtype` | Table 9-1 | Reserved management subtypes; counted so the subtype rows reconcile to `mgmt_frames` (identity 2). | diagnostic |

### ESSID and plaintext surfaces

Source: §9.4.2 (IEs), vendor specs (WPS, OWE, CCX, P2P), RFC 3748 (EAP identity). A regression that drops one of these is an `extraction_coverage.rs` failure.

| Line | Field(s) | Source | Why we care | Disposition |
|---|---|---|---|---|
| ESSID (unique APs seen) | `essid_count` | §9.4.2.2 | How many distinct APs have a known SSID (needed for PMK derivation). | skeleton |
| ESSID changes (per-AP maximum) | `essid_changes_max` | §9.4.2.2 | Largest per-AP SSID-variant count; a high value usually means RF-rotted duplicate beacons. | informational |
| hash lines dropped (no SSID resolved) / distinct APs affected | `essid_unresolved_emissions`, `essid_unresolved_aps` | FR-ESSID-3 | Hashes dropped at emit because the AP's SSID was never seen: uncrackable. Each AP also gets an `[essid_not_found_summary]` log line. | **dropped** |
| SSID List / Country / Mesh ID / WPS / Vendor AP / OWE / CCX1 / Time Zone / Multiple-BSSID / RNR BSSIDs / P2P | `ssid_list_entries`, `country_codes_extracted`, `mesh_ids_extracted`, `wps_probe_req_extracted`, `vendor_ap_names_extracted`, `owe_transition_ssids`, `ccx1_ap_names_extracted`, `time_zones_extracted`, `multiple_bssid_profiles`, `rnr_bssids_extracted`, `p2p_device_names_extracted` | §9.4.2.71/.9/.97/.170, WPS/OWE/CCX/P2P vendor specs | Plaintext surfaces feeding `-W` / `-E` / `-R`: wordlist material from IEs and vendor elements. | informational |
| Wordlist IE-scan runs inserted | `wordlist_scan_ie_runs` | n/a | Printable-ASCII runs swept from IE bodies for the `--wordlist-scan` delta output. | informational |
| EAP identities / usernames extracted | `identities_extracted`, `usernames_extracted` | RFC 3748 §5.1 | EAP identity / inner-method peer-identity strings; printed even when `-I`/`-U` are not configured. | informational |

### EAPOL store block

Source: IEEE 802.11-2024 §12.7 (4-way handshake, EAPOL-Key), §12.3.2 (preauth EtherType), §9.2.4.8.3 (Mesh Control); RFC 3748 §4.2 (EAP outcome).

| Line | Field(s) | Source | Why we care | Disposition |
|---|---|---|---|---|
| M1 / M2 / M3 / M4 messages + auth-len max | `eapol_m1`, `eapol_m2`, `eapol_m3`, `eapol_m4`, `m1_auth_len_max`, `m2_auth_len_max`, `m3_auth_len_max`, `m4_auth_len_max` | §12.7.6 Table 12-10 | The raw handshake-message inventory; the auth-len-max rows mirror hcxpcapngtool's `body / frame` widths. | skeleton |
| NULL / 0xFF / repeating-pattern nonce rejected (+ on-M4 split) | `null_nonce_rejected`, `null_nonce_rejected_on_m4`, `ff_nonce_rejected`, `ff_nonce_rejected_on_m4`, `repeat_nonce_rejected`, `repeat_nonce_rejected_on_m4` | §12.7.6.5 NOTE 9 | Garbage Key Nonce: an EAPOL line built from it cannot crack. The on-M4 split separates the spec-zero expected case from an abnormal nonce on M1/M2/M3. | **dropped** |
| NULL / 0xFF / repeating-pattern MIC rejected | `null_mic_rejected`, `ff_mic_rejected`, `repeat_mic_rejected` | §12.7.2 | Garbage Key MIC (M2/M3/M4); the line cannot crack. | **dropped** |
| NULL / 0xFF / repeating-pattern PMKID rejected | `null_pmkid_rejected`, `ff_pmkid_rejected`, `repeat_pmkid_rejected` | §12.7.1.3 | Garbage PMKID; not crackable material. | **dropped** |
| ESSID control bytes (informational; shipped unchanged) | `essid_control_bytes_warned` | §9.4.2.2 | SSID with a `0x00..=0x1F` byte; valid on the wire, shipped to hashcat unchanged: NOT a drop or a transformation. | informational |
| session time gap max | `eapol_time_gap_max_us` | §12.7.6 | Largest gap between paired messages; prints in ms, or us when sub-millisecond. | informational |
| ANonce M1/M3 mismatch sessions | `anonce_m1_m3_mismatch_sessions` | §12.7.6.4 | M1 and M3 ANonce differ (retransmit/PMK-cache/mid-capture start); both anchors are still emitted. | diagnostic |
| EAPOL classified by direction (Tier 1) + WDS tiers | `eapol_tier1_direction`, `eapol_tier1b_essid`, `eapol_tier2_ack_discovery`, `eapol_tier3_flag_fallback` | §9.3.2.1 Table 9-60 | How each EAPOL frame's (AP, STA) direction was resolved; the WDS tiers recover relay-frame handshakes. | recovered |
| direction/ACK mismatches (diagnostic; still paired) | `eapol_ack_mismatches` | §12.7.2 | MAC-header direction disagrees with the Key ACK bit; direction is authoritative, the pair is kept. | diagnostic |
| preauthentication frames (EtherType 0x88C7) | `eapol_preauth_frames` | §12.3.2 | Inter-AP preauth EAPOL, parsed on the same path as 0x888E. | informational |
| LLC accepted but EAPOL parse rejected (frame dropped) | `eapol_llc_invalid` | §12.7.2 | The LLC/packet-type gate said EAPOL-Key but the parser bailed (truncation, bad descriptor/KDV, sentinel nonce/MIC). | **dropped** |
| Mesh Data frames recovered (Mesh Control unwrapped) | `mesh_control_frames` | §9.2.4.8.3 | Mesh BSS data frame whose Mesh Control header was skipped to expose the inner MSDU. | recovered |
| Mesh Data dropped (bad Mesh Control header) | `mesh_control_malformed` | §9.2.4.8.3 | Mesh Control header with a reserved Address Extension Mode (11) or a too-short body; the inner MSDU is unrecoverable. | **dropped** |
| EAP-Success / EAP-Failure frames | `eap_success_frames`, `eap_failure_frames` | RFC 3748 §4.2 | Terminal EAP outcomes; capture-quality triage for mixed PSK/Enterprise traffic. | informational |

### PMKID sources (S1-S20)

Source: IEEE 802.11-2024 §12.7.1.3 (PMKID), §12.7.2 (M1/M2 KDE), §9.6.7 (FT Action), Wi-Fi Passpoint (OSEN). `pmkids_found` is the insertion total (post-garbage, post-insert-dedup, pre-global-dedup); the children split it by extraction site and by AKM family.

| Line | Field(s) | Source | Why we care | Disposition |
|---|---|---|---|---|
| PMKID store insertions (total, pre-dedup) | `pmkids_found` | §12.7.1.3 | The PMKID material inventory before global dedup. | skeleton |
| per-source S1-S20 | `pmkid_m1`, `pmkid_m2`, `pmkid_assoc_req`, `pmkid_reassoc_req`, `pmkid_ft_auth`, `pmkid_fils_auth`, `pmkid_pasn_auth`, `pmkid_ft_action`, `pmkid_probe_req`, `pmkid_beacon`, `pmkid_probe_resp`, `pmkid_mesh`, `pmkid_osen` | §12.7.2, §9.6.7, OSEN | Which of the 20 spec-defined locations each PMKID came from: the "never miss a PMKID" coverage map. | informational |
| by AKM family (non-FT / FT) | `pmkid_wpa2_psk`, `pmkid_ft_psk` | §12.7.1.3 | Same total split by AKM family (non-FT = PSK/SHA256/SHA384; FT = FT-PSK/FT-PSK-SHA384). | informational |

---

## Phase 4: Emit

Pairing, classification, dedup, and the per-sink output rows. Source: ARCHITECTURE.md §2 (11-type table), §5 (combos), §7 (line format), §8 (FR-PAIR / FR-OUT).

| Line | Field(s) | Source | Why we care | Disposition |
|---|---|---|---|---|
| output filters active | `filters_active` | FR-CLI-3 | Echoes the resolved filter state so a WIDE run and a `--strict` run are distinguishable from the banner alone. | informational |
| per-hash-type found / written (11 rows) | `hash_type_found`, `hash_type_emitted` | §2 | One row per 11-type code. **found** is the sink-independent inventory of what the capture contains; **written** is what reached a configured output file. They differ when a type has no configured accepting sink (e.g. the SHA-384 family with only `--22000-out` shows `14 / 0`). | skeleton |
| EAPOL pairs generated (total, pre-dedup) | `eapol_pairs_generated` | §5 | Pairs the engine produced before global dedup (identity 3). | skeleton |
| EAPOL pairs written (post-dedup) | `eapol_pairs_useful` | §5 | Pairs that survived dedup; the combo children sum to this. | skeleton |
| per-combo written (N1E2 / N3E2 / N1E4 / N2E3 / N4E3 / N3E4) | `pairs_written_n1e2`, `pairs_written_n3e2`, `pairs_written_n1e4`, `pairs_written_n2e3`, `pairs_written_n4e3`, `pairs_written_n3e4` | §5 | Which N#E# combos produced output (AP-less N2E3/N4E3 included). | informational |
| NC / LE / BE flag set | `pairs_nc`, `pairs_le`, `pairs_be` | hcxtools mp byte | Hints passed to hashcat's nonce-error-corrections / endianness handling. | informational |
| NC-dedup lines collapsed / cluster count / max cluster | `nc_dedup_collapsed_lines`, `nc_dedup_cluster_count`, `nc_dedup_max_cluster_size` | §5.8.1 | `--nc-dedup` folded near-identical-nonce siblings into one survivor. | informational (lines folded, not lost) |
| candidates dropped (--eapoltimeout filter) | `pairs_time_filtered` | FR-PAIR-3 | Opt-in session-window filter removed these candidate pairs (zero in WIDE mode). | **dropped** (filter) |
| candidates dropped (--rc-drift filter) | `pairs_rc_filtered` | FR-PAIR-4 | Opt-in replay-counter filter removed these candidate pairs (zero in WIDE mode). | **dropped** (filter) |
| messages dropped (--max-eapol-per-type cap) | `eapol_messages_capped` | FR-CLI | Opt-in pairing cap excluded these messages from fan-out (zero when off; store still keeps all). | **dropped** (cap) |
| RC gap max | `rc_gap_max`, `rc_drift_enabled` | §5.7 | Largest RC gap among written pairs; suggests an NC threshold. | informational |
| PMKIDs written (post-dedup) | `pmkids_written` | §6 | PMKID hashes that survived dedup at least once. | skeleton |
| dedup dropped (total) + EAPOL/PMKID children | `dedup_dropped`, `dedup_dropped_pairs`, `dedup_dropped_pmkids` | FR-DEDUP | Duplicate hash lines suppressed by global SipHash dedup, split by kind so the pre-dedup totals reconcile. | **dropped** (duplicates) |
| hashes dropped (unclassified AKM; no 11-type) | `emit_dropped_unclassified_akm` | §2 | Extracted crack material whose AKM maps to none of the 11 types, even after AKM-map inference, and is not a recognised non-PSK suite; cannot be formatted. | **dropped** |
| hashes dropped (non-PSK AKM; out of scope) | `emit_dropped_notpsk_akm` | §2.3 | A handshake / PMKID whose AKM is a recognised non-PSK suite (`AkmType::NotPsk`: enterprise 802.1X / FT-802.1X / SAE / OWE / FILS / PASN). The PMK is not `PBKDF2(PSK)`, so no crackable mode 22000 / 37100 line exists. | **dropped** |
| hashes dropped (FT context missing; no R0KH-ID) | `emit_dropped_ft_no_context` | §7 | An FT hash (types 6/7/10/11) with no R0KH-ID, so the `WPA*03*`/`WPA*04*` line cannot be built. | **dropped** |
| per hash sink (path + lines written + dedup dropped) | `path_*` family, `lines_*` family, `dropped_*` family | §2, §7 | Each configured hash sink's file, lines written, and per-sink dedup drops. Unconfigured sinks collapse to a count. | informational / **dropped** (per-sink dedup) |
| hash sinks not configured | (derived) | n/a | How many of the 9 hash sinks were not requested. | informational |
| per aux sink (path + entries written) | `essid_list_path`+`entries_essid_list`, `probe_list_path`+`entries_probe_list`, `wordlist_path`+`entries_wordlist`, `wordlist_scan_path`+`entries_wordlist_scan`, `identity_list_path`+`entries_identity_list`, `username_list_path`+`entries_username_list`, `device_info_path`+`entries_device_info` | FR-CLI-2 | Each configured auxiliary sink's file and entry count (parity with the hash sinks' line counts). | informational |
| auxiliary sinks not configured | (derived) | n/a | How many of the 7 auxiliary sinks were not requested. | informational |

---

## Phase 5: Report

Executive summary an operator reads in five seconds.

| Line | Field(s) | Source | Why we care | Disposition |
|---|---|---|---|---|
| hashes emitted (total) + EAPOL/PMKID split | `hash_type_emitted` (summed) | §2 | The headline yield written to files, split by attack surface (identity 4). | skeleton |
| distinct hash types observed | `hash_type_found` (nonzero count) | §2 | How many of the 11 types the capture contains: the inventory, independent of which sinks were configured. | skeleton |
| hash types found but not written (add -o to capture) | `hash_type_found` vs `hash_type_emitted` | §2 | Types present in the capture that reached no output file; configure `-o` or the per-AKM sink to write them. | **dropped** (operator config) |
| wallclock Phase 1-3 / Phase 4 / total | `wallclock_p13_ms`, `wallclock_p4_ms` | n/a | Where the time went (streaming pass vs pairing+emit). | informational |
| throughput (MiB/s) | `bytes_ingested`, `wallclock_p13_ms` | n/a | Ingest rate against the FR-PERF-1 target. | informational |
| peak RSS (MiB) | `peak_rss_mib` | n/a | High-water memory (lower bound, sampled at the pressure-check cadence). | informational |
| disk-backed fallback engaged | `disk_mode_engaged` | invariant 2 | "yes" means RSS hit the threshold and the run degraded to disk speed instead of aborting. | informational |
| hint (no hashes) | (derived from the largest drop counter) | n/a | On a zero-hash run, names the single largest drop so the operator knows where to look first. | diagnostic |

---

## Fields not tied to a single banner line

These back the banner indirectly (mirrors, scratch, per-sink arrays) and are listed here so the contract names every field:

- **Per-sink arrays** (rendered by the sink loops above; the `audit-stats` gate exempts these prefixes since they are documented per family, not per member): `lines_22000`/`lines_37100`/`lines_combined`/`lines_wpa1`/`lines_wpa2`/`lines_psk_sha256`/`lines_ft`/`lines_psk_sha384`/`lines_ft_psk_sha384` (`lines_*`); the matching `dropped_*` set; the matching `path_*` set; and the full `reassoc_req_*` per-AKM set (mirror of `assoc_req_*`).
- **Composite field:** `fragment_stats`, the `Stats` field of type `FragmentStats` whose members (`fragments_seen` etc.) are documented in the Phase 2 table above.
- **Scratch / derived state, not printed directly:** `eapol_last_seen`, the per-(AP,STA) timestamp map used to compute `eapol_time_gap_max_us`.

## hcxpcapngtool parity and exclusions

wpawolf's banner is a content-superset of every **PSK-relevant** row hcxpcapngtool prints, with three structural differences (by design):

1. hcxpcapngtool prints one summary per input file and resets between files; wpawolf prints one aggregate banner per run (collect-then-pair spans the whole input set).
2. hcxpcapngtool appends `Warning:` / `Information:` advice paragraphs; wpawolf adopts only the single-line zero-hash `hint`.
3. hcxpcapngtool's malformed-packet sub-breakdown (BEACON/broadcast-MAC/IE-tag/ESSID errors) lives in wpawolf's aggregated `--log` categories, not banner rows; the banner keeps the single `malformed_mac_hdr` count.

**Rows hcxpcapngtool prints that wpawolf intentionally excludes:** `skipped packets` and every `(use --all)` variant (wpawolf processes everything); zeroed-PSK / zeroed-PMK / ROGUE rows (superseded by the garbage-pattern gate); hccap / hccapx / JtR sink rows (legacy formats out of scope); EAP-MD5/LEAP/MSCHAPv2 pair rows, PPP-CHAP/PAP, TACACS+, RADIUS (v2: planned, not implemented); the NMEA/GPS block (v2); pwnagotchi / hcxhash2cap beacon fingerprints; FILS-PFS/PK/EPPKE auth sub-variants (folded into `auth_fils` / `auth_pasn`); `RESERVED MANAGEMENT frame` advisory wording; the `--max-essids` advisory; per-message `oversized` rows (no size gate exists to overflow); IP / transport / cipher-suite / RSN-capabilities histograms (no PSK relevance; PMF presence is observable via `mgmt_protected_frames`).

The Phase 8 superset test (`tests/integration/superset_test.rs`) enforces output-line parity at every release; `make audit-stats` enforces this catalogue against `src/stats.rs`.
