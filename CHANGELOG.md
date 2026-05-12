# Changelog

This file is a current-state summary of `wpawolf` rather than a per-release diary. For per-commit detail, see `git log`. For wire-level behaviour, see [`ARCHITECTURE.md`](ARCHITECTURE.md). The "Releases" section below captures notable per-version boundaries; the rest of the file describes what the current release supports. For semantic-version intent the project follows [SemVer](https://semver.org/spec/v2.0.0.html); the project is on the `v0.3.x` line and has not yet declared a `1.0` API.

## Releases

### v0.3.5 -- 2026-05-12

Two parity-with-hcxpcapngtool fixes driven by a single wpa-sec sample (Vladimir's iPhone) that produced a real PMK miss, plus one piece of dead-code hygiene that the parity work made obsolete. No change to the hashcat-line output format; existing 22000 / 37100 / taxonomy lines are byte-identical to v0.3.4 for any handshake that previously produced output. The two extract-path fixes both reduce the WIDE-mode default line count by removing emissions that were either blocking real handshakes or emitting cryptographically dead lines.

- **Mesh Control Present bit gated on 4-address frames.** `src/ieee80211/frame.rs` previously read bit B8 of QoS Control as "Mesh Control Present" on every QoS Data frame, including 3-address infrastructure uplinks. Per [IEEE 802.11-2024] §9.2.4.5.7, the Mesh Control Present subfield is defined for QoS Data frames "transmitted between mesh STAs" only -- mesh BSS data frames use 4-address format per §9.3.2.1. In 3-address infrastructure uplinks the same bit position holds Queue Size LSB (Tables 9-7 / 9-8). The earlier code stripped a phantom 6-byte Mesh Control header from any infrastructure EAPOL frame whose Queue Size happened to be odd, butchering the EAPOL body and dropping the M2 / M4 of the handshake. Observed in the field on a "Vladimir's iPhone" wpa-sec sample where 5x M2 + 5x M4 all carried QoS Control = `0x0b10` (Queue Size = 11) and produced 0 EAPOL pairs against hcxpcapngtool's 1. Fix: gate the B8 read on `four_addr` (ToDS=1 AND FromDS=1). Two new parser unit tests lock both directions (`qos_3addr_b8_set_is_not_mesh`, `qos_4addr_b8_set_is_mesh`); the existing `mesh_control_skip_recovers_eapol_handshake` integration test was rebuilt to use 4-address mesh fixtures (it previously relied on the bug).
- **M4 NULL-nonce dropped at extract.** v0.3.4 accepted M4 frames with all-zero Key Nonce as a "spec exception" per [IEEE 802.11-2024] §12.7.6.5 NOTE 9, but an EAPOL hash line built from such an M4 is mathematically uncrackable: the live PTK was derived from M2's `SNonce`, which the M4 frame does not carry, so combining the M4 NULL with M3's ANonce in N3E4 / N4E3 / N1E4 lines yields the input pair `(NULL, M3_ANonce)` that does not reproduce the live PTK. The garbage-pattern detector at `src/ieee80211/eapol.rs` no longer carves out the M4-null case; M4 NULL nonce is now rejected like any other garbage pattern, the rejection is logged via `[invalid_nonce] kind=null` for forensic traceability, and the `null_nonce_rejected` counter bumps. Matches hcxpcapngtool's `eapolm4zeroedcount++; return;` gate at `hcxpcapngtool.c:3636`. The other half of NOTE 9 (non-conforming firmware that copies M2's `SNonce` into M4) still passes the gate -- those frames carry a non-NULL nonce and produce a crackable line. On the Vladimir's iPhone sample the WIDE-mode emission drops from 4 hash lines to 2; both surviving lines crack to the same PMK as hcxpcapngtool's single line.
- **Removed the unused `nonce_is_valid` helper in `src/pair/constraints.rs`.** The function dated to a pre-v0.3.5 plan to enforce nonce validity at the pairing stage and cited a stale `(FR-PAIR-5)` doc reference (FR-PAIR-5 in the current spec covers `--dedup-hash-combos` collapse, not nonce validity). The M4 NULL-nonce drop above moved nonce-validity enforcement to parse time via `garbage_pattern_kind` in `src/ieee80211/eapol.rs`, which is strictly broader (covers `null` / `ff` / `repeat_1` / `repeat_2` / `repeat_4`, not just zero) and runs on every message type. Zero nonces never reach the pairing engine, so the helper had no production call site -- every reference was inside its own `#[cfg(test)]` block. Deleted the function, its three unit tests (`nonce_is_valid_nonzero` / `nonce_is_valid_all_zeros` / `nonce_is_valid_all_ones`), and updated the module doc-comment to point at FR-PAIR-7 / `garbage_pattern_kind` as the actual enforcement site.
- `make check-all` passes clean.

### v0.3.4 -- 2026-05-05

Follow-up to v0.3.3 that walks back the ESSID half of the new garbage-pattern rejection, adds forensic hex output to every discard log line, and lands a new README section that enumerates the discard paths. No change to hashcat-line output format; existing 22000 / 37100 / taxonomy lines are byte-identical to v0.3.3 except that v0.3.3-rejected ESSIDs now flow through and emit hashes again.

- **ESSID handling reverted from rejection to warning.** v0.3.3 applied the same garbage-pattern detector to SSIDs as to nonces / MICs / PMKIDs and dropped matching SSIDs at extract time. That was the wrong call: a repeating-byte or all-`0xFF` SSID is unusual but not invariant of "garbage" the way it is for HMAC outputs, and the cracker may still recover the right PMK from such an SSID. v0.3.4 keeps the spec-driven discard rule untouched (length 0 wildcard, length > 32 spec violation, first byte 0 hidden-network sentinel; mirrors hcxtools `fileops.c:72-86`) and adds a non-fatal warning for SSIDs that pass that gate but contain at least one byte in `0x00..=0x1F` (the full ASCII C0 control range, NUL through US -- every control character). The warning emits a `[essid_control_bytes]` log line carrying the SSID rendered in lowercase hex (`essid_hex=`) and bumps `essid_control_bytes_warned`. The SSID itself is stored and emitted unchanged. The v0.3.3 counter `garbage_essid_rejected` and the `[invalid_essid]` log category are removed; `essid_control_bytes_warned` and `[essid_control_bytes]` are the new operator-facing surface for SSID anomalies. Hash yield on captures with control-byte SSIDs is restored to the v0.3.2 baseline.
- **Hex output for discarded values.** The `[invalid_nonce]` / `[invalid_mic]` / `[invalid_pmkid]` log categories now end every line with `nonce_hex=` / `mic_hex=` / `pmkid_hex=` rendering the rejected bytes in lowercase hex (32 B nonce, 16 or 24 B MIC per AKM, 16 B PMKID). Operators triaging a noisy capture can grep the log for the exact byte sequence and locate the source frame without re-running the parser; per-`kind` filtering still works alongside (`grep 'kind=repeat_1' run.log`). `InvalidCheck` (in `src/ieee80211/eapol.rs`) carries the bytes alongside the kind string so `data.rs` and `wds.rs` forward them into the logger; the eight PMKID extract sites pass the 16-byte slice directly. `Logger::log_invalid_{nonce,mic,pmkid}` signatures gain a final `&[u8]` argument; a private `render_lower_hex` helper backs both the new fields and the existing `essid_hex=` render. Five new log unit tests lock the line layout.
- **New README section: "Why a hash gets discarded".** Enumerates every reason the current code drops a candidate PMKID or EAPOL hash before it reaches an output file: Key Nonce garbage pattern (NULL on M1/M2/M3, all-`0xFF` on any, or `repeat_1` / `repeat_2` / `repeat_4` -- M4 NULL nonce is spec-valid and is **not** discarded); Key MIC garbage pattern on M2/M3/M4 (M1 has no MIC); PMKID garbage pattern at any of the 20 spec-defined extraction sites; missing ESSID at output time. Includes a "things that are not rejected" list (WDS / 4-address relay frames, EAPOL > 255 B, cross-file pairing, legacy WPA1 vendor IE handshakes, control-byte SSIDs) so operators have a single page that explains both surprise-low and surprise-high yield. Sits between "When one AP shows up under many SSIDs" and "Stats output". `ARCHITECTURE.md §4 invariant 7` and `§9 stats catalogue` updated to match.
- **Repository hygiene sweep.** Every developer-side absolute path under `/root/` (typical local corpus directories) is now scrubbed from tracked artefacts: `CHANGELOG.md`, `ARCHITECTURE.md`, three source comments. Triage notes belong in gitignored `tools/` or `docs/` scratch space; corpus-driven results land in tracked artefacts described generically ("a multi-vendor capture corpus", "390 MB / 28 files"). Same rule applies going forward to operator hostnames, lab IPs, and internal AP MACs.
- **Release artefacts SSH-signed.** v0.3.3 and the original v0.3.4 push went out with `commit.gpgsign=false` set ad-hoc, so GitHub showed both as `Unverified`. v0.3.4 was re-cut with the configured SSH signing key (`user.signingkey = /root/github_ssh/github.pub`, `gpg.format = ssh`); the published commit and tag both verify cleanly on GitHub and locally via `git tag --verify v0.3.4`.
- 796 tests (up from 765 in v0.3.3); `make check-all` passes clean.

### v0.3.3 -- 2026-05-05

Operator-facing improvements driven by corpus-scale testing feedback (May 2026). No change to the hashcat-line output format; existing 22000 / 37100 / taxonomy lines are byte-identical.

- **Garbage-pattern validation on nonces, MICs, PMKIDs, and (initially) ESSIDs.** Field-level rejection at extract time now catches three new shape categories on top of the previous all-NULL / all-`0xFF` pair: `repeat_1` (every byte is the same value, e.g. all-`0x55` / all-`0xAB`), `repeat_2` (2-byte alternating period like `5555AAAA` or `01020304...`), and `repeat_4` (4-byte period). Real wire bytes from a healthy stack are HMAC outputs / random nonces -- any of these patterns is a firmware stub or test fixture, not crackable material. Applied at every site that feeds the cryptographic hash pipeline: the EAPOL parser (Key Nonce on M1/M2/M3, plus Key MIC on M2/M3/M4 when the Key MIC flag is set) and every PMKID-bearing IE (M1 KDE, M2 RSN IE, AssocReq / ReassocReq, FT / FILS / PASN Auth, FT Action, Probe Request, Beacon, ProbeResp, Mesh Peering, OSEN). New stats counters (`null_*_rejected` / `ff_*_rejected` / `repeat_*_rejected`) surface in the closing banner; the existing `[invalid_nonce]` / `[invalid_mic]` / `[invalid_pmkid]` `--log` categories now carry the kind string. Driven by a downstream-cracker report ("produces a lot of invalid MESSAGE PAIRS and PMKIDs") -- the previous all-NULL / all-`0xFF` rejection caught the obvious cases but left the subtle firmware-stub patterns slipping through. v0.3.3 also applied the same detector to ESSIDs and dropped matches at extract time (counter `garbage_essid_rejected`, `[invalid_essid]` log category). **That ESSID rejection was reverted in v0.3.4** -- repeating-byte SSIDs are not an invariant of "garbage" the way they are for cryptographic fields, and the cracker may still recover the right PMK from such an SSID. v0.3.4 callers should expect ESSIDs that v0.3.3 dropped to flow through and emit hashes again; the v0.3.3 ESSID-rejection counter and log category are removed.

- **Periodic progress reporting (default ON, opt-out via `--quiet`).** Phase 1 ingest now emits `[progress] elapsed=Ns files=N packets=N eapol=N pmkids=N rss=NMiB` to stderr every 5 seconds OR every 2 000 000 packets, whichever fires first. RSS is read from `/proc/self/statm` on Linux and omitted on other platforms. The closing Phase 1-5 stats banner is unaffected. Greppable line prefix `[progress]` so operators can filter via `grep -v '^\[progress\]'`.
- **`--quiet` flag.** Suppresses the progress lines; closing banner still prints. Intended for scripted / piped contexts.
- **`--per-file` flush mode.** Pair + emit hashes after each input file, then clear the per-file `MessageStore` / `PmkidStore`. Hash sinks, dedup state, auxiliary outputs (`-E`/`-W`/...), `EssidMap`, `AkmMap`, and `MldStore` accumulate across the run. Trades cross-file pairing for bounded memory; expected hash-yield drop < 1% on per-session corpora. See README "Output filters".
- **`--mem-stats` flag.** Prints a per-store byte-count table after the closing banner: `MessageStore`, `PmkidStore`, `EssidMap`, `AkmMap`, `MldStore`, every auxiliary set, plus the IE-scan store. Sorted descending; useful for triaging OOM behaviour at corpus scale. Approximations only: `HashMap` overhead estimated as `capacity * (entry_size + 8 B)`.
- **`--wordlist-scan-ies FILE` is now a standalone output.** The flag changed from `bool` to `Option<PathBuf>`. Printable-ASCII runs from plaintext management-frame IE bodies go **only** to FILE; they no longer flow into `-W`. Restores `-W` to its named purpose (ESSIDs + WPS + EAP + country + vendor names) and gives the IE-scan strand its own surface for triage. Operators who want both streams in one place can run with `-W` and `--wordlist-scan-ies` configured separately.
- **`< 4 byte` stub-file noise silenced.** Some submission-staging workflows leave 0/1/2/3-byte stub files alongside real captures. The directory walk's magic-byte filter already handled these, but a TOCTOU race or an explicitly-named non-capture argument could still reach `open_reader`. Such files now route through a new `[skipped_input]` `--log` category and a `files_skipped_unknown_format` Phase 1 counter; stderr stays clean. Genuine I/O failures still surface via `eprintln!`.
- **`--essid-collapse-min` / `--essid-collapse-ratio` (renamed from `--essid-fanout-threshold` / `--essid-dominance-ratio`).** Plain-English flag names replace the old jargon-laden ones; flag *behaviour* and *defaults* are unchanged (3 / 10). CLI help rewritten to one-sentence leads (~6 lines each). New README "When one AP shows up under many SSIDs" section with a 4-row worked example (dual-band, 3-SSID rollout, RF-rotted, CTF AP). New `ARCHITECTURE.md §9.3` paragraph explaining the RF-rot pattern that motivated the defaults. **Breaking:** scripts using the old flag names need a one-shot find-replace.
- **README restructured for plain-language clarity.** Section ordering tightened, jargon ("sinks", "taxonomy", "fanout", "inflation") swept out of prose, the upstream comparison reframed from "loses handshakes in eight ways" to a neutral wide-default vs narrow-default policy difference grounded in `hcxpcapngtool`'s actual constants (5 s `EAPOLTIMEOUT`, 255 B `EAPOL_AUTHLEN_OLD_MAX`, 20-entry sliding-window dedup, WDS off without `--all`). New "Proposed hashcat format changes" section pulled in from `HASHCAT-NEW-FORMATS.md` and `HASHCAT-PROPOSED-CHANGES.md`; the "unified mode 22001" reference (factually incorrect) corrected to modes 22002 / 22003. Authorized-use notice moved to the bottom. Repository layout relocated to `CONTRIBUTING.md`. New "Progress reporting" section documents the `[progress]` line format and the `--quiet` escape hatch. README dropped from 583 to ~340 lines; no behaviour change.
- **`--eapoltimeout` / `--rc-drift` bare-flag clap gotcha documented.** Both flags accept an optional value (`Option<Option<u64/u8>>` via clap's `num_args = 0..=1`). The bare form (no `=N`) makes clap greedily consume the trailing positional, so `wpawolf --eapoltimeout capture.pcap` exits 2 with `invalid value 'capture.pcap'`. CLI help text for both flags now spells out the failure mode and the two workarounds: `--eapoltimeout=` with explicit `=`, or another `--`-prefixed flag in between. README "Output filters" footnote covers the same.
- **`collapse()` is now O(n) at corpus scale (T-13).** The Phase 4 N#E# combo collapse step in `src/pair/collapse.rs` was a nested-Vec scan, O(n^2) per (AP, STA) group. Group sizes scale with corpus size (not handshake size), so a single noisy AP-STA pair could carry thousands of EAPOL messages and balloon `collapse()` into multi-second territory. Replaced with `HashMap<([u8; 32], Arc<[u8]>), usize>` keyed on (nonce, EAPOL frame); `Arc<[u8]>` defers `Hash` to byte-content and `PartialEq` short-circuits via `Arc::ptr_eq` for shared frame allocations. Insertion order preserved via index into a side `Vec<PairedHash>`, so emit order is unchanged. Verified byte-equivalent to the prior implementation under sort across a multi-vendor capture corpus for both WIDE and `--dedup-hash-combos` runs. Multi-second wall-clock under `--dedup-hash-combos` at multi-GB scale (was a 5+ minute timeout) -- the WIDE path was always linear and is unchanged. The §5.8 / FR-PAIR-5 spec (equivalence iff nonce bytes equal AND EAPOL frame bytes equal; survivor by smallest RC gap then authorized-priority tiebreak) is preserved exactly. New regression tests `collapse_preserves_first_seen_insertion_order` and `collapse_is_linear_at_thousand_pair_scale` lock the contract.
- **`DeviceInfoStore` row-level dedup (T-15).** The `--device-output` (`-D`) store was a plain `Vec<DeviceInfoEntry>` with no dedup; one Beacon every 100 ms produced thousands of byte-identical rows per AP. Corpus testing showed the `DeviceInfoStore` was the dominant memory grower (~99 % duplicate entries) and the `-D` output collapsed to a tiny fraction of its line count under `sort -u`. Replaced the backing `Vec` with `HashSet<DeviceInfoEntry>` and derived `Hash` / `PartialEq` / `Eq` over the full output-relevant field set. An all-empty-primary-fields skip on insert mirrors the existing all-empty guard in `write_device_info` so the store stops retaining observations the writer would never emit. Two distinct WPS observations for the same AP (e.g. a sparse Beacon and a rich Probe Response) have non-equal dedup keys and both survive as distinct lines, sidestepping the prior over-dedup failure mode that collapsed rich rows into sparse ones when keyed on `MAC` or `(MAC, UUID-E)`. `DeviceInfoStore` RSS drops by roughly 500x at corpus scale. Operators no longer need to post-process `-D` with `sort -u`.
- **New `model_number` column in `-D` output (T-15.1).** WPS attribute 0x1024 ("Model Number") was already parsed into `WpsInfo` and `DeviceInfoEntry` but was only routed to `-W` (the wordlist) -- the `-D` writer mirrored hcxpcapngtool's column set, which omits 0x1024 entirely (hcxtools only reads `WPS_MODELNAME = 0x1023`, no `WPS_MODELNUMBER` constant exists in their headers). Inserted `model_number` between `model_name` and `serial_number` in the `-D` output line and added it to the `DeviceInfoStore` dedup key + the all-empty-fields skip guard. Verified against a multi-vendor capture corpus: post-fix output with the new column stripped is byte-identical to pre-fix `sort -u`'d output; the majority of rows carry a populated model number, and a small number of additional rows surface where pre-fix dedup (with model_number excluded) was incorrectly collapsing observations that actually differed in model number.
- **Three more spec-driven `-D` columns (T-15.2): `os_version`, `primary_device_type`, `secondary_device_type_list`.** Audited the WSC §12 attribute table against `ref/wireshark/epan/dissectors/packet-wps.c` for any device-identity attribute that hcxpcapngtool drops. Three came out spec-defined and parser-clean: WPS attribute `0x102D` (OS Version, 4 B big-endian uint32), `0x1054` (Primary Device Type, 8 B `category | OUI | sub-category`), and `0x1055` (Secondary Device Type List, list of 8 B device-types up to 128 B). hcxpcapngtool defines none of these in `ref/hcxtools/include/ieee80211.h`. Vendor Extension (`0x1049`) was audit-excluded: its WFA sub-elements (Version2, AuthorizedMACs, NetworkKeyShareable, RequestToEnroll, SettingsDelayTime, MultiAP*) are all binary/numeric/MAC-list per `dissect_wps_wfa_ext` in wireshark -- there is no string payload to render in a `-D` column. New columns use raw lowercase hex (no `$HEX[]` wrapper) since they are spec-defined binary fields; absent values render as empty cells with their leading tab still emitted (UUID-E remains conditional for back-compat). The all-empty-fields skip guard and dedup key both now include the three new fields. Most consumer-AP rows carry a populated `primary_device_type`; `os_version` and `secondary_device_type_list` are spec-permitted-but-rare in management-frame WPS bodies (they appear primarily in the M1 EAP-WPS active-enrollment exchange, which wpawolf does not currently parse for WPS attribute extraction).
- **Fixed 11-column `-D` layout (T-15.3).** UUID-E was the last conditional field in the `-D` writer (no tab when absent). Every row now emits exactly 11 tab-separated columns regardless of which optional attributes the WPS body carried; absent values render as empty cells with their leading tab still present. Operators can `awk -F'\t' '{print $N}'` or `cut -f10` without conditional-column logic. Final column order: `mac \t mfr \t model_name \t model_number \t serial \t device_name \t os_version \t primary_device_type \t secondary_device_type_list \t uuid_e \t essid`. **Format change:** downstream tooling that parsed the prior `-D` by tab count needs to assume a fixed 11 columns; tooling that parsed hcxpcapngtool's `-D` (6 or 7 columns depending on UUID-E) needs the same 11-column update.
- 765 tests (up from 735); `make check-all` passes clean.

### v0.3.2 -- 2026-05-01

**Test-harness and CI reliability fix. No code or output-format changes.** Hash-line output is byte-identical to v0.3.1 for every capture; v0.3.2 upgraders do not need to re-process anything.

- Parity test (`tests/integration/superset_test.rs`) now pins the minimum supported oracle at `hcxpcapngtool >= 7.0.1`, parses the `--version` banner, and refuses to run against stale oracles (Ubuntu/Debian package 6.2.x, RHEL stream, Kali older releases). Pre-7.0.1 emits a different `WPA*01*` / `WPA*02*` trailer format and is not a valid parity reference.
- Missing or stale oracle is now a hard panic when `CI=true` is set in the environment, replacing the prior soft-skip path that silently no-op'd the gate. Locally the test still soft-skips with a clear message so contributors without hcxtools installed can still run the rest of the suite.
- CI (`.github/workflows/ci.yml`) builds `hcxpcapngtool` from a pinned upstream tag (`HCXTOOLS_TAG = 7.1.2`) before running `cargo test`, so the parity check actually executes on every PR for the first time.
- New `make check-parity` Makefile target mirrors the CI hard-fail behaviour locally.
- New `tools/audit_citations.sh` walks every `[hcxpcapngtool:NNNN]` citation in `src/` and `ARCHITECTURE.md` and asserts the cited region is in-bounds in `ref/hcxtools/hcxpcapngtool.c`. Skips cleanly when `ref/` is absent (gitignored, developer-side only). Wired into `make check-all`.
- README rewritten to the centered-HTML style used by the rest of the family (CredWolf, KerbWolf, Kerberos, WiFi_Cracking). "Authorized use only" moved from the top of the file to just above the License section.
- `CHANGELOG.md`, `CONTRIBUTING.md`, and the bug-report template now document the `>= 7.0.1` oracle requirement and the build-from-source recipe.

### v0.3.1 -- 2026-04-30

Stop seeding MAC addresses into the `-W` wordlist sink. Pre-v0.3.1 runs included AP/STA MACs alongside legitimate ESSID / EAP / WPS strings, which polluted the wordlist with non-credential material.

### v0.3.0 -- 2026-04-28

`-W` wordlist sink salvages WPS / FT / EAP leaked text; `--22000-out` / `--37100-out` apply hashcat-compatible ESSID filter at `EssidMap` admission; `-o` collapses multi-ESSID inflation at hash emit time; CHANGELOG / README rebuilt.

## What wpawolf is

A pure-Rust WPA/WPA2/WPA3-FT-PSK handshake extractor for hashcat. Reads pcap, pcapng, and gzip-compressed captures; emits hashcat mode 22000 (WPA-PSK / PMKID) and mode 37100 (FT-PSK) hash lines plus auxiliary wordlists, EAP identities, and WPS device info. Authorised use only -- wpawolf does not capture, inject, or crack.

## Pipeline (ARCHITECTURE.md §3)

Five explicit phases, each owned by a discrete module:

| Phase | Module | Role |
|---|---|---|
| 1 Ingest  | `src/input/`      | pcap / pcapng / gzip readers |
| 2 Decode  | `src/link/` + `src/ieee80211/` | radiotap/PPI/Prism/AVS strip; 802.11 frame, IE, RSN, EAPOL, EAP, FT parsing |
| 3 Extract | `src/extract/` + `src/store/` | per-subtype handlers populate AP / STA / EAPOL / PMKID / ESSID / aux stores |
| 4 Emit    | `src/pair/` + `src/output/`   | N#E# pairing, hashcat 22000/37100 line formatting, dedup, wordlists |
| 5 Report  | `src/stats.rs`   | operator-facing summary printed unconditionally on stderr |

Each `src/**/*.rs` carries a `//! Phase N -- ...` doc-comment naming its phase and the relevant ARCHITECTURE.md section.

## Hash-output coverage (ARCHITECTURE.md §2)

The 11-type taxonomy classifies every PSK-crackable hash by a unique type code 1-11. Current emission status:

| # | Name                    | AKM | hashcat mode | wpawolf emits |
|---|-------------------------|-----|--------------|---------------|
|  1 | WPA1-PSK-EAPOL          | vendor IE `00:50:F2:01` | 22000 | yes |
|  2 | WPA2-PSK-PMKID          | 2   | 22000 | yes |
|  3 | WPA2-PSK-EAPOL          | 2   | 22000 | yes |
|  4 | PSK-SHA256-PMKID        | 6   | 22000 | yes |
|  5 | PSK-SHA256-EAPOL        | 6   | 22000 | yes |
|  6 | FT-PSK-PMKID            | 4   | 37100 | yes |
|  7 | FT-PSK-EAPOL            | 4   | 37100 | yes |
|  8 | PSK-SHA384-PMKID        | 20  | --    | classified, not routed |
|  9 | PSK-SHA384-EAPOL        | 20  | --    | classified, not routed |
| 10 | FT-PSK-SHA384-PMKID     | 19  | --    | classified, not routed |
| 11 | FT-PSK-SHA384-EAPOL     | 19  | --    | classified, not routed |

The SHA-384 family (types 8/9/10/11) is detected and counted in stats but not yet written to a hashcat-compatible sink because its 24-byte MIC widens the hash-line MIC field beyond what hashcat modes 22000 / 37100 accept. Lines are routed through `--psk-sha384-out` and `--ft-psk-sha384-out` in the new 11-type prefix scheme; cracking awaits an upstream kernel update (see [`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md)).

## Input

- pcap (all six magic variants including Kuznetzov-patched 24-byte per-packet headers), IXIA `lcap` hardware-capture and software-capture variants (4 magics, per wireshark `wiretap/libpcap.c`), pcapng (multi-SHB, multi-IDB, `if_tsresol`, `if_tsoffset`), gzip-wrapped variants of any of the above
- DLT 105 (raw 802.11), 127 (radiotap), 192 (PPI), 119 (Prism, including AVS-within-Prism detection), 163 (AVS, big-endian per spec)
- Streaming reader; never buffers more than one block
- I/O errors abort; parse errors log-and-continue
- Positional arguments may be files or directories. Directories are walked recursively and every regular file whose first 4 bytes match a supported capture-file magic (pcap microsecond / nanosecond / Kuznetzov in either byte order, pcapng SHB, or gzip) is added to the input set in deterministic (sorted) order. File extensions are not consulted. Symlinks are not followed.

## PMKID extraction (ARCHITECTURE.md §6)

Every spec-defined PMKID location S1-S20 is extracted: M1 Key Data KDE, M2 RSN IE, Association / Reassociation Request RSN IE, FT Authentication (S5/S6), FILS Authentication (S7/S8), PASN Authentication (S9/S10), FT Action frames (S11-S13), Probe Request (S14/S15), Beacon / ProbeResponse vendor deviation (S16/S17), Mesh Peering AMPE Chosen-PMK (S18/S19), OSEN/Hotspot-2.0 IE (S20).

NULL and 0xFF nonces, MICs, and PMKIDs are rejected unconditionally on every message type, including M4. M1 NULL MIC is spec-valid and not flagged. M4 NULL nonce is spec-valid on the wire per [IEEE 802.11-2024] §12.7.6.5 NOTE 9 but the resulting hash line is mathematically uncrackable (the live PTK depends on M2's `SNonce`, which the M4 frame does not carry); rejected at extract from v0.3.5 onward, matching hcxpcapngtool. See `ARCHITECTURE.md §5.10`.

## CLI flags

Hash sinks. Every sink is optional; absent flag = file not written. The same logical hash fans out to every configured sink with the appropriate per-sink prefix and per-sink dedup. The legacy sinks (`--22000-out`, `--37100-out`) keep the four-prefix scheme `WPA*01*..*04*` and remain drop-in for hashcat. The taxonomy sinks (`--wpa1-out`, `--wpa2-out`, ..., and the combined `-o`) emit the new 11-type prefix scheme `WPA*01*..*11*` from `ARCHITECTURE.md §2`.

| Flag | Purpose |
|---|---|
| `--22000-out` | legacy hashcat mode 22000 (every non-FT hash, `WPA*01*`/`WPA*02*`) |
| `--37100-out` | legacy hashcat mode 37100 (every FT hash, `WPA*03*`/`WPA*04*`) |
| `-o` / `--out` | combined 11-type taxonomy file (every emitted hash) |
| `--wpa1-out` | type 1 (taxonomy `WPA*01*`) |
| `--wpa2-out` | types 2 + 3 (taxonomy `WPA*02*`/`WPA*03*`) |
| `--psk-sha256-out` | types 4 + 5 (taxonomy `WPA*04*`/`WPA*05*`) |
| `--ft-out` | types 6 + 7 (taxonomy `WPA*06*`/`WPA*07*`, FT extras) |
| `--psk-sha384-out` | types 8 + 9 (taxonomy `WPA*08*`/`WPA*09*`) |
| `--ft-psk-sha384-out` | types 10 + 11 (taxonomy `WPA*10*`/`WPA*11*`, FT extras) |

Auxiliary outputs and runtime knobs.

| Flag | Purpose |
|---|---|
| `-E` | unique ESSIDs from AP management frames |
| `-R` | unique ESSIDs from Probe Requests |
| `-W` | combined wordlist (ESSIDs + WPS + EAP + country + vendor names) |
| `-I` | EAP identities |
| `-U` | EAP usernames |
| `-D` | WPS device info |
| `--log` | structured malformed-frame / skipped-packet log |
| `--eapoltimeout [N]` | output filter: session window in seconds (omit = unlimited) |
| `--rc-drift [N]`     | output filter: replay-counter drift tolerance (default 8) |
| `--dedup-hash-combos` | output filter: collapse 6 N#E# combos to 3 unique per session |
| `--threads N`         | pairing thread count (default = CPU count) |
| `--wordlist-scan-ies` | opportunistic printable-ASCII run scan from IE bodies into `-W` |

The defaults emit all 6 N#E# combos per session and apply no time or replay-counter filtering -- maximum hash yield. Output filter flags narrow that further. The closing stats summary on stderr is unconditional; there is no `--stats` toggle.

## Stats output (ARCHITECTURE.md §9)

Five banner sections in pipeline order:

```
=== Phase 1 -- Ingest ===   file metadata, packet count, link errors
=== Phase 2 -- Decode ===   mgmt/data/control split, per-band, KDV mix
=== Phase 3 -- Extract ===  per-subtype mgmt counters, per-AKM assoc/reassoc
                            breakdown, ESSID/PMKID/EAPOL discovery,
                            NULL/0xFF rejects, identities/usernames/devices
=== Phase 4 -- Emit ===     per-hash-type 11-row breakdown, pair-combo
                            counts, NC/LE/BE flags, dedup drops, output paths
=== Phase 5 -- Report ===   total hashes, distinct hash types observed
```

The per-hash-type breakdown leads Phase 4 and prints one row per `HashType` variant with the canonical 11-type name verbatim (`WPA2-PSK-EAPOL`, `FT-PSK-PMKID`, etc.).

## Parity oracle

`tests/integration/superset_test.rs` validates the "no hash is silently dropped" claim by running `hcxpcapngtool` as a reference and asserting `wpawolf_output >= oracle_output` line-for-line.

**Minimum oracle version: `hcxpcapngtool >= 7.0.1`.** The wire trailer of `WPA*01*` (PMKID) and `WPA*02*` (EAPOL) lines changed three times across the 6.3.x / 7.0.x boundary: the PMKID status byte was added in 6.3.1, default `ST_NC` initialisation was added in 6.3.2, and the canonical EAPOL-frame selection swapped from the M3 frame to the M2 frame in 7.0.1. wpawolf's output matches the post-7.0.1 convention. Comparing against an older oracle is not meaningful and produces noisy false-positive mismatches.

The parity test parses the oracle banner, refuses stale versions, and hard-fails when `CI=true` is set so a missing install step in CI cannot silently no-op the gate. Locally, `make check-parity` reproduces the same hard-fail behaviour. Distro packages are too old; build hcxtools from the upstream tag (`HCXTOOLS_TAG` pinned in `.github/workflows/ci.yml`).

## Quality bar

- 735 tests (unit + binary + integration, including a superset oracle asserting `wpawolf_output >= hcxpcapngtool_output` on every fixture with `hcxpcapngtool >= 7.0.1`, a cross-file pairing oracle confirming the shared `MessageStore` reassembles handshakes split across pcap files, and the `generated_corpus` oracle that runs wpawolf against every fixture produced by the in-tree `wpawolf-fixturegen` workspace member)
- Sibling workspace crate `tools/fixturegen` emits a deterministic pcap/pcapng corpus covering all 11 hash types, the 20 PMKID extraction sites, the 6 N#E# combos, and the link-layer / container variants. Crypto primitives anchored to KAT vectors
- Strict clippy: `pedantic`, `nursery`, `cargo` enabled; `-D warnings`
- `#![forbid(unsafe_code)]` at crate root
- `cargo deny` gates the supply chain (OSI-approved permissive licences only)
- `make check-all` runs `fmt`, `clippy`, `audit`, `test`, `doc -D warnings`, ASCII / LF hygiene, `cargo machete`. Required green before any commit
- An external multi-GB regression dataset (out-of-tree) is exercised opportunistically before each release; it confirms content-level superset of hcxpcapngtool on real-world traffic that is too noisy or legally-encumbered to commit

## Performance

- Single-threaded throughput target: ~200 MB/s on a 250 MiB pcap
- Phase 4 (pairing) parallelised via `std::thread::scope` with LPT round-robin group scheduling; `--threads=1` reproduces the serial path
- `Arc<[u8]>` for `eapol_frame` storage avoids clone overhead on cross-combo reuse
- Inline fingerprint dedup in `generate()` drops 50-90 % of retransmission duplicates at generation time
- `HashSet<u64>` SipHash-1-3 fingerprints for global dedup -- no look-back window

## Architectural invariants (ARCHITECTURE.md §4)

- No `unsafe`. Pure-safe Rust; binary parsing via `TryInto` and bounds checks
- Collect-then-pair: every EAPOL message for an `(AP, STA)` pair is held before pairing runs. No ring buffer, no eviction
- No EAPOL size gate -- every valid frame is emitted regardless of length
- Relay (4-address WDS) frames are first-class; never filtered
- Global SipHash dedup over the significant hash fields
- Every wire constant cites its IEEE 802.11-2024 / RFC / hcxtools source

## Out of scope

- Capture / injection (file-only tool)
- Hash cracking (feed output to hashcat)
- Inner-EAP hash extraction (EAP-MD5 / LEAP / MSCHAPv2 -- v2)
- Legacy hashcat formats (hccap, hccapx, mode 2500)
- WEP, pure SAE, OWE hash-line emission (parsed and counted, not emitted)
- FCS validation
- Memory-usage estimation in stats (use `/usr/bin/time -v`)

## Trajectory

The 5-phase runtime pipeline, all nine implementation milestones (input parsers, link-layer strip, 802.11 frame parsing, stores, pairing engine, output, CLI, superset tests, stats), per-pair AKM resolution that correctly routes FT-PSK to mode 37100 even when the AP advertises PSK first, all 20 PMKID locations (S1-S20), tiered EAPOL direction classification for WDS relay frames, parallel Phase 4 pairing, hcxpcapngtool stats parity (per-AKM assoc/reassoc, per-band, beacon channel histogram, malformed MAC header counter), router-endianness detection (LE/BE bits in the message_pair byte), the canonical 11-type hash taxonomy, and the consolidation of the design / requirements / hash-types documents into a single canonical [`ARCHITECTURE.md`](ARCHITECTURE.md) have all landed on `v0.3.x`.

Notable recent work, summarised here for upgraders; full per-release detail is in the *Releases* section above.

- **Operator-experience pass (v0.3.0)** driven by a regression run against an out-of-tree dataset: multi-file Phase 1 banner (file-format / endian / network-type histograms across the whole input set), unresolved-SSID hashes are now dropped rather than silently emitted as uncrackable lines (with an `[essid_not_found_summary]` log entry per affected AP), lazy hash-sink files (configured-but-empty sinks no longer leave 0-byte files on disk), and a stat-line clarity pass that suffixes every issue counter with `(frame dropped)`, `(recovered)`, or `(diagnostic; ...)` so operators can tell loss from recovery at a glance. The biggest semantic relabel: `Mesh Data frames with Mesh Control header skipped` -> `Mesh Data frames recovered (Mesh Control header unwrapped)`.
- **Nine-sink CLI surface** that surfaces the 11-type taxonomy at the file level: `--22000-out` / `--37100-out` are line-format-identical hashcat drop-ins, the new `-o` is the combined taxonomy file (every emitted hash, prefix `WPA*<type-code>*`), and per-AKM sinks (`--wpa1-out`, `--wpa2-out`, `--psk-sha256-out`, `--ft-out`, `--psk-sha384-out`, `--ft-psk-sha384-out`) each route a single AKM family. The Phase 4 banner gains one row per sink with file path + lines written + dedup dropped.

Wire-level correctness improvements that landed alongside the nine-sink surface:

- **KDV-first AKM reconciliation** in `store_eapol_key`. The wire-level Key Descriptor Version (KDV bits B0-B2 of EAPOL Key Information per [IEEE 802.11-2024] §12.7.3) is consulted *before* the AKM map: KDV=1 forces `Wpa1`, KDV=2 collapses non-FT to `Wpa2Psk`, KDV=3 collapses non-FT to `PskSha256`. The FT family (`FtPsk` / `FtPskSha384`) is preserved across KDV=2/3 because FT can legitimately use either MIC. Mixed-mode beacons (RSN + WPA1 vendor IE; PSK + PSK-SHA256 advertised simultaneously) regularly produce an AKM map that disagrees with the actual wire bytes, so KDV is the only signal we can stake the type prefix on -- legacy mode 22000 auto-detected via the keyver byte but the new prefix-trusting modules silently fail on a mislabelled line.
- **PMKID-AKM decoupling** for vendor M1 quirks. Inteno / D-Link / TP-Link / ASUS firmware regularly emits an M1 with KDV=1 (HMAC-MD5 MIC) AND a PMKID KDE in Key Data: a wire-level inconsistency where the descriptor type is RSN (0x02) but the MIC algorithm is the legacy WPA1 one. The PMKID itself is still computed with the AKM-defined PRF (HMAC-SHA1 for AKM 2), so it remains crackable. wpawolf promotes the PMKID's `AkmType` from `Wpa1` to `Wpa2Psk` while keeping the EAPOL classification as `Wpa1`. Without this, `from_akm_and_attack(Wpa1, is_pmkid=true) -> None` would silently drop the PMKID at output.
- **A-MSDU subframe iteration** (`src/ieee80211/amsdu.rs`). 802.11n aggregated MSDUs are dispatched dual-path: the outer body is always parsed as a single MSDU (catches glitched A-MSDU bits on what is actually a complete single-MPDU EAPOL frame), then the A-MSDU bit (QoS Control byte 0 bit 7) drives a subframe walk that surfaces EAPOL hidden in subframes 2..N.
- **FCS detection and tail-strip**. `src/link/radiotap.rs::has_fcs` reads radiotap Flags bit 4 (`0x10` = `IEEE80211_RADIOTAP_F_FCS`) and `src/link/mod.rs::strip` returns `(payload, had_fcs)` so the trailing 4-byte FCS is chopped before IE walking, preventing tag/length mis-parse on captures whose radio appended an FCS.
- **MSDU fragment reassembly** (`src/store/fragments.rs`). Per-(SA, RA, SeqNum) buffer of non-final fragments; `take_completed` returns the concatenated MSDU body when the final fragment arrives. Most EAPOL fits in one MPDU but FT-PSK M2 with extended IEs occasionally fragments. Stats: `fragment_stats.{seen, reassembled, dropped_disorder, dropped_overflow}`.
- **Cross-file pairing test** (`tests/integration/cross_file_pairing.rs`). Splits a real-world capture at its midpoint into two files, runs wpawolf on the directory, asserts the output set matches the single-file baseline. Regression oracle for the shared-`MessageStore` invariant that lets handshakes survive `tcpdump`-rolled capture boundaries.

Documentation split into a six-doc layout:

- [`README.md`](README.md) -- project intro plus the operator-facing CLI surface (every output sink, examples, stats banner, hashcat drop-in workflow).
- [`ARCHITECTURE.md`](ARCHITECTURE.md) -- the why: pipeline shape, invariants, EAPOL pairing, PMKID extraction, output fan-out / dedup design, FR-* contracts, stats catalogue.
- [`CHANGELOG.md`](CHANGELOG.md) (this file) -- per-release summary of what shipped, what changed, and what was removed.
- [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md) -- every WPA-PSK hash format current hashcat understands today (modes 22000 + 37100), the four legacy prefixes, the `keyver` byte trick, message-pair byte (EAPOL + PMKID), per-row mapping of the 11 wpawolf types onto current hashcat, support matrix, limitations.
- [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) -- why the 11-type taxonomy exists and how each row works: encoding rules, per-type cracker math (PBKDF2 -> PMKID / PTK / MIC), hash-line layout (16 B vs 24 B MIC, FT extras), N#E# vs M#E# notation, complete message-pair byte specification.
- [`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md) -- sketch of a unified `mode 22001` consuming all 11 types: parsed-line struct widening, loader dispatch, per-kernel work items, migration path.

Known follow-ups: dedicated hashcat 24 B MIC kernel for the SHA-384 family (types 8-11) -- the lines are emitted today on the relevant taxonomy sinks but cannot be cracked without an upstream kernel update.
