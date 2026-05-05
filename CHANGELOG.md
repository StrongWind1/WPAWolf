# Changelog

This file is a current-state summary of `wpawolf` rather than a per-release diary. For per-commit detail, see `git log`. For wire-level behaviour, see [`ARCHITECTURE.md`](ARCHITECTURE.md). The "Releases" section below captures notable per-version boundaries; the rest of the file describes what the current release supports. For semantic-version intent the project follows [SemVer](https://semver.org/spec/v2.0.0.html); the project is on the `v0.3.x` line and has not yet declared a `1.0` API.

## Releases

### v0.3.3 -- unreleased

Operator-facing improvements driven by corpus-scale testing feedback (May 2026). No change to the hashcat-line output format; existing 22000 / 37100 / taxonomy lines are byte-identical.

- **Periodic progress reporting (default ON, opt-out via `--quiet`).** Phase 1 ingest now emits `[progress] elapsed=Ns files=N packets=N eapol=N pmkids=N rss=NMiB` to stderr every 5 seconds OR every 2 000 000 packets, whichever fires first. RSS is read from `/proc/self/statm` on Linux and omitted on other platforms. The closing Phase 1-5 stats banner is unaffected. Greppable line prefix `[progress]` so operators can filter via `grep -v '^\[progress\]'`.
- **`--quiet` flag.** Suppresses the progress lines; closing banner still prints. Intended for scripted / piped contexts.
- **`--per-file` flush mode.** Pair + emit hashes after each input file, then clear the per-file `MessageStore` / `PmkidStore`. Hash sinks, dedup state, auxiliary outputs (`-E`/`-W`/...), `EssidMap`, `AkmMap`, and `MldStore` accumulate across the run. Trades cross-file pairing for bounded memory; expected hash-yield drop < 1% on per-session corpora. See README "Output filters".
- **`--mem-stats` flag.** Prints a per-store byte-count table after the closing banner: `MessageStore`, `PmkidStore`, `EssidMap`, `AkmMap`, `MldStore`, every auxiliary set, plus the IE-scan store. Sorted descending; useful for triaging OOM behaviour at corpus scale. Approximations only: `HashMap` overhead estimated as `capacity * (entry_size + 8 B)`.
- **`--wordlist-scan-ies FILE` is now a standalone output.** The flag changed from `bool` to `Option<PathBuf>`. Printable-ASCII runs from plaintext management-frame IE bodies go **only** to FILE; they no longer flow into `-W`. Restores `-W` to its named purpose (ESSIDs + WPS + EAP + country + vendor names) and gives the IE-scan strand its own surface for triage. Operators who want both streams in one place can run with `-W` and `--wordlist-scan-ies` configured separately.
- **`< 4 byte` stub-file noise silenced.** Some submission-staging workflows leave 0/1/2/3-byte stub files alongside real captures. The directory walk's magic-byte filter already handled these, but a TOCTOU race or an explicitly-named non-capture argument could still reach `open_reader`. Such files now route through a new `[skipped_input]` `--log` category and a `files_skipped_unknown_format` Phase 1 counter; stderr stays clean. Genuine I/O failures still surface via `eprintln!`.
- **`--essid-fanout-threshold` / `--essid-dominance-ratio` docs.** CLI help rewritten to one-sentence leads (~6 lines each). New README "Multi-SSID inflation" section with a 4-row worked example (dual-band, 3-SSID rollout, RF-rotted, CTF AP). New `ARCHITECTURE.md §9.3` paragraph explaining the RF-rot pattern that motivated the defaults. Defaults unchanged (3 / 10).
- **README restructured for plain-language clarity.** Section ordering tightened, jargon ("sinks", "taxonomy", "fanout", "inflation") swept out of prose, the upstream comparison reframed from "loses handshakes in eight ways" to a neutral wide-default vs narrow-default policy difference grounded in `hcxpcapngtool`'s actual constants (5 s `EAPOLTIMEOUT`, 255 B `EAPOL_AUTHLEN_OLD_MAX`, 20-entry sliding-window dedup, WDS off without `--all`). New "Proposed hashcat format changes" section pulled in from `HASHCAT-NEW-FORMATS.md` and `HASHCAT-PROPOSED-CHANGES.md`; the "unified mode 22001" reference (factually incorrect) corrected to modes 22002 / 22003. Authorized-use notice moved to the bottom. Repository layout relocated to `CONTRIBUTING.md`. New "Progress reporting" section documents the `[progress]` line format and the `--quiet` escape hatch. README dropped from 583 to ~340 lines; no behaviour change.
- **`--eapoltimeout` / `--rc-drift` bare-flag clap gotcha documented.** Both flags accept an optional value (`Option<Option<u64/u8>>` via clap's `num_args = 0..=1`). The bare form (no `=N`) makes clap greedily consume the trailing positional, so `wpawolf --eapoltimeout capture.pcap` exits 2 with `invalid value 'capture.pcap'`. CLI help text for both flags now spells out the failure mode and the two workarounds: `--eapoltimeout=` with explicit `=`, or another `--`-prefixed flag in between. README "Output filters" footnote covers the same.
- **`collapse()` is now O(n) at corpus scale (T-13).** The Phase 4 N#E# combo collapse step in `src/pair/collapse.rs` was a nested-Vec scan, O(n^2) per (AP, STA) group. Group sizes scale with corpus size (not handshake size), so a single noisy AP-STA pair could carry thousands of EAPOL messages and balloon `collapse()` into multi-second territory. Replaced with `HashMap<([u8; 32], Arc<[u8]>), usize>` keyed on (nonce, EAPOL frame); `Arc<[u8]>` defers `Hash` to byte-content and `PartialEq` short-circuits via `Arc::ptr_eq` for shared frame allocations. Insertion order preserved via index into a side `Vec<PairedHash>`, so emit order is unchanged. Verified byte-equivalent to the prior implementation under sort across `/root/ALL_CAPS/collected_with_location/` (390 MB, 28 files) for both WIDE and `--dedup-hash-combos` runs. Wall-clock on the full 5.4 GB corpus: WIDE 30 s, `--dedup-hash-combos` 27 s -- vs the prior 5+ minute timeout for `--dedup-hash-combos`. The §5.8 / FR-PAIR-5 spec (equivalence iff nonce bytes equal AND EAPOL frame bytes equal; survivor by smallest RC gap then authorized-priority tiebreak) is preserved exactly. New regression tests `collapse_preserves_first_seen_insertion_order` and `collapse_is_linear_at_thousand_pair_scale` lock the contract.
- **`DeviceInfoStore` row-level dedup (T-15).** The `--device-output` (`-D`) store was a plain `Vec<DeviceInfoEntry>` with no dedup; one Beacon every 100 ms produced thousands of byte-identical rows per AP. Corpus run on `/root/ALL_CAPS` showed `DeviceInfoStore` at 372 MiB / 1.49 M entries, the dominant memory grower at corpus scale, while the `-D` output rendered 452 K lines that collapsed to 2,979 unique under `sort -u` (99.3 % duplicates). Replaced the backing `Vec` with `HashSet<DeviceInfoEntry>` and derived `Hash` / `PartialEq` / `Eq` over the full output-relevant field set. An all-empty-primary-fields skip on insert mirrors the existing all-empty guard in `write_device_info` so the store stops retaining observations the writer would never emit. Two distinct WPS observations for the same AP (e.g. a sparse Beacon and a rich Probe Response) have non-equal dedup keys and both survive as distinct lines, sidestepping the prior over-dedup failure mode that collapsed rich rows into sparse ones when keyed on `MAC` or `(MAC, UUID-E)`. `DeviceInfoStore` RSS drops from 372 MiB to 736 KiB (~500x). Operators no longer need to post-process `-D` with `sort -u`.
- **New `model_number` column in `-D` output (T-15.1).** WPS attribute 0x1024 ("Model Number") was already parsed into `WpsInfo` and `DeviceInfoEntry` but was only routed to `-W` (the wordlist) -- the `-D` writer mirrored hcxpcapngtool's column set, which omits 0x1024 entirely (hcxtools only reads `WPS_MODELNAME = 0x1023`, no `WPS_MODELNUMBER` constant exists in their headers). Inserted `model_number` between `model_name` and `serial_number` in the `-D` output line and added it to the `DeviceInfoStore` dedup key + the all-empty-fields skip guard. Verified against `/root/ALL_CAPS`: post-fix output with the new column stripped is byte-identical to pre-fix `sort -u`'d output (sha256 `d1bf82c04da47a1c700f776a0e3f06a7`); 75 % of rows carry a populated model number; 3 additional rows surface where pre-fix dedup (with model_number excluded) was incorrectly collapsing observations that actually differed in model number.
- **Three more spec-driven `-D` columns (T-15.2): `os_version`, `primary_device_type`, `secondary_device_type_list`.** Audited the WSC §12 attribute table against `ref/wireshark/epan/dissectors/packet-wps.c` for any device-identity attribute that hcxpcapngtool drops. Three came out spec-defined and parser-clean: WPS attribute `0x102D` (OS Version, 4 B big-endian uint32), `0x1054` (Primary Device Type, 8 B `category | OUI | sub-category`), and `0x1055` (Secondary Device Type List, list of 8 B device-types up to 128 B). hcxpcapngtool defines none of these in `ref/hcxtools/include/ieee80211.h`. Vendor Extension (`0x1049`) was audit-excluded: its WFA sub-elements (Version2, AuthorizedMACs, NetworkKeyShareable, RequestToEnroll, SettingsDelayTime, MultiAP*) are all binary/numeric/MAC-list per `dissect_wps_wfa_ext` in wireshark -- there is no string payload to render in a `-D` column. New columns use raw lowercase hex (no `$HEX[]` wrapper) since they are spec-defined binary fields; absent values render as empty cells with their leading tab still emitted (UUID-E remains conditional for back-compat). The all-empty-fields skip guard and dedup key both now include the three new fields. Verified against `/root/ALL_CAPS`: 86 % of rows carry a populated `primary_device_type` (consistent with WPS-equipped consumer APs); `os_version` and `secondary_device_type_list` are spec-permitted-but-rare in management-frame WPS bodies on this corpus (they appear primarily in the M1 EAP-WPS active-enrollment exchange, which wpawolf does not currently parse for WPS attribute extraction).
- **Final `-D` column order:** `mac \t mfr \t model_name \t model_number \t serial \t device_name \t os_version \t primary_device_type \t secondary_device_type_list [\t uuid_e] \t essid`. **Format change:** downstream tooling that parses `-D` by tab count needs to update from hcxpcapngtool's 6/7 columns to wpawolf's 10/11.
- 764 tests (up from 735); `make check-all` passes clean.

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

NULL and 0xFF nonces, MICs, and PMKIDs are rejected unconditionally (except the spec-valid M1 NULL MIC and M4 NULL nonce per [IEEE 802.11-2024] §12.7.6.5).

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
