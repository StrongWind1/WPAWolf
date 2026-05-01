# Changelog

This file is a current-state summary of `wpawolf` rather than a per-release
diary. For per-commit detail, see `git log`. For wire-level behaviour, see
[`ARCHITECTURE.md`](ARCHITECTURE.md). The "Releases" section below captures
notable per-version boundaries; the rest of the file describes what the
current release supports. For semantic-version intent the project follows
[SemVer](https://semver.org/spec/v2.0.0.html); v1.x is the current line.

## Releases

### v0.3.2 -- 2026-05-01

**Test-harness and CI reliability fix. No code or output-format changes.**
Hash-line output is byte-identical to v0.3.1 for every capture; v0.3.2
upgraders do not need to re-process anything.

- Parity test (`tests/integration/superset_test.rs`) now pins the
  minimum supported oracle at `hcxpcapngtool >= 7.0.1`, parses the
  `--version` banner, and refuses to run against stale oracles
  (Ubuntu/Debian package 6.2.x, RHEL stream, Kali older releases).
  Pre-7.0.1 emits a different `WPA*01*` / `WPA*02*` trailer format
  and is not a valid parity reference.
- Missing or stale oracle is now a hard panic when `CI=true` is set
  in the environment, replacing the prior soft-skip path that
  silently no-op'd the gate. Locally the test still soft-skips with
  a clear message so contributors without hcxtools installed can
  still run the rest of the suite.
- CI (`.github/workflows/ci.yml`) builds `hcxpcapngtool` from a
  pinned upstream tag (`HCXTOOLS_TAG = 7.1.2`) before running
  `cargo test`, so the parity check actually executes on every PR
  for the first time.
- New `make check-parity` Makefile target mirrors the CI hard-fail
  behaviour locally.
- New `tools/audit_citations.sh` walks every `[hcxpcapngtool:NNNN]`
  citation in `src/` and `ARCHITECTURE.md` and asserts the cited
  region is in-bounds in `ref/hcxtools/hcxpcapngtool.c`. Skips
  cleanly when `ref/` is absent (gitignored, developer-side only).
  Wired into `make check-all`.
- README rewritten to the centered-HTML style used by the rest of
  the family (CredWolf, KerbWolf, Kerberos, WiFi_Cracking).
  "Authorized use only" moved from the top of the file to just
  above the License section.
- `CHANGELOG.md`, `CONTRIBUTING.md`, and the bug-report template
  now document the `>= 7.0.1` oracle requirement and the
  build-from-source recipe.

### v0.3.1 -- 2026-04-30

Stop seeding MAC addresses into the `-W` wordlist sink. Pre-v0.3.1
runs included AP/STA MACs alongside legitimate ESSID / EAP / WPS
strings, which polluted the wordlist with non-credential material.

### v0.3.0 -- 2026-04-28

`-W` wordlist sink salvages WPS / FT / EAP leaked text;
`--22000-out` / `--37100-out` apply hashcat-compatible ESSID filter
at `EssidMap` admission; `-o` collapses multi-ESSID inflation at
hash emit time; CHANGELOG / README rebuilt.

## What wpawolf is

A pure-Rust WPA/WPA2/WPA3-FT-PSK handshake extractor for hashcat. Reads
pcap, pcapng, and gzip-compressed captures; emits hashcat mode 22000
(WPA-PSK / PMKID) and mode 37100 (FT-PSK) hash lines plus auxiliary
wordlists, EAP identities, and WPS device info. Authorised use only --
wpawolf does not capture, inject, or crack.

## Pipeline (ARCHITECTURE.md §3)

Five explicit phases, each owned by a discrete module:

| Phase | Module | Role |
|---|---|---|
| 1 Ingest  | `src/input/`      | pcap / pcapng / gzip readers |
| 2 Decode  | `src/link/` + `src/ieee80211/` | radiotap/PPI/Prism/AVS strip; 802.11 frame, IE, RSN, EAPOL, EAP, FT parsing |
| 3 Extract | `src/extract/` + `src/store/` | per-subtype handlers populate AP / STA / EAPOL / PMKID / ESSID / aux stores |
| 4 Emit    | `src/pair/` + `src/output/`   | N#E# pairing, hashcat 22000/37100 line formatting, dedup, wordlists |
| 5 Report  | `src/stats.rs`   | operator-facing summary printed unconditionally on stderr |

Each `src/**/*.rs` carries a `//! Phase N -- ...` doc-comment naming its
phase and the relevant ARCHITECTURE.md section.

## Hash-output coverage (ARCHITECTURE.md §2)

The 11-type taxonomy classifies every PSK-crackable hash by a unique type
code 1-11. Current emission status:

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

The SHA-384 family (types 8/9/10/11) is detected and counted in stats but
not yet written to a hashcat-compatible sink because its 24-byte MIC widens
the hash-line MIC field beyond what hashcat modes 22000 / 37100 accept.
Lines are routed through `--psk-sha384-out` and `--ft-psk-sha384-out` in the
new 11-type prefix scheme; cracking awaits an upstream kernel update (see
[`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md)).

## Input

- pcap (all six magic variants including Kuznetzov-patched 24-byte
  per-packet headers), IXIA `lcap` hardware-capture and
  software-capture variants (4 magics, per wireshark
  `wiretap/libpcap.c`), pcapng (multi-SHB, multi-IDB, `if_tsresol`,
  `if_tsoffset`), gzip-wrapped variants of any of the above
- DLT 105 (raw 802.11), 127 (radiotap), 192 (PPI), 119 (Prism, including
  AVS-within-Prism detection), 163 (AVS, big-endian per spec)
- Streaming reader; never buffers more than one block
- I/O errors abort; parse errors log-and-continue
- Positional arguments may be files or directories. Directories are
  walked recursively and every regular file whose first 4 bytes match
  a supported capture-file magic (pcap microsecond / nanosecond /
  Kuznetzov in either byte order, pcapng SHB, or gzip) is added to
  the input set in deterministic (sorted) order. File extensions are
  not consulted. Symlinks are not followed.

## PMKID extraction (ARCHITECTURE.md §6)

Every spec-defined PMKID location S1-S20 is extracted: M1 Key Data KDE,
M2 RSN IE, Association / Reassociation Request RSN IE, FT Authentication
(S5/S6), FILS Authentication (S7/S8), PASN Authentication (S9/S10),
FT Action frames (S11-S13), Probe Request (S14/S15),
Beacon / ProbeResponse vendor deviation (S16/S17),
Mesh Peering AMPE Chosen-PMK (S18/S19), OSEN/Hotspot-2.0 IE (S20).

NULL and 0xFF nonces, MICs, and PMKIDs are rejected unconditionally
(except the spec-valid M1 NULL MIC and M4 NULL nonce per
[IEEE 802.11-2024] §12.7.6.5).

## CLI flags

Hash sinks. Every sink is optional; absent flag = file not written. The same
logical hash fans out to every configured sink with the appropriate per-sink
prefix and per-sink dedup. The legacy sinks (`--22000-out`, `--37100-out`)
keep the four-prefix scheme `WPA*01*..*04*` and remain drop-in for hashcat.
The taxonomy sinks (`--wpa1-out`, `--wpa2-out`, ..., and the combined `-o`)
emit the new 11-type prefix scheme `WPA*01*..*11*` from `ARCHITECTURE.md §2`.

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

The defaults emit all 6 N#E# combos per session and apply no time or
replay-counter filtering -- maximum hash yield. Output filter flags narrow
that further. The closing stats summary on stderr is unconditional; there
is no `--stats` toggle.

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

The per-hash-type breakdown leads Phase 4 and prints one row per
`HashType` variant with the canonical 11-type name verbatim
(`WPA2-PSK-EAPOL`, `FT-PSK-PMKID`, etc.).

## Parity oracle

`tests/integration/superset_test.rs` validates the "no hash is silently
dropped" claim by running `hcxpcapngtool` as a reference and asserting
`wpawolf_output >= oracle_output` line-for-line.

**Minimum oracle version: `hcxpcapngtool >= 7.0.1`.** The wire trailer
of `WPA*01*` (PMKID) and `WPA*02*` (EAPOL) lines changed three times
across the 6.3.x / 7.0.x boundary: the PMKID status byte was added in
6.3.1, default `ST_NC` initialisation was added in 6.3.2, and the
canonical EAPOL-frame selection swapped from the M3 frame to the M2
frame in 7.0.1. wpawolf's output matches the post-7.0.1 convention.
Comparing against an older oracle is not meaningful and produces noisy
false-positive mismatches.

The parity test parses the oracle banner, refuses stale versions, and
hard-fails when `CI=true` is set so a missing install step in CI cannot
silently no-op the gate. Locally, `make check-parity` reproduces the
same hard-fail behaviour. Distro packages are too old; build hcxtools
from the upstream tag (`HCXTOOLS_TAG` pinned in `.github/workflows/ci.yml`).

## Quality bar

- 712 tests (unit + binary + integration, including a superset oracle
  asserting `wpawolf_output >= hcxpcapngtool_output` on every fixture
  with `hcxpcapngtool >= 7.0.1`,
  a cross-file pairing oracle confirming the shared `MessageStore`
  reassembles handshakes split across pcap files, and the
  `generated_corpus` oracle that runs wpawolf against every fixture
  produced by the in-tree `wpawolf-fixturegen` workspace member)
- Sibling workspace crate `tools/fixturegen` emits a deterministic
  pcap/pcapng corpus covering all 11 hash types, the 20 PMKID extraction
  sites, the 6 N#E# combos, and the link-layer / container variants.
  Crypto primitives anchored to KAT vectors
- Strict clippy: `pedantic`, `nursery`, `cargo` enabled; `-D warnings`
- `#![forbid(unsafe_code)]` at crate root
- `cargo deny` gates the supply chain (OSI-approved permissive licences only)
- `make check-all` runs `fmt`, `clippy`, `audit`, `test`, `doc -D warnings`,
  ASCII / LF hygiene, `cargo machete`. Required green before any commit
- A 1,788-capture regression corpus confirms content-level superset of
  hcxpcapngtool

## Performance

- Single-threaded throughput target: ~200 MB/s on a 250 MiB pcap
- Phase 4 (pairing) parallelised via `std::thread::scope` with LPT
  round-robin group scheduling; `--threads=1` reproduces the serial path
- `Arc<[u8]>` for `eapol_frame` storage avoids clone overhead on
  cross-combo reuse
- Inline fingerprint dedup in `generate()` drops 50-90 % of retransmission
  duplicates at generation time
- `HashSet<u64>` SipHash-1-3 fingerprints for global dedup -- no
  look-back window

## Architectural invariants (ARCHITECTURE.md §4)

- No `unsafe`. Pure-safe Rust; binary parsing via `TryInto` and bounds
  checks
- Collect-then-pair: every EAPOL message for an `(AP, STA)` pair is held
  before pairing runs. No ring buffer, no eviction
- No EAPOL size gate -- every valid frame is emitted regardless of length
- Relay (4-address WDS) frames are first-class; never filtered
- Global SipHash dedup over the significant hash fields
- Every wire constant cites its IEEE 802.11-2024 / RFC / hcxtools source

## Out of scope (v1)

- Capture / injection (file-only tool)
- Hash cracking (feed output to hashcat)
- Inner-EAP hash extraction (EAP-MD5 / LEAP / MSCHAPv2 -- v2)
- Legacy hashcat formats (hccap, hccapx, mode 2500)
- WEP, pure SAE, OWE hash-line emission (parsed and counted, not
  emitted)
- FCS validation
- Memory-usage estimation in stats (use `/usr/bin/time -v`)

## Trajectory

Major work that has landed: full pipeline (phases 0-9), per-pair AKM
resolution that correctly routes FT-PSK to mode 37100 even when the AP
advertises PSK first, all 20 PMKID locations (S1-S20), tiered EAPOL
direction classification for WDS relay frames, parallel Phase 2 pairing,
hcxpcapngtool stats parity (per-AKM assoc/reassoc, per-band, beacon
channel histogram, malformed MAC header counter), router-endianness
detection (LE/BE bits in the message_pair byte), the canonical 11-type
hash taxonomy, and the consolidation of the design / requirements /
hash-types documents into a single canonical [`ARCHITECTURE.md`](ARCHITECTURE.md).

Recent (v0.3.0): operator-experience pass driven by a 1,797-file regression
run.

- **Multi-file Phase 1 banner.** When the input expands to more than one
  capture (typical of a recursive directory walk), the Phase 1 stats
  banner now surfaces `input files processed`, plus
  `BTreeMap<String, u64>` histograms of `file formats seen`, `endians
  seen`, `network types seen`, and `last file processed`. Single-file
  runs keep the original `file name / file format / endian / network
  type` quartet for hcxpcapngtool parity. Counts and histograms are
  populated once per opened reader from `FileMetadata`; the histograms
  are sorted by descending count then key for deterministic display.
- **Unresolved-SSID hashes are dropped, not emitted (FR-ESSID-3
  rewrite).** A hash line whose AP has no SSID resolved (no Beacon /
  Probe Response / Assoc Request / Reassoc Request / directed Probe
  Request / MLD link-MAC fallback yielded one) is uncrackable -- hashcat
  derives the PMK from PSK + ESSID. Such lines also trigger
  `Salt-value exception` in mode 37100 and `Token length exception` in
  mode 22000 at hashcat parse time. Output now drops the would-be
  emission, accounts for it via `essid_unresolved_emissions` /
  `essid_unresolved_aps` in the Phase 3 banner, and writes one
  `[essid_not_found_summary] ap=... dropped=N first_seen_us=...
  last_seen_us=...` log line per affected AP. Operators can locate the
  source frames in the original capture via the timestamp range.
- **Lazy hash-sink files.** A configured sink (`--22000-out`,
  `--psk-sha384-out`, ...) no longer calls `File::create` until the
  first matching hash line is written. A sink whose hash type does not
  appear in the corpus therefore never materialises an empty file on
  disk. Previously `--psk-sha384-out` etc. always left a 0-byte file.
- **Stat-line clarity pass.** Every "issue" stat line now ends with an
  explicit suffix: `(frame dropped)`, `(frames dropped)`,
  `(unrecoverable)`, `(recovered)`, `(forgiven; processed)`, or
  `(diagnostic; ...)`. The biggest semantic fix:
  `Mesh Data frames with Mesh Control header skipped` ->
  `Mesh Data frames recovered (Mesh Control header unwrapped)`. The old
  label read like the frames were skipped (dropped); the counter
  actually means the opposite -- every increment is a frame whose mesh
  wrapper was successfully unwrapped so the inner LLC/EAPOL could be
  processed.
- **PMKID family counter relabel.** `non-FT PSK family (mode 22000:
  WPA2-PSK/SHA256/SHA384)` -> `PMKIDs found by AKM family (non-FT:
  WPA2-PSK/SHA256/SHA384)` (and the FT row in kind). The old label was
  misleading: the counter increments at PMKID *extraction* time, not at
  emission, so the value never matches the actual `lines written` to
  the legacy mode 22000 / 37100 sinks below it.

Earlier: nine-sink CLI surface that surfaces the 11-type taxonomy at the
file level. The legacy `-o` / `-f` short flags are now the long-form
`--22000-out` / `--37100-out` (line-format-identical for hashcat); the new
`-o` is the combined taxonomy file (every emitted hash, prefix
`WPA*<type-code>*`). Per-AKM sinks (`--wpa1-out`, `--wpa2-out`,
`--psk-sha256-out`, `--ft-out`, `--psk-sha384-out`, `--ft-psk-sha384-out`)
each accept a single AKM family in the new prefix scheme. Phase 4 banner
gains one row per sink with file path + lines written + dedup dropped.

Wire-level correctness improvements (post nine-sink):

- **KDV-first AKM reconciliation** in `store_eapol_key`. The wire-level
  Key Descriptor Version (KDV bits B0-B2 of EAPOL Key Information per
  [IEEE 802.11-2024] §12.7.3) is consulted *before* the AKM map: KDV=1
  forces `Wpa1`, KDV=2 collapses non-FT to `Wpa2Psk`, KDV=3 collapses
  non-FT to `PskSha256`. The FT family (`FtPsk` / `FtPskSha384`) is
  preserved across KDV=2/3 because FT can legitimately use either MIC.
  Mixed-mode beacons (RSN + WPA1 vendor IE; PSK + PSK-SHA256 advertised
  simultaneously) regularly produce an AKM map that disagrees with the
  actual wire bytes, so KDV is the only signal we can stake the type
  prefix on -- legacy mode 22000 auto-detected via the keyver byte but
  the new prefix-trusting modules silently fail on a mislabelled line.
- **PMKID-AKM decoupling** for vendor M1 quirks. Inteno / D-Link /
  TP-Link / ASUS firmware regularly emits an M1 with KDV=1 (HMAC-MD5
  MIC) AND a PMKID KDE in Key Data: a wire-level inconsistency where
  the descriptor type is RSN (0x02) but the MIC algorithm is the legacy
  WPA1 one. The PMKID itself is still computed with the AKM-defined PRF
  (HMAC-SHA1 for AKM 2), so it remains crackable. wpawolf promotes the
  PMKID's `AkmType` from `Wpa1` to `Wpa2Psk` while keeping the EAPOL
  classification as `Wpa1`. Without this, `from_akm_and_attack(Wpa1,
  is_pmkid=true) -> None` would silently drop the PMKID at output.
- **A-MSDU subframe iteration** (`src/ieee80211/amsdu.rs`). 802.11n
  aggregated MSDUs are dispatched dual-path: the outer body is always
  parsed as a single MSDU (catches glitched A-MSDU bits on what is
  actually a complete single-MPDU EAPOL frame), then the A-MSDU bit
  (QoS Control byte 0 bit 7) drives a subframe walk that surfaces EAPOL
  hidden in subframes 2..N.
- **FCS detection and tail-strip**. `src/link/radiotap.rs::has_fcs`
  reads radiotap Flags bit 4 (`0x10` = `IEEE80211_RADIOTAP_F_FCS`) and
  `src/link/mod.rs::strip` returns `(payload, had_fcs)` so the trailing
  4-byte FCS is chopped before IE walking, preventing tag/length
  mis-parse on captures whose radio appended an FCS.
- **MSDU fragment reassembly** (`src/store/fragments.rs`). Per-(SA, RA,
  SeqNum) buffer of non-final fragments; `take_completed` returns the
  concatenated MSDU body when the final fragment arrives. Most EAPOL
  fits in one MPDU but FT-PSK M2 with extended IEs occasionally
  fragments. Stats: `fragment_stats.{seen, reassembled, dropped_disorder,
  dropped_overflow}`.
- **Cross-file pairing test** (`tests/integration/cross_file_pairing.rs`).
  Splits a real-world capture at its midpoint into two files, runs
  wpawolf on the directory, asserts the output set matches the
  single-file baseline. Regression oracle for the shared-`MessageStore`
  invariant that lets handshakes survive `tcpdump`-rolled capture
  boundaries.

Documentation split into a six-doc layout:

- [`README.md`](README.md) -- project intro plus the operator-facing CLI
  surface (every output sink, examples, stats banner, hashcat drop-in
  workflow).
- [`ARCHITECTURE.md`](ARCHITECTURE.md) -- the why: pipeline shape,
  invariants, EAPOL pairing, PMKID extraction, output fan-out / dedup
  design, FR-* contracts, stats catalogue.
- [`CHANGELOG.md`](CHANGELOG.md) (this file) -- per-release summary of
  what shipped, what changed, and what was removed.
- [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md) -- every
  WPA-PSK hash format current hashcat understands today (modes 22000 +
  37100), the four legacy prefixes, the `keyver` byte trick, message-pair
  byte (EAPOL + PMKID), per-row mapping of the 11 wpawolf types onto
  current hashcat, support matrix, limitations.
- [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) -- why the 11-type
  taxonomy exists and how each row works: encoding rules, per-type
  cracker math (PBKDF2 -> PMKID / PTK / MIC), hash-line layout (16 B vs
  24 B MIC, FT extras), N#E# vs M#E# notation, complete message-pair
  byte specification.
- [`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md) -- sketch
  of a unified `mode 22001` consuming all 11 types: parsed-line struct
  widening, loader dispatch, per-kernel work items, migration path.

Known follow-ups: dedicated hashcat 24 B MIC kernel for the SHA-384 family
(types 8-11) -- the lines are emitted today on the relevant taxonomy sinks
but cannot be cracked without an upstream kernel update.
