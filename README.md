<h1 align="center">WPAWolf</h1>

<p align="center">
  <strong>Fast, no-drop WPA/WPA2/WPA3-FT-PSK handshake extractor for hashcat.</strong>
</p>

<p align="center">
  <a href="https://github.com/StrongWind1/WPAWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/WPAWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="rust-toolchain.toml"><img src="https://img.shields.io/badge/edition-2024-informational" alt="Edition 2024"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/msrv-1.85-informational" alt="MSRV 1.85"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> &bull;
  <a href="#cli-reference">CLI reference</a> &bull;
  <a href="#building">Building</a> &bull;
  <a href="ARCHITECTURE.md">Architecture</a> &bull;
  <a href="CHANGELOG.md">Changelog</a>
</p>

---

`wpawolf` ingests pcap / pcapng / gzip captures and emits hashcat mode
22000 (WPA-PSK / WPA-PSK-SHA256 / PMKID) and mode 37100 (FT-PSK) hash
lines, plus auxiliary wordlists, EAP identities, and WPS device info.
It is a ground-up Rust rewrite of
[ZerBea/hcxtools](https://github.com/ZerBea/hcxtools)' `hcxpcapngtool`,
designed to fix the handful of upstream behaviours that silently
discard valid handshakes.

## Quick start

```sh
# Drop-in replacement for hcxpcapngtool: hashcat-ready 22000 + 37100.
wpawolf --22000-out hashes.22000 --37100-out hashes.37100 capture.pcap
hashcat -m 22000 hashes.22000 wordlist.txt
hashcat -m 37100 hashes.37100 wordlist.txt
```

`wpawolf` requires at least one output flag. Both legacy sinks
(`--22000-out`, `--37100-out`) emit byte-identical lines to upstream
`hcxpcapngtool` for the same handshake. Use the new taxonomy sinks
(below) when you want triage by AKM family or want to preserve
SHA-384 captures the legacy format cannot represent.

---

## Documentation map

Six focused docs cover the project. Read by audience:

| Document | Audience | What it covers |
|----------|----------|----------------|
| [README.md](README.md) (this file) | every user | What wpawolf does, every CLI flag, examples, hashcat compatibility, build / install |
| [ARCHITECTURE.md](ARCHITECTURE.md) | contributors | Why everything is the way it is: 5-phase pipeline, critical invariants, EAPOL pairing, PMKID extraction, output fan-out / dedup design, FR-* contracts, stats catalogue |
| [CHANGELOG.md](CHANGELOG.md) | upgraders, integrators | Per-release summary of what shipped, what changed, and what was removed since the previous version |
| [HASHCAT-CURRENT-FORMATS.md](HASHCAT-CURRENT-FORMATS.md) | hashcat developers, integrators | Every WPA-PSK hash format current hashcat understands today (modes 22000 + 37100), the four prefixes, the `keyver` trick, message-pair byte (EAPOL + PMKID), per-row mapping of the 11 types onto today's hashcat, support matrix, limitations |
| [HASHCAT-NEW-FORMATS.md](HASHCAT-NEW-FORMATS.md) | hashcat developers, cryptographers | Why the 11-type taxonomy exists and how each row works: encoding rules, per-type cracker math (PBKDF2 -> PMKID / PTK / MIC), hash-line layout (16 B vs 24 B MIC, FT extras), N#E# notation + M#E# translation, message-pair byte spec |
| [HASHCAT-PROPOSED-CHANGES.md](HASHCAT-PROPOSED-CHANGES.md) | hashcat module maintainers | Sketch of a unified `mode 22001` consuming all 11 types: parsed-line struct widening, loader dispatch, per-kernel work items, migration path |

---

## Why wpawolf

`hcxpcapngtool` loses handshakes in eight well-documented ways.
`wpawolf` is designed around fixing each one:

| hcxpcapngtool behaviour | wpawolf behaviour |
|---|---|
| Single 64-entry circular buffer shared across all AP/STA pairs | `HashMap<(AP, STA), Vec<Message>>` with no ceiling |
| `cleanbackhandshake` only looks back 20 entries for duplicates | Global `HashSet<u64>` SipHash fingerprint dedup |
| Stream-pairs messages on arrival | Collect-then-pair: every (AP, STA) group is paired after the whole capture is read |
| `EAPOL_AUTHLEN_OLD_MAX = 255` silently drops oversized FT-PSK M2 frames | No size gate -- every valid EAPOL frame is emitted |
| Default mode emits 4 of 6 N#E# combos | All 6 combos emitted by default; `--dedup-hash-combos` reduces to 3 unique per session |
| Skips WDS / relay frames (To DS=1, From DS=1) unless `--all` | Always processes relay frames |
| AKM detection relies on the AP's first-advertised RSN-IE AKM | Observed FT IEs in the M2 Key Data / Association Request take precedence, then the per-pair RSN IE, then the AP-wide default |
| Declared-AKM-only classification can miss FT-PSK sessions | Wire-level MDIE + FTIE presence is the primary FT-PSK signal |
| Trusts the AP's advertised AKM at face value | KDV-first reconciliation: the wire-level Key Descriptor Version overrides the AKM-IE family when they disagree (the WPA1+RSN-descriptor+PMKID-KDE vendor quirk and other mixed-mode beacon mismatches) |

---

## What wpawolf reads

| Format | Notes |
|--------|-------|
| pcap | All six magic variants, including Kuznetzov-patched 24-byte per-packet headers |
| pcapng | Multi-SHB, multi-IDB, `if_tsresol`, `if_tsoffset` |
| gzip | `.pcap.gz` / `.pcapng.gz` auto-detected |

Link types: DLT 105 (raw 802.11), DLT 127 (radiotap), DLT 192 (PPI),
DLT 119 (Prism, with AVS-within-Prism detection), DLT 163 (AVS).

I/O errors abort the run; parse errors are logged and skipped.

### Multiple input files and directory expansion

`wpawolf` accepts any number of positional arguments. Each one is
either a capture file (pcap, pcapng, or gzip-compressed) or a
directory.

Directory expansion is **magic-byte-driven, not extension-driven.**
Every regular file under the directory is opened, its first 4 bytes
are inspected, and the file is included only if those bytes match a
supported capture magic. A `.pcap` file containing JSON is silently
skipped; a `.bin` or extensionless file containing valid pcap data is
included. The accepted magics are listed below.

| Format                       | On-disk first bytes (LE writer / BE writer) | Source                                     |
|------------------------------|---------------------------------------------|--------------------------------------------|
| pcap, microsecond resolution | `D4 C3 B2 A1` / `A1 B2 C3 D4`               | libpcap `TCPDUMP_MAGIC` (`0xa1b2c3d4`)     |
| pcap, nanosecond resolution  | `4D 3C B2 A1` / `A1 B2 3C 4D`               | libpcap `NSEC_TCPDUMP_MAGIC` (`0xa1b23c4d`)|
| pcap, Kuznetzov 24-byte hdr  | `34 CD B2 A1` / `A1 B2 CD 34`               | libpcap `KUZNETZOV_TCPDUMP_MAGIC` (`0xa1b2cd34`) |
| IXIA `lcap` HW (nanosecond)  | `AC 01 00 1C` / `1C 00 01 AC`               | wireshark `PCAP_IXIAHW_MAGIC` (`0x1c0001ac`) |
| IXIA `lcap` SW (microsecond) | `AB 01 00 1C` / `1C 00 01 AB`               | wireshark `PCAP_IXIASW_MAGIC` (`0x1c0001ab`) |
| pcapng                       | `0A 0D 0D 0A` (palindrome, BO-independent)  | draft-ietf-opsawg-pcapng-05 §4.1           |
| gzip                         | `1F 8B` (first two bytes; CM/FLG follow)    | RFC 1952 §2.3                              |

The pcap rows match libpcap's `pcap_check_header()` exactly (3
variants times 2 byte orders). The IXIA rows extend that set with
wireshark's `lcap` variants: otherwise standard pcap, but the file
header carries one extra 4-byte field after the standard 24-byte
pcap header (total packet-record size, informational only -- we read
and discard it). IXIA HW carries nanosecond timestamps like
`NSEC_TCPDUMP_MAGIC`; IXIA SW carries microsecond timestamps like
the standard pcap magic.

The libpcap-defined-but-rejected stubs `FMESQUITA_TCPDUMP_MAGIC`,
`NAVTEL_TCPDUMP_MAGIC`, and `CBPF_SAVEFILE_MAGIC` are deliberately
not accepted (libpcap itself never honors them).

Files named explicitly on the command line are passed through
verbatim and are not pre-filtered by magic -- `open_reader` runs the
same magic-byte detection during Phase 1 and emits a warning for
unrecognised formats so the operator hears about typos. Symlinks are
not followed during the directory walk.

Within each directory, files are sorted lexicographically and
processed before subdirectories are descended (also sorted). This
gives a deterministic order that does not depend on filesystem
iteration order. The order of the positional arguments themselves is
preserved -- e.g. `wpawolf early.pcap /captures/site2` processes
`early.pcap` first, then everything under `/captures/site2`.

`hcxpcapngtool` only accepts files; passing a directory is a
`wpawolf` extension. The two tools also differ sharply in whether
per-AP / per-STA state crosses the file boundary.

| Behaviour                                            | `hcxpcapngtool`                                          | `wpawolf`                                                |
|------------------------------------------------------|----------------------------------------------------------|----------------------------------------------------------|
| Per-(AP, STA) message store                          | calloc'd at file start, freed at file end                | created once before the file loop, mutated across files  |
| PMKID store                                          | calloc'd at file start, freed at file end                | created once, mutated across files                       |
| ESSID / AKM / device-info / EAP / mesh stores        | calloc'd at file start, freed at file end                | created once, mutated across files                       |
| Handshake spanning two files (M1 in file A, M2/3/4 in file B) | not paired -- file A's M1 is freed before file B is opened | paired -- M1 sits in `MessageStore` until file B's M2/3/4 arrives |
| PMKID in file A + EAPOL in file B for same (AP, STA) | both emitted independently per file (no cross-pairing)   | both fan out into the shared stores; emission sees the union |
| File-open failure                                    | prints "failed to open" to stdout, sets exit failure, continues to next file | warning on stderr, continues to next file                |
| Per-file pcapng metadata (SHB hardware/OS/app strings, IDB list) | tracked and emitted per file                             | tracked once; multi-file runs surface the format / endian / DLT histogram across the whole input set |
| File-format summary block                            | one summary per file                                     | one summary at the end of the run; single-file runs render the original `file name / file format / endian / network type` quartet, multi-file runs render `input files processed`, `file formats seen`, `endians seen`, `network types seen`, and `last file processed` |
| Pairing pass                                         | runs at end of each file, before `closelists()`          | runs once, after every input file has been read          |

The reference C implementation in `hcxpcapngtool.c` (`processcapfile`,
around line 6229) calls `initlists()` on entry and `closelists()` on exit. Every per-AP / per-STA / PMKID /
EAPOL / EAP-method buffer is reset to zero between files. The
practical effect is that splitting a capture across two files
(e.g. `tcpdump` rolled at midnight) loses any handshake whose M1 lands
on the first side of the split and whose M2 / M3 / M4 lands on the
second.

`wpawolf` (`src/main.rs:271 onward`) creates `MessageStore`,
`PmkidStore`, `EssidMap`, `AkmMap`, `MldStore`, `EssidSet`,
`ProbeEssidSet`, `WordlistStore`, `IdentitySet`, `UsernameSet`,
`DeviceInfoStore`, and `Stats` *before* the input-file loop and
mutates them as each file's packets are decoded. Phase 4 (pairing,
emission) runs once after every file has been read, so messages from
different files pair freely as long as they share the same (AP MAC,
STA MAC) pair.

Practical guidance:

- Passing `wpawolf capture-part-1.pcap capture-part-2.pcap` recovers
  any handshake whose four messages are split across the two files.
  `hcxpcapngtool` on the same pair drops it.
- Per-file isolation that `hcxpcapngtool` provides is occasionally
  wanted (e.g. preventing a stale M1 from a long capture from
  pairing with an unrelated later session). `wpawolf` does not have a
  per-file-reset mode; the equivalent workflow is to invoke `wpawolf`
  once per input file with separate output paths and merge the
  resulting hash files afterward.
- File order matters for `--eapoltimeout`. The session-window check
  uses each message's pcap timestamp, not file boundaries, so
  out-of-order files (e.g. `wpawolf later.pcap earlier.pcap`) can
  still pair correctly as long as the timestamps fall inside the
  configured window.

---

## CLI reference

```
wpawolf [OPTIONS] <INPUT>...
```

Each `<INPUT>` is a capture file or a directory; directories are
walked recursively and every regular file whose first 4 bytes match
a supported capture magic (pcap, pcapng, or gzip -- see "Multiple
input files and directory expansion" above) is included. File
extensions are never consulted.

At least one output flag is required; the binary refuses to run with
no sinks configured.

### Hash output sinks

Every sink is optional. The same logical hash fans out to every
configured sink with the appropriate per-sink prefix and per-sink
dedup. The legacy sinks (`--22000-out`, `--37100-out`) produce
hashcat-ready lines using the four-prefix scheme; the taxonomy sinks
produce the 11-type prefix scheme described in
[`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md).

| Flag                         | Types written          | Line prefix(es)              | Hashcat | FT extras |
|------------------------------|------------------------|------------------------------|---------|-----------|
| `--22000-out FILE`           | every non-FT hash      | `WPA*01*` PMKID, `WPA*02*` EAPOL | 22000 (drop-in) | no |
| `--37100-out FILE`           | every FT hash          | `WPA*03*` PMKID, `WPA*04*` EAPOL | 37100 (drop-in) | yes |
| `-o`, `--out FILE`           | every emitted hash     | `WPA*01*..*11*` (taxonomy)   | mixed | per line |
| `--wpa1-out FILE`            | type 1                 | `WPA*01*`                    | 22000 (`keyver=1` only) | no |
| `--wpa2-out FILE`            | types 2 + 3            | `WPA*02*` `WPA*03*`          | 22000 | no |
| `--psk-sha256-out FILE`      | types 4 + 5            | `WPA*04*` `WPA*05*`          | 22000 (type 5 only) | no |
| `--ft-out FILE`              | types 6 + 7            | `WPA*06*` `WPA*07*`          | 37100 | yes |
| `--psk-sha384-out FILE`      | types 8 + 9            | `WPA*08*` `WPA*09*`          | none yet (24 B MIC) | no |
| `--ft-psk-sha384-out FILE`   | types 10 + 11          | `WPA*10*` `WPA*11*`          | none yet (24 B MIC) | yes |

For the per-row mapping of the 11 types onto the legacy four-prefix
scheme (and exactly which rows crack today), see
[`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md) §7.

### Auxiliary outputs

| Flag                | Description |
|---------------------|-------------|
| `-E FILE` `--essid-output`     | unique ESSIDs from AP-side management frames (autohex) |
| `-R FILE` `--probe-output`     | unique ESSIDs from Probe Request frames (autohex) |
| `-W FILE` `--wordlist-output`  | combined wordlist: superset of `-E` + `-R` plus WPS strings, EAP identities, country codes, mesh IDs, vendor AP names |
| `-I FILE` `--identity-output`  | EAP identity strings (RFC 3748 §5.1, autohex) |
| `-U FILE` `--username-output`  | EAP peer-identity strings from inner methods (MSCHAPv2, LEAP, ...) |
| `-D FILE` `--device-output`    | WPS device info (tab-separated, sorted by manufacturer) |
| `--log FILE`                   | structured malformed-frame / skipped-packet log; also carries one `[essid_not_found_summary]` line per AP whose hashes were dropped because no SSID was ever observed |

### Output filters

These narrow the *output*; they have no effect on Phase 1 extraction.
Defaults are deliberately wide (maximum hash yield); turn filters on
when the capture is known clean.

| Flag                       | Default | Meaning |
|----------------------------|---------|---------|
| `--eapoltimeout [N]`       | unlimited | Maximum EAPOL session window in seconds. Bare flag uses 600 s. |
| `--rc-drift [N]`           | off       | Discard pairs whose replay-counter delta deviates by more than `N` from the expected sequence. Bare flag uses tolerance 8. Not the same as hashcat's `--nonce-error-corrections`. |
| `--dedup-hash-combos`      | off       | Collapse the 6 N#E# combos per session to 3 unique. |
| `--wordlist-scan-ies`      | off       | When set with `-W`, scan vendor IE bodies for printable-ASCII runs >= 8 bytes. |

### Runtime knobs

| Flag                 | Default               | Meaning |
|----------------------|-----------------------|---------|
| `--threads N`        | available CPU count   | Phase 4 (pairing) worker thread count. `--threads=1` is reproducible. |
| `-h` `--help`        | --                    | Full flag list with descriptions |
| `-V` `--version`     | --                    | Binary version |

---

## Examples

```sh
# Drop-in for hashcat: legacy 22000 + 37100 only.
wpawolf --22000-out hashes.22000 --37100-out hashes.37100 *.pcap

# Combined output: every hash in the 11-type prefix scheme.
wpawolf -o all-hashes.taxo *.pcap

# Per-AKM split: one file per family for triage.
wpawolf --wpa2-out wpa2.taxo \
        --psk-sha256-out psk-sha256.taxo \
        --ft-out ft.taxo \
        --psk-sha384-out psk-sha384.taxo \
        --ft-psk-sha384-out ft-sha384.taxo \
        capture.pcapng.gz

# Maximum extraction: legacy + every taxonomy sink + all auxiliaries.
wpawolf --22000-out h.22000 --37100-out h.37100 \
        -o all.taxo \
        --wpa1-out wpa1.taxo --wpa2-out wpa2.taxo \
        --psk-sha256-out psk256.taxo --ft-out ft.taxo \
        --psk-sha384-out psk384.taxo --ft-psk-sha384-out ft384.taxo \
        -E essids.txt -R probes.txt -W wordlist.txt \
        -I identities.txt -U usernames.txt -D devices.txt \
        --log run.log \
        captures/*

# Tighter output (hcxpcapngtool-like): 3 s session window, RC drift of 4,
# combo dedup, single-threaded for reproducible output.
wpawolf --22000-out hashes.22000 \
        --eapoltimeout 3 --rc-drift 4 --dedup-hash-combos \
        --threads 1 \
        capture.pcap
```

---

## Stats output

The closing stats summary is unconditional; there is no `--stats`
toggle. It prints to stderr at the end of every run, with one row per
configured sink under the Phase 4 banner:

```
=== Phase 4 -- Emit ==========================================
EAPOL pairs generated (total).......................: 142
  N#E# combo breakdown:
    N1E2 challenge (ANonce from M1, EAPOL from M2)......: 24
    N1E4 authorized (ANonce from M1, EAPOL from M4).....: 24
    N3E2 authorized (ANonce from M3, EAPOL from M2).....: 24
    N2E3 authorized (SNonce from M2, EAPOL from M3, AP-less): 24
    N4E3 authorized (SNonce from M4, EAPOL from M3, AP-less): 24
    N3E4 authorized (ANonce from M3, EAPOL from M4).....: 22
  NC flag (error-corr applied)......................: 3

--22000-out (legacy mode 22000).....................: hashes.22000
  lines written.....................................: 142
--37100-out (legacy mode 37100).....................: hashes.37100
  lines written.....................................: 12
-o / --out (combined taxonomy)......................: not configured
--wpa1-out (type 1).................................: not configured
--wpa2-out (types 2+3)..............................: wpa2.taxo
  lines written.....................................: 142
  dedup dropped.....................................: 8
--psk-sha256-out (types 4+5)........................: not configured
--ft-out (types 6+7)................................: ft.taxo
  lines written.....................................: 12
--psk-sha384-out (types 8+9)........................: not configured
--ft-psk-sha384-out (types 10+11)...................: not configured

=== Phase 5 -- Report ========================================
hashes emitted (total)..............................: 154
distinct hash types observed........................: 2
---
```

`hashes emitted (total)` is the per-`HashType` sum (one count per
logical hash) and does **not** sum the per-sink `lines written` rows.
Phases 1 -- 3 (capture metadata, frame / band breakdown, per-AKM
assoc/reassoc histogram, PMKID + EAPOL discovery, NULL / 0xFF
rejection counters) come before Phase 4; full catalogue in
[`ARCHITECTURE.md`](ARCHITECTURE.md) §9.

Every "issue" stat row is suffixed with whether the count means data
was **dropped**, **recovered**, or **diagnostic**. For example
`fragments dropped (out of order; unrecoverable)` is a real loss of
EAPOL bytes, `Mesh Data frames recovered (Mesh Control header
unwrapped)` is a positive (the mesh wrapper was unwrapped so the
inner LLC could be processed), and `direction/ACK mismatches
(diagnostic; frame still paired)` is just a capture-quality note --
the frame was paired anyway.

Hash sinks are created **lazily**: a configured sink that never
receives a matching hash never has its file created on disk. This
keeps `--psk-sha384-out` (and any other sink whose hash type doesn't
appear in the corpus) from materialising as a 0-byte file.

The N#E# notation (`N1E2`, `N1E4`, ..., `N3E4`) is the wpawolf taxonomy
form: **N**once from message **#**, **E**APOL frame from message **#**.
The same six combos appear under the older `M#E#` notation
(`M12E2`, `M14E4`, ...) in `hcxpcapngtool` source; a translation table
and the full message-pair byte spec are in
[`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) §6 and §7.

---

## Features

- AKM 1 (WPA1, vendor IE), 2 (PSK), 4 (FT-PSK), 6 (PSK-SHA256), 19
  (FT-PSK-SHA384), 20 (PSK-SHA384) -- all 11 hash-type rows from
  [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) §3 detected and
  classified
- PMKID extraction from all 20 spec-defined locations (S1 -- S20)
- SSID extraction from all 10 spec-valid IEEE 802.11-2024 sources
- Vendor AP name extraction from 12 enterprise vendors (Cisco, Aruba,
  Ubiquiti, Ruckus, Fortinet, ...)
- Per-subtype management frame counters (all 16 subtypes)
- Per-AKM assoc/reassoc request breakdown
- Per-band packet counts from radiotap Channel field (2.4 GHz / 5 GHz / 6 GHz)
- Beacon channel histogram from DS Parameter Set IE (tag 3)
- Malformed MAC header counter + `[malformed_frame]` log entries
- Router-endianness detection (LE/BE bits in the message-pair byte)
- Parallel Phase 4 pairing via `std::thread::scope` with LPT round-robin
- Pure-Rust, `#![forbid(unsafe_code)]`, 2 runtime crates (`flate2`, `clap`)
- A-MSDU subframe iteration (802.11n aggregation): EAPOL hidden in
  subframes 2..N is surfaced via dual-path dispatch (outer body + per-
  subframe walk)
- Radiotap FCS detection and tail-strip (Flags bit `0x10`)
- 802.11 MSDU fragment reassembly per `(SA, RA, SeqNum)` for FT-PSK M2
  frames that fragment under extended IEs
- KDV-first AKM reconciliation: wire-level Key Descriptor Version is
  consulted before the AKM map, correcting the WPA1+RSN-descriptor+
  PMKID-KDE vendor quirk and other mixed-mode beacon discrepancies
- Strict clippy (pedantic + nursery + cargo), `make check-all` zero
  warnings, 712 tests across lib + binary + integration suites
- Companion [`wpawolf-fixturegen`](tools/fixturegen/) workspace crate
  emits a deterministic 75-fixture pcap/pcapng corpus covering every
  (hash type x PMKID site x N#E# combo x link-layer x edge case)
  tuple, with cryptographically valid PMK / PMKID / MIC values --
  117 of 123 lines crack end-to-end through hashcat 7.1.2 with PSK
  `hashcat!` (the 6 that don't are documented hashcat kernel
  limitations, see
  [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md) §8.1)

---

## Status

Functional. Full pipeline (phases 0 -- 9), all 20 PMKID locations,
hcxpcapngtool stats parity, the 11-type taxonomy, and the nine-sink
CLI surface are complete. Superset integration tests plus a 1,788-
capture regression oracle confirm `wpawolf_output >=
hcxpcapngtool_output` at hash-content level.

Known follow-up: the SHA-384 family (types 8 -- 11) needs a dedicated
hashcat 24 B MIC kernel before those lines crack. The unified `mode
22001` proposal in [`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md)
covers this work.

---

## Building

```sh
make dev          # debug build
make build        # release build (native target)
make test         # run the test suite (parity test soft-skips if hcxtools missing)
make check-parity # run the parity test under CI=true (hard-fails on missing oracle)
make check-all    # full CI gate (fmt + clippy + deny + check + test + doc + hygiene + machete)
```

Requires a stable Rust toolchain (see `rust-toolchain.toml`). Once
[`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) and
[`cargo-machete`](https://github.com/bnjbvr/cargo-machete) are
installed, `make check-all` runs the complete pre-PR gate.

### Parity oracle: hcxpcapngtool >= 7.0.1

`tests/integration/superset_test.rs` validates wpawolf's correctness
claim by running `hcxpcapngtool` against the same fixture and asserting
wpawolf's output is a superset of the oracle's. **The claim only holds
against `hcxpcapngtool >= 7.0.1`** -- older releases emit different
`WPA*01*` and `WPA*02*` trailer bytes (PMKID status was added in 6.3.1,
default `ST_NC` initialisation arrived in 6.3.2, and the canonical
EAPOL-frame selection swapped from M3 to M2 in 7.0.1). The test reads
`--version`, parses the banner, and refuses to run against a stale
oracle.

Distro packages are too old: Ubuntu 22.04/24.04 and Debian stable still
ship `hcxtools 6.2.x` at time of writing, so `apt install hcxtools` does
*not* satisfy the parity gate. Build from upstream source:

```sh
git clone --depth 1 --branch 7.1.2 https://github.com/ZerBea/hcxtools
make -C hcxtools hcxpcapngtool
sudo install -m 0755 hcxtools/hcxpcapngtool /usr/local/bin/hcxpcapngtool
hcxpcapngtool --version  # must report >= 7.0.1
```

CI installs the pinned tag automatically (`HCXTOOLS_TAG` in
`.github/workflows/ci.yml`). The parity test is gated on `CI=true` so
the oracle install step cannot be silently dropped; locally,
`make check-parity` mirrors the CI behaviour.

If you do not have hcxtools installed and run `cargo test` directly, the
parity test logs a clearly-tagged skip notice on stderr and the rest of
the suite still runs.

### Release artifacts (cross-platform)

`make dist` (or bare `make`) detects the host OS / arch and builds
artifacts into `dist/`:

| Host                | Outputs                                                                |
|---------------------|------------------------------------------------------------------------|
| Linux x86_64        | `wpawolf-linux-x86_64`         (musl static, runs on any Linux distro) |
| Linux arm64         | `wpawolf-linux-arm64`          (musl static)                            |
| macOS (any)         | `wpawolf-macos-arm64` + `wpawolf-macos-x86_64` + `wpawolf-macos-universal` (lipo fat binary) |
| Windows             | CI-only (native runners required for MSVC / MinGW)                      |

Cutting a multi-platform release: `git tag vX.Y.Z && git push origin vX.Y.Z`
triggers `.github/workflows/release.yml`, which builds the full matrix
(Linux x86_64 + arm64, Windows MSVC x64/arm64 + GNU x64, macOS arm64 +
x86_64 + universal) on native runners, publishes a `SHA256SUMS` signed
with cosign keyless, emits SLSA build provenance attestations for every
binary, and creates a draft GitHub Release.

---

## Repository layout

```
wpawolf/
├── src/                          Rust source (input/, link/, ieee80211/, store/, pair/, output/)
├── tests/                        Integration tests + binary fixtures (incl. tests/fixtures/generated/ corpus)
├── tools/fixturegen/             Workspace crate that emits the test-capture corpus (separate Cargo crate)
├── .github/                      CI / Security / Release workflows + issue + PR templates
├── README.md                     Project intro + CLI / usage reference (this file)
├── ARCHITECTURE.md               Why everything is the way it is: pipeline, invariants, design decisions
├── CHANGELOG.md                  Released-version summary and milestone history
├── CONTRIBUTING.md               How to set up, lint, test, and submit a patch
├── HASHCAT-CURRENT-FORMATS.md    Current hashcat WPA formats (modes 22000 + 37100) and how the 11 types map onto them today
├── HASHCAT-NEW-FORMATS.md        The 11-type taxonomy: per-type cracker math, line layout, message-pair byte spec, design rationale
├── HASHCAT-PROPOSED-CHANGES.md   Sketch of a unified hashcat module (mode 22001) that consumes all 11 types
├── Cargo.toml                    Workspace + crate config + strict lint policy
└── Makefile                      Developer workflow + cross-platform release builds
```

---

## Authorized use only

`wpawolf` operates on pcap files you already have in hand. It does not
capture traffic, inject frames, or touch the radio in any way. Running
it on captures you do not own or have written authorisation to analyse
is illegal in most jurisdictions. Use it for your own networks, CTF
challenges, lab research, and authorised engagements.

---

## License

Apache 2.0. See [`LICENSE`](LICENSE).
