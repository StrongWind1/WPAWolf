<h1 align="center">WPAWolf</h1>

<p align="center">
  <strong>Pull every WPA / WPA2 / WPA3 PSK-family handshake and PMKID out of a pcap and hand it to hashcat.</strong>
</p>

<p align="center">
  <a href="https://github.com/StrongWind1/WPAWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/WPAWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="rust-toolchain.toml"><img src="https://img.shields.io/badge/edition-2024-informational" alt="Edition 2024"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/msrv-1.95-informational" alt="MSRV 1.95"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
</p>

<p align="center">
  <a href="#example">Example</a> &bull;
  <a href="#installation">Installation</a> &bull;
  <a href="#cli-reference">CLI reference</a> &bull;
  <a href="#further-reading">Further reading</a>
</p>

---

## Features

- **Pure safe Rust** - `#![forbid(unsafe_code)]`, five runtime crates (`flate2` + `crc32fast` + `clap` + `rayon` + `sysinfo`)
- **Parallel pairing** - rayon work-stealing across CPU cores with streaming per-group fan-out
- **Wide defaults** - emits every valid handshake; you filter at the end
- **Cross-file pairing** - M1 in file A pairs with M2 in file B
- **20 PMKID extraction sites** - every spec-defined location wired and counted
- **Deep frame walking** - A-MSDU subframes, out-of-order MSDU fragment reassembly, CRC-32 FCS validation with tiered recovery of corrupt link-layer headers
- **Garbage-pattern rejection** - nonces / MICs / PMKIDs checked against five pattern classes
- **Disk-backed fallback** - heavy stores spill to disk at 80 % RAM so corpus-scale runs finish instead of OOMing
- **Fast** - >=200 MB/s on NVMe; Phase 1 I/O-bound, Phase 4 CPU-parallel
- **966 tests**; `make check-all` zero-warning under strict clippy

---

## Example

```sh
wpawolf --22000-out hashes.22000 --37100-out hashes.37100 capture.pcap
hashcat -m 22000 hashes.22000 wordlist.txt
hashcat -m 37100 hashes.37100 wordlist.txt
```

Sample output (stats banner, truncated):

```
=== Phase 4: Emit ===================================================
output filters active.......................................: none (WIDE mode)
EAPOL pairs generated (total, pre-dedup)....................: 105
EAPOL pairs written (post-dedup)............................: 105
  N1E2 challenge (ANonce from M1, EAPOL from M2)............: 22
  N3E2 authorized (ANonce from M3, EAPOL from M2)...........: 18
--22000-out (legacy mode 22000).............................: hashes.22000
  lines written.............................................: 108
=== Phase 5: Report =================================================
hashes emitted (total)......................................: 147
wallclock total (s).........................................: 0.4
disk-backed fallback engaged................................: no
```

At least one output flag is required; `wpawolf` exits without doing any work if no output is configured.

---

## Installation

### Prebuilt binaries

Download from [GitHub Releases](https://github.com/StrongWind1/WPAWolf/releases). Static musl binaries for Linux x86_64 and arm64, macOS universal (arm64 + x86_64), and Windows (MSVC + GNU).

### From source

```sh
git clone https://github.com/StrongWind1/WPAWolf
cd WPAWolf
make release      # optimised native build -> target/release/wpawolf
```

Requires a stable Rust toolchain (see `rust-toolchain.toml`). See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full development workflow.

---

## Examples

```sh
# Legacy 22000 + 37100 (what hashcat cracks today).
wpawolf --22000-out hashes.22000 --37100-out hashes.37100 *.pcap

# Combined output: every hash in the extended 11-type format.
wpawolf -o all-hashes.out *.pcap

# Per-AKM split for triage.
wpawolf --wpa2-out wpa2.out --ft-out ft.out --psk-sha384-out psk384.out capture.pcapng.gz

# Maximum extraction: all hash sinks + all auxiliaries.
wpawolf --22000-out h.22000 --37100-out h.37100 -o all.out \
        -E essids.txt -R probes.txt -W wordlist.txt \
        -I identities.txt -U usernames.txt -D devices.txt \
        --log run.log captures/*

# hcxpcapngtool-shape output via the bundled shortcut.
wpawolf --22000-out hashes.22000 --strict captures/

# Custom tight filters: 3 s session window, RC drift 4, single-threaded.
wpawolf --22000-out hashes.22000 --eapoltimeout 3 --rc-drift 4 \
        --dedup-hash-combos --threads 1 capture.pcap
```

---

## How WPAWolf compares to hcxpcapngtool

Both tools cover the same AKM scope (PSK and FT-PSK). The difference is default policy: `hcxpcapngtool` filters hard at extraction time; WPAWolf emits everything and leaves filtering to you.

| Behaviour | `hcxpcapngtool` (default) | `wpawolf` (default) |
|---|---|---|
| EAPOL session window | 5 seconds | unlimited; `--eapoltimeout` opts in |
| EAPOL frame size ceiling | 512 bytes at parse | no size gate |
| Per-(AP, STA) message buffer | one shared 64-entry circular buffer | `HashMap<(AP, STA), Vec<Message>>`, no eviction |
| WDS / 4-address relay frames | skipped unless `--all` | always processed |
| Pairing strategy | stream-pairs as frames arrive | reads everything, then pairs |
| State across input files | reset between files | carried across files |

---

## CLI reference

<details>
<summary><strong>Full flag reference</strong> (click to expand)</summary>

`wpawolf` accepts pcap, pcapng, and gzip captures (ten libpcap magic byte sequences including IXIA lcap variants) over raw 802.11, radiotap, PPI, Prism, AVS, and Linux cooked (SLL / SLL2) link layers. Positional arguments can be files or directories (walked recursively, magic-byte inclusion, extensions never consulted). Cross-file pairing is always on: all EAPOL messages are collected across every input file before pairing runs.

### Hash output files

| Flag | Categories | Cracks in hashcat today? |
|---|---|---|
| `--22000-out FILE` | every non-FT hash (`WPA*01*`/`WPA*02*`) | yes - mode 22000 |
| `--37100-out FILE` | every FT hash (`WPA*03*`/`WPA*04*`) | yes - mode 37100 |
| `-o`, `--out FILE` | every emitted hash (`WPA*01*..*11*`, per-AKM format) | no - needs proposed mode 22002/22003 |
| `--wpa1-out FILE` | category 1 | no |
| `--wpa2-out FILE` | categories 2 + 3 | no |
| `--psk-sha256-out FILE` | categories 4 + 5 | no |
| `--ft-out FILE` | categories 6 + 7 | no |
| `--psk-sha384-out FILE` | categories 8 + 9 | no |
| `--ft-psk-sha384-out FILE` | categories 10 + 11 | no |

The per-AKM sinks (`-o` and the six per-family flags) use an eleven-prefix format described in [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md). No current hashcat mode reads it; proposed modes 22002/22003 are sketched in [`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md).

### Auxiliary outputs

| Flag | Description |
|---|---|
| `-E` `--essid-output FILE` | unique ESSIDs from AP-side management frames (autohex) |
| `-R` `--probe-output FILE` | unique ESSIDs from Probe Request frames (autohex) |
| `-W` `--wordlist-output FILE` | combined wordlist: superset of -E + -R + WPS + EAP + country + vendor |
| `-I` `--identity-output FILE` | EAP identity strings (autohex) |
| `-U` `--username-output FILE` | EAP peer-identity strings (autohex) |
| `-D` `--device-output FILE` | WPS device info (tab-separated, sorted by manufacturer) |
| `--wordlist-scan FILE` | printable-ASCII runs (>=8 B) from IE bodies; standalone from -W |
| `--log FILE` | structured processing log |

### `--prefix` and shared `/dev/*` sinks

`--prefix PREFIX` sets a default path for every hash and auxiliary sink at once: each sink left unset writes to `PREFIX` plus its own suffix (`PREFIX.22000`, `PREFIX.37100`, `PREFIX.combined`, `PREFIX.wpa1`, `PREFIX.wpa2`, `PREFIX.psk-sha256`, `PREFIX.ft`, `PREFIX.psk-sha384`, `PREFIX.ft-psk-sha384`, `PREFIX.essid`, `PREFIX.probe`, `PREFIX.wordlist`, `PREFIX.identity`, `PREFIX.username`, `PREFIX.device`, `PREFIX.wordlist-scan`, `PREFIX.log`). An explicit per-sink flag overrides its prefix-derived path. Mirrors hcxpcapngtool's `--prefix`.

Any output may be a `/dev/*` target (`/dev/stdout`, `/dev/stderr`, `/dev/null`, `/dev/fd/N`), and several sinks may share one: `wpawolf -o /dev/stdout --22000-out /dev/stdout -E /dev/stdout capture.pcap` streams the extended hashes, the legacy 22000 hashes, and the ESSID list all to stdout. Real files must still be unique - only `/dev/*` targets are exempt from the duplicate-path check.

### Output options

Output options split into two kinds, and the difference is the only thing that matters for recall. **Reduction** options *fold* redundant lines per MIC and never drop a crackable hash (`--smart` is the recommended one). **Filter** options drop *pairs or messages* by a threshold and can drop a crackable hash entirely, making that handshake uncrackable. The MIC is the key: one distinct MIC (or PMKID) is one crackable handshake, so "does this flag keep every MIC?" is the question. Reduction options always answer yes; filters do not.

#### Reduction (never-miss -- keeps every crackable hash)

| Flag | Default | Meaning |
|---|---|---|
| `--smart` | off | **recommended.** Handshake-instance attribution: emit ~one line per MIC instead of the full ANonce x MIC cross-product; prune only provably-uncrackable cross-instance cells. Implies `--dedup-hash-combos` + `--nc-dedup`. |
| `--dedup-hash-combos` | off | 6 N#E# combos -> 3 unique per session |
| `--nc-dedup` | off | fold +/-N/2 near-identical-nonce siblings into one survivor tagged FLAG_NC |
| `--nc-tolerance N` | 8 | cluster span for `--nc-dedup` |
| `--collapse-message-pair` | off | drop the message-pair metadata byte from the dedup identity (folds N#E# combos that differ only in that byte) |

#### Filters -- (!) CAUTION: these can drop crackable hashes (MICs)

MIC loss below was measured on a large multi-vendor corpus with the cap forced off (so every difference is the filter itself, not the cap); every reduction option above lost zero.

| Flag | Default | Meaning -- **(!) MIC-loss behaviour** |
|---|---|---|
| `--strict` | off | bundle: `--eapoltimeout=5 --rc-drift=8 --nc-tolerance=8 --max-eapol-per-type=500 --dedup-hash-combos --nc-dedup --collapse-message-pair`; bundles the MIC-droppers below -- **dropped thousands of crackable MICs**. Prefer `--smart`. |
| `--eapoltimeout [N]` | unlimited | discard pairs more than N seconds apart; bare = 600 s -- **tighter windows drop crackable MICs** |
| `--rc-drift [N]` | off | discard pairs with replay-counter delta > N; bare = 8 -- **exact (`=0`) drops the most crackable MICs; even the default (`=8`) drops some** |
| `--max-eapol-per-type N` | 0 (off) | cap pairing to the first N messages of each type per (AP, STA); bounds rotating-ANonce fan-out -- **when N > 0 can drop the M1 with a MIC's true ANonce; a loud end-of-run alarm fires** |

#### ESSID variant collapse

| Flag | Default | Meaning |
|---|---|---|
| `--essid-collapse-min N` | 3 | min distinct SSIDs per AP before SSID-variant collapse fires |
| `--essid-collapse-ratio N` | 10 | top/runner-up SSID-count ratio to trigger collapse |

### Runtime options

| Flag | Default | Meaning |
|---|---|---|
| `--threads N` | CPU count | Phase 4 worker count; `--threads=1` for reproducible output |
| `--quiet` | off | suppress progress lines |
| `--mem-stats` | off | per-store footprint table after closing banner |
| `--debug` | off | timestamped phase/file/group diagnostic lines |

Progress lines print to stdout every 5 s or every 2M packets; `--quiet` silences them. RSS is reported cross-platform via `sysinfo`. Every run prints a Phase 1-5 stats summary unconditionally. Garbage-pattern nonces / MICs / PMKIDs are rejected at extract time; missing SSIDs drop at emit time. Every line of that summary (its backing field, spec source, why it exists, and whether it drops packets) is catalogued in [`STATS.md`](STATS.md).

</details>

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the development workflow, parity oracle setup, and commit conventions.

---

## Further reading

| Document | Covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 5-phase pipeline, critical invariants, EAPOL pairing, PMKID extraction, FR-* contracts |
| [STATS.md](STATS.md) | the stats-banner contract: every line's field, spec source, reason, and drop behaviour |
| [CHANGELOG.md](CHANGELOG.md) | per-release summary of what shipped |
| [HASHCAT-CURRENT-FORMATS.md](HASHCAT-CURRENT-FORMATS.md) | modes 22000 + 37100 as they exist in hashcat today |
| [HASHCAT-NEW-FORMATS.md](HASHCAT-NEW-FORMATS.md) | the 11 hash types: per-AKM cracker math, line layout, message-pair byte |
| [HASHCAT-PROPOSED-CHANGES.md](HASHCAT-PROPOSED-CHANGES.md) | proposed modes 22002 / 22003 (design, not implemented) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | dev workflow, parity oracle, commit conventions |

---

## Credits

WPAWolf is a ground-up rewrite of [ZerBea/hcxtools](https://github.com/ZerBea/hcxtools)' `hcxpcapngtool`. The reference C implementation and its two custom variants informed every design decision in this project.

---

## Related tools

Other projects in this collection:

- [WiFi_Cracking](https://github.com/StrongWind1/WiFi_Cracking) - IEEE 802.11 security reference and attack guide
- [NFSWolf](https://github.com/StrongWind1/NFSWolf) - native NFS security toolkit

---

## Disclaimer

WPAWolf operates on pcap files you already have on disk. It does not capture traffic, inject frames, or touch a radio. It is intended for authorized security research only; running it on captures you do not own or lack written authorization to analyze is illegal in most jurisdictions. The authors are not responsible for any misuse or damage caused by this tool.

---

## License

[Apache License 2.0](LICENSE)
