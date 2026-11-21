<h1 align="center">WPAWolf</h1>

<p align="center"><strong>Pull every WPA / WPA2 / WPA3 PSK-family handshake and PMKID out of a pcap and hand it to hashcat.</strong></p>

<p align="center">
  <a href="https://github.com/StrongWind1/WPAWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/WPAWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/wpawolf"><img src="https://img.shields.io/crates/v/wpawolf.svg" alt="crates.io"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/msrv-1.95-informational" alt="MSRV 1.95"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
</p>

<p align="center">
  <a href="#installation">Installation</a> &bull;
  <a href="#quick-start">Quick start</a> &bull;
  <a href="#cli-reference">CLI reference</a> &bull;
  <a href="#how-wpawolf-compares-to-hcxpcapngtool">vs hcxpcapngtool</a>
</p>

---

WPAWolf reads pcap, pcapng, and gzip captures and writes every PSK-family EAPOL handshake and PMKID it finds (WPA1 and WPA2 PSK, PSK-SHA256, and FT-PSK) as hashcat mode 22000 lines. It is a ground-up Rust rewrite of hcxtools' `hcxpcapngtool` with the opposite default: hcxpcapngtool filters hard at extraction time, WPAWolf emits everything and leaves the filtering to you. It works offline on capture files you already have and never captures traffic, injects frames, or touches a radio.

## Example

```console
$ wpawolf -o hashes.22000 capture.pcap
...
=== Phase 4: Emit ===================================================
output filters active.......................................: none (WIDE mode)
EAPOL pairs generated (total, pre-dedup)....................: 105
EAPOL pairs written (post-dedup)............................: 105
  N1E2 challenge (ANonce from M1, EAPOL from M2)............: 22
  N3E2 authorized (ANonce from M3, EAPOL from M2)...........: 18
-o / --out (all types, mode 22000)..........................: hashes.22000
  lines written.............................................: 108
=== Phase 5: Report =================================================
hashes emitted (total)......................................: 147
wallclock total (s).........................................: 0.4
disk-backed fallback engaged................................: no
```

The stats banner is truncated here; [STATS.md](STATS.md) documents every line of it.

## Features

- **Pure safe Rust**: `#![forbid(unsafe_code)]` and five runtime crates (`flate2`, `crc32fast`, `clap`, `rayon`, `sysinfo`).
- **Wide defaults**: emits every valid handshake; you filter at the end.
- **Cross-file pairing**: M1 in file A pairs with M2 in file B.
- **20 PMKID extraction sites**: every spec-defined location wired and counted.
- **Deep frame walking**: A-MSDU subframes, out-of-order MSDU fragment reassembly, and CRC-32 FCS validation with tiered recovery of corrupt link-layer headers.
- **Garbage-pattern rejection**: nonces, MICs, and PMKIDs checked against five pattern classes.
- **Parallel and fast**: 200 MB/s or more on NVMe; Phase 1 is I/O-bound, and Phase 4 pairs across CPU cores with rayon work-stealing and streaming per-group fan-out.
- **Disk-backed fallback**: heavy stores spill to disk at 80% RAM, so corpus-scale runs finish instead of running out of memory.

## Installation

### From crates.io

```sh
cargo install wpawolf
```

### Prebuilt binaries

Download from [GitHub Releases](https://github.com/StrongWind1/WPAWolf/releases): static musl binaries for Linux x86_64 and arm64, macOS universal (arm64 + x86_64), and Windows (MSVC + GNU).

### From source

```sh
git clone https://github.com/StrongWind1/WPAWolf
cd WPAWolf
make release      # optimised native build -> target/release/wpawolf
```

Requires a stable Rust toolchain (pinned in `rust-toolchain.toml`).

## Quick start

```sh
# All crackable hashes in mode 22000 format
wpawolf -o hashes.22000 *.pcap

# Per-type split for triage
wpawolf --wpa2-eapol wpa2.22000 --ft-eapol ft.22000 capture.pcapng.gz

# Maximum extraction: all hash sinks plus all auxiliary outputs
wpawolf -o all.22000 \
        -E essids.txt -R probes.txt -W wordlist.txt \
        -I identities.txt -U usernames.txt -D devices.txt \
        --log run.log captures/*

# hcxpcapngtool-shape output (can drop crackable hashes, see the filters below)
wpawolf -o hashes.22000 --strict captures/

# Custom tight filters: 3 s session window, RC drift 4, single-threaded
wpawolf -o hashes.22000 --eapoltimeout 3 --rc-drift 4 \
        --dedup-hash-combos --threads 1 capture.pcap

# Crack the result
hashcat -m 22000 hashes.22000 wordlist.txt
```

At least one hash or auxiliary output flag is required; without one, `wpawolf` exits without doing any work.

## CLI reference

<details>
<summary><strong>Full flag reference</strong> (click to expand)</summary>

`wpawolf [OPTIONS] <INPUT>...` takes capture files or directories (walked recursively; files are picked by magic bytes, never by extension). It reads pcap (ten libpcap magic byte sequences, including the IXIA lcap variants), pcapng, and gzip, over raw 802.11, radiotap, PPI, Prism, AVS, and Linux cooked (SLL / SLL2) link layers. EAPOL messages from every input file are collected before pairing runs. The full flag contract is in [ARCHITECTURE.md](ARCHITECTURE.md) §8.8.

### Hash outputs

| Flag | Writes |
| --- | --- |
| `-o`, `--out FILE` | every crackable hash, types 1-7 (`WPA*01*` to `WPA*04*`) |
| `--wpa1-eapol FILE` | type 1, WPA1 EAPOL (`WPA*02*`) |
| `--wpa2-pmkid FILE` | type 2, WPA2-PSK PMKID (`WPA*01*`) |
| `--wpa2-eapol FILE` | type 3, WPA2-PSK EAPOL (`WPA*02*`) |
| `--sha256-pmkid FILE` | type 4, PSK-SHA256 PMKID (`WPA*01*`) |
| `--sha256-eapol FILE` | type 5, PSK-SHA256 EAPOL (`WPA*02*`) |
| `--ft-pmkid FILE` | type 6, FT-PSK PMKID (`WPA*03*`) |
| `--ft-eapol FILE` | type 7, FT-PSK EAPOL (`WPA*04*`) |
| `--prefix PREFIX` | default path `PREFIX.<suffix>` for every hash and auxiliary sink left unset (`PREFIX.22000`, `PREFIX.essid`, and so on), as in hcxpcapngtool |

Every hash sink writes mode 22000 lines. SHA-384 types (8-11) are counted in the stats but not emitted: their 24 B MIC does not fit mode 22000's 16 B field. Some emitted lines do not crack in current hashcat (PSK-SHA256 PMKIDs, FT-PSK APLESS combos); [HASHCAT.md](HASHCAT.md) covers the class mapping, per-class cracker math, and these kernel limitations.

Any output may be a `/dev/*` target (`/dev/stdout`, `/dev/stderr`, `/dev/null`, `/dev/fd/N`), and several sinks may share one: `wpawolf -o /dev/stdout -E /dev/stdout capture.pcap` streams the hashes and the ESSID list to stdout. Two sinks on the same real file are rejected.

### Auxiliary outputs

| Flag | Writes |
| --- | --- |
| `-E`, `--essid-output FILE` | unique ESSIDs from AP-side management frames (autohex) |
| `-R`, `--probe-output FILE` | unique ESSIDs from Probe Request frames (autohex) |
| `-W`, `--wordlist-output FILE` | combined wordlist: `-E`, `-R`, WPS, EAP, country, and vendor strings |
| `-I`, `--identity-output FILE` | EAP identity strings (autohex) |
| `-U`, `--username-output FILE` | EAP peer-identity strings (autohex) |
| `-D`, `--device-output FILE` | WPS device info (tab-separated, sorted by manufacturer) |
| `--wordlist-scan FILE` | printable-ASCII runs of 8 B or more from IE bodies, separate from `-W` |
| `-l`, `--log FILE` | structured processing log |

### Output reduction (never drops a crackable hash)

One distinct MIC (or PMKID) is one crackable handshake. Reduction options fold redundant lines per MIC and always keep every MIC; `--smart` is the recommended one.

| Flag | Default | Effect |
| --- | --- | --- |
| `--smart` | off | handshake-instance attribution: about one line per MIC instead of the full ANonce x MIC cross-product, pruning only provably uncrackable cells; implies `--dedup-hash-combos` and `--nc-dedup` |
| `--dedup-hash-combos` | off | 6 N#E# combos to 3 unique per session |
| `--nc-dedup` | off | fold +/-N/2 near-identical-nonce siblings into one survivor tagged FLAG_NC |
| `--nc-tolerance N` | 8 | cluster span for `--nc-dedup` |
| `--collapse-message-pair` | off | drop the message-pair byte from the dedup identity, folding combos that differ only in that byte |

### Output filters (can drop crackable hashes)

Filters drop pairs or messages by a threshold, and a dropped MIC is an uncrackable handshake. The MIC loss below was measured on a large multi-vendor corpus with the cap forced off; every reduction option above lost zero.

| Flag | Default | Effect and MIC loss |
| --- | --- | --- |
| `-s`, `--strict` | off | bundle of `--eapoltimeout=5 --rc-drift=8 --nc-tolerance=8 --max-eapol-per-type=500 --dedup-hash-combos --nc-dedup --collapse-message-pair`; **dropped thousands of crackable MICs**, prefer `--smart` |
| `--eapoltimeout [N]` | unlimited | discard pairs more than N seconds apart (bare: 600); **tighter windows drop crackable MICs** |
| `--rc-drift [N]` | off | discard pairs with a replay-counter delta above N (bare: 8); **`=0` drops the most crackable MICs, and even `=8` drops some** |
| `--max-eapol-per-type N` | 0 (off) | pair only the first N messages of each type per (AP, STA) to bound rotating-ANonce fan-out; **with N > 0 it can drop the M1 carrying a MIC's true ANonce**, and an end-of-run alarm fires |

### Other options

| Flag | Default | Effect |
| --- | --- | --- |
| `--essid-collapse-min N` | 3 | minimum distinct SSIDs per AP before SSID-variant collapse fires |
| `--essid-collapse-ratio N` | 10 | top/runner-up SSID-count ratio that triggers collapse |
| `-t`, `--threads N` | CPU count | Phase 4 worker count; `--threads=1` for reproducible output |
| `-q`, `--quiet` | off | suppress the progress lines (printed every 5 s or every 2M packets) |
| `--mem-stats` | off | per-store footprint table after the closing banner |
| `-d`, `--debug` | off | timestamped phase, file, and group diagnostics |

Every run prints the Phase 1-5 stats banner; [STATS.md](STATS.md) catalogues each line (backing field, spec source, why it exists, and whether it drops packets).

</details>

## How WPAWolf compares to hcxpcapngtool

Both tools cover the same AKM scope (PSK and FT-PSK). They differ in default policy:

| Behaviour | `hcxpcapngtool` (default) | `wpawolf` (default) |
| --- | --- | --- |
| EAPOL session window | 5 seconds | unlimited; `--eapoltimeout` opts in |
| EAPOL frame size ceiling | 512 bytes at parse | no size gate |
| Per-(AP, STA) message buffer | one shared 64-entry circular buffer | `HashMap<(AP, STA), Vec<Message>>`, no eviction |
| WDS / 4-address relay frames | skipped unless `--all` | always processed |
| Pairing strategy | stream-pairs as frames arrive | reads everything, then pairs |
| State across input files | reset between files | carried across files |

Collect-then-pair, the missing size gate, and first-class relay frames are critical invariants 2 to 4 in [ARCHITECTURE.md](ARCHITECTURE.md) §4.

## Development

Conventional commit messages (`feat:`, `fix:`, `docs:`); run `make check` before every commit. Parity against the hcxtools oracle is required for any extraction change. 976 tests; `make check-all` is zero-warning under strict clippy.

- [ARCHITECTURE.md](ARCHITECTURE.md): 5-phase pipeline, critical invariants, EAPOL pairing, PMKID extraction, FR-* contracts
- [HASHCAT.md](HASHCAT.md): mode 22000 format reference, 11-class mapping, per-class cracker math, known limitations
- [STATS.md](STATS.md): the stats-banner contract, with every line's field, spec source, reason, and drop behaviour
- [CHANGELOG.md](CHANGELOG.md): per-release summary of what shipped

## Credits

WPAWolf is a ground-up rewrite of [ZerBea/hcxtools](https://github.com/ZerBea/hcxtools)' `hcxpcapngtool`. The reference C implementation and its two custom variants informed every design decision in this project. The mode 22000 output is checked against upstream [hashcat](https://github.com/hashcat/hashcat).

## Related tools

- [**WEPWolf**](https://github.com/StrongWind1/WEPWolf): Offline, passive WEP key recovery from 802.11 captures
- [**WiFi_Cracking**](https://github.com/StrongWind1/WiFi_Cracking): IEEE 802.11 security reference: WPA/WPA2/WPA3 PSK, EAP, and WEP, from protocol internals to cracking

All tools: [strongwind.dev](https://strongwind.dev)

## Disclaimer

WPAWolf is for authorized security testing, research, and education. Use it only against systems and data you own or have written permission to test. You are responsible for how you use it.

## License

[Apache License 2.0](LICENSE)
