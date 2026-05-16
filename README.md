<h1 align="center">WPAWolf</h1>

<p align="center">
  <strong>Pull every WPA / WPA2 / WPA3-FT-PSK handshake out of a pcap and hand it to hashcat.</strong>
</p>

<p align="center">
  <a href="https://github.com/StrongWind1/WPAWolf/actions/workflows/ci.yml"><img src="https://github.com/StrongWind1/WPAWolf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="rust-toolchain.toml"><img src="https://img.shields.io/badge/edition-2024-informational" alt="Edition 2024"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/msrv-1.85-informational" alt="MSRV 1.85"></a>
</p>

---

## Features

- **Pure safe Rust** -- `#![forbid(unsafe_code)]`, two runtime crates (`flate2` + `clap`)
- **Parallel pairing** -- CPU cores via `std::thread::scope` with LPT scheduling
- **Wide defaults** -- emits every valid handshake; you filter at the end
- **Cross-file pairing** -- M1 in file A pairs with M2 in file B
- **20 PMKID extraction sites** -- every spec-defined location wired and counted
- **Deep frame walking** -- A-MSDU subframes, MSDU fragment reassembly, radiotap FCS strip
- **Garbage-pattern rejection** -- nonces / MICs / PMKIDs checked against five pattern classes
- **Fast** -- >=200 MB/s on NVMe; Phase 1 I/O-bound, Phase 4 CPU-parallel
- **853 tests**; `make check-all` zero-warning under strict clippy

---

## Quick start

```sh
wpawolf --22000-out hashes.22000 --37100-out hashes.37100 capture.pcap
hashcat -m 22000 hashes.22000 wordlist.txt
hashcat -m 37100 hashes.37100 wordlist.txt
```

Sample output (stats banner, truncated):

```
=== Phase 4 -- Emit ==========================================
EAPOL pairs generated (total).......................: 142
  N1E2 challenge (ANonce M1, EAPOL M2)..............: 24
  N3E2 authorized (ANonce M3, EAPOL M2).............: 24
--22000-out (legacy mode 22000).....................: hashes.22000
  lines written.....................................: 142
=== Phase 5 -- Report ========================================
hashes emitted (total)..............................: 154
```

At least one output flag is required; `wpawolf` exits without doing any work if no output is configured.

---

## Installation

### Prebuilt binaries

Download from [GitHub Releases](https://github.com/StrongWind1/WPAWolf/releases). Static musl binaries for Linux x86_64 and arm64, macOS universal (arm64 + x86_64), and Windows (MSVC + GNU).

### From source

```sh
git clone https://github.com/StrongWind1/WPAWolf && cd WPAWolf
make build        # release binary at target/release/wpawolf
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

## How wpawolf compares to hcxpcapngtool

Both tools cover the same AKM scope (PSK and FT-PSK). The difference is default policy: `hcxpcapngtool` filters hard at extraction time; `wpawolf` emits everything and leaves filtering to you.

| Behaviour | `hcxpcapngtool` (default) | `wpawolf` (default) |
|---|---|---|
| EAPOL session window | 5 seconds | unlimited; `--eapoltimeout` opts in |
| EAPOL frame size ceiling | 512 bytes at parse | no size gate |
| Per-(AP, STA) message buffer | one shared 64-entry circular buffer | `HashMap<(AP, STA), Vec<Message>>`, per-type cap 2048 |
| WDS / 4-address relay frames | skipped unless `--all` | always processed |
| Pairing strategy | stream-pairs as frames arrive | reads everything, then pairs |
| State across input files | reset between files | carried across files |

---

## CLI reference

<details>
<summary><strong>Full flag reference</strong> (click to expand)</summary>

`wpawolf` accepts pcap, pcapng, and gzip captures (ten libpcap magic byte sequences including IXIA lcap variants). Positional arguments can be files or directories (walked recursively, magic-byte inclusion, extensions never consulted). Cross-file pairing is on by default; `--per-file` disables it.

### Hash output files

| Flag | Categories | Cracks in hashcat today? |
|---|---|---|
| `--22000-out FILE` | every non-FT hash (`WPA*01*`/`WPA*02*`) | yes -- mode 22000 |
| `--37100-out FILE` | every FT hash (`WPA*03*`/`WPA*04*`) | yes -- mode 37100 |
| `-o`, `--out FILE` | every emitted hash (`WPA*01*..*11*`, per-AKM format) | no -- needs proposed mode 22002/22003 |
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

### Output filters

| Flag | Default | Meaning |
|---|---|---|
| `--eapoltimeout [N]` | unlimited | session window in seconds; bare = 600 s |
| `--rc-drift [N]` | off | discard pairs with RC delta > N; bare = 8 |
| `--dedup-hash-combos` | off | 6 combos -> 3 unique per session |
| `--nc-dedup` | off | cluster near-identical nonces, keep one survivor with FLAG_NC |
| `--nc-tolerance N` | 8 | cluster span for `--nc-dedup` |
| `--essid-collapse-min N` | 3 | SSID-variant collapse: min distinct SSIDs to trigger |
| `--essid-collapse-ratio N` | 10 | SSID-variant collapse: top/second ratio threshold |
| `--strict` | off | bundle: `--eapoltimeout=5 --rc-drift=8 --dedup-hash-combos --per-file --nc-dedup` |

### Runtime options

| Flag | Default | Meaning |
|---|---|---|
| `--threads N` | CPU count | Phase 4 worker count; `--threads=1` for reproducible output |
| `--per-file` | off | pair + emit + clear per input file; bounds RSS |
| `--max-eapol-per-type N` | 2048 | per-(AP,STA) stored-message cap per type; 0 = unlimited |
| `--quiet` | off | suppress progress lines |
| `--mem-stats` | off | per-store footprint table after closing banner |
| `--debug` | off | timestamped phase/file/group diagnostic lines |

Progress lines print to stdout every 5 s or every 2M packets; `--quiet` silences them. Every run prints a Phase 1-5 stats summary unconditionally. Garbage-pattern nonces / MICs / PMKIDs are rejected at extract time; missing SSIDs drop at emit time. See [`ARCHITECTURE.md`](ARCHITECTURE.md) §4 and §9 for the full rejection and stats catalogue.

</details>

---

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the development workflow, parity oracle setup, and commit conventions.

---

## Further reading

| Document | Covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | 5-phase pipeline, critical invariants, EAPOL pairing, PMKID extraction, stats catalogue, FR-* contracts |
| [CHANGELOG.md](CHANGELOG.md) | per-release summary of what shipped |
| [HASHCAT-CURRENT-FORMATS.md](HASHCAT-CURRENT-FORMATS.md) | modes 22000 + 37100 as they exist in hashcat today |
| [HASHCAT-NEW-FORMATS.md](HASHCAT-NEW-FORMATS.md) | the 11 hash types: per-AKM cracker math, line layout, message-pair byte |
| [HASHCAT-PROPOSED-CHANGES.md](HASHCAT-PROPOSED-CHANGES.md) | proposed modes 22002 / 22003 (design, not implemented) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | dev workflow, parity oracle, commit conventions |

---

## Credits

wpawolf is a ground-up rewrite of [ZerBea/hcxtools](https://github.com/ZerBea/hcxtools)' `hcxpcapngtool`. The reference C implementation and its two custom variants informed every design decision in this project.

---

## License

Apache 2.0. See [`LICENSE`](LICENSE).

> [!IMPORTANT]
> `wpawolf` operates on pcap files you already have on disk. It does not capture traffic, inject frames, or touch a radio. Running it on captures you don't own or lack written authorization to analyse is illegal in most jurisdictions.
