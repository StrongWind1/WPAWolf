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

`wpawolf` reads pcap, pcapng, and gzip-compressed capture files and writes hashcat-ready hash lines for WPA, WPA2, and WPA3 FT-PSK handshakes (mode 22000 and mode 37100), plus optional wordlists, EAP identity files, and WPS device-info dumps. It is a Rust rewrite of [ZerBea/hcxtools](https://github.com/ZerBea/hcxtools)' `hcxpcapngtool` with the opposite default policy: where `hcxpcapngtool` filters aggressively at extraction time so a downstream cracker sees only clean input, `wpawolf` writes everything it can recognise as a valid handshake and lets the operator narrow the output afterwards.

## Quick start

```sh
# Same hash-line formats as hcxpcapngtool; different default filters
# (see "How wpawolf compares to hcxpcapngtool" below).
wpawolf --22000-out hashes.22000 --37100-out hashes.37100 capture.pcap
hashcat -m 22000 hashes.22000 wordlist.txt
hashcat -m 37100 hashes.37100 wordlist.txt
```

`wpawolf` always needs at least one output flag; with none configured it exits without doing any work. The two flags above cover everything hashcat can crack today. Seven more output flags split the result by hash family (per-AKM, with FT and SHA-384 kept separate); see the CLI reference below.

---

## Documentation map

| Document | Read this when you want to know |
|----------|---------------------------------|
| [README.md](README.md) (this file) | What wpawolf does, every CLI flag, examples, hashcat compatibility, build / install |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Why everything is the way it is: 5-phase runtime pipeline, critical invariants, EAPOL pairing, PMKID extraction, per-output split / dedup design, FR-* contracts, stats catalogue |
| [CHANGELOG.md](CHANGELOG.md) | Per-release summary of what shipped, what changed, and what was removed since the previous version |
| [HASHCAT-CURRENT-FORMATS.md](HASHCAT-CURRENT-FORMATS.md) | Every WPA-PSK hash format current hashcat understands today (modes 22000 + 37100): the four prefixes, the `keyver` trick, message-pair byte (EAPOL + PMKID), per-row mapping of the 11 categories onto today's hashcat, support matrix, limitations |
| [HASHCAT-NEW-FORMATS.md](HASHCAT-NEW-FORMATS.md) | Why the eleven hash categories exist and how each one works: encoding rules, per-category cracker math (PBKDF2 -> PMKID / PTK / MIC), hash-line layout (16 B vs 24 B MIC, FT extras), N#E# notation + M#E# translation, message-pair byte spec |
| [HASHCAT-PROPOSED-CHANGES.md](HASHCAT-PROPOSED-CHANGES.md) | Two proposed hashcat modes (22002 passphrase + 22003 PMK-direct) that consume all eleven hash categories: parsed-line struct widening, loader dispatch, per-kernel work items, migration path. *(Design proposal, not implemented.)* |

---

## How wpawolf compares to hcxpcapngtool

`hcxpcapngtool` was tuned for high-volume crack-pool intake: narrow defaults, aggressive deduplication, and several silent gates that keep noise out of the output stream. `wpawolf` inverts that policy. The defaults are wide, no frame is silently dropped on size, and the operator filters at output time using the flags in the CLI reference. Both tools cover the same AKM scope (PSK and FT-PSK only — no SAE, OWE, or Enterprise); the difference is what each one does with the frames it sees.

| Behaviour                              | `hcxpcapngtool` (default)                                      | `wpawolf` (default)                                |
|----------------------------------------|----------------------------------------------------------------|----------------------------------------------------|
| EAPOL session window                   | 5 seconds (`EAPOLTIMEOUT` constant)                            | unlimited; `--eapoltimeout` opts in                |
| Replay-counter drift check             | always on, no off switch                                       | off; `--rc-drift` opts in                          |
| EAPOL frame size ceiling               | 255 bytes (`EAPOL_AUTHLEN_OLD_MAX`); larger frames are skipped | no size gate; oversized FT-PSK M2 passes through   |
| Duplicate-handshake detection          | 20-entry sliding window in `cleanbackhandshake`                | global SipHash fingerprint set                     |
| Per-(AP, STA) message buffer           | one shared 64-entry circular buffer                            | `HashMap<(AP, STA), Vec<Message>>`, no ceiling     |
| WDS / 4-address relay frames           | skipped unless `--all` is passed                               | always processed                                   |
| Pairing strategy                       | streams pairs as frames arrive                                 | reads everything, then pairs                       |
| State across multiple input files      | reset between files                                            | carried across files; M1 in file A pairs with M2 in file B |

Each row above is a documented `hcxpcapngtool` default, not a bug. The C tool's policy is appropriate for a feed into a shared cracking pool; `wpawolf`'s policy is appropriate for one-off analysis where the operator is closer to the capture and wants to choose the filters.

**Highlights.** `wpawolf` is pure-Rust (`#![forbid(unsafe_code)]`, two runtime crates: `flate2` and `clap`), parallelises pairing across CPU cores via `std::thread::scope` with LPT round-robin, parses A-MSDU subframes and reassembles MSDU fragments, strips radiotap FCS tails, extracts PMKIDs from all 20 spec-defined locations, rejects every garbage-pattern shape (NULL, all-`0xFF`, all-same-byte, 2-byte / 4-byte repeating period) on nonces / MICs / PMKIDs (ESSIDs are not garbage-filtered; bytes in the ASCII C0 control range surface as a non-fatal `[essid_control_bytes]` warning instead), and reconciles vendor AKM quirks against the wire-level Key Descriptor Version. 796 tests guard the behaviour; `make check-all` runs zero-warning under strict clippy.

---

## Reading captures

`wpawolf` accepts pcap (all six libpcap magics, including the 24-byte Kuznetzov header and Wireshark's two IXIA `lcap` variants), pcapng (multi-SHB, multi-IDB, with `if_tsresol` and `if_tsoffset` honoured), and gzip-compressed versions of either. Link types DLT 105 (raw 802.11), DLT 127 (radiotap), DLT 192 (PPI), DLT 119 (Prism, with AVS-within-Prism detection), and DLT 163 (AVS) are all read. I/O errors abort the run; parse errors are logged and skipped.

Positional arguments can be capture files or directories. Directories are walked recursively; each regular file is opened and its first four bytes are checked against the supported capture magics. Files that pass are read; files that don't (a `.pcap` of JSON, a screenshot, a stray `.DS_Store`) are silently skipped. File extensions are never used to decide. Within a directory the order is lexicographic, files first then subdirectories, so runs are deterministic.

Cross-file behaviour is one of the bigger differences between the two tools:

- `wpawolf` keeps per-(AP, STA) state across files; `hcxpcapngtool` resets between files. A handshake whose M1 lands in one file and whose M2/M3/M4 lands in another pairs in `wpawolf`, drops in `hcxpcapngtool`.
- Stats and metadata roll up across the run in `wpawolf` (one closing summary; multi-file inputs render a histogram of formats / endians / DLTs seen). `hcxpcapngtool` prints one summary per file.
- For per-file isolation (no cross-pairing) use `--per-file` — `MessageStore` and `PmkidStore` are flushed after every input file. Auxiliary outputs (`-E` / `-W` / ...), the dedup set, and `EssidMap` still accumulate so SSIDs observed early still resolve handshakes seen late.

Practical guidance:

- Passing `wpawolf capture-part-1.pcap capture-part-2.pcap` recovers any handshake whose four messages are split across the two files. `hcxpcapngtool` on the same pair drops it.
- File order matters for `--eapoltimeout`: the session-window check uses each message's pcap timestamp, not file boundaries, so out-of-order files (e.g. `wpawolf later.pcap earlier.pcap`) can still pair correctly as long as the timestamps fall inside the configured window.

---

## CLI reference

```
wpawolf [OPTIONS] <INPUT>...
```

Each `<INPUT>` is a capture file or a directory; directories are walked recursively and every regular file whose first four bytes match a supported capture magic is included. File extensions are never consulted. At least one output flag is required; the binary refuses to run with no outputs configured.

### Hash output files

Every output file is optional. The same handshake is written to every file you configure, using that file's prefix and its own dedup pass.

There are two distinct line formats. **Only the legacy format cracks in hashcat today.**

- **Legacy format** (`--22000-out`, `--37100-out`) uses the four-prefix scheme `WPA*01*` -- `WPA*04*` that current hashcat modes 22000 and 37100 read directly.
- **New eleven-category format** (`-o` plus the six per-family flags) uses prefixes `WPA*01*` -- `WPA*11*` where each prefix encodes its full AKM identity. This is the format described in [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md). The prefix bytes overlap with the legacy scheme but the meaning differs (e.g. legacy `WPA*01*` = PMKID; new `WPA*01*` = WPA1-PSK-EAPOL), so feeding a new-format file straight into hashcat 22000 misparses or rejects every line. **No current hashcat mode reads the new format**; the proposed modes 22002 / 22003 in [`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md) would.

| Flag                         | Categories written     | Line prefix(es)                  | Cracks in hashcat today? | FT extras |
|------------------------------|------------------------|----------------------------------|--------------------------|-----------|
| `--22000-out FILE`           | every non-FT hash      | `WPA*01*` PMKID, `WPA*02*` EAPOL | yes -- mode 22000 (drop-in; per-row caveats below) | no |
| `--37100-out FILE`           | every FT hash          | `WPA*03*` PMKID, `WPA*04*` EAPOL | yes -- mode 37100 (drop-in; per-row caveats below) | yes |
| `-o`, `--out FILE`           | every emitted hash     | `WPA*01*..*11*` (new format)     | **no** -- needs proposed mode 22002 / 22003 | per line |
| `--wpa1-out FILE`            | category 1             | `WPA*01*` (new format)           | **no** -- needs proposed mode 22002 / 22003 | no |
| `--wpa2-out FILE`            | categories 2 + 3       | `WPA*02*` `WPA*03*` (new format) | **no** -- needs proposed mode 22002 / 22003 | no |
| `--psk-sha256-out FILE`      | categories 4 + 5       | `WPA*04*` `WPA*05*` (new format) | **no** -- needs proposed mode 22002 / 22003 | no |
| `--ft-out FILE`              | categories 6 + 7       | `WPA*06*` `WPA*07*` (new format) | **no** -- needs proposed mode 22002 / 22003 | yes |
| `--psk-sha384-out FILE`      | categories 8 + 9       | `WPA*08*` `WPA*09*` (new format) | **no** -- needs proposed mode 22002 / 22003 (also: 24 B MIC unsupported by mode 22000) | no |
| `--ft-psk-sha384-out FILE`   | categories 10 + 11     | `WPA*10*` `WPA*11*` (new format) | **no** -- needs proposed mode 22002 / 22003 (also: 24 B MIC unsupported by mode 37100) | yes |

To crack today, configure `--22000-out` and / or `--37100-out`. The per-category files are useful right now for triage (`-o`, the six per-family flags) — splitting hashes by AKM family for inventory / statistics — but they cannot be fed to hashcat until modes 22002 / 22003 land. Configuring both legacy and new-format outputs in the same run is fine; the same handshake gets written to each in its respective format.

For the per-row mapping of the eleven categories onto the legacy four-prefix format (and the per-row support matrix on hashcat 7.1.2 — six categories crack cleanly via the legacy outputs, one misroutes silently, four have no legacy path), see [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md) §7 and §8.

### Auxiliary outputs

| Flag                | Description |
|---------------------|-------------|
| `-E FILE` `--essid-output`     | unique ESSIDs from AP-side management frames (autohex) |
| `-R FILE` `--probe-output`     | unique ESSIDs from Probe Request frames (autohex) |
| `-W FILE` `--wordlist-output`  | combined wordlist: superset of `-E` + `-R` plus WPS strings, EAP identities, country codes, mesh IDs, vendor AP names |
| `-I FILE` `--identity-output`  | EAP identity strings (RFC 3748 §5.1, autohex) |
| `-U FILE` `--username-output`  | EAP peer-identity strings from inner methods (MSCHAPv2, LEAP, ...) |
| `-D FILE` `--device-output`    | WPS device info (tab-separated, sorted by manufacturer) |
| `--wordlist-scan-ies FILE`     | printable-ASCII runs of 8 or more bytes pulled from plaintext management-frame IE bodies; standalone, not folded into `-W` |
| `--log FILE`                   | structured malformed-frame / skipped-packet log; also carries one `[essid_not_found_summary]` line per AP whose hashes were dropped because no SSID was ever observed |

### Output filters

These narrow what gets written to the hash output files; they have no effect on Phase 1 extraction. Defaults are deliberately wide (maximum hash yield); turn filters on when the capture is known clean.

| Flag                       | Default | Meaning |
|----------------------------|---------|---------|
| `--eapoltimeout [N]`       | unlimited | Maximum EAPOL session window in seconds. Bare flag uses 600 s. |
| `--rc-drift [N]`           | off       | Discard pairs whose replay-counter delta deviates by more than `N` from the expected sequence. Bare flag uses tolerance 8. Not the same as hashcat's `--nonce-error-corrections`. |
| `--dedup-hash-combos`      | off       | Collapse the six N#E# combos per session to the three cryptographically unique ones. |
| `--essid-collapse-min N`   | `3`     | Only collapse SSID variants when an AP has more than `N` recorded SSIDs. See worked example below. |
| `--essid-collapse-ratio N` | `10`    | When the guard fires, write only the top SSID iff `top_count >= N * second_count`. `< 2` disables. |

### Runtime options

| Flag                 | Default               | Meaning |
|----------------------|-----------------------|---------|
| `--threads N`        | available CPU count   | Phase 4 (pairing) worker thread count. `--threads=1` is reproducible. |
| `--per-file`         | off                   | Pair + emit + clear `MessageStore` / `PmkidStore` after each input file. Bounds RSS for corpus-scale runs at the cost of cross-file pairing (expected hash-yield drop < 1% on per-session corpora). |
| `--quiet`            | off                   | Suppress periodic `[progress]` stderr lines. The closing stats banner is unaffected. |
| `--mem-stats`        | off                   | After the closing banner, print a per-store entry / byte-count table sorted descending. Diagnostic; no effect on output. |
| `-h` `--help`        | --                    | Full flag list with descriptions |
| `-V` `--version`     | --                    | Binary version |

> **Bare-flag tip.** `--eapoltimeout` and `--rc-drift` accept an optional value. To use the bare-flag default (600 s session window or tolerance 8 respectively), put the flag before another `--`-prefixed flag, e.g. `--eapoltimeout --22000-out hashes.22000 capture.pcap`. Otherwise clap will try to consume the trailing positional as the flag's value and fail with exit 2.

---

## Examples

```sh
# Same hash-line formats as hcxpcapngtool: legacy 22000 + 37100 only.
wpawolf --22000-out hashes.22000 --37100-out hashes.37100 *.pcap

# Combined output: every hash in the eleven-category format.
wpawolf -o all-hashes.out *.pcap

# Per-AKM split: one file per family for triage.
wpawolf --wpa2-out wpa2.out \
        --psk-sha256-out psk-sha256.out \
        --ft-out ft.out \
        --psk-sha384-out psk-sha384.out \
        --ft-psk-sha384-out ft-sha384.out \
        capture.pcapng.gz

# Maximum extraction: legacy + every per-category file + all auxiliaries.
wpawolf --22000-out h.22000 --37100-out h.37100 \
        -o all.out \
        --wpa1-out wpa1.out --wpa2-out wpa2.out \
        --psk-sha256-out psk256.out --ft-out ft.out \
        --psk-sha384-out psk384.out --ft-psk-sha384-out ft384.out \
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

## When one AP shows up under many SSIDs

A single bit-flip in a beacon body decodes to a different SSID for the same physical AP. Most APs broadcast one to three stable SSIDs across an entire capture; an AP whose beacons arrived through a noisy channel can produce dozens of slightly-corrupted variants. `wpawolf` records every SSID it ever saw for an AP and writes one hash line per SSID. Without a guard, a single crackable handshake on a corrupted AP can spread into six or more lines, only one of which has the SSID that actually derives the correct PMK.

The `--essid-collapse-min` and `--essid-collapse-ratio` flags collapse that spread when the corruption pattern is unambiguous: if an AP has more than `N` recorded SSIDs and the most-frequent one outweighs the runner-up by a factor of at least `M`, `wpawolf` writes only that SSID's line. Defaults are `N=3` and `M=10`.

| AP                  | Observed SSIDs                                                       | Top count | Second count | What wpawolf writes by default |
|---------------------|----------------------------------------------------------------------|-----------|--------------|--------------------------------|
| dual-band           | `home-2g`, `home-5g`                                                 | 87        | 84           | both (count `<=` 3)            |
| 3-SSID rollout      | `corp`, `guest`, `iot`                                               | 412       | 280          | all three (count `<=` 3)       |
| RF-corrupted typical| `MyHome` x4192, `MyHomf` x3, `MzHome` x2, `MyHone` x1, `OyHome` x1   | 4192      | 3            | top only (count 5 > 3, ratio 1397 >= 10) |
| CTF AP              | 11 distinct named SSIDs, counts 80-120                               | 120       | 110          | all 11 (count 11 > 3 but ratio 1.09 < 10) |

Tuning:

```sh
# Keep more SSIDs per AP (e.g. CTF capture with intentional spread).
wpawolf --22000-out h.22000 --essid-collapse-min 16 capture.pcap

# Disable the collapse entirely (every recorded SSID always ships).
wpawolf --22000-out h.22000 --essid-collapse-ratio 1 capture.pcap

# Tighten: collapse on any AP with > 1 SSID and a 5x ratio gap.
wpawolf --22000-out h.22000 \
        --essid-collapse-min 1 --essid-collapse-ratio 5 \
        capture.pcap
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) §9 for the algorithm and the corpus context that motivates the defaults.

---

## Why a hash gets discarded

`wpawolf`'s defaults are deliberately wide -- the operator filters at output time, not at extract time. Even so, four rejection paths in the current code can drop a candidate PMKID or EAPOL hash before it ever reaches an output file. Every rejection bumps a stats counter (visible in the closing banner) and, when `--log FILE` is configured, emits a structured line carrying the rejected bytes in lowercase hex so the source capture can be grepped for the exact sequence.

A hash is discarded when **any** of the following is true:

| # | Reason | Field | Counters | `--log` category | Spec exception |
|---|--------|-------|----------|------------------|----------------|
| 1 | Key Nonce is structurally broken: all-`0x00` (entropy starvation or M4 spec-zero), all-`0xFF` (firmware flash-erase sentinel), or a short-period repeating pattern (`repeat_1` = every byte equal, `repeat_2` = 2-byte period, `repeat_4` = 4-byte period) -- none of these reproduce the live PTK from a real handshake | EAPOL Key Nonce, 32 B | `null_nonce_rejected`, `ff_nonce_rejected`, `repeat_nonce_rejected` | `[invalid_nonce] ... kind=<k> nonce_hex=<32 B hex>` | M4 NULL nonce is spec-valid on the wire per [IEEE 802.11-2024] §12.7.6.5 NOTE 9 but the resulting hash line is mathematically uncrackable (live PTK depends on M2's `SNonce`, which the M4 frame does not carry); dropped like any other garbage. Matches hcxpcapngtool `hcxpcapngtool.c:3636`. Non-conforming firmware that copies M2's `SNonce` into M4 (also covered by NOTE 9) still passes since the nonce is non-NULL |
| 2 | Key MIC is structurally broken: same five patterns as above | EAPOL Key MIC, 16 B (most AKMs) or 24 B (SHA-384 family) | `null_mic_rejected`, `ff_mic_rejected`, `repeat_mic_rejected` | `[invalid_mic] ... kind=<k> mic_hex=<16/24 B hex>` | Only checked when the Key MIC flag (bit B8) is set, i.e. on M2 / M3 / M4. M1 has no MIC by spec and is **never** flagged |
| 3 | PMKID is structurally broken: same five patterns as above | 16-byte PMKID at any of the 20 spec-defined extraction sites (M1 KDE, M2 RSN IE, AssocReq / ReassocReq, FT / FILS / PASN Auth, FT Action, Probe Request, Beacon, ProbeResp, Mesh Peering, OSEN IE) | `null_pmkid_rejected`, `ff_pmkid_rejected`, `repeat_pmkid_rejected` | `[invalid_pmkid] ... kind=<k> pmkid_hex=<16 B hex>` | None |
| 4 | No SSID was ever observed for this AP across the whole run, so the hash line cannot be written without inventing an ESSID | ESSID at hash-emit time | `essids_not_found` | `[essid_not_found_summary] ap=<mac> dropped=<n> first_seen_us=<t> last_seen_us=<t>` (one per affected AP at end of run) | None -- happens when the capture started mid-handshake or the Beacon channel was missed |

Reasons 1-3 fire at **extract time** (Phase 3); reason 4 fires at **emit time** (Phase 4). Real wire bytes from a healthy stack are HMAC outputs (PMKID, MIC) or cryptographically-random nonces, so any of the structural patterns above is firmware stub data, test fixtures, or a mid-flight bit-corruption event -- not crackable material.

The `[invalid_*]` log lines are intended for forensic triage: an operator who wants to see *which* AP / STA / capture-time emitted the bad bytes can grep the log file by any of `kind=`, `ap=`, `sta=`, or the literal hex string. Example:

```sh
wpawolf --22000-out hashes.22000 --log run.log captures/
grep -F 'kind=repeat_1' run.log | wc -l
grep 'pmkid_hex=00000000000000000000000000000000' run.log | head
```

Things that are **not** rejected (despite some of them being unusual):

- **WDS / 4-address relay frames** -- always processed; upstream `hcxpcapngtool` skips them without `--all`.
- **EAPOL frames over 255 bytes** -- always emitted; upstream drops them via `EAPOL_AUTHLEN_OLD_MAX`.
- **Cross-file pairing** -- M1 in file A pairs with M2 in file B.
- **Legacy WPA1 vendor IE handshakes** -- emitted as Type 1.
- **SSIDs with bytes in the ASCII C0 control range (`0x00..=0x1F`)** -- the SSID is still stored and emitted, but a non-fatal `[essid_control_bytes]` log line is written so the operator can audit the source frame. SSIDs that fail the spec-driven length / first-byte-zero gate (length 0, length > 32, or first byte = 0) are silently dropped as wildcard / hidden / spec-invalid; that drop has no `--log` line by design (the volume on noisy captures would be untriageable).

For deeper detail on per-AKM hash routing, dedup behaviour, and the full Phase-1-through-Phase-5 stats catalogue, see [`ARCHITECTURE.md`](ARCHITECTURE.md) §4-§9.

---

## Stats output

Every run prints a closing summary to stderr. There is no toggle — `--quiet` only silences the per-frame progress lines. The Phase 4 and Phase 5 banners are the part most operators care about:

```
=== Phase 4 -- Emit ==========================================
EAPOL pairs generated (total).......................: 142
  N1E2 challenge (ANonce M1, EAPOL M2)..............: 24
  N3E2 authorized (ANonce M3, EAPOL M2).............: 24
  [... four more rows, one per N#E# combo ...]
--22000-out (legacy mode 22000).....................: hashes.22000
  lines written.....................................: 142
--wpa2-out (categories 2+3).........................: wpa2.out
  lines written.....................................: 142
  dedup dropped.....................................: 8

=== Phase 5 -- Report ========================================
hashes emitted (total)..............................: 154
distinct hash types observed........................: 2
```

- `hashes emitted (total)` counts each unique handshake once. Per-file `lines written` rows can sum higher because a handshake configured into two files is written to both.
- Output files are created lazily — configuring `--psk-sha384-out` on a capture with no SHA-384 sessions leaves no zero-byte artefact on disk.
- Each "issue" stat is suffixed with **dropped**, **recovered**, or **diagnostic** so a real loss is distinguishable from a capture-quality note.

Phases 1-3 (capture-format breakdown, per-band counts, per-AKM histograms, garbage-pattern rejection counters for nonces / MICs / PMKIDs, ESSID control-byte warnings, etc.) come before this; the full catalogue is in [`ARCHITECTURE.md`](ARCHITECTURE.md) §9. The N#E# combo names are the `wpawolf` convention; the same six combos appear as `M#E#` in `hcxpcapngtool` source. A translation table is in [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) §6. For a category-by-category list of every reason a hash gets discarded, see "Why a hash gets discarded" above.

---

## Progress reporting

During Phase 1 (ingest) `wpawolf` prints periodic progress lines to stderr so an operator can confirm the run is making forward progress without watching `top`. The lines are on by default; pass `--quiet` (see Runtime options) to suppress them when running under `tee`, in CI, or in a pipeline where stderr noise is unwanted. The closing Phase 1-5 stats banner is unaffected by `--quiet`.

```
[progress] elapsed=15s files=312 packets=4823910 eapol=8412 pmkids=193 rss=287MiB
```

Cadence is hybrid: a line prints whenever 5 seconds OR 2,000,000 packets have elapsed since the previous one, whichever fires first. Small captures (under a few seconds) print at most one line at the end of Phase 1; corpus-scale runs get steady throughput feedback. Fields:

- `elapsed=<s>` -- wall-clock seconds since the run started.
- `files=<n>` -- input capture files opened so far.
- `packets=<n>` -- total packets seen across all files.
- `eapol=<n>` -- EAPOL-Key frames extracted (M1/M2/M3/M4 sum).
- `pmkids=<n>` -- PMKIDs harvested across the 20 spec-defined extraction sites.
- `rss=<n>MiB` -- resident-set size from `/proc/self/statm` (Linux only; field omitted on other platforms).

Every line is prefixed `[progress]` so `grep -v '^\[progress\]' run.log` strips them cleanly.

---

## Proposed hashcat format changes

`wpawolf` writes nine output files. The two legacy ones (`--22000-out`, `--37100-out`) match what `hcxpcapngtool` writes today and feed straight into hashcat modes 22000 and 37100. The other seven (`-o` plus the six per-family flags) write a newer line format that splits every PSK-crackable hash the IEEE 802.11-2024 specification defines into eleven self-contained categories:

| Code | Category               | Code | Category                  |
|------|------------------------|------|---------------------------|
| 1    | WPA1 PSK EAPOL         | 7    | FT-PSK EAPOL              |
| 2    | WPA2 PSK PMKID         | 8    | PSK SHA-384 PMKID         |
| 3    | WPA2 PSK EAPOL         | 9    | PSK SHA-384 EAPOL         |
| 4    | PSK SHA-256 PMKID      | 10   | FT-PSK SHA-384 PMKID      |
| 5    | PSK SHA-256 EAPOL      | 11   | FT-PSK SHA-384 EAPOL      |
| 6    | FT-PSK PMKID           |      |                           |

Categories 8-11 (the SHA-384 families) have no working hashcat kernel today: hashcat's mode 22000 hardcodes a 16-byte MIC, and SHA-384 produces a 24-byte MIC. The lines `wpawolf` writes for those categories are correct and complete, but the cracker side does not yet know how to consume them.

[`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md) sketches two new hashcat modes that close that gap: **mode 22002** (passphrase input, one PBKDF2 pass per ESSID, branches per category afterwards) and **mode 22003** (PMK-direct, skips PBKDF2). One `hashcat -m 22002 all-hashes wordlist.txt` would crack every PSK family the spec defines from a single mixed-format file. The legacy modes 22000, 22001, and 37100 stay in hashcat unchanged.

For the per-category cracker math, the line layout, and the message-pair byte spec, see [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md). For the proposed hashcat-side implementation (loader dispatch, kernel layout, the two phases of the rollout), see [`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md). Both documents are design specifications; nothing in modes 22002 / 22003 ships in upstream hashcat today.

---

## Building

```sh
make dev          # debug build
make build        # release build (native target)
make test         # run the test suite (parity test soft-skips if hcxtools missing)
make check-parity # run the parity test under CI=true (hard-fails on missing oracle)
make check-all    # full CI gate (fmt + clippy + deny + check + test + doc + hygiene + machete)
```

Requires a stable Rust toolchain (see `rust-toolchain.toml`). Once [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) and [`cargo-machete`](https://github.com/bnjbvr/cargo-machete) are installed, `make check-all` runs the complete pre-PR gate. Contributors who need to run the parity test against `hcxpcapngtool` should see [`CONTRIBUTING.md`](CONTRIBUTING.md#parity-oracle-hcxpcapngtool--701).

### Release artifacts (cross-platform)

`make dist` (or bare `make`) detects the host OS / arch and builds artifacts into `dist/`:

| Host                | Outputs                                                                |
|---------------------|------------------------------------------------------------------------|
| Linux x86_64        | `wpawolf-linux-x86_64`         (musl static, runs on any Linux distro) |
| Linux arm64         | `wpawolf-linux-arm64`          (musl static)                            |
| macOS (any)         | `wpawolf-macos-arm64` + `wpawolf-macos-x86_64` + `wpawolf-macos-universal` (lipo fat binary) |
| Windows             | CI-only (native runners required for MSVC / MinGW)                      |

Cutting a multi-platform release: `git tag vX.Y.Z && git push origin vX.Y.Z` triggers `.github/workflows/release.yml`, which builds the full matrix (Linux x86_64 + arm64, Windows MSVC x64/arm64 + GNU x64, macOS arm64 + x86_64 + universal) on native runners, publishes a `SHA256SUMS` signed with cosign keyless, emits SLSA build provenance attestations for every binary, and creates a draft GitHub Release.

---

## License

Apache 2.0. See [`LICENSE`](LICENSE).

---

## Authorized use only

`wpawolf` operates on pcap files you already have on disk. It does not capture traffic, inject frames, or interact with a radio in any way. Running it on captures you do not own or do not have written authorization to analyse is illegal in most jurisdictions. Use `wpawolf` for your own networks, CTF challenges, lab research, and authorized engagements.
