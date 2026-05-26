# WPAWolf Architecture & Reference

This document is the canonical specification for the wpawolf codebase. Source files cite section anchors here (e.g. `§4`, `§8.6`); do not rename or remove them. Reorganise contents only at major-version boundaries.

---

## §1  Project scope

wpawolf is a pure-Rust rewrite of `hcxpcapngtool` that reads pcap, pcapng, and gzip-compressed captures and emits hashcat mode 22000 and 37100 hash lines. Scope: WPA1, WPA2, and WPA3-FT-PSK personal handshake extraction plus PMKID extraction from every spec-defined location. Enterprise (EAP-TLS / PEAP), pure SAE, OWE, WEP, DPP / Wi-Fi Easy Connect, and inner-EAP hash harvest are out of scope for v1. DPP frames provision credentials over public-key exchange instead of a PSK handshake, so they yield nothing crackable as a mode 22000 / 37100 hash and are not parsed beyond the generic action-frame counter.

Primary design goal: **never miss an extractable hash**. Defaults are unfiltered; operators narrow output via output-filter flags. Every hash a conformant reference extractor produces must also appear in wpawolf output (`tests/integration/superset_test.rs` is the regression oracle).

File-only tool: no capture, no injection, no cracking. Authorised use only.

### Tool-landscape niche

| Tool | Lang | pcap/pcapng/gzip | WPA2-PSK | PMKID | FT-PSK | mode 22000 | mode 37100 | Dedup |
|---|---|---|---|---|---|---|---|---|
| **wpawolf** | Rust | yes / yes / yes | yes | yes | yes (no 512 B parse gate) | yes | yes | global SipHash set |
| **hcxpcapngtool** | C | yes / yes / yes | yes | yes | yes (parse cap 512 B; legacy hccap/hccapx output paths drop > 255 B) | yes | yes | full dedup at write time (equivalent to wpawolf) |
| `wpapcap2john` | C (JtR) | pcap only | yes | no | no | no | no | none |
| `wlan2john` | C (JtR) | pcap only | yes | no | no | no | no | none |

Capture-side tools (hcxdumptool, airodump-ng, Kismet) and cracker-side tools (hashcat, JtR) live on the other side of the file boundary wpawolf sits on. They are out of scope.

---

## §2  The 11-Type Hash Classification (summary)

wpawolf classifies every PSK-crackable hash by a unique type code 1-11. The type code is self-contained: it determines the PMKID hash primitive, the PTK KDF, the KCK length, the MIC algorithm, and the MIC field width. Two encoding rules cover the whole table:

```
EVEN code  =  PMKID attack    (no full handshake needed)
ODD  code  =  EAPOL attack    (needs nonce + MIC frame)

Ascending code  =  ascending hash complexity
   01        WPA1 / TKIP            (HMAC-MD5 MIC, PRF-SHA1 PTK)
   02-03    WPA2-PSK                (HMAC-SHA1, 16 B MIC)
   04-05    PSK-SHA256 flat         (HMAC-SHA256, AES-CMAC, 16 B MIC)
   06-07    FT-PSK SHA-256          (FT chain, 16 B MIC, FT extras)
   08-09    PSK-SHA384 flat         (HMAC-SHA384, KDF-SHA384, 24 B MIC)
   10-11    FT-PSK SHA-384          (FT chain + SHA-384, 24 B MIC, FT extras)
```

The eleven canonical names (used verbatim in stats, source code, and output line text):

| # | Name                       | AKM (selector)   | KDV |
|---|----------------------------|------------------|-----|
| 1 | WPA1-PSK-EAPOL             | WPA1 vendor IE   | 1   |
| 2 | WPA2-PSK-PMKID             | 2 (`00:0F:AC:02`) | --  |
| 3 | WPA2-PSK-EAPOL             | 2                | 2   |
| 4 | PSK-SHA256-PMKID           | 6 (`00:0F:AC:06`) | --  |
| 5 | PSK-SHA256-EAPOL           | 6                | 3   |
| 6 | FT-PSK-PMKID               | 4 (`00:0F:AC:04`) | --  |
| 7 | FT-PSK-EAPOL               | 4                | 3   |
| 8 | PSK-SHA384-PMKID           | 20 (`00:0F:AC:14`) | --  |
| 9 | PSK-SHA384-EAPOL           | 20               | 0   |
| 10 | FT-PSK-SHA384-PMKID       | 19 (`00:0F:AC:13`) | --  |
| 11 | FT-PSK-SHA384-EAPOL       | 19               | 0   |

**See [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) for the deep dive:** the encoding rules, per-type cracker math (PBKDF2 -> PMK -> PMKID / PTK / MIC paths), the differential view between adjacent rows, the shared-subtree map a cracker can cache, the complete hash-line field layout including the 24 B MIC SHA-384 split, the full message-pair byte specification (combo discriminant + APLESS / NC / LE / BE flag bits, plus the separate PMKID-line PMKID_AP / PMKID_CLIENT / PMKID_APPSK256 byte values), and the N#E# vs M#E# notation translation table.

For how the 11 types currently route through hashcat modes 22000 and 37100 (legacy four-prefix scheme, the `keyver` trick, support matrix per row), see [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md). For a sketch of a unified hashcat module (mode 22001) that consumes all 11 types, see [`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md).

For how `wpawolf` writes lines and which CLI flags route hashes to which sink, see [`README.md`](README.md).

### §2.2  Where the deep detail lives

The deep per-type detail (PBKDF2 shared foundation, per-type post-PMK computation, hash-line format with field widths, differential view between adjacent rows, shared-subtree overlap map, and the complete message-pair byte specification including PMKID-line semantics) lives in [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md). How those 11 types are reached through current hashcat (modes 22000 + 37100, the four legacy prefixes, the `keyver` trick, per-row support matrix) is in [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md). The unified-module sketch (mode 22001) for a future kernel that consumes all 11 types is in [`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md). The operator-facing CLI / output-sink reference lives in [`README.md`](README.md). This document focuses on `wpawolf`'s architecture decisions only.

| Looking for...                                       | Read this                                    |
|------------------------------------------------------|----------------------------------------------|
| Cracker math for type N                              | [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) §4 |
| Hash-line field layout / widths                      | [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) §5 |
| N#E# vs M#E# notation; what triggers each combo      | [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) §6 |
| Message-pair byte spec (EAPOL + PMKID)               | [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) §7 |
| Current hashcat 4-prefix scheme + per-row support    | [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md) §3 -- §8 |
| `keyver` byte trick (how WPA*02* fans out)           | [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md) §4 |
| What a future hashcat module must implement          | [`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md) §3 -- §6 |
| `wpawolf` CLI flags, output sinks, examples          | [`README.md`](README.md) |
| How `wpawolf` stays drop-in for current hashcat      | [`README.md`](README.md) + [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md) §7 |
| Current state and quality bar                        | [`CHANGELOG.md`](CHANGELOG.md) |

The 11 types differ in exactly four dimensions after the PMK step: **PMKID hash primitive**, **PTK KDF**, **KCK size**, and **MIC algorithm
+ size**. FT variants (types 6, 7, 10, 11) also add an intermediate PMK-R0 -> PMK-R1 hierarchy step before the PTK, which requires MDID, R0KH-ID, and R1KH-ID in the hash line. See `HASHCAT-NEW-FORMATS.md` §4 for the algebra.

### §2.3  Type-routing decision tree

```
EAPOL (odd codes): KDV first, FTIE second, AKM IE only as refiner
  Tier 1: KDV byte (key_info bits 0..2)
    KDV=1 ─────────────────────────────────────────────────► Type 1    [closed]
    KDV=2 ──┬─ FTIE absent ─────────────────────────────────► Type 3    [closed]
            └─ FTIE present ─ AKM=4 ────────────────────────► Type 7    [via Tier 3]
    KDV=3 ──┬─ FTIE absent ─────────────────────────────────► Type 5    [closed]
            └─ FTIE present ─┬─ AKM=4 ──────────────────────► Type 7
                             └─ AKM=19 ─────────────────────► Type 11
    KDV=0 ──┬─ FTIE absent + AKM=20 ────────────────────────► Type 9
            └─ FTIE present + AKM=19 ──────────────────────► Type 11

PMKID (even codes): no KDV; AKM IE only, scoped strongest first
  AKM=2  ──► Type 2     (WPA1+PMKID vendor quirk also lands here)
  AKM=6  ──► Type 4
  AKM=4  ──► Type 6
  AKM=20 ──► Type 8
  AKM=19 ──► Type 10
```

## §3  The 5-phase pipeline

wpawolf is a batch pipeline. The five phases run strictly in order; each phase reads from the previous phase's outputs and writes its own.

```
+-----------+    +----------+    +----------+    +--------+    +---------+
|  Ingest   | -> |  Decode  | -> | Extract  | -> |  Emit  | -> | Report  |
|           |    |          |    |          |    |        |    |         |
| pcap/ng/  |    | radiotap |    | mgmt/    |    | pair/  |    | stats   |
| gzip read |    | + 802.11 |    | data/    |    | dedup/ |    | summary |
| -> packet |    | -> frame |    | aux ->   |    | write  |    | per     |
|           |    |          |    | stores   |    |        |    | phase   |
+-----------+    +----------+    +----------+    +--------+    +---------+
   (I/O)         (CPU, fast)     (CPU, fast)     (CPU + I/O)   (stdout)
```

| Phase | Crate path | Input | Output | Bound |
|-------|------------|-------|--------|-------|
| §3.1 Ingest  | `src/input/`              | file paths | `Packet { timestamp_us, interface_id, data }` records | I/O |
| §3.2 Decode  | `src/link/` + `src/ieee80211/` | raw packets | parsed 802.11 frames + IEs + EAPOL | CPU |
| §3.3 Extract | `src/extract/` + `src/store/` | parsed frames | populated stores keyed by `MacPair` | CPU |
| §3.4 Emit    | `src/pair/` + `src/output/`   | populated stores | hashcat lines + auxiliary files | CPU + I/O |
| §3.5 Report  | `src/stats.rs`             | counters from all earlier phases | summary on stdout | I/O |

Phase 1 dominates wall time on warm caches at NVMe speeds (~50-500x phase 2). Phase 4 is parallelised via rayon work-stealing (`--threads N`, default = CPU count; `--threads=1` for reproducible output). Pairs are streamed per-group through a Mutex-serialized fan-out callback so peak memory is bounded to one group's pairs at a time. Every shared structure is `Send + Sync` (see §4 invariant 9).

### Module DAG

```
main --> input --> link --> ieee80211 --> extract --> store --> pair --> output
           |                    |                      |                    |
           +--------------------+----------------------+-------------------> types
                                                                            stats
                                                                            log
```

No circular dependencies. Each layer depends only on layers to its right plus the three shared modules (`types`, `stats`, `log`).

### §3.1  Phase 1 - Ingest

`src/input/` reads files, detects format by magic bytes (FR-IN-2), dispatches to the streaming parser, and yields:

```rust
pub struct Packet {
    pub timestamp_us: u64,
    pub interface_id: u32,
    pub data: Vec<u8>,
}
```

The link type (DLT) is not stored per-packet; it lives on the reader's per-interface metadata and is retrieved via `reader.link_type(interface_id)` when Phase 2 needs it.

Sub-modules: `mod.rs` (format detection + dispatch); `pcapng.rs` (SHB / IDB / EPB streaming, per-section endianness, per-interface `if_tsresol` and `if_tsoffset`); `pcap.rs` (ten magic variants: standard LE/BE, nanosecond LE/BE, Kuznetzov LE/BE, IXIA HW LE/BE, IXIA SW LE/BE); `gzip.rs` (`flate2::read::GzDecoder<R>`, re-detects inner format).

One block / record at a time. I/O buffer 64 KiB (FR-MEM-2). EOF mid-record logs the offset and stops the file (FR-IN-10); multi-file runs continue with the next file. Phase 1 owns no protocol knowledge above the file container.

### §3.2  Phase 2 - Decode

`src/link/` strips the radio metadata header; `src/ieee80211/` parses 802.11 frames and tagged parameters.

`src/link/`: `radiotap.rs` (DLT 127, LE, variable `it_len`, multi-word `it_present`); `ppi.rs` (DLT 192, `pph_dlt` must be 105); `prism.rs` (DLT 119, host byte order, AVS-within-Prism detection via BE magic `0x80211xxx`); `avs.rs` (DLT 163, BE per spec - hcxtools treats as LE which is a documented bug we refuse to replicate, with the deviation commented at the parse site per the project's wire-spec convention).

`src/ieee80211/`: `frame.rs` (MAC header per `[IEEE 802.11-2024]` §9.2.4.1, address mapping Table 9-60, WDS first-class per §4 invariant 4); `ie.rs` (IE TLV walker for SSID, SSID List tag 84, Mesh ID tag 114, Country, vendor AP names, OWE Transition Mode, CCX1, WPS); `rsn.rs` (RSN IE tag 48: version, group cipher, pairwise list, AKM list, RSN caps, PMKID list, group management cipher per §9.4.2.24); `ft.rs` (MDE tag 54 for MDID, FTE tag 55 subelement 3 for R0KH-ID 1-48 B, subelement 1 for R1KH-ID 6 B per §9.4.2.45, §9.4.2.46); `eapol.rs` (EAPOL-Key per §12.7.2, M1/M2/M3/M4 from Key Information bits per Table 12-10, KDV validation per Table 12-11); `eap.rs` (EAP per RFC 3748 §4 - identity Type 1 and inner-method username); `amsdu.rs` (A-MSDU subframe iteration per §9.3.2.2.2); `anqp.rs` (ANQP element parsing for venue / domain / NAI realm extraction).

Pure parsing: no I/O, no allocation beyond owned struct payloads, trivially testable with byte literals.

### §3.3  Phase 3 - Extract

`src/extract/` (new module - see TaskList commit 3) hosts the per-frame handlers that decide what each parsed frame contributes to the stores. The handlers run as a single match on frame type and route extracted data into `src/store/`:

```rust
match frame.subtype {
    Beacon | ProbeResponse => extract_essid_and_akm(frame),
    ProbeRequest           => extract_probe_essid(frame),
    AssocRequest           => extract_assoc_pmkid_and_ft(frame),
    ReassocRequest         => extract_reassoc_pmkid_and_ft(frame),
    Auth { algo: 2, .. }   => extract_ft_auth_pmkid(frame),         // S5/S6
    Auth { algo: 4|5, .. } => extract_fils_auth_pmkid(frame),       // S7/S8
    Auth { algo: PASN, .. }=> extract_pasn_auth_pmkid(frame),       // S9/S10
    Action { cat: 6, .. }  => extract_ft_action_pmkid(frame),       // S11-S13
    Action { cat: 15, .. } => extract_mesh_peering_pmkid(frame),    // S18/S19
    Data EAPOL-Key M1..M4  => extract_eapol_msg_and_pmkid(frame),   // S1/S2
    Data EAP               => extract_eap_identity_username(frame),
    _                      => stats.skipped += 1,
}
```

`src/store/` holds Phase-3 outputs / Phase-4 inputs: `messages.rs` (`MessageStore = HashMap<MacPair, Vec<EapolMessage>>` per FR-MSG-1, no eviction); `pmkid.rs` (`PmkidStore` with each entry tagging its S1-S20 origin via `PmkidSource`); `essid.rs` (`EssidMap`, multi-entry per AP for SSID changes); `auxiliary.rs` (`EssidSet`, `ProbeEssidSet`, `WordlistStore`, `IdentitySet`, `UsernameSet`, `DeviceInfoStore` - lazy-initialised, zero overhead if the corresponding flag is unset).

Phase 3 enforces the §4 invariant 7 rejection rules and emits `[invalid_nonce]` / `[invalid_mic]` / `[invalid_pmkid]` log entries when `--log` is set.

#### EAPOL transport-vector inventory

Every spec-defined path that can carry an EAPOL-Key M1 / M2 / M3 / M4 frame, plus the closely-related PMKID-bearing action frames. This table is the canonical answer for "does wpawolf catch EAPOL hidden in encapsulation X?" and is regression-tested by `tests/integration/eapol_transport_vectors.rs`.

| # | Vector | Spec | Coverage | Notes |
|---|---|---|---|---|
| 1 | LLC/SNAP `EtherType` `0x888E` Data frame | §9.3, §12.7 | done -- `extract::data` | Standard BSS uplink/downlink; ~95 % of all real EAPOL traffic. |
| 2 | A-MSDU subframe carrying EAPOL | §9.7.2 | done -- `ieee80211::amsdu` | Iterates every subframe; outer (AP, STA) is authoritative. |
| 3 | MSDU fragmentation (multi-fragment EAPOL) | §9.2.4.4 | done -- `store::fragments` | Reassembly key `(SA, RA, SeqNum)`; bounded `MAX_ENTRIES = 1024` with oldest-first eviction. WDS fragmentation is out of scope for v1 (single-MPDU WDS works). |
| 4 | 4-address WDS / relay frame | §9.3.2.1.2 | done -- `extract::wds` Phase 1.5 | Three-tier ladder (essid_map / ACK discovery / flag fallback); see §5.12. |
| 5 | Mesh Data frame with Mesh Control header | §9.2.4.8.3 | done -- `extract::data::process_msdu_payload` | 6 / 12 / 18-byte header decoded from QoS Control bit B0; reserved Address-Extension Mode `11` skipped silently. Counter `mesh_control_frames`. |
| 6 | A-MPDU PHY-layer aggregation (raw delimiter stream) | §9.7.1, §10.12 | depends on PCAP source | Modern pcap drivers (mac80211, iwlwifi) split A-MPDU into individual MPDUs before delivery. radiotap A-MPDU Status field (it_present bit 20) is decoded for visibility (`stats.ampdu_status_frames`); raw-delimiter walking is not implemented because no in-the-wild capture has demonstrated raw aggregation. |
| 7 | Encrypted M3 / M4 (Protected Frame bit set) | §12.7.2.1 NOTE | not applicable | Decrypting M3 / M4 requires the PTK -- which is what cracking *produces*. Out of scope. |
| 8 | FILS HLP Container element | §9.4.2.182 | not applicable | HLP carries DHCP / ARP per spec, not EAPOL. FILS PMKID is harvested at S7 / S8 from the FILS Authentication exchange. See §6.9 "FILS HLP Container is not an EAPOL transport". |
| 9 | Mesh Peering Open / Confirm action frame (AMPE Chosen-PMK) | §9.6.15.2-3, §14.3.5 | done -- `extract::action` | PMKID extracted from AMPE element body (last 16 bytes); sources S18 / S19. No 4-way handshake exists in mesh AMPE; the AMPE element directly conveys the chosen PMK identifier. |
| 10 | Pre-authentication `EtherType` `0x88C7` over the air | §12.3.2 | done -- `extract::common::is_preauth_llc` | Same EAPOL-Key parse path as `0x888E`; counted separately as `eapol_preauth_frames`. |

Items 1-5, 9, 10 are all live transport vectors with end-to-end coverage. Items 7, 8 are spec features that are not EAPOL transports (item 7 because decryption requires the very key being cracked; item 8 because HLP is for DHCP / ARP, not EAPOL). Item 6 is decoded only as a visibility counter -- a reproducer pcap is the gate to add the delimiter walker.

### §3.4  Phase 4 - Emit

`src/pair/` runs the pairing engine; `src/output/` formats and writes.

`src/pair/`:

- `combos.rs` generates the 6 N#E# combos (FR-PAIR-2):

  | Combo | Needs | External Nonce | EAPOL From | mp bits 0-2 |
  |-------|-------|----------------|------------|-------------|
  | N1E2  | M1+M2 | ANonce from M1 | M2 | 0x00 |
  | N1E4  | M1+M4 | ANonce from M1 | M4 | 0x01 |
  | N3E2  | M3+M2 | ANonce from M3 | M2 | 0x02 |
  | N2E3  | M2+M3 | SNonce from M2 | M3 | 0x03 |
  | N4E3  | M4+M3 | SNonce from M4 | M3 | 0x04 |
  | N3E4  | M3+M4 | ANonce from M3 | M4 | 0x05 |

- `constraints.rs` applies the optional output filters:
  - `--eapoltimeout[=N]` enforces a session time window in seconds.
  - `--rc-drift[=N]` enforces replay-counter consistency with tolerance N.
  - LE/BE nonce-endianness detection always runs; the result is folded into the message_pair byte when set.

- `collapse.rs` reduces the 6 combos to 3 equivalence classes per session when `--dedup-hash-combos` is set (FR-PAIR-5). See §5.

`src/output/`:

- `hashcat.rs` formats `WPA*01*` through `WPA*11*` lines. The MIC field in `<EAPOL>` is zeroed at format time per FR-OUT-8.
- `wordlists.rs` writes `-E`, `-R`, `-W`, `-I`, `-U` files in autohex form (NUL trim per `crate::types::trim_nul_padding`).
- `device_info.rs` writes `-D` (deduped by MAC, sorted by manufacturer).
- `dedup.rs` is the `HashSet<u64>` SipHash-1-3 fingerprint gate. PMKID and EAPOL fingerprints have disjoint field sets prefixed by the hash-line kind byte (see §7).

The two pipelines run strictly in order: the PMKID emission pass runs to completion before the EAPOL pairing pass starts (both within `OutputContext::emit_inner()`). They share only the dedup set and the `BufWriter`. See OUT-1 in §4 invariant 6.

### §3.5  Phase 5 - Report

`src/stats.rs` owns every counter the four earlier phases increment. The Phase 5 report prints the summary unconditionally to stderr at the end of every run. There is no `--stats` toggle: suppressing the summary would hide exactly the information an operator needs to know whether the capture was any good.

The summary is hcxpcapngtool-shaped - anyone who has read `hcxpcapngtool` output should be able to read wpawolf output without a glossary. We match hcxpcapngtool's line set as the floor and add more where the upstream tool is missing data. See §9 for the full counter inventory.

The summary is organised as five banner sections, one per pipeline phase, so an operator can immediately see which phase a parse failure occurred in:

```
=== Phase 1 (Ingest) ===     packets, endianness, malformed blocks, FCS framing
=== Phase 2 (Decode) ===     per-DLT counts, radiotap/PPI/Prism mismatches
=== Phase 3 (Extract) ===    mgmt subtypes, EAPOL M1/M2/M3/M4, PMKIDs by source
=== Phase 4 (Emit) ===       pairs, combos, dedup decisions, lines per output file
=== Phase 5 (Report) ===     wallclock, counters not surfaced elsewhere
```

NMEA / GPS summary lines are emitted only when a GPS-bearing pcapng was observed. v1 counts them; structured GPS output is deferred to v2 via `--nmea-out`.

---

## §4  Critical invariants

These are the non-negotiable rules of the codebase. Violating any of them is a regression even if "it still works." Source code references each rule by number (e.g. `// see ARCHITECTURE.md §4 invariant 2`).

### 1. No unsafe code

`Cargo.toml` declares `unsafe_code = "forbid"` and `lib.rs` re-states `#![forbid(unsafe_code)]` at the crate root. Pure-safe Rust only. Binary parsing uses `TryInto`, `from_le_bytes` / `from_be_bytes`, `slice::get`, and bounds-checked indexing. If a contributor thinks they need `unsafe`, they are wrong - file a discussion before opening a PR.

### 2. Collect-then-pair (no stream pairing, no eviction)

All EAPOL messages for an `(AP, STA)` pair go into `HashMap<MacPair, Vec<EapolMessage>>` first. Pairing runs in §3.4 on the complete per-group message set. There is no ring buffer, no eviction, and no per-type message cap. If RSS exceeds 80 % of system RAM during Phase 1 ingestion or Phase 4 pairing, the process aborts with a clear "approaching OOM" message. Use `--per-file` to bound memory on large corpora.

This is the single most important architectural difference vs upstream hcxpcapngtool. Their implementation pairs on arrival using a 64-entry shared ring (`MESSAGELIST_MAX = 64`); when the 65th message arrives without a successful pair, the oldest is silently dropped. wpawolf cannot miss a valid pair regardless of message ordering or interleaving from other AP/STA pairs because pairing never runs on a partial set.

The memory cost is acceptable because EAPOL frames are a tiny fraction of total traffic. A 100 GB capture at 100 B/packet average is roughly 1 billion packets; EAPOL frames are 0.01-0.1% of that, i.e. 1K-1M messages. At ~250 bytes per stored message, 1M messages is ~250 MiB.

### 3. No EAPOL size gate

Upstream drops EAPOL frames > 255 B via `EAPOL_AUTHLEN_OLD_MAX`. wpawolf emits every valid EAPOL-Key frame regardless of length. FT-PSK M2 frames in real captures reach 510 B because the Key Data contains a full RSN IE plus MDE plus FTE; hcxtools silently truncates these. wpawolf does not. If hashcat refuses an oversized frame today, that is hashcat's bug to fix - mode 37100 PR #4645 raised the buffer to 1024 bytes for exactly this reason.

### 4. Relay frames are first-class

Upstream skips WDS frames (To DS = 1, From DS = 1) unless `--all` is passed. wpawolf always processes them. The frame parser handles all four To-DS / From-DS combinations per `[IEEE 802.11-2024]` Table 9-60. Relay frames carry valid handshakes between repeaters and upstream APs; skipping them means missing hashes.

There is no flag to opt out. WDS frames are counted in `stats.wds_count` for observability.

### 5. Global SipHash dedup

The dedup filter is `HashSet<u64>` of SipHash-1-3 fingerprints over the significant hash fields. `HashMap` and `HashSet` use the default hasher, which is HashDoS-resistant against crafted MACs.

For PMKID lines the fingerprint is:

```
SipHash-1-3( line_kind_byte || PMKID || MAC_AP || MAC_STA || ESSID )
```

For EAPOL lines:

```
SipHash-1-3( line_kind_byte || MIC || MAC_AP || MAC_STA || NONCE || EAPOL || ESSID )
```

This is a global filter. Duplicates separated by hours of capture are still caught. The line-kind byte prefix prevents a PMKID value that happens to equal a MIC value from aliasing across pipelines. (hcxpcapngtool uses an internal 20-entry look-back ring in `cleanbackhandshake` as a speedup, then a full dedup at write time; the two tools are therefore equivalent at the output boundary.)

### 6. PMKID and EAPOL pipelines are strictly separate (OUT-1)

PMKID-derived hashes and EAPOL-derived hashes traverse separate pipelines. A PMKID is emitted independently of whether any M2/M3/M4 is ever seen for the same `(AP, STA)`. Conversely, a complete 4-way handshake is emitted regardless of whether a PMKID was also present. The two pipelines share only the ESSID resolution step and the dedup filter (§4 invariant 5).

A single `(AP, STA)` session can legitimately yield up to four distinct hashcat lines: 1 PMKID plus up to 3 equivalence-class EAPOL pairs. This is correct and expected; downstream tools that expect one line per session are wrong.

Enforcement: the PMKID emission pass within `OutputContext::emit_inner()` runs to completion before the EAPOL pairing pass starts. The two passes take disjoint store references and write into the same `BufWriter` only after the dedup filter accepts the line. No control-flow path collapses the two.

### 7. Garbage-pattern nonce / MIC / PMKID rejected unconditionally; ESSID gets a non-fatal warning

Invalid sentinel values and short-period repeating patterns are rejected at parse time and store insertion **for cryptographic fields only**. There is no flag to disable these rejections; they are firmware artifacts with no cracking value. Real wire bytes from a healthy stack are HMAC outputs / random nonces and never carry these shapes.

The detector (`types::garbage_pattern_kind`) classifies a byte run into one of five mutually-exclusive kinds, in priority order:

| Kind | Pattern | Notes |
|---|---|---|
| `null` | every byte is `0x00` | Fires at any length |
| `ff` | every byte is `0xFF` | Fires at any length; NOR-flash erase value |
| `repeat_1` | every byte equals the first byte (other than `0x00` / `0xFF`) | Length `>= 4` so short fields are never flagged |
| `repeat_2` | 2-byte alternating period (e.g. `5555AAAA`) | Length multiple of 2 and `>= 4` |
| `repeat_4` | 4-byte repeating period (e.g. `01020304...`) | Length multiple of 4 and `>= 8` |

Per-field rejection matrix:

| Field | Rejected kinds | Spec-valid exception |
|-------|----------------|----------------------|
| Nonce M1, M2, M3, M4 | every kind | -- |
| MIC on frame with `Key MIC Present` set (M2/M3/M4) | every kind | -- |
| MIC on M1 (`Key MIC Present` cleared) | not checked | M1 MIC is legitimately zero |
| PMKID (any source) | every kind | -- |

M4 NULL nonce is spec-valid on the wire per [IEEE 802.11-2024] §12.7.6.5 NOTE 9 ("M4 Key Nonce SHALL be zero") but is dropped at extract: an EAPOL hash line built from such an M4 is mathematically uncrackable because the live PTK depends on M2's `SNonce`, which the M4 frame does not carry. Combining the M4 NULL with M3's ANonce in an N3E4 line, or with M3's EAPOL body in an N4E3 line, yields the PTK input pair `(NULL, M3_ANonce)` which does not reproduce the live PTK. The drop matches hcxpcapngtool's `eapolm4zeroedcount++; return;` gate at `hcxpcapngtool.c:3636`. Non-conforming firmware that copies M2's `SNonce` into M4 (the other half of NOTE 9) still passes the gate -- those frames carry a non-NULL nonce and produce a crackable line.

**ESSIDs are not garbage-filtered and not transformed.** Per [IEEE 802.11-2024] §9.4.2.2 the SSID element is "an arbitrary sequence of 0-32 octets" with no printable-character restriction. A repeating-byte or all-`0xFF` SSID is unusual but not "garbage" the way an all-`0xFF` HMAC output is -- the cracker may still recover the right PMK from such an SSID. The spec-driven discard rule stays unchanged (length 0 wildcard, length > 32 spec violation, first byte 0 hidden-network sentinel; mirrors hcxtools `fileops.c:72-86`). On top of that, SSIDs that survive the gate but contain at least one byte in `0x00..=0x1F` (the full ASCII C0 control range, NUL through US -- every control character) emit an `[essid_control_bytes]` log line with the SSID rendered in lowercase hex and tick the `essid_control_bytes_warned` counter. **This is informational, not a discard and not a notice that wpawolf altered the SSID** -- the byte run is shipped to hashcat unchanged at every output sink; the counter and log line exist only to help an operator locate the source frame when triaging a capture.

Each rejection / warning increments a dedicated counter:

```
stats.null_nonce_rejected   stats.ff_nonce_rejected   stats.repeat_nonce_rejected
stats.null_mic_rejected     stats.ff_mic_rejected     stats.repeat_mic_rejected
stats.null_pmkid_rejected   stats.ff_pmkid_rejected   stats.repeat_pmkid_rejected
stats.essid_control_bytes_warned
```

Rejected frames generate `[invalid_nonce]` / `[invalid_mic]` / `[invalid_pmkid]` log entries when `--log` is set; each line carries the kind string and the rejected bytes in lowercase hex (`nonce_hex=` / `mic_hex=` / `pmkid_hex=`) so downstream tooling can filter by pattern and an operator can grep the source capture for the exact byte sequence that triggered the drop. Control-byte SSIDs generate informational `[essid_control_bytes]` log entries with `essid_hex=` carrying the raw bytes in lowercase hex; the SSID itself is shipped to hashcat unchanged.

### 8. Every wire constant cites the spec

Flags, tag numbers, lengths, OUIs, struct offsets - each one has a trailing comment naming `[IEEE 802.11-2024]` §X.Y.Z, RFC ZZZZ §X, the hcxtools reference line, or (when the spec and observed behaviour disagree) both the spec citation and the deviation. Example:

```rust
const RSN_IE_TAG: u8 = 48;          // [IEEE 802.11-2024] §9.4.2.24.1
const PMKID_KDE_TYPE: u8 = 0x04;    // [IEEE 802.11-2024] Table 12-8
const AVS_HEADER_BE: bool = true;   // libpcap gencode.c:3479; hcxtools
                                    // treats as LE - bug not replicated.
```

No heuristic `_looks_valid()` checks. No "this byte pattern looks like an EAPOL frame" inference. Every decoding decision must be flag-driven from a documented field.

### 9. Send + Sync by default; no Rc / Cell / thread-local state

Phase 4 is parallelised via rayon work-stealing (`--threads N`, default = CPU count, `--threads=1` for reproducible output). Each group is paired lock-free in a rayon worker; the resulting pairs are fanned out through a `Mutex<EmitState>` that serializes dedup checks and buffered writes. Every shared structure is `Send + Sync`. No `Rc`, no `Cell`, no `thread_local!`. `MacAddr`, `MacPair`, `MsgType`, `AkmType` are all `Copy`. The stores hold `Vec<T>` of owned data; pairing reads via shared references.

### 10. Error propagation via custom enum; I/O aborts, parse errors continue

The crate defines `enum Error { ... }` with manual `Display` and `std::error::Error` impls. There is no `anyhow`, no `thiserror`. The custom enum keeps the proc-macro dep budget low (see invariant 11).

Error policy:

- **I/O errors abort.** A read failure, write failure, or disk-full condition returns `Err` from the offending function and propagates to `main`, which prints the error and exits non-zero. The run does not continue with the next file.
- **Parse errors log-and-continue.** A truncated pcapng block, a malformed 802.11 frame, an EAPOL-Key with bad KDV, a PMKID with a rejected sentinel value - none of these abort the run. Each increments a stats counter and (when `--log` is set) writes a structured log entry.

### 11. Minimal dependency budget

Direct runtime dependencies: 4 crates -- `flate2` (gzip, `rust_backend`-only feature), `clap` (CLI, derive), `rayon` (parallel Phase 4 pairing via work-stealing), and `sysinfo` (cross-platform RSS + total-RAM queries for OOM detection and `--debug` memory reporting). New deps require a paragraph-long justification in the PR body. Rejected crates: `pcap-file` / `pcap-parser` (8-10 transitive deps for ~500 lines we write); `ieee80211` (9 mandatory deps for a fraction of its features); `serde`, `regex`, `tokio`, `anyhow`, `thiserror`, `hex`, `nom` (each replaceable inline or out of scope). Future cryptographic primitives may use RustCrypto (`sha1`, `md-5`, `aes`, `cmac`, `hmac`). `cargo deny` (`deny.toml`) gates the supply chain: OSI-permissive licenses only, no unknown registries, no git deps.

### Memory budget (informational)

No artificial ceiling. Two compaction passes shape the runtime footprint: `EssidMap` SSID bodies are interned through an `Arc<[u8]>` set so identical SSID broadcasts across APs share one heap allocation, and `MessageStore::add` dedups byte-identical EAPOL frames at insert by `(msg_type, akm, eapol_frame)` so retransmitted M2 / M4 frames collapse before pair generation runs. The runtime is dominated by `MessageStore`, then `EssidMap`, `AkmMap`, `PmkidStore`, `EssidSet`, and the global `DedupSet` (~one `u64` per emitted line). Empirically the footprint scales roughly linearly with input size at well under one GiB per few GiB of mixed-vendor capture data after the compaction passes. wpawolf does not introspect its own memory footprint; operators run `/usr/bin/time -v` or `perf stat` for an authoritative number, or pass `--mem-stats` to print a per-store table at the end of the run.

---

## §5  EAPOL / 4-way handshake

### §5.1  What the handshake does

The 4-way handshake derives the PTK without transmitting it. Both sides start from a shared PMK (PBKDF2-HMAC-SHA1 of passphrase+SSID for PSK; EAP MSK for enterprise) and combine it with ANonce, SNonce, AP MAC, and STA MAC via the AKM-specific PRF/KDF. The PTK splits into KCK (MIC key for M2/M3/M4), KEK (encrypts M3 Key Data), and TK (data encryption key).

### §5.2  The four messages

```
AP                                           Client
|                                               |
|------- M1: ANonce --------------------------->|
|        (Key Ack=1, MIC=0)                     |
|        Contains: ANonce, [PMKID in Key Data]  |
|                                               |
|<------ M2: SNonce + MIC ----------------------|
|        (Key Ack=0, MIC=1, Secure=0)           |
|        Contains: SNonce, MIC, RSN IE          |
|                                               |
|------- M3: Install + Encrypted GTK ---------->|
|        (Key Ack=1, MIC=1, Install=1, Enc=1)   |
|        Contains: ANonce, MIC, Encrypted GTK   |
|                                               |
|<------ M4: Confirmation ----------------------|
|        (Key Ack=0, MIC=1, Secure=1)           |
|        Contains: MIC only                     |
|                                               |
              [data encryption begins]
```

- **M1** carries ANonce; if PMKSA caching is in use the AP includes the precomputed PMKID in the Key Data (location S1; §6).
- **M2** carries SNonce, the client's RSNE, and the first MIC. Primary cracker target.
- **M3** confirms the AP computed the same PTK (via M2's MIC) and ships the encrypted GTK plus its own MIC.
- **M4** confirms PTK installation; final MIC.

### §5.3  EAPOL-Key frame layout

Per `[IEEE 802.11-2024]` §12.7.2 Figure 12-35. Offsets are from the start of the EAPOL-Key body (after the 4-byte EAPOL header):

```
Offset  0: Descriptor Type     (1 B) -- 0x02 = RSN, 0xFE = WPA (legacy)
Offset  1: Key Information     (2 B, BE) -- bit-packed control word
Offset  3: Key Length          (2 B)
Offset  5: Replay Counter      (8 B, BE) -- monotonic, AP-incremented
Offset 13: Key Nonce           (32 B) -- ANonce or SNonce
Offset 45: Key IV              (16 B) -- zeroed for WPA2; nonzero for TKIP
Offset 61: Key RSC             (8 B)
Offset 69: Reserved            (8 B)
Offset 77: Key MIC             (16 B for AKMs 1-6, 8, 9, 11; 24 B for AKMs 12, 13, 19, 20, 22, 23)
Offset 77+MIC_len: Key Data Length (2 B)
Offset 79+MIC_len: Key Data    (variable)
```

For output formatting (FR-OUT-8) the parser stores the EAPOL-Key frame verbatim including the original MIC bytes. At emit time `output/hashcat.rs` makes a copy with the MIC field zeroed (offset 77 .. 77+MIC_len) and writes the original MIC bytes into the `<MIC>` hash-line field. hashcat recomputes the MIC from a candidate password and compares against `<MIC>`.

Key Information bit layout per §12.7.2 Figure 12-36:

```
Bits 0-2:  Key Descriptor Version (KDV)
Bit  3:    Key Type (1 = Pairwise)
Bit  6:    Install
Bit  7:    Key Ack (1 in M1 and M3)
Bit  8:    Key MIC Present (1 in M2, M3, M4)
Bit  9:    Secure (1 in M3, M4, and M1/M2 for rekeying)
Bit 12:    Encrypted Key Data (1 in M3)
```

M1/M2/M3/M4 identification per `[IEEE 802.11-2024]` Table 12-10:

| Message | Key Ack | Key MIC | Install | Secure | Nonce |
|---------|---------|---------|---------|--------|-------|
| M1 | 1 | 0 | 0 | 0 (initial) or 1 (rekey) | non-zero (ANonce) |
| M2 | 0 | 1 | 0 | 0 (initial) or 1 (rekey) | non-zero (SNonce) |
| M3 | 1 | 1 | 1 | 1 | non-zero (ANonce, repeat of M1) |
| M4 | 0 | 1 | 0 | 1 | all-zero (or SNonce copy - see §12.7.6.5 NOTE 9) |

### §5.4  KDV and MIC algorithm mapping

Per `[IEEE 802.11-2024]` §12.7.2 Table 12-11:

| KDV | MIC algorithm | MIC size | When used |
|-----|---------------|----------|-----------|
| **1** | HMAC-MD5-128 | 16 B | WPA1-PSK (TKIP cipher, `00-50-F2:01`) |
| **2** | HMAC-SHA-1-128 | 16 B | WPA2-PSK (AKM 2) with any pairwise cipher |
| **3** | AES-128-CMAC | 16 B | AKMs 3, 4, 5, 6 - required by 802.11w / PMF AKMs |
| **0** | determined by AKM (see below) | varies | AKMs 8, 11-18, 22-25 |

When KDV = 0, the MIC algorithm is implicit from the negotiated AKM:

| AKM | MIC when KDV=0 |
|-----|----------------|
| 8, 9 (SAE) | AES-128-CMAC, 16 B |
| 11 (Suite B-128) | HMAC-SHA-256, 16 B |
| 12, 13 (Suite B-192 / CNSA) | HMAC-SHA-384, **24 B** |
| 14-17 (FILS) | AES-SIV AEAD, **0 B** (no explicit MIC) |
| 19, 20 (PSK-SHA384) | HMAC-SHA-384, **24 B** |
| 22, 23 (802.1X-SHA384) | HMAC-SHA-384, **24 B** |
| 24, 25 (SAE H2E) | AES-128-CMAC, 16 B |

AKMs 19 and 20 produce a 24-byte MIC. Existing hashcat mode 22000 expects a 16-byte MIC; emitting a truncated 24-byte MIC would be the same silent wrong-answer trap as the AKM-6 PMKID SHA1/SHA256 mismatch. These AKMs are counted in stats and routed to the per-AKM format-only sinks `--psk-sha384-out` (types 8/9) and `--ft-psk-sha384-out` (types 10/11); the legacy `--22000-out` and `--37100-out` sinks deliberately skip them.

### §5.5  What the cracker verifies

Per `[IEEE 802.11-2024]` §12.7.1.3 the cracker runs PBKDF2 once, then derives PTK via the AKM-specific PRF/KDF over `min(AP,STA) || max(AP,STA) || min(ANonce,SNonce) || max(ANonce,SNonce)`, takes KCK = PTK[0..16], replaces the MIC field of the captured EAPOL frame with zero bytes, recomputes the MIC under the AKM-specific primitive, and compares against the captured MIC. PRF output length depends on KDV (512 bits for KDV=1/3, 384 bits for KDV=2). Inputs needed from the capture: ANonce, SNonce, EAPOL frame, MIC, both MACs, SSID - one nonce-carrying frame plus one MIC-carrying frame.

### §5.6  The 6 N#E# combos

wpawolf creates hash lines by combining one nonce source with one EAPOL/MIC source. There are six valid combinations - the spec and hcxtools call these N#E# combos (Nonce from message #, EAPOL from message #).

| Combo | Nonce from | EAPOL/MIC from | Hash-line NONCE field | mp bits 0-2 |
|-------|------------|----------------|----------------------|-------------|
| **N1E2** | M1 | M2 | ANonce | 0x00 |
| **N1E4** | M1 | M4 | ANonce | 0x01 |
| **N3E2** | M3 | M2 | ANonce | 0x02 |
| **N2E3** | M2 | M3 | SNonce | 0x03 |
| **N4E3** | M4 | M3 | SNonce | 0x04 |
| **N3E4** | M3 | M4 | ANonce | 0x05 |

For N2E3 and N4E3 the SNonce is the external nonce because the EAPOL frame is M3 and the cracker-computed PTK uses SNonce from M2/M4 as the STA nonce input.

By default wpawolf emits all six combos. With `--dedup-hash-combos`, collapse to three (see §5.8).

### §5.7  message_pair byte

Every `WPA*02*` and `WPA*04*` line ends with a 1-byte message_pair field encoding the combo type plus diagnostic flags.

Bits 0-2: combo type (see §5.6).

Bits 3-7 diagnostic flags:

| Bit | Hex | Meaning |
|-----|-----|---------|
| 4 | `0x10` | AP-less attack -- pair did not consume an M1 (set for N2E3 / N4E3 combos) |
| 5 | `0x20` | LE flag - replay counter relationship detected as little-endian |
| 6 | `0x40` | BE flag - replay counter relationship detected as big-endian |
| 7 | `0x80` | NC flag - nonce correction was applied (RC not checked) |

Examples:

| Hex | Meaning |
|-----|---------|
| `00` | N1E2, no flags (clean capture) |
| `02` | N3E2, no flags |
| `82` | N3E2, NC flag set (nonce error correction applied) |
| `22` | N3E2, LE replay-counter detected |

**FLAG_NC is set on a three-source OR.** For M3-anchored pairs (N3E2 / N3E4) wpawolf sets `FLAG_NC` (`0x80`) when any one of three independent sources fires:

1. The (AP, STA) session has seen any M1 frame. hcxpcapngtool stores every M1 with `status=ST_NC` (`hcxpcapngtool.c:4190`) and the `addhandshake` inheritance loop (`hcxpcapngtool.c:2758-2767`) ORs that into every subsequent non-APLESS handshake for the same AP. Mirroring this is required because hashcat module `module_22000.c::module_hash_decode_postprocess` (lines 1302-1326) gates the nonce-error-corrections iteration window on `FLAG_NC=1`: without the bit, sessions where M1 and M3 ANonce differ are uncrackable.
2. Nonce endianness has been detected on M1 or M3 -- hcx sets `ST_LE+ST_NC` or `ST_BE+ST_NC` on both the stored and current message (`hcxpcapngtool.c:3814-3826`, `4242-4253`). The detector compares M1s against M3s across (AP, STA) groups, matching hcx's loop guard at `hcxpcapngtool.c:3810` / `4238`.
3. Per-pair replay-counter gap is non-zero (`hcxpcapngtool.c:2787-2790`).

### §5.8  6 -> 3 equivalence collapse

Within a single handshake session (where M1 and M3 carry the same ANonce, M2 and M4 carry the same SNonce), the 6 combos produce at most 3 unique crackable hashes:

| Class | Members | Unique because of |
|-------|---------|-------------------|
| Hash-A | N1E2, N3E2 | M2's EAPOL frame |
| Hash-B | N2E3, N4E3 | M3's EAPOL frame |
| Hash-C | N1E4, N3E4 | M4's EAPOL frame |

Two pairs are equivalent if their NONCE field bytes are equal AND their EAPOL field bytes are equal. This handles the case where M1.ANonce == M3.ANonce (true per spec but may differ if the AP retransmitted with a new nonce).

By default (unfiltered) all 6 combos are emitted. With `--dedup-hash-combos`, one hash per equivalence class is emitted with the survivor chosen by:

1. Smallest RC gap magnitude (exact RC match preferred).
2. Authorized combo type as tiebreaker (N3E2 over N1E2, N2E3 over N4E3, N3E4 over N1E4 - M3-sourced nonces are canonical).

### §5.8.1  NC-dedup near-identical-nonce clustering

Some firmware emits many EAPOL-Key messages for one (AP, STA) that share the same EAPOL body and MIC but differ only in the trailing bytes of the nonce. A real-world report on the hcxtools list showed 2041 WPA*02* lines for one (AP, STA) sharing a 28-byte nonce prefix and differing only on byte 31. Hashcat with `--nonce-error-corrections=N` (default 8) iterates `+/- N/2` on the trailing byte during MIC verification and can therefore recover the entire family from one representative line - but only if wpawolf emits the representative tagged with `FLAG_NC` (`0x80`). Without that tag hashcat treats each variant as a distinct hash and re-derives the PTK across the whole wordlist for every line.

`--nc-dedup` enables a post-collapse clustering pass that runs once per (AP, STA) group. Pairs are bucketed by `(eapol_frame, mic, combo_type, nonce[..28])`; within each bucket the trailing 4 bytes of the nonce are interpreted as a `u32` in both endiannesses, sorted, and split into contiguous runs whose `max - min` span fits within `--nc-tolerance` (default 8, matching hashcat's `NONCE_ERROR_CORRECTIONS=8`). The endianness producing the larger collapse wins; ties go to LE. The survivor of each cluster is the observed nonce that minimises `max(tail - min, max - tail)` - the cluster member hashcat's symmetric `[survivor - N/2, survivor + N/2]` iteration can recover every dropped sibling from. For dense clusters this is the sorted-median observation; for sparse-edge clusters (e.g. just `[0, N]`) the safest observation still sits an edge away from at least one sibling, in which case the safety guard skips the collapse entirely and the cluster members survive as singletons. The survivor's `message_pair` byte gains `FLAG_NC | FLAG_LE` or `FLAG_NC | FLAG_BE`; the remaining cluster members are dropped. Singleton buckets pass through untouched - hashcat NC iteration is wasted CPU when no other observed nonce sits within tolerance.

Why this is safe by spec: `[IEEE 802.11-2024]` §12.7.2 NOTE 9 - "the key replay counter does not play any role beyond a performance optimization; replay protection is provided by selecting a never-before-used nonce." Merging near-identical nonces does not violate the protocol; it acknowledges firmware that re-uses a nearly-identical nonce across consecutive handshake attempts and lets the cracker recover the exact value within tolerance.

Three counters appear in the closing stats banner whenever the pass dropped at least one line: `NC-dedup near-identical-nonce lines collapsed (--nc-dedup)`, `NC-dedup cluster count (--nc-dedup)`, and `NC-dedup max cluster size (--nc-dedup)`. Default-mode banners are unchanged because the `nz!` macro suppresses zero rows.

### §5.9  Pairing constraints (output filters)

Three optional output filters narrow which combos make it to disk. All three are off by default; turning any of them on can discard pairs that would otherwise be emitted.

**`--eapoltimeout[=<s>]`** sets the maximum wall-time gap between the two messages in a pair. A pair is discarded if `|ts_nonce_msg - ts_eapol_msg| > eapoltimeout_s * 1_000_000` (timestamps in microseconds). Without this flag the time check is disabled (unlimited). Bare `--eapoltimeout` uses 600 seconds (10 minutes); use e.g. `--eapoltimeout=3` for a tight 3-second window when the capture is known clean. hcxpcapngtool's default is roughly 3 seconds, which is overly aggressive for capture conditions where retransmissions stretch sessions out.

**`--rc-drift[=N]`** activates replay-counter consistency verification. Expected RC relationship per combo:

```
N1E2:           RC(M2) == RC(M1)
N3E2:           RC(M2) == RC(M3) - 1
N1E4:           RC(M4) == RC(M1) + 1
N3E4:           RC(M4) == RC(M3)
N2E3:           RC(M3) == RC(M2) + 1
N4E3:           RC(M3) == RC(M4)
```

A pair is discarded if `|actual_delta - expected_delta| > N`, including byte-swapped RC comparisons that detect broken-endianness firmware (LE/BE flag set in the message_pair byte). Default tolerance N = 8 when the flag is bare. Without `--rc-drift` all pairs pass regardless of RC.

**`--dedup-hash-combos`** runs the 6 -> 3 collapse described in §5.8.

LE/BE nonce-endianness detection always runs even when `--rc-drift` is off; the flag is informational only when the filter is disabled.

### §5.9.1  FT-PSK emission and hashcat verification

For FT-PSK (AKM 4 / AKM 19) the FT-PTK derivation pins both nonces and the BSSID into the KDF input:

```
FT-PTK = KDF-Hash(PMK-R1, "FT-PTK", SNonce || ANonce || BSSID || SPA)
```

A given EAPOL frame's MIC is therefore verifiable only by reconstructing that exact `(SNonce, ANonce, BSSID, SPA)` quadruple. hashcat's mode 37100 kernel verifies the line as written -- it reads the ANonce from the line and the SNonce from the embedded EAPOL body. Combos where those two nonce sources disagree (typical of M3-derived APless pairs that wpawolf emits for max coverage) cannot pass mode 37100's MIC check no matter the PSK.

This is intentional and not a bug. wpawolf still emits all six N#E# combos per FR-PAIR-* (max coverage, "never miss a hash") because (a) future hashcat versions may add APless FT MIC verification, and (b) operators may post-process the file with a different cracker. The generated test corpus's t06 / t07 fixtures consequently produce four EAPOL lines each, of which exactly two crack with `hashcat -m 37100`. That ratio is the expected outcome, not a corpus defect.

If an operator wants only the verifiable subset for FT, the simplest mechanical filter is:

```sh
# Keep only combos where the line's ANonce matches the ANonce hashcat
# extracts from the embedded EAPOL body (offset 17..49 of the EAPOL
# Key frame field, hex chars 35..99 of the eapol field in WPA*04*).
# Future-tooling task; not currently in wpawolf because the criteria
# may change as hashcat adds APless FT support.
```

### §5.10  M4 zero-nonce drop

`[IEEE 802.11-2024]` §12.7.6.5 says M4's nonce field SHALL be zero, but NOTE 9 acknowledges that "some deployed Supplicant implementations set the Key Nonce field in message 4 to the same value as in message 2." Spec-compliant M4 (NULL nonce) is dropped at extract; the non-conforming SNonce-copy form passes through and pairs normally.

The reason for dropping is cryptographic, not spec-driven. The live PTK is derived from M2's `SNonce` and M3's ANonce. An EAPOL hash line built from an M4 with a NULL Key Nonce supplies the cracker with the input pair `(NULL, M3_ANonce)`, which does not reproduce the live PTK -- the resulting MIC verification cannot succeed for any candidate password, so no value of N1E4 / N4E3 / N3E4 lines can crack a spec-compliant M4 handshake. This matches hcxpcapngtool's `eapolm4zeroedcount++; return;` drop at `hcxpcapngtool.c:3636`.

Frames with non-zero M4 Key Nonce (the SNonce-copy form, also covered by NOTE 9) still pair: the nonce passes the garbage-pattern check, the M4 enters `MessageStore`, and the pairing engine emits N1E4 / N4E3 / N3E4 combos with that nonce in the cryptographic role. Those lines are crackable because the M4 carries the real `SNonce`. M4 with a 0xFF, all-same-byte, or short-period repeating nonce is rejected like any other garbage pattern per §4 invariant 7.

### §5.11  Stored EapolMessage

```rust
pub struct EapolMessage {
    pub timestamp:      u64,            //  8 B  capture timestamp in us, for session window
    pub msg_type:       MsgType,        //  1 B  M1, M2, M3, or M4
    pub key_version:    u8,             //  1 B  KDV (0, 1, 2, or 3)
    pub replay_counter: u64,            //  8 B  big-endian on the wire
    pub nonce:          [u8; 32],       // 32 B  ANonce or SNonce
    pub mic:            MicBytes,       // 16 or 24 B  original MIC (MicBytes { bytes: [u8; 24], len: u8 })
    pub pmkid:          Option<[u8; 16]>,// 17 B PMKID extracted from Key Data
    pub eapol_frame:    Arc<[u8]>,      // raw EAPOL frame, MIC intact (zeroed at output)
    pub ft:             Option<FtFields>,// MDID + R0KH-ID + R1KH-ID for FT-PSK
    pub akm:            AkmType,        //  1 B  detected from RSN IE context
    pub is_rsn:         bool,           //  1 B  RSN (0x02) vs WPA legacy (0xFE) descriptor
}

pub struct FtFields {
    pub mdid:        [u8; 2],
    pub r0khid_len:  u8,
    pub r0khid:      [u8; 48],
    pub r1khid:      [u8; 6],
}
```

`eapol_frame` is `Arc<[u8]>` so Phase 4 pairing threads can share the frame body without heap-cloning the millions of `PairedHash` objects that fan out from the 6-N#E#-combos × multi-handshake-per-session explosion.

Typical size: ~110 B stack + ~140 B shared-heap = ~250 B per message (amortised across combo reuse). With FT fields: ~310 B. Oversized FT EAPOL (~500 B): ~460 B.

### §5.12  Relay (WDS / 4-address) frames

Standard 802.11 frames use three MAC address fields. Mesh and WDS frames use four (To DS = 1, From DS = 1). Both the address interpretation and the BSSID detection change per `[IEEE 802.11-2024]` Table 9-60. wpawolf parses these frames identically and pairs handshakes carried within them without any flag (§4 invariant 4). They are counted in `stats.wds_count`.

WDS classification runs in **Phase 1.5** (`src/extract/wds.rs`) after the `essid_map` is fully populated, then walks every deferred frame through a three-tier resolution ladder. Tier 3 always succeeds for syntactically valid EAPOL frames, so resolution does **not** depend on `essid_map` being populated -- a capture with no Beacon / Probe Response still recovers every valid WDS handshake.

| Tier | Mechanism | Counter | Coverage |
|---|---|---|---|
| 1b | `essid_map` AP lookup on `addr_ta` or `addr_ra` | `eapol_tier1b_essid` | Best path; requires Beacon / Probe Response |
| 2 | ACK-flag-based AP discovery (any in-capture frame with Key ACK = 1 reveals its TA as the AP) | `eapol_tier2_ack_discovery` | Works without `essid_map` when at least one M1 / M3 is present |
| 3 | Flag-based fallback via `eapol::parse(.., None)` | `eapol_tier3_flag_fallback` | Always-on last resort; mirrors hcxpcapngtool's tree |

### §5.13  Why FT-PSK frames break hcxtools

FT-PSK M2 frames routinely reach 400-510 B because the Key Data contains a full RSN IE plus MDE (5 B) plus FTE (90-200 B). hcxpcapngtool's `EAPOL_AUTHLEN_OLD_MAX = 255` silently drops these. wpawolf has no size gate (§4 invariant 3); every valid EAPOL frame is stored and emitted. hashcat mode 37100 PR #4645 raised its buffer to 1024 B; captures made today crack once the PR is fully merged.

---

## §6  PMKID extraction

### §6.1  Background

PMKSA caching (`[IEEE 802.11-2024]` §12.6.8) lets a station that has previously authenticated to an AP skip the EAP / SAE step on re-association. The station references a cached PMKSA by its 16-byte **PMKID**. Because the AP includes its precomputed PMKID in the very first EAPOL frame it sends (M1), an attacker who captures M1 can mount a dictionary attack without ever waiting for a full 4-way handshake - this is the Steube 2018 attack, the reason wpawolf treats PMKID extraction as a first-class priority.

### §6.2  PMKID formula by AKM

The canonical formula (WPA2-PSK, AKM 2):

```
PMK   = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096 iterations, 32 bytes)
PMKID = Truncate-128( HMAC-SHA1( PMK, "PMK Name" || AP_MAC || STA_MAC ) )
```

`"PMK Name"` is literal ASCII (8 bytes: `50 4D 4B 20 4E 61 6D 65`). `AP_MAC = AA` and `STA_MAC = SPA` per the spec naming.

Per `[IEEE 802.11-2024]` §12.7.1.3 the HMAC primitive varies by AKM:

| AKM | Selector | Name | PMKID formula | PMK source | Crackable? |
|-----|----------|------|---------------|------------|------------|
| WPA1 | `00-50-F2:01` | WPA-PSK (TKIP) | none - WPA1 has no PMKID | PBKDF2-SHA1 | n/a |
| **2** | `00-0F-AC:2` | **WPA2-PSK** | `Truncate-128(HMAC-SHA1(PMK, "PMK Name" \|\| AA \|\| SPA))` | PBKDF2-SHA1 | yes - hashcat 22000 |
| 4 | `00-0F-AC:4` | FT-PSK-SHA256 | Two-step FT chain (see §6.3) | PBKDF2-SHA1 -> FT KDF | yes - hashcat 37100 |
| **6** | `00-0F-AC:6` | PSK-SHA256 | `Truncate-128(HMAC-SHA256(PMK, "PMK Name" \|\| AA \|\| SPA))` | PBKDF2-SHA1 | yes via EAPOL; PMKID broken in hashcat (§6.7) |
| 1 | `00-0F-AC:1` | 802.1X-SHA1 | HMAC-SHA1 | EAP MSK | no - PMK from server |
| 3 | `00-0F-AC:3` | FT-802.1X | FT chain | EAP MSK | no |
| 5 | `00-0F-AC:5` | 802.1X-SHA256 | HMAC-SHA256 | EAP MSK | no |
| 8 | `00-0F-AC:8` | SAE | HMAC-SHA256 | SAE PAKE | no - PMK not derivable |
| 9 | `00-0F-AC:9` | FT-SAE | FT chain, SHA256 | SAE PAKE | no |
| 11-13 | `00-0F-AC:11..13` | Suite B | SHA-256 / SHA-384 | EAP TLS / MSK | no |
| 14-17 | `00-0F-AC:14..17` | FILS | `Truncate-128(Hash(EAP-Initiate/Reauth))` | EAP rMSK | no |
| 18 | `00-0F-AC:18` | OWE | `Truncate-128(Hash(C \|\| A))` | ECDH | no |
| 19 | `00-0F-AC:19` | FT-PSK-SHA384 | Two-step FT chain, SHA384 | PBKDF2-SHA1 | capture yes; no hashcat module |
| 20 | `00-0F-AC:20` | PSK-SHA384 | HMAC-SHA384 | PBKDF2-SHA1 | capture yes; no hashcat module |
| 21 | `00-0F-AC:21` | PASN | none (no EAPOL-Key) | ephemeral DH | no |
| 24-25 | `00-0F-AC:24..25` | SAE H2E | as AKM 8/9 | SAE PAKE | no |

For PSK AKMs the PMK comes from PBKDF2, which makes it password-crackable. For 802.1X and SAE the PMK comes from material not derivable from a pcap.

wpawolf extracts PMKIDs from every AKM (§4 invariant 7 covers the NULL/0xFF rejection, but no AKM is filtered out). Routing decides which output file each PMKID lands in (§6.4); non-PSK AKMs are counted in stats but produce no `WPA*` line.

### §6.3  FT PMKID - the two-step chain

Fast BSS Transition (`[IEEE 802.11-2024]` §13.4, AKM 4 / 19) does not use a flat PMKID. Instead it uses a hierarchy:

```
PMK-R0  =  KDF-SHA256(PMK, "FT-R0",
                      SPA || SSID || MDID || R0KH-ID-len || R0KH-ID || S0KH-ID)

PMK-R0-Name  =  Truncate-128(SHA256("FT-R0N" || PMK-R0-Name-salt))
    where PMK-R0-Name-salt = bytes 32..47 of the KDF output above

PMK-R1  =  KDF-SHA256(PMK-R0, "FT-R1", R1KH-ID || S1KH-ID)

PMKID  =  PMK-R1-Name  =  Truncate-128(SHA256("FT-R1N" || PMK-R0-Name || R1KH-ID || S1KH-ID))
```

For AKM 19 (FT-PSK-SHA384) the same chain runs on KDF-SHA384 throughout.

To emit a crackable `WPA*06*` (FT-PSK PMKID) line we need:

- **MDID** (2 B) - Mobility Domain ID, from MDE (tag 54).
- **R0KH-ID** (1-48 B) - R0 Key Holder ID, from FTE (tag 55) subelement 3.
- **R1KH-ID** (6 B) - R1 Key Holder ID, from FTE subelement 1 (usually = AP MAC).

All three must appear in the hash line for hashcat 37100 to walk the chain. wpawolf's FT extraction is in `src/ieee80211/ft.rs`.

### §6.4  AKM routing decision

After extraction, the PMKID is routed based on the AKM detected from the Beacon / ProbeResponse RSN IE for the AP's BSSID, with the per-`(AP, STA)` observed AKM (from the M2 RSN IE in Key Data) winning over the AP-wide default. If no Beacon was captured for the AP (AKM is Unknown), wpawolf defaults to 22000 output - the PMKID is not discarded just because the AKM is unknown.

| Detected AKM | Output sinks | hash type code | Notes |
|--------------|--------------|----------------|-------|
| AKM 2 (PSK) | `--22000-out`, `-o`, `--wpa2-out` | type 02 | Primary target |
| AKM 6 (PSK-SHA256) | `--22000-out`, `-o`, `--psk-sha256-out` | type 04 | hashcat aux4 currently broken (§6.7) |
| AKM 4 (FT-PSK) with FT fields | `--37100-out`, `-o`, `--ft-out` | type 06 | Requires MDID + R0KH-ID + R1KH-ID |
| AKM 20 (PSK-SHA384) | `-o`, `--psk-sha384-out` | type 08 | Needs HMAC-SHA384 PMKID kernel |
| AKM 19 (FT-PSK-SHA384) with FT fields | `-o`, `--ft-psk-sha384-out` | type 10 | Needs FT-KDF-SHA384 chain |
| AKM 1, 3, 5, 8, 9, 11-18, 21, 24, 25 | counted only | - | non-PSK AKM, not crackable from pcap |
| Unknown | `--22000-out`, `-o`, `--wpa2-out` | type 02 | log AKM value for diagnostics |

This is always-on; there is no AKM filter flag. Pure SAE / OWE / enterprise EAP networks produce no PSK-style 4-way handshake and therefore no wpawolf PSK output - not because wpawolf filters on AKM, but because the on-wire EAPOL-Key exchange wpawolf parses does not occur for those schemes.

### §6.5  The 20 PMKID locations - complete inventory

PMKIDs appear in many frame types, not just EAPOL. The spec defines 20 distinct locations; wpawolf labels them S1 through S20. Each location maps to a `PmkidSource` enum variant.

Almost every PMKID on the wire lives in one of two containers:

- **Container A - RSN IE (tag 48)**, the standard security descriptor. PMKID Count + PMKID List sit near the end of the IE per `[IEEE 802.11-2024]` §9.4.2.24.5.
- **Container B - PMKID KDE**, a vendor-specific blob inside EAPOL-Key Data: `[0xDD][0x14][00:0F:AC][0x04][16 B PMKID]`. Tag `0xDD` is the vendor-specific tag used in WPA key data; OUI `00:0F:AC` is the IEEE OUI for 802.11 security; type `0x04` is PMKID KDE per Table 12-8.

Per-location notes follow. Each maps to a `PmkidSource` enum variant. The summary table in §6.6 gives the frame type, direction, and container at a glance; entries here record only the spec citation and anything specific that affects extraction logic.

- **S1 - EAPOL-Key M1 KDE.** Spec: §12.7.2, §12.6.8.3, Table 12-8. `PmkidSource::M1KeyData`. The Steube attack vector.
- **S2 - EAPOL-Key M2 RSN IE.** Spec: §12.7.2 Table 12-9, §9.4.2.24.5. `PmkidSource::M2RsnIe`. For FT-PSK the PMKID list carries PMKR1Name and the Key Data also contains MDE + FTE.
- **S3 - Association Request RSN IE.** Spec: §9.4.2.24.5, §12.6.8.3. `PmkidSource::AssocRequest`.
- **S4 - Reassociation Request RSN IE.** Spec: §9.4.2.24.5, §13.4, §13.8.3. `PmkidSource::ReassocRequest`. For FT over-the-air roaming the PMKID list carries PMKR1Name and MDE + FTE accompany.
- **S5 - FT Auth seq=1.** Algorithm = 2 (FBT). Spec: §13.8.3. `PmkidSource::FtAuthStaToAp`. RSNE list carries PMKR0Name; FTE carries R0KH-ID and ANonce; MDE carries MDID.
- **S6 - FT Auth seq=2.** Algorithm = 2. Spec: §13.8.3. `PmkidSource::FtAuthApToSta`. RSNE list carries PMKR1Name; FTE carries R0KH-ID (subelement 3) and R1KH-ID (subelement 1) - everything needed to construct a `WPA*06*` line.
- **S7 - FILS Auth seq=1.** Algorithm = 4 or 5. Spec: §12.11.2.3.2. `PmkidSource::FilsAuthStaToAp`. PMK from EAP rMSK; not PSK-crackable.
- **S8 - FILS Auth seq=2.** Spec: §12.11.2.3.4. `PmkidSource::FilsAuthApToSta`. AP echoes the chosen PMKID.
- **S9 - PASN Auth seq=1.** Spec: §12.13.1-2. `PmkidSource::PasnAuthStaToAp`. Crackable only when base AKMP is PSK or FT-PSK.
- **S10 - PASN Auth seq=2.** Spec: §12.13.2. `PmkidSource::PasnAuthApToSta`.
- **S11 - FT Action Request (cat=6, action=1).** Spec: §13.8.5, §9.6.7.3. `PmkidSource::FtActionRequest`. Action body: Category + Action + STA Address + Target AP Address + (RSNE / MDE / FTE) tagged IEs.
- **S12 - FT Action Response (cat=6, action=2).** Spec: §13.8.5, §9.6.7.4. `PmkidSource::FtActionResponse`.
- **S13 - FT Action Confirm (cat=6, action=3).** Spec: §13.8.5, §9.6.7.5. `PmkidSource::FtActionConfirm`. RSNE carries PMKR1Name.
- **S14 - Probe Request (directed) RSN IE.** Spec: §9.4.2.24.5. `PmkidSource::ProbeRequest`. Most client drivers do not include the RSN IE in Probe Requests; presence usually indicates active PMKSA caching.
- **S15 - Probe Request (broadcast) RSN IE.** Spec: §9.4.2.24.5. `PmkidSource::ProbeRequest` (S14 and S15 share one variant; the directed-vs-broadcast split is a stats-only distinction). Spec-valid but rare.
- **S16 - Beacon RSN IE (vendor firmware bug).** Spec: §9.4.2.24.5 says AP-originated PMKID Count should be 0; some Broadcom chipsets and embedded APs ship non-zero values. `PmkidSource::BeaconRsnIe`. wpawolf extracts to ensure nothing is missed.
- **S17 - Probe Response RSN IE (vendor firmware bug).** Same rationale as S16. `PmkidSource::ProbeRespRsnIe`.
- **S18 - Mesh Peering Open AMPE element.** Action category=15 (Self-Protected), action=1. AMPE element (tag 139), "Chosen PMK" subfield = last 16 bytes of element body. Spec: §9.6.15.2, §14.3.5. `PmkidSource::MeshPeeringOpen`. Detection: `if tag_len - offset == 16`. Mesh PMKSAs derive from SAE so not PSK-crackable.
- **S19 - Mesh Peering Confirm AMPE element.** Action category=15, action=2. Spec: §9.6.15.3, §14.3.5. `PmkidSource::MeshPeeringConfirm`.
- **S20 - Association Request OSEN IE.** Vendor IE tag 221, OUI `50:6F:9A`, type `0x12`. Wi-Fi Passpoint / Hotspot 2.0 spec. Wireshark reference `packet-ieee80211.c:20494`. `PmkidSource::OsenIe`. OSEN IE inner structure is byte-for-byte identical to RSN IE starting from the Group Cipher Suite field, so the same PMKID Count + PMKID List offset applies. OSEN AKM is enterprise 802.1X so not PSK-crackable.

### §6.6  Complete location summary

| ID | Frame type | Subtype | Direction | Container | Crackable | mp byte | tshark display filter |
|----|------------|---------|-----------|-----------|-----------|---------|----------------------|
| S1 | EAPOL-Key M1 | Data | AP->STA | KDE `{DD 14 00:0F:AC 04}` | yes (PSK) | 0x01 | `wlan_rsna_eapol.keydes.key_info.key_ack == 1 && wlan_rsna_eapol.keydes.key_info.key_mic == 0 && wlan.rsn.ie.pmkid` |
| S2 | EAPOL-Key M2 | Data | STA->AP | RSN IE in Key Data | yes (PSK / FT-PSK) | 0x04 | `wlan_rsna_eapol.keydes.key_info.key_ack == 0 && wlan_rsna_eapol.keydes.key_info.key_mic == 1 && wlan_rsna_eapol.keydes.key_info.install == 0 && wlan.rsn.pmkid.count > 0` |
| S3 | Association Request | Mgmt 0x00 | STA->AP | RSN IE tagged params | yes (PSK) | 0x01 | `wlan.fc.type_subtype == 0x00 && wlan.rsn.pmkid.count > 0` |
| S4 | Reassociation Request | Mgmt 0x02 | STA->AP | RSN IE tagged params | yes (PSK / FT-PSK) | 0x01 | `wlan.fc.type_subtype == 0x02 && wlan.rsn.pmkid.count > 0` |
| S5 | FT Auth (algo=2, seq=1) | Mgmt 0x0B | STA->AP | RSN IE + MDE + FTE | yes (FT-PSK) | 0x04 | `wlan.fc.type_subtype == 0x0b && wlan.fixed.auth.alg == 2 && wlan.fixed.auth_seq == 1 && wlan.rsn.pmkid.count > 0` |
| S6 | FT Auth (algo=2, seq=2) | Mgmt 0x0B | AP->STA | RSN IE + MDE + FTE | yes (FT-PSK) | 0x01 | `wlan.fc.type_subtype == 0x0b && wlan.fixed.auth.alg == 2 && wlan.fixed.auth_seq == 2 && wlan.rsn.pmkid.count > 0` |
| S7 | FILS Auth (algo=4/5, seq=1) | Mgmt 0x0B | STA->AP | RSN IE | conditional | 0x04 | `wlan.fc.type_subtype == 0x0b && wlan.fixed.auth.alg in {4 5} && wlan.fixed.auth_seq == 1 && wlan.rsn.pmkid.count > 0` |
| S8 | FILS Auth (algo=4/5, seq=2) | Mgmt 0x0B | AP->STA | RSN IE | conditional | 0x01 | `wlan.fc.type_subtype == 0x0b && wlan.fixed.auth.alg in {4 5} && wlan.fixed.auth_seq == 2 && wlan.rsn.pmkid.count > 0` |
| S9 | PASN Auth (seq=1) | Mgmt 0x0B | STA->AP | RSN IE | conditional | 0x04 | `wlan.fc.type_subtype == 0x0b && wlan.fixed.auth.alg == 7 && wlan.fixed.auth_seq == 1 && wlan.rsn.pmkid.count > 0` ¹ |
| S10 | PASN Auth (seq=2) | Mgmt 0x0B | AP->STA | RSN IE | conditional | 0x01 | `wlan.fc.type_subtype == 0x0b && wlan.fixed.auth.alg == 7 && wlan.fixed.auth_seq == 2 && wlan.rsn.pmkid.count > 0` ¹ |
| S11 | FT Action Request (cat=6, act=1) | Mgmt 0x0D | STA->AP | RSN IE + FTE | yes (FT-PSK) | 0x04 | `wlan.fc.type_subtype == 0x0d && wlan.fixed.category_code == 6 && wlan.fixed.action_code == 1 && wlan.rsn.pmkid.count > 0` |
| S12 | FT Action Response (cat=6, act=2) | Mgmt 0x0D | AP->STA | RSN IE + FTE | yes (FT-PSK) | 0x01 | `wlan.fc.type_subtype == 0x0d && wlan.fixed.category_code == 6 && wlan.fixed.action_code == 2 && wlan.rsn.pmkid.count > 0` |
| S13 | FT Action Confirm (cat=6, act=3) | Mgmt 0x0D | STA->AP | RSN IE + FTE | yes (FT-PSK) | 0x04 | `wlan.fc.type_subtype == 0x0d && wlan.fixed.category_code == 6 && wlan.fixed.action_code == 3 && wlan.rsn.pmkid.count > 0` |
| S14 | Probe Request (directed) | Mgmt 0x04 | STA->AP | RSN IE | yes (if PSK) | 0x04 | `wlan.fc.type_subtype == 0x04 && wlan.rsn.pmkid.count > 0` ² |
| S15 | Probe Request (broadcast) | Mgmt 0x04 | STA->bcast | RSN IE | yes (if PSK) | 0x04 | `wlan.fc.type_subtype == 0x04 && wlan.rsn.pmkid.count > 0` ² |
| S16 | Beacon (vendor FW bug) | Mgmt 0x08 | AP->all | RSN IE | yes (if PSK) | 0x01 | `wlan.fc.type_subtype == 0x08 && wlan.rsn.pmkid.count > 0` |
| S17 | Probe Response (vendor FW bug) | Mgmt 0x05 | AP->STA | RSN IE | yes (if PSK) | 0x01 | `wlan.fc.type_subtype == 0x05 && wlan.rsn.pmkid.count > 0` |
| S18 | Mesh Peering Open (cat=15, act=1) | Mgmt 0x0D | STA->STA | AMPE element tag 139 | no (SAE) | 0x04 | `wlan.fc.type_subtype == 0x0d && wlan.fixed.category_code == 15 && wlan.fixed.selfprot_action == 1` ³ |
| S19 | Mesh Peering Confirm (cat=15, act=2) | Mgmt 0x0D | STA->STA | AMPE element tag 139 | no (SAE) | 0x04 | `wlan.fc.type_subtype == 0x0d && wlan.fixed.category_code == 15 && wlan.fixed.selfprot_action == 2` ³ |
| S20 | Association Request (OSEN IE) | Mgmt 0x00 | STA->AP | Vendor IE `{50:6F:9A:12}` | no (EAP) | 0x04 | `wlan.fc.type_subtype == 0x00 && wlan.osen.pmkid.count > 0` |

**tshark filter notes:**

¹ S9/S10: Filter uses `algo == 7` ([IEEE 802.11-2024] Table 9-43 PASN). wpawolf also processes any unrecognized algorithm value as a potential PASN base-AKMP per §12.13.1 reservation; those would require `!(wlan.fixed.auth.alg == 0 || ... || wlan.fixed.auth.alg == 128)` which is impractical as a display filter.

² S14/S15: Same base filter. The directed-vs-broadcast distinction (SSID element length > 0 vs = 0) is not expressible as a tshark display filter on the `wlan.ssid` FT_BYTES field. Post-filter by inspecting the SSID tag in the packet detail tree.

³ S18/S19: Frame-level match only. The PMKID (Chosen-PMK identifier, last 16 bytes of AMPE element body) is inside SAE-encrypted AMPE content; Wireshark does not dissect the PMKID as an individually filterable field. Verify AMPE tag 139 presence in the element list manually.

All field names verified against the local Wireshark 4.x field registry (`tshark -G fields`). The S1 KDE filter uses `wlan.rsn.ie.pmkid` (KDE type 4 PMKID dissection); S3-S17 use `wlan.rsn.pmkid.count` (RSN IE PMKID List); S20 uses the dedicated `wlan.osen.pmkid.count` (OSEN IE PMKID dissection).

### §6.6  AKMs that wpawolf parses but does not emit

Three AKM families produce PMKIDs that wpawolf walks through the extraction path (and counts in stats) but does not turn into a hashcat line:

- **FILS-SHA256 / FILS-SHA384 (AKM 14-17, S7 / S8).** FILS PMKs are derived from an EAP exchange (FILS-Shared-Key) or pre-distributed shared secret (FILS-Public-Key), not from `PBKDF2-HMAC-SHA1(PSK, SSID, 4096, 32)`. wpawolf has no way to materialise the FILS PMK from the inputs hashcat provides; emitting the line would always be uncrackable. FILS AKMs are therefore *not* in `AkmType` -- the PMKIDs are stored with `AkmType::Unknown` and dropped by the FR-OUT-3 emit gate. The `pmkid_fils_auth` stats counter still fires so the parse path is observable.
- **Mesh Peering AMPE (S18 / S19).** Mesh PMKIDs come from SAE, which is out of project scope (see §1).
- **OSEN (S20).** Hotspot 2.0 OSEN PMKIDs are derived from an EAP authentication, not PSK; out of project scope for the same reason.

If hashcat ever ships a FILS / SAE / OSEN kernel that takes a PSK or similar PSK-equivalent input, this decision is reversible -- extend `AkmType` with the new variant, route the PMKID into the appropriate sink, and update §7's compatibility matrix.

### §6.7  PMKID line message_pair byte

Unlike EAPOL lines where the message_pair byte encodes the combo type, for PMKID lines it records where the PMKID came from:

| Value | Meaning | wpawolf sources |
|-------|---------|-----------------|
| `0x01` | PMKID from AP side, non-FT | M1 KDE, AssocReq, ReassocReq, Beacon, ProbeResp, FT Auth seq=2, FT Action Response, FILS Auth seq=2, PASN Auth seq=2 |
| `0x04` | PMKID from client side, non-FT | M2, FT Auth seq=1, FT Action Request, FT Action Confirm, ProbeReq, FILS Auth seq=1, PASN Auth seq=1, Mesh Peering Open/Confirm, OSEN |
| `0x10` | PMKID from AP side, FT-PSK | same sources as `0x01` when `akm.is_ft()` |
| `0x20` | PMKID from client side, FT-PSK | same sources as `0x04` when `akm.is_ft()` |

hcxtools defines a fifth constant `PMKID_APPSK256 = 0x02` (`hcxpcapngtool.h:387`) for AP-side PSK-SHA256 PMKIDs; wpawolf does not currently emit `0x02` (all AP-side non-FT PMKIDs emit `0x01` regardless of AKM -- see TODO CR-16 for the planned split). The four values above mirror `PMKID_AP`, `PMKID_CLIENT`, `PMKID_AP_FTPSK`, `PMKID_CLIENT_FTPSK` in hcxtools. `pmkid_message_pair` in `src/output/hashcat.rs` inspects `entry.akm.is_ft()` and returns the FT pair when the line is FT.

### §6.8  Sanity checks before storing

Every PMKID passes through two gates at store time and one gate at emit time:

1. **Garbage-pattern rejection** (§4 invariant 7): a 16-byte PMKID matching `null` (all-zero), `ff` (all-0xFF), `repeat_1` (all-same-byte), `repeat_2` (2-byte period), or `repeat_4` (4-byte period) is rejected unconditionally. Separate counters `null_pmkid_rejected`, `ff_pmkid_rejected`, and `repeat_pmkid_rejected` surface the breakdown.
2. **Per-(AP, STA) deduplication**: if the same 16-byte PMKID value has already been stored for this `(AP MAC, STA MAC)` pair, the duplicate is dropped silently. Different PMKID values for the same pair are all kept.
3. **Length sanity for FT**: emitting `WPA*06*` / `WPA*10*` requires non-empty MDID, R0KH-ID, and R1KH-ID. PMKIDs from FT locations with missing FT material are stored but not emitted to `--37100-out` / `--ft-out` / `--ft-psk-sha384-out`.

hcxtools additionally rejects PMKIDs where any consecutive 4-byte window is all-zero or all-0xFF, treating these as PLCP bit errors. wpawolf's whole-field period-2 / period-4 checks cover the deterministic synthetic-pattern cases that motivated hcx's window heuristic; we do not extend the check to arbitrary 4-byte windows because that becomes heuristic (a real HMAC output occasionally has an internal 4-byte run that matches `null` or `ff` but is not garbage as a whole).

### §6.9  Known issues

**AKM 6 PMKID broken in hashcat.** hashcat mode 22000's PMKID path (`m22000_aux4`) currently uses HMAC-SHA1 for all PMKID lines regardless of AKM. AKM 6 PMKIDs require HMAC-SHA256, so the correct passphrase produces a SHA256-based PMKID that never matches the SHA1-based computation - hashcat reports "Exhausted" with no error. Workaround: attack via the EAPOL MIC instead (mode 22000's EAPOL path `m22000_aux3` correctly handles AKM 6 with AES-128-CMAC). wpawolf emits the type-04 PMKID line regardless so it will work if/when hashcat is fixed.

**AKMs 19, 20 (SHA-384 PSK).** PMK derivable from passphrase (PBKDF2-SHA1, same as AKM 2) but MIC uses HMAC-SHA-384 (24 B) and no hashcat module exists. wpawolf captures and stores the PMKID and routes the lines to `--psk-sha384-out` (type 8/9) or `--ft-psk-sha384-out` (type 10/11). See the §7 compatibility matrix for hashcat support status.

**FT Action frames and PMF.** FT Action frames (category 6) are in the robust management frame set and *can* be PMF-encrypted. An encrypted FT Action frame is opaque - wpawolf cannot extract the PMKID. The FT over-the-air path (S5 / S6, using Authentication frames) is not PMF-protected so it is always accessible; S11-S13 are captured opportunistically.

**Multiple PMKIDs in one RSNE -- resolved.** The spec ([IEEE 802.11-2024] §9.4.2.23.5, §12.6.8.3) allows a client to offer multiple PMKID candidates in the PMKID List field of a single RSNE -- the primary use case is PMKSA caching during roaming, where the client advertises every cached PMKSA identifier it believes valid for the target AP. wpawolf's RSN IE parser (`src/ieee80211/rsn.rs::parse_rsn_ie`) loops over the full PMKID Count and returns every PMKID in the list; every extraction site (S2-S20) iterates the full `Vec<[u8; 16]>` and stores each PMKID independently. hcxpcapngtool extracts only the first PMKID (`hcxpcapngtool.c:3397`). The IE Length field (1 byte, max 255) constrains the body to 255 B; with typical overhead of 22 B (Version + Group Cipher + 1 Pairwise + 1 AKM + RSN Caps + PMKID Count), the hard maximum is `floor((255 - 22) / 16) = 14` PMKIDs per RSNE. In practice, multiple PSK-derived PMKIDs in a single frame are rare (the formula is deterministic for a given PSK + SSID + AP + STA) but do occur when the AP advertises multiple AKMs (e.g. AKM 2 + AKM 6) and the client caches a PMKSA under each.

**FILS HLP Container is not an EAPOL transport.** The FILS HLP Container element (id 240, `[IEEE 802.11-2024]` §9.4.2.182) is sometimes mistaken for an EAPOL tunnel. The spec text -- mirrored in the FILS Authentication / `(Re)Association` Request / Response parameter descriptions -- defines the contents as "encapsulated data of higher layer protocol frames (e.g., a DHCP message)". HLP carries DHCP, ARP, and similar non-EAPOL traffic to shave a round trip off association; it does not carry EAPOL-Key M1 / M2 / M3 / M4. The full FILS PMK derivation happens inside the FILS Authentication frame exchange and yields a PMKID that wpawolf already harvests at sources S7 / S8 (`PmkidSource::FilsAuth*`). wpawolf intentionally does not parse HLP bodies: there is no PSK-crackable hash inside.

---

## §7  Hashcat output -- architectural decisions

The detailed hash-line formats (per-prefix layout, field widths, MIC zeroing, MAC / ESSID encoding) live in [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) §5. How the 11 types currently route through hashcat modes 22000 / 37100 lives in [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md). The complete operator-facing CLI / sink reference (every `--*-out` flag, routing rules, stats output) lives in [`README.md`](README.md). This section captures only the architecture-level decisions behind the output stage.

**Per-sink fan-out with per-sink dedup.** A single classified hash is written to up to three sinks per emission: the legacy `--22000-out` *or* `--37100-out` (chosen by `is_ft`), the per-AKM-family per-AKM sink for the hash's row (`--wpa1-out` ... `--ft-psk-sha384-out`), and the combined `-o` per-AKM sink. Each sink keeps its own dedup `HashSet<u64>` so a logical hash that fans out to N sinks lands once per sink without one suppressing another. The same SipHash-1-3 fingerprint scheme is used across all sinks (kind byte + PMKID/MIC + AP + STA + nonce/eapol + ESSID + message-pair) -- see §4 invariant 5.

**Logical-vs-line counting.** `hashes emitted (total)` in the Phase 5 report counts logical hashes (one per `HashType` row, regardless of fan-out). The Phase 4 `lines written` per-sink counters count physical lines on disk, so they do not sum to the logical total when multiple sinks are configured. This is the right semantics for both audit ("how many distinct hashes did this capture yield?") and operations ("how big will my hash file be?").

**Legacy vs extended prefix selection.** `HashType::legacy_prefix()` and `HashType::per-AKM format_prefix()` are the two sources of truth (in `src/types.rs`). Legacy sinks call the legacy prefix, per-AKM sinks call the extended prefix; nothing else in the output pipeline knows the difference. Adding a new sink is one match-arm change.

**PMKID and EAPOL pipelines run as separate passes** (Invariant OUT-1 in §4 invariant 6). A single `(AP, STA)` session can yield up to four distinct hash lines: 1 PMKID plus up to 3 equivalence-class EAPOL pairs (FR-PAIR-5). This is correct and expected; downstream tools that expect one line per session are wrong.

**FT context required for FT lines.** `wpawolf` only emits FT lines (legacy `WPA*03*` / `WPA*04*` and per-AKM format `WPA*06*` / `WPA*07*` / `WPA*10*` / `WPA*11*`) when MDID, R0KH-ID, and R1KH-ID are all present in the captured handshake. FT-PSK PMKIDs / EAPOL pairs without an FTE in the same handshake are dropped at emission time -- hashcat 37100 cannot crack them without the chain.

**SHA-384 deliberately bypasses legacy sinks.** PSK-SHA384 and FT-PSK-SHA384 hashes (types 8 -- 11) are *not* written to the legacy `--22000-out` / `--37100-out` sinks. `legacy_sink_for` in `src/output/mod.rs` returns `None` for these hash types. The reason is hashcat's mode 22000 strict-checks the MIC field at exactly 16 bytes (`module_22000.c::check_token`) and rejects any line with a wider MIC at parser startup with a `Token length exception`; mode 37100 only ships a SHA-256 FT key-hierarchy kernel and rejects the SHA-384 chain the same way. Routing the 24-byte HMAC-SHA384-192 MIC through those sinks would therefore poison the input file with unparseable lines. The dedicated per-AKM sinks (`--psk-sha384-out`, `--ft-psk-sha384-out`) and the combined `-o` sink continue to receive these lines under the `WPA*08*..*11*` extended prefix, where downstream tooling can recognise the wider MIC width.

### Hashcat compatibility matrix

| Type | Hash family            | Legacy sink         | Per-AKM sink           | hashcat support today |
| ---- | ---------------------- | ------------------- | ----------------------- | --------------------- |
| 1    | WPA1-PSK EAPOL         | `--22000-out` (`WPA*02*`) | `--wpa1-out` (`WPA*01*`) | mode 22000, KDV=1 (HMAC-MD5 MIC) |
| 2    | WPA2-PSK PMKID         | `--22000-out` (`WPA*01*`) | `--wpa2-out` (`WPA*02*`) | mode 22000 |
| 3    | WPA2-PSK EAPOL         | `--22000-out` (`WPA*02*`) | `--wpa2-out` (`WPA*03*`) | mode 22000, KDV=2 (HMAC-SHA1-128) |
| 4    | PSK-SHA-256 PMKID      | `--22000-out` (`WPA*01*`) | `--psk-sha256-out` (`WPA*04*`) | mode 22000 PMKID kernel reads HMAC-SHA1 only -- the line emits but does not crack |
| 5    | PSK-SHA-256 EAPOL      | `--22000-out` (`WPA*02*`) | `--psk-sha256-out` (`WPA*05*`) | mode 22000, KDV=3 (AES-128-CMAC MIC); cracks |
| 6    | FT-PSK PMKID           | `--37100-out` (`WPA*03*`) | `--ft-out` (`WPA*06*`) | mode 37100 (SHA-256 FT chain) |
| 7    | FT-PSK EAPOL           | `--37100-out` (`WPA*04*`) | `--ft-out` (`WPA*07*`) | mode 37100 (SHA-256 FT chain) |
| 8    | PSK-SHA-384 PMKID      | *(skipped)*         | `--psk-sha384-out` (`WPA*08*`) | no kernel; per-AKM sink only |
| 9    | PSK-SHA-384 EAPOL      | *(skipped)*         | `--psk-sha384-out` (`WPA*09*`) | no kernel (24 B MIC); per-AKM sink only |
| 10   | FT-PSK-SHA-384 PMKID   | *(skipped)*         | `--ft-psk-sha384-out` (`WPA*10*`) | no kernel; per-AKM sink only |
| 11   | FT-PSK-SHA-384 EAPOL   | *(skipped)*         | `--ft-psk-sha384-out` (`WPA*11*`) | no kernel (24 B MIC + SHA-384 FT chain); per-AKM sink only |

The combined `-o` sink receives every emitted hash regardless of the above; types 8-11 are visible there for downstream tooling that can read the 11-prefix per-AKM format directly. Update both `legacy_sink_for` in `src/output/mod.rs` and this table together when hashcat ships a new kernel.

---

## §8  Wire-level requirements (FR-*)

Every FR-* identifier in this section is cited by source code. Do not rename, drop, or merge them. Group changes are allowed; renumbering is not. The text is summarised; the source-of-truth wire-level details live in the spec citations attached to each requirement.

### §8.1  Input - FR-IN-* and FR-LL-*

#### FR-IN-1
Accept one or more file paths or directory paths as positional arguments. Files are processed sequentially in input order; directories are walked recursively (sorted, magic-byte-driven inclusion, symlinks not followed). Per-file ingest runs single-threaded; the parallelism budget is spent on Phase 4 pairing (FR-THREAD-2).

#### FR-IN-2
Auto-detect file format by magic bytes:

- `0x0A0D0D0A` -> pcapng Section Header Block (palindromic, `"\n\r\r\n"`)
- `0xA1B2C3D4` / `0xD4C3B2A1` -> pcap LE/BE microsecond
- `0xA1B23C4D` / `0x4D3CB2A1` -> pcap LE/BE nanosecond
- `0xA1B2CD34` / `0x34CDB2A1` -> pcap Kuznetzov-patched (24-byte packet headers; libpcap `sf-pcap.c`)
- `0x1C0001AC` / `0xAC01001C` -> IXIA lcap hardware-capture (nanosecond); `0x1C0001AB` / `0xAB01001C` -> IXIA lcap software-capture (microsecond). 24-byte packet headers (standard 20 + 4-byte total-count field, read and discarded). Per wireshark `wiretap/libpcap.c`, issue #14073.
- `0x1F8B` -> gzip; decompress and re-detect inner format
- Unknown -> error with hex dump of first 4 bytes

#### FR-IN-3
For pcapng, handle byte-order magic (`0x1A2B3C4D` vs `0x4D3C2B1A`) per-section. Swap all multi-byte fields when big-endian. Each section delimited by SHBs can have different endianness. [draft-ietf-opsawg-pcapng §3.6.1, §4.1]

#### FR-IN-4
Support multiple Interface Description Blocks with different link types and timestamp resolutions within a single pcapng file. Interface IDs are assigned sequentially starting at 0 within each section, in IDB appearance order. Parse `if_tsresol` option (code 9, 1 byte): MSB=0 -> resolution is 10^(-value) seconds; MSB=1 -> resolution is 2^(-(value & 0x7F)) seconds. Default: 10^-6. [draft-ietf-opsawg-pcapng §4.2]

#### FR-IN-5
Parse pcapng blocks by Block Type:

- `0x0A0D0D0A` SHB - re-init section state
- `0x00000001` IDB - register interface
- `0x00000006` EPB - extract packet data
- `0x00000003` SPB - skip (no timestamp, no interface ID)
- `0x00000004` NRB - skip
- `0x00000005` ISB - skip
- `0x00000BAD` / `0x40000BAD` Custom Block - skip
- All other block types - skip (read Block Total Length, seek past)

Every block ends with a repeated Block Total Length. BTL is always multiple of 4. Packet data within EPB padded to 4-byte boundary. [draft-ietf-opsawg-pcapng §3.1, §4.1-4.8]

#### FR-IN-6
For pcapng EPB timestamps, combine Timestamp High and Low into 64-bit: `ts_u64 = (ts_high << 32) | ts_low`. Convert to microseconds using the interface's `if_tsresol`. Apply `if_tsoffset` (option code 14, i64 seconds) if present. [draft-ietf-opsawg-pcapng §4.3]

#### FR-IN-7
Classic pcap 24-byte global header: magic (4), version_major (2), version_minor (2), thiszone (4, ignore), sigfigs (4, ignore), snaplen (4), linktype (4). Current version: 2.4. linktype lower 16 bits are the link type; bit 26 is FCS-length-present flag; bits 28-31 are FCS length in 16-bit words. [libpcap `pcap/pcap.h`, `sf-pcap.c`]

#### FR-IN-8
Classic pcap packet record header (16 bytes): tv_sec (u32), tv_usec (u32), caplen (u32), len (u32). Both tv_sec and tv_usec are unsigned 32-bit regardless of platform. For nanosecond magic, tv_usec contains nanoseconds. For Kuznetzov magic, packet headers are 24 bytes (16 standard + 4 index + 2 protocol + 1 pkt_type + 1 padding). [libpcap `sf-pcap.c:151-174`]

#### FR-IN-9
Read input in a streaming fashion. Never buffer more than one pcapng block (or one pcap packet record) in memory at a time. I/O buffer size: configurable, default 64 KiB.

#### FR-IN-10
Handle truncated captures gracefully. On EOF mid-record (pcap) or mid-block (pcapng), log the byte offset and stop processing the file. Do not panic, do not drop stored handshakes from earlier in the same file. Multi-file runs continue with the next file.

#### FR-IN-11
Handle multi-member gzip streams. `flate2::read::GzDecoder` reads through concatenated gzip members until the final EOF. No special casing needed; `cat a.pcap.gz b.pcap.gz > merged.pcap.gz` works.

#### FR-IN-12
For pcapng, the `if_tsoffset` option (code 14, i64 seconds) is added to the EPB timestamp BEFORE converting to microseconds. Captures rolled over midnight on non-UTC systems rely on this; forgetting it shifts every handshake timestamp by whatever the offset is.

### §8.2  Link-layer - FR-LL-*

#### FR-LL-1
Parse Radiotap headers (DLT 127). Fields little-endian. Fixed 8-byte header: `it_version` (u8, must be 0), `it_pad` (u8), `it_len` (u16 LE, total header length including this 8-byte part), `it_present` (u32 LE, bitmask). Bit 31 of `it_present` set -> additional u32 present words follow until one with bit 31 clear. Skip to IEEE 802.11 frame at offset `it_len`. Bit 1 of first `it_present` set -> Flags field present; if `flags & 0x10`, the frame has a 4-byte FCS appended (subtract 4 from frame length). All radiotap fields require natural alignment relative to byte 0 (u16 -> 2, u32 -> 4, u64 -> 8). [radiotap.org spec]

#### FR-LL-2
Parse PPI headers (DLT 192). Fields little-endian. Fixed 8-byte header: `pph_version` (u8), `pph_flags` (u8), `pph_len` (u16 LE, total header length), `pph_dlt` (u32 LE, must be DLT_IEEE802_11 = 105). Skip to payload at offset `pph_len`. [hcxtools `ieee80211.h:225-233`, libpcap `dlt.h:818`]

#### FR-LL-3
Parse Prism headers (DLT 119). Host byte order (LE in practice). Header: `msgcode` (u32), `msglen` (u32, total header length), `devname` (16 bytes), then 10 x 12-byte Prism items. Typical 144 bytes. Use `msglen` (not hardcoded 144) to find the 802.11 frame offset. AVS- within-Prism detection: read first 4 bytes as BE u32, mask `& 0xFFFFF000`, compare to `0x80211000`; if match, treat as AVS per FR-LL-4. [libpcap `gencode.c:3441-3505`, hcxtools `ieee80211.h:176-203`]

#### FR-LL-4
Parse AVS / WLAN-NG headers (DLT 163, or detected within DLT 119). Fields **big-endian** per spec. Header: `version` (u32 BE, upper 20 bits = `0x80211`), `len` (u32 BE, total header length), then mactime (u64), hosttime (u64), phytype (u32), channel (u32), datarate (u32), antenna (u32), priority (u32), ssi_type (u32), ssi_signal (i32), ssi_noise (i32), preamble (u32), encoding (u32). Minimum 64 bytes. Use `len` for frame offset. hcxtools treats AVS as LE - documented bug not replicated. [libpcap `gencode.c:3479`, hcxtools `ieee80211.h:205-223`]

#### FR-LL-5
Handle raw IEEE 802.11 (DLT 105). No link-layer header. Frame starts at offset 0.

#### FR-LL-6
Reject unsupported link types with a warning. Do not abort the file - skip packets from that interface.

### §8.3  802.11 frame parsing - FR-80211-*

#### FR-80211-1
Parse the 802.11 MAC header. Frame Control field (2 B, LE) bit layout per `[IEEE 802.11-2024]` §9.2.4.1, Figure 9-3:

```
B0-B1:  Protocol Version (must be 0)
B2-B3:  Type (0=Mgmt, 1=Ctrl, 2=Data)
B4-B7:  Subtype
B8:     To DS
B9:     From DS
B10:    More Fragments
B11:    Retry
B12:    Power Management
B13:    More Data
B14:    Protected Frame
B15:    +HTC/Order
```

MAC header byte offsets (3-address frame):

```
Offset  0: Frame Control       (2 B)
Offset  2: Duration/ID         (2 B)
Offset  4: Address 1           (6 B)
Offset 10: Address 2           (6 B)
Offset 16: Address 3           (6 B)
Offset 22: Sequence Control    (2 B)
Offset 24: [Address 4]         (6 B, only when To DS=1, From DS=1)
Offset 24/30: [QoS Control]    (2 B, only for QoS Data subtypes)
```

Address mapping per `[IEEE 802.11-2024]` §9.3.2.1.2 Table 9-60:

| To DS | From DS | AP MAC | STA MAC |
|-------|---------|--------|---------|
| 0 | 0 | BSSID (addr3) | SA (addr2) |
| 0 | 1 | BSSID (addr2) | DA (addr1) |
| 1 | 0 | BSSID (addr1) | SA (addr2) |
| 1 | 1 | TA (addr2)    | RA (addr1) |

Always process relay/WDS frames (To DS=1, From DS=1). No filtering (§4 invariant 4).

#### FR-80211-2
Management frames (type 0). Subtypes per §9.2.4.1.3 Table 9-1:

- **Beacon (subtype 8)**: Parse SSID (Element ID 0, max 32 B per §9.4.2.2), RSN IE (Element ID 48 per §9.4.2.24), RSNXE (Element ID 244 per §9.4.2.241) for SAE-H2E / SAE-PK / OCI bits. Vendor IEs (Element ID 221) by OUI: `00:50:F2` Microsoft (type 1 = WPA1, type 4 = WPS); `50:6F:9A` WFA (type 9 = P2P, type 16 = HS 2.0, type 18 = OSEN, type 28 = OWE Transition Mode).
- **Probe Response (subtype 5)**: Same as Beacon.
- **Probe Request (subtype 4)**: Extract SSID (length 0 = wildcard).
- **Association Request (subtype 0)**: Parse RSN IE for PMKID list. RSNXE optional.
- **Reassociation Request (subtype 2)**: Parse RSN IE for PMKID list. Parse MDE (Element ID 54, §9.4.2.45) for MDID. Parse FTE (Element ID 55, §9.4.2.46) for R0KH-ID (subelement type 3, 1-48 B) and R1KH-ID (subelement type 1, 6 B) per Table 9-221.

#### FR-80211-3
Data frames (type 2):

- QoS detection: bit B7 of Subtype = 1 -> QoS data frame. QoS Control field is 2 extra bytes after Sequence Control (or Address 4 in 4-address). Per §9.2.4.5. Frame body offsets: 24 (non-QoS 3-addr), 26 (QoS 3-addr), 30 (non-QoS 4-addr), 32 (QoS 4-addr).
- A-MSDU detection: QoS Control A-MSDU Present bit (bit 7) per §9.2.4.5.9. Each subframe: 14-byte header (DA 6, SA 6, Length 2 BE), LLC/SNAP, payload, padded to 4-byte boundary. Iterate subframes, check each for EtherType `0x888E`.
- +HTC/Order: Frame Control bit 15 set -> 4-byte HT Control field follows QoS Control per §9.2.4.6. Body offset increases by 4.
- LLC/SNAP (8 bytes per RFC 1042): DSAP=`0xAA`, SSAP=`0xAA`, Control=`0x03`, OUI=`00:00:00`, EtherType (2 B BE). EtherType `0x888E` = IEEE 802.1X / EAPOL.
- EAPOL header (4 bytes): Protocol Version (1), Packet Type (1), Body Length (2 BE). Packet Type `3` = EAPOL-Key, Packet Type `0` = EAP-Packet.
- Parse EAPOL-Key body per `[IEEE 802.11-2024]` §12.7.2.
- Parse EAP frames (Packet Type 0) per RFC 3748.
- Protected Frame bit (FC bit 14): set -> MPDU encrypted. Initial M1/M2/M3/M4 are clear regardless of PMF (§12.7.6 / §12.7.9). Encrypted management frames are logged in `stats.encrypted_mgmt_count` and skipped.

#### FR-80211-4
EAPOL-Key frame Key Information field (2 B, offset 5 from EAPOL body start, BE) per §12.7.2 Figure 12-36:

```
B0-B2:  Key Descriptor Version (0=AKM-determined, 1=HMAC-MD5/ARC4,
                                2=HMAC-SHA1/AES, 3=AES-CMAC/AES)
B3:     Key Type (1=Pairwise, 0=Group)
B4-B5:  Reserved
B6:     Install
B7:     Key Ack
B8:     Key MIC Present
B9:     Secure
B10:    Error
B11:    Request
B12:    Encrypted Key Data
B13-B15: Reserved
```

Message identification per §12.7.6.2-12.7.6.5 - see §5.3 for the canonical truth table.

Per §12.7.2 NOTE 9: M4 Key Nonce SHALL be zero; some Supplicant implementations set it to M2's SNonce. Parser accepts both.

#### FR-80211-5
EAPOL frame validation:

- MIC field non-zero for M2/M3/M4 (unless AKM 14/15 AEAD).
- Nonce non-zero for M1/M2/M3. M4 nonce may be zero or non-zero.
- No upper limit on EAPOL frame size.
- KDV: accept 0/1/2/3. Value 0 = algorithm determined by AKM per Table 12-11.
- MIC length is variable per AKM per Table 12-11:
  - 16 B: AKMs 1, 2 (HMAC-SHA-1-128); AKMs 3, 4, 5, 6, 8, 9 (AES-128-CMAC); AKM 11 (HMAC-SHA-256).
  - 24 B: AKMs 12, 13, 19, 20, 22, 23 (HMAC-SHA-384). Key Data Length at offset 105 instead of 97.
  - 0 B: AKMs 14, 15 (FILS AES-SIV).
  - AKM 16/17: 0/16/24 depending on EAPOL-Key (AES-SIV) vs FT auth sequence.
  - Variable 16/24/32: AKMs 18, 24, 25 per negotiated hash.
  - AKM 21 (PASN): no EAPOL-Key.
- KDV consistency per §12.7.2 bullet list:
  - KDV=1 iff AKM 1 or 2 with TKIP pairwise (legacy)
  - KDV=2 iff AKM 1 or 2 with non-TKIP RSNA pairwise
  - KDV=3 iff AKM 3, 4, 5, or 6 (mandatorily)
  - KDV=0 otherwise
  - Other values increment `stats.bad_kdv_count` and the frame is skipped.
- Reject frames with all-ones (0xFFFFFFFF) in MIC or nonce.

### §8.4  PMKID extraction - FR-PMKID-*

#### FR-PMKID-1
Extract PMKID from M1 Key Data. Parse TLV: tag 0xDD, length 0x14 (20 bytes), OUI `00:0F:AC`, type `0x04`. PMKID is 16 bytes following the OUI+type. Validate: not all zeros, not all ones. PMKID derivation formula by AKM per `[IEEE 802.11-2024]` §12.7.1.3 (see §6.2). `"PMK Name"` is literal ASCII (8 bytes: `50 4D 4B 20 4E 61 6D 65`). AA = AP MAC, SPA = STA MAC.

#### FR-PMKID-2
Extract PMKID from M2 RSN IE in Key Data. RSN IE structure per §9.4.2.24 Figure 9-367:

```
Element ID (1, =48) | Length (1) | Version (2, =1) |
Group Data Cipher Suite (0 or 4) | Pairwise Cipher Suite Count (0 or 2) |
Pairwise Cipher Suite List (4*m) | AKM Suite Count (0 or 2) |
AKM Suite List (4*n) | RSN Capabilities (0 or 2) |
PMKID Count (0 or 2) | PMKID List (16*s) |
Group Management Cipher Suite (0 or 4)
```

All fields after Version are optional - if one is absent, all subsequent are absent. Extract AKM suite selector (OUI `00:0F:AC` + type byte) per Table 9-190; cipher suites per §9.4.2.24.2 Table 9-188; RSN Capabilities per §9.4.2.24.4 Figure 9-374. wpawolf logs the raw RSN Capabilities hex into `stats.rsn_caps_histogram` and uses bits B6/B7 (MFPR/MFPC) to annotate each `(AP, STA)` pair with PMF state.

#### FR-PMKID-3
Extract PMKID from Association/Reassociation Request RSN IE. Parse RSN IE from tagged parameters, extract PMKID list. For FT-PSK: also parse MDE (Element ID 54 per §9.4.2.45) for MDID (2 B) and FTE (Element ID 55 per §9.4.2.46) for R0KH-ID (subelement type 3, 1-48 B) and R1KH-ID (subelement type 1, 6 B).

#### FR-PMKID-4
Extract ALL PMKIDs regardless of AKM type. No filtering based on hashcat support status. Route to appropriate output format per the table in §6.4.

### §8.5  EAPOL message storage - FR-MSG-*

#### FR-MSG-1
Store ALL extracted EAPOL messages in a hash map keyed by `(AP_MAC, STA_MAC)`. No circular buffer. No eviction. No per-type cap. Process aborts if RSS exceeds 80 % of system RAM.

#### FR-MSG-2
Each stored message contains: timestamp (u64 us), msg_type (M1/M2/M3/M4), replay_counter (u64), nonce (32 B), mic (16 B), KDV (0/1/2/3), eapol_frame (heap, no upper bound), eapol_frame_len, pmkid (16 B optional), FT fields (MDID 2 B, R0KH-ID up to 48 B, R1KH-ID 6 B), AKM type from context.

#### FR-MSG-3
No memory ceiling. Memory scales with EAPOL message count, not file size. Typical 100 GB capture with <1M EAPOL messages: <250 MiB. The OS OOM killer is the natural backstop for degenerate inputs.

#### FR-MSG-4
The statistics summary is printed to stdout unconditionally after every run. stderr produces no output. wpawolf does not report process memory usage; `/proc/self/status` VmRSS is misleading. Operators run `/usr/bin/time -v wpawolf ...` for an authoritative number.

### §8.6  Pairing - FR-PAIR-*

#### FR-PAIR-1
After all input is parsed, iterate over each `(AP_MAC, STA_MAC)` group. Sort messages within each group by timestamp.

#### FR-PAIR-2
Generate all valid message pair combinations - the 6 N#E# combos documented in §5.6.

#### FR-PAIR-3
Pairing constraints (output filters, all off by default):

- Time gap <= `--eapoltimeout` seconds when set; bare flag = 600 s.
- Replay counter gap <= `rc_drift_tolerance` (default 8 when bare). Only enforced when `--rc-drift` is set:
  - M1->M2: `RC_M2 == RC_M1` within tolerance
  - M2->M3: `RC_M3 == RC_M2 + 1` within tolerance
  - M3->M4: `RC_M4 == RC_M3` or `RC_M4 == RC_M3 + 1` within tolerance
  - M1->M4: `RC_M4 - RC_M1` within tolerance

#### FR-PAIR-4
Within each combo type, prefer the pair with the smallest time gap. If time gaps are equal, prefer smallest RC gap.

#### FR-PAIR-5
Hash combo deduplication. Within a single handshake session (same ANonce across M1/M3): N1E2 == N3E2 (same M2 EAPOL); N2E3 == N4E3 (same M3 EAPOL); N1E4 == N3E4 (same M4 EAPOL). When `--dedup-hash-combos` is set, emit only one hash per equivalence class. Survivor chosen by smallest RC gap then authorized combo preference (N3E2 > N1E2, N2E3 > N4E3, N3E4 > N1E4). See §5.8.

#### FR-PAIR-6
Detect nonce endianness. Compare replay counters across M1->M2 or M3->M4. If the relationship only makes sense under byte-swap, set the LE (`0x20`) or BE (`0x40`) flag in message_pair. If RC relationship is ambiguous, set NC flag (`0x80`).

#### FR-PAIR-7
Invalid value rejection (unconditional, not a flag). Per §4 invariant 7:

- Key Nonce matching any garbage-pattern kind (`null`, `ff`, `repeat_1`, `repeat_2`, `repeat_4`): rejected at parse time on every message type including M4. M4 NULL nonce is spec-valid on the wire per §12.7.6.5 NOTE 9 but the hash line is mathematically uncrackable (the live PTK depends on M2's `SNonce`, which the M4 frame does not carry); see §5.10.
- MIC matching any garbage-pattern kind when Key MIC Present (B8) is set: rejected. M1 MIC is legitimately zero and is not checked.
- PMKIDs matching any garbage-pattern kind: rejected at store insertion.
- ESSIDs are NOT garbage-filtered and NOT transformed. Per [IEEE 802.11-2024] §9.4.2.2 the SSID element is "an arbitrary sequence of 0-32 octets" with no printable-character restriction; wpawolf ships the byte run to hashcat unchanged. The spec-driven discard rule (length 0, length > 32, first byte 0) stays the only path that drops an SSID; SSIDs that pass it but contain at least one byte in `0x00..=0x1F` (the full ASCII C0 control range) emit an informational `[essid_control_bytes]` log line and bump `essid_control_bytes_warned`. **This is informational, not a discard and not a notice that wpawolf altered the SSID** -- the byte run still flows to hashcat as-is.

Counters: `null_nonce_rejected`, `ff_nonce_rejected`, `repeat_nonce_rejected`, `null_mic_rejected`, `ff_mic_rejected`, `repeat_mic_rejected`, `null_pmkid_rejected`, `ff_pmkid_rejected`, `repeat_pmkid_rejected`, `essid_control_bytes_warned`.

### §8.7  ESSID and output formatting - FR-ESSID-*, FR-OUT-*, FR-DEDUP-*

#### FR-ESSID-1
Build an ESSID map: `AP_MAC -> Vec<(ESSID, timestamp)>`. Populated from Beacons and Probe Responses.

#### FR-ESSID-2
When generating a hash line, look up the AP MAC in the ESSID map. If multiple ESSIDs exist for the same AP (SSID change), use the one closest in time to the handshake.

#### FR-ESSID-3
If no ESSID is found for an AP, **drop** the would-have-been-emitted hash line and account for it via the `[essid_not_found_summary]` log category in `--log` (one line per affected AP with `dropped=N`, `first_seen_us=`, `last_seen_us=`). Hashcat derives the PMK from PSK + ESSID, so an empty-ESSID line can never match -- emitting it would waste downstream cracking time and trigger `Salt-value exception` / `Token length exception` parser errors in mode 22000 / 37100. The Phase 3 stats banner surfaces the same information as `hash lines dropped (no SSID resolved; not crackable)` with the `distinct APs dropped` sub-counter.

#### FR-OUT-1
Mode 22000 PMKID line shape (canonical type 02; types 04, 08 use the same shape with only the `<XX>` code changing):

```
WPA*02*<PMKID>*<MAC_AP>*<MAC_STA>*<ESSID>***<MP>
       32hex   12hex    12hex    0-128hex   2hex
```

Trailing `***` = three empty fields (reserved, maintain field count). See §7.2.

#### FR-OUT-2
Mode 22000 EAPOL line shape (canonical type 03):

```
WPA*03*<MIC>*<MAC_AP>*<MAC_STA>*<ESSID>*<NONCE>*<EAPOL>*<MP>
       32hex 12hex    12hex    0-128hex 64hex   var hex 2hex
```

`<MIC>` is the original Key MIC extracted before zeroing. `<NONCE>` is the **external** nonce. `<EAPOL>` is the raw frame with the Key MIC field zeroed at offset 77..(77+MIC_len). MIC length is AKM-dependent per Table 12-11; current hashcat 22000 only accepts 16 B. `<MP>` per §5.7. See §7.3.

#### FR-OUT-3
Mode 37100 FT PMKID line (type 06):

```
WPA*06*<PMKID>*<MAC_AP>*<MAC_STA>*<ESSID>****<MDID>*<R0KHID>*<R1KHID>
       32hex   12hex    12hex    0-128hex      4hex  var hex   12hex
```

Four empty fields (reserved + mode 22000 compat padding). See §7.2.

#### FR-OUT-4
Mode 37100 FT EAPOL line (type 07):

```
WPA*07*<MIC>*<MAC_AP>*<MAC_STA>*<ESSID>*<NONCE>*<EAPOL>*<MP>*<MDID>*<R0KHID>*<R1KHID>
```

FT-PSK M2 EAPOL frames often exceed 255 bytes (real captures: 256-510) because of embedded FT IEs. wpawolf emits without truncation.

#### FR-OUT-5
No EAPOL size gating. All valid EAPOL frames are emitted regardless of length.

#### FR-OUT-6
All hex output is lowercase. Consistent encoding for deduplication and downstream tool compatibility.

#### FR-OUT-7
ESSID field is always hex-encoded because IEEE 802.11 defines SSIDs as arbitrary 0-32 byte sequences, not strings. Use field length / 2 as the ESSID byte length when parsing. Do not call `strlen()` on decoded bytes.

#### FR-OUT-8
EAPOL frame MIC zeroing for output. The EAPOL-Key frame stored in `<EAPOL>` must have the Key MIC field zeroed at offset 77..(77+MIC_len). Original MIC preserved in the `<MIC>` line field. See §7.4 for the full byte layout and AKM-dependent MIC length table.

#### FR-DEDUP-1
Before writing any hash line, check it against a global deduplication set (§4 invariant 5).

#### FR-DEDUP-2
Dedup key is a 64-bit SipHash of the significant fields. PMKID lines: `PMKID || MAC_AP || MAC_STA || ESSID`. EAPOL lines: `MIC || MAC_AP || MAC_STA || NONCE || EAPOL || ESSID`. Both prefixed by the line-kind byte to prevent cross-pipeline aliasing.

#### FR-DEDUP-3
If two hash lines differ only in ESSID (AP changed SSID), both are emitted (different ESSID = different salt = different hash).

#### FR-DEDUP-4
If two hash lines differ only in message_pair bits 3-7 (flags), keep the one with the most informative flags (prefer LE/BE detection over NC-mandatory).


### §8.8  CLI - FR-CLI-*

#### FR-CLI-1
Positional arguments: input capture file path(s) and/or directory path(s). Directories are walked recursively; every regular file whose first 4 bytes match a supported capture-file magic is added to the input set. File extensions are never consulted -- a `.bin` or extensionless file with valid magic is included; a `.pcap` file with text content is skipped. Accepted magics:

- pcap microsecond `0xA1B2C3D4` (`TCPDUMP_MAGIC`), nanosecond `0xA1B23C4D` (`NSEC_TCPDUMP_MAGIC`), and Kuznetzov `0xA1B2CD34` (`KUZNETZOV_TCPDUMP_MAGIC`), each accepted in either byte order (6 byte-sequences total) -- exactly the set libpcap's `pcap_check_header()` accepts;
- IXIA `lcap` hardware-capture `0x1C0001AC` (`PCAP_IXIAHW_MAGIC`, nanosecond) and software-capture `0x1C0001AB` (`PCAP_IXIASW_MAGIC`, microsecond), each in either byte order (4 byte-sequences total -- per wireshark `wiretap/libpcap.c`, issue #14073). Aside from one trailing 4-byte field after the standard 20-byte header tail (total packet-record byte count, read and discarded), records are standard pcap;
- pcapng SHB block-type `0x0A0D0D0A` (byte-order-independent palindrome, per draft-ietf-opsawg-pcapng-05 §4.1);
- gzip wrapper, identified by ID1/ID2 = `0x1F 0x8B` (RFC 1952 §2.3).

Files named explicitly on the command line are passed through verbatim; `open_reader` then runs the same magic check during Phase 1 and warns on unrecognised formats. Within each directory, files are sorted lexicographically and emitted before subdirectories are descended (also sorted), giving a deterministic order independent of filesystem iteration order. Symlinks are not followed.

Magics defined but never accepted by libpcap (`FMESQUITA_TCPDUMP_MAGIC`, `NAVTEL_TCPDUMP_MAGIC`, `CBPF_SAVEFILE_MAGIC`) are not accepted here either.

#### FR-CLI-2
Output flags:

| Flag | Long | Description |
|------|------|-------------|
| -          | `--22000-out FILE`        | hashcat mode 22000 (legacy `WPA*01*`/`WPA*02*`; every non-FT hash) |
| -          | `--37100-out FILE`        | hashcat mode 37100 (legacy `WPA*03*`/`WPA*04*`; every FT hash) |
| `-o FILE`  | `--out FILE`              | combined 11-type classification file (every emitted hash, prefixes `WPA*01*..*11*`) |
| -          | `--wpa1-out FILE`         | type 1 only (per-AKM format `WPA*01*`) |
| -          | `--wpa2-out FILE`         | types 2 + 3 (per-AKM format `WPA*02*`/`WPA*03*`) |
| -          | `--psk-sha256-out FILE`   | types 4 + 5 (per-AKM format `WPA*04*`/`WPA*05*`) |
| -          | `--ft-out FILE`           | types 6 + 7 (per-AKM format `WPA*06*`/`WPA*07*`, FT extras) |
| -          | `--psk-sha384-out FILE`   | types 8 + 9 (per-AKM format `WPA*08*`/`WPA*09*`, no kernel yet) |
| -          | `--ft-psk-sha384-out FILE`| types 10 + 11 (per-AKM format `WPA*10*`/`WPA*11*`, FT extras, no kernel yet) |
| `-E FILE` | `--essid-output`    | unique ESSIDs from AP-side frames (autohex) |
| `-R FILE` | `--probe-output`    | unique ESSIDs from client-side frames (Probe Requests, Action MR) |
| `-W FILE` | `--wordlist-output` | comprehensive leaked-text wordlist (superset of -E and -R, plus WPS strings, EAP identities, country codes, etc.) |
| `-I FILE` | `--identity-output` | EAP identities (autohex, sorted) |
| `-U FILE` | `--username-output` | EAP usernames (autohex, sorted) |
| `-D FILE` | `--device-output`   | WPS device info (deduped by MAC, sorted by manufacturer) |
|       | `--wordlist-scan FILE` | printable-ASCII runs (>= 8 B) from plaintext management-frame IE bodies; standalone, not folded into -W |
|       | `--log FILE`            | structured processing log |

All string outputs (-E, -R, -W, -I, -U, and string fields of -D) use hashcat / hcxtools autohex format: bytes in printable ASCII range 0x20-0x7E are written as-is; all other byte sequences are encoded as `$HEX[<lowercase hex>]`.

#### FR-CLI-3
Output-filter and runtime flags (unfiltered defaults):

| Long | Default | Description |
|------|---------|-------------|
| `--eapoltimeout` [*s*] | off | session time window in seconds; bare flag = 600 s |
| `--rc-drift` [*n*]    | off | require RC consistency, tolerance n (default 8 if bare) |
| `--dedup-hash-combos` | false | 6 combos -> 3 unique per session |
| `--nc-dedup`          | false | cluster near-identical nonces, keep one survivor with FLAG_NC (§5.8.1) |
| `--nc-tolerance` *n*  | 8 | cluster span tolerance for `--nc-dedup`; ignored unless `--nc-dedup` set |
| `--strict`            | false | bundle: `--eapoltimeout=5 --rc-drift=8 --dedup-hash-combos --per-file --nc-dedup` |
| `--per-file`          | false | pair + emit + clear MessageStore/PmkidStore per input file |
| `--threads` *n*       | CPU count | Phase 4 worker thread count |
| `--essid-collapse-min` *n* | 3 | multi-SSID collapse guard: minimum distinct SSIDs before collapse fires |
| `--essid-collapse-ratio` *n* | 10 | multi-SSID collapse guard: top-count / second-count ratio threshold |
| `--quiet`             | false | suppress periodic `[progress]` lines; closing banner unaffected |
| `--mem-stats`         | false | print per-store entry/byte table after closing banner |
| `--debug`             | false | emit timestamped phase/file/group/memory diagnostic lines to stdout |

#### FR-CLI-4
Info flags: `-h` / `--help`, `-v` / `--version` provided by `clap`. The summary statistics are printed unconditionally to stdout on every run. stderr produces no output.

`--log` categories (lowercase tags, written by `src/log.rs`):

- `malformed_frame`     - truncated or structurally invalid 802.11 / EAPOL data
- `plcp_error`          - link-layer header validation failed (radiotap / PPI / Prism / AVS error, or an unsupported DLT)
- `unknown_linktype`    - pcapng EPB referenced an `interface_id` for which no preceding IDB exists; the packet is dropped
- `unknown_akm`         - AKM suite type outside [IEEE 802.11-2024] Table 9-190
- `essid_not_found_summary` - per-AP summary: the AP's SSID was never observed, so every would-have-been-emitted hash line for it was dropped at output time as uncrackable. One line per affected AP at end of run; carries `ap=`, `dropped=N`, `first_seen_us=`, `last_seen_us=` so the operator can locate the source frames in the original capture
- `capture_read_error`  - per-file ingest error (typically a truncated trailing packet record per FR-IN-10); the file is closed and the run continues
- `invalid_nonce`       - EAPOL frame discarded: nonce matched a garbage pattern (`null` / `ff` / `repeat_1` / `repeat_2` / `repeat_4` on any message type, M4 included). M4 NULL nonce is spec-valid on the wire per §12.7.6.5 NOTE 9 but is dropped because the hash line is cryptographically dead; see §5.10. Line carries `kind=<k> nonce_hex=<32 B hex>` so downstream tooling can filter by pattern and an operator can grep the source capture for the rejected bytes
- `invalid_mic`         - EAPOL frame discarded: MIC matched a garbage pattern (`null`, `ff`, `repeat_1`, `repeat_2`, `repeat_4`) with the Key MIC flag set (M2/M3/M4). Line carries `kind=<k> mic_hex=<16/24 B hex>` (16 for AKMs 1-6, 8, 9, 11; 24 for the SHA-384 family)
- `invalid_pmkid`       - PMKID discarded: matched a garbage pattern (`null`, `ff`, `repeat_1`, `repeat_2`, `repeat_4`). Line carries `kind=<k> pmkid_hex=<16 B hex>`
- `eapol_key_rejected`  - EAPOL-Key frame passed the LLC/packet-type gate (EtherType `0x888E`/`0x88C7`, packet type = 3) but failed the EAPOL-Key parser for a structural reason other than a garbage nonce or MIC (those are already captured by `[invalid_nonce]` / `[invalid_mic]`). Carries `timestamp_us`, `ap=`, `sta=`, `reason=` (one of `truncated_short`, `bad_descriptor_type`, `bad_kdv`, `truncated_24mic`, `classify_flags_invalid`), and `bytes=` (first 32 raw bytes in lowercase colon-hex for Wireshark cross-reference). Only the ~10 genuinely structural failures per multi-GB corpus appear here; the ~15 600 spec-correct M4 null-nonce drops are already fully described by `[invalid_nonce] kind=null msg_type=m4`
- `essid_control_bytes` - SSID informational notice, **not a discard and not a sign wpawolf altered the SSID**: the SSID byte run contained at least one byte in `0x00..=0x1F` (the full ASCII C0 control range, NUL through US -- every control character). Per [IEEE 802.11-2024] §9.4.2.2 the SSID element is "an arbitrary sequence of 0-32 octets" with no printable-character requirement, so a control-byte SSID is valid on the wire; wpawolf is required to handle it and ships the byte run to hashcat unchanged. The line carries `essid_hex=` in lowercase hex so the operator triaging a capture can locate the source frame. SSIDs that fail the spec-driven length / first-byte-zero gate are discarded silently by upstream counters and are NOT logged

Format: `[category] <category-specific fields>`. Per-category field layout matches the `Logger::log_*` method signatures. Frame-bearing categories (`malformed_frame`, `plcp_error`, `invalid_nonce`, `invalid_mic`, `invalid_pmkid`, `essid_control_bytes`) lead with `timestamp_us`; `unknown_linktype`, `unknown_akm`, `essid_not_found_summary`, and `capture_read_error` do not (the event has no single packet timestamp; the summary line carries its own `first_seen_us` / `last_seen_us` range fields).

### §8.9  Correctness, performance, dependencies, build, threading

#### FR-CORRECT-1
Output is a strict content-superset of any conformant reference extractor running on the same capture with filters disabled, after stripping the trailing `message_pair` byte. The oracle lives in `tests/integration/superset_test.rs`.

#### FR-CORRECT-2
Zero duplicate hash lines in output. Verified by `sort | uniq -d` producing empty output.

#### FR-CORRECT-3
Every emitted hash line must be format-valid per the hashcat mode 22000 / 37100 specification.

#### FR-PERF-1
Process pcapng input at >= 200 MB/s on a single core (bounded by I/O, not CPU). Parser must not be the bottleneck.

#### FR-PERF-2
Total processing time for a 100 GB file should be dominated by I/O read time, not pairing or dedup.

#### FR-PERF-3
Phase 4 (pairing) runs multi-threaded by default via rayon work-stealing. The `--threads N` flag selects worker count (default = available CPU cores; `--threads=1` reproduces the serial path for deterministic test output). Pairs are streamed per-group through a `Mutex<EmitState>` callback so peak memory is bounded to one group's output at a time. All shared structures are `Send + Sync` (§4 invariant 9).

#### FR-MEM-1
No artificial memory ceiling. Memory scales with EAPOL message count.

#### FR-MEM-2
I/O buffer: one read buffer (default 64 KiB). No full-file buffering. Streaming parser reads one block/record at a time.

#### FR-MEM-3
Estimated memory for typical captures - see §4 memory budget table.

#### FR-MEM-4
wpawolf does not introspect its own memory footprint; process memory is measured externally via `/usr/bin/time -v` or `perf stat`.

#### FR-DEP-1
Direct dependency count: 4 crates (`flate2` + `clap` + `rayon` + `sysinfo`). `flate2` pulls `miniz_oxide`; `clap` pulls its derive/builder proc-macro ecosystem; `rayon` pulls `crossbeam-deque`/`crossbeam-epoch`; `sysinfo` is self-contained on Linux (adds `core-foundation-sys` on macOS).

#### FR-DEP-2
No large async / serialisation frameworks. All hex encoding, pcap / pcapng / 802.11 / EAPOL parsing is implemented inline.

#### FR-DEP-3
If cryptographic primitives are needed in future versions, prefer battle-tested libraries (RustCrypto) over inline implementations.

#### FR-DEP-4
pcap / pcapng parsing implemented inline. No pcap library dependencies. The formats are simple and total ~500 lines.

#### FR-BUILD-1
Single static binary. No runtime dependencies.

#### FR-BUILD-2
Cross-compile targets: x86_64-linux, aarch64-linux at minimum.

#### FR-BUILD-3
Release binary <= 5 MiB stripped.

#### FR-THREAD-1
Phase 1 (parsing) is I/O-bound and sequential for a single file. Multi- file ingest still runs serially in v1; pipeline parallelism (reader thread + parser thread) and parallel-file processing are deferred.

#### FR-THREAD-2
**Shipped.** Phase 4 (pairing) runs each `(AP, STA)` group in parallel via rayon work-stealing. `--threads N` selects worker count (default = CPU cores). Pairs stream through a per-group fan-out callback (no all-pairs Vec materialization).

#### FR-THREAD-3
**Shipped.** Per-sink output writers serialise on a single `Mutex<HashSet<u64>>` dedup set keyed by SipHash-1-3 fingerprints over the significant fields. Pairing threads compute fingerprints in parallel; only the cross-thread set membership check + line write sequence is locked.

---

## §9  Stats catalogue

The closing summary is hcxpcapngtool-shaped: anyone who has read `hcxpcapngtool` output should be able to read wpawolf output without a glossary. We match hcxpcapngtool's line set as the floor and add more where the upstream tool is missing data. The summary is reorganised into five banner sections (one per pipeline phase) so an operator can immediately see which phase a parse failure occurred in.

### §9.1  Phase 1 (Ingest) counters

- `input_file_count` -- regular files actually opened by the ingest loop. Single-file runs render the original `file name / file format / endian / network type` quartet for hcxpcapngtool parity; multi-file runs (when positional args expand to more than one capture, typically from a recursive directory walk) instead surface a histogram-style banner: `input files processed`, `file formats seen` (e.g. `pcap 2.4 (12), pcapng 1.0 (3)`), `endians seen`, `network types seen`, `last file processed`.
- `file_formats_seen` / `endians_seen` / `dlt_descs_seen` -- `BTreeMap<String, u64>` histograms populated once per file from the reader's `FileMetadata`. Sorted by descending count (then key) at display time so an operator can spot a single odd file in a large multi-capture run.
- Truncated-trailing-record count (`truncated_capture_files`, `unreadable_packets`); MAC-header-malformed count (`malformed_mac_hdr`); link/parse error count (`link_errors`); forgiven non-zero Protocol Version frames (`lenient_proto_version`).
- FCS framing count (radiotap Flags bit 0x10).
- Multi-member gzip stream count.

Every "issue" stat is suffixed with whether the count means data was **dropped** (frames or hashes lost), **recovered** (the issue was worked around and the data was processed), or **diagnostic** (the issue was noted but had no data impact). For example `link/parse errors (frames dropped)`, `frames with non-zero Protocol Version (forgiven; processed)`, `capture files with truncated trailing record (earlier records kept)`. This convention applies across every phase.

### §9.2  Phase 2 (Decode) counters

- Per-DLT packet counts (105, 119, 127, 163, 192) - parser-health signal for radiotap / PPI / Prism mismatch.
- Radiotap vendor-namespace blocks skipped; AVS-within-Prism frames detected.
- Per-band packet counts (2.4 / 5 / 6 GHz) from radiotap Channel field; beacon channel distribution from DS Parameter Set IE (tag 3).
- WDS / 4-address frame count (`stats.wds_count`); frame-type histogram (mgmt / ctrl / data); encrypted management frame count (`stats.encrypted_mgmt_count`); malformed MAC header counter.
- A-MSDU aggregation: `stats.amsdu_frames_seen` (Data frames with A-MSDU bit set) and `stats.amsdu_subframes_total` (subframes parsed for hidden EAPOL).
- Radiotap FCS: `stats.fcs_stripped_frames` (frames whose trailing 4-byte FCS was tail-stripped because radiotap Flags bit `0x10` signalled `IEEE80211_RADIOTAP_F_FCS`).
- EAPOL Key Descriptor Version histogram: `stats.eapol_kdv1` (HMAC-MD5 / WPA legacy), `eapol_kdv2` (HMAC-SHA1 / WPA2-PSK family), `eapol_kdv3` (AES-CMAC / PSK-SHA256 family), `eapol_kdv_other` (KDV=0 or reserved). Plus `stats.eapol_rsn` vs `stats.eapol_wpa` for the descriptor type byte (0x02 RSN vs 0xFE WPA legacy). Drives the KDV-first AKM reconciliation in `store_eapol_key`.

### §9.3  Phase 3 (Extract) counters

**Management subtype counts.**

- Beacons, Probe Requests (directed / undirected), Probe Responses.
- Association Requests, Reassociation Requests with per-AKM breakdown (PSK / FT-PSK / PSK-SHA256 / SAE / OWE).
- Authentication frames per algorithm (Open System / Shared / SAE / FBT / FILS / PASN / Network-EAP / unknown).
- Action frames: total + containing ESSID. AWDL.
- Deauthentication, Disassociation. Reason Code histogram per `[IEEE 802.11-2024]` §9.4.1.7 Table 9-90 with these promoted to their own counters:
  - Reason 14 "Message integrity code (MIC) failure" -> `stats.mic_failure_deauths` (canonical "this handshake will never pair cleanly" signal).
  - SAE status 77 "Authentication is rejected because the offered finite cyclic group is not supported" -> `stats.sae_group_rejected` (WPA3 equivalent of the FT failure signals).
- Authentication response Status Code per §9.4.1.9 Table 9-92, with these promoted:
  - 52 "R0KH unreachable" -> own counter.
  - 53 "Invalid PMKID" -> own counter.
  - 54 "Invalid MDE" -> own counter.
  - 55 "Invalid FTE" -> own counter.

**ESSID counters.**

- Total unique, SSID wildcard / unset, zeroed SSID, oversized SSID, ESSID changes per AP.
- `essid_unresolved_emissions` / `essid_unresolved_aps` -- hash lines dropped at output time because no ESSID was ever observed for the AP (uncrackable per FR-ESSID-3), and the count of distinct AP MACs contributing those drops. Each affected AP also produces one `[essid_not_found_summary]` line in `--log` carrying `dropped=N`, `first_seen_us=`, `last_seen_us=`.

**Multi-SSID inflation -- why this exists.**

Hash extraction is a per-(AP, SSID) cartesian product: every recorded SSID for an AP produces its own hash line because the PMK derivation binds PSK + SSID. In a clean capture this is the right behaviour -- dual-band ("Home-2g" / "Home-5g") and 3-SSID enterprise rollouts ship 2-3 lines per AP and a downstream tool cracks whichever applies.

In a corpus with RF-rotted captures, one physical AP can produce 4-30+ "distinct" SSIDs that are all bit-flipped variants of one real broadcast. The fanout inflates one crackable handshake into N uncrackable lines plus one crackable line, polluting the queue. The per-AP fanout is also load-bearing on the scan-line yield: a thousand corrupted APs with mean fanout 6 add ~5000 line-equivalents that nobody can solve.

`--essid-collapse-min` / `--essid-collapse-ratio` collapse the inflation when both axes agree. The collapse minimum (default 3) keeps genuine multi-SSID setups untouched; the collapse ratio (default 10) keeps APs with no clear primary SSID untouched (e.g. a CTF AP cycling through 11 named SSIDs with similar counts). Both must trip for the collapse to fire, so a singleton corruption (`SSID-A x4192`, `SSID-B x3`) drops the corruption while a 4-SSID load-balanced rollout (counts 100/95/90/85) ships every SSID. Defaults are tuned against a representative multi-SSID sample drawn from real-world captures: most multi-SSID hash-producing APs broadcast 2 SSIDs (genuine dual-band), a smaller fraction broadcast 3 (segmented rollouts), and outliers exhibit clear RF-rot patterns. See README "When one AP shows up under many SSIDs" for a worked example.

**EAPOL counters.**

- M1 / M2 / M3 / M4 totals, oversized, FT-using-PSK.
- Max EAPOL authentication length seen per message type.
- Replay-counter gap histogram, EAPOLTIME gap (max ms).
- ANonce error corrections, M4 zeroed-nonce count, M1 4E4 authorized variants.
- Rejection counters: `null_nonce_rejected`, `ff_nonce_rejected`, `repeat_nonce_rejected`, `null_mic_rejected`, `ff_mic_rejected`, `repeat_mic_rejected`, `null_pmkid_rejected`, `ff_pmkid_rejected`, `repeat_pmkid_rejected`, `bad_kdv_count`.
- Informational counter: `essid_control_bytes_warned` (SSIDs that survived the spec gate but contained at least one byte in `0x00..=0x1F`; not a rejection, not a transformation -- the SSID byte run is shipped to hashcat unchanged).
- WDS direction tier breakdown: `eapol_tier1_direction`, `eapol_tier1b_essid`, `eapol_tier2_ack_discovery`, `eapol_tier3_flag_fallback`, `eapol_ack_mismatches`.
- `eapol_preauth_frames` -- LLC/SNAP `EtherType` `0x88C7` frames per [IEEE 802.11-2024] §12.3.2; counted alongside standard `0x888E` so inter-AP preauth traffic is visible.
- `eapol_llc_invalid` -- frames where the LLC/SNAP `EtherType` was `0x888E` / `0x88C7` AND the EAPOL Packet Type byte was 3 (EAPOL-Key) but the EAPOL-Key parser bailed (truncated body, bad descriptor, sentinel-rejected MIC/nonce). EAP-Packet (type 0), EAPOL-Start (1), and EAPOL-Logoff (2) are legitimate non-key frames and do **not** increment this counter.
- `mesh_control_frames` -- mesh BSS Data frames whose Mesh Control header was successfully skipped per §9.2.4.8.3, recovering an inner MSDU for downstream EAPOL/EAP processing.
- `eap_success_frames` / `eap_failure_frames` -- terminal EAP outcome codes (RFC 3748 §4.2). Stats-only; carry no identity data and never affect hash extraction. Drives capture-quality triage for mixed PSK / Enterprise traffic.

**Plaintext extraction surfaces.** Every IE / vendor-IE / action-frame field that yields wordlist-grade plaintext is parsed and counted. The catalogue below is the contract -- a regression that drops one of these surfaces is a `tests/integration/extraction_coverage.rs` failure.

| Surface | Spec / source | Counter | Sink |
|---|---|---|---|
| SSID (tag 0) | §9.4.2.2 | (always) | `essid_set`, `essid_map`, wordlist |
| SSID List (tag 84) | §9.4.2.71 | `ssid_list_entries` | `essid_set`, wordlist |
| Mesh ID (tag 114) | §9.4.2.97 | `mesh_ids_extracted` | `essid_map`, `essid_set`, wordlist |
| Country (tag 7) | §9.4.2.9 | `country_codes_extracted` | wordlist |
| Time Zone (tag 98) | §9.4.2.85 | `time_zones_extracted` | wordlist |
| WPS device info (vendor IE OUI `00:50:F2` type 4) | WPS spec §12 | (per field) | wordlist + `device_store` |
| OWE Transition SSID (vendor IE OUI `50:6F:9A` type 28) | WFA OWE §4 | `owe_transition_ssids` | `essid_map`, wordlist |
| Cisco CCX1 AP name (tag 133) | Cisco CCX v1 §A.3 | `ccx1_ap_names_extracted` | wordlist |
| Vendor AP names (tag 221, multiple OUIs) | wireshark `packet-ieee80211.c` | `vendor_ap_names_extracted` | wordlist |
| Multiple BSSID profile (tag 71 / sub-BSSID) | §9.4.2.45a + §35.2.2 | `multiple_bssid_profiles` | `essid_map` |
| Reduced Neighbor Report BSSIDs (tag 201) | §9.4.2.170 | `rnr_bssids_extracted` | stats only (MAC, not seeded into -W) |
| Wi-Fi Direct (P2P) device name (vendor IE OUI `50:6F:9A` type 9) | WFA Wi-Fi Direct | `p2p_device_names_extracted` | wordlist |
| FILS Discovery SSID (Public Action 34) | §9.6.7.36 | `fils_discovery_ssids` | `essid_map`, `essid_set`, wordlist |
| Action Neighbor Report SSID (Action cat 5) | §9.6.6.6 | `action_nr_req_ssids` | `essid_set` |
| ANQP Venue Name (Info ID 258) | §9.4.5 | (per element) | wordlist |
| ANQP Domain Name List (Info ID 263) | §9.4.5 | (per element) | wordlist |
| ANQP NAI Realm (Info ID 268) | §9.4.5.10 | (per element) | wordlist |
| ANQP Hotspot 2.0 Operator Friendly Name | HS2.0 Tech Spec §4.3 | (per element) | wordlist |
| EAP-Identity (Code 1/2 Type 1) | RFC 3748 §5.1 | (always) | `identity_set`, `username_set`, wordlist |
| EAP outcome (Code 3/4) | RFC 3748 §4.2 | `eap_success_frames`, `eap_failure_frames` | stats only |

Out of scope: DPP / Wi-Fi Easy Connect (§1), pure SAE / OWE authentication frames (no PSK to crack), Roaming Consortium / BSS Load / Interworking / RSNXE / DMG capabilities (numeric-only IEs, no plaintext value), Short SSID (irreversible CRC-32).

**MSDU fragment reassembly counters** (`stats.fragment_stats`, populated by `src/store/fragments.rs`).

- `fragments_seen` -- non-final fragments buffered for later concatenation.
- `fragments_reassembled` -- final fragments that completed an MSDU and triggered `take_completed`.
- `fragments_dropped_disorder` -- final fragment arrived without a matching fragment-0 (orphan). Body is still passed through the EAPOL parser as a single MSDU in case of glitched MoreFrag bits on what is actually a complete frame.
- `fragments_dropped_overflow` -- in-flight buffer hit `MAX_ENTRIES` and the oldest entry was evicted to make room for a new fragment-0.

**PMKID counters per source (S1-S20).** Each `PmkidSource` variant has its own counter. Also: total, useful, useless, faulty, best.

**EAP / RADIUS / TACACS+ counters.** EAP ID, EAP request/response, method breakdown (MD5, LEAP, MSCHAPv2, PEAP, TLS, TTLS, SIM, AKA, Expanded), RADIUS Access-Request/Challenge/Accept/Reject, TACACS+ AUTHEN/AUTHOR/ACCT. v1 counts only; v2 writes the hashcat-compatible output.

**IP / transport counters** (informational): IPv4, IPv6, TCP, UDP, ICMPv4, ICMPv6, GRE.

**RSN capabilities histogram** (`stats.rsn_caps_histogram`): raw 2-byte hex distribution per §9.4.2.24.4 Figure 9-374. B6/B7 drive per-`(AP, STA)` PMF annotation.

**Cipher suite counters.** Per-suite counts under OUI `00:0F:AC` (CCMP-128, GCMP-128, GCMP-256, CCMP-256, BIP-CMAC-128, BIP-GMAC-128, BIP-GMAC-256, BIP-CMAC-256, TKIP, WEP-40, WEP-104). `stats.unknown_cipher_count` for unrecognised selectors; `stats.vendor_cipher_count` for non-`00:0F:AC` OUIs.

### §9.4  Phase 4 (Emit) counters

- EAPOL pairs: total, useful, best, ignored-oversized, written-to-22000, written-to-37100, rogue pairs, pairs-from-zeroed-PMK, pairs-from-zeroed-PSK.
- Per N#E# combo counts (six counters: N1E2, N1E4, N3E2, N2E3, N4E3, N3E4) - individually before dedup, plus equivalence-class survivor counts after `--dedup-hash-combos` collapse.
- RSN PMKID emission: total, useful, useless, faulty, best, PSK, FT-PSK, rogue, from-zeroed-PMK, from-zeroed-PSK, written-to-22000, written-to-37100.
- Per-AKM hash-emission decisions: counts by AKM selector (`00-0F-AC:x`) of hashes emitted vs suppressed vs counted-only, with the Table number cross-referenced to §6 in the line label.
- Per-type-code line counts: 01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11 (the 11-type classification of §2). One counter per output sink: `--22000-out`, `--37100-out`, `-o`, `--wpa1-out`, `--wpa2-out`, `--psk-sha256-out`, `--ft-out`, `--psk-sha384-out`, `--ft-psk-sha384-out`.
- FT specifics: R0KH-ID / R1KH-ID / MDID observed counts.
- Dedup stats: fingerprint collisions per line-kind byte, unique lines written per output file, duplicates suppressed.

### §9.5  Phase 5 (Report) counters

- Wallclock breakdown per phase.
- OWE Transition Mode pairs (`stats.owe_transition_pairs`).
- MLO capture detected (`stats.mlo_capture_detected`).
- Weird-format counts: Kuznetzov pcap records, AVS-within-Prism frames, pcapng nanosecond-resolution interfaces, multi-SHB pcapng files.
- NMEA / GPS records observed (count only in v1; structured GPS output deferred to v2 via `--nmea-out`).

### §9.6  Hcxpcapngtool parity

Any stat, frame type, or metadata category `hcxpcapngtool` emits, wpawolf emits too. Where `hcxpcapngtool` silently drops:

- FT-PSK frames > 255 B (wpawolf has no size gate per §4 invariant 3).
- Global-dedup-across-the-whole-capture (wpawolf has SipHash global set per §4 invariant 5).
- Relay frames without `--all` (wpawolf processes WDS unconditionally per §4 invariant 4).

wpawolf emits and documents the difference. The Phase 8 superset test in `tests/integration/superset_test.rs` enforces this parity at every release.

### §9.7  Operational verification -- cross-version comparison

Beyond unit + fixture tests, wpawolf is verified at release time against a local multi-vendor capture set by re-running every prior release plus the current `HEAD` binary in both `WIDE` (bare) and `STRICT` (`--strict` bundle) modes alongside the upstream `hcxpcapngtool` in `default` and `wide` modes, then sorted-unique-diffing the resulting hashcat lines per capture and across the run. The verification scripts and their inputs are developer-local (kept out of the repository) since they reference operator-side capture paths; the methodology and the three invariants they pin are documented here so any contributor can reproduce them on their own captures.

The verification pins three invariants:

1. **Cross-version drops.** For each adjacent (older, newer) version pair, every line emitted by the older binary on a capture must also appear in the newer binary's output. Any drop must trace to a documented intentional spec-compliance transition (e.g. v0.3.5's Mesh Control bit gate, v0.3.6's MessageStore dedup-on-insert) -- never to a regression.
2. **Superset invariant.** `hcx-default ⊆ wpawolf-HEAD-WIDE` per capture. Any hcx-only line must trace to a documented per-(AP, STA) precision difference (a different `message_pair` flag byte for the same body, i.e. a body-matched diff -- not a genuinely missing handshake) -- never to a missing line. The FLAG_NC three-source rule (CC-1, see §5.7) and the FT-PSK PMKID `message_pair` byte (see §6.7 and `hcxpcapngtool.h:386-390`) are the two output-format fixes that closed the bulk of pre-v0.3.7 violations; residual differences are all body-matched flag-byte differences attributable to hcx-default's data-structure quirks (AP-wide M1 cross-leakage and 20-entry eviction window).
3. **Mode parity `STRICT ⊆ WIDE`.** For every (capture, version, channel) tuple, the STRICT line-set must be a subset of the WIDE line-set. The `--strict` bundle (`--eapoltimeout` / `--rc-drift` / `--dedup-hash-combos` / `--per-file` / `--nc-dedup`) is a pure output filter; none of its passes can synthesize lines the WIDE pipeline did not produce. Any violation is a P0 STRICT-mode logic bug. The fixture-level test `tests/integration/mode_parity_strict_subset_wide.rs` gates the same invariant in CI without requiring an external capture set.

---

## §10  References

### §10.1  Specifications

| Spec | Sections used |
|------|---------------|
| **IEEE 802.11-2024** | §9.2.4 (Frame Control), §9.3.2 (Address mapping, Table 9-60), §9.4.2.2 (SSID), §9.4.2.24 (RSNE, Table 9-190 AKM selectors, Figure 9-374 RSN Caps), §9.4.2.45 (MDE), §9.4.2.46 (FTE, Table 9-221 subelements), §9.6.7 (FT Action frames), §9.6.15 (Mesh Peering Action frames), §11.52 (Beacon protection), §12.6.1.3 (PMKID derivation), §12.6.8 (PMKSA caching), §12.7.1.2 (PRF), §12.7.1.3 (PMKID derivation), §12.7.1.6 (FT key hierarchy), §12.7.2 (EAPOL-Key frame, Table 12-10 message types, Table 12-11 MIC lengths), §12.7.6 (4-way handshake), §12.11 (FILS auth), §12.13 (PASN), §13.4 (FT Initial Association), §13.8 (FT over-the-DS), §14.3.5 (AMPE), §35 (MLO) |
| **IEEE 802.11-2020** | Same sections, prior numbering |
| **IEEE 802.11-2012** | §8.2.4.1 (Frame Control), §8.3.2.1 (Address mapping, Table 8-19), §11.6.2 (EAPOL-Key), Annex P Table P-2 (LLC/SNAP) |
| **IEEE 802.11i-2004** | §8.5.1 (PRF), §8.5.3 (4-way handshake) |
| **draft-ietf-opsawg-pcapng-05** | §3.1 (block structure), §3.5 (options), §3.6 (endianness), §4.1 (SHB), §4.2 (IDB, if_tsresol), §4.3 (EPB), §4.4 (SPB), §10.1 (block type registry) |
| **libpcap source** | `pcap/pcap.h` (file header), `sf-pcap.c` (magic numbers, Kuznetzov), `pcap/dlt.h` (DLT constants), `gencode.c:3441-3505` (Prism / AVS detection) |
| **Radiotap spec** | Header structure, alignment rules, Flags field, extension words |
| **RFC 3748** | §4 (EAP packet format), §4.1 (Request/Response with Type field), §5.1 (Identity), §5.4 (MD5-Challenge) |
| **RFC 4284** | NAI realm format and Hotspot 2.0 type-prefix marker |
| **RFC 1042** | LLC/SNAP encapsulation for EtherType on 802.11 |
| **Wi-Fi Alliance WPA spec** | WPA vendor IE (Element ID 221, OUI `00:50:F2`, type 1) |
| **Wi-Fi Passpoint / Hotspot 2.0** | OSEN IE (vendor IE OUI `50:6F:9A`, type 0x12) |
| **Wi-Fi Protected Setup §12** | WPS string attribute padding rules |
| **hashcat module_22000.c** | `WPA*01/02` line format, wpa_t struct, verification logic |
| **hashcat OpenCL** | `inc_hash_sha1.cl`, `inc_hash_sha256.cl`, `inc_hash_sha384.cl`, `inc_hash_md5.cl`, `inc_cipher_aes.cl` |

### §10.2  Reference C source

- `hcxpcapngtool.c` from upstream `hcxtools` -- reference implementation.
- `hcxpcapngtool_hashtable.c` -- custom variant proving the no-ring-buffer thesis works.
- `hcxpcapngtool_sortgroup.c` -- second custom variant.
- `hcxtools/include/fileops.c:72-86` -- `fwriteessidstr` admission filter (FR-OUT-7 reference).
- `hcxpcapngtool.h:386-390` -- `PMKID_AP`, `PMKID_APPSK256`, `PMKID_CLIENT`, `PMKID_AP_FTPSK`, `PMKID_CLIENT_FTPSK` constants (§6.7 reference).

### §10.3  Repository layout

```
src/
  main.rs        entry point, arg parsing, orchestration
  lib.rs         public API for integration tests
  input/         Phase 1 (§3.1) - mod / pcapng / pcap / gzip
  link/          Phase 2 (§3.2) - mod / radiotap / ppi / prism / avs
  ieee80211/     Phase 2 (§3.2) - mod / frame / ie / rsn / ft / eapol / eap / amsdu / anqp
  extract/       Phase 3 (§3.3) - per-frame handlers routing to stores
  store/         Phase 3 (§3.3) - mod / messages / pmkid / essid / fragments / auxiliary
  pair/          Phase 4 (§3.4) - mod / combos / constraints / collapse / nc_dedup
  output/        Phase 4 (§3.4) - mod / hashcat / wordlists / device_info / dedup
  stats.rs       Phase 5 (§3.5) - counters, summary
  progress.rs    periodic progress line emitter
  debug.rs       --debug diagnostic mode
  log.rs         structured logging
  mem_stats.rs   --mem-stats per-store footprint table
  strings_scan.rs  --wordlist-scan IE plaintext scanner
  types.rs       shared: MacAddr, MacPair, MsgType, AkmType, MicBytes, Error
```

### §10.4  Data structures (essential)

```rust
pub struct MacAddr(pub [u8; 6]);                              // 6 B, Copy
pub struct MacPair { pub ap: MacAddr, pub sta: MacAddr }      // 12 B, Copy

pub enum MsgType { M1 = 1, M2 = 2, M3 = 3, M4 = 4 }

pub enum AkmType {
    Wpa1,          // WPA legacy (vendor IE 00:50:F2:01, HMAC-MD5 MIC, KDV=1)
    Wpa2Psk,       // AKM 2: HMAC-SHA1 PMKID, PRF-SHA1 PTK, KDV=2
    FtPsk,         // AKM 4: FT-SHA256 chain PMKID, mode 37100
    FtPskSha384,   // AKM 19: FT-SHA384 chain PMKID, HMAC-SHA384-192 MIC
    PskSha256,     // AKM 6: HMAC-SHA256 PMKID, AES-CMAC MIC, KDV=3
    PskSha384,     // AKM 20: HMAC-SHA384-192 MIC (24 B), KDF-SHA384 PTK
    Unknown,       // could not determine; treated as Wpa2Psk for output routing
}

pub struct EapolMessage { /* see §5.11 */ }
pub struct FtFields { /* see §5.11 */ }

pub struct MessageStore {
    groups: HashMap<MacPair, Vec<EapolMessage>>,
    total_count: usize,
}

pub struct DedupSet { seen: HashSet<u64> }
```

`HashMap` and `HashSet` use the default SipHash-1-3 hasher - safe against HashDoS from crafted MACs.

### §10.5  Tests and benchmarks

- Unit tests colocated with modules (`#[cfg(test)] mod tests`).
- Integration tests in `tests/integration/*.rs`:
  - `superset_test.rs` runs both `hcxpcapngtool` and `wpawolf` on the same capture and asserts `wpawolf_output >= hcxpcapngtool_output` line by line. The "never miss a hash" regression oracle.
  - `per-AKM format_outputs_per_akm.rs`, `per-AKM format_combined_o.rs`, `per-AKM format_dedup_per_sink.rs` -- per-sink fan-out and dedup checks for the 11-type classification outputs.
  - `pmkid_coverage.rs` -- crafted in-memory pcap exercising the 20 spec-defined PMKID extraction sites; asserts no-dup, WPA*01* field count = 9, WPA*03* field count = 12.
  - `cross_file_pairing.rs` -- M1 in file A, M2/3/4 in file B; asserts the shared `MessageStore` reassembles the handshake.
  - `fragment_reassembly.rs` -- 802.11 MSDU fragment reassembly per `(SA, RA, SeqNum)` for FT-PSK M2 frames split by the radio MTU.
  - `log_categories_coverage.rs` -- exercises every `[category]` line in `src/log.rs` from a real run.
  - `malformed_frame_log.rs`, `wordlist_scan_ies.rs`, `anqp_parse.rs` -- targeted feature smoke tests.
- Fixtures: small per-test pcaps under `tests/fixtures/pcaps/` (kept under 1 MiB each); larger corpora live out-of-tree and are exercised by benchmarks only.

### §10.6  Build and lint policy

Rust 2024 edition, stable toolchain pinned in `rust-toolchain.toml`. `Cargo.toml` enforces `unsafe_code = "forbid"`; `lib.rs` re-states `#![forbid(unsafe_code)]`. Clippy: `all` at `deny`, `pedantic` / `nursery` / `cargo` at `warn`. `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` at `warn`. `dbg_macro`, `todo`, `unimplemented`, `mem_forget` at `deny`. Cast lints (`cast_possible_truncation`, `cast_sign_loss`, `cast_precision_loss`, `cast_possible_wrap`) at `warn`. `wildcard_imports` at `deny` (tests may `#[allow]`). `.cargo/config.toml` sets `rustflags = ["-D", "warnings"]`.

`make check-all` runs `fmt`, `lint` (clippy zero warnings), `audit` (cargo deny), `check`, `test`, `doc` (rustdoc `-D warnings`), `hygiene` (ASCII + LF), `machete` (unused deps).

