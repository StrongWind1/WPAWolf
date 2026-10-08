# Hashcat Mode 22000: WPA-PSK Hash Format Reference

> Consolidates the former `HASHCAT-CURRENT-FORMATS.md`, `HASHCAT-NEW-FORMATS.md`, and `HASHCAT-PROPOSED-CHANGES.md`.

---

## §1  Overview

wpawolf classifies every PSK-crackable WPA hash into one of eleven **hash classes** (§2). Classes 1-7 are emitted to hashcat mode 22000, the sole output target. Classes 8-11 (SHA-384 family) are classified and counted in the stats banner but not emitted -- the 24 B MIC exceeds mode 22000's fixed 16 B MIC field, and no hashcat kernel exists for them.

Mode 22000 accepts four **line prefixes**: `WPA*01*` (PMKID), `WPA*02*` (EAPOL), `WPA*03*` (FT PMKID), `WPA*04*` (FT EAPOL). Standard records use a 9-token format; FT records (`WPA*03*`/`WPA*04*`) use a 12-token format with three additional fields (MDID, R0KH-ID, R1KH-ID).

**Terminology.** This document uses **"class"** (numbered 1-11) for wpawolf's internal classification and **"prefix"** (`WPA*01*`-`WPA*04*`) for the 2-digit code in token 1 of the hashcat hash line. The two numbering systems overlap but do not align: for example, class 1 (WPA1-PSK-EAPOL) emits prefix `WPA*02*`, while class 2 (WPA2-PSK-PMKID) emits prefix `WPA*01*`.

wpawolf output flags:
- `-o` / `--out`: combined output, all crackable classes 1-7
- `--wpa1-eapol`, `--wpa2-pmkid`, `--wpa2-eapol`, `--sha256-pmkid`, `--sha256-eapol`, `--ft-pmkid`, `--ft-eapol`: per-class sinks, each maps 1:1 to a single class

---

## §2  The 11-Class Master List

Two encoding rules cover the entire table:

```
EVEN class code  =  PMKID attack    (no full handshake needed)
ODD  class code  =  EAPOL attack    (needs nonce + MIC frame)

Ascending code   =  ascending hash complexity
```

Class 1 (WPA1-PSK-EAPOL) is the only odd code without a PMKID partner: WPA1 has no PMKID field in its vendor IE.

| Class | Name                    | AKM selector           | KDV | Attack | MIC width | hashcat status |
|-------|-------------------------|------------------------|-----|--------|-----------|----------------|
|  1    | WPA1-PSK-EAPOL          | WPA1 vendor IE         | 1   | EAPOL  | 16 B      | emitted, cracks (aux1) |
|  2    | WPA2-PSK-PMKID          | 2 (`00:0F:AC:02`)      | --  | PMKID  | --        | emitted, cracks (aux4) |
|  3    | WPA2-PSK-EAPOL          | 2                      | 2   | EAPOL  | 16 B      | emitted, cracks (aux2) |
|  4    | PSK-SHA256-PMKID        | 6 (`00:0F:AC:06`)      | --  | PMKID  | --        | emitted, **does not crack** (§7) |
|  5    | PSK-SHA256-EAPOL        | 6                      | 3   | EAPOL  | 16 B      | emitted, cracks (aux3) |
|  6    | FT-PSK-PMKID            | 4 (`00:0F:AC:04`)      | --  | PMKID  | --        | emitted, cracks (aux5) |
|  7    | FT-PSK-EAPOL            | 4                      | 3   | EAPOL  | 16 B      | emitted, cracks (aux6) |
|  8    | PSK-SHA384-PMKID        | 20 (`00:0F:AC:14`)     | --  | PMKID  | --        | classified only, not emitted |
|  9    | PSK-SHA384-EAPOL        | 20                     | 0   | EAPOL  | 24 B      | classified only, not emitted |
| 10    | FT-PSK-SHA384-PMKID     | 19 (`00:0F:AC:13`)     | --  | PMKID  | --        | classified only, not emitted |
| 11    | FT-PSK-SHA384-EAPOL     | 19                     | 0   | EAPOL  | 24 B      | classified only, not emitted |

AKM values reference [IEEE 802.11-2024] Table 9-190 (OUI `00:0F:AC`). KDV values reference §12.7.2 Key Information bits 0-2; PMKID-only rows have no KDV (the field exists only in EAPOL-Key frames). KDV `0` for SHA-384 EAPOL is the spec's "reserved" value; the AKM negotiates SHA-384 out of band rather than via the keyver field, because the 16 B MIC slot the keyver field selects cannot accommodate a 24 B MIC.

**Classes 8-11 (SHA-384):** AKMs 19 and 20 are defined in the spec but not yet implemented by hostapd or wpa_supplicant. No real-world captures with these AKMs have been observed. wpawolf classifies and counts them in the stats banner but does not emit them to any output sink. hashcat mode 22000 cannot express the 24 B MIC (fixed 16 B field) and rejects `keyver=0` at load time. Full SHA-384 support is deferred until these AKMs see production deployment.

---

## §3  Mode 22000 Format Reference

Verified against upstream hashcat branch `master`, commit `bb52c06b9`.

### Line format

The canonical format uses `*` as the delimiter and the signature `WPA`. Two shapes exist:

**Standard record (9 tokens, prefixes `WPA*01*`/`WPA*02*`):**
```
WPA*TT*<hash>*<mac_ap>*<mac_sta>*<essid>*<anonce>*<eapol>*<mp>
```

**FT record (12 tokens, prefixes `WPA*03*`/`WPA*04*`):**
```
WPA*TT*<hash>*<mac_ap>*<mac_sta>*<essid>*<anonce>*<eapol>*<mp>*<mdid>*<r0khid>*<r1khid>
```

The parser counts `*` separators before tokenizing: 11 separators = 12 tokens (FT record), otherwise 9 tokens (standard). `WPA*03*`/`WPA*04*` **require** 12 tokens; `WPA*01*`/`WPA*02*` **require** 9 tokens. A mismatch returns `PARSER_SALT_VALUE`.

### Field width table

| Token | Field         | Width constraint        | Notes |
|-------|---------------|-------------------------|-------|
| 0     | Signature     | fixed 3 chars           | `WPA` |
| 1     | Prefix        | fixed 2 hex chars       | `01`, `02`, `03`, or `04` |
| 2     | Hash          | fixed 32 hex chars      | PMKID (`WPA*01*`/`WPA*03*`) or MIC (`WPA*02*`/`WPA*04*`); always 16 bytes |
| 3     | MAC AP        | fixed 12 hex chars      | 6 bytes, lowercase hex, no separators |
| 4     | MAC STA       | fixed 12 hex chars      | 6 bytes |
| 5     | ESSID         | 0-64 hex chars          | 0-32 bytes raw SSID; must be even length |
| 6     | ANonce        | 0 or 64 hex chars       | 32 bytes for EAPOL prefixes; empty for PMKID prefixes |
| 7     | EAPOL         | 0 to 1024 hex chars     | `WPA_EAPOL_LEN_MAX = 512` bytes; min `sizeof(auth_packet_t) * 2 = 198` for EAPOL prefixes; empty for PMKID |
| 8     | message_pair  | 0 or 2 hex chars        | Required (2 chars) for `WPA*02*`/`WPA*04*`; empty for `WPA*01*` PMKID |
| 9     | MDID          | fixed 4 hex chars       | FT only (`WPA*03*`/`WPA*04*`): Mobility Domain ID, 2 bytes |
| 10    | R0KH-ID       | 0-96 hex chars          | FT only: R0 Key Holder ID, 0-48 bytes |
| 11    | R1KH-ID       | 0-96 hex chars          | FT only: R1 Key Holder ID, 0-48 bytes |

### Kernel dispatch

All six auxiliary kernels share `m22000_init` and `m22000_loop`, which compute `PBKDF2-HMAC-SHA1(passphrase, ESSID, 4096)` to derive the 32-byte PMK. The auxiliary kernel then uses the PMK differently depending on the line prefix and keyver:

| Kernel | Line Prefix  | Dispatch condition | Algorithm |
|--------|--------------|-------------------|-----------|
| aux1   | `WPA*02*`    | keyver = 1        | PRF-SHA1 PTK, HMAC-MD5 MIC (WPA1/TKIP) |
| aux2   | `WPA*02*`    | keyver = 2        | PRF-SHA1 PTK, HMAC-SHA1 MIC (WPA2/CCMP) |
| aux3   | `WPA*02*`    | keyver = 3        | KDF-SHA256 PTK, AES-128-CMAC MIC (WPA2/802.11w) |
| aux4   | `WPA*01*`    | always            | HMAC-SHA1 PMKID (`"PMK Name" \|\| AP \|\| STA`) |
| aux5   | `WPA*03*`    | always            | SHA-256 KDF chain: PMK -> PMK-R0 -> PMK-R0-Name -> PMK-R1-Name |
| aux6   | `WPA*04*`    | keyver = 3 (enforced) | Full FT chain: PMK -> PMK-R0 -> PMK-R1 -> PTK, AES-128-CMAC MIC |

The `keyver` value is extracted from bits 0-2 of the Key Information field at offset 5 of the EAPOL frame header: `wpa->keyver = byte_swap_16(auth_packet->key_information) & 3`.

### The `keyver` trick

A `WPA*02*` line carries no AKM identifier. Three PSK families share the same 16 B MIC width and are disambiguated by the `keyver` value inside the embedded EAPOL frame:

| keyver | AKM family  | MIC algorithm    | PTK derivation |
|--------|-------------|------------------|----------------|
| 1      | WPA1        | HMAC-MD5 (16 B)  | PRF-SHA1       |
| 2      | WPA2-PSK    | HMAC-SHA1 (16 B) | PRF-SHA1       |
| 3      | PSK-SHA256  | AES-128-CMAC (16 B) | KDF-SHA256 |

Any other `keyver` value returns `PARSER_SALT_VALUE`.

### Legacy format compatibility

Mode 22000 auto-detects and internally converts two older formats:
- **hccapx binary** (393 bytes, signature `0x58504348`, version 4): converted to `WPA*02*...`
- **Old PMKID format** (`hash*macap*macsta*essid` or colon-separated): converted to `WPA*01*...***`

### Key constants

| Constant | Value | Source |
|----------|-------|--------|
| `WPA_EAPOL_LEN_MAX` | 512 bytes | `OpenCL/m22000-pure.cl:58` |
| Max ESSID length | 32 bytes (64 hex chars) | token 5 `len_max=64` |
| ANonce size | 32 bytes (64 hex chars, fixed) | token 6 |
| Password min | 8 chars | `module_pw_min()` |
| Password max | 63 chars | `module_pw_max()` |
| PBKDF2 rounds | 4096 | `ROUNDS_WPA_PBKDF2` |
| `NONCE_ERROR_CORRECTIONS` | 8 (default) | `include/types.h:1055` |
| Max R0KH-ID | 48 bytes (96 hex chars) | token 10 `len_max=96` |
| Max R1KH-ID | 48 bytes (96 hex chars) | token 11 `len_max=96` |
| MDID | 2 bytes (4 hex chars, fixed) | token 9 |
| Min EAPOL frame | 99 bytes (`sizeof(auth_packet_t)`) | 198 hex chars |

---

## §4  Class-to-Prefix Mapping

Every emitted hash uses mode 22000 format. Class numbers (1-11) are wpawolf's internal classification; line prefixes (`WPA*01*`-`WPA*04*`) are what appears in the hash line that hashcat parses.

| Class | Name                    | Line Prefix | Kernel | Cracks? | wpawolf Sink      | Notes |
|-------|-------------------------|-------------|--------|---------|-------------------|-------|
| 1     | WPA1-PSK-EAPOL          | `WPA*02*`   | aux1 (HMAC-MD5)     | YES     | `--wpa1-eapol`    | keyver=1 dispatches to MD5 kernel |
| 2     | WPA2-PSK-PMKID          | `WPA*01*`   | aux4 (HMAC-SHA1)    | YES     | `--wpa2-pmkid`    | |
| 3     | WPA2-PSK-EAPOL          | `WPA*02*`   | aux2 (HMAC-SHA1)    | YES     | `--wpa2-eapol`    | keyver=2 |
| 4     | PSK-SHA256-PMKID        | `WPA*01*`   | aux4 (HMAC-SHA1)    | **NO**  | `--sha256-pmkid`  | hashcat bug: aux4 runs HMAC-SHA1, needs HMAC-SHA256 |
| 5     | PSK-SHA256-EAPOL        | `WPA*02*`   | aux3 (AES-CMAC)     | YES     | `--sha256-eapol`  | keyver=3 |
| 6     | FT-PSK-PMKID            | `WPA*03*`   | aux5 (SHA-256 KDF)  | YES     | `--ft-pmkid`      | 12-token format with FT extras |
| 7     | FT-PSK-EAPOL            | `WPA*04*`   | aux6 (AES-CMAC/FT)  | YES     | `--ft-eapol`      | 12-token, keyver=3 enforced |
| 8     | PSK-SHA384-PMKID        | --          | --                  | NO      | (none)            | 24B MIC, no kernel |
| 9     | PSK-SHA384-EAPOL        | --          | --                  | NO      | (none)            | 24B MIC, no kernel |
| 10    | FT-PSK-SHA384-PMKID     | --          | --                  | NO      | (none)            | 24B MIC, no kernel |
| 11    | FT-PSK-SHA384-EAPOL     | --          | --                  | NO      | (none)            | 24B MIC, no kernel |

---

## §5  Per-Class Cracker Math

Every class starts from the same step. PBKDF2 is the only deliberately expensive operation; the post-PMK work is microseconds per candidate.

```
Step 0 (shared by all 11 classes):
    PMK = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096 rounds, 32 B)
```

### Class 1: WPA1-PSK-EAPOL

```
PMK ---[PRF-SHA1, 512 b]---> PTK
KCK = PTK[0:16]
MIC = HMAC-MD5(KCK, EAPOL_zeroed)[0:16]
```
KDV = 1. No PMKID partner.

### Classes 2 + 3: WPA2-PSK

```
WPA2-PSK-PMKID (class 2):
    PMKID = HMAC-SHA1(PMK, "PMK Name" || AP || STA)[0:16]

WPA2-PSK-EAPOL (class 3):
    PMK ---[PRF-SHA1, 384 b]---> PTK
    KCK = PTK[0:16]
    MIC = HMAC-SHA1(KCK, EAPOL_zeroed)[0:16]
```
KDV = 2.

### Classes 4 + 5: PSK-SHA256

```
PSK-SHA256-PMKID (class 4):
    PMKID = HMAC-SHA256(PMK, "PMK Name" || AP || STA)[0:16]

PSK-SHA256-EAPOL (class 5):
    PMK ---[KDF-SHA256, 384 b]---> PTK
    KCK = PTK[0:16]
    MIC = AES-128-CMAC(KCK, EAPOL_zeroed)   [16 B]
```
KDV = 3.

### Classes 6 + 7: FT-PSK (802.11r SHA-256)

```
PMK ---[FT-KDF-SHA256]---> PMK-R0 ---[FT-KDF-SHA256]---> PMK-R1

FT-PSK-PMKID (class 6):
    PMKID = PMK-R1-Name = SHA256("FT-R1N" || PMK-R0-Name || R1KH-ID || STA)[0:16]

FT-PSK-EAPOL (class 7):
    same chain ---> PTK
    KCK = PTK[0:16]
    MIC = AES-128-CMAC(KCK, EAPOL_zeroed)   [16 B]
```

Both rows require MDID (2 B), R0KH-ID (1-48 B), R1KH-ID (6 B) from the hash line to drive the FT chain. KDV = 3 (EAPOL).

### Classes 8 + 9: PSK-SHA384

```
PSK-SHA384-PMKID (class 8):
    PMKID = HMAC-SHA384(PMK, "PMK Name" || AP || STA)[0:16]
    (still 16 B output, Truncate-128)

PSK-SHA384-EAPOL (class 9):
    PMK ---[KDF-SHA384, 576 b]---> PTK
    KCK = PTK[0:24]                        <-- 24 bytes (192 bits)
    MIC = HMAC-SHA384(KCK, EAPOL_zeroed)[0:24]   <-- 24 bytes
```
KDV = 0.

### Classes 10 + 11: FT-PSK-SHA384

```
PMK ---[FT-KDF-SHA384]---> PMK-R0 ---[FT-KDF-SHA384]---> PMK-R1

FT-PSK-SHA384-PMKID (class 10):
    PMKID = SHA384("FT-R1N" || PMK-R0-Name || R1KH-ID || STA)[0:16]

FT-PSK-SHA384-EAPOL (class 11):
    same chain ---> PTK
    KCK = PTK[0:24]
    MIC = HMAC-SHA384(KCK, EAPOL_zeroed)[0:24]
```

Both rows require MDID + R0KH-ID + R1KH-ID. KDV = 0 (EAPOL).

### Shared subtrees a cracker can cache

```
passphrase + SSID
       |
       v
 PBKDF2-SHA1 ---------------------------------------- shared by all 11 classes
       |
       +-- [HMAC-SHA1]   -----> PMKID              -> class 2  (WPA*01*)
       |
       +-- [PRF-SHA1]  -> KCK16 -> [MD5 MIC]       -> class 1  (WPA*02*)
       |               +--------->  [SHA1 MIC]      -> class 3  (WPA*02*)
       |
       +-- [HMAC-SHA256] -----> PMKID              -> class 4  (WPA*01*)
       |
       +-- [KDF-SHA256]  -> KCK16 -> [CMAC MIC]    -> class 5  (WPA*02*)
       |
       +-- [FT-KDF-SHA256] -> PMKR1-Name           -> class 6  (WPA*03*)
       |                  +-> KCK16 -> [CMAC MIC]  -> class 7  (WPA*04*)
       |
       +-- [HMAC-SHA384] -----> PMKID              -> class 8  (not emitted)
       |
       +-- [KDF-SHA384]  -> KCK24 -> [SHA384 MIC]  -> class 9  (not emitted)
       |
       +-- [FT-KDF-SHA384] -> PMKR1-Name           -> class 10 (not emitted)
       |                   +-> KCK24 -> [SHA384 MIC]-> class 11 (not emitted)
```

---

## §6  Message-Pair Byte

The trailing 1-byte `<mp>` field encodes metadata about how the hash line was constructed. EAPOL and PMKID lines use different encodings: the byte is a **control signal** for EAPOL (affects hashcat kernel behavior) and a **source tag** for PMKID (diagnostic only).

### §6.1  EAPOL lines (`WPA*02*`, `WPA*04*`)

#### Byte layout

```
  7     6     5     4     3    2    1    0
┌─────┬─────┬─────┬─────┬────┬────┴────┴────┐
│ NC  │ BE  │ LE  │ APL │ —  │  combo (0-5)  │
└─────┴─────┴─────┴─────┴────┴───────────────┘
```

| Bit(s) | Mask   | Name   | hashcat effect                                                   |
| ------ | ------ | ------ | ---------------------------------------------------------------- |
| 0-2    | `0x07` | Combo  | Identifies the N#E# pairing (kernel does not read it)            |
| 3      | `0x08` | —      | Reserved, always 0                                               |
| 4      | `0x10` | APLESS | Zeroes `nonce_error_corrections` (overrides NC)                  |
| 5      | `0x20` | LE     | Restricts nonce iteration to LE byte order only                  |
| 6      | `0x40` | BE     | Restricts nonce iteration to BE byte order only                  |
| 7      | `0x80` | NC     | Enables nonce-error-correction iteration (default 8 corrections) |

#### Bits 0-2: Combo discriminant

`N{nonce_msg}E{eapol_msg}`: **N**once from message **#**, **E**APOL frame from message **#**.

| Value | Combo    | Nonce source | EAPOL source | RC relationship       | APLESS |
| ----: | -------- | ------------ | ------------ | --------------------- | ------ |
|     0 | **N1E2** | M1 (ANonce)  | M2           | `RC(M2) == RC(M1)`   | no     |
|     1 | **N1E4** | M1 (ANonce)  | M4           | `RC(M4) == RC(M1)+1` | no     |
|     2 | **N3E2** | M3 (ANonce)  | M2           | `RC(M2) == RC(M3)-1` | no     |
|     3 | **N2E3** | M2 (SNonce)  | M3           | `RC(M3) == RC(M2)+1` | yes    |
|     4 | **N4E3** | M4 (SNonce)  | M3           | `RC(M3) == RC(M4)`   | yes    |
|     5 | **N3E4** | M3 (ANonce)  | M4           | `RC(M4) == RC(M3)`   | no     |

**Rule E1.** Set to the combo type. Immutable. Determined at pairing time.

#### Bit 4 (0x10): APLESS

"The nonce in this hash line is the STA's SNonce, not the AP's ANonce." The STA generated the SNonce fresh for this session -- it cannot be stale and nonce iteration is pointless.

hashcat (`module_22000.c:1601-1605`): APLESS is checked **before** NC. When set, `nonce_error_corrections` is zeroed unconditionally, regardless of the NC bit.

**Rule E2.** Set IFF combo is N2E3 or N4E3. Structural property of the combo, never conditional.

**Rule E3.** APLESS overrides NC. Do not set NC when APLESS is set -- it has no effect and is misleading.

#### Bit 7 (0x80): NC (Nonce-error-corrections)

"hashcat should iterate nearby ANonce values when cracking." The kernel sweeps `±NONCE_ERROR_CORRECTIONS/2` (default ±4, 9 total values) around the last 4 bytes of the ANonce (`m22000-pure.cl:534-573`). NC=0 means exact match only (1 value).

The AP maintains a global nonce counter incremented for every M1 sent to any STA. If the captured M1 and M2 are from different handshake attempts -- dropped packets, interleaved STAs, retransmissions -- the ANonce in the hash line is off by a small integer. Without iteration, hashcat tries only the exact captured nonce and silently fails.

**Rule E4.** Set on every non-APLESS pair. A pcap capture cannot guarantee ANonce-EAPOL session alignment. The cost is negligible (9 iterations vs 4096 PBKDF2 rounds = 0.2%). Omitting NC risks silent crack failure -- the worst outcome for a security tool.

**Rule E5.** NC is independent of LE/BE. "How many values to try" is orthogonal to "which byte order to count in."

#### Bits 5-6 (0x20, 0x40): LE / BE (Nonce counter byte order)

An optimization hint. The AP's nonce counter may be stored as LE or BE in firmware. When iterating nearby nonce values, hashcat needs to know which byte of the 4-byte nonce tail to increment (`m22000-pure.cl:542-555`).

hashcat behavior (`module_22000.c:1463-1481`):
- Neither set: `detected_le=1, detected_be=1`, `bo_loops=2` -- try both byte orders (safe default).
- LE only: `detected_le=1, detected_be=0`, `bo_loops=1` -- LE only (halves work).
- BE only: `detected_le=0, detected_be=1`, `bo_loops=1` -- BE only (halves work).
- Both set: `bo_loops=2` -- equivalent to neither (contradictory, wastes a metadata bit).

**Rule E6.** LE and BE are mutually exclusive. Never set both -- it is semantically contradictory and functionally equivalent to neither.

**Rule E7.** LE/BE require NC. Without NC, `nonce_error_corrections=0`, the kernel runs exactly 1 iteration with correction=0 (the original nonce value). Byte order is irrelevant when there is nothing to iterate.

**Rule E8.** Set LE or BE only when nonce counter byte order is specifically detected. The detection signal is: two ANonces from the same AP where the first 28 bytes match and the last 4 bytes differ by a small integer in one specific byte order. Replay counter byte order is NOT the correct signal -- RC endianness and nonce counter endianness are independent firmware properties.

**Rule E9.** When endianness is unknown, do not set either flag. The safe default (try both) costs 2x the inner loop but guarantees no silent failure. Setting the wrong flag halves the search space and silently misses the crack.

#### 6-to-3 equivalence collapse

Within a single handshake session the 6 combos produce at most 3 cryptographically unique hashes, grouped by the EAPOL frame whose MIC was computed:

| Hash group | Members    | Unique because of |
| ---------- | ---------- | ----------------- |
| Hash-A     | N1E2, N3E2 | M2's EAPOL frame  |
| Hash-B     | N2E3, N4E3 | M3's EAPOL frame  |
| Hash-C     | N1E4, N3E4 | M4's EAPOL frame  |

#### Valid EAPOL mp bytes (current)

LE/BE flags are disabled per Rule E9: the mapping between `detect_nonce_endianness` byte groups and hashcat's kernel `to` field byte layout has not been verified. The safe default (neither set, hashcat tries both byte orders) is used. 4 non-APLESS combos x NC + 2 APLESS combos = 6 values:

| mp byte | Combo | Flags  |
| ------- | ----- | ------ |
| `0x80`  | N1E2  | NC     |
| `0x81`  | N1E4  | NC     |
| `0x82`  | N3E2  | NC     |
| `0x85`  | N3E4  | NC     |
| `0x13`  | N2E3  | APLESS |
| `0x14`  | N4E3  | APLESS |

#### Invalid EAPOL mp bytes (never emit)

| Pattern                          | Violated rule                              |
| -------------------------------- | ------------------------------------------ |
| `0x00`-`0x05` (no NC, no APLESS) | E4: NC required on non-APLESS             |
| `0x20`-`0x25` (LE without NC)   | E7: LE requires NC                         |
| `0x40`-`0x45` (BE without NC)   | E7: BE requires NC                         |
| `0xE0`-`0xE5` (NC+LE+BE)        | E6: LE and BE mutually exclusive           |
| `0x93`, `0x94` (APLESS+NC)      | E3: NC redundant on APLESS                 |
| `0x33`, `0x34` (APLESS+LE)      | E3+E7: APLESS overrides NC; LE needs NC    |
| `0x53`, `0x54` (APLESS+BE)      | E3+E7: same                                |
| `0xB3`, `0xB4` (APLESS+NC+LE)   | E3: NC redundant on APLESS                 |
| `0xD3`, `0xD4` (APLESS+NC+BE)   | E3: NC redundant on APLESS                 |

### §6.2  PMKID lines (`WPA*01*`, `WPA*03*`)

PMKID kernels (aux4 for `WPA*01*`, aux5 for `WPA*03*`) have zero references to `nonce_error_corrections`, `detected_le`, or `detected_be`. The byte is not read by any kernel. It is a source tag -- diagnostic metadata recording which side of the wire the PMKID was observed on and which PMKID derivation was used.

#### Byte layout

```
  7     6     5     4     3     2     1     0
┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐
│  —  │  —  │ FTC │ FTA │  —  │ CLT │ S26 │ AP  │
└─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘
```

| Bit | Mask   | Name      | Meaning                                      |
| --- | ------ | --------- | -------------------------------------------- |
| 0   | `0x01` | AP        | AP-association path                          |
| 1   | `0x02` | SHA256    | PMKID derived via HMAC-SHA-256 (AKM 6)       |
| 2   | `0x04` | CLIENT    | Client-probing path                          |
| 3   | `0x08` | —         | Reserved, always 0                           |
| 4   | `0x10` | FT_AP     | FT-PSK AP-side                               |
| 5   | `0x20` | FT_CLIENT | FT-PSK client-side                           |
| 6-7 |        | —         | Reserved, always 0                           |

#### Rules

**Rule P1: Direction.** Every PMKID source is AP-side or client-side. The classification is by who placed the PMKID on the wire or whether the PMKID is part of the AP-association path vs the client-probing path.

**Rule P2: AP and CLIENT are mutually exclusive.** A PMKID comes from one side of the wire. Never set both.

**Rule P3: SHA256 is independent of direction.** Set bit 1 whenever the AKM is PSK-SHA-256 (AKM 6, `00:0F:AC:06`). This signals that the PMKID was derived via `HMAC-SHA-256(PMK, "PMK Name" || AA || SPA)` instead of `HMAC-SHA-1`. hashcat mode 22000 aux4 computes HMAC-SHA-1 unconditionally -- the SHA256 bit warns that aux4 cannot crack the line.

Not set for FT-PSK (AKM 4). FT-PSK's PMKID is `PMK-R1Name` -- a structurally different object derived via the FT-KDF-SHA-256 chain, not `HMAC-SHA-256`. It goes to mode 37100 aux5, not mode 22000 aux4. FT-PSK cannot carry the SHA256 bit.

**Rule P4: FT replaces the base direction flag.** When the AKM is FT-PSK (AKM 4), use FT_AP (bit 4) or FT_CLIENT (bit 5) instead of AP (bit 0) or CLIENT (bit 2). FT PMKIDs use the 12-token `WPA*03*` format with MDID, R0KH-ID, R1KH-ID -- the FT flag marks this structural difference.

**Rule P5: FT and base direction bits are mutually exclusive.** An FT PMKID sets FT_AP or FT_CLIENT. A non-FT PMKID sets AP or CLIENT. Never mix.

#### Valid PMKID mp bytes (exhaustive)

Exactly 6 values exist. The byte has 5 defined flag bits, but SHA256 and FT are determined by the AKM type, not free variables: WPA2-PSK (AKM 2) uses HMAC-SHA-1, so SHA256 is always off and FT is always off. PSK-SHA-256 (AKM 6) uses HMAC-SHA-256, so SHA256 is always on and FT is always off. FT-PSK (AKM 4) uses PMK-R1Name (a structurally different derivation, not HMAC-SHA-256), so SHA256 is always off and FT is always on. The only free variable is direction (AP or CLIENT), giving 3 types x 2 directions = 6.

| mp byte | Bits             | AKM             | Direction   |
| ------- | ---------------- | --------------- | ----------- |
| `0x01`  | AP               | WPA2-PSK (2)    | AP-side     |
| `0x03`  | AP + SHA256      | PSK-SHA-256 (6) | AP-side     |
| `0x04`  | CLIENT           | WPA2-PSK (2)    | Client-side |
| `0x06`  | CLIENT + SHA256  | PSK-SHA-256 (6) | Client-side |
| `0x10`  | FT_AP            | FT-PSK (4)      | AP-side     |
| `0x20`  | FT_CLIENT        | FT-PSK (4)      | Client-side |

No other values are valid. WPA2-PSK never carries SHA256 (wrong hash function). FT-PSK never carries SHA256 (PMK-R1Name is not an HMAC-SHA-256 PMKID). Non-FT types never carry FT flags. No AKM is both FT and HMAC-SHA-256, so `0x12` and `0x22` cannot exist.

#### S1-S20 source-to-direction mapping

AP-side sources (bit 0 or bit 4): S1 (M1 KDE), S3 (AssocReq RSN IE), S4 (ReassocReq RSN IE), S6 (FT Auth AP->STA), S8 (FILS Auth AP->STA), S10 (PASN Auth AP->STA), S12 (FT Action Response), S16 (Beacon RSN IE), S17 (ProbeResp RSN IE).

Client-side sources (bit 2 or bit 5): S2 (M2 RSN IE), S5 (FT Auth STA->AP), S7 (FILS Auth STA->AP), S9 (PASN Auth STA->AP), S11 (FT Action Request), S13 (FT Action Confirm), S14 (ProbeReq directed), S15 (ProbeReq broadcast), S18 (Mesh Peering Open), S19 (Mesh Peering Confirm), S20 (OSEN IE).

The complete mapping per AKM family:

| S#  | Source              | Dir    | WPA2-PSK (2) | PSK-SHA-256 (6) | FT-PSK (4) |
| --- | ------------------- | ------ | ------------ | --------------- | ---------- |
| S1  | M1 KDE              | AP     | `0x01`       | `0x03`          | `0x10`     |
| S2  | M2 RSN IE            | CLIENT | `0x04`       | `0x06`          | `0x20`     |
| S3  | AssocReq RSN IE      | AP     | `0x01`       | `0x03`          | `0x10`     |
| S4  | ReassocReq RSN IE    | AP     | `0x01`       | `0x03`          | `0x10`     |
| S5  | FT Auth STA->AP      | CLIENT | `0x04`       | `0x06`          | `0x20`     |
| S6  | FT Auth AP->STA      | AP     | `0x01`       | `0x03`          | `0x10`     |
| S7  | FILS Auth STA->AP    | CLIENT | `0x04`       | `0x06`          | `0x20`     |
| S8  | FILS Auth AP->STA    | AP     | `0x01`       | `0x03`          | `0x10`     |
| S9  | PASN Auth STA->AP    | CLIENT | `0x04`       | `0x06`          | `0x20`     |
| S10 | PASN Auth AP->STA    | AP     | `0x01`       | `0x03`          | `0x10`     |
| S11 | FT Action Request    | CLIENT | `0x04`       | `0x06`          | `0x20`     |
| S12 | FT Action Response   | AP     | `0x01`       | `0x03`          | `0x10`     |
| S13 | FT Action Confirm    | CLIENT | `0x04`       | `0x06`          | `0x20`     |
| S14 | ProbeReq directed    | CLIENT | `0x04`       | `0x06`          | `0x20`     |
| S15 | ProbeReq broadcast   | CLIENT | `0x04`       | `0x06`          | `0x20`     |
| S16 | Beacon RSN IE        | AP     | `0x01`       | `0x03`          | `0x10`     |
| S17 | ProbeResp RSN IE     | AP     | `0x01`       | `0x03`          | `0x10`     |
| S18 | Mesh Peering Open    | CLIENT | `0x04`       | `0x06`          | `0x20`     |
| S19 | Mesh Peering Confirm | CLIENT | `0x04`       | `0x06`          | `0x20`     |
| S20 | OSEN IE              | CLIENT | `0x04`       | `0x06`          | `0x20`     |

---

## §7  Hashcat Kernel Limitations

Root-cause analysis of every uncrackable hash-line category against hashcat mode 22000, verified on hashcat master commit `bb52c06b9` (CPU backend, `-D 1 -O`). Every uncracked line traces to a specific code path in `module_22000.c` or `m22000-pure.cl`; none is a wpawolf bug.

### §7.1  PSK-SHA-256 PMKID (class 4)

**Affected lines.** All `WPA*01*` lines from AKM 6 (PSK-SHA-256). The PMKID is `HMAC-SHA-256(PMK, "PMK Name" || AA || SPA)[0:16]`.

**Root cause.** The PMKID kernel (`m22000-pure.cl:1097-1163`, function `m22000_aux4`) hardcodes HMAC-SHA-1:

```c
sha1_hmac_init (&sha1_hmac_ctx, w, 32);                    // line 1133
sha1_hmac_update_global_swap (&sha1_hmac_ctx, wpa->pmkid_data, 20); // line 1135
sha1_hmac_final (&sha1_hmac_ctx);                           // line 1137
```

No SHA-256 branch exists. The candidate produces a SHA-1 output that never matches the SHA-256 wire value. hashcat reports "Exhausted" with no error.

**Workaround.** Attack the corresponding EAPOL (class 5, `WPA*02*` keyver=3) via the AES-128-CMAC kernel (`m22000_aux3`), which handles PSK-SHA-256 correctly.

**wpawolf behavior.** Emits PSK-SHA-256 PMKIDs as `WPA*01*` with the SHA256 bit (`mp=0x03` AP-side, `mp=0x06` client-side per §6.2 Rule P3). The line is format-valid and will work if hashcat adds a SHA-256 PMKID branch.

### §7.2  FT-PSK APLESS (class 7, combos N2E3 / N4E3)

**Affected lines.** `WPA*04*` lines with APLESS bit set (mp low nibble `0x03` or `0x04`, bit 4 set).

**Root cause.** The FT EAPOL kernel builds the FT-PTK derivation buffer with a hardcoded nonce layout (`module_22000.c:1302-1303`):

```c
memcpy (pke_ptr +  8, auth_packet->wpa_key_nonce, 32);  // assumed SNonce
memcpy (pke_ptr + 40, wpa->anonce,                32);  // line's <anonce> field
```

For M2-anchored combos (N1E2, N3E2, N3E4) this is correct: `auth_packet->wpa_key_nonce` is the SNonce (from the STA's M2/M4 EAPOL body) and `wpa->anonce` is the ANonce (from the hash line's nonce field). For APLESS combos (N2E3, N4E3) the roles are swapped: the EAPOL body is M3 (AP-originated, contains the ANonce) and the hash line's nonce field holds the SNonce. The kernel has no code path to reorder nonces based on the APLESS bit. The FT-PTK derivation uses the wrong nonce ordering, producing a wrong PTK. The MIC never matches.

Non-FT APLESS (`WPA*02*` with mp=`0x13`/`0x14`) cracks correctly because the non-FT kernels (aux1/aux2/aux3) sort nonces by `memcmp` (`module_22000.c:1350-1361`), which is order-independent.

**wpawolf behavior.** Emits FT APLESS lines per convention. M2-anchored FT combos (N1E2, N3E2, N3E4) crack correctly.

### §7.3  LE/BE nonce-endianness flags (bits 5-6)

**Affected lines.** Any `WPA*02*` or `WPA*04*` line with `FLAG_LE` (0x20) or `FLAG_BE` (0x40) set.

**Root cause.** The LE/BE correction paths in the mode 22000 kernel (`m22000-pure.cl:540-573`) have two issues:

1. **Label inversion (aux1/aux2).** For keyver=1 (aux1, WPA1) and keyver=2 (aux2, WPA2-PSK), the LE path (no swap) corrects nonce bytes 30-31, and the BE path (swap) corrects bytes 28-29. This is inverted relative to the detection convention: hcxtools sets `FLAG_LE` when bytes 28-29 differ (the LE counter's LSB changed) and `FLAG_BE` when bytes 30-31 differ. The flag steers hashcat to the wrong path, suppressing the path that would find the correction.

2. **Kernel-dependent mapping (aux3).** For keyver=3 (aux3, PSK-SHA-256 / AES-CMAC), the byte-to-path mapping is different from aux1/aux2. A byte-28 drift that cracks at NC=2 via the BE path on aux1/aux2 requires NC=512 on aux3. A byte-31 drift that cracks via the LE path on aux1/aux2 does not crack at all on aux3 even at NC=512.

```
Empirical results (hashcat v7.1.2-868, CPU backend, verified PSK):

byte shifted | keyver=1,2 LE | keyver=1,2 BE | keyver=3 LE | keyver=3 BE
-------------|---------------|---------------|-------------|------------
   28        |  no           | YES (NC=2)    |  no         |  no (NC=8), YES (NC=512)
   29        |  no           |  no           |  no         |  no
   30        |  no           |  no           |  no         |  no
   31        | YES (NC=2)    |  no           |  no         |  no
```

No single flag assignment works for all three keyver paths. A tool producing hash lines cannot set LE or BE correctly because the correct path depends on the keyver inside the EAPOL body, and the detection (which bytes differ) maps to different correction paths per kernel.

**wpawolf behavior.** LE/BE flags are disabled (Rule E9). Neither flag is set. hashcat tries both paths on every line. See `tools/nonce-endianness-label-inversion.md` for the full analysis with reproduction steps.

---

## §8  References

- hashcat source: `src/modules/module_22000.c`, `OpenCL/m22000-pure.cl`
- [IEEE 802.11-2024]:
  - §9.4.2.24: RSN Information Element (AKM suite enumeration, Table 9-190)
  - §12.6.1.3: PMKID derivation
  - §12.7.1.3: PTK length per AKM
  - §12.7.2: Key Information field (`keyver` bits 0-2)
  - §12.7.6: 4-Way Handshake / EAPOL-Key frames
  - §13.4-§13.8: Fast BSS Transition (FT) key hierarchy
- RFC 3748: EAP (Extensible Authentication Protocol)
- hcxtools: `hcxpcapngtool.c`, `include/hcxpcapngtool.h` (message-pair and PMKID byte constants)
- [`ARCHITECTURE.md`](ARCHITECTURE.md): wpawolf design decisions
