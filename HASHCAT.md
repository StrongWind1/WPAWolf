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

---

## §3  Mode 22000 Format Reference

Verified against upstream hashcat branch `master`, commit `b3ecf3293`.

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

The trailing 1-byte `<mp>` field encodes metadata about how the hash line was constructed. The format is identical across all line prefixes and between wpawolf and hcxpcapngtool. Constants reference `hcxtools/include/hcxpcapngtool.h`.

### EAPOL lines (`WPA*02*`, `WPA*04*`)

```
   bit 7: NC      0x80   nonce-error-correction tolerance was needed
   bit 6: BE      0x40   replay-counter pair resolved as big-endian
   bit 5: LE      0x20   replay-counter pair resolved as little-endian
   bit 4: APLESS  0x10   pair did not require an M1 (set for N2E3, N4E3)
   bits 3-0:      0x0F   combo discriminant (0..5)
```

### N#E# combo notation

`N{nonce_msg}E{eapol_msg}`: **N**once from message **#**, **E**APOL frame from message **#**.

| Combo    | Nonce source | EAPOL source | Low nibble | RC relationship       | APLESS |
|----------|--------------|--------------|----------:|-----------------------|--------|
| **N1E2** | M1 (ANonce)  | M2           | `0x00`    | `RC(M2) == RC(M1)`    | no     |
| **N1E4** | M1 (ANonce)  | M4           | `0x01`    | `RC(M4) == RC(M1)+1`  | no     |
| **N3E2** | M3 (ANonce)  | M2           | `0x02`    | `RC(M2) == RC(M3)-1`  | no     |
| **N2E3** | M2 (SNonce)  | M3           | `0x03`    | `RC(M3) == RC(M2)+1`  | yes    |
| **N4E3** | M4 (SNonce)  | M3           | `0x04`    | `RC(M3) == RC(M4)`    | yes    |
| **N3E4** | M3 (ANonce)  | M4           | `0x05`    | `RC(M4) == RC(M3)`    | no     |

Concrete byte values commonly seen:
```
0x00   N1E2, no flags             clean capture, challenge pair
0x02   N3E2, no flags             clean capture, authorized
0x05   N3E4, no flags             clean capture, authorized
0x13   N2E3, APLESS               AP-less authorized
0x14   N4E3, APLESS               AP-less authorized
0x82   N3E2 with NC               RC drift required nonce correction
0x22   N3E2 with LE               RC pair resolved as little-endian
0x42   N3E2 with BE               RC pair resolved as big-endian
```

Hashcat reads the byte and: masks bits 0-3 to identify the combo; inspects bit 4 (APLESS) to zero nonce-error-corrections; inspects bit 7 (NC) to enable nonce-correction kernel iterations. Bits 5 and 6 (LE/BE) are diagnostic only.

#### 6-to-3 equivalence collapse

Within a single handshake session the 6 combos produce at most 3 cryptographically unique hashes, grouped by the EAPOL frame whose MIC was computed:

| Hash group | Members      | Unique because of   |
|------------|--------------|---------------------|
| Hash-A     | N1E2, N3E2   | M2's EAPOL frame    |
| Hash-B     | N2E3, N4E3   | M3's EAPOL frame    |
| Hash-C     | N1E4, N3E4   | M4's EAPOL frame    |

### PMKID lines (`WPA*01*`, `WPA*03*`)

PMKID lines repurpose the `<mp>` slot as a status byte recording which side of the wire the PMKID was observed on:

| Value  | Constant              | Meaning |
|--------|-----------------------|---------|
| `0x01` | `PMKID_AP`            | AP-to-STA path (M1 KDE, Beacon, Probe Response) |
| `0x03` | `PMKID_AP \| PMKID_APPSK256` | AP-side with PSK-SHA256 AKM hint |
| `0x04` | `PMKID_CLIENT`        | STA-to-AP path (M2 RSN IE, Association Request) |
| `0x10` | `PMKID_AP_FTPSK`      | FT-PSK AP-side (`WPA*03*` lines) |
| `0x20` | `PMKID_CLIENT_FTPSK`  | FT-PSK client-side (`WPA*03*` lines) |

Hashcat's PMKID parser does not use this byte for kernel dispatch; it is diagnostic metadata preserved for round-trip compatibility with hcxpcapngtool.

---

## §7  Known Limitations

### PSK-SHA256-PMKID (class 4)

The mode 22000 PMKID kernel (`m22000_aux4`) computes `HMAC-SHA1(PMK, "PMK Name" || AP || STA)` unconditionally. There is no AKM-dependent branch. This is correct for WPA2-PSK-PMKID (class 2) but **wrong** for PSK-SHA256-PMKID (class 4), which derives the PMKID with `HMAC-SHA256`. A candidate that should match produces a SHA-1 value that never matches the SHA-256 wire value; hashcat reports "Exhausted" with no error.

wpawolf emits PSK-SHA256-PMKID (class 4) as `WPA*01*` lines because the format is valid and will work if hashcat adds a SHA-256 PMKID branch. The workaround today is to attack the corresponding EAPOL (PSK-SHA256-EAPOL, class 5, `WPA*02*` keyver=3), which the AES-CMAC kernel handles correctly.

### SHA-384 family (classes 8-11)

SHA-384 EAPOL classes produce a 24 B (192-bit) MIC (`HMAC-SHA384-192`). Mode 22000's hash field is fixed at 32 hex chars (16 bytes); there is no way to express the wider MIC. Additionally, `keyver=0` (the spec's "reserved" value for SHA-384 EAPOL) is rejected by the loader: `if ((keyver != 1) && (keyver != 2) && (keyver != 3)) return PARSER_SALT_VALUE`.

SHA-384 PMKID classes derive the PMKID with `HMAC-SHA384`, which aux4 does not implement.

wpawolf classifies and counts all four SHA-384 classes (8-11) in the stats banner but does not write them to any output sink.

### FT-PSK-EAPOL APLESS (class 7, combos N2E3 / N4E3)

The mode 22000 FT EAPOL kernel (`m22000_aux6`) builds the PTK derivation buffer with a hardcoded nonce layout:

```c
memcpy(pke_ptr +  8, auth_packet->wpa_key_nonce, 32);   // assumed SNonce
memcpy(pke_ptr + 40, wpa->anonce,                32);   // line's <anonce> field
```

For M2-anchored combos (N1E2, N3E2) this is correct: the EAPOL body's `wpa_key_nonce` is the SNonce and the line's `<anonce>` is the ANonce. For APLESS combos (N2E3, N4E3) the roles are swapped: the EAPOL body (M3) contains the ANonce and the line's `<anonce>` holds the SNonce. The kernel has no code path to re-order nonces based on the APLESS bit. Result: APLESS FT-PSK EAPOL lines load cleanly but never match.

wpawolf emits these lines per the hcxtools convention (APLESS bit set on the message-pair byte). M2-anchored FT combos (N1E2, N3E2, N3E4) crack correctly.

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
