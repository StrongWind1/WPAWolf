# Hashcat WPA-PSK Hash Formats Today (Modes 22000 and 37100)

> **Status: reference.** Describes what current hashcat releases accept today. Frozen against hashcat at the time of writing; no design or proposal content is in this file.

A self-contained reference for every WPA-PSK hash-line format the current hashcat release accepts, exactly as the modules parse them. This document covers state of the world; it does not propose changes.

If you need the new 11-type per-AKM format that supersedes this scheme, read [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md). If you want to know how a future hashcat module could unify everything, read [`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md).

References for every claim in this document:

- `hashcat/src/modules/module_22000.c` -- the mode-22000 loader, formatter, and signature checks
- `hashcat/src/modules/module_37100.c` -- the mode-37100 loader
- `hashcat/OpenCL/m22000-pure.cl`, `m37100-pure.cl` -- the kernels
- `hcxtools/include/hcxpcapngtool.h` -- canonical message-pair byte values and PMKID status bytes
- `hcxtools/hcxpcapngtool.c` -- upstream emitter

---

## §1  The two modes

Hashcat exposes WPA-PSK cracking through two distinct modes today:

| Mode  | Name                               | Reads prefixes        | Used for                            |
|-------|------------------------------------|-----------------------|-------------------------------------|
| 22000 | `WPA-PBKDF2-PMKID+EAPOL`           | `WPA*01*`, `WPA*02*`  | every non-FT PSK hash               |
| 37100 | `WPA-PBKDF2-PMKID+EAPOL` (FT)      | `WPA*03*`, `WPA*04*`  | FT-PSK (fast-roaming, 802.11r) only |

Both modules share the same hash-line shape (the type byte after the first `*` selects which family) but have independent parsers, kernels, and tunings. A line beginning with `WPA*05*` and above is rejected by both modules with `PARSER_SALT_VALUE`.

```c
// module_22000.c, line ~867
if ((type != 1) && (type != 2)) return (PARSER_SALT_VALUE);

// module_37100.c, line ~467
if ((type != 3) && (type != 4)) return (PARSER_SALT_VALUE);
```

The `WPA` literal is checked as a fixed signature on every line (`token.signatures_buf[0] = "WPA"` in both modules).

---

## §2  The four prefixes

| Prefix    | Mode  | Attack surface | Family   | Demuxes AKM via                                            |
|-----------|-------|----------------|----------|------------------------------------------------------------|
| `WPA*01*` | 22000 | PMKID          | flat PSK | none -- kernel runs HMAC-SHA1 unconditionally              |
| `WPA*02*` | 22000 | EAPOL          | flat PSK | `keyver` field bits 0 -- 2 inside the embedded EAPOL frame |
| `WPA*03*` | 37100 | PMKID          | FT-PSK   | none -- kernel hardcodes SHA-256 FT chain                  |
| `WPA*04*` | 37100 | EAPOL          | FT-PSK   | `keyver = 3` only (anything else rejected)                 |

These four prefixes are the entire wire vocabulary current hashcat understands for WPA-PSK. There is no `WPA*05*` or beyond in the released modules.

---

## §3  Field layout per prefix

### `WPA*01*` -- PMKID (mode 22000)

```
WPA*01*<pmkid>*<mac_ap>*<mac_sta>*<essid>***
       32 hex   12 hex    12 hex   0-64 hex
```

| Field         | Width                | Encoding                     |
|---------------|----------------------|------------------------------|
| `<pmkid>`     | 32 hex (16 B)        | lowercase hex                |
| `<mac_ap>`    | 12 hex (6 B)         | lowercase hex, no separators |
| `<mac_sta>`   | 12 hex (6 B)         | lowercase hex                |
| `<essid>`     | 0 -- 64 hex (0 -- 32 B SSID) | lowercase hex; `wpawolf` and hashcat both treat the SSID field as bytes (per `[IEEE 802.11-2024]` §9.4.2.2 it is an arbitrary byte string) |

Three trailing `*` (the empty `<nonce>` and `<eapol>` slots, kept so the field count matches `WPA*02*`). `WPA*01*` lines have **no message-pair byte** in the released module -- the line ends in `***` exactly. (`hcxpcapngtool` writes a single message-pair byte after the trailing `***` for diagnostic purposes; the released hashcat 22000 parser ignores it.)

### `WPA*02*` -- EAPOL (mode 22000)

```
WPA*02*<mic>*<mac_ap>*<mac_sta>*<essid>*<nonce>*<eapol>*<mp>
       32 hex 12 hex    12 hex    0-64h   64 hex  0-512h  2 hex
```

| Field      | Width                   | Notes |
|------------|-------------------------|-------|
| `<mic>`    | 32 hex (16 B)           | the original Key MIC bytes -- before the EAPOL field is zeroed |
| `<mac_ap>` | 12 hex (6 B)            |       |
| `<mac_sta>`| 12 hex (6 B)            |       |
| `<essid>`  | 0 -- 64 hex             |       |
| `<nonce>`  | 64 hex (32 B)           | the *external* nonce (ANonce or SNonce, depending on combo -- see §6) |
| `<eapol>`  | 0 -- 512 hex            | the complete EAPOL-Key frame body with the MIC field (bytes 81 -- 96 of the EAPOL header) zeroed |
| `<mp>`     | 2 hex (1 B)             | message-pair byte; see §6 |

Token width caps come from `module_22000.c` (`token.len_max[7] = 512`).

### `WPA*03*` -- FT PMKID (mode 37100)

Same first six fields as `WPA*01*`, plus three FT extras appended after `***<mp>*`:

```
WPA*03*<pmkid>*<mac_ap>*<mac_sta>*<essid>***<mp>*<mdid>*<r0khid>*<r1khid>
                                              2h   4 hex 2-96 hex 12 hex
```

| Field      | Width                    | Notes |
|------------|--------------------------|-------|
| `<mp>`     | 2 hex                    | PMKID side -- usually `0x20` (`PMKID_CLIENT_FTPSK`) |
| `<mdid>`   | 4 hex (2 B)              | Mobility-Domain ID, lowercase hex |
| `<r0khid>` | 2 -- 96 hex (1 -- 48 B)  | R0 Key Holder ID, lowercase hex |
| `<r1khid>` | 12 hex (6 B)             | R1 Key Holder ID (always a MAC), lowercase hex |

### `WPA*04*` -- FT EAPOL (mode 37100)

Same first eight fields as `WPA*02*`, plus the same three FT extras appended:

```
WPA*04*<mic>*<mac_ap>*<mac_sta>*<essid>*<nonce>*<eapol>*<mp>*<mdid>*<r0khid>*<r1khid>
```

The 37100 module rejects every `WPA*04*` line whose embedded EAPOL frame does not have `keyver = 3` (`if (wpa->keyver != 3) return (PARSER_SALT_VALUE);`). FT-PSK uses AES-128-CMAC, which on the wire is KDV 3 -- the only legal value for an FT EAPOL line.

---

## §4  The `keyver` trick that makes `WPA*02*` ambiguous

A `WPA*02*` line carries no AKM identifier. Three completely different PSK families produce a 16 B MIC and share the wire layout:

- AKM 1 (WPA1)         -- HMAC-MD5 MIC, PRF-SHA1 PTK
- AKM 2 (WPA2-PSK)     -- HMAC-SHA1 MIC, PRF-SHA1 PTK
- AKM 6 (PSK-SHA256)   -- AES-128-CMAC MIC, KDF-SHA256 PTK

Hashcat tells them apart by reading bits 0 -- 2 of the Key Information field (offset 5 of the embedded EAPOL header) -- the standard's `keyver` sub-field per `[IEEE 802.11-2024]` §12.7.2:

```c
// module_22000.c, line ~951
wpa->keyver = key_information & 3;
if ((wpa->keyver != 1) && (wpa->keyver != 2) && (wpa->keyver != 3))
    return (PARSER_SALT_VALUE);
```

| `keyver` | AKM            | MIC algorithm   | Kernel selected (m22000-pure.cl) |
|----------|----------------|------------------|----------------------------------|
| 1        | WPA1           | HMAC-MD5 (16 B)  | `m22000_aux1`                    |
| 2        | WPA2-PSK       | HMAC-SHA1 (16 B) | `m22000_aux2`                    |
| 3        | PSK-SHA256 *or* FT-PSK (37100) | AES-128-CMAC (16 B) | `m22000_aux3` |

The trick works because all three primitives output a 16 B MIC and hashcat can keep one parsed-line struct (`hccapx`-derived) for every case. The moment a family's MIC width differs (SHA-384 produces 24 B), the trick fails -- see §7.

---

## §5  PMKID kernel: one HMAC-SHA1 path for every `WPA*01*` line

The mode-22000 PMKID kernel (`m22000_aux4`) computes:

```
PMKID = HMAC-SHA1(PMK, "PMK Name" || mac_ap || mac_sta)[0:16]
```

unconditionally. There is no AKM-dependent branch; the kernel does not inspect any byte to choose between HMAC-SHA1 and HMAC-SHA256. This is correct for AKM 2 (WPA2-PSK -- the original PMKID definition in `[IEEE 802.11-2024]` §12.6.1.3) and for AKM 1 (WPA1 -- vacuous, WPA1 has no PMKID anyway), but **wrong** for AKM 6 (PSK-SHA256), AKM 19 (FT-PSK-SHA-384), and AKM 20 (PSK-SHA-384), all of which derive the PMKID with a different HMAC primitive.

Practical effect: a passphrase-derived candidate that should match an AKM-6 PMKID will produce a SHA-1 PMKID that never matches the SHA-256-derived value on the wire. Hashcat reports "Exhausted" with no error. The workaround today is to attack the corresponding EAPOL line (`WPA*02*` keyver=3) instead -- the EAPOL kernel correctly handles AES-128-CMAC.

---

## §6  Message-pair byte

The trailing 1-byte `<mp>` field on every EAPOL line encodes which two 4-way-handshake messages were paired plus three diagnostic flag bits. Hashcat parses it in `module_22000.c` line ~1046; the byte values come from `hcxtools` (`hcxtools/include/hcxpcapngtool.h:267 -- 279`).

### EAPOL lines (`WPA*02*`, `WPA*04*`)

```
   bit 7: NC      0x80   nonce-error-correction tolerance was needed
   bit 6: BE      0x40   replay-counter pair resolved as big-endian
   bit 5: LE      0x20   replay-counter pair resolved as little-endian
   bit 4: APLESS  0x10   pair did not require an M1 (set for N2E3, N4E3)
   bits 3-0:      0x0F   combo discriminant (0..5)
```

The combo discriminant identifies which N#E# pair the line represents. Six valid combos exist; a single 4-way handshake can produce at most six lines, one per combo:

| `wpawolf` (N#E#) | `hcxtools` (M#E#) | Nonce source | EAPOL source | Low nibble | RC relationship       |
|------------------|-------------------|--------------|--------------|-----------:|-----------------------|
| **N1E2**         | M12E2             | M1 (ANonce)  | M2           | `0x00`     | `RC(M2) == RC(M1)`    |
| **N1E4**         | M14E4             | M1 (ANonce)  | M4           | `0x01`     | `RC(M4) == RC(M1)+1`  |
| **N3E2**         | M32E2             | M3 (ANonce)  | M2           | `0x02`     | `RC(M2) == RC(M3)-1`  |
| **N2E3**         | M32E3             | M2 (SNonce)  | M3           | `0x03`     | `RC(M3) == RC(M2)+1`; APLESS bit set -> `0x13` |
| **N4E3**         | M34E3             | M4 (SNonce)  | M3           | `0x04`     | `RC(M3) == RC(M4)`; APLESS bit set -> `0x14` |
| **N3E4**         | M34E4             | M3 (ANonce)  | M4           | `0x05`     | `RC(M4) == RC(M3)`    |

Concrete byte values commonly seen on `WPA*02*` / `WPA*04*` lines:

```
0x00   N1E2, no flags             clean capture, challenge pair
0x02   N3E2, no flags             clean capture, authorized
0x05   N3E4, no flags             clean capture, authorized
0x13   N2E3, APLESS               AP-less authorized
0x14   N4E3, APLESS               AP-less authorized
0x82   N3E2 with NC               RC drift required nonce correction
0x22   N3E2 with LE               RC pair resolved as little-endian
0x42   N3E2 with BE               RC pair resolved as big-endian
0xA2   N3E2 with NC + LE          NC and LE both set
```

Hashcat reads the byte and:

- masks bits 0 -- 3 to look up the combo (used to know whether the cracker should try nonce-error-correction reverses);
- inspects bit 4 (APLESS) to know whether a single-side attack is enough;
- inspects bit 7 (NC) to enable the nonce-error-correction kernel (`--nonce-error-corrections=N` cooperates with this bit).

Bits 5 and 6 (LE/BE) are diagnostic only and do not affect the kernel math.

### PMKID lines (`WPA*01*`, `WPA*03*`)

PMKID lines reuse the `<mp>` slot for a different field. The byte records which side of the wire the PMKID was observed on, plus a PSK-SHA256 hint bit. Constants from `hcxtools/include/hcxpcapngtool.h:386 -- 390`:

| Bit / value | Constant                 | Meaning                                                                  |
|-------------|--------------------------|--------------------------------------------------------------------------|
| `0x01`      | `PMKID_AP`               | PMKID observed on the AP-to-STA path (M1 KDE, AP-sent FT Auth seq=2, Beacon, Probe Response) |
| `0x02`      | `PMKID_APPSK256`         | PSK-SHA256 hint -- ORed onto `PMKID_AP` when the AP advertised AKM 6 (the legacy AKM disambiguator the new per-AKM format makes redundant) |
| `0x04`      | `PMKID_CLIENT`           | PMKID observed on the STA-to-AP path (M2 RSN IE, STA-sent FT Auth seq=1, Association / Reassociation Request, Probe Request) |
| `0x10`      | `PMKID_AP_FTPSK`         | FT-PSK AP-side variant (legacy `WPA*03*` only)                           |
| `0x20`      | `PMKID_CLIENT_FTPSK`     | FT-PSK client-side variant (legacy `WPA*03*` only)                       |

Concrete byte values:

```
0x01   AP-side PMKID (M1 KDE -- the most common case)
0x03   AP-side PSK-SHA256 PMKID (PMKID_AP | PMKID_APPSK256)
0x04   client-side PMKID
0x20   FT-PSK client-side PMKID (legacy WPA*03*, what hcxpcapngtool emits)
```

Hashcat's mode-22000 PMKID parser does not consume this byte (it reads the `***` terminator and stops). The byte is captured because the same line format is fed back into `hcxpcapngtool` for diagnostic round-trip and because future kernels (and the new 11-type scheme) keep it.

---

## §7  How the 11 wpawolf hash types map onto the four legacy prefixes

`wpawolf` classifies every PSK-crackable hash into one of eleven types (see [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) for the full classification). When the legacy sinks (`--22000-out`, `--37100-out`) are configured, each row is rewritten with a legacy prefix; this table shows what comes out and how hashcat handles it.

| 11-type row             | Legacy prefix      | Legacy sink     | Hashcat reads via | Cracks today?      |
|-------------------------|--------------------|-----------------|-------------------|--------------------|
| WPA1-PSK-EAPOL          | `WPA*02*`          | `--22000-out`   | `keyver=1`        | yes (m22000_aux1)  |
| WPA2-PSK-PMKID          | `WPA*01*`          | `--22000-out`   | direct prefix     | yes (m22000_aux4)  |
| WPA2-PSK-EAPOL          | `WPA*02*`          | `--22000-out`   | `keyver=2`        | yes (m22000_aux2)  |
| PSK-SHA256-PMKID        | `WPA*01*`          | `--22000-out`   | direct prefix     | **no** -- kernel runs HMAC-SHA1, line is HMAC-SHA256 |
| PSK-SHA256-EAPOL        | `WPA*02*`          | `--22000-out`   | `keyver=3`        | yes (m22000_aux3)  |
| FT-PSK-PMKID            | `WPA*03*`          | `--37100-out`   | direct prefix     | yes (m37100 type=3)|
| FT-PSK-EAPOL            | `WPA*04*`          | `--37100-out`   | `keyver=3`        | partial (m37100 type=4) -- N2E3 / N4E3 APLESS combos do not crack, see §8.1 |
| PSK-SHA384-PMKID        | `WPA*01*`          | `--22000-out`   | best-effort       | **no** -- kernel runs HMAC-SHA1, line is HMAC-SHA384 |
| PSK-SHA384-EAPOL        | `WPA*02*`          | `--22000-out`   | `keyver=0`        | **no** -- 24 B MIC truncated to 16 B; module rejects keyver=0 |
| FT-PSK-SHA384-PMKID     | `WPA*03*`          | `--37100-out`   | best-effort       | **no** -- kernel runs SHA-256 FT chain, line is SHA-384 |
| FT-PSK-SHA384-EAPOL     | `WPA*04*`          | `--37100-out`   | `keyver=0`        | **no** -- 24 B MIC truncated; module rejects keyver=0 |

Six of eleven rows route cleanly through the legacy scheme today. One row misroutes silently inside the kernel (PSK-SHA256-PMKID -- the line is well-formed but the cracker checks the wrong primitive). Four rows have no usable legacy path at all -- the SHA-384 family's 24 B MIC does not fit the 16 B `<mic>` field, and the module rejects `keyver=0` even before reaching the kernel.

---

## §8  Hashcat support matrix today

Status verified against hashcat v7.1.2 using the `tools/fixturegen` corpus (PSK = `hashcat!`, 75 fixtures, 147 lines on the combined `-o` sink, 108 lines routed to `--22000-out`, 15 lines routed to `--37100-out`).

| 11-type code | Name                  | Legacy prefix       | Hashcat mode | Kernel              | Verified status (hashcat 7.1.2)                                                            |
|--------------|-----------------------|---------------------|--------------|---------------------|-------------------------------------------------------------------------------------------|
| 1            | WPA1-PSK-EAPOL        | `WPA*02*` keyver=1  | 22000        | `m22000_aux1`       | **cracks** -- every WPA1 EAPOL line in the corpus matched                                 |
| 2            | WPA2-PSK-PMKID        | `WPA*01*` (AKM 2)   | 22000        | `m22000_aux4`       | **cracks** -- every WPA2 PMKID line matched                                               |
| 3            | WPA2-PSK-EAPOL        | `WPA*02*` keyver=2  | 22000        | `m22000_aux2`       | **cracks** -- every WPA2 EAPOL line matched                                               |
| 4            | PSK-SHA256-PMKID      | `WPA*01*` (AKM 6)   | 22000        | `m22000_aux4`       | **does not crack** -- kernel computes HMAC-SHA1 PMKID; line carries HMAC-SHA-256 value    |
| 5            | PSK-SHA256-EAPOL      | `WPA*02*` keyver=3  | 22000        | `m22000_aux3`       | **cracks** -- KDV=3 AES-CMAC MIC kernel branches on the trailing flag byte                |
| 6            | FT-PSK-PMKID          | `WPA*03*`           | 37100        | `m37100_aux1`       | **cracks** -- PMK-R1Name HMAC-SHA-256 over PMK-R1                                         |
| 7            | FT-PSK-EAPOL          | `WPA*04*`           | 37100        | `m37100_aux2`       | **partial** -- N1E2 / N3E2 / N3E4 (M2-anchored) crack; **APLESS combos N2E3 / N4E3 (M3-anchored) do not** -- see §8.1 below |
| 8            | PSK-SHA384-PMKID      | -- (suppressed)     | --           | --                  | **no module** -- `legacy_sink_for` skips so no `WPA*01*` line is written                 |
| 9            | PSK-SHA384-EAPOL      | -- (suppressed)     | --           | --                  | **no module** -- 24 B HMAC-SHA-384-192 MIC, KDV=0; loader rejects keyver=0               |
| 10           | FT-PSK-SHA384-PMKID   | -- (suppressed)     | --           | --                  | **no module** -- needs FT-KDF-SHA-384 chain                                              |
| 11           | FT-PSK-SHA384-EAPOL   | -- (suppressed)     | --           | --                  | **no module** -- SHA-384 24 B MIC + FT chain, both unsupported                            |

Walking the corpus end-to-end:

| Sink              | Lines wpawolf wrote | Cracked (unique) | Uncracked (unique) | Failure cause                                      |
|-------------------|--------------------:|-----------------:|-------------------:|----------------------------------------------------|
| `--22000-out`     |                 108 |               73 |                  5 | All 5 are PSK-SHA-256 PMKID (type 4)               |
| `--37100-out`     |                  15 |                9 |                  2 | Both are APLESS FT-PSK EAPOL (type 7, N2E3 / N4E3) |
| `-o` combined     |                 147 |       n/a (per-AKM format sink, not fed to hashcat)              |

Six of eleven 11-type rows are wire-cleanly cracked end-to-end. One row is partially crackable -- type 7 cracks for the M2-anchored combos but not the M3-anchored APLESS variants (§8.1). One row routes silently to a wrong-primitive kernel (type 4: SHA-256 PMKID checked against an HMAC-SHA-1 candidate). Four rows are deliberately not written to the legacy sinks because no compatible kernel exists.

### §8.1  The APLESS gap in mode 37100

`module_37100.c::module_hash_decode` lines 691 -- 709 build the FT-PTK derivation buffer with this **hardcoded** layout:

```c
memcpy(pke_ptr +  2, "FT-PTK", 6);
memcpy(pke_ptr +  8, auth_packet->wpa_key_nonce, 32);   // <- assumed SNonce
memcpy(pke_ptr + 40, wpa->anonce,                32);   // <- line's <anonce> field
memcpy(pke_ptr + 72, mac_ap, 6);
memcpy(pke_ptr + 78, mac_sta, 6);
```

`auth_packet->wpa_key_nonce` is the Key Nonce field at offset 17 of whatever EAPOL body the line carries. The kernel **always** treats it as the SNonce input to `KDF-Hash(PMK-R1, "FT-PTK", SNonce || ANonce || BSSID || STA-ADDR)` (per [IEEE 802.11-2024] §13.4.2; nonces are not lex-ordered for FT, unlike non-FT 4-way).

For wpawolf's WPA*04* lines:

| Combo      | Flag    | Line `<anonce>` field | EAPOL body's `wpa_key_nonce` | Hashcat reads as `(SNonce, ANonce)` | Result    |
|------------|---------|-----------------------|------------------------------|-------------------------------------|-----------|
| N1E2       | `*80*`  | M1 ANonce             | M2's nonce = SNonce          | `(SNonce, ANonce)` correct          | cracks    |
| N3E2       | `*02*`  | M3 ANonce             | M2's nonce = SNonce          | `(SNonce, ANonce)` correct          | cracks    |
| **N2E3**   | `*13*`  | M2 SNonce             | M3's nonce = ANonce          | `(ANonce, SNonce)` **swapped**      | no match  |
| **N4E3**   | `*14*`  | M4 SNonce             | M3's nonce = ANonce          | `(ANonce, SNonce)` **swapped**      | no match  |

`module_hash_decode_postprocess` reads the message-pair byte and uses it only to suppress NC iterations when bit 4 is set (`if (wpa->message_pair & (1 << 4)) wpa->nonce_error_corrections = 0;`). There is no code path that re-orders the nonces based on the APLESS bit, and `module_deep_comp_kernel` switches only on `wpa->keyver == 3`, never on `wpa->message_pair`. A hashcat 37100 kernel that handles APLESS would need both: a swap of the line layout interpretation and either a new aux kernel or a runtime branch.

`wpawolf` emits these lines per the established hcxtools convention (SNonce in the line's `<nonce>` field, M3 body in the `<eapol>` field, APLESS bit set on the message-pair byte). The corpus walk confirms the bytes are well-formed -- the failure is exclusively kernel-side. The lines remain available on `--ft-out` and `-o` for downstream tools that do support APLESS FT-PSK.

---

## §9  Limitations (why this scheme is at end-of-life)

1. **The `keyver` trick does not scale past 16 B MICs.** SHA-384 produces a 24 B (192-bit) MIC. The legacy `<mic>` field is locked at 32 hex characters (16 B). Stretching it to 48 hex characters changes the token-length validation in the loader and breaks the parsed-line struct that today holds `keymic[4]` of `u32`. Backporting wider MIC support means breaking-changes to every consumer of the format.
2. **PMKID kernel cannot disambiguate AKM.** A `WPA*01*` line carries no AKM byte. The kernel runs HMAC-SHA1 unconditionally, which is correct for AKM 2 only. AKM 6 (SHA-256) and AKMs 19/20 (SHA-384) all produce different PMKID values; the cracker checks a SHA-1 answer against a SHA-256 / SHA-384 wire value and never matches. There is no way to fix this without a new prefix (or an AKM byte in the line, which is the same thing structurally).
3. **FT prefixes hardcode SHA-256.** `WPA*03*` and `WPA*04*` were defined when AKM 4 (FT-PSK with SHA-256) was the only FT-PSK variant. AKM 19 (FT-PSK-SHA-384) uses the same FT key-hierarchy shape with SHA-384 throughout -- nothing in the line tells a `WPA*03*` reader to switch primitives.
4. **`keyver=0` reserved.** AKMs 19 and 20 negotiate SHA-384 out of band and emit `keyver=0` in their EAPOL Key Information. The current 22000 loader rejects `keyver=0` outright (`if ((keyver != 1) && (keyver != 2) && (keyver != 3)) return PARSER_SALT_VALUE`), so even a SHA-384 line with a fictitious 16 B MIC would not load.
5. **No room for a new variant.** Any future PSK family added to the IEEE spec (e.g. a hypothetical "PSK-SHA512" or a quantum-resistant replacement) would need yet another `keyver` slot or yet another prefix. The scheme is structurally not extensible.

The new 11-type prefix scheme (one prefix per row) is the response to limitations 2 -- 5; the unified "1 module for all PSK types" proposal in [`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md) is the response to limitation 1.

---

## §10  References

- `hashcat/src/modules/module_22000.c` -- mode 22000 loader, formatter, parsed-line struct
- `hashcat/src/modules/module_37100.c` -- mode 37100 loader (FT-PSK)
- `hashcat/OpenCL/m22000-pure.cl`, `m37100-pure.cl` -- kernels
- `hcxtools/include/hcxpcapngtool.h:267 -- 279` -- `MESSAGE_PAIR_M*` and `ST_*` flag bits
- `hcxtools/include/hcxpcapngtool.h:386 -- 390` -- `PMKID_*` byte values
- `hcxtools/hcxpcapngtool.c:2333 -- 2552` -- upstream emitter for `WPA*01*..*04*`
- `[IEEE 802.11-2024]` §12.6.1.3 -- PMKID derivation
- `[IEEE 802.11-2024]` §12.7.2 -- Key Information field, `keyver` bits 0 -- 2
- `[IEEE 802.11-2024]` §12.7.6 -- 4-Way Handshake / EAPOL-Key frames
- `[IEEE 802.11-2024]` §13.4 -- §13.8 -- FT key hierarchy
- [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) -- the 11-type per-AKM format
- [`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md) -- proposed unified module
- [`ARCHITECTURE.md`](ARCHITECTURE.md) -- `wpawolf` design decisions
