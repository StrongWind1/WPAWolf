# The 11 New WPA-PSK Hash Formats: How and Why

> **Status: specification.** Defines the 11-type classification that wpawolf emits today on its per-AKM sinks (`-o`, `--wpa1-out`, `--wpa2-out`, ...). The hashcat side of consuming these is sketched separately in [`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md) and is not yet implemented in upstream hashcat.

A complete reference for the 11-type WPA-PSK hash classification that `wpawolf` emits and that a future hashcat module will consume. Every PSK-crackable hash defined by `[IEEE 802.11-2024]` gets exactly one type code, one line prefix, and one self-contained format. This document covers the format itself: per-row line layout, cracker math, and the design rationale for each choice. It does not cover implementation in hashcat (see [`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md)) and it does not cover what current hashcat understands today (see [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md)).

---

## §1  Why eleven types

The legacy hashcat scheme uses four prefixes (`WPA*01*..*04*`) and demuxes the AKM / MIC variant via a `keyver` byte buried inside the EAPOL frame body. That trick worked when every PSK family produced a 16 B MIC, but it has three structural problems:

1. **The `keyver` trick does not scale past 16 B MICs.** SHA-384 produces a 24 B MIC (192 bits). The legacy `<mic>` field is locked at 32 hex characters; stretching it changes loader validation, parsed-line structs, and every downstream tool.
2. **The `WPA*01*` PMKID prefix carries no AKM identifier.** Hashcat runs HMAC-SHA1 unconditionally, so AKM 6 / 19 / 20 PMKIDs misroute silently; the cracker checks the wrong primitive and reports "Exhausted" with no error.
3. **`WPA*03*` / `WPA*04*` hardcode SHA-256 for FT.** The AKM-19 FT-PSK-SHA-384 family has the same FT key-hierarchy shape but with SHA-384 throughout; nothing in the line tells the parser to switch.

The new scheme makes the type code self-contained: it alone determines the PMKID hash primitive, the PTK KDF, the KCK length, the MIC algorithm, and the MIC field width. A parser inspects the 2-digit type byte after `WPA*` and knows everything else.

The cracking math is unchanged. The classification reorganises what the line declares to the cracker; the underlying cryptographic operations are the same ones the spec already defined.

---

## §2  The encoding rules

Two rules cover the entire table:

```
EVEN code  =  PMKID attack    (no full handshake needed)
ODD  code  =  EAPOL attack    (needs nonce + MIC frame)

Ascending code  =  ascending hash complexity
   (each row lists, in order: PMKID primitive; PTK KDF; MIC algorithm, width; FT extras if present)
   01      WPA1 / TKIP      (no PMKID; PRF-SHA1 PTK; HMAC-MD5 MIC, 16 B)
   02-03   WPA2-PSK         (HMAC-SHA1 PMKID; PRF-SHA1 PTK; HMAC-SHA1 MIC, 16 B)
   04-05   PSK-SHA256 flat  (HMAC-SHA256 PMKID; KDF-SHA256 PTK; AES-128-CMAC MIC, 16 B)
   06-07   FT-PSK SHA-256   (FT-KDF-SHA256 PMKID; FT-KDF-SHA256 PTK; AES-128-CMAC MIC, 16 B; FT extras)
   08-09   PSK-SHA384 flat  (HMAC-SHA384 PMKID; KDF-SHA384 PTK; HMAC-SHA384 MIC, 24 B)
   10-11   FT-PSK SHA-384   (FT-KDF-SHA384 PMKID; FT-KDF-SHA384 PTK; HMAC-SHA384 MIC, 24 B; FT extras)
```

Type 01 (WPA1-PSK-EAPOL) is the only odd code without a PMKID partner: WPA1 has no PMKID field in its RSN IE, so there is nothing to attack on that path.

### Why this ordering

- **Ascending complexity at a glance.** Reading the table top-down, each pair adds at most one or two changes from the pair above (different MIC primitive, different KDF, or insertion of the FT key chain). A cracker that holds the PMK can derive type N+1 from type N's intermediate values almost for free; ordering the table by complexity makes that overlap visible.
- **PMKID + EAPOL stay adjacent within a family.** Codes (2, 3) are both WPA2-PSK; (4, 5) are both PSK-SHA256; etc. Operators triaging captures think "WPA2 family, WPA3 SAE family, FT family", not "PMKID family, EAPOL family".
- **Even/odd parity is a quick attack-surface filter.** A `grep '^WPA\*0[24680]\*'` selects every PMKID line in a combined output; `'^WPA\*0[1357]\*\|^WPA\*1[1]\*'` selects every EAPOL line.

### Why type 01 is WPA1, not WPA2

WPA1 / TKIP predates the IEEE numbering. AKM 1 was reserved for 802.1X / EAP and AKM 2 was the first PSK suite. The 11-type scheme follows hardware lineage: WPA1 (the oldest crackable variant, vendor IE `00:50:F2:01`, HMAC-MD5 MIC) gets type 01, then the WPA2 family fills 02-03, and complexity climbs from there.

---

## §3  The 11 canonical names

These names are used verbatim in stats output, source code (`HashType` enum in `src/types.rs`), and operator-facing log messages.

| # | Name                       | AKM (selector)     | KDV |
|---|----------------------------|--------------------|-----|
| 1 | WPA1-PSK-EAPOL             | WPA1 vendor IE     | 1   |
| 2 | WPA2-PSK-PMKID             | 2 (`00:0F:AC:02`)  | -   |
| 3 | WPA2-PSK-EAPOL             | 2                  | 2   |
| 4 | PSK-SHA256-PMKID           | 6 (`00:0F:AC:06`)  | -   |
| 5 | PSK-SHA256-EAPOL           | 6                  | 3   |
| 6 | FT-PSK-PMKID               | 4 (`00:0F:AC:04`)  | -   |
| 7 | FT-PSK-EAPOL               | 4                  | 3   |
| 8 | PSK-SHA384-PMKID           | 20 (`00:0F:AC:14`) | -   |
| 9 | PSK-SHA384-EAPOL           | 20                 | 0   |
| 10 | FT-PSK-SHA384-PMKID       | 19 (`00:0F:AC:13`) | -   |
| 11 | FT-PSK-SHA384-EAPOL       | 19                 | 0   |

AKM values reference `[IEEE 802.11-2024]` Table 9-190 (OUI `00:0F:AC` selector). KDV values reference §12.7.2 Key Information bits 0-2; PMKID-only rows have no KDV (the field exists only in EAPOL-Key frames). KDV `0` for SHA-384 EAPOL is the spec's "reserved" value; the AKM negotiates SHA-384 out of band rather than via the keyver field, because the 16 B MIC slot the keyver field selects cannot accommodate a 24 B MIC.

### Why these names exactly

- **All-uppercase, dash-separated.** `WPA2-PSK-EAPOL` not `wpa2_psk_eapol` or `WPA2PSKEapol`. Stable identifier across stats output, log messages, and cross-doc references; trivially shell- greppable; unambiguous when read aloud.
- **Family-prefix-then-attack-suffix.** Reading left-to-right narrows by family (`WPA2`, `PSK-SHA256`, `FT-PSK`, `PSK-SHA384`, `FT-PSK-SHA384`) then specifies the attack surface (`-PMKID` or `-EAPOL`). Sorting the names lexically gives the same family grouping the type-code ordering gives.
- **`-PMKID` / `-EAPOL` not `-PMK` / `-MIC`.** The suffix names the *attack surface* (what the cracker sees on the wire), not the *output of the kernel* (which would be `PMKID` for both `-PMKID` rows and `-MIC` for the EAPOL rows). Surface-naming matches the operator's mental model of "do I have a full handshake or not?".

---

## §4  Per-type cracker math

Every type starts from the same step. PBKDF2 is the only deliberately expensive operation; the post-PMK work is microseconds per candidate.

```
Step 0 (shared by all 11 types):
    PMK = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096 rounds, 32 B)
```

### Type 1: WPA1-PSK-EAPOL

```
PMK ---[PRF-SHA1, 512 b]---> PTK
KCK = PTK[0:16]
MIC = HMAC-MD5(KCK, EAPOL_zeroed)[0:16]
```
KDV = 1. No PMKID partner.

### Types 2 + 3: WPA2-PSK

```
PMKID (type 2):
    PMKID = HMAC-SHA1(PMK, "PMK Name" || AP || STA)[0:16]

EAPOL (type 3):
    PMK ---[PRF-SHA1, 384 b]---> PTK
    KCK = PTK[0:16]
    MIC = HMAC-SHA1(KCK, EAPOL_zeroed)[0:16]
```
KDV = 2.

### Types 4 + 5: PSK-SHA256

```
PMKID (type 4):
    PMKID = HMAC-SHA256(PMK, "PMK Name" || AP || STA)[0:16]

EAPOL (type 5):
    PMK ---[KDF-SHA256, 384 b]---> PTK
    KCK = PTK[0:16]
    MIC = AES-128-CMAC(KCK, EAPOL_zeroed)   [16 B]
```
KDV = 3.

### Types 6 + 7: FT-PSK (802.11r SHA-256)

```
PMK ---[FT-KDF-SHA256]---> PMK-R0 ---[FT-KDF-SHA256]---> PMK-R1

PMKID (type 6):
    PMKID = PMK-R1-Name = SHA256("FT-R1N" || PMK-R0-Name || R1KH-ID || STA)[0:16]

EAPOL (type 7):
    same chain ---> PTK
    KCK = PTK[0:16]
    MIC = AES-128-CMAC(KCK, EAPOL_zeroed)   [16 B]
```

Both rows require MDID (2 B), R0KH-ID (1-48 B), R1KH-ID (6 B) from the hash line to drive the chain. KDV = 3 (EAPOL).

### Types 8 + 9: PSK-SHA384

```
PMKID (type 8):
    PMKID = HMAC-SHA384(PMK, "PMK Name" || AP || STA)[0:16]
    (still 16 B output, Truncate-128)

EAPOL (type 9):
    PMK ---[KDF-SHA384, 576 b]---> PTK
    KCK = PTK[0:24]                        <-- 24 bytes (192 bits)
    MIC = HMAC-SHA384(KCK, EAPOL_zeroed)[0:24]   <-- 24 bytes
```
KDV = 0.

### Types 10 + 11: FT-PSK-SHA384

```
PMK ---[FT-KDF-SHA384]---> PMK-R0 ---[FT-KDF-SHA384]---> PMK-R1

PMKID (type 10):
    PMKID = SHA384("FT-R1N" || PMK-R0-Name || R1KH-ID || STA)[0:16]

EAPOL (type 11):
    same chain ---> PTK
    KCK = PTK[0:24]
    MIC = HMAC-SHA384(KCK, EAPOL_zeroed)[0:24]
```

Both rows require MDID + R0KH-ID + R1KH-ID. KDV = 0 (EAPOL).

### The differential view: one swap per step

Reading the table top-to-bottom, each row changes exactly one or two things. This is the cracker's perspective.

```
01 -> 03   Same PRF-SHA1 PTK; swap MIC: MD5 -> SHA1.
03 -> 05   Swap PTK KDF: PRF-SHA1 -> KDF-SHA256; swap MIC: HMAC-SHA1 -> AES-CMAC.
05 -> 07   Insert FT chain (PMK -> PMK-R0 -> PMK-R1) before PTK; MIC unchanged.
02 -> 04   Same PMKID formula structure; swap hash: SHA1 -> SHA256.
04 -> 06   Insert FT chain to derive PMKR1-Name instead of flat PMKID.
05 -> 09   Swap PTK KDF: KDF-SHA256 -> KDF-SHA384.
           KCK grows: 16 B -> 24 B.
           Swap MIC: AES-CMAC-128 -> HMAC-SHA384, size 16 B -> 24 B.
           (largest single step: new MIC field width)
07 -> 11   Same FT chain structure and same extra fields.
           Swap KDF: SHA-256 -> SHA-384 throughout the chain.
           KCK grows: 16 B -> 24 B; MIC grows: 16 B -> 24 B.
```

### Shared subtrees a cracker can cache

```
passphrase + SSID
       |
       v
 PBKDF2-SHA1 ---------------------------------------- shared by all 11 types
       |
       +-- [HMAC-SHA1]   -----> PMKID         -> type 02
       |
       +-- [PRF-SHA1]  -> KCK16 -> [MD5 MIC]    -> type 01
       |               +--------->  [SHA1 MIC]   -> type 03
       |
       +-- [HMAC-SHA256] -----> PMKID         -> type 04
       |
       +-- [KDF-SHA256]  -> KCK16 -> [CMAC MIC]  -> type 05
       |
       +-- [FT-KDF-SHA256] -> PMKR1-Name      -> type 06
       |                  +-> KCK16 -> [CMAC MIC] -> type 07
       |
       +-- [HMAC-SHA384] -----> PMKID         -> type 08
       |
       +-- [KDF-SHA384]  -> KCK24 -> [SHA384 MIC] -> type 09
       |
       +-- [FT-KDF-SHA384] -> PMKR1-Name      -> type 10
       |                   +-> KCK24 -> [SHA384 MIC] -> type 11
```

Implementation consequence: a cracker that handles all 11 types implements each leaf node (HMAC-SHA1, PRF-SHA1 PTK, MD5 MIC, SHA1 MIC, HMAC-SHA256, KDF-SHA256 PTK, AES-CMAC, FT-KDF-SHA256, HMAC-SHA384, KDF-SHA384 PTK, HMAC-SHA384 MIC, FT-KDF-SHA384) once. The branches above each leaf are shared. The PBKDF2-SHA1 step is the single hot path; the type-specific work is a constant amount of post-PMK arithmetic.

---

## §5  Hash-line format

Two base shapes. The type code selects between them.

### Non-FT (types 1, 2, 3, 4, 5, 8, 9)

```
WPA*XX*<hash>*<ap>*<sta>*<essid>*<nonce>*<eapol>*<mp>
```

Eight `*`-separated fields after `WPA*XX*`. PMKID rows (codes 2, 4, 8) present `<nonce>` and `<eapol>` as empty fields (`**`) so the field count is identical to EAPOL rows of the same family.

### FT (types 6, 7, 10, 11)

```
WPA*XX*<hash>*<ap>*<sta>*<essid>*<nonce>*<eapol>*<mp>*<mdid>*<r0khid>*<r1khid>
```

Eleven `*`-separated fields. The FT extras (MDID, R0KH-ID, R1KH-ID) are required so the cracker can re-derive PMK-R1.

### Field widths

| Field      | PMKID rows (2, 4, 6, 8, 10) | EAPOL rows 1, 3, 5, 7 | EAPOL rows 9, 11 (24 B MIC) |
|------------|-----------------------------|-----------------------|------------------------------|
| `<hash>`   | 32 hex (16 B PMKID)         | 32 hex (16 B MIC)     | **48 hex (24 B MIC)**        |
| `<ap>`     | 12 hex (6 B)                | 12 hex                | 12 hex                       |
| `<sta>`    | 12 hex (6 B)                | 12 hex                | 12 hex                       |
| `<essid>`  | 0-64 hex (0-32 B SSID)      | 0-64 hex              | 0-64 hex                     |
| `<nonce>`  | empty                       | 64 hex (32 B)         | 64 hex (32 B)                |
| `<eapol>`  | empty                       | variable hex; MIC zeroed at offset 81-96    | variable hex; MIC zeroed |
| `<mp>`     | 2 hex                       | 2 hex                 | 2 hex                        |
| `<mdid>`   | 4 hex (FT only)             | 4 hex (FT only)       | 4 hex (FT only)              |
| `<r0khid>` | 2-96 hex (FT only)          | 2-96 hex (FT only)    | 2-96 hex (FT only)           |
| `<r1khid>` | 12 hex (FT only)            | 12 hex (FT only)      | 12 hex (FT only)             |

`<eapol>` carries the complete EAPOL-Key frame with the Key MIC field (bytes 81-96 of the EAPOL header) zeroed. The cracker recomputes the MIC over the zeroed frame to verify a candidate passphrase. The **original** Key MIC bytes (before zeroing) are what the `<hash>` field contains for EAPOL rows.

### Concrete examples

```
type 02   WPA*02*4a8fc3d19e2b...32hex...*aabbccddeeff*112233445566*4d79...***01
type 03   WPA*03*9f1e0d...32hex...*aabbccddeeff*112233445566*4d79...*<64h>*<eapol>*00
type 07   WPA*07*2b7d...32hex...*aabbccddeeff*112233445566*4d79...*<n>*<e>*00*dead*<r0>*<r1>
type 09   WPA*09*5c4a...48hex (24 B MIC)...*aabbccddeeff*112233445566*4d79...*<n>*<e>*00
type 11   WPA*11*3f8b...48hex...*aabbccddeeff*112233445566*4d79...*<n>*<e>*00*dead*<r0>*<r1>
```

A parser tokenises on `*`, reads the 2-digit type code, and from the type code looks up FT-vs-non-FT (column count) and 16-B-vs-24-B MIC (`<hash>` width). No `keyver` peek inside the EAPOL frame is required.

### Why these specific design choices

- **Type code as the first field after `WPA*`.** First field after a fixed signature so a tokeniser can dispatch without scanning the whole line. Hashcat's existing 22000 / 37100 modules already validate the position with `TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_SIGNATURE`; the new scheme reuses that machinery.
- **2 hex digits, zero-padded.** Lexically sortable (`WPA*02*` precedes `WPA*10*` correctly); always exactly 2 columns; trivial to validate (`token.len[1] = 2`).
- **MIC field width determined by the type code, not by the line.** Type 09 always has a 48-hex MIC; type 03 always has a 32-hex MIC. Loaders read the type byte first, then know to validate the MIC field at 32 or 48 hex. This is the structural fix for limitation 1 in [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md) §9.
- **PMKID rows preserve `<nonce>` and `<eapol>` slots empty.** The field count is identical between PMKID and EAPOL within a family; parsers that strip empty fields can reuse the same struct for both. An older parser written for the legacy `WPA*01*` "ends in `***`" pattern still works on `WPA*02*`, `WPA*04*`, `WPA*08*`.
- **FT extras appended after `<mp>`, not interleaved.** Non-FT lines have 8 columns; FT lines have 11. A parser that does not understand FT can stop after column 8 (the `<mp>` byte) and still get the right PMKID / MIC / MAC / ESSID values for the line; the FT extras are additive, never repositioning. This preserves the legacy `WPA*03*` / `WPA*04*` ordering verbatim.
- **Lowercase hex, no `0x` prefix, no separators.** Single regex validation per field (`[0-9a-f]+`); no ambiguity about case comparison; matches the upstream `hcxpcapngtool` convention so downstream tools transition with no string-handling changes.

---

## §6  N#E# notation: the six pair combos

Every EAPOL line ends with a 1-byte `<mp>` field that encodes which two messages of the 4-way handshake formed the pair, plus three diagnostic flag bits. The byte format and bit values are identical between the new classification and the legacy scheme (the new scheme only changes which prefix the line carries, not what the trailing byte means), so a future hashcat module can reuse the existing parsing logic verbatim.

### Notation

`wpawolf` and the new classification use **N#E#** notation: **N**once from message **#**, **E**APOL frame from message **#**. So `N1E2` = ANonce sourced from M1, EAPOL/MIC sourced from M2.

`hcxpcapngtool` uses the older **M#E#** notation, written in full as `M{nonce}{eapol}E{eapol}` so `M12E2` packs both message IDs around the `E`. The two notations describe the same six combos.

| wpawolf / extended format | hcxpcapngtool | Nonce source | EAPOL source | Hash-line `<nonce>` field | RC relationship       | `<mp>` low nibble |
|--------------------|---------------|--------------|--------------|---------------------------|-----------------------|------------------:|
| **N1E2**           | M12E2         | M1 (ANonce)  | M2           | M1 ANonce                 | `RC(M2) == RC(M1)`    | `0x00`            |
| **N1E4**           | M14E4         | M1 (ANonce)  | M4           | M1 ANonce                 | `RC(M4) == RC(M1)+1`  | `0x01`            |
| **N3E2**           | M32E2         | M3 (ANonce)  | M2           | M3 ANonce                 | `RC(M2) == RC(M3)-1`  | `0x02`            |
| **N2E3**           | M32E3         | M2 (SNonce)  | M3           | M2 SNonce                 | `RC(M3) == RC(M2)+1`  | `0x03` (APLESS bit set -> `0x13`) |
| **N4E3**           | M34E3         | M4 (SNonce)  | M3           | M4 SNonce                 | `RC(M3) == RC(M4)`    | `0x04` (APLESS bit set -> `0x14`) |
| **N3E4**           | M34E4         | M3 (ANonce)  | M4           | M3 ANonce                 | `RC(M4) == RC(M3)`    | `0x05`            |

For N2E3 and N4E3 the SNonce is the external nonce because the EAPOL frame is M3 (which already contains the AP's ANonce internally); the cracker needs the STA-side SNonce as the second nonce input to KDF / PRF when deriving the candidate PTK. These two combos can be cracked without an M1 in hand at all; hence "AP-less".

### What triggers each combo

A combo is emitted whenever the extractor finds, within a single `(AP, STA)` group, both required messages (the nonce source and the EAPOL/MIC source) and the optional output-filter constraints pass. With every filter off, all six combos that the captured messages permit are emitted.

| Combo | Required messages | Typical capture conditions                                                |
|-------|-------------------|----------------------------------------------------------------------------|
| N1E2  | M1 + M2           | initial handshake observed cleanly                                         |
| N1E4  | M1 + M4           | M2 / M3 missed but the STA still completed; M4 confirms install            |
| N3E2  | M2 + M3           | AP retransmitted M3 with same ANonce as M1; M2 carries STA's MIC           |
| N2E3  | M2 + M3           | AP-less viewpoint of the same M2 + M3 pair; nonce is SNonce                |
| N4E3  | M3 + M4           | AP-less viewpoint with M4's SNonce; M3 carries the AP's MIC                |
| N3E4  | M3 + M4           | both AP-side messages observed; nonce is M3 ANonce                         |

A capture that contains all four messages (M1, M2, M3, M4) for a single session can produce all six combos. A capture that lost M1 still produces N3E2 / N2E3 / N4E3 / N3E4 (4 of 6). A capture with only M2 + M3 produces N3E2 and N2E3 (2 of 6).

### 6 -> 3 equivalence collapse

Within a single handshake session (M1 and M3 carry the same ANonce, M2 and M4 carry the same SNonce), the 6 combos produce at most 3 cryptographically unique hashes. They group by the EAPOL frame whose MIC was computed:

| Class  | Members      | Unique because of |
|--------|--------------|-------------------|
| Hash-A | N1E2, N3E2   | M2's EAPOL frame  |
| Hash-B | N2E3, N4E3   | M3's EAPOL frame  |
| Hash-C | N1E4, N3E4   | M4's EAPOL frame  |

By default emitters write all 6 (resilient against retransmissions where one combo's nonce mutated); collapsing to 3 keeps one survivor per class chosen by smallest RC gap, then by authorized-combo priority (N3E2 over N1E2, N2E3 over N4E3, N3E4 over N1E4; M3-sourced nonces are canonical because M3 is signed by the AP after its own PTK derivation).

---

## §7  Message-pair byte (`<mp>`): complete bit spec

The most underdocumented part of the legacy hashcat format. The byte is **identical** between the legacy and new classification schemes; a future hashcat kernel can use the same parsing logic for both.

### EAPOL lines (codes 1, 3, 5, 7, 9, 11)

```
   bit 7: NC      0x80   nonce-error-correction tolerance was needed to pair
   bit 6: BE      0x40   replay-counter pair resolved as big-endian
   bit 5: LE      0x20   replay-counter pair resolved as little-endian
   bit 4: APLESS  0x10   pair did not require an M1 (set for N2E3, N4E3)
   bits 3-0:      0x0F   combo discriminant (N1E2=0..N3E4=5; see §6)
```

**APLESS** (bit 4) is set whenever the combo did not consume an M1. N2E3 (`0x03`) and N4E3 (`0x04`) are the two AP-less combos; an emitter ORs `0x10` onto the byte for both.

**LE** and **BE** (bits 5 and 6) mark replay-counter endianness disagreement. Most APs encode the EAPOL replay counter in big-endian network order, but some embedded firmware emits little-endian. The pairing engine compares RC bytes both ways and sets the bit corresponding to the encoding that resolved the match. These bits are diagnostic; they do not affect the cracking math.

**NC** (bit 7) signals that nonce-error-correction was needed to pair; the engine had to allow the RC delta to wander beyond the spec's expected value (`RC(M2) == RC(M1)`, `RC(M3) == RC(M2) + 1`, etc.) by up to the pairing tolerance. A cracker reading this bit knows the pair may need extra nonce-bit guessing during cracking. `wpawolf` also sets NC unconditionally on N3E4 pairs that share a session group with at least one M1, mirroring the upstream heuristic for "session likely had nonce drift".

#### Concrete byte values

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

A new hashcat kernel reading the byte should mask bits 0-3 to extract the combo discriminant, branch on bits 4-7 for diagnostic flags (only NC affects cracking strategy), and ignore reserved bit 3 (always 0 in current emitters).

### PMKID lines (codes 2, 4, 6, 8, 10)

PMKID lines reuse the `<mp>` byte slot for a different purpose: it records which side of the wire the PMKID was observed on, plus an optional PSK-SHA256 hint bit. Values come from `hcxtools/include/hcxpcapngtool.h:386-390`:

| Bit / value | Constant            | Meaning |
|-------------|---------------------|---------|
| `0x01`      | `PMKID_AP`          | PMKID observed on the AP-to-STA path (M1 KDE, AP-sent FT Auth seq=2, Beacon, Probe Response) |
| `0x02`      | `PMKID_APPSK256`    | PSK-SHA256 hint: ORed onto `PMKID_AP` when the AP advertised AKM 6 (legacy disambiguator the new classification makes redundant) |
| `0x04`      | `PMKID_CLIENT`      | PMKID observed on the STA-to-AP path (M2 RSN IE, STA-sent FT Auth seq=1, Association Request, Probe Request) |
| `0x10`      | `PMKID_AP_FTPSK`    | FT-PSK AP-side variant (legacy `WPA*03*` only) |
| `0x20`      | `PMKID_CLIENT_FTPSK`| FT-PSK client-side variant (legacy `WPA*03*` only) |

For the new classification, the AKM is already encoded in the type code (`WPA*02*` is always WPA2-PSK, `WPA*04*` is always PSK-SHA256, etc.); the `PMKID_APPSK256` hint becomes redundant. The AP-vs-client distinction (`PMKID_AP` vs `PMKID_CLIENT`) remains useful as a diagnostic but does not affect verification math.

### Why the byte stays compatible

Keeping the `<mp>` byte format unchanged across the two schemes is a deliberate design choice: it lets a hashcat module that handles both legacy and per-AKM format lines share one parser branch for the message-pair logic, and it lets `wpawolf` (and any other emitter) write the byte once without per-prefix branching. The trailing byte is the only field whose semantics are independent of the line prefix.

---

## §8  Hash-line examples by row

Hash-line shapes for every row, with realistic field widths.

```
type 01  WPA1-PSK-EAPOL
WPA*01*<32hex MIC>*<12hex AP>*<12hex STA>*<0-64hex ESSID>*<64hex M1 ANonce>*<eapol with MIC zeroed>*<2hex mp>

type 02  WPA2-PSK-PMKID
WPA*02*<32hex PMKID>*<12hex AP>*<12hex STA>*<0-64hex ESSID>***<2hex mp>

type 03  WPA2-PSK-EAPOL
WPA*03*<32hex MIC>*<12hex AP>*<12hex STA>*<0-64hex ESSID>*<64hex nonce>*<eapol>*<2hex mp>

type 04  PSK-SHA256-PMKID
WPA*04*<32hex PMKID>*<12hex AP>*<12hex STA>*<0-64hex ESSID>***<2hex mp>

type 05  PSK-SHA256-EAPOL
WPA*05*<32hex MIC>*<12hex AP>*<12hex STA>*<0-64hex ESSID>*<64hex nonce>*<eapol>*<2hex mp>

type 06  FT-PSK-PMKID
WPA*06*<32hex PMKID>*<12hex AP>*<12hex STA>*<0-64hex ESSID>***<2hex mp>*<4hex MDID>*<2-96hex R0KH-ID>*<12hex R1KH-ID>

type 07  FT-PSK-EAPOL
WPA*07*<32hex MIC>*<12hex AP>*<12hex STA>*<0-64hex ESSID>*<64hex nonce>*<eapol>*<2hex mp>*<4hex MDID>*<2-96hex R0KH-ID>*<12hex R1KH-ID>

type 08  PSK-SHA384-PMKID
WPA*08*<32hex PMKID>*<12hex AP>*<12hex STA>*<0-64hex ESSID>***<2hex mp>

type 09  PSK-SHA384-EAPOL
WPA*09*<48hex MIC>*<12hex AP>*<12hex STA>*<0-64hex ESSID>*<64hex nonce>*<eapol>*<2hex mp>

type 10  FT-PSK-SHA384-PMKID
WPA*10*<32hex PMKID>*<12hex AP>*<12hex STA>*<0-64hex ESSID>***<2hex mp>*<4hex MDID>*<2-96hex R0KH-ID>*<12hex R1KH-ID>

type 11  FT-PSK-SHA384-EAPOL
WPA*11*<48hex MIC>*<12hex AP>*<12hex STA>*<0-64hex ESSID>*<64hex nonce>*<eapol>*<2hex mp>*<4hex MDID>*<2-96hex R0KH-ID>*<12hex R1KH-ID>
```

Note that types 09 and 11 are the only rows with a 48-hex (24 B) `<hash>` field. All other rows use 32 hex (16 B). A parser keys this off the type code, not off field length.

---

## §9  References

- `[IEEE 802.11-2024]` Wi-Fi specification:
  - §9.4.2.24 RSN Element (AKM suite enumeration)
  - §12.6.1.3 PMKID derivation
  - §12.7.1.3 PTK length per AKM
  - §12.7.2 Key Information field (`keyver` bits 0-2)
  - §12.7.6 4-Way Handshake / EAPOL-Key frames
  - §13.4-§13.8 Fast BSS Transition (FT) key hierarchy
  - Table 9-190 AKM suite type codes
  - Table 12-9 integrity algorithm per AKM
- [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md): current hashcat formats (modes 22000 + 37100), `keyver` trick, limitations
- [`HASHCAT-PROPOSED-CHANGES.md`](HASHCAT-PROPOSED-CHANGES.md): proposed unified hashcat module that consumes this extended format
- [`ARCHITECTURE.md`](ARCHITECTURE.md): `wpawolf` architecture decisions
- [`README.md`](README.md): using `wpawolf` in practice
