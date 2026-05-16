# Hashcat Proposed Changes: Two New WPA-PSK Modes

> **Status: design proposal, not implemented.** Nothing in this file ships in upstream hashcat today. The wpawolf side already emits the per-AKM format described in [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md); this document is the half of the story that lives outside this repository and would require a hashcat module patch to land.

A design sketch for two new hashcat modules that consume the 11-type classification from [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) in a single pass: one passphrase-input mode and one PMK-direct mode, covering every PSK family the spec defines.

This is a greenfield design. The new modules accept ONLY the new `WPA*01*..*11*` per-AKM prefixes -- no legacy line acceptance, no `keyver` peek, no HCCAPX import. The existing modes 22000, 22001, and 37100 remain in the codebase exactly as they are today and continue to read the legacy `WPA*01*..*04*` prefixes; this proposal does not touch them. Operators with existing legacy hash files convert them to the new format with the `wpawolf-convert` companion tool (§8); operators re-extracting from pcaps run `wpawolf -o` to write the new format directly.

The proposal is staged in two phases:

- **Phase 1** ships within hashcat's existing 4-aux-kernel limit per module. Per-AKM-family aux kernels with internal branching for the PMKID-vs-EAPOL and FT-vs-flat sub-cases.
- **Phase 2** extends hashcat core to 11 aux kernels per module and splits the family kernels into per-type kernels. Same module identity, same on-disk hash format, same loader -- only the kernel layout changes.

Phase 1 is shippable without any hashcat-core patch. Phase 2 unlocks the maximum-throughput design but requires extending the AUX-slot count from 4 to 11 in `include/types.h`, `src/backend.c`, and the kernel-load path.

---

## §1  Design principles

1. **One module per input semantic.** Mode 22002 takes a passphrase and runs PBKDF2; mode 22003 takes a 64-hex PMK and skips PBKDF2. The on-disk hash format and the post-PMK math are identical between them. This mirrors the relationship between today's 22000 and 22001.
2. **Type-driven dispatch.** The 2-digit prefix code after `WPA*` is the SOLE routing axis. The loader reads the type, picks the kernel, sets the MIC width, and decides whether to expect FT extras. No `keyver` byte inspection, no AKM inference, no pair-of-fields correlation.
3. **PBKDF2 reuse across all 11 types per ESSID.** A hash file containing every PSK family the operator's capture produced runs PBKDF2 *once per (ESSID, work-item)* and dispatches per-type post-PMK math from the cached PMK in `tmps[].out`. PBKDF2 is the dominant cost (4096 SHA-1 iterations); the per-type math is ~0.1% of that on mode 22002.
4. **Single-pass cracking of mixed-type files.** The natural input is a `wpawolf -o` per-AKM file containing every hash extracted from one capture. One `hashcat -m 22002 all.taxo wordlist.txt` cracks every variant. No per-type hash-file splitting, no per-mode re-runs.
5. **Greenfield format consumption.** New format only. The new modules never see a legacy line. This eliminates entire categories of loader complexity (the `keyver` peek, the AKM-from-`WPA*01*` guessing problem, the HCCAPX binary path).
6. **Two-phase implementation.** Phase 1 is a self-contained ship target requiring no hashcat-core changes. Phase 2 is an independently reviewable hashcat-core patch plus a kernel-layout refactor. Operators see no CLI or hash-format change between phases.

---

## §2  Module identity

Two new modules, parallel structure:

| Mode  | Name                        | Input                     | tmps                                    |
|-------|-----------------------------|---------------------------|-----------------------------------------|
| 22002 | `WPA-PBKDF2-Universal`      | passphrase                | `wpa_pbkdf2_tmp_t` (ipad/opad/dgst/out) |
| 22003 | `WPA-PMK-Universal`         | 64-hex PMK                | `wpa_pmk_tmp_t` (out only)              |

**Why these numbers.** 22000 (`WPA-PBKDF2-PMKID+EAPOL`) and 22001 (`WPA-PMK-PMKID+EAPOL`) are taken. 22002 and 22003 sit immediately adjacent, advertising lineage: same WPA family, expanded coverage.

**Why two modules and not one.** Mirrors the existing 22000 / 22001 pattern. The PMK-direct path is faster (skips 4096 SHA-1 iterations) and useful for known-PMK testing, rainbow-table workflows, and PMK-recovery validation. Both modules read the same hash file; only the input-side semantic differs (passphrase vs hex-encoded PMK).

**What they cover.** Every row of the 11-type classification, including the SHA-384 rows (types 8 -- 11) that have no working hashcat kernel today, and the PSK-SHA256 PMKID row (type 4) that current mode 22000 silently misroutes through the HMAC-SHA1 PMKID kernel.

**What stays separate.** Modes 22000, 22001, and 37100 are unchanged. Operators with existing legacy hash files keep using them; operators adopting the 11-type classification use 22002 / 22003.

---

## §3  Per-type kernel inventory

Eleven types -> eleven post-PMK verifier paths. PBKDF2 is shared across the whole set via `_init` + `_loop` (mode 22002) or trivial hex-decoding (mode 22003); the cached PMK lives in `tmps[gid].out`.

| #  | Type                      | Verifier path                                       | Reference implementation             |
|----|---------------------------|-----------------------------------------------------|--------------------------------------|
| 1  | WPA1-PSK-EAPOL            | PRF-SHA1 PTK + HMAC-MD5 MIC                          | lift `m22000_aux1`                   |
| 2  | WPA2-PSK-PMKID            | HMAC-SHA1 PMKID                                      | lift `m22000_aux4`                   |
| 3  | WPA2-PSK-EAPOL            | PRF-SHA1 PTK + HMAC-SHA1 MIC                         | lift `m22000_aux2`                   |
| 4  | PSK-SHA256-PMKID          | HMAC-SHA256 PMKID                                    | new (clone aux4, swap SHA-1 -> SHA-256) |
| 5  | PSK-SHA256-EAPOL          | KDF-SHA256 PTK + AES-128-CMAC MIC                    | lift `m22000_aux3`                   |
| 6  | FT-PSK-PMKID              | FT-KDF-SHA256 chain -> PMK-R1-Name                   | lift `m37100_aux1`                   |
| 7  | FT-PSK-EAPOL              | FT-KDF-SHA256 chain + AES-128-CMAC MIC               | lift `m37100_aux2`                   |
| 8  | PSK-SHA384-PMKID          | HMAC-SHA384 PMKID                                    | new (clone type 4, SHA-256 -> SHA-384) |
| 9  | PSK-SHA384-EAPOL          | KDF-SHA384 PTK (24 B KCK) + HMAC-SHA384 MIC (24 B)   | new (widest single addition)         |
| 10 | FT-PSK-SHA384-PMKID       | FT-KDF-SHA384 chain -> PMK-R1-Name                   | new (clone type 6, SHA-256 -> SHA-384) |
| 11 | FT-PSK-SHA384-EAPOL       | FT-KDF-SHA384 chain + HMAC-SHA384 MIC (24 B)         | new (compose types 9 + 10)           |

The "reference implementation" column shows what existing OpenCL code the new module's author can copy as a starting point. The lifted kernels keep their internal structure but are renamed and dropped into the new module's `.cl` file. Cross-module sharing happens via copy, not via shared headers, because each hashcat module owns its own `.cl` translation unit.

The complete cracker math for every row (PMKID derivation, PTK derivation, MIC computation, FT key hierarchy) lives in [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) §4.

---

## §4  Esalt struct -- one shape, all 11 types

Both modules use the same per-digest `wpa_universal_t` esalt struct. It carries every field any of the 11 types needs; per-type fields unused by a given row stay zero-initialised.

```c
typedef struct wpa_universal
{
  u32  essid_buf[16];   // ESSID bytes, padded
  u32  essid_len;

  u32  mac_ap[2];       // 6 B AP MAC
  u32  mac_sta[2];      // 6 B STA MAC

  u32  type;            // 1 .. 11 (type code -- the only dispatch axis)

  // PMKID specific (used iff type is even: 2, 4, 6, 8, 10).
  u32  pmkid[4];        // 16 B PMKID (always Truncate-128 of the underlying HMAC)
  u32  pmkid_data[16];  // PMKID input ("PMK Name" || AP || STA, or FT chain inputs)

  // EAPOL specific (used iff type is odd: 1, 3, 5, 7, 9, 11).
  u32  keymic[6];       // 16 B (types 1, 3, 5, 7) or 24 B (types 9, 11) MIC
  u32  anonce[8];       // 32 B external nonce (ANonce or SNonce per N#E# combo)

  u32  eapol[64 + 16];  // EAPOL frame body, MIC field zeroed
  u32  eapol_len;

  u32  pke[32];         // PTK-derivation input scratch buffer

  // FT extras (used iff type in {6, 7, 10, 11}).
  u32  mdid[1];         // 2 B Mobility Domain ID
  u32  r0khid[12];      // 1 -- 48 B R0 Key Holder ID
  u32  r0khid_len;
  u32  r1khid[12];      // 6 B R1 Key Holder ID (a MAC)
  u32  r1khid_len;

  // Diagnostic / nonce-correction fields (mirrors today's m22000 wpa_t):
  u32  message_pair;
  int  nonce_error_corrections;
  int  nonce_compare;
  int  detected_le;
  int  detected_be;

} wpa_universal_t;
```

Field-by-field rationale:

- **`type`** is the single dispatch axis. No `keyver`, no `is_ft` flag, no AKM enum -- the type code encodes all of those.
- **`keymic[6]`** holds 16 B for SHA-1 / MD5 / AES-CMAC MICs (first 4 u32s used) and 24 B for SHA-384 MICs (all 6 u32s used). Per-type kernels know which width to read; non-MIC PMKID rows ignore the field entirely. The 8-byte cost on non-SHA-384 rows is negligible.
- **`pmkid[4]`** is always 16 B. Truncate-128 applies to every PMKID primitive (HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, FT-PMK-R1-Name); the field width never changes.
- **FT extras** (`mdid`, `r0khid`, `r1khid`) match today's m37100 `wpa_t` shape and are populated only by the loader when `type` is 6, 7, 10, or 11. Non-FT kernels never read them.
- **Diagnostic fields** (`message_pair`, `nonce_error_corrections`, `nonce_compare`, `detected_le`, `detected_be`) preserve the byte-order-correction and nonce-correction machinery that today's m22000 uses inside its EAPOL kernels. This logic is independent of the AKM family and applies uniformly to every EAPOL row (1, 3, 5, 7, 9, 11).

`tmps` differ between 22002 and 22003 exactly as 22000 vs 22001 differ today: 22002 uses `wpa_pbkdf2_tmp_t` (ipad/opad/dgst/out, ~144 B); 22003 uses `wpa_pmk_tmp_t` (out[8] only, 32 B). The post-PMK aux kernels read the PMK from `tmps[gid].out[0..8]` in both cases.

---

## §5  Phase 1 -- four aux kernels, internal branching

### §5.1  The 4-aux constraint

Hashcat today hardcodes a maximum of four aux sub-kernels per module:

- `include/types.h` -- `cl_kernel opencl_kernel_aux1..aux4` (and CUDA / HIP / Metal mirrors)
- `include/types.h` enum -- `KERN_RUN_AUX1..AUX4` (constants 7001 -- 7004)
- `include/types.h` flags -- `OPTS_TYPE_AUX1..AUX4` (1<<41 -- 1<<44)
- `src/backend.c` -- four switch cases per backend dispatcher

Phase 1 fits within those four slots by grouping the 11 types into four AKM-family kernels and letting each kernel branch internally on PMKID-vs-EAPOL and (where applicable) FT-vs-flat.

### §5.2  Aux mapping

```
m22002_aux1   types 1, 2, 3        SHA-1 family + WPA1
                                   - branches: PMKID vs EAPOL,
                                               MD5-MIC (type 1) vs SHA1-MIC (type 3)
                                   - copies primitives from m22000_aux1, _aux2, _aux4

m22002_aux2   types 4, 5           PSK-SHA256 family (flat)
                                   - branches: PMKID vs EAPOL
                                   - PMKID half is NEW (type 4 -- HMAC-SHA256)
                                   - EAPOL half is m22000_aux3 (CMAC MIC) verbatim

m22002_aux3   types 6, 7           FT-PSK-SHA256 family
                                   - branches: PMKID vs EAPOL
                                   - copies m37100_aux1 (PMKID) and _aux2 (EAPOL)

m22002_aux4   types 8, 9, 10, 11   SHA-384 family (flat + FT)
                                   - branches: PMKID vs EAPOL, FT vs flat
                                   - all four sub-paths are NEW
                                   - carries the 24 B MIC width
```

The grouping splits cleanly along the dominant primitive: aux1 only loads SHA-1 and MD5; aux2 only loads SHA-256 and AES-CMAC; aux3 only loads SHA-256 (with FT chain glue); aux4 only loads SHA-384. Per-kernel register pressure stays near today's m22000 / m37100 levels because no kernel loads more SHA primitives than its corresponding legacy kernel.

22003 (PMK-direct) uses the identical aux kernel layout. The only differences are:

- `m22003_init` parses 64-hex PMK input into `tmps[].out[0..8]` (mirror of today's `m22001_init`).
- `m22003_loop` is empty -- no PBKDF2 iterations needed.

Everything from the aux kernels onward is byte-identical between 22002 and 22003.

### §5.3  Aux kernel internal structure

Each aux kernel reads `wpa->type` and dispatches to the matching sub-path. Sketch for `m22002_aux2`:

```
m22002_aux2 (per (gid, digest_pos)):
  read PMK from tmps[gid].out[0..8]
  read wpa = esalt_bufs[digest_cur]
  switch (wpa->type) {
    case 4:  // PSK-SHA256-PMKID
      pmkid_out = HMAC-SHA256(PMK, wpa->pmkid_data)[0:16]
      compare pmkid_out vs wpa->pmkid
      break
    case 5:  // PSK-SHA256-EAPOL
      PTK = KDF-SHA256(PMK, "Pairwise key expansion", wpa->pke, 384)
      KCK = PTK[0:16]
      mic_out = AES-128-CMAC(KCK, wpa->eapol)
      compare mic_out vs wpa->keymic[0..4]
      break
  }
```

The branch is a single `switch` at the top of the kernel body. Inside each case the math is identical to today's per-type kernels in m22000 and m37100 (or, for type 4, a copy of m22000_aux4 with HMAC-SHA1 swapped for HMAC-SHA256).

### §5.4  Branch divergence cost

Inside one wavefront, GPU lanes that take different `switch` arms run serialised. Realistic mix:

- Operator runs `wpawolf -o all.taxo` and feeds it to `hashcat -m 22002`.
- `all.taxo` carries one `WPA*<type>*` line per detected handshake; one capture often has many (PMKID + 3 EAPOL pair combos per session).
- Within a single salt (ESSID), every type the capture produced shares the same PBKDF2 output; the host buckets digests by salt before launching aux kernels.
- The host launches `m22002_aux2` once per (salt, work-item-batch) with all type-4 + type-5 digests for that salt visible. A wavefront iterating digest_pos sees mixed type 4 / type 5 lanes -> ~2x divergence cost on the post-PMK math (cheap relative to PBKDF2 on mode 22002, but visible on mode 22003).

For aux4 (4 sub-paths -> up to 4-way divergence on SHA-384 mixed captures), the cost is more significant. Phase 2 removes this divergence entirely.

### §5.5  Loader and dispatch

The 22002 loader follows the same `input_tokenizer` pattern as today's m22000:

```c
// Pseudo-code -- not a literal hashcat loader.
int module_hash_decode (...)
{
  // Token 0: "WPA" signature, fixed length 3.
  // Token 1: 2-hex type code (1 -- 11).
  // Tokens 2 -- 8: hash, mac_ap, mac_sta, essid, nonce, eapol, mp.
  // Tokens 9 -- 11 (FT only): mdid, r0khid, r1khid.

  // Peek the type to determine token count.
  const u8 type = peek_type_after_prefix (line_buf);
  if (type < 1 || type > 11) return (PARSER_SALT_VALUE);

  hc_token_t token;
  token.token_cnt = (type == 6 || type == 7 || type == 10 || type == 11) ? 12 : 9;
  // ... call input_tokenizer with that count ...

  wpa->type = type;

  // Type-driven hash-field width.
  if (type % 2 == 1) {
    // Odd = EAPOL. MIC field: 32 hex (16 B) for types 1, 3, 5, 7;
    //                          48 hex (24 B) for types 9, 11.
    const int mic_hex = (type == 9 || type == 11) ? 48 : 32;
    if (token.len[2] != mic_hex) return (PARSER_SALT_VALUE);
    // ... copy MIC into wpa->keymic[0 .. mic_hex / 2] ...
  } else {
    // Even = PMKID. Always 32 hex (16 B).
    if (token.len[2] != 32) return (PARSER_SALT_VALUE);
    // ... copy PMKID into wpa->pmkid[0..4] ...
  }

  // mac_ap, mac_sta, essid, nonce, eapol, mp: same shape as m22000.
  // FT extras (mdid, r0khid, r1khid): only when type_cnt == 12.
  return PARSER_OK;
}
```

The host-side aux selection (mirror of `module_22000.c:542 -- 570`) reads `wpa->type` and picks the right `KERN_RUN_AUX*`:

```c
u32 module_kern_type_per_digest (const wpa_universal_t *wpa)
{
  switch (wpa->type) {
    case 1: case 2: case 3:                return KERN_RUN_AUX1;
    case 4: case 5:                        return KERN_RUN_AUX2;
    case 6: case 7:                        return KERN_RUN_AUX3;
    case 8: case 9: case 10: case 11:      return KERN_RUN_AUX4;
  }
  return 0;
}
```

The OPTS_TYPE bits stay as in m22000: `OPTS_TYPE_AUX1 | OPTS_TYPE_AUX2
| OPTS_TYPE_AUX3 | OPTS_TYPE_AUX4`.

Things the loader does NOT do (and that today's m22000 / m37100 must do):

- No `keyver` peek into the embedded EAPOL frame.
- No HCCAPX binary import path.
- No legacy `WPA*01*..*04*` line acceptance.
- No AKM inference from `(AP MAC, ESSID)` history.

These removals collapse the loader to a single straight-line parser keyed on the type code.

---

## §6  Phase 2 -- eleven aux kernels, zero internal branching

### §6.1  What changes vs Phase 1

Same module identity (22002 / 22003), same loader, same on-disk hash format, same `wpa_universal_t` esalt struct. The on-wire and host-API surface is byte-identical to Phase 1. **The only thing that changes is the kernel layout**: each of the four Phase 1 aux kernels splits into its constituent per-type kernels.

```
Phase 1                          Phase 2
m22002_aux1 (types 1, 2, 3)  ->  m22002_aux1   type 1   WPA1-PSK-EAPOL
                                 m22002_aux2   type 2   WPA2-PSK-PMKID
                                 m22002_aux3   type 3   WPA2-PSK-EAPOL
m22002_aux2 (types 4, 5)     ->  m22002_aux4   type 4   PSK-SHA256-PMKID
                                 m22002_aux5   type 5   PSK-SHA256-EAPOL
m22002_aux3 (types 6, 7)     ->  m22002_aux6   type 6   FT-PSK-PMKID
                                 m22002_aux7   type 7   FT-PSK-EAPOL
m22002_aux4 (types 8 .. 11)  ->  m22002_aux8   type 8   PSK-SHA384-PMKID
                                 m22002_aux9   type 9   PSK-SHA384-EAPOL
                                 m22002_aux10  type 10  FT-PSK-SHA384-PMKID
                                 m22002_aux11  type 11  FT-PSK-SHA384-EAPOL
```

Each per-type kernel is a single straight-line verifier with no internal `switch` on the type code. The host dispatcher becomes a flat 11-arm map:

```c
u32 module_kern_type_per_digest (const wpa_universal_t *wpa)
{
  switch (wpa->type) {
    case  1: return KERN_RUN_AUX1;
    case  2: return KERN_RUN_AUX2;
    case  3: return KERN_RUN_AUX3;
    case  4: return KERN_RUN_AUX4;
    case  5: return KERN_RUN_AUX5;
    case  6: return KERN_RUN_AUX6;
    case  7: return KERN_RUN_AUX7;
    case  8: return KERN_RUN_AUX8;
    case  9: return KERN_RUN_AUX9;
    case 10: return KERN_RUN_AUX10;
    case 11: return KERN_RUN_AUX11;
  }
  return 0;
}
```

### §6.2  Hashcat-core changes required

The 4-aux limit lives in five places. Each is a mechanical extension:

| File                                              | Change                                                                                                   |
|---------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| `include/types.h` (kernel-handle struct)          | Add `cl_kernel opencl_kernel_aux5..aux11` (and CUDA `CUfunction`, HIP `hipFunction_t`, Metal `mtl_function` / `mtl_pipeline` mirrors). 7 new fields x 4 backends = ~28 new struct members. |
| `include/types.h` (KERN_RUN enum)                 | Extend `KERN_RUN_AUX1..AUX4` to `..AUX11` (constants 7005 -- 7011).                                      |
| `include/types.h` (OPTS_TYPE flags)               | Extend `OPTS_TYPE_AUX1..AUX4` (bits 41 -- 44) to `..AUX11` (bits 45 -- 51). Fits in u64.                 |
| `include/types.h` (per-kernel tracking)           | Mirror `kernel_wgs_aux1`, `kernel_local_mem_size_aux1`, `kernel_dynamic_local_mem_size_aux1`, `kernel_preferred_wgs_multiple_aux1`, `exec_us_prev_aux1[]` for aux5..aux11. ~25 new fields. |
| `src/backend.c` (dispatcher switch tables)        | Extend the per-backend `metal_pipeline_with_id` / `opencl_kernel_with_id` / `hip_function_with_id` / `cuda_function_with_id` switches (and their `run_kernel` analogues) with 7 new cases each. ~28 new cases x 2 dispatch sites = ~56 new lines. |
| Kernel-load path (`backend.c` symbol resolution)  | Resolve `m<MODE>_aux5..aux11` symbols at load time. ~7 new lines per backend.                            |

Total estimate: ~200 -- 400 lines of mechanical changes across ~6 files. No architectural questions; every aux1 site has an obvious aux5..aux11 parallel. The change is upstream-compatible -- existing modules that declare only `OPTS_TYPE_AUX1..AUX4` see no behaviour change.

This patch must land in hashcat core before the Phase 2 kernel layout for 22002 / 22003 can be compiled and loaded.

### §6.3  Performance comparison: Phase 1 vs Phase 2

The win comes from removing branch divergence inside the aux kernels and shrinking per-kernel register footprint. PBKDF2 is unchanged across phases (same `_init` / `_loop`); the per-type math is what speeds up.

| Aux kernel  | Types in Phase 1 | Phase 1 internal switch          | Wavefront occupancy gain (Phase 2) | Throughput gain per aux (Phase 2) |
|-------------|------------------|----------------------------------|------------------------------------|------------------------------------|
| aux1        | 1, 2, 3          | 3-way: PMKID/EAPOL + MD5/SHA1 MIC | small (~10 -- 15%)                | 1.05 -- 1.15x                      |
| aux2        | 4, 5             | 2-way: PMKID/EAPOL                | moderate (~20 -- 25%)             | 1.20 -- 1.40x                      |
| aux3        | 6, 7             | 2-way: PMKID/EAPOL                | moderate (~20 -- 25%)             | 1.20 -- 1.40x                      |
| aux4        | 8 .. 11          | 4-way: PMKID/EAPOL + FT/flat      | high (~30 -- 50%)                 | 1.50 -- 2.00x                      |

Net hash-rate change for the whole run depends on the type mix in the hash file. The post-PMK math is ~0.1 -- 1% of total wall time on mode 22002 (PBKDF2 dominates); on mode 22003 (PMK-direct) the per-type math is closer to ~30 -- 80% of wall time, so the speedup is far more visible.

| Workload                                   | 22002 (passphrase) | 22003 (PMK-direct) |
|--------------------------------------------|--------------------|--------------------|
| Pure WPA2-PSK (only types 2, 3)            | ~1.00x (no change) | ~1.05 -- 1.10x     |
| Mixed AKM 2 + AKM 6 (types 2, 3, 4, 5)     | ~1.01 -- 1.02x     | ~1.20 -- 1.30x     |
| Heavy SHA-384 (types 8 -- 11)              | ~1.02 -- 1.05x     | ~1.50 -- 2.00x     |
| Realistic per-AKM format `-o` file (mixed)       | ~1.01 -- 1.03x     | ~1.20 -- 1.40x     |

Phase 2 also reduces register pressure per kernel (each kernel only loads the SHA primitives it needs), which can lift overall device occupancy by 10 -- 20% on register-constrained GPUs (older Polaris, Pascal). This effect compounds with the divergence reduction.

The exact numbers are estimates pending micro-benchmarks against a prototype. The directional ordering (Phase 2 always >= Phase 1) is guaranteed by the kernel design; the magnitude depends on GPU architecture and hash-file composition.

### §6.4  When to choose Phase 2 over Phase 1

- **Phase 1** is the right shipping target for the first release of 22002 / 22003. It delivers all 11 types under one mode without requiring any hashcat-core patch. The perf cost on mode 22002 (where PBKDF2 dominates) is negligible.
- **Phase 2** is the right target once a hashcat-core PR adding the aux5 -- aux11 slots lands. It unlocks the maximum-throughput design, particularly on PMK-direct mode 22003 and on SHA-384-heavy workloads.

The migration from Phase 1 to Phase 2 is invisible to operators: same mode number, same hash format, same CLI. Only the kernel binaries on disk change.

---

## §7  Test vectors

A test fixture covers all eleven types. For each:

```
hashcat -m 22002 fixtures/typeNN.taxo wordlist.txt
hashcat -m 22003 fixtures/typeNN.taxo pmk_list.txt
# expected: cracks the fixture password / matches the fixture PMK
```

Sources for fixture material:

- Types 1, 2, 3, 5, 6, 7: synthesise from the `[IEEE 802.11-2024]` spec test vectors, or extract from authorized lab captures via `wpawolf -o`. The lifted reference kernels (m22000_aux1..4 and m37100_aux1..2) already have known-good test corpora that can be re-emitted in the new prefix scheme.
- Type 4: extract PSK-SHA256 PMKID from a captured AKM-6 handshake via `wpawolf --psk-sha256-out`. The `[IEEE 802.11-2024]` annex has AKM-6 PMKID test vectors usable as a known-answer.
- Types 8, 9: AKM-20 (PSK-SHA384) is rare in the wild; synthesise with a vendor radio that supports it (Aruba IAP, Cisco IOS-XE) or craft fixtures using the spec's test vectors.
- Types 10, 11: AKM-19 (FT-PSK-SHA384) likewise rare; same synthesis approach as 8 / 9 with the FT key hierarchy added.

Each fixture exercises both 22002 (passphrase) and 22003 (PMK input). On Phase 2, each per-type kernel can be benchmarked in isolation by feeding a single-type fixture file -- a useful regression oracle for kernel-perf work.

---

## §8  Implementation roadmap

The build sequence below ships incremental usable subsets. Each step is independently reviewable.

| Step | What lands                                                                                                             |
|------|------------------------------------------------------------------------------------------------------------------------|
| 1    | Modes 22002 and 22003 ship with **Phase 1** kernel layout. Six types (1, 2, 3, 5, 6, 7) work immediately via lifted m22000 / m37100 kernels. Aux2 / aux3 / aux4 carry stub branches for types 4 / 8 / 9 / 10 / 11 that return "not yet implemented." |
| 2    | Type 4 (PSK-SHA256-PMKID) lands in aux2. Smallest new kernel; one HMAC primitive swap on top of the type-2 PMKID shape. |
| 3    | Types 8 and 9 (PSK-SHA384 family) land in aux4. Both need SHA-384 primitives; type 9 brings the 24 B MIC width.        |
| 4    | Types 10 and 11 (FT-PSK-SHA384 family) land in aux4. Compose the SHA-384 primitives from step 3 with the FT chain code already lifted from m37100. |
| 5    | All 11 types covered under Phase 1. Mode 22002 is the operator's one-stop PSK module.                                  |
| 6    | (Independent of steps 1 -- 5.) Hashcat-core PR adds aux5 -- aux11 slots per §6.2.                                       |
| 7    | After step 6 lands, modes 22002 and 22003 switch to **Phase 2** kernel layout in the same release. Operators see no CLI or hash-format change; benchmark numbers improve on PMK-direct and SHA-384 workloads. |

### `wpawolf-convert`: legacy file migration

For operators with existing legacy hash files (extracted by `hcxpcapngtool` or by older `wpawolf` builds writing only `--22000-out` / `--37100-out`), a small companion utility `wpawolf-convert` reads `WPA*01*..*04*` lines and emits `WPA*01*..*11*` lines in the new per-AKM format. It does no pcap parsing; it works on already-extracted hash files.

Conversion notes (the tool documents these in its own help text; listed here for context):

- `WPA*01*` (legacy PMKID) -> type 2 (WPA2-PSK-PMKID). The legacy hashcat 22000 PMKID kernel runs HMAC-SHA1 unconditionally, so any PMKID line that ever cracked under mode 22000 must be a type-2 hash. Lines representing type 4 / 8 PMKIDs that the legacy kernel silently mis-cracked cannot be recovered without the original pcap -- re-extract via `wpawolf --psk-sha256-out` or `--psk-sha384-out`.
- `WPA*02*` keyver=1 -> type 1 (WPA1-PSK-EAPOL).
- `WPA*02*` keyver=2 -> type 3 (WPA2-PSK-EAPOL).
- `WPA*02*` keyver=3 -> type 5 (PSK-SHA256-EAPOL) by default, with a one-line stderr warning that this row is ambiguous between type 5 and type 7 (FT-PSK-EAPOL) in the legacy format. Operators with FT-PSK captures should re-extract via `wpawolf -o` from the original pcap, where the FT IE context resolves the ambiguity.
- `WPA*03*` -> type 6 (FT-PSK-PMKID).
- `WPA*04*` -> type 7 (FT-PSK-EAPOL).

The new modules never read a legacy line directly; `wpawolf-convert` is the migration boundary. After conversion, the new modules consume the resulting file natively.

The recommended workflow for new captures is `wpawolf -o all.taxo capture.pcap` followed by `hashcat -m 22002 all.taxo wordlist.txt` -- no conversion step needed, no legacy file ever produced.

---

## §9  Why two new modes instead of extending 22000 / 22001 / 37100

A reasonable counter-proposal: leave the new format and the new aux layout, but graft them onto the three existing modes (22000 reads new non-FT prefixes, 37100 reads new FT prefixes). Three arguments against:

1. **Operator clarity.** Two modes with crisp scopes (`-m 22002` for passphrase, `-m 22003` for PMK-direct) is simpler to choose between than three modes with overlapping scopes ("does this hash file have FT lines?"). The user picks the input semantic; the hash file's own type codes do everything else.
2. **Single-pass cracking requires kernel sharing inside one module.** PBKDF2 reuse across all 11 types only works when the per-type aux kernels read from the same `tmps[]`. Patching 22000 to also accept FT lines doesn't help, because 37100 still owns the FT-PSK code path -- the operator would still split their hash file or run twice. One module is the only structure where all 11 types share one PBKDF2 invocation.
3. **Phase 2 contained to two new modules.** The 11-aux-kernel layout and the hashcat-core slot extension touch one module-set instead of three. Smaller surface, easier to review, no risk of a Phase 2 regression in the legacy modes that the operator depended on.

A fourth, softer point: operators who depend on the existing modes keep them unchanged. Nothing about modes 22000 / 22001 / 37100 changes under this proposal. Adopting 22002 / 22003 is opt-in.

---

## §10  Out of scope

These are deliberately not part of the proposal:

- **Inner-EAP cracking.** EAP-MD5, LEAP, MSCHAPv2, etc. live in their own hashcat modes; they have nothing to do with the WPA PSK per-AKM format. `wpawolf` extracts EAP identities (`-I`) and inner usernames (`-U`); cracking them belongs to other modules.
- **SAE / OWE.** WPA3-SAE and OWE use Dragonfly key exchange, not PBKDF2-PSK; they need a fundamentally different cracker (and hashcat does support some SAE variants today via mode 22301). `wpawolf` parses and counts SAE / OWE management frames but does not emit a hash line for them.
- **Quantum-resistant successors.** Any future PSK family that is not PBKDF2-derived needs a new module entirely. The 11-type classification structurally accommodates new codes (type 12 and beyond could append) but the post-PMK arithmetic would be unrelated.
- **WEP, hccap, hccapx.** Legacy hashcat formats (modes 2500, etc.) remain available; the new modules do not absorb them.
- **Concrete OpenCL kernel code.** This document sketches the design. The actual `m22002-pure.cl` and `m22003-pure.cl` files are written by referring to the existing `m22000-pure.cl`, `m22001-pure.cl`, and `m37100-pure.cl` for reusable pieces and composing them per the kernel inventory in §3.
- **Changes to legacy modes 22000 / 22001 / 37100.** Out of scope. They keep working as today.

---

## §11  References

- [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md) -- the current modes 22000 / 22001 / 37100, their limitations, and what each kernel does today
- [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) -- the 11-type classification itself, hash-line layout, message-pair byte spec
- `hashcat/src/modules/module_22000.c` -- structural reference for the proposed 22002 module's loader and dispatch
- `hashcat/src/modules/module_22001.c` -- structural reference for the proposed 22003 PMK-direct module
- `hashcat/src/modules/module_37100.c` -- reference for FT chain parsing
- `hashcat/OpenCL/m22000-pure.cl` -- existing aux1 / aux2 / aux3 / aux4 to be lifted into Phase 1 aux1 / aux2
- `hashcat/OpenCL/m22001-pure.cl` -- existing PMK-direct init / aux pattern to be lifted into 22003
- `hashcat/OpenCL/m37100-pure.cl` -- existing aux1 / aux2 to be lifted into Phase 1 aux3
- `hashcat/include/types.h` -- where the AUX-slot extension lands (`opencl_kernel_aux*`, `KERN_RUN_AUX*`, `OPTS_TYPE_AUX*`)
- `hashcat/src/backend.c` -- where the per-backend dispatcher switch tables extend
- `[IEEE 802.11-2024]` §12.6.1.3 -- PMKID derivation
- `[IEEE 802.11-2024]` §12.7.1.3 -- PTK length per AKM (24 B KCK for SHA-384)
- `[IEEE 802.11-2024]` §13.4 -- §13.8 -- FT key hierarchy
- [`README.md`](README.md) -- how `wpawolf` produces lines for the new modules to consume natively (the `-o` per-AKM file)
- [`ARCHITECTURE.md`](ARCHITECTURE.md) -- `wpawolf` design decisions
