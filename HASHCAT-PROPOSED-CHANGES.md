# Hashcat Mode 22002: WPA-PSK Universal

> **Status: implemented.** Mode 22002 is built and tested on branch [`feat/wpa-22002`](https://github.com/StrongWind1/hashcat/tree/feat/wpa-22002). All 11 WPA-PSK types crack correctly on NVIDIA CUDA, NVIDIA OpenCL, AMD ROCm/OpenCL, and PoCL CPU. Mode 22003 (PMK-direct) and PMK potfile caching are follow-up items.

A single hashcat module that consumes the 11-type classification from [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) and cracks every PSK-crackable WPA hash in one pass. Accepts ONLY the `WPA*01*..*11*` per-AKM prefixes. No legacy line acceptance, no `keyver` peek, no HCCAPX import. Modes 22000, 22001, and 37100 remain unchanged.

---

## S1  Design principles

1. **Type-driven dispatch.** The 2-digit decimal type code after `WPA*` is the SOLE routing axis. The loader reads the type, picks the aux kernel, sets the MIC width, and decides whether to expect FT extras. No `keyver` byte inspection, no AKM inference.
2. **PBKDF2 reuse across all 11 types per ESSID.** A hash file containing every PSK family runs PBKDF2 once per (ESSID, work-item). The per-type post-PMK math is less than 1% of wall time.
3. **Single-pass cracking of mixed-type files.** One `hashcat -m 22002 all.hash wordlist.txt` cracks every type. No per-type splitting or per-mode re-runs.
4. **Greenfield format.** New format only. No legacy compatibility path.
5. **No hashcat core changes.** The module stays within the existing AUX1-5 slot limit. No modifications to `types.h` or `backend.c`.

---

## S2  Module identity

| Mode  | HASH_NAME                                       | Input      | Status      |
|-------|-------------------------------------------------|------------|-------------|
| 22002 | `WPA-PBKDF2-PMKID-EAPOL (WPA-PSK Universal)`   | passphrase | implemented |
| 22003 | `WPA-PMK-Universal` (PMK-direct)                | 64-hex PMK | follow-up   |

22002 and 22003 sit adjacent to 22000/22001, advertising lineage. 22003 would share the same kernel and esalt struct, differing only in `_init` (hex-decode PMK instead of PBKDF2) and `_loop` (empty).

---

## S3  Files added

Three files, zero modifications to existing hashcat code:

| File                           | Lines | Purpose                                      |
|--------------------------------|-------|----------------------------------------------|
| `OpenCL/m22002-pure.cl`       | 1255  | Kernel: PBKDF2 init/loop + 11 type verifiers |
| `src/modules/module_22002.c`  | 726   | Module: loader, encoder, JIT, dispatch        |
| `tools/test_modules/m22002.py`| 359   | Python test module for test_edge.sh           |

---

## S4  Kernel architecture: 5-aux primitive-based packing with JIT

Five aux kernels grouped by cryptographic primitive, with JIT type-mask specialization for compile-time dead-code elimination. No hashcat core patch required (AUX1-5 are stock).

### S4.1  Aux mapping

```
aux1: type 1        WPA1-PSK-EAPOL
aux2: type 3        WPA2-PSK-EAPOL
aux3: types 5,7     PSK-SHA256-EAPOL + FT-PSK-EAPOL
aux4: types 2,4,6,8,10  all five PMKID types
aux5: types 9,11    PSK-SHA384-EAPOL + FT-PSK-SHA384-EAPOL
```

The grouping follows the dominant cryptographic primitive:

- aux1 loads only MD5 + SHA-1 (type 1 MIC is HMAC-MD5, PTK is PRF-SHA1)
- aux2 loads only SHA-1 (type 3 MIC and PTK are both SHA-1)
- aux3 loads SHA-256 + AES (types 5 and 7 use AES-128-CMAC for the MIC)
- aux4 loads SHA-1 + SHA-256 + SHA-384 (all PMKID types are a single HMAC, cheap)
- aux5 loads SHA-384 only (types 9 and 11 use SHA-384 throughout)

### S4.2  JIT type-mask specialization

`module_jit_build_options` scans the loaded hash file and emits `-DENABLE_TYPE_N` for each type present. The kernel wraps each type's verifier code in `#ifdef ENABLE_TYPE_N` blocks. Types not in the loaded hashes are compiled out entirely, producing a smaller kernel binary with lower register pressure and faster JIT compilation.

Type 2 (WPA2-PSK-PMKID) is always enabled because the self-test hash is a type 2 PMKID.

JIT compilation time with type-mask: 12-15s on both CUDA and OpenCL (vs 50-60s CUDA / 150-170s OpenCL without JIT). Zero throughput cost.

---

## S5  Esalt struct

Both the implemented 22002 and the future 22003 use the same `wpa_universal_t` esalt struct. It carries every field any of the 11 types needs; unused fields stay zero-initialized.

Notable sizing choices:

- `pmkid_data[32]`: FT PMKID types need template space for the "FT-R1N" label, PMKR0Name gap, R1KH-ID, and STA MAC
- `eapol[256 + 16]`: 1088 B to hold real FT M3 frames (observed up to 515 B in the wild)
- `pke_r0[32]` and `pke_r1[32]`: pre-built FT KDF input templates, byte-swapped once at load time so the kernel reads them directly
- `keymic[6]`: 24 B for SHA-384 EAPOL MICs (types 9, 11); 16 B for all others (first 4 words used)

---

## S6  Loader and dispatch

The loader follows the tokenizer pattern from mode 22000. It reads the 2-digit decimal type code, determines the token count (9 for non-FT, 12 for FT types), validates field widths by type, and populates the esalt.

The host-side dispatch (`module_deep_comp_kernel`) maps each type to its aux kernel:

```c
switch (wpa->type)
{
  case  1: return KERN_RUN_AUX1;   // WPA1-PSK-EAPOL
  case  2: return KERN_RUN_AUX4;   // WPA2-PSK-PMKID
  case  3: return KERN_RUN_AUX2;   // WPA2-PSK-EAPOL
  case  4: return KERN_RUN_AUX4;   // PSK-SHA256-PMKID
  case  5: return KERN_RUN_AUX3;   // PSK-SHA256-EAPOL
  case  6: return KERN_RUN_AUX4;   // FT-PSK-PMKID
  case  7: return KERN_RUN_AUX3;   // FT-PSK-EAPOL
  case  8: return KERN_RUN_AUX4;   // PSK-SHA384-PMKID
  case  9: return KERN_RUN_AUX5;   // PSK-SHA384-EAPOL
  case 10: return KERN_RUN_AUX4;   // FT-PSK-SHA384-PMKID
  case 11: return KERN_RUN_AUX5;   // FT-PSK-SHA384-EAPOL
}
```

---

## S7  Output formats

### Outfile (-o)

The full original hash line, replayed verbatim via `OPTS_TYPE_HASH_COPY`:

```
WPA*02*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***01:hashcat!
```

This matches the latest upstream 22000 behavior after PR #4908 and works correctly with `--outfile-check-dir`.

### Potfile

Currently the same as the outfile (full hash line replay). PMK potfile caching (`<PMK hex>*<ESSID hex>:<password>`) is a follow-up that requires host-emulated aux kernels for `module_potfile_custom_check`, matching what mode 22000 does.

### --show

Works via standard potfile string matching against the replayed hash line.

---

## S8  Benchmark results

### Correctness (2x RTX 4090, Quebec CA)

100 tests (50 modules x 2 backends during the bake-off). Mode 22002:

| Backend | Benchmark (kH/s) | Types pass | Mixed workload |
|---------|------------------|------------|----------------|
| CUDA    | 4560             | 11/11      | 155/155        |
| OpenCL  | 4428             | 11/11      | 155/155        |

### vs stock 22000 (apples-to-apples, identical handshakes)

| Density         | Backend | Universal | Stock 22000 | Ratio  |
|-----------------|---------|-----------|-------------|--------|
| EAPOL 1x1       | CUDA    | 1185      | 1085        | 1.09x  |
| EAPOL 1x1       | OpenCL  | 3383      | 3101        | 1.09x  |
| EAPOL 1x100     | CUDA    | 575       | 557         | 1.03x  |
| EAPOL 10x100    | OpenCL  | 1497      | 1489        | 1.00x  |

Universal beats stock 22000 by 9% at single-hash on both backends, converging to tied at density. Universal is never slower than stock on the WPA2 types stock supports.

### test_edge.sh

- AMD Radeon 780M (ROCm/OpenCL GPU): **0 errors**
- PoCL CPU: 15 errors (all `CL_INVALID_VALUE` on combinator attack, identical to stock mode 22000 on the same hardware)

---

## S9  Follow-up items

| Item                   | Scope                                                  | Status     |
|------------------------|--------------------------------------------------------|------------|
| Mode 22003 (PMK-direct)| Same kernel, trivial `_init` (hex-decode), empty `_loop`| not started|
| PMK potfile caching    | `module_hash_encode_potfile` + `module_hash_decode_potfile` + `module_potfile_custom_check` with host-emulated aux kernels for all 11 types | not started |
| `module_hash_hints`    | ESSID-based hint words for attack mode 9 (association attack) | not started |
| HCCAPX binary import   | `OPTS_TYPE_BINARY_HASHFILE` path for .hccapx files      | out of scope (operators use wpawolf or hcxpcapngtool to emit text) |

---

## S10  The 50-module bake-off

Before building mode 22002, 50 experimental modules (90001-90050) were benchmarked on AMD Radeon 780M (ROCm/HIP) and 2x NVIDIA RTX 4090 (CUDA + OpenCL) to empirically determine the best kernel architecture. The bake-off tested monolithic comp, 2/3/4/5/11-aux packings, HOOK23 host-side verification, JIT specialization, branchless superset execution, SIMD vs scalar aux, dynamic shared memory, and struct layout variants.

Key findings:

1. **PBKDF2 dominates.** All 42 GPU-only modules clustered within 0.7% CV on CUDA (4445-4599 kH/s). Aux packing strategy has no measurable benchmark impact.
2. **HOOK23 costs 91-94%.** Host-side verification is not viable for a general-purpose mode.
3. **Branchless designs collapse at density.** Running all 11 verifiers per digest and masking by type degrades 4-10x when PBKDF2 amortizes.
4. **JIT saves startup time.** Type-mask dead-code elimination produces 4x faster CUDA compilation and 12x faster OpenCL compilation with zero throughput cost.
5. **OpenCL is 2.8-3.9x faster than CUDA on sustained workloads** on the RTX 4090. Same .cl source, same driver. The NVIDIA OpenCL compiler produces substantially better sustained-throughput code than NVRTC.

The bake-off data (7 phases, 994 data points across correctness, density sweep, per-type cost, vs-stock comparison, multi-GPU scaling, and attack mode validation) is archived in `bakeoff-2x4090-results/` on the hashcat branch.

---

## S11  References

- [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md): current modes 22000 / 22001 / 37100 and their limitations
- [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md): the 11-type classification, hash-line layout, message-pair byte spec
- [`feat/wpa-22002`](https://github.com/StrongWind1/hashcat/tree/feat/wpa-22002): the implementation branch
- `hashcat/src/modules/module_22002.c`: the module (726 lines)
- `hashcat/OpenCL/m22002-pure.cl`: the kernel (1255 lines)
- `hashcat/tools/test_modules/m22002.py`: the Python test module (359 lines)
- `[IEEE 802.11-2024]` S12.6.1.3: PMKID derivation
- `[IEEE 802.11-2024]` S12.7.1.3: PTK length per AKM (24 B KCK for SHA-384)
- `[IEEE 802.11-2024]` S13.4-S13.8: Fast BSS Transition (FT) key hierarchy
