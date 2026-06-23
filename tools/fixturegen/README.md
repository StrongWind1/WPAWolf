# wpawolf-fixturegen

Standalone test-capture generator for [wpawolf](../..). Emits pcap and pcapng
files containing 802.11 management and EAPOL frames covering every code path
in the wpawolf parser, with cryptographically valid PMK / PMKID / MIC values
derived from a known PSK so the corpus doubles as a `hashcat -m 22000` /
`-m 37100` smoke test.

## Quick start

Regenerate the canonical corpus (committed under `tests/fixtures/generated/`):

```sh
cargo run --release -p wpawolf-fixturegen -- all --out tests/fixtures/generated/
```

Run the integration test that walks every fixture through wpawolf:

```sh
cargo test --release --test generated_corpus
```

Run the library unit tests (KAT vectors for PBKDF2, PRF, KDF, HMAC, AES-CMAC):

```sh
cargo test -p wpawolf-fixturegen --lib
```

Run the language-independent SHA-384 KAT oracle (pure Python stdlib, no
deps; cross-checks `crypto.rs` against `hmac` / `hashlib` / `pbkdf2_hmac`):

```sh
python3 tools/fixturegen/scripts/verify_sha384.py             # quiet
python3 tools/fixturegen/scripts/verify_sha384.py --verbose   # print vectors
python3 tools/fixturegen/scripts/verify_sha384.py --emit-vectors  # canonical
```

## CLI

```text
wpawolf-fixturegen all       --out DIR          # full corpus
wpawolf-fixturegen type N    --out DIR          # one of the 11 hash types
wpawolf-fixturegen pmkid S   --out DIR          # one of the 20 PMKID sources
wpawolf-fixturegen combo ID  --out DIR          # one N#E# combo (n1e2 ... n3e4)
wpawolf-fixturegen manifest  --out DIR          # ground-truth manifest only
```

## Verification pipeline

End-to-end corpus → wpawolf → hashcat smoke test. Run from the repo root.

```sh
# 1. Generate the corpus (idempotent; commits cleanly).
cargo run --release -p wpawolf-fixturegen -- all --out tests/fixtures/generated/

# 2. Build the wpawolf binary.
cargo build --release --bin wpawolf

# 3. Run wpawolf over the whole corpus, splitting the legacy + per-AKM sinks.
mkdir -p /tmp/wpawolf-verify
./target/release/wpawolf \
    --22000-out         /tmp/wpawolf-verify/all.22000 \
    --37100-out         /tmp/wpawolf-verify/all.37100 \
    -o                  /tmp/wpawolf-verify/all.combined \
    --wpa1-out          /tmp/wpawolf-verify/wpa1 \
    --wpa2-out          /tmp/wpawolf-verify/wpa2 \
    --psk-sha256-out    /tmp/wpawolf-verify/psksha256 \
    --psk-sha384-out    /tmp/wpawolf-verify/psksha384 \
    --ft-out            /tmp/wpawolf-verify/ft \
    --ft-psk-sha384-out /tmp/wpawolf-verify/ftsha384 \
    -E                  /tmp/wpawolf-verify/essids \
    tests/fixtures/generated

# 4. Run hashcat (install separately; this repo does not vendor it).
#    PSK is "hashcat!" (8 chars, WPA's 8-63 byte minimum).
#    Use -D 1 to force the CPU OpenCL backend if no GPU is available.
echo 'hashcat!' > /tmp/wpawolf-verify/wordlist.txt

# 4a. Mode 22000: WPA-PBKDF2-PMKID+EAPOL: WPA1 / WPA2 / PSK-SHA256 lines.
hashcat -m 22000 -D 1 \
    /tmp/wpawolf-verify/all.22000 \
    /tmp/wpawolf-verify/wordlist.txt \
    -O --runtime=120 --potfile-path=/tmp/wpawolf-verify/cracked.22000.pot

# 4b. Mode 37100: FT-PSK (802.11r): the AKM-4 (SHA-256) FT lines crack here.
#     hashcat 37100 only implements the SHA-256 FT chain, so wpawolf no
#     longer routes FT-PSK-SHA-384 lines into the legacy `WPA*04*` sink --
#     `legacy_sink_for` in `src/output/mod.rs` skips types 10/11. The
#     dedicated `--ft-psk-sha384-out` sink still receives them under the
#     `WPA*11*` per-AKM prefix for downstream tooling.
hashcat -m 37100 -D 1 \
    /tmp/wpawolf-verify/all.37100 \
    /tmp/wpawolf-verify/wordlist.txt \
    -O --runtime=120 --potfile-path=/tmp/wpawolf-verify/cracked.37100.pot
```

### What cracks

The PSK is shared across every fixture (`hashcat!`, 8 chars). Verified
end-to-end against hashcat v7.1.2 (CPU backend, `-D 1 -O`). Per hash
type, walking the canonical 75-fixture corpus:

| AKM family       | Type | Hashcat result (v7.1.2) | Why                                                                  |
| ---------------- | ---: | :---------------------: | -------------------------------------------------------------------- |
| WPA1-PSK         |    1 | cracks                  | KDV=1, HMAC-MD5 MIC; mode 22000 `m22000_aux1` kernel                 |
| WPA2-PSK         |    2 | cracks                  | HMAC-SHA-1-128 PMKID; mode 22000 `m22000_aux4` kernel                |
| WPA2-PSK         |    3 | cracks                  | KDV=2, HMAC-SHA-1-128 MIC; mode 22000 `m22000_aux2` kernel            |
| PSK-SHA-256      |    4 | **does not crack**      | Hashcat 22000 PMKID kernel computes HMAC-SHA-1 only; line carries HMAC-SHA-256-128 PMKID. Lines remain on `--psk-sha256-out` / `-o`. |
| PSK-SHA-256      |    5 | cracks                  | KDV=3, AES-128-CMAC MIC; `m22000_aux3` branches on the trailing flag byte |
| FT-PSK (SHA-256) |    6 | cracks                  | PMK-R1Name; mode 37100 `m37100_aux1` kernel                          |
| FT-PSK (SHA-256) |    7 | partial                 | M2-anchored combos (N1E2 / N3E2 / N3E4) crack; APLESS combos N2E3 / N4E3 (`*13*` / `*14*`) **do not**; hashcat 37100 hardcodes M2-only nonce ordering in `module_37100.c:702`. See `HASHCAT-CURRENT-FORMATS.md` §8.1. Documented, not fixed; lines remain on `--ft-out` / `-o`. |
| PSK-SHA-384      |    8 | n/a                     | `legacy_sink_for` skips writing to `--22000-out`; no kernel exists for HMAC-SHA-384 PMKID. Lines on `--psk-sha384-out` / `-o`. |
| PSK-SHA-384      |    9 | n/a                     | `legacy_sink_for` skips: 24 B HMAC-SHA-384-192 MIC at KDV=0; loader rejects keyver=0. Lines on `--psk-sha384-out` / `-o`. |
| FT-PSK-SHA-384   |   10 | n/a                     | `legacy_sink_for` skips: needs FT-KDF-SHA-384 chain. Lines on `--ft-psk-sha384-out` / `-o`. |
| FT-PSK-SHA-384   |   11 | n/a                     | `legacy_sink_for` skips: 24 B MIC + FT-SHA-384 chain. Lines on `--ft-psk-sha384-out` / `-o`. |

End-to-end corpus walk numbers (PSK = `hashcat!`):

| Sink              | Lines wpawolf wrote | Cracked (unique) | Uncracked (unique) | Failure cause                                      |
| ----------------- | ------------------: | ---------------: | -----------------: | -------------------------------------------------- |
| `--22000-out`     |                 108 |               73 |                  5 | Type 4 PSK-SHA-256 PMKID (kernel limitation)       |
| `--37100-out`     |                  15 |                9 |                  2 | Type 7 APLESS combos N2E3 / N4E3 (kernel limitation) |
| `-o` combined     |                 147 |        n/a: per-AKM sink, not fed to hashcat                       |

Net: of 123 lines routed into hashcat-compatible sinks, **117 cracked**
(95.1 %). The 7 that did not are all attributable to documented
hashcat-7.1.2 kernel limitations.

`n/a`: wpawolf's `legacy_sink_for` in `src/output/mod.rs` deliberately
omits these hash types from `--22000-out` / `--37100-out` because no
compatible hashcat kernel exists. The per-AKM sinks
(`--psk-sha384-out` / `--ft-psk-sha384-out`) and combined `-o` sink still
receive them.

#### N#E# combo reference

The trailing `*<mp>*` byte on every `WPA*02*` / `WPA*04*` line encodes
which two 4-way handshake messages were paired. Six combos exist:

| Combo  | Nonce source       | EAPOL source | Wire byte (low nibble) | Hashcat 22000 (type 3, KDV=2) | Hashcat 37100 (type 7, FT-PSK SHA-256) |
| ------ | ------------------ | ------------ | :--------------------: | :---------------------------: | :------------------------------------: |
| N1E2   | M1 ANonce          | M2           | `0x00`                 | cracks                        | cracks (often as `*80*` with NC)       |
| N1E4   | M1 ANonce          | M4           | `0x01`                 | cracks                        | cracks                                 |
| N3E2   | M3 ANonce          | M2           | `0x02`                 | cracks                        | cracks                                 |
| N2E3   | M2 SNonce          | M3 (APLESS)  | `0x13`                 | cracks                        | **does not crack** (kernel hardcodes M2-only layout) |
| N4E3   | M4 SNonce          | M3 (APLESS)  | `0x14`                 | cracks                        | **does not crack** (same root cause)   |
| N3E4   | M3 ANonce          | M4           | `0x05`                 | cracks                        | cracks                                 |

`hcxpcapngtool`'s legacy `M#E#` notation maps directly: `N1E2` =
`M12E2`, `N1E4` = `M14E4`, `N3E2` = `M32E2`, `N2E3` = `M32E3`, `N4E3` =
`M34E3`, `N3E4` = `M34E4`. Same six combos, different naming convention.

### Documented-uncrackable lines

The canonical 75-fixture corpus emits 147 hash lines on the combined `-o`
sink. Of those, 24 lines fall under the SHA-384 family and are not crackable
by any current hashcat kernel:

| Prefix     | Hash type                  | Lines | Source fixtures                                                                 |
| ---------- | -------------------------- | ----: | ------------------------------------------------------------------------------- |
| `WPA*08*`  | PSK-SHA-384 PMKID          |     2 | `11_types/type08_psksha384_pmkid.pcap`, `11_types/type09_psksha384_eapol.pcap`  |
| `WPA*09*`  | PSK-SHA-384 EAPOL          |    12 | same two fixtures (one M1-PMKID + four N#E# combos × two fixtures)              |
| `WPA*10*`  | FT-PSK-SHA-384 PMK-R1Name  |     2 | `11_types/type10_ftpsk_sha384_pmkid.pcap`, `11_types/type11_ftpsk_sha384_eapol.pcap` |
| `WPA*11*`  | FT-PSK-SHA-384 EAPOL       |     8 | same two fixtures (one M1-PMK-R1Name + three N#E# combos × two fixtures)        |

These lines are still emitted to the combined `-o` sink and to the dedicated
per-AKM sinks (`--psk-sha384-out` / `--ft-psk-sha384-out`) so downstream
tooling can consume them; they are deliberately suppressed from the legacy
`--22000-out` and `--37100-out` sinks because feeding them to those hashcat
modes would just waste GPU cycles. Example shape per prefix:

```text
WPA*08*<pmkid:32hex>*<ap:12hex>*<sta:12hex>*<essid:hex>***01
WPA*09*<mic:48hex>*<ap:12hex>*<sta:12hex>*<essid:hex>*<anonce:64hex>*<eapol2:hex>*<flags:02hex>
WPA*10*<pmk_r1_name:32hex>*<ap:12hex>*<sta:12hex>*<essid:hex>***01*<mdid:04hex>*<r0kh_id:hex>*<r1kh_id:12hex>
WPA*11*<mic:48hex>*<ap:12hex>*<sta:12hex>*<essid:hex>*<anonce:64hex>*<eapol2:hex>*<flags:02hex>*<mdid:04hex>*<r0kh_id:hex>*<r1kh_id:12hex>
```

Why emit them at all?

- `tests/integration/generated_corpus.rs::manifest_expected_hashes_present_per_fixture`
  asserts every prefix listed in `manifest.toml` appears in the combined-sink
  output. A regression that silently drops SHA-384 emission trips this test.
- The 24 lines flow through the same classifier and emitter paths as the
  crackable ones; verifying the fields stay well-formed protects the
  per-AKM sinks if hashcat ships SHA-384 kernels later.

### What gets verified

- **wpawolf side**: `tests/integration/generated_corpus.rs::manifest_expected_hashes_present_per_fixture`
  walks every fixture, runs wpawolf, and asserts each declared per-AKM
  prefix appears in the combined-sink output. A wpawolf-side classifier
  regression that drops a type prefix trips this test immediately.
- **Cross-variant invariant**: `link_layer_fixtures_emit_consistent_output`
  and `container_fixtures_emit_consistent_output` assert byte-identical
  hash output across the 7 link-layer headers and 14 container variants.
  Drift is a regression in `src/link/*` or `src/input/*`.
- **Cross-fixture isolation**: every fixture has its own `(AP, STA)` MAC
  pair (see `IDX_*_BASE` constants in `catalog.rs`); the only intentional
  exceptions are the link-layer / container sections (one shared pair each
  so the cross-variant invariant test compares like with like) and the
  `multi_file_a` / `multi_file_b` pair (shared so wpawolf cross-pairs the
  two files per FR-PAIR-CROSS-FILE).

## Module map

- `crypto.rs`: PMK (PBKDF2-HMAC-SHA1), PTK (PRF-SHA1 / KDF-SHA-256 /
  KDF-SHA-384), PMKID (`Truncate-128(HMAC-Hash(PMK, "PMK Name" || AA || SPA))`),
  MIC (HMAC-MD5 / HMAC-SHA1-128 / AES-128-CMAC / HMAC-SHA-384-192). All
  primitives anchored to KATs cross-checked against Python `hashlib` /
  `cryptography`.
- `frame/`: typed builders for 802.11 management frames, EAPOL-Key M1-M4,
  KDEs, RSN IE, RSNXE, MDE, FTE, vendor IEs (WPA1, OSEN, WPS).
- `linklayer.rs`: raw 802.11, radiotap (with optional FCS bit), PPI, Prism,
  AVS, and Prism-wrapping-AVS link-layer wrappers.
- `pcap_writer.rs`: pcap (10 magic variants) and pcapng (LE/BE sections)
  serialisers, plus gzip wrapping via `flate2`.
- `handshake.rs`: orchestrates a full M1-M4 sequence with valid crypto for
  one `(PSK, SSID, AP, STA, AKM)` tuple.
- `catalog.rs`: the corpus enumerator: 11 hash-type fixtures + S1-S20
  PMKID sources + 6 N#E# combos + edge cases (FCS strip, gzip, pcapng).

## Reuse, not re-invent

This crate path-deps `wpawolf` and re-exports `wpawolf::types::{AkmType,
HashType, PmkidSource, MacAddr, MacPair, MicBytes, MsgType}` so the generator
and parser share one enum surface. Wire-level constants (Key Information
bits, IE tag numbers, AKM OUIs) come from `[IEEE 802.11-2024]` and are cited
inline in every module's doc comment.

## Lint policy

The crate inherits the workspace `[lints.*]` policy from the repo root:
`unsafe_code = "forbid"`, full clippy `pedantic + nursery + cargo`, all
restriction lints (no `unwrap` / `expect` / `panic` / `dbg` / `todo`), and
`-D warnings` from `.cargo/config.toml`. Run `make check-all` before
committing; it gates fmt, clippy zero-warnings, cargo deny, all tests,
rustdoc, ASCII / LF hygiene, and unused-deps detection.
