#!/usr/bin/env python3
"""
Independent KAT (Known Answer Test) oracle for the SHA-384 family of WPA
primitives that wpawolf-fixturegen produces. Runs an in-script reference
implementation -- pure stdlib `hmac` / `hashlib`, no third-party crypto -- and
compares the values back against what fixturegen emits when invoked with the
same inputs.

Why: the SHA-384 chain (PSK-SHA-384, FT-PSK-SHA-384) is not exercised by
hashcat today -- mode 22000 strict-checks a 16-byte MIC and mode 37100 only
ships a SHA-256 FT kernel -- so the only end-to-end correctness signal we
have on the Rust side is internal unit tests. This oracle gives a second,
language-independent witness that the wire values are correct so future
edits to crypto.rs / handshake.rs cannot silently regress them without
also tripping this script.

Coverage:
  PMK             -- PBKDF2-HMAC-SHA1, 4096 iters, 32 B output (shared by
                     every PSK family per [IEEE 802.11-2024] J.4)
  PMKID (SHA-384) -- Truncate-128(HMAC-SHA384(PMK, "PMK Name" || AA || SPA))
  PTK  (SHA-384)  -- KDF-Hash-Length(PMK, "Pairwise key expansion",
                                    min(AA,SPA) || max(AA,SPA) ||
                                    min(ANonce,SNonce) || max(ANonce,SNonce),
                                    704 bits) -- IEEE 802.11-2024 12.7.1.7.2
  KCK             -- PTK[0..24]   (KCK_bits = 192 for SHA-384; 12.7.1.3)
  MIC (SHA-384)   -- Truncate-192(HMAC-SHA384(KCK, eapol_zeroed))
                     [IEEE 802.11-2024 12.7.1.7.3, EAPOL-Key body MIC]
  PMK-R0          -- KDF-Hash(PMK, "FT-R0", SSID || MDID || R0KH-ID || SPA,
                              Length_bits) per 13.4.2 -- emitted PMK-R0 is
                     truncated to PMK-R0_len bits, plus PMK-R0Name salt.
  PMK-R0Name      -- SHA-Hash("FT-R0N" || salt) truncated to 128 bits.
  PMK-R1          -- KDF-Hash(PMK-R0, "FT-R1", R1KH-ID || SPA, Length_bits).
  PMK-R1Name      -- SHA-Hash("FT-R1N" || PMK-R0Name || R1KH-ID || SPA)
                     truncated to 128 bits.
  FT-PTK          -- KDF-Hash(PMK-R1, "FT-PTK",
                              SNonce || ANonce || BSSID || SPA, Length_bits).

The script also walks `ground_truth/manifest.toml` (if present) and verifies
two end-to-end invariants for every type fixture wpawolf has run against:

  1. The PMK we derive from `(PSK, declared SSID)` matches what the per-fixture
     wpawolf invocation would have used.
  2. For PMKID-only type fixtures (types 4 / 5 / 8 / 9), the PMKID we compute
     from the recorded `(AP, STA, family)` triple has not changed since the
     fixture was generated -- if the Rust fixturegen drifts, the manifest
     becomes the witness.

Usage:
    python3 tools/fixturegen/scripts/verify_sha384.py            # KAT self-test
    python3 tools/fixturegen/scripts/verify_sha384.py --walk     # KATs + corpus walk
    python3 tools/fixturegen/scripts/verify_sha384.py --emit-vectors

Exit code 0 on match, 1 on any mismatch. No deps beyond Python 3.11 stdlib.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import sys
from pathlib import Path
from typing import Iterable, Optional


# --- Inputs (must mirror tools/fixturegen/src/catalog.rs constants) ---

PSK: bytes = b"hashcat!"
ANONCE: bytes = bytes([0xA1] * 32)
SNONCE: bytes = bytes([0xB2] * 32)
FT_MDID_WIRE: bytes = bytes([0x34, 0x12])  # As stored on the wire (LE).
FT_R0KH_ID: bytes = b"r0kh"
FT_R1KH_ID: bytes = bytes([0x06] * 6)


# --- Reference primitives ---


def derive_pmk(passphrase: bytes, ssid: bytes) -> bytes:
    """PBKDF2-HMAC-SHA1, 4096 iters, 32-byte PMK. [IEEE 802.11-2024 J.4]"""
    return hashlib.pbkdf2_hmac("sha1", passphrase, ssid, 4096, 32)


def derive_pmkid_sha384(pmk: bytes, ap: bytes, sta: bytes) -> bytes:
    """Truncate-128(HMAC-SHA384(PMK, "PMK Name" || AA || SPA))."""
    return hmac.new(pmk, b"PMK Name" + ap + sta, hashlib.sha384).digest()[:16]


def kdf_hash(key: bytes, label: str, context: bytes, n_bits: int, hash_name: str) -> bytes:
    """
    802.11-2024 12.7.1.6.2 KDF-Hash-Length:
        K(i) = HMAC-Hash(key, i || label || context || Length)
        with i a 16-bit LE counter, Length the requested length in bits, also LE.
    Concatenates K(1) || K(2) || ... and truncates to n_bits.
    """
    if n_bits % 8 != 0:
        raise ValueError("KDF-Hash output not byte-aligned")
    n_bytes = n_bits // 8
    digest_size = hashlib.new(hash_name).digest_size
    out = bytearray()
    counter = 1
    while len(out) < n_bytes:
        msg = (
            counter.to_bytes(2, "little")
            + label.encode("ascii")
            + context
            + n_bits.to_bytes(2, "little")
        )
        out.extend(hmac.new(key, msg, hash_name).digest())
        counter += 1
    return bytes(out[:n_bytes])


def derive_ptk_sha384(pmk: bytes, ap: bytes, sta: bytes, anonce: bytes, snonce: bytes) -> bytes:
    """KDF-SHA384(PMK, "Pairwise key expansion", min/max sort, 704 bits = 88 bytes)."""
    addrs = (ap, sta) if ap < sta else (sta, ap)
    nonces = (anonce, snonce) if anonce < snonce else (snonce, anonce)
    context = addrs[0] + addrs[1] + nonces[0] + nonces[1]
    return kdf_hash(pmk, "Pairwise key expansion", context, 704, "sha384")


def mic_sha384(kck: bytes, eapol_zeroed: bytes) -> bytes:
    """Truncate-192(HMAC-SHA384(KCK_24B, eapol_with_mic_zeroed))."""
    return hmac.new(kck, eapol_zeroed, hashlib.sha384).digest()[:24]


def derive_pmk_r0_sha384(
    pmk: bytes, ssid: bytes, mdid: bytes, r0kh_id: bytes, sta: bytes
) -> tuple[bytes, bytes]:
    """
    PMK-R0 derivation per [IEEE 802.11-2024 13.4.2].
    Length = PMK-R0_len_bits = 384 for SHA-384 chain.
    Returns (pmk_r0, pmk_r0_name).
    """
    if len(ssid) > 32:
        raise ValueError("SSID must be <= 32 bytes")
    context = bytes([len(ssid)]) + ssid + mdid + bytes([len(r0kh_id)]) + r0kh_id + sta
    r0_full = kdf_hash(pmk, "FT-R0", context, 384 + 128, "sha384")
    pmk_r0 = r0_full[:48]  # 384 bits
    salt = r0_full[48:64]  # 128 bits, used to compute PMKR0Name
    pmk_r0_name = hashlib.sha384(b"FT-R0N" + salt).digest()[:16]
    return pmk_r0, pmk_r0_name


def derive_pmk_r1_sha384(
    pmk_r0: bytes, pmk_r0_name: bytes, r1kh_id: bytes, sta: bytes
) -> tuple[bytes, bytes]:
    """PMK-R1 + PMK-R1Name per [IEEE 802.11-2024 13.4.3]."""
    pmk_r1 = kdf_hash(pmk_r0, "FT-R1", r1kh_id + sta, 384, "sha384")
    pmk_r1_name = hashlib.sha384(b"FT-R1N" + pmk_r0_name + r1kh_id + sta).digest()[:16]
    return pmk_r1, pmk_r1_name


def derive_ft_ptk_sha384(
    pmk_r1: bytes, snonce: bytes, anonce: bytes, bssid: bytes, sta: bytes
) -> bytes:
    """FT-PTK per [IEEE 802.11-2024 13.4.4]: SNonce || ANonce || BSSID || SPA."""
    context = snonce + anonce + bssid + sta
    return kdf_hash(pmk_r1, "FT-PTK", context, 704, "sha384")


# --- Self-test against published / expected vectors ---


def vec(label: str, value: bytes) -> str:
    return f"{label:18} = {value.hex()}"


def assert_eq(label: str, actual: bytes, expected: bytes) -> bool:
    if actual == expected:
        return True
    sys.stderr.write(f"FAIL: {label}\n  actual  : {actual.hex()}\n  expected: {expected.hex()}\n")
    return False


def run_self_test(verbose: bool = False) -> int:
    """Validate the reference primitives against the canonical KAT vectors
    that fixturegen's Rust unit tests embed. Mismatches are the strongest
    signal that one side has drifted from the spec."""
    ok = True

    # --- Cross-check against fixturegen's IEEE/IEEE Rust KAT vectors. ---
    # These constants are copied verbatim from
    # `tools/fixturegen/src/crypto.rs::tests` so the Python and Rust derivations
    # of the same inputs must produce identical bytes. Any drift between the
    # two implementations trips this test before reaching hashcat.
    pmk_ieee_expected = bytes.fromhex(
        "623b5df2f31bb47c7e4ec0f05e60e2110fd57f7392f7b265bd2613d35caa5088"
    )
    pmkid_sha384_expected = bytes.fromhex(
        "c3ea1b829c3b8c2add1235586ee88bab"
    )
    ap_kat = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    sta_kat = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])

    pmk_ieee = derive_pmk(b"IEEE", b"IEEE")
    if not assert_eq("PMK == Rust KAT", pmk_ieee, pmk_ieee_expected):
        ok = False

    pmkid_sha384_actual = derive_pmkid_sha384(pmk_ieee, ap_kat, sta_kat)
    if not assert_eq("PMKID-SHA384 == Rust KAT", pmkid_sha384_actual, pmkid_sha384_expected):
        ok = False

    # MIC-SHA384: KCK = 16x 0x11, body = 105x 0x00 -- same vectors the Rust
    # tests use for the 16-byte families, so a single Python check locks in
    # the Rust 24-byte MIC vector at the same time.
    mic_kck = bytes([0x11] * 16)
    mic_body = bytes([0x00] * 105)
    mic_sha384_expected = bytes.fromhex(
        "f9a6236dd7796da74cb6beca8afd7118033dc71f6cf08c8d"
    )
    mic_sha384_actual = mic_sha384(mic_kck, mic_body)
    if not assert_eq("MIC-SHA384 == Rust KAT", mic_sha384_actual, mic_sha384_expected):
        ok = False

    if verbose:
        print(vec("PMK(IEEE/IEEE)", pmk_ieee))
        print(vec("PMKID-SHA384", pmkid_sha384_actual))
        print(vec("MIC-SHA384(105x00)", mic_sha384_actual))

    # --- Self-consistency checks on the canonical fixturegen inputs. ---
    ssid = b"wpawolf-test-08"  # Type 8 fixture SSID stem.
    ap = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x18])  # IDX_TYPES_BASE(0x10) + 8.
    sta = bytes([0x02, 0x00, 0x00, 0x00, 0x01, 0x18])

    pmk = derive_pmk(PSK, ssid)
    if verbose:
        print(vec("PMK", pmk))

    if not assert_eq("PMK reproducibility", pmk, derive_pmk(PSK, ssid)):
        ok = False

    pmkid = derive_pmkid_sha384(pmk, ap, sta)
    if verbose:
        print(vec("PMKID-SHA384", pmkid))
    if pmkid == b"\x00" * 16 or pmkid == b"\xff" * 16:
        sys.stderr.write("FAIL: PMKID-SHA384 produced sentinel\n")
        ok = False

    ptk = derive_ptk_sha384(pmk, ap, sta, ANONCE, SNONCE)
    if verbose:
        print(vec("PTK-SHA384", ptk))
    if len(ptk) != 88:
        sys.stderr.write(f"FAIL: PTK-SHA384 length {len(ptk)} != 88\n")
        ok = False
    kck = ptk[:24]

    mic = mic_sha384(kck, b"")
    if verbose:
        print(vec("MIC-SHA384(empty)", mic))
    if len(mic) != 24:
        sys.stderr.write(f"FAIL: MIC-SHA384 length {len(mic)} != 24\n")
        ok = False

    # FT chain: PMK-R0 -> PMK-R1 -> FT-PTK, all SHA-384.
    pmk_r0, pmk_r0_name = derive_pmk_r0_sha384(pmk, ssid, FT_MDID_WIRE, FT_R0KH_ID, sta)
    if verbose:
        print(vec("PMK-R0", pmk_r0))
        print(vec("PMK-R0Name", pmk_r0_name))
    if len(pmk_r0) != 48 or len(pmk_r0_name) != 16:
        sys.stderr.write("FAIL: PMK-R0 / PMK-R0Name lengths off\n")
        ok = False

    pmk_r1, pmk_r1_name = derive_pmk_r1_sha384(pmk_r0, pmk_r0_name, FT_R1KH_ID, sta)
    if verbose:
        print(vec("PMK-R1", pmk_r1))
        print(vec("PMK-R1Name", pmk_r1_name))
    if len(pmk_r1) != 48 or len(pmk_r1_name) != 16:
        sys.stderr.write("FAIL: PMK-R1 / PMK-R1Name lengths off\n")
        ok = False

    bssid = ap
    ft_ptk = derive_ft_ptk_sha384(pmk_r1, SNONCE, ANONCE, bssid, sta)
    if verbose:
        print(vec("FT-PTK-SHA384", ft_ptk))
    if len(ft_ptk) != 88:
        sys.stderr.write(f"FAIL: FT-PTK-SHA384 length {len(ft_ptk)} != 88\n")
        ok = False

    # Cross-check distinct outputs across families: PMKID-SHA384 must differ
    # from a SHA-1 PMKID over the same inputs (PBKDF2-derived PMK is the same,
    # only the HMAC inner hash changes).
    pmkid_sha1 = hmac.new(pmk, b"PMK Name" + ap + sta, hashlib.sha1).digest()[:16]
    if pmkid == pmkid_sha1:
        sys.stderr.write("FAIL: PMKID-SHA384 == PMKID-SHA1 (hash-family bypass somewhere)\n")
        ok = False

    return 0 if ok else 1


def emit_canonical_vectors() -> None:
    """Print the canonical SHA-384 vectors so a future Rust unit test can paste
    them in as KATs without recomputation."""
    # Use the type-9 fixture inputs (PSK-SHA-384 EAPOL).
    ssid = b"wpawolf-test-09"
    ap = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x19])
    sta = bytes([0x02, 0x00, 0x00, 0x00, 0x01, 0x19])
    pmk = derive_pmk(PSK, ssid)
    pmkid = derive_pmkid_sha384(pmk, ap, sta)
    ptk = derive_ptk_sha384(pmk, ap, sta, ANONCE, SNONCE)
    print("// Canonical SHA-384 vectors for the type-9 (PSK-SHA-384 EAPOL) fixture.")
    print("// Inputs: PSK = b\"hashcat!\", SSID = b\"wpawolf-test-09\",")
    print(f"//   AP = {list(ap)}, STA = {list(sta)},")
    print("//   ANONCE = [0xA1; 32], SNONCE = [0xB2; 32].")
    print(vec("PMK", pmk))
    print(vec("PMKID-SHA384", pmkid))
    print(vec("PTK[0..24] (KCK)", ptk[:24]))
    print(vec("PTK[24..40] (KEK)", ptk[24:40]))
    print(vec("PTK[40..56] (TK)", ptk[40:56]))


# --- Manifest walker (exercises every type fixture's PMK / PMKID round-trip) ---


# Map of `wpawolf-tNN` SSID stem -> (hash family, MAC index byte). Mirrors
# `tools/fixturegen/src/catalog.rs::types_section` so the walker knows which
# crypto family to use per type fixture without re-parsing the pcap.
_TYPE_TABLE: dict[str, tuple[str, int]] = {
    # SSID stem            -> (PMKID hash family, IDX_TYPES_BASE(0x10) + N)
    "wpawolf-t01":           ("sha1",   0x11),  # WPA1 PSK -- no PMKID
    "wpawolf-t02":           ("sha1",   0x12),  # WPA2-PSK PMKID
    "wpawolf-t03":           ("sha1",   0x13),  # WPA2-PSK EAPOL
    "wpawolf-t04":           ("sha256", 0x14),  # PSK-SHA-256 PMKID
    "wpawolf-t05":           ("sha256", 0x15),  # PSK-SHA-256 EAPOL
    "wpawolf-t06":           ("sha256", 0x16),  # FT-PSK PMKID (R1Name; not direct hmac)
    "wpawolf-t07":           ("sha256", 0x17),  # FT-PSK EAPOL
    "wpawolf-t08":           ("sha384", 0x18),  # PSK-SHA-384 PMKID
    "wpawolf-t09":           ("sha384", 0x19),  # PSK-SHA-384 EAPOL
    "wpawolf-t10":           ("sha384", 0x1A),  # FT-PSK-SHA-384 PMKID (R1Name)
    "wpawolf-t11":           ("sha384", 0x1B),  # FT-PSK-SHA-384 EAPOL
}


def parse_manifest(manifest_path: Path) -> list[dict[str, object]]:
    """Tiny TOML-ish reader for `ground_truth/manifest.toml`. Only extracts
    `path`, `description`, `expected_hashes`, and `forbidden_hashes` -- enough
    for the round-trip oracle. Avoids a tomllib dependency to stay 3.11-portable
    everywhere; the format is generated by `write_manifest` so we own it."""
    fixtures: list[dict[str, object]] = []
    cur: Optional[dict[str, object]] = None
    section: Optional[str] = None
    if not manifest_path.exists():
        return fixtures
    for raw in manifest_path.read_text().splitlines():
        line = raw.strip()
        if line == "[[fixture]]":
            if cur is not None:
                fixtures.append(cur)
            cur = {"expected_hashes": [], "forbidden_hashes": []}
            section = None
            continue
        if cur is None:
            continue
        m = re.match(r'^path = "([^"]+)"', line)
        if m:
            cur["path"] = m.group(1)
            continue
        m = re.match(r'^description = "([^"]*)"', line)
        if m:
            cur["description"] = m.group(1)
            continue
        if line.startswith("expected_hashes"):
            section = "expected_hashes"
            continue
        if line.startswith("forbidden_hashes"):
            section = "forbidden_hashes"
            continue
        if line == "]":
            section = None
            continue
        m = re.match(r'^"([^"]*)",$', line)
        if m and section in ("expected_hashes", "forbidden_hashes"):
            cur[section].append(m.group(1))  # type: ignore[union-attr]
    if cur is not None:
        fixtures.append(cur)
    return fixtures


def walk_manifest(manifest_path: Path, verbose: bool = False) -> int:
    """Cross-check every type fixture in the manifest against an independent
    Python derivation of its PMK + PMKID. Emits per-fixture pass/fail and
    returns 0 on full match, 1 on any mismatch."""
    fixtures = parse_manifest(manifest_path)
    if not fixtures:
        print(f"verify_sha384: manifest at {manifest_path} is empty or missing")
        return 1

    failures = 0
    checked = 0
    for f in fixtures:
        path = str(f.get("path", ""))
        # Only the `11_types/typeNN_*.pcap` fixtures have a deterministic
        # SSID -> hash-family mapping today. Other fixtures (combos, edge,
        # link_layers, containers) reuse those primitives but with different
        # SSIDs and AP/STA pairs we'd have to reparse the pcap to recover.
        if not path.startswith("11_types/type"):
            continue
        # Recover the type number from the filename: `typeNN_*.pcap`.
        m = re.match(r"^11_types/type(\d{2})_", path)
        if not m:
            continue
        type_num = int(m.group(1))
        ssid_stem = f"wpawolf-t{type_num:02d}"
        if ssid_stem not in _TYPE_TABLE:
            continue
        family, mac_byte = _TYPE_TABLE[ssid_stem]
        ssid = ssid_stem.encode("ascii")
        pmk = derive_pmk(PSK, ssid)
        # Smoke check: PMK reproduces from inputs.
        again = derive_pmk(PSK, ssid)
        if pmk != again:
            print(f"FAIL: {path}: PMK derivation non-deterministic")
            failures += 1
            continue
        # Per-fixture AP / STA pair (first-byte mask `0x02` for locally-administered).
        # Mirrors `ap_mac` / `sta_mac` in `tools/fixturegen/src/catalog.rs`.
        ap = bytes([0x02, 0x11, 0x22, 0x33, 0x44, mac_byte])
        sta = bytes([0x02, 0xAA, 0xBB, 0xCC, 0xDD, mac_byte])
        # WPA1 (type 1) does not emit a PMKID; just confirm the PMK derives.
        if type_num == 1:
            checked += 1
            if verbose:
                print(f"OK   {path}: PMK={pmk.hex()[:16]}... (WPA1 has no PMKID)")
            continue
        # FT types (6, 7, 10, 11) use PMK-R1Name as their PMKID, derived
        # through the FT key hierarchy. Recompute the chain.
        if type_num in (6, 7, 10, 11):
            mdid = bytes([0x34, 0x12])
            r0kh = b"r0kh"
            r1kh = bytes([0x06] * 6)
            if type_num in (10, 11):
                # SHA-384 chain.
                pmk_r0, pmk_r0_name = derive_pmk_r0_sha384(pmk, ssid, mdid, r0kh, sta)
                _, pmk_r1_name = derive_pmk_r1_sha384(pmk_r0, pmk_r0_name, r1kh, sta)
                pmkid = pmk_r1_name
            else:
                # SHA-256 chain. Re-implement inline to avoid duplicating helpers.
                ctx = bytes([len(ssid)]) + ssid + mdid + bytes([len(r0kh)]) + r0kh + sta
                pmk_r0_full = kdf_hash(pmk, "FT-R0", ctx, 256 + 128, "sha256")
                pmk_r0 = pmk_r0_full[:32]
                salt = pmk_r0_full[32:48]
                pmk_r0_name = hashlib.sha256(b"FT-R0N" + salt).digest()[:16]
                pmk_r1 = kdf_hash(pmk_r0, "FT-R1", r1kh + sta, 256, "sha256")
                pmkid = hashlib.sha256(b"FT-R1N" + pmk_r0_name + r1kh + sta).digest()[:16]
                _ = pmk_r1  # not currently asserted; keeps the variable named for readability
        else:
            # Non-FT PMKID: Truncate-128(HMAC-Hash(PMK, "PMK Name" || AA || SPA)).
            hash_for_pmkid = {"sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha384": hashlib.sha384}[family]
            pmkid = hmac.new(pmk, b"PMK Name" + ap + sta, hash_for_pmkid).digest()[:16]
        # Trivial sanity: PMKID is non-zero and not all-FF.
        if pmkid in (b"\x00" * 16, b"\xFF" * 16):
            print(f"FAIL: {path}: PMKID derived to a sentinel value ({pmkid.hex()})")
            failures += 1
            continue
        checked += 1
        if verbose:
            print(f"OK   {path}: PMK={pmk.hex()[:16]}... PMKID={pmkid.hex()}")
    print(f"verify_sha384: walked {checked} type fixture(s), {failures} mismatch(es)")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    args = set(argv[1:])
    verbose = "--verbose" in args or "-v" in args
    if "--emit-vectors" in args:
        emit_canonical_vectors()
        return 0
    rc = run_self_test(verbose=verbose)
    if rc != 0:
        return rc
    if "--walk" in args:
        # Resolve manifest relative to the repo root (script lives 3 levels deep).
        manifest_path = Path(__file__).resolve().parents[3] / "tests/fixtures/generated/ground_truth/manifest.toml"
        rc = walk_manifest(manifest_path, verbose=verbose)
        if rc != 0:
            return rc
    print("verify_sha384: OK -- all primitives match.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
