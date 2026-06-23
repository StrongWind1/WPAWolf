//! Cryptographic primitives for the 11-type WPA/WPA2/WPA3-FT-PSK per-AKM.
//!
//! Each function corresponds to a specific clause in `[IEEE 802.11-2024]`:
//!
//! | Step  | Primitive                              | Spec section                   |
//! | ----- | -------------------------------------- | ------------------------------ |
//! | PMK   | `PBKDF2-HMAC-SHA1(PSK, SSID, 4096, 32)`| §J.4.1 / §12.7.1.6.4           |
//! | PTK   | `PRF-N` / `KDF-Hash-N`                 | §12.7.1.2 / §12.7.1.3          |
//! | PMKID | `Truncate-128(HMAC-Hash(PMK, "PMK Name" \|\| AA \|\| SPA))` | §12.7.1.3 / §12.10.3 |
//! | MIC   | HMAC-MD5 / HMAC-SHA1-128 / AES-128-CMAC / HMAC-SHA384-192 | §12.7.3 |
//!
//! Reference KAT vectors are pulled from `hostap.git`
//! `src/common/wpa_common.c` and Wireshark's reference dissector.

use aes::Aes128;
use cmac::Cmac;
// `KeyInit` is the RustCrypto 0.11+ trait that provides `new_from_slice` for
// keyed constructions (HMAC, CMAC). Before 0.11 the method lived directly on
// the type; importing the trait restores the same call site.
use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha384};
use subtle::ConstantTimeEq;

use crate::{Error, Result};

/// Hash family used by the PRF / KDF / MIC for a given AKM suite.
///
/// `[IEEE 802.11-2024]` table 12-11 -- the discriminant drives every
/// per-AKM crypto branch in this module.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HashFamily {
    /// HMAC-MD5 -- WPA1 (KDV=1) MIC only. Not used for any KDF.
    Md5,
    /// HMAC-SHA1 -- AKM 2 (WPA2-PSK), KDV=2 MIC, baseline PRF.
    Sha1,
    /// HMAC-SHA-256 -- AKMs 4 / 6 / 11 / 13, KDV=3 MIC, FT KDF (SHA-256).
    Sha256,
    /// HMAC-SHA-384 -- AKMs 19 / 20, KDV=0 MIC (24-byte field), FT KDF (SHA-384).
    Sha384,
    /// AES-128-CMAC -- KDV=3 MIC for the SHA-256 family (AKMs 4 / 6 / 11).
    AesCmac128,
}

/// Width of the EAPOL-Key MIC field for an AKM family.
///
/// `[IEEE 802.11-2024]` §12.7.3: 16 bytes for MD5 / SHA-1-128 / AES-CMAC-128,
/// 24 bytes for HMAC-SHA-384-192.
#[must_use]
pub const fn mic_len(family: HashFamily) -> usize {
    match family {
        HashFamily::Md5 | HashFamily::Sha1 | HashFamily::Sha256 | HashFamily::AesCmac128 => 16,
        HashFamily::Sha384 => 24,
    }
}

/// Constant-time equality on byte slices -- exposed so callers asserting
/// against KAT vectors do not leak timing through `==`.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Derive a 32-byte PMK from a passphrase + SSID via PBKDF2-HMAC-SHA1.
///
/// `[IEEE 802.11-2024]` §J.4.1: `PMK = PBKDF2(PSK, SSID, 4096, 32)`. Used by
/// every PSK family -- the AKM-specific divergence happens later in the PTK
/// derivation, not in the PMK.
///
/// # Errors
///
/// Returns [`Error::InvalidWireFormat`] if `passphrase` is empty or `ssid`
/// exceeds the 32-byte SSID limit (`[IEEE 802.11-2024]` §9.4.2.2).
pub fn derive_pmk(passphrase: &[u8], ssid: &[u8]) -> Result<[u8; 32]> {
    if passphrase.is_empty() {
        return Err(Error::InvalidWireFormat("PSK passphrase must be non-empty"));
    }
    if ssid.len() > 32 {
        return Err(Error::InvalidWireFormat("SSID exceeds 32-byte limit"));
    }
    let mut pmk = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha1>(passphrase, ssid, 4096, &mut pmk);
    Ok(pmk)
}

/// Derive a PMKID from a PMK + AP MAC + STA MAC.
///
/// `[IEEE 802.11-2024]` §12.10.3: `PMKID = Truncate-128(HMAC-Hash(PMK,
/// "PMK Name" || AA || SPA))`. The hash is selected by the AKM family.
///
/// # Errors
///
/// Returns [`Error::UnsupportedSpec`] if `family` is `HashFamily::AesCmac128`
/// (PMKID is never AES-CMAC; this catches a caller bug at compile-adjacent
/// time).
pub fn derive_pmkid(family: HashFamily, pmk: &[u8], ap: [u8; 6], sta: [u8; 6]) -> Result<[u8; 16]> {
    let mut input = Vec::with_capacity(8 + 6 + 6);
    input.extend_from_slice(b"PMK Name");
    input.extend_from_slice(&ap);
    input.extend_from_slice(&sta);
    let tag = match family {
        HashFamily::Md5 | HashFamily::Sha1 => hmac_sha1(pmk, &input)?,
        HashFamily::Sha256 => hmac_sha256(pmk, &input)?,
        HashFamily::Sha384 => hmac_sha384(pmk, &input)?,
        HashFamily::AesCmac128 => return Err(Error::UnsupportedSpec("PMKID is not defined for AES-CMAC")),
    };
    let mut out = [0u8; 16];
    out.copy_from_slice(tag.get(..16).ok_or(Error::InvalidWireFormat("HMAC tag shorter than 16 bytes"))?);
    Ok(out)
}

/// PTK length per AKM family.
///
/// `[IEEE 802.11-2024]` §12.7.1.3 table 12-9: PTK = KCK || KEK || TK.
/// SHA-1/SHA-256 families: 48 bytes (16 KCK + 16 KEK + 16 TK).
/// SHA-384 family: 88 bytes (24 KCK + 32 KEK + 32 TK) per §12.7.1.3.
#[must_use]
pub const fn ptk_len(family: HashFamily) -> usize {
    match family {
        HashFamily::Md5 | HashFamily::Sha1 | HashFamily::Sha256 | HashFamily::AesCmac128 => 48,
        HashFamily::Sha384 => 88,
    }
}

/// KCK length per AKM family. Matches the leading slice of [`ptk_len`].
#[must_use]
pub const fn kck_len(family: HashFamily) -> usize {
    match family {
        HashFamily::Md5 | HashFamily::Sha1 | HashFamily::Sha256 | HashFamily::AesCmac128 => 16,
        HashFamily::Sha384 => 24,
    }
}

/// Derive the PTK for a 4-way handshake.
///
/// `[IEEE 802.11-2024]` §12.7.1.2 / §12.7.1.3:
/// `PTK = PRF-N(PMK, "Pairwise key expansion", min(AA,SPA) || max(AA,SPA) ||
/// min(ANonce,SNonce) || max(ANonce,SNonce))`. The PRF function is
/// `PRF-HMAC-SHA1` for AKM 2 (legacy SHA-1 family) and `KDF-Hash-Length` for
/// AKMs 4 / 6 / 8 / 11 / 13 / 19 / 20 (`[IEEE 802.11-2024]` §12.7.1.6.2).
///
/// # Errors
///
/// Forwards any HMAC failure (effectively unreachable -- HMAC accepts any
/// key length per RFC 2104).
pub fn derive_ptk(
    family: HashFamily,
    pmk: &[u8],
    ap: [u8; 6],
    sta: [u8; 6],
    a_nonce: &[u8; 32],
    s_nonce: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut data = Vec::with_capacity(12 + 64);
    if ap <= sta {
        data.extend_from_slice(&ap);
        data.extend_from_slice(&sta);
    } else {
        data.extend_from_slice(&sta);
        data.extend_from_slice(&ap);
    }
    if a_nonce <= s_nonce {
        data.extend_from_slice(a_nonce);
        data.extend_from_slice(s_nonce);
    } else {
        data.extend_from_slice(s_nonce);
        data.extend_from_slice(a_nonce);
    }
    let total = ptk_len(family);
    match family {
        HashFamily::Md5 | HashFamily::Sha1 | HashFamily::AesCmac128 => {
            prf_sha1(pmk, b"Pairwise key expansion", &data, total)
        },
        HashFamily::Sha256 => kdf_sha256(pmk, "Pairwise key expansion", &data, total),
        HashFamily::Sha384 => kdf_sha384(pmk, "Pairwise key expansion", &data, total),
    }
}

/// Slice the KCK off the front of a derived PTK.
///
/// # Errors
///
/// Returns [`Error::InvalidWireFormat`] if `ptk` is shorter than the AKM's
/// expected KCK length.
pub fn kck_from_ptk(family: HashFamily, ptk: &[u8]) -> Result<Vec<u8>> {
    let want = kck_len(family);
    Ok(ptk.get(..want).ok_or(Error::InvalidWireFormat("PTK shorter than KCK"))?.to_vec())
}

/// `PRF-N` per `[IEEE 802.11-2024]` §12.7.1.2 (HMAC-SHA1-based PRF).
fn prf_sha1(key: &[u8], label: &[u8], data: &[u8], n_bytes: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(n_bytes);
    let mut counter: u8 = 0;
    while out.len() < n_bytes {
        let mut input = Vec::with_capacity(label.len() + 1 + data.len() + 1);
        input.extend_from_slice(label);
        input.push(0); // Separator.
        input.extend_from_slice(data);
        input.push(counter);
        let block = hmac_sha1(key, &input)?;
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(n_bytes);
    Ok(out)
}

/// `KDF-Hash-Length` per `[IEEE 802.11-2024]` §12.7.1.6.2 (SHA-256 family).
fn kdf_sha256(key: &[u8], label: &str, context: &[u8], n_bytes: usize) -> Result<Vec<u8>> {
    kdf_generic(key, label, context, n_bytes, HashFamily::Sha256)
}

/// `KDF-Hash-Length` per `[IEEE 802.11-2024]` §12.7.1.6.2 (SHA-384 family).
fn kdf_sha384(key: &[u8], label: &str, context: &[u8], n_bytes: usize) -> Result<Vec<u8>> {
    kdf_generic(key, label, context, n_bytes, HashFamily::Sha384)
}

/// Generic NIST-style KDF: `i || Label || Context || Length` blocks fed to
/// HMAC-Hash. `[IEEE 802.11-2024]` §12.7.1.6.2.
fn kdf_generic(key: &[u8], label: &str, context: &[u8], n_bytes: usize, family: HashFamily) -> Result<Vec<u8>> {
    let length_bits = u16::try_from(n_bytes * 8).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(n_bytes);
    let mut counter: u16 = 1;
    while out.len() < n_bytes {
        let mut input = Vec::with_capacity(2 + label.len() + context.len() + 2);
        input.extend_from_slice(&counter.to_le_bytes());
        input.extend_from_slice(label.as_bytes());
        input.extend_from_slice(context);
        input.extend_from_slice(&length_bits.to_le_bytes());
        let block = match family {
            HashFamily::Sha256 => hmac_sha256(key, &input)?,
            HashFamily::Sha384 => hmac_sha384(key, &input)?,
            _ => return Err(Error::UnsupportedSpec("kdf_generic only supports SHA-256/SHA-384")),
        };
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(n_bytes);
    Ok(out)
}

/// Compute an EAPOL-Key MIC over the supplied EAPOL body.
///
/// The MIC field inside `eapol_body` MUST already be zeroed by the caller.
/// `family` selects the algorithm; the returned `Vec<u8>` is `mic_len(family)`
/// bytes long.
///
/// # Errors
///
/// Returns [`Error::InvalidWireFormat`] if `eapol_body` is shorter than the
/// minimum EAPOL-Key body (95 bytes for 16-byte MIC, 103 for 24-byte).
pub fn compute_mic(family: HashFamily, kck: &[u8], eapol_body: &[u8]) -> Result<Vec<u8>> {
    let want = mic_len(family);
    let min_body = 95 + (want - 16);
    if eapol_body.len() < min_body {
        return Err(Error::InvalidWireFormat("EAPOL body shorter than MIC offset"));
    }
    let tag = match family {
        HashFamily::Md5 => hmac_md5(kck, eapol_body)?,
        HashFamily::Sha1 => hmac_sha1(kck, eapol_body)?,
        HashFamily::Sha256 => hmac_sha256(kck, eapol_body)?,
        HashFamily::Sha384 => hmac_sha384(kck, eapol_body)?,
        HashFamily::AesCmac128 => aes_cmac_128(kck, eapol_body)?,
    };
    Ok(tag.get(..want).ok_or(Error::InvalidWireFormat("MAC tag shorter than expected"))?.to_vec())
}

// --- Internal HMAC / CMAC helpers ---
//
// `Hmac::new_from_slice` accepts any key length per RFC 2104 (long keys are
// hashed down internally), so the documented `InvalidLength` error is
// effectively unreachable. We still propagate it through `Result` to keep
// the call sites lint-clean (no `.unwrap()` / `.expect()` in library code).

fn hmac_md5(key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Md5>::new_from_slice(key).map_err(|_| Error::InvalidWireFormat("HMAC-MD5 key length"))?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha1(key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).map_err(|_| Error::InvalidWireFormat("HMAC-SHA1 key length"))?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::InvalidWireFormat("HMAC-SHA256 key length"))?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_sha384(key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let mut mac =
        Hmac::<Sha384>::new_from_slice(key).map_err(|_| Error::InvalidWireFormat("HMAC-SHA384 key length"))?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn aes_cmac_128(key: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let mut mac =
        Cmac::<Aes128>::new_from_slice(key).map_err(|_| Error::InvalidWireFormat("AES-CMAC requires a 16-byte key"))?;
    mac.update(msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

// --- Fast BSS Transition (802.11r) key hierarchy -------------------------
//
// Per `[IEEE 802.11-2024]` §13.4.4 the FT four-way handshake derives keys
// through three layers below the PMK:
//
//   PMK-R0   = first N bits of  KDF-Hash(PMK,    "FT-R0", S0,        L_R0)
//   PMK-R0Salt = trailing 128 bits of the same KDF output
//   PMK-R0Name = Truncate-128(Hash("FT-R0N" || PMK-R0Salt))   Hash per AKM
//   PMK-R1   = KDF-Hash(PMK-R0, "FT-R1",  R1KH-ID || SPA, hashlen)
//   PMK-R1Name = Truncate-128(Hash("FT-R1N" || PMK-R0Name || R1KH-ID || SPA))
//   PTK_FT   = KDF-Hash(PMK-R1, "FT-PTK", SNonce || ANonce || BSSID || SPA, L_PTK)
//
// `S0` for PMK-R0 is `SSIDlength(1) || SSID || MDID(2) || R0KHlength(1) ||
// R0KH-ID || SPA(6)`. Hashcat mode 37100 reproduces this layout in
// `module_37100.c` (the 32-byte `pke_r0` template + the `FT-R1N` template);
// the byte-for-byte schema below tracks that expectation so wpawolf's emitted
// `WPA*03*/WPA*04*` lines crack against the wpawolf test PSK.

/// FT key-derivation context. Carries the immutable identifiers the PMK-R0 /
/// PMK-R1 chain hashes over.
#[derive(Debug, Clone)]
pub struct FtContext<'a> {
    /// SSID -- bytes only, length must fit in `u8`.
    pub ssid: &'a [u8],
    /// Mobility Domain Identifier (`MDID`, 2 B little-endian on the wire).
    pub mdid: [u8; 2],
    /// R0 Key Holder ID (1-48 bytes per `[IEEE 802.11-2024]` §9.4.2.46).
    pub r0kh_id: &'a [u8],
    /// R1 Key Holder ID (always 6 bytes -- a MAC address).
    pub r1kh_id: [u8; 6],
}

/// Truncate-128 of the AKM family hash over `input` -- the FT Name
/// construction. `[IEEE 802.11-2024]` §12.7.1.6.3 / §12.7.1.6.4: `PMKR0Name` and
/// `PMKR1Name` use the hash algorithm of the negotiated AKM (Table 9-190) --
/// SHA-256 for AKM 4 (FT-PSK), SHA-384 for AKM 19 (FT-PSK-SHA384). The 128-bit
/// truncation is identical; only the underlying hash changes.
///
/// # Errors
///
/// Returns [`Error::UnsupportedSpec`] for non-FT hash families.
fn ft_name_truncate_128(family: HashFamily, input: &[u8]) -> Result<[u8; 16]> {
    use sha2::Digest;
    let digest: Vec<u8> = match family {
        HashFamily::Sha256 => Sha256::digest(input).to_vec(),
        HashFamily::Sha384 => Sha384::digest(input).to_vec(),
        _ => return Err(Error::UnsupportedSpec("FT Name hash only defined for SHA-256 / SHA-384")),
    };
    let mut out = [0u8; 16];
    out.copy_from_slice(digest.get(..16).ok_or(Error::InvalidWireFormat("hash output shorter than 16 bytes"))?);
    Ok(out)
}

/// Derive `PMK-R0` and `PMK-R0Name` per `[IEEE 802.11-2024]` §13.4.4.
///
/// The KDF runs at 384 bits (SHA-256) or 512 bits (SHA-384). The leading 32 /
/// 48 bytes are `PMK-R0`; the trailing 16 bytes are the `PMK-R0Salt` that
/// feeds the AKM family hash (SHA-256 / SHA-384) for `PMK-R0Name`.
///
/// # Errors
///
/// Returns [`Error::UnsupportedSpec`] for non-FT hash families and
/// [`Error::InvalidWireFormat`] if the SSID or R0KH-ID exceed `u8` length.
pub fn derive_pmk_r0(family: HashFamily, pmk: &[u8], ctx: &FtContext<'_>, sta: [u8; 6]) -> Result<(Vec<u8>, [u8; 16])> {
    let pmk_r0_len = match family {
        HashFamily::Sha256 => 32,
        HashFamily::Sha384 => 48,
        _ => return Err(Error::UnsupportedSpec("FT key hierarchy only supports SHA-256 / SHA-384")),
    };
    let ssid_len = u8::try_from(ctx.ssid.len()).map_err(|_| Error::InvalidWireFormat("SSID exceeds u8 length"))?;
    let r0kh_len =
        u8::try_from(ctx.r0kh_id.len()).map_err(|_| Error::InvalidWireFormat("R0KH-ID exceeds u8 length"))?;
    let mut s0 = Vec::with_capacity(1 + ctx.ssid.len() + 2 + 1 + ctx.r0kh_id.len() + 6);
    s0.push(ssid_len);
    s0.extend_from_slice(ctx.ssid);
    s0.extend_from_slice(&ctx.mdid);
    s0.push(r0kh_len);
    s0.extend_from_slice(ctx.r0kh_id);
    s0.extend_from_slice(&sta);
    let total = pmk_r0_len + 16;
    let kdf_out = kdf_generic(pmk, "FT-R0", &s0, total, family)?;
    let pmk_r0 = kdf_out.get(..pmk_r0_len).ok_or(Error::InvalidWireFormat("KDF short: PMK-R0"))?.to_vec();
    let salt: [u8; 16] = kdf_out
        .get(pmk_r0_len..pmk_r0_len + 16)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::InvalidWireFormat("KDF short: PMK-R0-Salt"))?;
    let mut name_input = Vec::with_capacity(6 + 16);
    name_input.extend_from_slice(b"FT-R0N");
    name_input.extend_from_slice(&salt);
    // PMKR0Name uses the AKM family hash (SHA-384 for AKM 19), not a fixed
    // SHA-256. [IEEE 802.11-2024] §12.7.1.6.3 line 108004.
    let pmk_r0_name = ft_name_truncate_128(family, &name_input)?;
    Ok((pmk_r0, pmk_r0_name))
}

/// Derive `PMK-R1` and `PMK-R1Name` per `[IEEE 802.11-2024]` §13.4.4.
///
/// `PMK-R1` is 32 bytes (SHA-256) or 48 bytes (SHA-384); `PMK-R1Name` is
/// always 16 bytes (the truncated AKM family hash -- SHA-256 for AKM 4,
/// SHA-384 for AKM 19 -- over `"FT-R1N" || PMK-R0Name || R1KH-ID || SPA`).
/// `PMK-R1Name` is the value emitted as the `PMKID` in `WPA*06*` (FT-PSK) /
/// `WPA*10*` (FT-PSK-SHA384) lines.
///
/// # Errors
///
/// Returns [`Error::UnsupportedSpec`] for non-FT hash families.
pub fn derive_pmk_r1(
    family: HashFamily,
    pmk_r0: &[u8],
    pmk_r0_name: &[u8; 16],
    r1kh_id: [u8; 6],
    sta: [u8; 6],
) -> Result<(Vec<u8>, [u8; 16])> {
    let pmk_r1_len = match family {
        HashFamily::Sha256 => 32,
        HashFamily::Sha384 => 48,
        _ => return Err(Error::UnsupportedSpec("FT key hierarchy only supports SHA-256 / SHA-384")),
    };
    let mut context = Vec::with_capacity(6 + 6);
    context.extend_from_slice(&r1kh_id);
    context.extend_from_slice(&sta);
    let pmk_r1 = kdf_generic(pmk_r0, "FT-R1", &context, pmk_r1_len, family)?;
    let mut name_input = Vec::with_capacity(6 + 16 + 6 + 6);
    name_input.extend_from_slice(b"FT-R1N");
    name_input.extend_from_slice(pmk_r0_name);
    name_input.extend_from_slice(&r1kh_id);
    name_input.extend_from_slice(&sta);
    // PMKR1Name uses the AKM family hash (SHA-384 for AKM 19), not a fixed
    // SHA-256. [IEEE 802.11-2024] §12.7.1.6.4 lines 108029/108037.
    let pmk_r1_name = ft_name_truncate_128(family, &name_input)?;
    Ok((pmk_r1, pmk_r1_name))
}

/// Derive the FT `PTK` per `[IEEE 802.11-2024]` §13.4.5.
///
/// `PTK = KDF-Hash(PMK-R1, "FT-PTK", SNonce || ANonce || BSSID || SPA, L)`
/// where `L` is `48` bytes (SHA-256) or `88` bytes (SHA-384). Note this is a
/// *different* PRF input layout from the non-FT PTK: `SNonce` precedes `ANonce`,
/// and BSSID precedes SPA -- without the lexicographic min/max ordering the
/// non-FT 4-way handshake uses.
///
/// # Errors
///
/// Returns [`Error::UnsupportedSpec`] for non-FT hash families.
pub fn derive_ft_ptk(
    family: HashFamily,
    pmk_r1: &[u8],
    s_nonce: &[u8; 32],
    a_nonce: &[u8; 32],
    bssid: [u8; 6],
    sta: [u8; 6],
) -> Result<Vec<u8>> {
    let total = match family {
        HashFamily::Sha256 => 48,
        HashFamily::Sha384 => 88,
        _ => return Err(Error::UnsupportedSpec("FT key hierarchy only supports SHA-256 / SHA-384")),
    };
    let mut context = Vec::with_capacity(32 + 32 + 6 + 6);
    context.extend_from_slice(s_nonce);
    context.extend_from_slice(a_nonce);
    context.extend_from_slice(&bssid);
    context.extend_from_slice(&sta);
    kdf_generic(pmk_r1, "FT-PTK", &context, total, family)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PMK = `PBKDF2-HMAC-SHA1("IEEE", "IEEE", 4096, 32)` -- regression
    /// vector cross-checked against Python `hashlib.pbkdf2_hmac` and
    /// `wpa_passphrase` from hostap. Locks the PBKDF2 wiring.
    const PMK_IEEE_IEEE: [u8; 32] = [
        0x62, 0x3b, 0x5d, 0xf2, 0xf3, 0x1b, 0xb4, 0x7c, 0x7e, 0x4e, 0xc0, 0xf0, 0x5e, 0x60, 0xe2, 0x11, 0x0f, 0xd5,
        0x7f, 0x73, 0x92, 0xf7, 0xb2, 0x65, 0xbd, 0x26, 0x13, 0xd3, 0x5c, 0xaa, 0x50, 0x88,
    ];

    const AP_KAT: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    const STA_KAT: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

    /// `Truncate-128(HMAC-SHA1(PMK_IEEE_IEEE, "PMK Name" || AP || STA))`.
    const PMKID_SHA1_KAT: [u8; 16] =
        [0xd0, 0x67, 0x28, 0x23, 0x26, 0x5f, 0x14, 0x2a, 0x8f, 0xd4, 0x8f, 0x2c, 0x93, 0xc4, 0x2d, 0x8d];

    /// `Truncate-128(HMAC-SHA256(PMK_IEEE_IEEE, "PMK Name" || AP || STA))`.
    const PMKID_SHA256_KAT: [u8; 16] =
        [0xb5, 0x54, 0x47, 0xc7, 0xae, 0x75, 0x1f, 0x18, 0x44, 0x13, 0x0f, 0x1a, 0x26, 0xa1, 0x54, 0x4a];

    /// `Truncate-128(HMAC-SHA384(PMK_IEEE_IEEE, "PMK Name" || AP || STA))`.
    const PMKID_SHA384_KAT: [u8; 16] =
        [0xc3, 0xea, 0x1b, 0x82, 0x9c, 0x3b, 0x8c, 0x2a, 0xdd, 0x12, 0x35, 0x58, 0x6e, 0xe8, 0x8b, 0xab];

    /// MIC fixtures: KCK = 16x `0x11`, body = 105x `0x00`. The PRF inputs are
    /// arbitrary, but reproducing them exactly is what catches a regression.
    const MIC_KCK: [u8; 16] = [0x11; 16];
    const MIC_BODY: [u8; 105] = [0x00; 105];

    const MIC_MD5_KAT: [u8; 16] =
        [0x1d, 0x07, 0x4c, 0xec, 0x7c, 0x2b, 0x42, 0x72, 0xe4, 0x79, 0xb0, 0xf5, 0x20, 0x26, 0x70, 0x7b];
    const MIC_SHA1_KAT: [u8; 16] =
        [0x4a, 0x2d, 0x64, 0x6b, 0x9d, 0xcf, 0xd9, 0xb8, 0x39, 0x1a, 0x05, 0x92, 0x5e, 0x1b, 0x19, 0x76];
    const MIC_SHA256_KAT: [u8; 16] =
        [0x38, 0xed, 0xe3, 0xac, 0xf5, 0xc4, 0x1f, 0xa2, 0xa3, 0x97, 0x71, 0xa5, 0xcb, 0x16, 0xd6, 0x0a];
    const MIC_SHA384_KAT: [u8; 24] = [
        0xf9, 0xa6, 0x23, 0x6d, 0xd7, 0x79, 0x6d, 0xa7, 0x4c, 0xb6, 0xbe, 0xca, 0x8a, 0xfd, 0x71, 0x18, 0x03, 0x3d,
        0xc7, 0x1f, 0x6c, 0xf0, 0x8c, 0x8d,
    ];
    const MIC_AES_CMAC_KAT: [u8; 16] =
        [0x86, 0xd5, 0x92, 0x5c, 0xb1, 0x49, 0x43, 0x40, 0xe5, 0x1b, 0x1e, 0xc8, 0x8e, 0x8e, 0x99, 0xd9];

    #[test]
    fn pmk_kat_ieee() {
        let pmk = derive_pmk(b"IEEE", b"IEEE").expect("derive_pmk");
        assert!(ct_eq(&pmk, &PMK_IEEE_IEEE));
    }

    #[test]
    fn pmkid_sha1_kat() {
        let pmkid = derive_pmkid(HashFamily::Sha1, &PMK_IEEE_IEEE, AP_KAT, STA_KAT).expect("derive_pmkid sha1");
        assert!(ct_eq(&pmkid, &PMKID_SHA1_KAT));
    }

    #[test]
    fn pmkid_sha256_kat() {
        let pmkid = derive_pmkid(HashFamily::Sha256, &PMK_IEEE_IEEE, AP_KAT, STA_KAT).expect("derive_pmkid sha256");
        assert!(ct_eq(&pmkid, &PMKID_SHA256_KAT));
    }

    #[test]
    fn pmkid_sha384_kat() {
        let pmkid = derive_pmkid(HashFamily::Sha384, &PMK_IEEE_IEEE, AP_KAT, STA_KAT).expect("derive_pmkid sha384");
        assert!(ct_eq(&pmkid, &PMKID_SHA384_KAT));
    }

    #[test]
    fn pmkid_rejects_aes_cmac() {
        let err = derive_pmkid(HashFamily::AesCmac128, &PMK_IEEE_IEEE, AP_KAT, STA_KAT);
        assert!(err.is_err());
    }

    #[test]
    fn mic_md5_kat() {
        let mic = compute_mic(HashFamily::Md5, &MIC_KCK, &MIC_BODY).expect("compute_mic md5");
        assert!(ct_eq(&mic, &MIC_MD5_KAT));
    }

    #[test]
    fn mic_sha1_kat() {
        let mic = compute_mic(HashFamily::Sha1, &MIC_KCK, &MIC_BODY).expect("compute_mic sha1");
        assert!(ct_eq(&mic, &MIC_SHA1_KAT));
    }

    #[test]
    fn mic_sha256_kat() {
        let mic = compute_mic(HashFamily::Sha256, &MIC_KCK, &MIC_BODY).expect("compute_mic sha256");
        assert!(ct_eq(&mic, &MIC_SHA256_KAT));
    }

    #[test]
    fn mic_sha384_kat() {
        // Sha384 family carries a 24-byte MIC; the body is the same 105
        // bytes used for the 16-byte vectors above so a single Python KAT
        // computation locks in every algorithm.
        let mic = compute_mic(HashFamily::Sha384, &MIC_KCK, &MIC_BODY).expect("compute_mic sha384");
        assert_eq!(mic.len(), 24);
        assert!(ct_eq(&mic, &MIC_SHA384_KAT));
    }

    #[test]
    fn mic_aes_cmac_kat() {
        let mic = compute_mic(HashFamily::AesCmac128, &MIC_KCK, &MIC_BODY).expect("compute_mic cmac");
        assert!(ct_eq(&mic, &MIC_AES_CMAC_KAT));
    }

    /// PTK KAT: PRF-SHA1, PMK = `PMK_IEEE_IEEE`, `ANonce` = 32x 0xA1, `SNonce` = 32x 0xB2.
    const PTK_SHA1_KAT: [u8; 48] = [
        0xef, 0xf7, 0x82, 0x72, 0xd8, 0x98, 0x83, 0xf7, 0x66, 0x04, 0xa5, 0x24, 0x71, 0xb9, 0x58, 0xd6, 0x3e, 0x89,
        0xa9, 0x11, 0x5e, 0xf4, 0x79, 0x70, 0x9b, 0x92, 0xad, 0x2d, 0x82, 0x66, 0x6a, 0x5d, 0x6f, 0x77, 0x72, 0x67,
        0xbd, 0xd5, 0x34, 0x7c, 0x39, 0xe3, 0xf3, 0x20, 0xa8, 0x54, 0x24, 0x0a,
    ];
    /// PTK KAT: KDF-SHA256 with the same inputs.
    const PTK_SHA256_KAT: [u8; 48] = [
        0x32, 0x76, 0xd2, 0x2b, 0xca, 0x4e, 0x15, 0xa1, 0xe6, 0x73, 0xb2, 0x9c, 0x92, 0x8a, 0x93, 0xc0, 0x82, 0x81,
        0x7d, 0xd5, 0xcc, 0xf5, 0x9e, 0xbe, 0x64, 0x2a, 0x68, 0x4c, 0x30, 0xf1, 0x50, 0xd7, 0xd8, 0x29, 0x1c, 0x9d,
        0x6a, 0x88, 0x1f, 0xe5, 0x48, 0x40, 0xe5, 0x17, 0xf5, 0x3c, 0x57, 0xb5,
    ];
    /// PTK KAT: KDF-SHA384 with the same inputs (88 bytes).
    const PTK_SHA384_KAT: [u8; 88] = [
        0x29, 0x18, 0x8e, 0xc1, 0x8c, 0x37, 0xa2, 0x34, 0x31, 0x94, 0xbf, 0xf8, 0x3c, 0x24, 0x83, 0xb4, 0x7c, 0xfe,
        0xb0, 0xae, 0xdc, 0xfc, 0x23, 0x71, 0x9b, 0xf4, 0x8e, 0xc7, 0x74, 0x3b, 0xdf, 0x70, 0x85, 0x5c, 0xf0, 0x3a,
        0x73, 0x4c, 0xc8, 0xd8, 0xd5, 0x64, 0x90, 0x8e, 0x89, 0x92, 0x54, 0xb3, 0xea, 0x5b, 0xa4, 0x37, 0xee, 0x8a,
        0x02, 0xfc, 0xe2, 0x6d, 0x81, 0xa7, 0x23, 0x85, 0x66, 0x4c, 0x17, 0xc9, 0x0e, 0x49, 0x7d, 0x30, 0x22, 0x13,
        0x57, 0x25, 0x4c, 0x12, 0x7f, 0x98, 0x7a, 0x4c, 0x02, 0x1f, 0xdf, 0xfd, 0x27, 0xe4, 0xff, 0xfb,
    ];

    const ANONCE_KAT: [u8; 32] = [0xA1; 32];
    const SNONCE_KAT: [u8; 32] = [0xB2; 32];

    #[test]
    fn ptk_sha1_kat() {
        let ptk = derive_ptk(HashFamily::Sha1, &PMK_IEEE_IEEE, AP_KAT, STA_KAT, &ANONCE_KAT, &SNONCE_KAT)
            .expect("derive_ptk sha1");
        assert!(ct_eq(&ptk, &PTK_SHA1_KAT));
    }

    #[test]
    fn ptk_sha256_kat() {
        let ptk = derive_ptk(HashFamily::Sha256, &PMK_IEEE_IEEE, AP_KAT, STA_KAT, &ANONCE_KAT, &SNONCE_KAT)
            .expect("derive_ptk sha256");
        assert!(ct_eq(&ptk, &PTK_SHA256_KAT));
    }

    #[test]
    fn ptk_sha384_kat() {
        let ptk = derive_ptk(HashFamily::Sha384, &PMK_IEEE_IEEE, AP_KAT, STA_KAT, &ANONCE_KAT, &SNONCE_KAT)
            .expect("derive_ptk sha384");
        assert!(ct_eq(&ptk, &PTK_SHA384_KAT));
    }

    #[test]
    fn kck_split_from_ptk() {
        let ptk = derive_ptk(HashFamily::Sha1, &PMK_IEEE_IEEE, AP_KAT, STA_KAT, &ANONCE_KAT, &SNONCE_KAT)
            .expect("derive_ptk sha1");
        let kck = kck_from_ptk(HashFamily::Sha1, &ptk).expect("kck_from_ptk");
        assert_eq!(kck.len(), 16);
        assert!(ct_eq(&kck, &PTK_SHA1_KAT[..16]));
    }

    #[test]
    fn pmk_rejects_empty_passphrase() {
        assert!(derive_pmk(b"", b"ssid").is_err());
    }

    #[test]
    fn pmk_rejects_oversize_ssid() {
        assert!(derive_pmk(b"hashcat", &[b'a'; 33]).is_err());
    }

    #[test]
    fn ct_eq_matches_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
    }

    /// FT key-hierarchy Name KAT: `PMKR0Name` / `PMKR1Name` for both AKM
    /// families. Vectors from the independent Python stdlib oracle
    /// (`tools/fixturegen/scripts`; PMK = `PBKDF2-HMAC-SHA1("IEEE","IEEE")`,
    /// SSID `"IEEE"`, STA = `STA_KAT`, MDID `0x1234`-LE, R0KH-ID `"r0kh"`,
    /// R1KH-ID `06:06:06:06:06:06`). Locks the family-dependent Name hash --
    /// regression guard for the bug where both Names hardcoded SHA-256
    /// regardless of AKM. `[80211-2024 §12.7.1.6.3/.6.4]`: the Name hash is the
    /// AKM's hash (SHA-256 for AKM 4, SHA-384 for AKM 19).
    #[test]
    fn ft_names_kat_per_family() {
        const MDID: [u8; 2] = [0x34, 0x12];
        const R0KH: &[u8] = b"r0kh";
        const R1KH: [u8; 6] = [0x06; 6];
        // (family, expected PMKR0Name, expected PMKR1Name).
        let cases: &[(HashFamily, [u8; 16], [u8; 16])] = &[
            (
                HashFamily::Sha256,
                [0x15, 0xba, 0xbe, 0xd8, 0x41, 0x41, 0x98, 0x00, 0xa9, 0x72, 0xad, 0x3f, 0x08, 0x97, 0x47, 0x66],
                [0xc9, 0x34, 0x49, 0xb5, 0x9b, 0x8a, 0xd6, 0x7b, 0xd6, 0x3a, 0x44, 0x7f, 0xbb, 0x04, 0xbc, 0xc9],
            ),
            (
                HashFamily::Sha384,
                [0xa3, 0x37, 0x47, 0x8e, 0x43, 0x9f, 0xf6, 0x8b, 0x61, 0x5d, 0x95, 0xa8, 0x16, 0x02, 0xfe, 0xa4],
                [0x93, 0x54, 0xfb, 0x08, 0xe7, 0x23, 0xb1, 0x53, 0x59, 0xfb, 0xb5, 0x67, 0x0a, 0xe9, 0xae, 0xb3],
            ),
        ];
        let pmk = derive_pmk(b"IEEE", b"IEEE").expect("derive_pmk");
        for (family, want_r0, want_r1) in cases {
            let ctx = FtContext { ssid: b"IEEE", mdid: MDID, r0kh_id: R0KH, r1kh_id: R1KH };
            let (pmk_r0, r0_name) = derive_pmk_r0(*family, &pmk, &ctx, STA_KAT).expect("derive_pmk_r0");
            assert!(ct_eq(&r0_name, want_r0), "PMKR0Name mismatch for {family:?}");
            let (_, r1_name) = derive_pmk_r1(*family, &pmk_r0, &r0_name, R1KH, STA_KAT).expect("derive_pmk_r1");
            assert!(ct_eq(&r1_name, want_r1), "PMKR1Name mismatch for {family:?}");
        }
    }
}
