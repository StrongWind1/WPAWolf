//! Phase 5 -- per-store byte-count reporter for `--mem-stats`. See `ARCHITECTURE.md §3.5 + §9`.
//!
//! Walks every long-lived store at end of run and prints a stderr table of
//! `name | entries | approx_bytes`. The byte counts are coarse approximations
//! (`HashMap` bucket overhead estimated as `capacity * (entry_size + 8 B)`,
//! `Vec` heap as `capacity` not `len`) -- the goal is identifying the dominant
//! memory grower across a long-running corpus, not a VM-page-accurate audit.
//!
//! Each store carries its own `approx_bytes()` method so the formula stays
//! co-located with the type. `print_report` aggregates the per-store
//! contributions into a single closing block, sorted descending by size with
//! the all-stores total on the last row.
//!
//! Off by default to keep the closing summary concise; opt in with
//! `--mem-stats`.

use std::io::Write as _;

use crate::store::auxiliary::{
    DeviceInfoStore, EssidSet, IdentitySet, ProbeEssidSet, UsernameSet, WordlistScanIesStore, WordlistStore,
};
use crate::store::essid::EssidMap;
use crate::store::fragments::FragmentStore;
use crate::store::messages::MessageStore;
use crate::store::pmkid::PmkidStore;
use crate::store::{AkmMap, MldStore};

/// Aggregates each store's per-row figures into a single owned vector.
///
/// `print_report` can then sort + format without re-borrowing the stores. The
/// `entries` value is the store's domain-meaningful "row count" -- pairs for
/// `MessageStore`, MAC keys for `AkmMap` (sum of both inner maps), distinct
/// strings for the auxiliary sets, etc.
#[allow(clippy::too_many_arguments, reason = "report aggregator: one parameter per long-lived store")]
#[must_use]
pub fn collect(
    message_store: &MessageStore,
    pmkid_store: &PmkidStore,
    essid_map: &EssidMap,
    akm_map: &AkmMap,
    mld_store: &MldStore,
    essid_set: &EssidSet,
    probe_essid_set: &ProbeEssidSet,
    wordlist_store: &WordlistStore,
    scan_ies_store: &WordlistScanIesStore,
    identity_set: &IdentitySet,
    username_set: &UsernameSet,
    device_store: &DeviceInfoStore,
    fragment_store: &FragmentStore,
) -> Vec<(&'static str, usize, usize)> {
    vec![
        ("MessageStore (EAPOL groups)", message_store.group_count(), message_store.approx_bytes()),
        ("PmkidStore", pmkid_store.total_count(), pmkid_store.approx_bytes()),
        ("EssidMap", essid_map.ap_count(), essid_map.approx_bytes()),
        ("AkmMap", akm_map.entry_count(), akm_map.approx_bytes()),
        ("MldStore", mld_store.len(), mld_store.approx_bytes()),
        ("EssidSet (-E)", essid_set.len(), essid_set.approx_bytes()),
        ("ProbeEssidSet (-R)", probe_essid_set.len(), probe_essid_set.approx_bytes()),
        ("WordlistStore (-W)", wordlist_store.len(), wordlist_store.approx_bytes()),
        ("WordlistScanIesStore (--wordlist-scan-ies)", scan_ies_store.len(), scan_ies_store.approx_bytes()),
        ("IdentitySet (-I)", identity_set.len(), identity_set.approx_bytes()),
        ("UsernameSet (-U)", username_set.len(), username_set.approx_bytes()),
        ("DeviceInfoStore (-D)", device_store.len(), device_store.approx_bytes()),
        ("FragmentStore", fragment_store.len(), fragment_store.approx_bytes()),
    ]
}

/// Formats `bytes` as a human-readable size (B / KiB / MiB / GiB) with one
/// decimal place. Avoids a third-party dep; the formatter is cheap and
/// deterministic.
fn format_bytes(bytes: usize) -> String {
    const KIB: usize = 1024;
    const MIB: usize = KIB * 1024;
    const GIB: usize = MIB * 1024;
    if bytes >= GIB {
        // u128 cast: bytes <= usize::MAX so the multiply cannot overflow on
        // any platform wpawolf supports (usize >= u32 ; bytes/GIB fits u32 by
        // construction). Float cast accepts the small precision loss.
        #[allow(clippy::cast_precision_loss, reason = "MiB-precision display value")]
        let v = bytes as f64 / GIB as f64;
        format!("{v:.1} GiB")
    } else if bytes >= MIB {
        #[allow(clippy::cast_precision_loss, reason = "MiB-precision display value")]
        let v = bytes as f64 / MIB as f64;
        format!("{v:.1} MiB")
    } else if bytes >= KIB {
        #[allow(clippy::cast_precision_loss, reason = "KiB-precision display value")]
        let v = bytes as f64 / KIB as f64;
        format!("{v:.1} KiB")
    } else {
        format!("{bytes} B")
    }
}

/// Prints a stderr block of per-store byte counts, sorted by descending size.
///
/// Output is bracketed with the same `=== Phase ... ===` banner style as
/// `Stats::print_summary` so the operator sees one continuous closing report.
/// Called from `main` after `stats.print_summary` when `--mem-stats` is set.
pub fn print_report(rows: &[(&'static str, usize, usize)]) {
    let mut sorted = rows.to_vec();
    sorted.sort_by_key(|r| std::cmp::Reverse(r.2));
    let total: usize = rows.iter().map(|(_, _, b)| *b).sum();

    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "=== Memory stats (--mem-stats) ===============================");
    let _ = writeln!(out, "{:<46}{:>14}{:>14}", "store", "entries", "approx_bytes");
    for (name, entries, bytes) in &sorted {
        let _ = writeln!(out, "{name:<46}{entries:>14}{:>14}", format_bytes(*bytes));
    }
    let _ = writeln!(out, "{:<46}{:>14}{:>14}", "TOTAL", "", format_bytes(total));
    let _ = out.flush();
}

// --- Unit tests ---

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        missing_docs,
        clippy::wildcard_imports,
        reason = "test module"
    )]

    use super::*;

    #[test]
    fn format_bytes_thresholds() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(2 * 1024), "2.0 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
    }

    #[test]
    fn collect_returns_one_row_per_store() {
        let message_store = MessageStore::new();
        let pmkid_store = PmkidStore::new();
        let essid_map = EssidMap::new();
        let akm_map = AkmMap::new();
        let mld_store = MldStore::new();
        let essid_set = EssidSet::new();
        let probe_essid_set = ProbeEssidSet::new();
        let wordlist_store = WordlistStore::new();
        let scan_ies_store = WordlistScanIesStore::new();
        let identity_set = IdentitySet::new();
        let username_set = UsernameSet::new();
        let device_store = DeviceInfoStore::new();
        let fragment_store = FragmentStore::new();

        let rows = collect(
            &message_store,
            &pmkid_store,
            &essid_map,
            &akm_map,
            &mld_store,
            &essid_set,
            &probe_essid_set,
            &wordlist_store,
            &scan_ies_store,
            &identity_set,
            &username_set,
            &device_store,
            &fragment_store,
        );

        // Every store is represented; entry counts on a fresh set of stores are zero.
        assert_eq!(rows.len(), 13);
        for (_name, entries, _bytes) in &rows {
            assert_eq!(*entries, 0);
        }
    }
}
