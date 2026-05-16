//! Phase 3 -- Extract: frame-handler entry points (dispatched per 802.11 subtype). See ARCHITECTURE.md §3.3.

pub mod action;
pub mod assoc;
pub mod auth;
pub mod beacon;
pub mod common;
pub mod data;
pub mod mgmt;
pub mod probe;
pub mod wds;

pub use action::process_action;
pub use assoc::process_assoc_or_reassoc_req;
pub use auth::{process_auth_fils, process_auth_ft, process_auth_pasn};
pub use beacon::process_beacon_or_probe_resp;
pub use data::process_data;
pub use mgmt::process_mgmt;
pub use probe::process_probe_req;
pub use wds::resolve_wds_eapol;

/// Per-frame extraction toggles derived from the CLI output flags.
///
/// `process_mgmt` and `process_data` consult these bools to decide which sinks
/// (wordlist, device-info store, identity / username sets) to populate. Bundled
/// into a struct so the extract module does not depend on the binary's `Cli`
/// type (which lives in `src/main.rs`).
#[derive(Debug, Clone, Copy)]
pub struct ExtractConfig {
    /// `-W` requested: populate `WordlistStore` from every available source.
    pub populate_wordlist: bool,
    /// `-D` requested: populate `DeviceInfoStore` from beacon/probe-resp WPS IEs.
    pub populate_device: bool,
    /// `-I` requested: populate `IdentitySet` from EAP Identity frames.
    pub populate_identity: bool,
    /// `-U` requested: populate `UsernameSet` from EAP inner-method identities.
    pub populate_username: bool,
    /// `--wordlist-scan-ies`: opportunistically scan management-frame IE bodies
    /// for printable-ASCII runs and add them to the wordlist.
    pub scan_ies: bool,
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
    fn extract_config_construction_and_copy() {
        // ExtractConfig is `Copy + Debug`; the binary builds one per run from the
        // CLI flags and passes it down by value to every `process_*`. The copy
        // semantics are load-bearing because the dispatch layer does not borrow
        // the config across the `process_data` / `process_mgmt` call chain.
        let cfg = ExtractConfig {
            populate_wordlist: true,
            populate_device: false,
            populate_identity: true,
            populate_username: false,
            scan_ies: true,
        };
        let copied = cfg;
        assert!(copied.populate_wordlist);
        assert!(!copied.populate_device);
        assert!(copied.populate_identity);
        assert!(!copied.populate_username);
        assert!(copied.scan_ies);
        // Original still usable -> Copy semantics confirmed.
        assert!(cfg.populate_wordlist);
    }

    #[test]
    fn extract_config_all_off() {
        // Default-shape "no aux output requested" config: every flag false. The
        // `process_*` functions short-circuit each aux branch on this shape, so
        // it is the cheap-path baseline and worth pinning in tests.
        let cfg = ExtractConfig {
            populate_wordlist: false,
            populate_device: false,
            populate_identity: false,
            populate_username: false,
            scan_ies: false,
        };
        assert!(!cfg.populate_wordlist);
        assert!(!cfg.populate_device);
        assert!(!cfg.populate_identity);
        assert!(!cfg.populate_username);
        assert!(!cfg.scan_ies);
    }
}
