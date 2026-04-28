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
#[allow(clippy::struct_excessive_bools, reason = "independent CLI extraction flags, not a state machine")]
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
