//! 802.11 management frame, EAPOL-Key, and KDE builders.
//!
//! Each submodule is named after the frame family it produces. Wire constants
//! are cited inline; cross-cutting bit definitions (Frame Control flags, Key
//! Information bits) live in [`mac`] and [`eapol`] respectively.

pub mod action;
pub mod assoc;
pub mod auth;
pub mod beacon;
pub mod eapol;
pub mod ie;
pub mod kde;
pub mod mac;
pub mod probe;
