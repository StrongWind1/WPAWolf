//! Phase 2 -- Decode: 802.11 frame-type dispatch (mgmt / data / ctrl). See ARCHITECTURE.md §3.2 + §8.3.
//!
//! Routes incoming raw 802.11 frames to management, control, or data frame handlers based
//! on the Type (bits B2-B3) and Subtype (bits B4-B7) fields of the 2-byte Frame Control
//! field (IEEE 802.11-2024 §9.2.4.1, Figure 9-3). Management and data frames are fully
//! parsed; control frames are counted and skipped.

pub mod amsdu;
pub mod anqp;
pub mod eap;
pub mod eapol;
pub mod frame;
pub mod ft;
pub mod ie;
pub mod rsn;
