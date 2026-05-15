//! Shared -- crate root (used by binary `main.rs` and integration tests). See ARCHITECTURE.md §3.
//!
//! Reads pcap, pcapng, and gzip-compressed captures, extracts EAPOL 4-way handshakes
//! and PMKIDs, and writes hashcat-compatible hash lines. See `ARCHITECTURE.md §3` for the
//! full architecture and `ARCHITECTURE.md §8` for the wire-level behaviour contract.

#![forbid(unsafe_code)]

// clap is used only by the binary (src/main.rs). Suppress the unused_crate_dependencies
// lint that fires on the library compilation unit because both targets share [dependencies].
use clap as _;

pub mod debug;
pub mod extract;
pub mod ieee80211;
pub mod input;
pub mod link;
pub mod log;
pub mod mem_stats;
pub mod output;
pub mod pair;
pub mod progress;
pub mod stats;
pub mod store;
pub mod strings_scan;
pub mod types;
