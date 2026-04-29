//! Persistent security state — append-only binary journal for replay and
//! rekey protection state that survives node restart.
//!
//! # Usage
//!
//! ```rust,ignore
//! use liberty_controlled_chaos::security_state::{SecurityStateStore, restore_replay_window};
//!
//! // On startup: load prior state.
//! let entries = SecurityStateStore::load_all("security_state.log").unwrap();
//! let window  = restore_replay_window(&entries, circuit_id);
//!
//! // Open for appending.
//! let mut store = SecurityStateStore::open("security_state.log").unwrap();
//! store.record_packet(circuit_id, sequence).unwrap();
//! ```

pub mod store;
pub mod types;

pub use store::{
    SecurityStateStore, StoreError, restore_nonce_store, restore_replay_window,
    restore_transport_filter,
};
pub use types::{
    ENTRY_REKEY_NONCE_SEEN, ENTRY_SESSION_REPLAY_UPDATE, ENTRY_TRANSPORT_PACKET_SEEN,
    SecurityStateEntry,
};
