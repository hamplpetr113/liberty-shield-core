//! Node identity — long-term X25519 keypair and SHA-256 derived node ID.
//!
//! # Usage
//!
//! ```rust,ignore
//! use liberty_controlled_chaos::node_identity::{NodeIdentity, NodeIdentityStore};
//!
//! // Generate once and persist.
//! let store = NodeIdentityStore::new("node_identity.json");
//! let identity = store.load_or_generate().unwrap();
//! println!("node_id: {:?}", identity.node_id);
//! ```

pub mod identity;
pub mod store;

pub use identity::{IdentityError, NodeIdentity};
pub use store::{NodeIdentityStore, StoreError};
