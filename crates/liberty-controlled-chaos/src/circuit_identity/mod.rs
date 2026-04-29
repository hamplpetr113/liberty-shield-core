//! Circuit identity — cryptographic binding of a circuit to its two endpoints.
//!
//! # Usage
//!
//! ```rust,ignore
//! use liberty_controlled_chaos::circuit_identity::CircuitIdentity;
//!
//! let id = CircuitIdentity::generate(&local_node_id, &peer_node_id, nonce);
//! pipeline.register_circuit_with_identity(id.circuit_id, send, recv, id)?;
//! ```

pub mod circuit_id;

pub use circuit_id::{CircuitIdentity, CollisionError};
