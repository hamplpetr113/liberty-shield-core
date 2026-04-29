//! Mesh node descriptors, peer table, and in-memory handshake protocol.
//!
//! # Usage
//!
//! ```rust,ignore
//! use liberty_controlled_chaos::node_descriptor::{
//!     NodeDescriptor, PeerTable, perform_handshake,
//! };
//! use liberty_controlled_chaos::node_identity::NodeIdentity;
//!
//! let id_a = NodeIdentity::generate();
//! let id_b = NodeIdentity::generate();
//! let result = perform_handshake(&id_a, "127.0.0.1:8001".parse().unwrap(),
//!                                &id_b, "127.0.0.1:8002".parse().unwrap(), 1)?;
//! // register result.initiator_keys / result.responder_keys into pipelines
//! ```

pub mod descriptor;
pub mod handshake;
pub mod peer_table;

pub use descriptor::NodeDescriptor;
pub use handshake::{
    HandshakeError, HandshakeInit, HandshakeResponse, HandshakeResult, perform_handshake,
};
pub use peer_table::PeerTable;
