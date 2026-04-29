//! Onion circuit construction and key negotiation.
//!
//! Provides an X25519-based per-hop handshake and a session rekey protocol
//! for long-running circuits.

pub mod handshake;
pub mod rekey;

pub use handshake::{
    HandshakeError, HandshakeResult, HandshakeState, HopHandshakeParams, HopPublicKey,
    build_circuit_keys, complete_handshake, generate_public_key,
};
