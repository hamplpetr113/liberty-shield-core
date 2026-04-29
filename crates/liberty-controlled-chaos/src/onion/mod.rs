//! Onion circuit construction and key negotiation.
//!
//! Currently provides a simplified HKDF-based handshake framework.
//! Designed to be upgraded to NTor (X25519 + BLAKE2s) in a future sprint
//! without changing the external interface.

pub mod handshake;

pub use handshake::{
    HandshakeError, HandshakeResult, HandshakeState, HopHandshakeParams, HopPublicKey,
    build_circuit_keys, complete_handshake, generate_public_key,
};
