//! NoiseLink — encrypts `Cell` values into fixed-size `EncryptedCell` values.
//!
//! Sits between `CellEncoder` and `UDPTransport`.
//!
//! Current implementation: ChaCha8-XOR + SipHash-2-4-128 AEAD placeholder.
//! NON-PRODUCTION: replace cipher+MAC with `chacha20poly1305` crate (RFC 8439)
//! before real networking.
//!
//! `NoiseLink` never opens sockets, never inspects payload semantics, and
//! contains no unsafe code.

mod link_encryptor;
mod noise_session;
pub mod types;

pub use link_encryptor::NoiseLinkEncoder;
pub use noise_session::NoiseSession;
pub use types::{ENCRYPTED_CELL_SIZE, EncryptedCell, NoiseError, NoiseNonce};
