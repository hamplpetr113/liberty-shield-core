//! Encrypted relay cells — ChaCha20-Poly1305 secured relay protocol.
//!
//! Combines `SessionKeys` from the `crypto` module with per-hop replay
//! protection to produce authenticated, encrypted relay cells.
//!
//! # Layer position
//!
//! ```text
//! Application
//!     │
//! RelayCellPlaintext  ← typed relay command + payload
//!     │  seal / open
//! EncryptedRelayCell  ← ChaCha20-Poly1305 + AAD(circuit, stream)
//!     │  to_wire / from_wire
//! [Transport / OnionLayer]
//! ```

mod cell;
mod errors;
mod pipeline;
mod types;

pub use cell::EncryptedRelayCell;
pub use errors::EncryptedRelayError;
pub use pipeline::{PipelineResult, RelayPipeline};
pub use types::{MAX_RELAY_PAYLOAD, RELAY_HEADER_SIZE, RelayCellCommand, RelayCellPlaintext};
