//! Cryptographic primitives for Liberty Shield.
//!
//! All implementations are pure Rust, zero external dependencies.
//!
//! # Architecture
//!
//! ```text
//! hkdf (+ sha256) ─────────────► session_keys
//!                                      │
//! chacha20 ──┐                         │  encrypt_packet / decrypt_packet
//!            ├──► aead ────────────────┘
//! poly1305 ──┘
//! ```
//!
//! # Usage
//!
//! ```rust
//! use liberty_controlled_chaos::crypto::SessionKeys;
//! // Symmetric session: both sides share the same key (test only).
//! let key = [0xABu8; 32];
//! let mut sender = SessionKeys::new(key, key);
//! let receiver = SessionKeys::new(key, key);
//! let ct = sender.encrypt_packet(b"aad", b"hello").unwrap();
//! let plain = receiver.decrypt_packet(b"aad", 0, &ct).unwrap();
//! assert_eq!(&plain, b"hello");
//! ```

mod aead;
mod chacha20;
mod hkdf;
mod poly1305;
mod session_keys;
mod sha256;

pub use aead::{AeadError, aead_open, aead_seal};
pub use hkdf::{derive_session_keys, hkdf, hkdf_expand, hkdf_extract};
pub use session_keys::{MAX_SEQUENCE, SessionError, SessionKeys};
pub use sha256::{hmac_sha256, sha256};
