//! Directory authority — signs node descriptors and produces epoch consensus documents.
//!
//! NON-PRODUCTION: signatures are HMAC-SHA256(private_key, message).
//! Real deployment requires Ed25519 or similar asymmetric signing.

mod authority;
mod consensus;

pub use authority::{AuthorityError, AuthorityIdentity, SignedNodeDescriptor};
pub use consensus::{ConsensusError, DirectoryConsensus};
