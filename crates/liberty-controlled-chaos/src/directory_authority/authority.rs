//! `AuthorityIdentity` and `SignedNodeDescriptor`.
//!
//! NON-PRODUCTION: signatures are HMAC-SHA256(private_key, message_bytes).

use crate::crypto::{hmac_sha256, sha256};
use crate::node_descriptor::NodeDescriptor;
use crate::node_identity::NodeIdentity;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum AuthorityError {
    /// A descriptor for this node_id is already present.
    DuplicateNodeId([u8; 32]),
    /// The epoch is older than or equal to the current consensus epoch.
    StaleEpoch(u64),
    /// The signature on a descriptor does not verify.
    InvalidDescriptorSignature,
    /// The signature on a consensus document does not verify.
    InvalidConsensusSignature,
}

impl std::fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorityError::DuplicateNodeId(id) => {
                write!(f, "duplicate node_id: {}", hex_short(id))
            }
            AuthorityError::StaleEpoch(e) => write!(f, "stale epoch {e}"),
            AuthorityError::InvalidDescriptorSignature => write!(f, "invalid descriptor signature"),
            AuthorityError::InvalidConsensusSignature => write!(f, "invalid consensus signature"),
        }
    }
}

fn hex_short(b: &[u8; 32]) -> String {
    b[..4].iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Signing helpers  (NON-PRODUCTION)
// ---------------------------------------------------------------------------

/// Sign `data` with `private_key` using HMAC-SHA256.
///
/// NON-PRODUCTION: a real implementation would use Ed25519.
pub(crate) fn sign(private_key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    hmac_sha256(private_key, data)
}

/// Verify a signature produced by `sign`.
///
/// Requires the private key, so verification is only possible by the authority itself.
/// NON-PRODUCTION.
pub(crate) fn verify(private_key: &[u8; 32], data: &[u8], expected: &[u8; 32]) -> bool {
    &sign(private_key, data) == expected
}

// ---------------------------------------------------------------------------
// SignedNodeDescriptor
// ---------------------------------------------------------------------------

/// A `NodeDescriptor` with an authority signature.
#[derive(Debug, Clone)]
pub struct SignedNodeDescriptor {
    pub descriptor: NodeDescriptor,
    /// HMAC-SHA256(authority_private_key, descriptor_bytes) — NON-PRODUCTION.
    pub signature: [u8; 32],
    /// `node_id` of the authority that signed this descriptor.
    pub authority_id: [u8; 32],
}

impl SignedNodeDescriptor {
    /// Serialise the descriptor into bytes for signing/verification.
    fn descriptor_bytes(desc: &NodeDescriptor) -> Vec<u8> {
        let mut b = Vec::with_capacity(96);
        b.extend_from_slice(&desc.node_id);
        b.extend_from_slice(&desc.public_key);
        // address: encode as a fixed 18-byte block (16 IP + 2 port).
        let ip_bytes = match desc.address.ip() {
            std::net::IpAddr::V4(v4) => {
                let mut buf = [0u8; 16];
                buf[..4].copy_from_slice(&v4.octets());
                buf
            }
            std::net::IpAddr::V6(v6) => v6.octets(),
        };
        b.extend_from_slice(&ip_bytes);
        b.extend_from_slice(&desc.address.port().to_le_bytes());
        b
    }

    /// Verify this descriptor against `authority`.
    ///
    /// Returns `true` if the signature is valid.
    pub fn verify(&self, authority: &AuthorityIdentity) -> bool {
        if self.authority_id != authority.identity.node_id {
            return false;
        }
        let msg = Self::descriptor_bytes(&self.descriptor);
        verify(&authority.identity.private_key, &msg, &self.signature)
    }

    /// Hash this descriptor (used for consensus-level signing).
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut b = Self::descriptor_bytes(&self.descriptor);
        b.extend_from_slice(&self.signature);
        sha256(&b)
    }
}

// ---------------------------------------------------------------------------
// AuthorityIdentity
// ---------------------------------------------------------------------------

/// A directory authority: a node that can sign descriptors and publish consensus.
#[derive(Clone)]
pub struct AuthorityIdentity {
    /// The authority's own long-term identity.
    pub identity: NodeIdentity,
}

impl AuthorityIdentity {
    /// Create an authority from an existing `NodeIdentity`.
    pub fn new(identity: NodeIdentity) -> Self {
        Self { identity }
    }

    /// Sign a `NodeDescriptor`, producing a `SignedNodeDescriptor`.
    pub fn sign_descriptor(&self, descriptor: NodeDescriptor) -> SignedNodeDescriptor {
        let msg = SignedNodeDescriptor::descriptor_bytes(&descriptor);
        let signature = sign(&self.identity.private_key, &msg);
        SignedNodeDescriptor {
            descriptor,
            signature,
            authority_id: self.identity.node_id,
        }
    }

    /// Verify a descriptor signed by this authority.
    pub fn verify_descriptor(&self, signed: &SignedNodeDescriptor) -> bool {
        signed.verify(self)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::node_identity::NodeIdentity;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn authority(seed: u8) -> AuthorityIdentity {
        AuthorityIdentity::new(NodeIdentity::generate_from_seed([seed; 32]))
    }

    fn descriptor(seed: u8) -> NodeDescriptor {
        let pk = NodeIdentity::generate_from_seed([seed; 32]).public_key;
        NodeDescriptor::new(pk, addr(9000 + seed as u16))
    }

    // DA1: sign_descriptor produces a verifiable signature.
    #[test]
    fn da1_sign_and_verify() {
        let auth = authority(0x01);
        let signed = auth.sign_descriptor(descriptor(0x02));
        assert!(auth.verify_descriptor(&signed));
    }

    // DA2: tampered descriptor body fails verification.
    #[test]
    fn da2_tampered_descriptor_rejected() {
        let auth = authority(0x03);
        let mut signed = auth.sign_descriptor(descriptor(0x04));
        signed.descriptor.node_id[0] ^= 0xFF;
        assert!(!auth.verify_descriptor(&signed));
    }

    // DA3: tampered signature fails verification.
    #[test]
    fn da3_tampered_signature_rejected() {
        let auth = authority(0x05);
        let mut signed = auth.sign_descriptor(descriptor(0x06));
        signed.signature[0] ^= 0xFF;
        assert!(!auth.verify_descriptor(&signed));
    }

    // DA4: wrong authority fails verification.
    #[test]
    fn da4_wrong_authority_rejected() {
        let auth1 = authority(0x07);
        let auth2 = authority(0x08);
        let signed = auth1.sign_descriptor(descriptor(0x09));
        // auth2 has a different node_id, so authority_id check fails.
        assert!(!auth2.verify_descriptor(&signed));
    }

    // DA5: authority_id field matches the authority's node_id.
    #[test]
    fn da5_authority_id_matches() {
        let auth = authority(0x0A);
        let signed = auth.sign_descriptor(descriptor(0x0B));
        assert_eq!(signed.authority_id, auth.identity.node_id);
    }
}
