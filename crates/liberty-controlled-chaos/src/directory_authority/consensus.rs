//! `DirectoryConsensus` — an epoch-stamped list of signed node descriptors.
//!
//! NON-PRODUCTION: the consensus signature uses HMAC-SHA256(private_key, body).

use std::collections::HashSet;

use super::authority::{AuthorityIdentity, SignedNodeDescriptor, sign, verify};

// ---------------------------------------------------------------------------
// ConsensusError
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum ConsensusError {
    /// A descriptor for this node_id was already added to this consensus.
    DuplicateNodeId([u8; 32]),
    /// The proposed epoch is not newer than the current consensus epoch.
    StaleEpoch { current: u64, proposed: u64 },
    /// Signature verification failed.
    InvalidSignature,
}

impl std::fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusError::DuplicateNodeId(_) => write!(f, "duplicate node_id in consensus"),
            ConsensusError::StaleEpoch { current, proposed } => {
                write!(f, "stale epoch: proposed {proposed} <= current {current}")
            }
            ConsensusError::InvalidSignature => write!(f, "consensus signature invalid"),
        }
    }
}

// ---------------------------------------------------------------------------
// DirectoryConsensus
// ---------------------------------------------------------------------------

/// A signed directory consensus for one epoch.
///
/// Produced by an `AuthorityIdentity`; verified by any holder of the same
/// authority (which has the private key in this NON-PRODUCTION scheme).
#[derive(Debug, Clone)]
pub struct DirectoryConsensus {
    /// Epoch number — must strictly increase across consensus documents.
    pub epoch: u64,
    /// Signed node descriptors included in this consensus.
    pub descriptors: Vec<SignedNodeDescriptor>,
    /// `node_id` of the authority that produced this consensus.
    pub authority_id: [u8; 32],
    /// HMAC-SHA256(authority_private_key, consensus_body) — NON-PRODUCTION.
    pub signature: [u8; 32],
}

impl DirectoryConsensus {
    /// Start building a new consensus for `epoch` under `authority`.
    ///
    /// `epoch` must be strictly greater than `previous_epoch` (pass 0 for the
    /// first consensus).
    pub fn begin(
        authority: &AuthorityIdentity,
        epoch: u64,
        previous_epoch: u64,
    ) -> Result<DirectoryConsensusBuilder, ConsensusError> {
        if epoch <= previous_epoch {
            return Err(ConsensusError::StaleEpoch {
                current: previous_epoch,
                proposed: epoch,
            });
        }
        Ok(DirectoryConsensusBuilder {
            authority_id: authority.identity.node_id,
            epoch,
            descriptors: Vec::new(),
            seen_node_ids: HashSet::new(),
        })
    }

    /// Verify the consensus signature using `authority`.
    ///
    /// Returns `true` if the signature is valid and the authority_id matches.
    pub fn verify(&self, authority: &AuthorityIdentity) -> bool {
        if self.authority_id != authority.identity.node_id {
            return false;
        }
        let body = self.body_bytes();
        verify(&authority.identity.private_key, &body, &self.signature)
    }

    /// Compute the canonical byte representation of the consensus body.
    fn body_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.epoch.to_le_bytes());
        b.extend_from_slice(&self.authority_id);
        // Hash each descriptor digest into the body so insertion order is stable.
        for sd in &self.descriptors {
            b.extend_from_slice(&sd.digest());
        }
        b
    }
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Accumulates descriptors and finalises a `DirectoryConsensus`.
#[derive(Debug)]
pub struct DirectoryConsensusBuilder {
    authority_id: [u8; 32],
    epoch: u64,
    descriptors: Vec<SignedNodeDescriptor>,
    seen_node_ids: HashSet<[u8; 32]>,
}

impl DirectoryConsensusBuilder {
    /// Add a signed descriptor; rejects duplicate node_ids.
    pub fn add_descriptor(&mut self, signed: SignedNodeDescriptor) -> Result<(), ConsensusError> {
        let node_id = signed.descriptor.node_id;
        if self.seen_node_ids.contains(&node_id) {
            return Err(ConsensusError::DuplicateNodeId(node_id));
        }
        self.seen_node_ids.insert(node_id);
        self.descriptors.push(signed);
        Ok(())
    }

    /// Finalise and sign the consensus, producing a `DirectoryConsensus`.
    pub fn finalise(self, authority: &AuthorityIdentity) -> DirectoryConsensus {
        let mut doc = DirectoryConsensus {
            epoch: self.epoch,
            descriptors: self.descriptors,
            authority_id: self.authority_id,
            signature: [0u8; 32],
        };
        let body = doc.body_bytes();
        doc.signature = sign(&authority.identity.private_key, &body);
        doc
    }

    /// Number of descriptors added so far.
    pub fn len(&self) -> usize {
        self.descriptors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.descriptors.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::directory_authority::AuthorityIdentity;
    use crate::node_descriptor::NodeDescriptor;
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

    fn signed(auth: &AuthorityIdentity, seed: u8) -> SignedNodeDescriptor {
        auth.sign_descriptor(descriptor(seed))
    }

    // DC1: empty consensus builds and verifies.
    #[test]
    fn dc1_empty_consensus() {
        let auth = authority(0x10);
        let builder = DirectoryConsensus::begin(&auth, 1, 0).unwrap();
        let doc = builder.finalise(&auth);
        assert!(doc.verify(&auth));
        assert_eq!(doc.epoch, 1);
        assert!(doc.descriptors.is_empty());
    }

    // DC2: consensus with descriptors verifies.
    #[test]
    fn dc2_with_descriptors() {
        let auth = authority(0x11);
        let mut builder = DirectoryConsensus::begin(&auth, 1, 0).unwrap();
        builder.add_descriptor(signed(&auth, 0xA0)).unwrap();
        builder.add_descriptor(signed(&auth, 0xA1)).unwrap();
        let doc = builder.finalise(&auth);
        assert!(doc.verify(&auth));
        assert_eq!(doc.descriptors.len(), 2);
    }

    // DC3: stale epoch is rejected.
    #[test]
    fn dc3_stale_epoch_rejected() {
        let auth = authority(0x12);
        assert_eq!(
            DirectoryConsensus::begin(&auth, 5, 5).unwrap_err(),
            ConsensusError::StaleEpoch {
                current: 5,
                proposed: 5
            }
        );
        assert_eq!(
            DirectoryConsensus::begin(&auth, 3, 5).unwrap_err(),
            ConsensusError::StaleEpoch {
                current: 5,
                proposed: 3
            }
        );
    }

    // DC4: duplicate node_id in same consensus is rejected.
    #[test]
    fn dc4_duplicate_node_id_rejected() {
        let auth = authority(0x13);
        let mut builder = DirectoryConsensus::begin(&auth, 1, 0).unwrap();
        let s = signed(&auth, 0xB0);
        builder.add_descriptor(s.clone()).unwrap();
        assert_eq!(
            builder.add_descriptor(s).unwrap_err(),
            ConsensusError::DuplicateNodeId(descriptor(0xB0).node_id)
        );
    }

    // DC5: tampered consensus signature fails verify.
    #[test]
    fn dc5_tampered_signature_rejected() {
        let auth = authority(0x14);
        let builder = DirectoryConsensus::begin(&auth, 1, 0).unwrap();
        let mut doc = builder.finalise(&auth);
        doc.signature[0] ^= 0xFF;
        assert!(!doc.verify(&auth));
    }

    // DC6: wrong authority fails verify.
    #[test]
    fn dc6_wrong_authority_rejected() {
        let auth1 = authority(0x15);
        let auth2 = authority(0x16);
        let builder = DirectoryConsensus::begin(&auth1, 1, 0).unwrap();
        let doc = builder.finalise(&auth1);
        assert!(!doc.verify(&auth2));
    }

    // DC7: each epoch must be strictly greater than the previous.
    #[test]
    fn dc7_epoch_must_advance() {
        let auth = authority(0x17);
        assert!(DirectoryConsensus::begin(&auth, 10, 9).is_ok());
        assert!(DirectoryConsensus::begin(&auth, 10, 10).is_err());
        assert!(DirectoryConsensus::begin(&auth, 9, 10).is_err());
    }

    // DC8: descriptor digests differ for different descriptors.
    #[test]
    fn dc8_descriptor_digest_unique() {
        let auth = authority(0x18);
        let s1 = signed(&auth, 0xC0);
        let s2 = signed(&auth, 0xC1);
        assert_ne!(s1.digest(), s2.digest());
    }

    // DC9: builder len and is_empty reflect additions.
    #[test]
    fn dc9_builder_len() {
        let auth = authority(0x19);
        let mut builder = DirectoryConsensus::begin(&auth, 1, 0).unwrap();
        assert!(builder.is_empty());
        builder.add_descriptor(signed(&auth, 0xD0)).unwrap();
        assert_eq!(builder.len(), 1);
        builder.add_descriptor(signed(&auth, 0xD1)).unwrap();
        assert_eq!(builder.len(), 2);
    }

    // DC10: consensus body changes when a descriptor is added.
    #[test]
    fn dc10_body_changes_with_descriptor() {
        let auth = authority(0x1A);
        let b1 = DirectoryConsensus::begin(&auth, 1, 0).unwrap();
        let doc_empty = b1.finalise(&auth);

        let mut b2 = DirectoryConsensus::begin(&auth, 1, 0).unwrap();
        b2.add_descriptor(signed(&auth, 0xE0)).unwrap();
        let doc_with = b2.finalise(&auth);

        assert_ne!(doc_empty.signature, doc_with.signature);
    }
}
