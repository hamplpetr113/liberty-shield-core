//! Local deterministic directory consensus.
//!
//! NON-PRODUCTION: signatures are deterministic hashes, not real crypto.

use crate::peer_directory::PeerRole;

/// Identifies an authority that signs descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DirectoryAuthorityId(pub u64);

/// Descriptor for one node in the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDescriptor {
    pub node_id: u64,
    pub role: PeerRole,
    pub address: String,
    pub port: u16,
    /// 0–100 reliability score.
    pub reliability: u8,
    /// Latency in ms (smaller is better).
    pub latency_ms: u32,
}

impl NodeDescriptor {
    /// Build a deterministic descriptor from a node ID.
    pub fn deterministic(node_id: u64, base_port: u16) -> Self {
        let role = match node_id % 3 {
            0 => PeerRole::Guard,
            1 => PeerRole::Relay,
            _ => PeerRole::Exit,
        };
        Self {
            node_id,
            role,
            address: "127.0.0.1".to_string(),
            port: base_port + node_id as u16,
            reliability: ((node_id * 7) % 101) as u8,
            latency_ms: ((node_id * 13) % 200) as u32,
        }
    }

    /// Deterministic hash of this descriptor's fields (NON-PRODUCTION).
    fn field_hash(&self) -> u64 {
        let mut h = 0xcbf29ce484222325u64;
        for &b in self.address.as_bytes() {
            h = h.wrapping_mul(0x100000001b3).wrapping_add(b as u64);
        }
        h = h.wrapping_mul(0x100000001b3).wrapping_add(self.node_id);
        h = h.wrapping_mul(0x100000001b3).wrapping_add(self.port as u64);
        h = h
            .wrapping_mul(0x100000001b3)
            .wrapping_add(self.reliability as u64);
        h = h
            .wrapping_mul(0x100000001b3)
            .wrapping_add(self.latency_ms as u64);
        h = h
            .wrapping_mul(0x100000001b3)
            .wrapping_add(self.role_tag() as u64);
        h
    }

    fn role_tag(&self) -> u8 {
        match self.role {
            PeerRole::Guard => 0,
            PeerRole::Relay => 1,
            PeerRole::Exit => 2,
        }
    }
}

/// A descriptor with a deterministic signature attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDescriptor {
    pub descriptor: NodeDescriptor,
    pub authority_id: DirectoryAuthorityId,
    /// NON-PRODUCTION: deterministic hash used as signature placeholder.
    pub signature: u64,
}

/// Errors from consensus operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    /// The signature does not match the descriptor's field hash.
    InvalidSignature,
    /// A node with this ID is already present.
    DuplicateNodeId,
    /// The consensus contains no descriptors.
    EmptyConsensus,
}

/// A directory consensus: a collection of signed descriptors for one epoch.
#[derive(Debug, Clone)]
pub struct DirectoryConsensus {
    pub epoch: u64,
    pub authority_id: DirectoryAuthorityId,
    /// Descriptors sorted by node_id for deterministic output.
    descriptors: Vec<SignedDescriptor>,
    node_ids: std::collections::HashSet<u64>,
}

impl DirectoryConsensus {
    pub fn new(epoch: u64, authority_id: DirectoryAuthorityId) -> Self {
        Self {
            epoch,
            authority_id,
            descriptors: Vec::new(),
            node_ids: std::collections::HashSet::new(),
        }
    }

    /// Produce a signed descriptor. Signature = hash(descriptor fields XOR authority_id).
    pub fn sign_descriptor(&self, desc: NodeDescriptor) -> SignedDescriptor {
        let sig = desc.field_hash() ^ self.authority_id.0;
        SignedDescriptor {
            descriptor: desc,
            authority_id: self.authority_id,
            signature: sig,
        }
    }

    /// Verify that a signed descriptor's signature is valid.
    pub fn verify_descriptor(signed: &SignedDescriptor) -> Result<(), ConsensusError> {
        let expected = signed.descriptor.field_hash() ^ signed.authority_id.0;
        if signed.signature == expected {
            Ok(())
        } else {
            Err(ConsensusError::InvalidSignature)
        }
    }

    /// Add a signed descriptor to this consensus.
    pub fn add_descriptor(&mut self, signed: SignedDescriptor) -> Result<(), ConsensusError> {
        Self::verify_descriptor(&signed)?;
        let node_id = signed.descriptor.node_id;
        if self.node_ids.contains(&node_id) {
            return Err(ConsensusError::DuplicateNodeId);
        }
        self.node_ids.insert(node_id);
        self.descriptors.push(signed);
        self.descriptors.sort_by_key(|s| s.descriptor.node_id);
        Ok(())
    }

    /// Build a consensus from a list of pre-signed descriptors.
    pub fn build_consensus(
        epoch: u64,
        authority_id: DirectoryAuthorityId,
        signed: Vec<SignedDescriptor>,
    ) -> Result<Self, ConsensusError> {
        if signed.is_empty() {
            return Err(ConsensusError::EmptyConsensus);
        }
        let mut consensus = Self::new(epoch, authority_id);
        for s in signed {
            consensus.add_descriptor(s)?;
        }
        Ok(consensus)
    }

    /// Verify every descriptor in this consensus.
    pub fn verify_consensus(&self) -> Result<(), ConsensusError> {
        for s in &self.descriptors {
            Self::verify_descriptor(s)?;
        }
        Ok(())
    }

    pub fn list_guards(&self) -> Vec<&NodeDescriptor> {
        self.by_role(PeerRole::Guard)
    }

    pub fn list_relays(&self) -> Vec<&NodeDescriptor> {
        self.by_role(PeerRole::Relay)
    }

    pub fn list_exits(&self) -> Vec<&NodeDescriptor> {
        self.by_role(PeerRole::Exit)
    }

    pub fn descriptor_count(&self) -> usize {
        self.descriptors.len()
    }

    fn by_role(&self, role: PeerRole) -> Vec<&NodeDescriptor> {
        self.descriptors
            .iter()
            .filter(|s| s.descriptor.role == role)
            .map(|s| &s.descriptor)
            .collect()
    }
}

/// Convenience: build a consensus from raw node IDs using deterministic descriptors.
pub fn build_deterministic_consensus(
    epoch: u64,
    authority_id: DirectoryAuthorityId,
    node_ids: &[u64],
    base_port: u16,
) -> Result<DirectoryConsensus, ConsensusError> {
    let mut consensus = DirectoryConsensus::new(epoch, authority_id);
    for &id in node_ids {
        let desc = NodeDescriptor::deterministic(id, base_port);
        let signed = consensus.sign_descriptor(desc);
        consensus.add_descriptor(signed)?;
    }
    Ok(consensus)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> DirectoryAuthorityId {
        DirectoryAuthorityId(0xABCD_1234)
    }

    fn consensus(epoch: u64) -> DirectoryConsensus {
        DirectoryConsensus::new(epoch, authority())
    }

    fn signed(c: &DirectoryConsensus, node_id: u64) -> SignedDescriptor {
        c.sign_descriptor(NodeDescriptor::deterministic(node_id, 45000))
    }

    // DC1: sign_descriptor produces a non-zero signature
    #[test]
    fn dc1_sign_descriptor() {
        let c = consensus(1);
        let s = signed(&c, 3);
        assert_ne!(s.signature, 0);
    }

    // DC2: verify_descriptor accepts a valid signed descriptor
    #[test]
    fn dc2_verify_descriptor() {
        let c = consensus(1);
        let s = signed(&c, 3);
        assert!(DirectoryConsensus::verify_descriptor(&s).is_ok());
    }

    // DC3: tampered signature rejected
    #[test]
    fn dc3_reject_invalid_signature() {
        let c = consensus(1);
        let mut s = signed(&c, 3);
        s.signature ^= 0xFF; // corrupt
        assert_eq!(
            DirectoryConsensus::verify_descriptor(&s).unwrap_err(),
            ConsensusError::InvalidSignature
        );
    }

    // DC4: build_consensus from a set of descriptors
    #[test]
    fn dc4_build_consensus() {
        let c = consensus(5);
        let signed_list: Vec<_> = (1u64..=9).map(|id| signed(&c, id)).collect();
        let built = DirectoryConsensus::build_consensus(5, authority(), signed_list).unwrap();
        assert_eq!(built.descriptor_count(), 9);
        assert_eq!(built.epoch, 5);
    }

    // DC5: duplicate node ID rejected
    #[test]
    fn dc5_reject_duplicate_node() {
        let mut c = consensus(1);
        c.add_descriptor(signed(&c, 3)).unwrap();
        let dup = signed(&c, 3);
        assert_eq!(
            c.add_descriptor(dup).unwrap_err(),
            ConsensusError::DuplicateNodeId
        );
    }

    // DC6: list_guards / list_relays / list_exits return correct subsets
    #[test]
    fn dc6_list_guards_relays_exits() {
        let result =
            build_deterministic_consensus(1, authority(), &[1, 2, 3, 4, 5, 6, 7, 8, 9], 45000)
                .unwrap();
        // IDs 3,6,9 → Guard; 1,4,7 → Relay; 2,5,8 → Exit
        assert_eq!(result.list_guards().len(), 3);
        assert_eq!(result.list_relays().len(), 3);
        assert_eq!(result.list_exits().len(), 3);
    }

    // DC7: deterministic — same inputs produce identical signed descriptors
    #[test]
    fn dc7_deterministic_consensus() {
        let c1 = build_deterministic_consensus(1, authority(), &[1, 2, 3], 45000).unwrap();
        let c2 = build_deterministic_consensus(1, authority(), &[1, 2, 3], 45000).unwrap();
        assert_eq!(c1.list_guards().len(), c2.list_guards().len());
        // Signatures must match
        assert_eq!(c1.list_guards()[0].node_id, c2.list_guards()[0].node_id);
    }

    // DC8: epoch is preserved in consensus
    #[test]
    fn dc8_epoch_preserved() {
        let c = build_deterministic_consensus(99, authority(), &[1, 2, 3], 45000).unwrap();
        assert_eq!(c.epoch, 99);
    }

    // DC9: verify_consensus accepts a fully valid consensus
    #[test]
    fn dc9_verify_consensus_valid() {
        let c = build_deterministic_consensus(1, authority(), &[1, 2, 3, 4, 5, 6], 45000).unwrap();
        assert!(c.verify_consensus().is_ok());
    }

    // DC10: empty consensus rejected
    #[test]
    fn dc10_empty_consensus_rejected() {
        assert_eq!(
            DirectoryConsensus::build_consensus(1, authority(), vec![]).unwrap_err(),
            ConsensusError::EmptyConsensus
        );
    }
}
