//! Directory consensus — voting-based network-state agreement.
//!
//! Each authority casts a `DirectoryVote` for the current epoch.  Once a
//! simple majority (`votes >= threshold`) is collected, `finalize()` produces
//! a signed `DirectoryConsensus`.
//!
//! `NodeDescriptor` here is a lightweight network advertisement: node_id,
//! address string, epoch, and a TTL.
//!
//! NON-PRODUCTION: signatures are HMAC-SHA256(authority_id, payload_bytes).

use std::collections::{HashMap, HashSet};

use crate::crypto::hmac_sha256;

// ---------------------------------------------------------------------------
// NodeDescriptor
// ---------------------------------------------------------------------------

/// Lightweight advertisement for a network node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDescriptor {
    pub node_id: [u8; 32],
    /// Human-readable address (e.g. "127.0.0.1:9001").
    pub address: String,
    /// Epoch at which this descriptor was published.
    pub published_epoch: u64,
    /// Number of epochs this descriptor remains valid.
    pub ttl_epochs: u64,
}

impl NodeDescriptor {
    pub fn is_valid_at(&self, epoch: u64) -> bool {
        epoch >= self.published_epoch && epoch < self.published_epoch + self.ttl_epochs
    }

    fn bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.node_id);
        b.extend_from_slice(self.address.as_bytes());
        b.extend_from_slice(&self.published_epoch.to_le_bytes());
        b.extend_from_slice(&self.ttl_epochs.to_le_bytes());
        b
    }
}

// ---------------------------------------------------------------------------
// DirectoryVote
// ---------------------------------------------------------------------------

/// A single authority's vote for an epoch.
#[derive(Debug, Clone)]
pub struct DirectoryVote {
    /// node_id of the voting authority.
    pub authority_id: [u8; 32],
    pub epoch: u64,
    /// Descriptors this authority endorses.
    pub descriptors: Vec<NodeDescriptor>,
    /// HMAC-SHA256(authority_id, vote_payload) — NON-PRODUCTION.
    pub signature: [u8; 32],
}

impl DirectoryVote {
    /// Create a signed vote.
    pub fn new(
        authority_id: [u8; 32],
        authority_key: &[u8; 32],
        epoch: u64,
        descriptors: Vec<NodeDescriptor>,
    ) -> Self {
        let payload = Self::payload_bytes(authority_id, epoch, &descriptors);
        let signature = hmac_sha256(authority_key, &payload);
        Self {
            authority_id,
            epoch,
            descriptors,
            signature,
        }
    }

    fn payload_bytes(authority_id: [u8; 32], epoch: u64, descs: &[NodeDescriptor]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&authority_id);
        b.extend_from_slice(&epoch.to_le_bytes());
        for d in descs {
            b.extend_from_slice(&d.bytes());
        }
        b
    }

    pub fn verify(&self, authority_key: &[u8; 32]) -> bool {
        let payload = Self::payload_bytes(self.authority_id, self.epoch, &self.descriptors);
        hmac_sha256(authority_key, &payload) == self.signature
    }
}

// ---------------------------------------------------------------------------
// DirectoryConsensus
// ---------------------------------------------------------------------------

/// Finalized consensus produced once enough votes are tallied.
#[derive(Debug, Clone)]
pub struct DirectoryConsensus {
    pub epoch: u64,
    /// Deduplicated descriptors that appeared in >= threshold votes.
    pub descriptors: Vec<NodeDescriptor>,
    pub authority_count: usize,
    pub vote_count: usize,
    /// HMAC-SHA256(finalize_key, consensus_bytes) — NON-PRODUCTION.
    pub signature: [u8; 32],
}

impl DirectoryConsensus {
    fn payload_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.epoch.to_le_bytes());
        b.extend_from_slice(&(self.vote_count as u64).to_le_bytes());
        for d in &self.descriptors {
            b.extend_from_slice(&d.bytes());
        }
        b
    }

    pub fn verify(&self, finalize_key: &[u8; 32]) -> bool {
        hmac_sha256(finalize_key, &self.payload_bytes()) == self.signature
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusError {
    /// A vote from this authority has already been recorded.
    DuplicateVote,
    /// The vote's epoch does not match the accumulator's epoch.
    EpochMismatch,
    /// Threshold not yet reached; consensus cannot be finalized.
    InsufficientVotes,
}

impl std::fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusError::DuplicateVote => write!(f, "duplicate vote from authority"),
            ConsensusError::EpochMismatch => write!(f, "vote epoch mismatch"),
            ConsensusError::InsufficientVotes => write!(f, "insufficient votes to finalize"),
        }
    }
}

// ---------------------------------------------------------------------------
// VoteAccumulator
// ---------------------------------------------------------------------------

/// Collects votes and finalizes consensus when threshold is reached.
pub struct VoteAccumulator {
    epoch: u64,
    threshold: usize,
    votes: HashMap<[u8; 32], DirectoryVote>,
}

impl VoteAccumulator {
    /// Create an accumulator for `epoch` that requires `threshold` votes.
    pub fn new(epoch: u64, threshold: usize) -> Self {
        Self {
            epoch,
            threshold,
            votes: HashMap::new(),
        }
    }

    pub fn add_vote(&mut self, vote: DirectoryVote) -> Result<(), ConsensusError> {
        if vote.epoch != self.epoch {
            return Err(ConsensusError::EpochMismatch);
        }
        if self.votes.contains_key(&vote.authority_id) {
            return Err(ConsensusError::DuplicateVote);
        }
        self.votes.insert(vote.authority_id, vote);
        Ok(())
    }

    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    pub fn has_quorum(&self) -> bool {
        self.votes.len() >= self.threshold
    }

    /// Finalize consensus. Descriptors that appear in >= threshold votes are included.
    pub fn finalize(&self, finalize_key: &[u8; 32]) -> Result<DirectoryConsensus, ConsensusError> {
        if !self.has_quorum() {
            return Err(ConsensusError::InsufficientVotes);
        }
        // Count how many votes endorse each descriptor (by node_id).
        let mut counts: HashMap<[u8; 32], (NodeDescriptor, usize)> = HashMap::new();
        for vote in self.votes.values() {
            let mut seen: HashSet<[u8; 32]> = HashSet::new();
            for desc in &vote.descriptors {
                if seen.insert(desc.node_id) {
                    let entry = counts.entry(desc.node_id).or_insert((desc.clone(), 0));
                    entry.1 += 1;
                }
            }
        }
        let mut descriptors: Vec<NodeDescriptor> = counts
            .into_values()
            .filter(|(_, count)| *count >= self.threshold)
            .map(|(desc, _)| desc)
            .collect();
        descriptors.sort_by_key(|d| d.node_id);

        let vote_count = self.votes.len();
        let authority_count = vote_count;
        let mut consensus = DirectoryConsensus {
            epoch: self.epoch,
            descriptors,
            authority_count,
            vote_count,
            signature: [0u8; 32],
        };
        consensus.signature = hmac_sha256(finalize_key, &consensus.payload_bytes());
        Ok(consensus)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn desc(node: u8, epoch: u64) -> NodeDescriptor {
        NodeDescriptor {
            node_id: nid(node),
            address: format!("127.0.0.1:{}", 9000 + node as u16),
            published_epoch: epoch,
            ttl_epochs: 10,
        }
    }

    // DC1: single vote can be added.
    #[test]
    fn dc1_add_vote() {
        let mut acc = VoteAccumulator::new(1, 1);
        let vote = DirectoryVote::new(nid(1), &key(1), 1, vec![desc(10, 1)]);
        assert!(acc.add_vote(vote).is_ok());
        assert_eq!(acc.vote_count(), 1);
    }

    // DC2: duplicate vote is rejected.
    #[test]
    fn dc2_duplicate_vote_rejected() {
        let mut acc = VoteAccumulator::new(1, 2);
        let vote = DirectoryVote::new(nid(1), &key(1), 1, vec![]);
        acc.add_vote(vote.clone()).unwrap();
        assert_eq!(
            acc.add_vote(vote).unwrap_err(),
            ConsensusError::DuplicateVote
        );
    }

    // DC3: epoch mismatch is rejected.
    #[test]
    fn dc3_epoch_mismatch() {
        let mut acc = VoteAccumulator::new(1, 2);
        let vote = DirectoryVote::new(nid(1), &key(1), 2, vec![]);
        assert_eq!(
            acc.add_vote(vote).unwrap_err(),
            ConsensusError::EpochMismatch
        );
    }

    // DC4: finalize fails below threshold.
    #[test]
    fn dc4_insufficient_votes() {
        let acc = VoteAccumulator::new(1, 2);
        assert_eq!(
            acc.finalize(&key(0)).unwrap_err(),
            ConsensusError::InsufficientVotes
        );
    }

    // DC5: finalize succeeds at threshold.
    #[test]
    fn dc5_finalize_at_threshold() {
        let mut acc = VoteAccumulator::new(1, 2);
        acc.add_vote(DirectoryVote::new(nid(1), &key(1), 1, vec![desc(10, 1)]))
            .unwrap();
        acc.add_vote(DirectoryVote::new(nid(2), &key(2), 1, vec![desc(10, 1)]))
            .unwrap();
        let consensus = acc.finalize(&key(0)).unwrap();
        assert_eq!(consensus.epoch, 1);
        assert_eq!(consensus.descriptors.len(), 1);
    }

    // DC6: descriptor only included if endorsed by >= threshold votes.
    #[test]
    fn dc6_descriptor_threshold_filter() {
        let mut acc = VoteAccumulator::new(1, 2);
        // Node 10 endorsed by both; Node 11 only by authority 1.
        acc.add_vote(DirectoryVote::new(
            nid(1),
            &key(1),
            1,
            vec![desc(10, 1), desc(11, 1)],
        ))
        .unwrap();
        acc.add_vote(DirectoryVote::new(nid(2), &key(2), 1, vec![desc(10, 1)]))
            .unwrap();
        let consensus = acc.finalize(&key(0)).unwrap();
        assert_eq!(consensus.descriptors.len(), 1);
        assert_eq!(consensus.descriptors[0].node_id, nid(10));
    }

    // DC7: vote signature verifies correctly.
    #[test]
    fn dc7_vote_signature_verify() {
        let vote = DirectoryVote::new(nid(1), &key(1), 1, vec![desc(10, 1)]);
        assert!(vote.verify(&key(1)));
        assert!(!vote.verify(&key(2)));
    }

    // DC8: consensus signature verifies.
    #[test]
    fn dc8_consensus_signature_verify() {
        let mut acc = VoteAccumulator::new(1, 1);
        acc.add_vote(DirectoryVote::new(nid(1), &key(1), 1, vec![desc(10, 1)]))
            .unwrap();
        let consensus = acc.finalize(&key(0)).unwrap();
        assert!(consensus.verify(&key(0)));
        assert!(!consensus.verify(&key(1)));
    }

    // DC9: NodeDescriptor TTL validity check.
    #[test]
    fn dc9_descriptor_ttl() {
        let d = NodeDescriptor {
            node_id: nid(1),
            address: "127.0.0.1:9001".to_string(),
            published_epoch: 5,
            ttl_epochs: 3,
        };
        assert!(d.is_valid_at(5));
        assert!(d.is_valid_at(7));
        assert!(!d.is_valid_at(8));
        assert!(!d.is_valid_at(4));
    }

    // DC10: three authorities, all endorse same node, all included.
    #[test]
    fn dc10_three_authority_consensus() {
        let mut acc = VoteAccumulator::new(2, 2);
        for i in 1u8..=3 {
            acc.add_vote(DirectoryVote::new(nid(i), &key(i), 2, vec![desc(99, 2)]))
                .unwrap();
        }
        let consensus = acc.finalize(&key(0)).unwrap();
        assert_eq!(consensus.vote_count, 3);
        assert!(!consensus.descriptors.is_empty());
    }

    // DC11: has_quorum reflects threshold correctly.
    #[test]
    fn dc11_quorum_tracking() {
        let mut acc = VoteAccumulator::new(1, 3);
        assert!(!acc.has_quorum());
        for i in 1u8..=3 {
            acc.add_vote(DirectoryVote::new(nid(i), &key(i), 1, vec![]))
                .unwrap();
        }
        assert!(acc.has_quorum());
    }
}
