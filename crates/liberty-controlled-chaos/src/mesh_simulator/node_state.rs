use std::collections::HashSet;

use crate::replay_protection::ReplayDetector;

use super::topology::NodeRole;

/// Per-node runtime state tracked during simulation.
pub struct SimNodeState {
    pub node_id: u64,
    pub role: NodeRole,
    /// Number of packets this node has forwarded.
    pub forward_count: u64,
    /// Number of packets this node has dropped (replay or invalid).
    pub drop_count: u64,
    /// Number of cover-traffic intents generated on this node.
    pub cover_count: u64,
    pub replay_detector: ReplayDetector,
    /// Nonces of packets already forwarded — used to prove no double-forward
    /// invariant per simulated round.
    forwarded_nonces: HashSet<u64>,
}

impl SimNodeState {
    pub fn new(node_id: u64, role: NodeRole) -> Self {
        Self {
            node_id,
            role,
            forward_count: 0,
            drop_count: 0,
            cover_count: 0,
            replay_detector: ReplayDetector::new(),
            forwarded_nonces: HashSet::new(),
        }
    }

    /// Returns `true` if this node has already forwarded a packet with `nonce`.
    pub fn has_forwarded(&self, nonce: u64) -> bool {
        self.forwarded_nonces.contains(&nonce)
    }

    /// Record a successful forward; panics if the same nonce is forwarded twice.
    pub fn record_forward(&mut self, nonce: u64) {
        debug_assert!(
            !self.forwarded_nonces.contains(&nonce),
            "node {} would forward nonce {nonce} twice",
            self.node_id
        );
        self.forwarded_nonces.insert(nonce);
        self.forward_count += 1;
    }

    pub fn record_drop(&mut self) {
        self.drop_count += 1;
    }

    pub fn record_cover(&mut self) {
        self.cover_count += 1;
    }
}
