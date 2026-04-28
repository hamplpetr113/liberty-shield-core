use crate::udp_transport::PeerAddress;

/// Identifies a node in the discovery layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DiscoveryNodeId(pub u64);

/// Descriptor for a known relay node, including liveness metadata.
#[derive(Debug, Clone)]
pub struct NodeDescriptor {
    pub node_id: DiscoveryNodeId,
    pub public_key: [u8; 32],
    pub peer_address: PeerAddress,
    /// Smoothed round-trip latency estimate in microseconds (lower is better).
    pub latency_estimate: u64,
    /// Fraction of packets delivered successfully, in [0.0, 1.0] (higher is better).
    pub reliability_score: f64,
    /// Opaque timestamp of the last observed activity (e.g. Unix milliseconds).
    pub last_seen_timestamp: u64,
}

/// Computed quality score for a single node.
#[derive(Debug, Clone, Copy)]
pub struct NodeScore {
    pub node_id: DiscoveryNodeId,
    pub score: f64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum NodeDiscoveryError {
    /// A node with this id is already registered.
    DuplicateNode(DiscoveryNodeId),
    /// No node with this id exists.
    NodeNotFound(DiscoveryNodeId),
    /// Fewer candidate nodes are available than the number requested.
    NotEnoughNodes { requested: usize, available: usize },
}
