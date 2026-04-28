use crate::node_discovery::DiscoveryNodeId;
use crate::udp_transport::PeerAddress;

/// Identifies a guard in contexts where a distinct guard-layer identity is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GuardId(pub u64);

/// A live guard node entry, enriched with stability metadata.
#[derive(Debug, Clone)]
pub struct GuardNode {
    pub node_id: DiscoveryNodeId,
    pub public_key: [u8; 32],
    pub peer_address: PeerAddress,
    /// Smoothed round-trip latency estimate in microseconds.
    pub latency_estimate: u32,
    /// Fraction of packets delivered successfully, in [0.0, 1.0].
    pub reliability_score: f64,
    /// Timestamp when this guard was first selected.
    pub first_seen_timestamp: u64,
    /// Timestamp of the last successful interaction.
    pub last_seen_timestamp: u64,
    /// Number of consecutive or cumulative failures observed.
    pub failure_count: u32,
    /// Number of successful interactions recorded.
    pub success_count: u32,
}

/// Computed quality score for a guard candidate.
#[derive(Debug, Clone, Copy)]
pub struct GuardScore {
    pub node_id: DiscoveryNodeId,
    pub score: f64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GuardSelectionError {
    /// Fewer valid candidates exist than the number requested.
    NotEnoughCandidates,
    /// A guard with this `node_id` is already present in the set.
    DuplicateGuard(DiscoveryNodeId),
    /// No guard with this `node_id` exists in the set.
    GuardNotFound(DiscoveryNodeId),
    /// The guard set contains no entries.
    EmptyGuardSet,
    /// A candidate was rejected by the active `GuardPolicy`.
    PolicyRejected,
}
