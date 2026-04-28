use crate::udp_transport::PeerAddress;

/// Identifies a node in the circuit overlay network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub u64);

/// Identifies a fully-built circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircuitId(pub u64);

/// Static descriptor for a candidate relay node.
#[derive(Debug, Clone)]
pub struct NodeDescriptor {
    pub node_id: NodeId,
    /// 32-byte public key material (used to derive per-hop `OnionLayerKey`).
    pub public_key: [u8; 32],
    pub peer_address: PeerAddress,
    /// Smoothed round-trip latency estimate in microseconds.
    pub latency_estimate: u64,
    /// Fraction of packets delivered successfully, in [0.0, 1.0].
    pub reliability_score: f64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CircuitError {
    /// Fewer candidate nodes were supplied than the requested hop count.
    NotEnoughNodes,
    /// Requested hop count is below the minimum of 3.
    BelowMinimumHops,
    /// The candidate list contained duplicate `NodeId` values.
    DuplicateNode(NodeId),
}
