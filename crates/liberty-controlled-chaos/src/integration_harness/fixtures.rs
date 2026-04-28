use std::net::SocketAddr;

use crate::circuit_builder::{NodeDescriptor as CircuitNode, NodeId};
use crate::guard_selection::GuardPolicy;
use crate::node_discovery::{DiscoveryNodeId, NodeDescriptor as DiscoveryNode};
use crate::noise_link::NoiseSession;
use crate::onion_layer::OnionLayerKey;
use crate::udp_transport::PeerAddress;

pub fn peer(port: u16) -> PeerAddress {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    PeerAddress::new(addr)
}

/// N deterministic `node_discovery::NodeDescriptor` values.
///
/// IDs run 1..=count; latency = 100 + id * 10; reliability = 0.95; key = [id as u8; 32].
pub fn discovery_nodes(count: usize) -> Vec<DiscoveryNode> {
    (1..=(count as u64))
        .map(|id| DiscoveryNode {
            node_id: DiscoveryNodeId(id),
            public_key: [id as u8; 32],
            peer_address: peer(9000 + id as u16),
            latency_estimate: 100 + id * 10,
            reliability_score: 0.95,
            last_seen_timestamp: 1_000,
        })
        .collect()
}

/// N deterministic `circuit_builder::NodeDescriptor` values.
///
/// Same deterministic layout as `discovery_nodes`; bridged to `NodeId` / `CircuitNode`.
pub fn circuit_nodes(count: usize) -> Vec<CircuitNode> {
    (1..=(count as u64))
        .map(|id| CircuitNode {
            node_id: NodeId(id),
            public_key: [id as u8; 32],
            peer_address: peer(9000 + id as u16),
            latency_estimate: 100 + id * 10,
            reliability_score: 0.95,
        })
        .collect()
}

/// Lenient `GuardPolicy` that accepts all test nodes produced by `discovery_nodes`.
pub fn guard_policy() -> GuardPolicy {
    GuardPolicy {
        min_guards: 3,
        max_guards: 5,
        max_latency: 500_000,
        min_reliability: 0.5,
        max_failure_count: 10,
        stability_window: 3600,
    }
}

/// Symmetric `NoiseSession` (same send and recv key) for round-trip testing.
pub fn noise_session() -> NoiseSession {
    NoiseSession::new([0xABu8; 32], [0xABu8; 32])
}

/// N deterministic `OnionLayerKey` values (key = [i as u8; 32]).
pub fn onion_keys(count: usize) -> Vec<OnionLayerKey> {
    (1..=(count as u8))
        .map(|i| OnionLayerKey { bytes: [i; 32] })
        .collect()
}
