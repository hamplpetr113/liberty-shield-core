use crate::node_discovery::{DiscoveryNodeId, NodeDescriptor as DiscoveryNode};
use crate::udp_transport::PeerAddress;

use super::packet_flow::SimCircuit;
use super::topology::MeshTopology;

use std::net::SocketAddr;

/// Generate N deterministic `node_discovery::NodeDescriptor` values.
///
/// IDs 1..=n; latency = 100 + id * 10 µs; reliability = 0.95.
pub fn generate_nodes(n: usize) -> Vec<DiscoveryNode> {
    (1..=(n as u64))
        .map(|id| {
            let addr: SocketAddr = format!("127.0.0.1:{}", 9000 + id).parse().unwrap();
            DiscoveryNode {
                node_id: DiscoveryNodeId(id),
                public_key: [id as u8; 32],
                peer_address: PeerAddress::new(addr),
                latency_estimate: 100 + id * 10,
                reliability_score: 0.95,
                last_seen_timestamp: 1_000,
            }
        })
        .collect()
}

/// Generate a deterministic payload of `len` bytes.
///
/// Pattern: `byte[i] = (i as u8).wrapping_add(0xA5)`.
pub fn generate_payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_add(0xA5)).collect()
}

/// Generate `count` deterministic `SimCircuit` values from `topology`.
///
/// Circuit i: guard[i % guards.len()] → relay[i % relays.len()] → exit[i % exits.len()]
pub fn generate_circuits(topology: &MeshTopology, count: usize) -> Vec<SimCircuit> {
    (0..count)
        .map(|i| {
            let guard_id = topology.guards[i % topology.guards.len()];
            let relay_id = topology.relays[i % topology.relays.len()];
            let exit_id = topology.exits[i % topology.exits.len()];
            SimCircuit::new((i + 1) as u64, vec![guard_id, relay_id, exit_id])
        })
        .collect()
}
