//! CircuitBuilder — assembles a multi-hop onion circuit from relay descriptors.
//!
//! Sits above `OnionLayer` and `MeshRouter`:
//!   CircuitBuilder → OnionLayer → MeshRouter → UDPTransport
//!
//! Circuits are built deterministically from a sorted slice of `NodeDescriptor`s.
//! Each hop gets a distinct `OnionLayerKey` derived from the node's public key
//! material combined with a per-position nonce.  No network I/O is performed.

mod builder;
mod circuit;
mod types;

pub use builder::CircuitBuilder;
pub use circuit::Circuit;
pub use types::{CircuitError, CircuitId, NodeDescriptor, NodeId};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::udp_transport::PeerAddress;

    use super::*;

    fn peer(port: u16) -> PeerAddress {
        PeerAddress::new(format!("127.0.0.1:{port}").parse::<SocketAddr>().unwrap())
    }

    fn node(id: u64, key_seed: u8, port: u16) -> NodeDescriptor {
        NodeDescriptor {
            node_id: NodeId(id),
            public_key: [key_seed; 32],
            peer_address: peer(port),
            latency_estimate: 100,
            reliability_score: 0.99,
        }
    }

    fn three_nodes() -> Vec<NodeDescriptor> {
        vec![
            node(3, 0x03, 3001),
            node(1, 0x01, 1001),
            node(2, 0x02, 2001),
        ]
    }

    // ── C1: build 3-hop circuit ───────────────────────────────────────────────

    #[test]
    fn c1_build_three_hop_circuit() {
        let nodes = three_nodes();
        let circuit = CircuitBuilder::build_circuit(&nodes, 3).unwrap();
        assert_eq!(circuit.hop_count(), 3);
        assert_eq!(circuit.onion_keys.len(), 3);
    }

    // ── C2: duplicate nodes rejected ─────────────────────────────────────────

    #[test]
    fn c2_duplicate_node_rejected() {
        let nodes = vec![
            node(1, 0x01, 1001),
            node(1, 0x01, 1002),
            node(2, 0x02, 2001),
        ];
        assert!(matches!(
            CircuitBuilder::build_circuit(&nodes, 3),
            Err(CircuitError::DuplicateNode(NodeId(1)))
        ));
    }

    // ── C3: onion keys generated per hop ─────────────────────────────────────

    #[test]
    fn c3_onion_keys_distinct_per_hop() {
        let nodes = three_nodes();
        let circuit = CircuitBuilder::build_circuit(&nodes, 3).unwrap();
        // Keys must differ from each other (different nonces applied).
        assert_ne!(circuit.onion_keys[0].bytes, circuit.onion_keys[1].bytes);
        assert_ne!(circuit.onion_keys[1].bytes, circuit.onion_keys[2].bytes);
        // Keys must also differ from the raw public key of their node.
        for (i, key) in circuit.onion_keys.iter().enumerate() {
            assert_ne!(key.bytes, circuit.hops[i].public_key);
        }
    }

    // ── C4: deterministic construction ───────────────────────────────────────

    #[test]
    fn c4_deterministic_construction() {
        let nodes_a = three_nodes();
        let nodes_b = three_nodes();
        let c1 = CircuitBuilder::build_circuit(&nodes_a, 3).unwrap();
        let c2 = CircuitBuilder::build_circuit(&nodes_b, 3).unwrap();
        assert_eq!(c1.circuit_id, c2.circuit_id);
        for i in 0..3 {
            assert_eq!(c1.hops[i].node_id, c2.hops[i].node_id);
            assert_eq!(c1.onion_keys[i].bytes, c2.onion_keys[i].bytes);
        }
    }

    // ── C5: minimum hop enforcement ──────────────────────────────────────────

    #[test]
    fn c5_below_minimum_hops_rejected() {
        let nodes = three_nodes();
        assert!(matches!(
            CircuitBuilder::build_circuit(&nodes, 2),
            Err(CircuitError::BelowMinimumHops)
        ));
        assert!(matches!(
            CircuitBuilder::build_circuit(&nodes, 1),
            Err(CircuitError::BelowMinimumHops)
        ));
        assert!(matches!(
            CircuitBuilder::build_circuit(&nodes, 0),
            Err(CircuitError::BelowMinimumHops)
        ));
    }

    // ── C6: not enough nodes ──────────────────────────────────────────────────

    #[test]
    fn c6_not_enough_nodes_rejected() {
        let nodes = vec![node(1, 0x01, 1001), node(2, 0x02, 2001)];
        assert!(matches!(
            CircuitBuilder::build_circuit(&nodes, 3),
            Err(CircuitError::NotEnoughNodes)
        ));
    }

    // ── C7: nodes selected in ascending NodeId order ─────────────────────────

    #[test]
    fn c7_selection_is_sorted_by_node_id() {
        // Input is unsorted; expect hops to be [1, 2, 3].
        let nodes = vec![
            node(3, 0x03, 3001),
            node(1, 0x01, 1001),
            node(2, 0x02, 2001),
        ];
        let circuit = CircuitBuilder::build_circuit(&nodes, 3).unwrap();
        assert_eq!(circuit.hops[0].node_id, NodeId(1));
        assert_eq!(circuit.hops[1].node_id, NodeId(2));
        assert_eq!(circuit.hops[2].node_id, NodeId(3));
    }

    // ── C8: first_hop / last_hop helpers ─────────────────────────────────────

    #[test]
    fn c8_first_last_hop_helpers() {
        let nodes = three_nodes();
        let circuit = CircuitBuilder::build_circuit(&nodes, 3).unwrap();
        // After sorting by NodeId: [1→1001, 2→2001, 3→3001]
        assert_eq!(*circuit.first_hop().unwrap(), peer(1001));
        assert_eq!(*circuit.last_hop().unwrap(), peer(3001));
    }
}
