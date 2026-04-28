//! NodeDiscovery — maintains a registry of known relay nodes and ranks them.
//!
//! Sits above `CircuitBuilder` in the stack:
//!   NodeDiscovery → CircuitBuilder → OnionLayer → MeshRouter → UDPTransport
//!
//! Nodes are scored by:  reliability_score / (latency_estimate + 1)
//! Ranking is fully deterministic: no randomness, no I/O.

mod registry;
mod scoring;
mod types;

pub use registry::NodeRegistry;
pub use scoring::{rank_nodes, select_relays};
pub use types::{DiscoveryNodeId, NodeDescriptor, NodeDiscoveryError, NodeScore};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::udp_transport::PeerAddress;

    use super::*;

    fn peer(port: u16) -> PeerAddress {
        PeerAddress::new(format!("127.0.0.1:{port}").parse::<SocketAddr>().unwrap())
    }

    fn node(id: u64, latency: u64, reliability: f64) -> NodeDescriptor {
        NodeDescriptor {
            node_id: DiscoveryNodeId(id),
            public_key: [id as u8; 32],
            peer_address: peer(1000 + id as u16),
            latency_estimate: latency,
            reliability_score: reliability,
            last_seen_timestamp: 0,
        }
    }

    fn make_registry() -> NodeRegistry {
        let mut r = NodeRegistry::new();
        r.register_node(node(3, 100, 0.9)).unwrap();
        r.register_node(node(1, 50, 0.95)).unwrap();
        r.register_node(node(2, 200, 0.7)).unwrap();
        r
    }

    // ── N1: register node ─────────────────────────────────────────────────────

    #[test]
    fn n1_register_node() {
        let mut r = NodeRegistry::new();
        r.register_node(node(10, 100, 0.9)).unwrap();
        assert!(r.get_node(DiscoveryNodeId(10)).is_ok());
    }

    // ── N2: duplicate rejected ────────────────────────────────────────────────

    #[test]
    fn n2_duplicate_rejected() {
        let mut r = NodeRegistry::new();
        r.register_node(node(5, 50, 0.8)).unwrap();
        assert!(matches!(
            r.register_node(node(5, 60, 0.9)),
            Err(NodeDiscoveryError::DuplicateNode(DiscoveryNodeId(5)))
        ));
    }

    // ── N3: remove node ───────────────────────────────────────────────────────

    #[test]
    fn n3_remove_node() {
        let mut r = make_registry();
        r.remove_node(DiscoveryNodeId(1)).unwrap();
        assert!(matches!(
            r.get_node(DiscoveryNodeId(1)),
            Err(NodeDiscoveryError::NodeNotFound(DiscoveryNodeId(1)))
        ));
    }

    #[test]
    fn n3_remove_unknown_returns_error() {
        let mut r = NodeRegistry::new();
        assert!(matches!(
            r.remove_node(DiscoveryNodeId(99)),
            Err(NodeDiscoveryError::NodeNotFound(DiscoveryNodeId(99)))
        ));
    }

    // ── N4: get node ──────────────────────────────────────────────────────────

    #[test]
    fn n4_get_node() {
        let r = make_registry();
        let n = r.get_node(DiscoveryNodeId(2)).unwrap();
        assert_eq!(n.latency_estimate, 200);
        assert!((n.reliability_score - 0.7).abs() < f64::EPSILON);
    }

    // ── N5: list deterministic ────────────────────────────────────────────────

    #[test]
    fn n5_list_deterministic() {
        let r = make_registry();
        let ids: Vec<u64> = r.list_nodes().iter().map(|n| n.node_id.0).collect();
        // Must be sorted ascending regardless of insertion order.
        assert_eq!(ids, vec![1, 2, 3]);

        // Second call returns identical ordering.
        let ids2: Vec<u64> = r.list_nodes().iter().map(|n| n.node_id.0).collect();
        assert_eq!(ids, ids2);
    }

    // ── N6: rank deterministic ────────────────────────────────────────────────

    #[test]
    fn n6_rank_deterministic() {
        // node 1: 0.95 / 51  ≈ 0.01863  (best)
        // node 3: 0.9  / 101 ≈ 0.00891
        // node 2: 0.7  / 201 ≈ 0.00348  (worst)
        let nodes: Vec<NodeDescriptor> =
            make_registry().list_nodes().into_iter().cloned().collect();
        let ranked = rank_nodes(&nodes);
        let ids: Vec<u64> = ranked.iter().map(|s| s.node_id.0).collect();
        assert_eq!(ids, vec![1, 3, 2]);

        // Scores decrease monotonically.
        for w in ranked.windows(2) {
            assert!(w[0].score >= w[1].score);
        }

        // Second call is identical.
        let ranked2 = rank_nodes(&nodes);
        let ids2: Vec<u64> = ranked2.iter().map(|s| s.node_id.0).collect();
        assert_eq!(ids, ids2);
    }

    #[test]
    fn n6_tie_break_by_lower_node_id() {
        // Both nodes have identical latency and reliability → same score.
        // Lower node_id must rank higher.
        let tied = vec![node(20, 100, 0.5), node(10, 100, 0.5)];
        let ranked = rank_nodes(&tied);
        assert_eq!(ranked[0].node_id.0, 10);
        assert_eq!(ranked[1].node_id.0, 20);
    }

    // ── N7: select unique relays ──────────────────────────────────────────────

    #[test]
    fn n7_select_unique_relays() {
        let nodes: Vec<NodeDescriptor> =
            make_registry().list_nodes().into_iter().cloned().collect();

        let selected = select_relays(&nodes, 2).unwrap();
        assert_eq!(selected.len(), 2);

        // All selected node_ids must be distinct.
        let mut ids: Vec<u64> = selected.iter().map(|n| n.node_id.0).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 2);

        // Top-2 by rank are node 1 and node 3.
        let selected_ids: std::collections::HashSet<u64> =
            selected.iter().map(|n| n.node_id.0).collect();
        assert!(selected_ids.contains(&1));
        assert!(selected_ids.contains(&3));
    }

    // ── N8: not enough nodes error ────────────────────────────────────────────

    #[test]
    fn n8_not_enough_nodes() {
        let nodes = vec![node(1, 100, 0.9)];
        assert!(matches!(
            select_relays(&nodes, 3),
            Err(NodeDiscoveryError::NotEnoughNodes {
                requested: 3,
                available: 1
            })
        ));
    }

    #[test]
    fn n8_empty_input_not_enough() {
        assert!(matches!(
            select_relays(&[], 1),
            Err(NodeDiscoveryError::NotEnoughNodes {
                requested: 1,
                available: 0
            })
        ));
    }
}
