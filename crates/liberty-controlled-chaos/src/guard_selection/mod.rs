//! GuardSelection — deterministic selection and management of entry-guard nodes.
//!
//! Sits between `NodeDiscovery` and `CircuitBuilder`:
//!   NodeDiscovery → GuardSelection → CircuitBuilder → CircuitRuntime
//!
//! Guards are chosen deterministically by scoring candidates and applying a
//! configurable `GuardPolicy`.  No randomness, no I/O, no system time calls.

mod guard_set;
mod policy;
mod selector;
mod types;

pub use guard_set::GuardSet;
pub use policy::GuardPolicy;
pub use selector::GuardSelector;
pub use types::{GuardId, GuardNode, GuardScore, GuardSelectionError};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::node_discovery::{DiscoveryNodeId, NodeDescriptor};
    use crate::udp_transport::PeerAddress;

    use super::*;

    fn peer(port: u16) -> PeerAddress {
        PeerAddress::new(format!("127.0.0.1:{port}").parse::<SocketAddr>().unwrap())
    }

    fn node(id: u64, latency: u64, reliability: f64) -> NodeDescriptor {
        NodeDescriptor {
            node_id: DiscoveryNodeId(id),
            public_key: [id as u8; 32],
            peer_address: peer(9000 + id as u16),
            latency_estimate: latency,
            reliability_score: reliability,
            last_seen_timestamp: 1_000,
        }
    }

    fn default_policy() -> GuardPolicy {
        GuardPolicy::default()
    }

    /// Five nodes that all pass the default policy.
    fn five_nodes() -> Vec<NodeDescriptor> {
        vec![
            node(5, 400, 0.80),
            node(3, 100, 0.95),
            node(1, 200, 0.90),
            node(4, 300, 0.85),
            node(2, 150, 0.92),
        ]
    }

    // ── G1: select_initial_guards selects 3 valid guards ─────────────────────

    #[test]
    fn g1_select_initial_guards() {
        let guards =
            GuardSelector::select_initial_guards(&five_nodes(), &default_policy(), 3).unwrap();
        assert_eq!(guards.active_count(), 3);
    }

    // ── G2: candidates below reliability threshold are rejected ──────────────

    #[test]
    fn g2_low_reliability_rejected() {
        // Only 2 nodes pass min_reliability = 0.60; requesting 3 → error.
        let nodes = vec![
            node(1, 100, 0.95),
            node(2, 100, 0.50), // below threshold
            node(3, 100, 0.80),
            node(4, 100, 0.40), // below threshold
            node(5, 100, 0.20), // below threshold
        ];
        assert!(matches!(
            GuardSelector::select_initial_guards(&nodes, &default_policy(), 3),
            Err(GuardSelectionError::NotEnoughCandidates)
        ));
    }

    // ── G3: candidates above latency threshold are rejected ──────────────────

    #[test]
    fn g3_high_latency_rejected() {
        // max_latency = 500; only 2 nodes pass.
        let nodes = vec![
            node(1, 100, 0.95),
            node(2, 600, 0.95), // above threshold
            node(3, 200, 0.90),
            node(4, 700, 0.95), // above threshold
        ];
        assert!(matches!(
            GuardSelector::select_initial_guards(&nodes, &default_policy(), 3),
            Err(GuardSelectionError::NotEnoughCandidates)
        ));
    }

    // ── G4: duplicate guards rejected ────────────────────────────────────────

    #[test]
    fn g4_duplicate_guard_rejected() {
        let mut set = GuardSet::new();
        let guard = selector::guard_from_node(&node(1, 100, 0.95));
        set.add_guard(guard.clone()).unwrap();
        assert!(matches!(
            set.add_guard(guard),
            Err(GuardSelectionError::DuplicateGuard(DiscoveryNodeId(1)))
        ));
    }

    // ── G5: deterministic ordering with tie-break by node_id ─────────────────

    #[test]
    fn g5_deterministic_ordering() {
        // Nodes with identical latency and reliability → tie-break by node_id.
        // score = 0.90 * 1000 - 200 = 700 for both.
        let tied = vec![node(10, 200, 0.90), node(5, 200, 0.90), node(7, 200, 0.90)];
        let gs = GuardSelector::select_initial_guards(&tied, &default_policy(), 3).unwrap();
        let ids: Vec<u64> = gs.list_guards().iter().map(|g| g.node_id.0).collect();
        // list_guards returns ascending node_id order; all three selected.
        assert_eq!(ids, vec![5, 7, 10]);

        // Run again: must be identical.
        let gs2 = GuardSelector::select_initial_guards(&tied, &default_policy(), 3).unwrap();
        let ids2: Vec<u64> = gs2.list_guards().iter().map(|g| g.node_id.0).collect();
        assert_eq!(ids, ids2);
    }

    // ── G6: not enough valid candidates returns NotEnoughCandidates ───────────

    #[test]
    fn g6_not_enough_candidates() {
        let nodes = vec![node(1, 100, 0.95), node(2, 100, 0.90)]; // only 2 valid
        assert!(matches!(
            GuardSelector::select_initial_guards(&nodes, &default_policy(), 3),
            Err(GuardSelectionError::NotEnoughCandidates)
        ));
    }

    // ── G7: GuardSet record_success increments success_count ─────────────────

    #[test]
    fn g7_record_success() {
        let mut set = GuardSet::new();
        set.add_guard(selector::guard_from_node(&node(1, 100, 0.95)))
            .unwrap();
        set.record_success(DiscoveryNodeId(1), 2_000).unwrap();
        let g = set.get_guard(DiscoveryNodeId(1)).unwrap();
        assert_eq!(g.success_count, 1);
        assert_eq!(g.last_seen_timestamp, 2_000);
    }

    // ── G8: GuardSet record_failure increments failure_count ─────────────────

    #[test]
    fn g8_record_failure() {
        let mut set = GuardSet::new();
        set.add_guard(selector::guard_from_node(&node(2, 100, 0.95)))
            .unwrap();
        set.record_failure(DiscoveryNodeId(2)).unwrap();
        set.record_failure(DiscoveryNodeId(2)).unwrap();
        let g = set.get_guard(DiscoveryNodeId(2)).unwrap();
        assert_eq!(g.failure_count, 2);
    }

    // ── G9: refresh_guards keeps existing valid guards ────────────────────────

    #[test]
    fn g9_refresh_keeps_valid_guards() {
        let initial =
            GuardSelector::select_initial_guards(&five_nodes(), &default_policy(), 3).unwrap();
        let initial_ids: Vec<u64> = initial.list_guards().iter().map(|g| g.node_id.0).collect();

        // Refresh with same candidates — all current guards are still valid.
        let refreshed =
            GuardSelector::refresh_guards(&initial, &five_nodes(), &default_policy()).unwrap();

        // Every guard from the initial set must still be present.
        for id in &initial_ids {
            assert!(refreshed.contains(DiscoveryNodeId(*id)));
        }
    }

    // ── G10: refresh_guards fills missing guards from candidates ──────────────

    #[test]
    fn g10_refresh_fills_missing() {
        // Start with 3 guards; manually mark one with too many failures so it
        // fails policy, then refresh with a larger candidate pool.
        let mut initial =
            GuardSelector::select_initial_guards(&five_nodes(), &default_policy(), 3).unwrap();

        // Force the first guard to exceed max_failure_count (default = 5).
        let first_id = initial.list_guards()[0].node_id;
        for _ in 0..6 {
            initial.record_failure(first_id).unwrap();
        }

        // After refresh, the set should still have 3 guards.
        let refreshed =
            GuardSelector::refresh_guards(&initial, &five_nodes(), &default_policy()).unwrap();
        assert_eq!(refreshed.active_count(), 3);

        // The evicted guard should not be present.
        assert!(!refreshed.contains(first_id));
    }

    // ── G11: remove_guard removes the correct guard ───────────────────────────

    #[test]
    fn g11_remove_guard() {
        let mut set = GuardSet::new();
        set.add_guard(selector::guard_from_node(&node(1, 100, 0.95)))
            .unwrap();
        set.add_guard(selector::guard_from_node(&node(2, 100, 0.90)))
            .unwrap();

        set.remove_guard(DiscoveryNodeId(1)).unwrap();
        assert!(!set.contains(DiscoveryNodeId(1)));
        assert!(set.contains(DiscoveryNodeId(2)));

        // Removing an absent guard returns error.
        assert!(matches!(
            set.remove_guard(DiscoveryNodeId(1)),
            Err(GuardSelectionError::GuardNotFound(DiscoveryNodeId(1)))
        ));
    }

    // ── G12: list_guards returns deterministic ordering ───────────────────────

    #[test]
    fn g12_list_guards_deterministic() {
        let gs = GuardSelector::select_initial_guards(&five_nodes(), &default_policy(), 3).unwrap();
        let ids1: Vec<u64> = gs.list_guards().iter().map(|g| g.node_id.0).collect();
        let ids2: Vec<u64> = gs.list_guards().iter().map(|g| g.node_id.0).collect();

        // Ordering is consistent across calls.
        assert_eq!(ids1, ids2);

        // Ordering is ascending by node_id.
        assert!(ids1.windows(2).all(|w| w[0] < w[1]));
    }

    // ── Extra: best candidate selected first by score ─────────────────────────

    #[test]
    fn g_extra_best_score_selected_first() {
        // node 1: 0.95 * 1000 - 200 = 750
        // node 2: 0.92 * 1000 - 150 = 770  ← best
        // node 3: 0.90 * 1000 - 100 = 800  ← actually best
        // node 4: 0.85 * 1000 - 300 = 550
        // node 5: 0.80 * 1000 - 400 = 400  ← worst
        // Sorted: 3 (800) > 2 (770) > 1 (750) > 4 (550) > 5 (400)
        let gs = GuardSelector::select_initial_guards(&five_nodes(), &default_policy(), 3).unwrap();
        let selected_ids: std::collections::HashSet<u64> =
            gs.list_guards().iter().map(|g| g.node_id.0).collect();
        // Top 3 by score: nodes 3, 2, 1
        assert!(selected_ids.contains(&3));
        assert!(selected_ids.contains(&2));
        assert!(selected_ids.contains(&1));
        assert!(!selected_ids.contains(&5)); // worst, not selected
    }
}
