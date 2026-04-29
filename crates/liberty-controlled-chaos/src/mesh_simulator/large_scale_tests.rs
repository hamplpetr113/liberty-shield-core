//! Large-scale simulation tests for Phase 6.
//!
//! Covers 50-node, 100-node and 200-circuit scenarios and verifies:
//! - packet delivery rates
//! - replay rejection behaviour
//! - scheduler stability
//! - cover traffic scalability

#[cfg(test)]
mod tests {
    use crate::mesh_simulator::{MeshSimulator, MeshTopology, NodeRole, generate_payload};

    // LS1: 50-node topology has correct role distribution
    #[test]
    fn ls1_fifty_node_topology() {
        let topo = MeshTopology::generate_deterministic(50);
        assert_eq!(topo.node_count(), 50);
        // Guard=10%, Relay=80%, Exit=10%
        assert_eq!(topo.guard_count(), 5);
        assert_eq!(topo.relay_count(), 40);
        assert_eq!(topo.exit_count(), 5);
    }

    // LS2: 50-node network — 100 packets delivered without drop
    #[test]
    fn ls2_fifty_node_100_packets() {
        let mut sim = MeshSimulator::new(50);
        sim.build_random_circuits(5);
        sim.run_simulation(100);

        let m = sim.metrics();
        assert_eq!(m.packets_sent, 100);
        assert_eq!(m.packets_dropped, 0);
        assert_eq!(m.paths_completed, 100);
    }

    // LS3: 100-node network — 500 packets delivered without drop
    #[test]
    fn ls3_hundred_node_500_packets() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(10);
        sim.run_simulation(500);

        let m = sim.metrics();
        assert_eq!(m.packets_sent, 500);
        assert_eq!(m.packets_dropped, 0);
        assert_eq!(m.paths_completed, 500);
    }

    // LS4: 200-circuit scenario on 100-node network
    #[test]
    fn ls4_two_hundred_circuits() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(200);
        assert_eq!(sim.circuit_count(), 200);

        // Each circuit must have exactly 3 hops
        for circuit in sim.circuits() {
            assert_eq!(
                circuit.hop_count(),
                3,
                "circuit {} must be 3 hops",
                circuit.circuit_id
            );
        }
    }

    // LS5: replay detection at scale — 1000 unique nonces, none dropped
    #[test]
    fn ls5_replay_detection_scale() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(5);
        sim.run_simulation(1000);

        let m = sim.metrics();
        assert_eq!(
            m.replay_rejected, 0,
            "no replays expected with unique nonces"
        );
        assert_eq!(m.packets_dropped, 0);
    }

    // LS6: replay injection on each of 10 circuits
    #[test]
    fn ls6_replay_injection_multi_circuit() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(10);
        let payload = generate_payload(32);

        let mut replays_detected = 0usize;

        for circuit_idx in 0..10 {
            // First send (nonce=1000+idx): accepted
            let r1 = sim.send_on_circuit(circuit_idx, 1000 + circuit_idx as u64, &payload);
            assert!(
                r1.delivered,
                "initial send on circuit {circuit_idx} must succeed"
            );

            // Second send with same nonce: replay
            let r2 = sim.send_on_circuit(circuit_idx, 1000 + circuit_idx as u64, &payload);
            if !r2.delivered {
                replays_detected += 1;
            }
        }
        assert_eq!(replays_detected, 10, "all 10 replays must be detected");
    }

    // LS7: cover traffic at scale — 200 circuits generate cover packets
    #[test]
    fn ls7_cover_traffic_at_scale() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(200);

        let before = sim.metrics().cover_packets;
        sim.tick_cover_traffic(1_000_000);
        let after = sim.metrics().cover_packets;

        assert!(
            after > before,
            "cover traffic must be generated for 200 circuits"
        );
    }

    // LS8: heavy traffic burst — 5000 packets on 50 circuits
    #[test]
    fn ls8_heavy_burst_5000_packets() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(50);
        sim.run_simulation(5000);

        let m = sim.metrics();
        assert_eq!(m.packets_sent, 5000);
        assert_eq!(m.packets_dropped, 0);
        assert_eq!(m.paths_completed, 5000);
        // 5000 packets × 3 hops = 15000 forwards
        assert_eq!(m.packets_forwarded, 15000);
    }

    // LS9: all nodes in a 50-node network are reachable via circuits
    #[test]
    fn ls9_all_roles_covered() {
        let sim = MeshSimulator::new(50);
        // Check that every role type has at least one node
        let has_guard = sim.topology.nodes.iter().any(|n| n.role == NodeRole::Guard);
        let has_relay = sim.topology.nodes.iter().any(|n| n.role == NodeRole::Relay);
        let has_exit = sim.topology.nodes.iter().any(|n| n.role == NodeRole::Exit);
        assert!(has_guard);
        assert!(has_relay);
        assert!(has_exit);
    }

    // LS10: average path length is consistently 3.0 at scale
    #[test]
    fn ls10_average_path_length_stable() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(50);
        sim.run_simulation(2000);

        let m = sim.metrics();
        let avg = m.average_path_length();
        assert!(
            (avg - 3.0).abs() < f64::EPSILON,
            "average path length must be 3.0, got {avg}"
        );
    }

    // LS11: scheduler stability — 10 rounds of cover traffic + data
    #[test]
    fn ls11_scheduler_stability() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(20);

        for epoch in 0u64..10 {
            sim.tick_cover_traffic(epoch * 1_000_000);
            sim.run_simulation(100);
        }

        let m = sim.metrics();
        assert_eq!(m.packets_sent, 1000); // 10 × 100
        assert_eq!(m.packets_dropped, 0);
        assert!(m.cover_packets > 0);
    }

    // LS12: 50-node circuits — each circuit accepts its own unique nonce
    #[test]
    fn ls12_circuit_unique_nonces() {
        let mut sim = MeshSimulator::new(50);
        sim.build_random_circuits(10);
        let payload = generate_payload(16);

        // Each circuit gets a unique nonce range to avoid node-level nonce collisions.
        for circuit_idx in 0..10 {
            let nonce = (circuit_idx as u64) * 1000;
            let result = sim.send_on_circuit(circuit_idx, nonce, &payload);
            assert!(
                result.delivered,
                "circuit {circuit_idx} with nonce {nonce} must deliver"
            );
        }
    }

    // LS13: forward count equals packets × hops for multi-circuit burst
    #[test]
    fn ls13_forward_count_correct() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(30);
        let rounds = 300;
        sim.run_simulation(rounds);

        let m = sim.metrics();
        assert_eq!(m.packets_forwarded, (rounds * 3) as u64);
    }

    // LS14: 100-node deterministic topology is reproducible
    #[test]
    fn ls14_deterministic_topology() {
        let t1 = MeshTopology::generate_deterministic(100);
        let t2 = MeshTopology::generate_deterministic(100);
        let ids1: Vec<u64> = t1.nodes.iter().map(|n| n.node_id).collect();
        let ids2: Vec<u64> = t2.nodes.iter().map(|n| n.node_id).collect();
        assert_eq!(ids1, ids2);
    }

    // LS15: large-scale simulation metrics reset after new simulator
    #[test]
    fn ls15_fresh_simulator_zero_metrics() {
        let sim = MeshSimulator::new(100);
        let m = sim.metrics();
        assert_eq!(m.packets_sent, 0);
        assert_eq!(m.packets_forwarded, 0);
        assert_eq!(m.cover_packets, 0);
        assert_eq!(m.replay_rejected, 0);
    }
}
