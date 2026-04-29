//! MeshSimulator — deterministic in-process mesh network simulation.
//!
//! Simulates the Liberty Shield mesh protocol stack without real networking:
//! topology, circuits, onion routing, replay protection, and cover traffic.
//! All state is caller-driven; no randomness, no system time, no I/O.

mod fixtures;
mod metrics;
mod node_state;
mod packet_flow;
mod simulator;
mod topology;

#[cfg(test)]
mod large_scale_tests;

pub use fixtures::{generate_circuits, generate_nodes, generate_payload};
pub use metrics::MeshMetrics;
pub use node_state::SimNodeState;
pub use packet_flow::{FlowRejection, HopResult, PacketFlowEngine, PacketFlowResult, SimCircuit};
pub use simulator::MeshSimulator;
pub use topology::{MeshTopology, NodeRole, TopologyNode};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::noise_link::ENCRYPTED_CELL_SIZE;

    use super::*;

    // ── S1: create 100-node topology ─────────────────────────────────────────

    #[test]
    fn s1_create_100_node_topology() {
        let topo = MeshTopology::generate_deterministic(100);
        assert_eq!(topo.node_count(), 100);
        assert_eq!(topo.guard_count(), 10);
        assert_eq!(topo.relay_count(), 80);
        assert_eq!(topo.exit_count(), 10);
        // Links: 10 guard→relay + 80 relay→exit = 90.
        assert_eq!(topo.link_count(), 90);

        // All node IDs must be unique.
        let mut ids: Vec<u64> = topo.nodes.iter().map(|n| n.node_id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 100);
    }

    // ── S2: build circuits across guards ─────────────────────────────────────

    #[test]
    fn s2_build_circuits_across_guards() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(10);
        assert_eq!(sim.circuit_count(), 10);

        // Every circuit must start with a guard node.
        for circuit in sim.circuits() {
            let first_id = circuit.route[0];
            let node = sim.topology.get_node(first_id).unwrap();
            assert_eq!(node.role, NodeRole::Guard, "first hop must be a guard");

            // Last hop must be an exit.
            let last_id = *circuit.route.last().unwrap();
            let last_node = sim.topology.get_node(last_id).unwrap();
            assert_eq!(last_node.role, NodeRole::Exit, "last hop must be an exit");
        }
    }

    // ── S3: send payload across 3-hop route ──────────────────────────────────

    #[test]
    fn s3_send_payload_three_hop() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(1);

        let circuit = &sim.circuits()[0];
        assert_eq!(circuit.hop_count(), 3, "circuit must be 3 hops");
        let circuit_id = circuit.circuit_id;

        let payload = generate_payload(64);
        let result = sim.send_payload(&payload);

        assert!(result.delivered, "payload must be delivered");
        assert_eq!(
            result.circuit_id, circuit_id,
            "circuit ID must be preserved"
        );
        assert_eq!(result.hops.len(), 3, "must traverse exactly 3 hops");
        assert!(
            result.hops.iter().all(|h| h.accepted),
            "all hops must accept"
        );
    }

    // ── S4: replay detection triggers ────────────────────────────────────────

    #[test]
    fn s4_replay_detection_triggers() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(1);

        let payload = generate_payload(32);

        // First send with nonce=0 must succeed.
        let r1 = sim.send_on_circuit(0, 0, &payload);
        assert!(r1.delivered, "first send must succeed");

        // Second send with the SAME nonce=0 must be rejected.
        let r2 = sim.send_on_circuit(0, 0, &payload);
        assert!(!r2.delivered, "replay must be rejected");
        assert_eq!(
            r2.hops[0].rejection,
            Some(FlowRejection::ReplayDetected),
            "first hop must report ReplayDetected"
        );
    }

    // ── S5: packet size remains constant ─────────────────────────────────────

    #[test]
    fn s5_packet_size_constant() {
        // All simulated packets are ENCRYPTED_CELL_SIZE bytes on the wire.
        assert_eq!(PacketFlowEngine::packet_size(), ENCRYPTED_CELL_SIZE);
        assert_eq!(PacketFlowEngine::packet_size(), 1482);

        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(1);

        // Verify the result reports the correct size regardless of payload.
        for &payload_len in &[0usize, 64, 512, 1450] {
            let payload = generate_payload(payload_len);
            let result = sim.send_payload(&payload);
            assert_eq!(
                result.packet_size_bytes, 1482,
                "packet_size_bytes must always be 1482 (got {} for payload_len={payload_len})",
                result.packet_size_bytes
            );
        }
    }

    // ── S6: cover traffic generation ─────────────────────────────────────────

    #[test]
    fn s6_cover_traffic_generation() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(3);

        let before = sim.metrics().cover_packets;
        sim.tick_cover_traffic(1_000_000); // epoch_start_us = 1 s

        let after = sim.metrics().cover_packets;
        assert!(after > before, "cover traffic must be generated");

        // Guard nodes of our circuits must have non-zero cover_count.
        let first_guard = sim.circuits()[0].route[0];
        let state = &sim.node_states[&first_guard];
        assert!(state.cover_count > 0, "guard must record cover traffic");
    }

    // ── S7: simulation metrics update correctly ───────────────────────────────

    #[test]
    fn s7_metrics_update() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(1);

        let payload = generate_payload(64);

        sim.send_payload(&payload);
        sim.send_payload(&payload);
        sim.send_payload(&payload);

        let m = sim.metrics();
        assert_eq!(m.packets_sent, 3);
        assert_eq!(m.paths_completed, 3);
        assert_eq!(m.packets_dropped, 0);
        // 3 packets × 3 hops each = 9 hop forwards.
        assert_eq!(m.packets_forwarded, 9);
        assert!(
            (m.average_path_length() - 3.0).abs() < f64::EPSILON,
            "average path length must be 3.0"
        );
    }

    // ── S8: no node forwards a packet twice ───────────────────────────────────

    #[test]
    fn s8_no_node_forwards_twice() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(1);

        let payload = generate_payload(32);
        let result = sim.send_payload(&payload);

        // All hop node IDs must be distinct.
        let node_ids: Vec<u64> = result.hops.iter().map(|h| h.node_id).collect();
        let unique: std::collections::HashSet<u64> = node_ids.iter().copied().collect();
        assert_eq!(
            node_ids.len(),
            unique.len(),
            "each node must appear at most once in the route"
        );

        // Verify that node_state.has_forwarded returns true after forwarding
        // and that double-forwarding the same nonce is detected at the state level.
        let nonce_used = 0u64; // first send used nonce 0
        let guard_id = result.hops[0].node_id;
        assert!(
            sim.node_states[&guard_id].has_forwarded(nonce_used),
            "guard must have recorded the forward"
        );
    }

    // ── S9: routing never loops ───────────────────────────────────────────────

    #[test]
    fn s9_routing_never_loops() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(20);

        for circuit in sim.circuits() {
            let route = &circuit.route;
            // Every node in the route must be unique.
            let unique: std::collections::HashSet<u64> = route.iter().copied().collect();
            assert_eq!(
                route.len(),
                unique.len(),
                "circuit {} contains a routing loop",
                circuit.circuit_id
            );

            // Every address in the route must be unique.
            let addrs: Vec<_> = route
                .iter()
                .map(|&id| sim.topology.get_node(id).unwrap().peer_address.clone())
                .collect();
            let unique_addrs: std::collections::HashSet<String> =
                addrs.iter().map(|a| a.to_string()).collect();
            assert_eq!(
                addrs.len(),
                unique_addrs.len(),
                "circuit {} has duplicate peer addresses (routing loop)",
                circuit.circuit_id
            );
        }
    }

    // ── S10: simulation of 1000 packets stable ────────────────────────────────

    #[test]
    fn s10_simulation_1000_packets_stable() {
        let mut sim = MeshSimulator::new(100);
        sim.build_random_circuits(5);

        sim.run_simulation(1000);

        let m = sim.metrics();
        assert_eq!(m.packets_sent, 1000, "must have sent exactly 1000 packets");
        assert_eq!(
            m.packets_dropped, 0,
            "no drops expected (unique nonces per round)"
        );
        assert_eq!(m.paths_completed, 1000, "all packets must be delivered");
        // 1000 packets × 3 hops = 3000 hop-forwards.
        assert_eq!(m.packets_forwarded, 3000);
        assert!(
            (m.average_path_length() - 3.0).abs() < f64::EPSILON,
            "average path length must be 3.0 for a 3-hop circuit"
        );
    }
}
