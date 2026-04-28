use std::collections::HashMap;

use crate::circuit_builder::{CircuitBuilder, NodeDescriptor as CBNodeDescriptor, NodeId};
use crate::circuit_runtime::CircuitRuntime;
use crate::cover_traffic::{CoverTrafficGenerator, CoverTrafficPolicy};
use crate::mesh_router::{MeshRouter, Route, RouteId, RoutingTable};
use crate::replay_protection::CellNonce;

use super::fixtures::generate_circuits;
use super::metrics::MeshMetrics;
use super::node_state::SimNodeState;
use super::packet_flow::{
    FlowRejection, HopResult, PacketFlowEngine, PacketFlowResult, SimCircuit,
};
use super::topology::MeshTopology;

/// In-process mesh network simulator.
///
/// Simulates the full Liberty Shield protocol stack without real I/O:
/// nodes, guards, circuits, onion routing, replay protection, and cover traffic.
pub struct MeshSimulator {
    pub topology: MeshTopology,
    /// Per-node runtime state (forward/drop/cover counters + replay detector).
    pub node_states: HashMap<u64, SimNodeState>,
    /// Registered circuits; updated by `build_random_circuits`.
    pub circuit_runtime: CircuitRuntime,
    /// Mesh router for deterministic next-hop lookups.
    pub router: MeshRouter,
    /// Aggregated simulation statistics.
    pub metrics: MeshMetrics,
    /// Active simulated circuits built by `build_random_circuits`.
    circuits: Vec<SimCircuit>,
    /// Monotonically-increasing nonce for successive `send_payload` calls.
    next_nonce: u64,
}

impl MeshSimulator {
    /// Create a simulator with a deterministic `node_count`-node topology.
    pub fn new(node_count: usize) -> Self {
        let topology = MeshTopology::generate_deterministic(node_count);

        // Build per-node state.
        let node_states: HashMap<u64, SimNodeState> = topology
            .nodes
            .iter()
            .map(|n| (n.node_id, SimNodeState::new(n.node_id, n.role)))
            .collect();

        // Build a routing table: one route per link in the topology.
        let mut table = RoutingTable::new();
        for (idx, link) in topology.links.iter().enumerate() {
            if let Some(dest) = topology.get_node(link.to) {
                let route = Route {
                    route_id: RouteId(idx as u64),
                    next_hop: dest.peer_address.clone(),
                    hop_count: 1,
                    latency_estimate: 100,
                    reliability_score: 0.99,
                };
                // Ignore duplicate route IDs; the first wins.
                let _ = table.add_route(route);
            }
        }

        Self {
            topology,
            node_states,
            circuit_runtime: CircuitRuntime::new(),
            router: MeshRouter::new(table),
            metrics: MeshMetrics::new(),
            circuits: Vec::new(),
            next_nonce: 0,
        }
    }

    /// Build `count` deterministic circuits and register them with `circuit_runtime`.
    ///
    /// Circuits are guard → relay → exit (3 hops) using topology node IDs.
    /// Named `build_random_circuits` for API compatibility; internally deterministic.
    pub fn build_random_circuits(&mut self, count: usize) {
        let new_circuits = generate_circuits(&self.topology, count);
        for circuit in &new_circuits {
            // Build a real circuit_builder::Circuit from the route's topology nodes.
            let nodes: Option<Vec<CBNodeDescriptor>> = circuit
                .route
                .iter()
                .map(|&id| {
                    self.topology.get_node(id).map(|n| CBNodeDescriptor {
                        node_id: NodeId(n.node_id),
                        public_key: [n.node_id as u8; 32],
                        peer_address: n.peer_address.clone(),
                        latency_estimate: 100,
                        reliability_score: 0.95,
                    })
                })
                .collect();

            if let Some(nodes) = nodes
                && let Ok(cb_circuit) = CircuitBuilder::build_circuit(&nodes, nodes.len())
            {
                // Register; ignore errors (e.g. duplicate circuit_id from identical routes).
                let _ = self.circuit_runtime.register_circuit(cb_circuit, 0);
            }
        }
        self.circuits.extend(new_circuits);
    }

    /// Inject `payload` into the first available circuit and simulate traversal.
    ///
    /// Returns the per-hop result and updates node state and metrics.
    /// Uses a monotonically-increasing internal nonce (never repeats).
    pub fn send_payload(&mut self, payload: &[u8]) -> PacketFlowResult {
        if self.circuits.is_empty() {
            return PacketFlowResult {
                circuit_id: 0,
                hops: Vec::new(),
                delivered: false,
                packet_size_bytes: PacketFlowEngine::packet_size(),
            };
        }

        let circuit = self.circuits[0].clone();
        let nonce = self.next_nonce;
        self.next_nonce += 1;

        self.metrics.record_sent();
        self.process_packet(&circuit, nonce, payload)
    }

    /// Inject `payload` on the circuit at `circuit_index`.
    ///
    /// Uses an explicit `nonce` so tests can trigger replay detection.
    pub fn send_on_circuit(
        &mut self,
        circuit_index: usize,
        nonce: u64,
        payload: &[u8],
    ) -> PacketFlowResult {
        if circuit_index >= self.circuits.len() {
            return PacketFlowResult {
                circuit_id: 0,
                hops: Vec::new(),
                delivered: false,
                packet_size_bytes: PacketFlowEngine::packet_size(),
            };
        }
        let circuit = self.circuits[circuit_index].clone();
        self.metrics.record_sent();
        self.process_packet(&circuit, nonce, payload)
    }

    /// Generate cover traffic for `epoch` and update node counters.
    pub fn tick_cover_traffic(&mut self, epoch: u64) {
        if self.circuits.is_empty() {
            return;
        }
        use crate::circuit_builder::CircuitId;

        let circuit_ids: Vec<crate::circuit_builder::CircuitId> = self
            .circuits
            .iter()
            .map(|c| CircuitId(c.circuit_id))
            .collect();

        let policy = CoverTrafficPolicy::default();
        let cover_gen = CoverTrafficGenerator::new();
        let intents = cover_gen.generate_epoch(&policy, &circuit_ids, epoch);

        for intent in &intents {
            // Credit the cover count to the guard node of the circuit.
            if let Some(circuit) = self
                .circuits
                .iter()
                .find(|c| c.circuit_id == intent.circuit_id.0)
                && let Some(guard_id) = circuit.route.first().copied()
                && let Some(state) = self.node_states.get_mut(&guard_id)
            {
                state.record_cover();
            }
            self.metrics.record_cover();
        }
    }

    /// Run the simulation for `rounds` rounds, each sending a distinct payload.
    ///
    /// Each round uses a unique nonce so no replay detection is triggered.
    pub fn run_simulation(&mut self, rounds: usize) {
        for round in 0..rounds {
            let base = (round & 0xFF) as u8;
            let payload: Vec<u8> = (0u8..8).map(|i| base.wrapping_add(i)).collect();
            let _ = self.send_payload(&payload);
        }
    }

    /// Snapshot of the current simulation metrics.
    pub fn metrics(&self) -> &MeshMetrics {
        &self.metrics
    }

    /// Number of active simulated circuits.
    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    /// Read-only access to the mesh router.
    pub fn router(&self) -> &MeshRouter {
        &self.router
    }

    /// Read-only slice of all active simulated circuits.
    pub fn circuits(&self) -> &[SimCircuit] {
        &self.circuits
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn process_packet(
        &mut self,
        circuit: &SimCircuit,
        nonce: u64,
        payload: &[u8],
    ) -> PacketFlowResult {
        let cell = PacketFlowEngine::make_cell(circuit.circuit_id, nonce, payload);
        let cell_nonce = CellNonce(cell.nonce);
        let circuit_id = circuit.circuit_id;
        let hop_count = circuit.route.len();

        let mut hop_results: Vec<HopResult> = Vec::with_capacity(hop_count);
        let mut delivered = true;

        for &node_id in &circuit.route {
            let result = match self.node_states.get_mut(&node_id) {
                None => HopResult {
                    node_id,
                    accepted: false,
                    rejection: Some(FlowRejection::NodeNotFound),
                },
                Some(state) => {
                    use crate::replay_protection::ReplayError;
                    match state
                        .replay_detector
                        .check_cell(crate::circuit_builder::CircuitId(circuit_id), cell_nonce)
                    {
                        Ok(()) => {
                            state.record_forward(nonce);
                            self.metrics.record_hop_forward();
                            HopResult {
                                node_id,
                                accepted: true,
                                rejection: None,
                            }
                        }
                        Err(ReplayError::DuplicateNonce) => {
                            state.record_drop();
                            self.metrics.record_drop();
                            self.metrics.record_replay_rejected();
                            HopResult {
                                node_id,
                                accepted: false,
                                rejection: Some(FlowRejection::ReplayDetected),
                            }
                        }
                        Err(ReplayError::WindowExpired) => {
                            state.record_drop();
                            self.metrics.record_drop();
                            self.metrics.record_replay_rejected();
                            HopResult {
                                node_id,
                                accepted: false,
                                rejection: Some(FlowRejection::ReplayWindowExpired),
                            }
                        }
                    }
                }
            };

            let accepted = result.accepted;
            hop_results.push(result);

            if !accepted {
                delivered = false;
                break;
            }
        }

        if delivered {
            self.metrics.record_delivery(hop_count as u64);
        }

        PacketFlowResult {
            circuit_id,
            hops: hop_results,
            delivered,
            packet_size_bytes: PacketFlowEngine::packet_size(),
        }
    }
}
