//! Onion relay runtime — routes `OnionCellV2` cells through registered circuits.
//!
//! Each circuit has a designated next hop.  The relay decides whether to forward
//! a cell, deliver it locally, or drop it.  Replay protection is enforced per
//! circuit using a sequence-number set, and a policy hook is consulted before
//! any forward.

use std::collections::{HashMap, HashSet};

use crate::onion_cell_v2::{CMD_DATA, OnionCellV2};
use crate::policy_engine::{PolicyAction, PolicyEngine, PolicyRequest, TrafficClass};

// ---------------------------------------------------------------------------
// RouteDecision
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    /// Deliver the cell to the local application layer.
    LocalDelivery,
    /// Forward the cell to the given next-hop node ID.
    Forward([u8; 32]),
    /// Drop with reason.
    Drop(DropReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DropReason {
    UnknownCircuit,
    ReplayDetected,
    PolicyDenied,
    LoopDetected,
}

// ---------------------------------------------------------------------------
// RelayCircuit
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RelayCircuit {
    pub circuit_id: u64,
    /// If `None`, this node is the exit — deliver locally.
    pub next_hop: Option<[u8; 32]>,
    pub cells_forwarded: u64,
    pub cells_dropped: u64,
}

// ---------------------------------------------------------------------------
// OnionRelayRuntime
// ---------------------------------------------------------------------------

pub struct OnionRelayRuntime {
    local_id: [u8; 32],
    circuits: HashMap<u64, RelayCircuit>,
    seen_sequences: HashMap<u64, HashSet<u64>>,
    policy: PolicyEngine,
    total_forwarded: u64,
    total_dropped: u64,
}

impl OnionRelayRuntime {
    pub fn new(local_id: [u8; 32]) -> Self {
        Self {
            local_id,
            circuits: HashMap::new(),
            seen_sequences: HashMap::new(),
            policy: PolicyEngine::new(),
            total_forwarded: 0,
            total_dropped: 0,
        }
    }

    /// Register a circuit. `next_hop = None` means local delivery (exit node).
    pub fn register_circuit(&mut self, circuit_id: u64, next_hop: Option<[u8; 32]>) {
        self.circuits.insert(
            circuit_id,
            RelayCircuit {
                circuit_id,
                next_hop,
                cells_forwarded: 0,
                cells_dropped: 0,
            },
        );
        self.seen_sequences.insert(circuit_id, HashSet::new());
    }

    pub fn remove_circuit(&mut self, circuit_id: u64) {
        self.circuits.remove(&circuit_id);
        self.seen_sequences.remove(&circuit_id);
    }

    /// Process an inbound cell and return the routing decision.
    pub fn process_inbound_cell(&mut self, cell: &OnionCellV2) -> RouteDecision {
        let circuit_id = cell.circuit_id;

        // 1. Unknown circuit.
        if !self.circuits.contains_key(&circuit_id) {
            self.total_dropped += 1;
            return RouteDecision::Drop(DropReason::UnknownCircuit);
        }

        // 2. Replay protection.
        let seen = self.seen_sequences.entry(circuit_id).or_default();
        if !seen.insert(cell.sequence) {
            if let Some(c) = self.circuits.get_mut(&circuit_id) {
                c.cells_dropped += 1;
            }
            self.total_dropped += 1;
            return RouteDecision::Drop(DropReason::ReplayDetected);
        }

        // 3. Policy check.
        let class = if cell.command == CMD_DATA {
            TrafficClass::Normal
        } else {
            TrafficClass::Cover
        };
        let action = self
            .policy
            .evaluate(&PolicyRequest::TrafficSend { circuit_id, class });
        if action != PolicyAction::Allow {
            if let Some(c) = self.circuits.get_mut(&circuit_id) {
                c.cells_dropped += 1;
            }
            self.total_dropped += 1;
            return RouteDecision::Drop(DropReason::PolicyDenied);
        }

        // 4. Route.
        let next_hop = self.circuits[&circuit_id].next_hop;

        // Loop guard: next hop must not be us.
        if next_hop.is_some_and(|hop| hop == self.local_id) {
            self.total_dropped += 1;
            return RouteDecision::Drop(DropReason::LoopDetected);
        }

        if let Some(c) = self.circuits.get_mut(&circuit_id) {
            c.cells_forwarded += 1;
        }
        self.total_forwarded += 1;

        match next_hop {
            None => RouteDecision::LocalDelivery,
            Some(hop) => RouteDecision::Forward(hop),
        }
    }

    pub fn policy_mut(&mut self) -> &mut PolicyEngine {
        &mut self.policy
    }

    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    pub fn total_forwarded(&self) -> u64 {
        self.total_forwarded
    }

    pub fn total_dropped(&self) -> u64 {
        self.total_dropped
    }

    pub fn circuit_stats(&self, circuit_id: u64) -> Option<(u64, u64)> {
        self.circuits
            .get(&circuit_id)
            .map(|c| (c.cells_forwarded, c.cells_dropped))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion_cell_v2::{CMD_DATA, OnionCellV2};
    use crate::policy_engine::PolicyRule;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn cell(circuit_id: u64, sequence: u64) -> OnionCellV2 {
        OnionCellV2 {
            command: CMD_DATA,
            circuit_id,
            stream_id: 0,
            sequence,
            header_mac: [0u8; 32],
            payload: [0u8; 1364],
        }
    }

    // ORR1: known circuit with next_hop returns Forward.
    #[test]
    fn orr1_known_circuit_forward() {
        let mut rt = OnionRelayRuntime::new(nid(0));
        rt.register_circuit(1, Some(nid(2)));
        assert_eq!(
            rt.process_inbound_cell(&cell(1, 0)),
            RouteDecision::Forward(nid(2))
        );
    }

    // ORR2: unknown circuit returns Drop(UnknownCircuit).
    #[test]
    fn orr2_unknown_circuit() {
        let mut rt = OnionRelayRuntime::new(nid(0));
        assert_eq!(
            rt.process_inbound_cell(&cell(99, 0)),
            RouteDecision::Drop(DropReason::UnknownCircuit)
        );
    }

    // ORR3: exit circuit (next_hop=None) returns LocalDelivery.
    #[test]
    fn orr3_local_delivery() {
        let mut rt = OnionRelayRuntime::new(nid(0));
        rt.register_circuit(1, None);
        assert_eq!(
            rt.process_inbound_cell(&cell(1, 0)),
            RouteDecision::LocalDelivery
        );
    }

    // ORR4: duplicate sequence returns Drop(ReplayDetected).
    #[test]
    fn orr4_replay_detected() {
        let mut rt = OnionRelayRuntime::new(nid(0));
        rt.register_circuit(1, Some(nid(2)));
        rt.process_inbound_cell(&cell(1, 0));
        assert_eq!(
            rt.process_inbound_cell(&cell(1, 0)),
            RouteDecision::Drop(DropReason::ReplayDetected)
        );
    }

    // ORR5: policy deny blocks forwarding.
    #[test]
    fn orr5_policy_denied() {
        use crate::policy_engine::TrafficClass;
        let mut rt = OnionRelayRuntime::new(nid(0));
        rt.register_circuit(1, Some(nid(2)));
        rt.policy_mut().add_rule(crate::policy_engine::PolicyRule {
            name: "deny-normal".into(),
            action: PolicyAction::Deny,
            min_trust: 0.0,
            denied_classes: vec![TrafficClass::Normal],
            max_privacy_mode: 0,
        });
        assert_eq!(
            rt.process_inbound_cell(&cell(1, 0)),
            RouteDecision::Drop(DropReason::PolicyDenied)
        );
    }

    // ORR6: loop prevention — next_hop == local_id dropped.
    #[test]
    fn orr6_loop_detected() {
        let mut rt = OnionRelayRuntime::new(nid(1));
        rt.register_circuit(1, Some(nid(1))); // next_hop == self
        assert_eq!(
            rt.process_inbound_cell(&cell(1, 0)),
            RouteDecision::Drop(DropReason::LoopDetected)
        );
    }

    // ORR7: total_forwarded increments on successful forward.
    #[test]
    fn orr7_total_forwarded() {
        let mut rt = OnionRelayRuntime::new(nid(0));
        rt.register_circuit(1, Some(nid(2)));
        rt.process_inbound_cell(&cell(1, 0));
        rt.process_inbound_cell(&cell(1, 1));
        assert_eq!(rt.total_forwarded(), 2);
    }

    // ORR8: total_dropped increments on drops.
    #[test]
    fn orr8_total_dropped() {
        let mut rt = OnionRelayRuntime::new(nid(0));
        rt.process_inbound_cell(&cell(99, 0)); // unknown circuit
        assert_eq!(rt.total_dropped(), 1);
    }

    // ORR9: remove_circuit makes subsequent cells return UnknownCircuit.
    #[test]
    fn orr9_remove_circuit() {
        let mut rt = OnionRelayRuntime::new(nid(0));
        rt.register_circuit(1, Some(nid(2)));
        rt.remove_circuit(1);
        assert_eq!(
            rt.process_inbound_cell(&cell(1, 0)),
            RouteDecision::Drop(DropReason::UnknownCircuit)
        );
    }

    // ORR10: circuit_stats returns per-circuit counts.
    #[test]
    fn orr10_circuit_stats() {
        let mut rt = OnionRelayRuntime::new(nid(0));
        rt.register_circuit(1, Some(nid(2)));
        rt.process_inbound_cell(&cell(1, 0));
        let (fwd, dropped) = rt.circuit_stats(1).unwrap();
        assert_eq!(fwd, 1);
        assert_eq!(dropped, 0);
    }
}
