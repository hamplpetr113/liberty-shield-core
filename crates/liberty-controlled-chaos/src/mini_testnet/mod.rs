//! Mini testnet — virtual multi-node network for in-process simulation.
//!
//! `TestnetController` spawns virtual `TestnetNode`s (no real I/O) and lets
//! callers build simulated circuits, send packets through them, and query
//! aggregate `TestnetMetrics`.  All state is deterministic and epoch-driven.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// TestnetNode
// ---------------------------------------------------------------------------

/// A virtual node in the simulated network.
#[derive(Debug, Clone)]
pub struct TestnetNode {
    pub node_id: [u8; 32],
    pub address: String,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub circuits_built: u64,
    pub is_online: bool,
}

impl TestnetNode {
    fn new(node_id: [u8; 32], address: String) -> Self {
        Self {
            node_id,
            address,
            packets_sent: 0,
            packets_received: 0,
            circuits_built: 0,
            is_online: true,
        }
    }
}

// ---------------------------------------------------------------------------
// SimulatedCircuit
// ---------------------------------------------------------------------------

/// A three-hop circuit in the simulated network.
#[derive(Debug, Clone)]
pub struct SimulatedCircuit {
    pub circuit_id: u64,
    pub guard_id: [u8; 32],
    pub relay_id: [u8; 32],
    pub exit_id: [u8; 32],
    pub built_epoch: u64,
    pub packets_forwarded: u64,
}

// ---------------------------------------------------------------------------
// TestnetMetrics
// ---------------------------------------------------------------------------

/// Aggregate statistics over the whole testnet.
#[derive(Debug, Clone, Default)]
pub struct TestnetMetrics {
    pub epoch: u64,
    pub total_nodes: usize,
    pub online_nodes: usize,
    pub total_circuits: usize,
    pub total_packets_forwarded: u64,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestnetError {
    NodeNotFound,
    CircuitNotFound,
    NodeOffline,
    DuplicateNode,
}

// ---------------------------------------------------------------------------
// TestnetController
// ---------------------------------------------------------------------------

/// Orchestrates a virtual multi-node network.
pub struct TestnetController {
    nodes: HashMap<[u8; 32], TestnetNode>,
    circuits: HashMap<u64, SimulatedCircuit>,
    next_circuit_id: u64,
    current_epoch: u64,
}

impl TestnetController {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            circuits: HashMap::new(),
            next_circuit_id: 1,
            current_epoch: 0,
        }
    }

    /// Add a virtual node.  Returns `DuplicateNode` if the id already exists.
    pub fn add_node(&mut self, node_id: [u8; 32], address: String) -> Result<(), TestnetError> {
        if self.nodes.contains_key(&node_id) {
            return Err(TestnetError::DuplicateNode);
        }
        self.nodes
            .insert(node_id, TestnetNode::new(node_id, address));
        Ok(())
    }

    /// Remove a node and all circuits it participates in.
    pub fn remove_node(&mut self, node_id: &[u8; 32]) -> Result<(), TestnetError> {
        if self.nodes.remove(node_id).is_none() {
            return Err(TestnetError::NodeNotFound);
        }
        self.circuits.retain(|_, c| {
            &c.guard_id != node_id && &c.relay_id != node_id && &c.exit_id != node_id
        });
        Ok(())
    }

    /// Toggle a node's online status.
    pub fn set_node_online(
        &mut self,
        node_id: &[u8; 32],
        online: bool,
    ) -> Result<(), TestnetError> {
        self.nodes
            .get_mut(node_id)
            .ok_or(TestnetError::NodeNotFound)
            .map(|n| n.is_online = online)
    }

    /// Build a simulated 3-hop circuit.  All three nodes must be online.
    pub fn build_circuit(
        &mut self,
        guard: [u8; 32],
        relay: [u8; 32],
        exit: [u8; 32],
    ) -> Result<u64, TestnetError> {
        for id in [&guard, &relay, &exit] {
            let node = self.nodes.get(id).ok_or(TestnetError::NodeNotFound)?;
            if !node.is_online {
                return Err(TestnetError::NodeOffline);
            }
        }
        let circuit_id = self.next_circuit_id;
        self.next_circuit_id += 1;
        for id in [guard, relay, exit] {
            if let Some(n) = self.nodes.get_mut(&id) {
                n.circuits_built += 1;
            }
        }
        self.circuits.insert(
            circuit_id,
            SimulatedCircuit {
                circuit_id,
                guard_id: guard,
                relay_id: relay,
                exit_id: exit,
                built_epoch: self.current_epoch,
                packets_forwarded: 0,
            },
        );
        Ok(circuit_id)
    }

    /// Send one packet through a circuit, updating per-node counters.
    pub fn send_packet(&mut self, circuit_id: u64) -> Result<(), TestnetError> {
        let c = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or(TestnetError::CircuitNotFound)?;
        c.packets_forwarded += 1;
        let guard = c.guard_id;
        let relay = c.relay_id;
        let exit = c.exit_id;
        for id in [guard, relay, exit] {
            if let Some(n) = self.nodes.get_mut(&id) {
                n.packets_sent += 1;
                n.packets_received += 1;
            }
        }
        Ok(())
    }

    pub fn advance_epoch(&mut self) {
        self.current_epoch += 1;
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn metrics(&self) -> TestnetMetrics {
        let online_nodes = self.nodes.values().filter(|n| n.is_online).count();
        let total_packets_forwarded = self.circuits.values().map(|c| c.packets_forwarded).sum();
        TestnetMetrics {
            epoch: self.current_epoch,
            total_nodes: self.nodes.len(),
            online_nodes,
            total_circuits: self.circuits.len(),
            total_packets_forwarded,
        }
    }

    pub fn node(&self, node_id: &[u8; 32]) -> Option<&TestnetNode> {
        self.nodes.get(node_id)
    }

    pub fn circuit(&self, circuit_id: u64) -> Option<&SimulatedCircuit> {
        self.circuits.get(&circuit_id)
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    pub fn online_node_ids(&self) -> Vec<[u8; 32]> {
        self.nodes
            .values()
            .filter(|n| n.is_online)
            .map(|n| n.node_id)
            .collect()
    }
}

impl Default for TestnetController {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn controller_with_nodes() -> TestnetController {
        let mut c = TestnetController::new();
        c.add_node(nid(1), "127.0.0.1:9001".into()).unwrap();
        c.add_node(nid(2), "127.0.0.1:9002".into()).unwrap();
        c.add_node(nid(3), "127.0.0.1:9003".into()).unwrap();
        c
    }

    // TN1: add_node creates an online node.
    #[test]
    fn tn1_add_node() {
        let mut c = TestnetController::new();
        c.add_node(nid(1), "addr".into()).unwrap();
        assert_eq!(c.node_count(), 1);
        assert!(c.node(&nid(1)).unwrap().is_online);
    }

    // TN2: duplicate node returns DuplicateNode.
    #[test]
    fn tn2_duplicate_node() {
        let mut c = TestnetController::new();
        c.add_node(nid(1), "addr".into()).unwrap();
        assert_eq!(
            c.add_node(nid(1), "addr".into()),
            Err(TestnetError::DuplicateNode)
        );
    }

    // TN3: build_circuit creates a circuit and returns a valid id.
    #[test]
    fn tn3_build_circuit() {
        let mut c = controller_with_nodes();
        let cid = c.build_circuit(nid(1), nid(2), nid(3)).unwrap();
        assert_eq!(c.circuit_count(), 1);
        assert_eq!(c.circuit(cid).unwrap().circuit_id, cid);
    }

    // TN4: build_circuit with offline node returns NodeOffline.
    #[test]
    fn tn4_offline_node_circuit() {
        let mut c = controller_with_nodes();
        c.set_node_online(&nid(2), false).unwrap();
        assert_eq!(
            c.build_circuit(nid(1), nid(2), nid(3)),
            Err(TestnetError::NodeOffline)
        );
    }

    // TN5: send_packet increments packet counters.
    #[test]
    fn tn5_send_packet() {
        let mut c = controller_with_nodes();
        let cid = c.build_circuit(nid(1), nid(2), nid(3)).unwrap();
        c.send_packet(cid).unwrap();
        assert_eq!(c.circuit(cid).unwrap().packets_forwarded, 1);
        assert_eq!(c.node(&nid(1)).unwrap().packets_sent, 1);
    }

    // TN6: metrics aggregates correctly.
    #[test]
    fn tn6_metrics() {
        let mut c = controller_with_nodes();
        let cid = c.build_circuit(nid(1), nid(2), nid(3)).unwrap();
        c.send_packet(cid).unwrap();
        c.send_packet(cid).unwrap();
        let m = c.metrics();
        assert_eq!(m.total_nodes, 3);
        assert_eq!(m.online_nodes, 3);
        assert_eq!(m.total_circuits, 1);
        assert_eq!(m.total_packets_forwarded, 2);
    }

    // TN7: remove_node removes associated circuits.
    #[test]
    fn tn7_remove_node_removes_circuits() {
        let mut c = controller_with_nodes();
        c.build_circuit(nid(1), nid(2), nid(3)).unwrap();
        c.remove_node(&nid(1)).unwrap();
        assert_eq!(c.circuit_count(), 0);
        assert_eq!(c.node_count(), 2);
    }

    // TN8: set_node_online toggles status.
    #[test]
    fn tn8_set_online_toggle() {
        let mut c = controller_with_nodes();
        c.set_node_online(&nid(1), false).unwrap();
        assert!(!c.node(&nid(1)).unwrap().is_online);
        c.set_node_online(&nid(1), true).unwrap();
        assert!(c.node(&nid(1)).unwrap().is_online);
    }

    // TN9: advance_epoch increments current epoch.
    #[test]
    fn tn9_advance_epoch() {
        let mut c = TestnetController::new();
        c.advance_epoch();
        c.advance_epoch();
        assert_eq!(c.current_epoch(), 2);
    }

    // TN10: build_circuit records built_epoch correctly.
    #[test]
    fn tn10_built_epoch() {
        let mut c = controller_with_nodes();
        c.advance_epoch();
        c.advance_epoch();
        let cid = c.build_circuit(nid(1), nid(2), nid(3)).unwrap();
        assert_eq!(c.circuit(cid).unwrap().built_epoch, 2);
    }

    // TN11: send_packet on unknown circuit returns CircuitNotFound.
    #[test]
    fn tn11_unknown_circuit() {
        let mut c = TestnetController::new();
        assert_eq!(c.send_packet(999), Err(TestnetError::CircuitNotFound));
    }

    // TN12: online_node_ids excludes offline nodes.
    #[test]
    fn tn12_online_node_ids() {
        let mut c = controller_with_nodes();
        c.set_node_online(&nid(2), false).unwrap();
        let online = c.online_node_ids();
        assert!(!online.contains(&nid(2)));
        assert_eq!(online.len(), 2);
    }

    // TN14: remove_node on unknown id returns NodeNotFound.
    #[test]
    fn tn14_remove_unknown_node() {
        let mut c = TestnetController::new();
        assert_eq!(c.remove_node(&nid(99)), Err(TestnetError::NodeNotFound));
    }

    // TN15: build_circuit with unknown node returns NodeNotFound.
    #[test]
    fn tn15_build_circuit_unknown_node() {
        let mut c = TestnetController::new();
        c.add_node(nid(1), "a".into()).unwrap();
        c.add_node(nid(2), "b".into()).unwrap();
        assert_eq!(
            c.build_circuit(nid(1), nid(2), nid(99)),
            Err(TestnetError::NodeNotFound)
        );
    }

    // TN13: multiple circuits tracked independently.
    #[test]
    fn tn13_multiple_circuits() {
        let mut c = controller_with_nodes();
        c.add_node(nid(4), "127.0.0.1:9004".into()).unwrap();
        c.add_node(nid(5), "127.0.0.1:9005".into()).unwrap();
        c.add_node(nid(6), "127.0.0.1:9006".into()).unwrap();
        let cid1 = c.build_circuit(nid(1), nid(2), nid(3)).unwrap();
        let cid2 = c.build_circuit(nid(4), nid(5), nid(6)).unwrap();
        c.send_packet(cid1).unwrap();
        c.send_packet(cid2).unwrap();
        c.send_packet(cid2).unwrap();
        assert_eq!(c.circuit(cid1).unwrap().packets_forwarded, 1);
        assert_eq!(c.circuit(cid2).unwrap().packets_forwarded, 2);
    }
}
