//! Mini testnet v2 — larger-scale in-process mesh simulation.
//!
//! Extends the original mini_testnet with up to 25 nodes, multi-hop circuit
//! chains, and a simple failure injection model.  All nodes are virtual; no
//! real network I/O is performed.

use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// NodeRole
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    Guard,
    Relay,
    Exit,
    Mixed,
}

// ---------------------------------------------------------------------------
// V2Node
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct V2Node {
    pub node_id: [u8; 32],
    pub role: NodeRole,
    pub online: bool,
    pub packets_received: u64,
    pub packets_sent: u64,
}

impl V2Node {
    pub fn new(node_id: [u8; 32], role: NodeRole) -> Self {
        Self {
            node_id,
            role,
            online: true,
            packets_received: 0,
            packets_sent: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// V2Circuit
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct V2Circuit {
    pub circuit_id: u64,
    /// Ordered list of node IDs (guard → relay(s) → exit).
    pub hops: Vec<[u8; 32]>,
    pub packets_forwarded: u64,
    pub created_epoch: u64,
}

// ---------------------------------------------------------------------------
// TestnetV2Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestnetV2Error {
    NodeNotFound,
    NodeOffline,
    CircuitNotFound,
    DuplicateNode,
    InsufficientHops,
    TooManyNodes,
    DuplicateCircuit,
}

// ---------------------------------------------------------------------------
// TestnetV2Metrics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct TestnetV2Metrics {
    pub total_packets: u64,
    pub circuits_built: u64,
    pub circuits_torn_down: u64,
    pub failures_injected: u64,
    pub recoveries: u64,
}

// ---------------------------------------------------------------------------
// TestnetV2Controller
// ---------------------------------------------------------------------------

pub struct TestnetV2Controller {
    nodes: HashMap<[u8; 32], V2Node>,
    circuits: HashMap<u64, V2Circuit>,
    metrics: TestnetV2Metrics,
    next_circuit_id: u64,
    max_nodes: usize,
}

impl TestnetV2Controller {
    pub fn new(max_nodes: usize) -> Self {
        Self {
            nodes: HashMap::new(),
            circuits: HashMap::new(),
            metrics: TestnetV2Metrics::default(),
            next_circuit_id: 1,
            max_nodes,
        }
    }

    pub fn add_node(&mut self, node_id: [u8; 32], role: NodeRole) -> Result<(), TestnetV2Error> {
        if self.nodes.len() >= self.max_nodes {
            return Err(TestnetV2Error::TooManyNodes);
        }
        if self.nodes.contains_key(&node_id) {
            return Err(TestnetV2Error::DuplicateNode);
        }
        self.nodes.insert(node_id, V2Node::new(node_id, role));
        Ok(())
    }

    pub fn remove_node(&mut self, node_id: &[u8; 32]) -> Result<(), TestnetV2Error> {
        if self.nodes.remove(node_id).is_none() {
            return Err(TestnetV2Error::NodeNotFound);
        }
        // Cascade: remove circuits that include this node.
        self.circuits.retain(|_, c| !c.hops.contains(node_id));
        Ok(())
    }

    pub fn set_online(&mut self, node_id: &[u8; 32], online: bool) -> Result<(), TestnetV2Error> {
        let node = self
            .nodes
            .get_mut(node_id)
            .ok_or(TestnetV2Error::NodeNotFound)?;
        node.online = online;
        if !online {
            self.metrics.failures_injected += 1;
        } else {
            self.metrics.recoveries += 1;
        }
        Ok(())
    }

    /// Build a circuit through an ordered list of hops (minimum 2).
    pub fn build_circuit(
        &mut self,
        hops: Vec<[u8; 32]>,
        epoch: u64,
    ) -> Result<u64, TestnetV2Error> {
        if hops.len() < 2 {
            return Err(TestnetV2Error::InsufficientHops);
        }
        for nid in &hops {
            let node = self.nodes.get(nid).ok_or(TestnetV2Error::NodeNotFound)?;
            if !node.online {
                return Err(TestnetV2Error::NodeOffline);
            }
        }
        let id = self.next_circuit_id;
        self.next_circuit_id += 1;
        self.circuits.insert(
            id,
            V2Circuit {
                circuit_id: id,
                hops,
                packets_forwarded: 0,
                created_epoch: epoch,
            },
        );
        self.metrics.circuits_built += 1;
        Ok(id)
    }

    pub fn tear_down_circuit(&mut self, circuit_id: u64) -> Result<(), TestnetV2Error> {
        if self.circuits.remove(&circuit_id).is_none() {
            return Err(TestnetV2Error::CircuitNotFound);
        }
        self.metrics.circuits_torn_down += 1;
        Ok(())
    }

    /// Send a packet through a circuit, incrementing counters for each hop.
    pub fn send_packet(&mut self, circuit_id: u64) -> Result<(), TestnetV2Error> {
        let circuit = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or(TestnetV2Error::CircuitNotFound)?;
        let hops: Vec<[u8; 32]> = circuit.hops.clone();
        // Check all hops are still online.
        for nid in &hops {
            if let Some(n) = self.nodes.get(nid) {
                if !n.online {
                    return Err(TestnetV2Error::NodeOffline);
                }
            } else {
                return Err(TestnetV2Error::NodeNotFound);
            }
        }
        circuit.packets_forwarded += 1;
        self.metrics.total_packets += 1;
        // Update per-node counters.
        for (i, nid) in hops.iter().enumerate() {
            if let Some(node) = self.nodes.get_mut(nid) {
                if i == 0 {
                    node.packets_sent += 1;
                } else {
                    node.packets_received += 1;
                }
            }
        }
        Ok(())
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    pub fn online_nodes(&self) -> Vec<[u8; 32]> {
        self.nodes
            .values()
            .filter(|n| n.online)
            .map(|n| n.node_id)
            .collect()
    }

    pub fn metrics(&self) -> &TestnetV2Metrics {
        &self.metrics
    }

    pub fn circuit(&self, id: u64) -> Option<&V2Circuit> {
        self.circuits.get(&id)
    }

    pub fn nodes_with_role(&self, role: NodeRole) -> Vec<[u8; 32]> {
        self.nodes
            .values()
            .filter(|n| n.role == role)
            .map(|n| n.node_id)
            .collect()
    }

    /// Returns circuit IDs where any hop is offline.
    pub fn broken_circuits(&self) -> Vec<u64> {
        let offline: HashSet<[u8; 32]> = self
            .nodes
            .values()
            .filter(|n| !n.online)
            .map(|n| n.node_id)
            .collect();
        self.circuits
            .values()
            .filter(|c| c.hops.iter().any(|h| offline.contains(h)))
            .map(|c| c.circuit_id)
            .collect()
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

    fn ctrl() -> TestnetV2Controller {
        TestnetV2Controller::new(25)
    }

    // MT2_1: add_node registers a node.
    #[test]
    fn mt2_1_add_node() {
        let mut c = ctrl();
        c.add_node(nid(1), NodeRole::Guard).unwrap();
        assert_eq!(c.node_count(), 1);
    }

    // MT2_2: build_circuit creates a circuit.
    #[test]
    fn mt2_2_build_circuit() {
        let mut c = ctrl();
        c.add_node(nid(1), NodeRole::Guard).unwrap();
        c.add_node(nid(2), NodeRole::Relay).unwrap();
        c.add_node(nid(3), NodeRole::Exit).unwrap();
        let id = c.build_circuit(vec![nid(1), nid(2), nid(3)], 0).unwrap();
        assert_eq!(c.circuit(id).unwrap().hops.len(), 3);
    }

    // MT2_3: send_packet increments forwarded counter.
    #[test]
    fn mt2_3_send_packet() {
        let mut c = ctrl();
        c.add_node(nid(1), NodeRole::Guard).unwrap();
        c.add_node(nid(2), NodeRole::Exit).unwrap();
        let id = c.build_circuit(vec![nid(1), nid(2)], 0).unwrap();
        c.send_packet(id).unwrap();
        assert_eq!(c.circuit(id).unwrap().packets_forwarded, 1);
    }

    // MT2_4: offline node blocks circuit build.
    #[test]
    fn mt2_4_offline_blocks_build() {
        let mut c = ctrl();
        c.add_node(nid(1), NodeRole::Guard).unwrap();
        c.add_node(nid(2), NodeRole::Exit).unwrap();
        c.set_online(&nid(2), false).unwrap();
        assert_eq!(
            c.build_circuit(vec![nid(1), nid(2)], 0),
            Err(TestnetV2Error::NodeOffline)
        );
    }

    // MT2_5: tear_down_circuit removes circuit.
    #[test]
    fn mt2_5_tear_down() {
        let mut c = ctrl();
        c.add_node(nid(1), NodeRole::Guard).unwrap();
        c.add_node(nid(2), NodeRole::Exit).unwrap();
        let id = c.build_circuit(vec![nid(1), nid(2)], 0).unwrap();
        c.tear_down_circuit(id).unwrap();
        assert_eq!(c.circuit_count(), 0);
    }

    // MT2_6: remove_node cascades to circuits.
    #[test]
    fn mt2_6_remove_node_cascades() {
        let mut c = ctrl();
        c.add_node(nid(1), NodeRole::Guard).unwrap();
        c.add_node(nid(2), NodeRole::Exit).unwrap();
        c.build_circuit(vec![nid(1), nid(2)], 0).unwrap();
        c.remove_node(&nid(1)).unwrap();
        assert_eq!(c.circuit_count(), 0);
    }

    // MT2_7: TooManyNodes enforced.
    #[test]
    fn mt2_7_too_many_nodes() {
        let mut c = TestnetV2Controller::new(2);
        c.add_node(nid(1), NodeRole::Guard).unwrap();
        c.add_node(nid(2), NodeRole::Exit).unwrap();
        assert_eq!(
            c.add_node(nid(3), NodeRole::Relay),
            Err(TestnetV2Error::TooManyNodes)
        );
    }

    // MT2_8: broken_circuits detects offline hops.
    #[test]
    fn mt2_8_broken_circuits() {
        let mut c = ctrl();
        c.add_node(nid(1), NodeRole::Guard).unwrap();
        c.add_node(nid(2), NodeRole::Exit).unwrap();
        let id = c.build_circuit(vec![nid(1), nid(2)], 0).unwrap();
        c.set_online(&nid(2), false).unwrap();
        assert!(c.broken_circuits().contains(&id));
    }

    // MT2_9: metrics track circuits_built.
    #[test]
    fn mt2_9_metrics_circuits_built() {
        let mut c = ctrl();
        c.add_node(nid(1), NodeRole::Guard).unwrap();
        c.add_node(nid(2), NodeRole::Exit).unwrap();
        c.build_circuit(vec![nid(1), nid(2)], 0).unwrap();
        assert_eq!(c.metrics().circuits_built, 1);
    }

    // MT2_10: nodes_with_role filters by role.
    #[test]
    fn mt2_10_nodes_with_role() {
        let mut c = ctrl();
        c.add_node(nid(1), NodeRole::Guard).unwrap();
        c.add_node(nid(2), NodeRole::Exit).unwrap();
        c.add_node(nid(3), NodeRole::Guard).unwrap();
        assert_eq!(c.nodes_with_role(NodeRole::Guard).len(), 2);
    }
}
