//! Topology snapshot — immutable view of the known network topology.

#[derive(Debug, Clone)]
pub struct TopologyEdge {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub latency_us: u64,
    pub bandwidth_kbps: u64,
}

#[derive(Debug, Clone)]
pub struct TopologySnapshot {
    pub epoch: u64,
    nodes: Vec<[u8; 32]>,
    edges: Vec<TopologyEdge>,
}

impl TopologySnapshot {
    pub fn new(epoch: u64, nodes: Vec<[u8; 32]>, edges: Vec<TopologyEdge>) -> Self {
        Self {
            epoch,
            nodes,
            edges,
        }
    }

    pub fn nodes(&self) -> &[[u8; 32]] {
        &self.nodes
    }

    pub fn edges(&self) -> &[TopologyEdge] {
        &self.edges
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    pub fn has_node(&self, node_id: &[u8; 32]) -> bool {
        self.nodes.contains(node_id)
    }

    pub fn edges_from(&self, node_id: &[u8; 32]) -> Vec<&TopologyEdge> {
        self.edges.iter().filter(|e| &e.from == node_id).collect()
    }

    pub fn edges_to(&self, node_id: &[u8; 32]) -> Vec<&TopologyEdge> {
        self.edges.iter().filter(|e| &e.to == node_id).collect()
    }

    pub fn is_stale(&self, current_epoch: u64, max_age: u64) -> bool {
        current_epoch.saturating_sub(self.epoch) > max_age
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn edge(from: u8, to: u8) -> TopologyEdge {
        TopologyEdge {
            from: nid(from),
            to: nid(to),
            latency_us: 1000,
            bandwidth_kbps: 10000,
        }
    }

    // TS1: node_count correct.
    #[test]
    fn ts1_node_count() {
        let s = TopologySnapshot::new(1, vec![nid(1), nid(2)], vec![]);
        assert_eq!(s.node_count(), 2);
    }

    // TS2: edge_count correct.
    #[test]
    fn ts2_edge_count() {
        let s = TopologySnapshot::new(1, vec![], vec![edge(1, 2), edge(2, 3)]);
        assert_eq!(s.edge_count(), 2);
    }

    // TS3: has_node true for known node.
    #[test]
    fn ts3_has_node() {
        let s = TopologySnapshot::new(1, vec![nid(1)], vec![]);
        assert!(s.has_node(&nid(1)));
    }

    // TS4: has_node false for unknown node.
    #[test]
    fn ts4_no_node() {
        let s = TopologySnapshot::new(1, vec![], vec![]);
        assert!(!s.has_node(&nid(99)));
    }

    // TS5: edges_from filters correctly.
    #[test]
    fn ts5_edges_from() {
        let s = TopologySnapshot::new(1, vec![], vec![edge(1, 2), edge(1, 3), edge(2, 3)]);
        assert_eq!(s.edges_from(&nid(1)).len(), 2);
    }

    // TS6: edges_to filters correctly.
    #[test]
    fn ts6_edges_to() {
        let s = TopologySnapshot::new(1, vec![], vec![edge(1, 3), edge(2, 3)]);
        assert_eq!(s.edges_to(&nid(3)).len(), 2);
    }

    // TS7: epoch is stored.
    #[test]
    fn ts7_epoch() {
        let s = TopologySnapshot::new(42, vec![], vec![]);
        assert_eq!(s.epoch, 42);
    }

    // TS8: is_stale false within max_age.
    #[test]
    fn ts8_not_stale() {
        let s = TopologySnapshot::new(10, vec![], vec![]);
        assert!(!s.is_stale(15, 10));
    }

    // TS9: is_stale true beyond max_age.
    #[test]
    fn ts9_stale() {
        let s = TopologySnapshot::new(0, vec![], vec![]);
        assert!(s.is_stale(100, 10));
    }

    // TS10: nodes slice accessible.
    #[test]
    fn ts10_nodes_slice() {
        let s = TopologySnapshot::new(1, vec![nid(1), nid(2)], vec![]);
        assert_eq!(s.nodes().len(), 2);
    }
}
