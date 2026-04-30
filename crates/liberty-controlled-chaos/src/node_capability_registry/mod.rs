//! Node capability registry — tracks which features each peer supports.
//!
//! Capabilities are bit-flagged per node and queried for compatibility checks.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum Capability {
    OnionRelay = 1 << 0,
    CoverTraffic = 1 << 1,
    CircuitExtend = 1 << 2,
    StreamMux = 1 << 3,
    DirectoryServe = 1 << 4,
    BandwidthProbe = 1 << 5,
}

impl Capability {
    pub fn flag(self) -> u32 {
        self as u32
    }
}

// ---------------------------------------------------------------------------
// CapabilitySet
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapabilitySet(pub u32);

impl CapabilitySet {
    pub fn empty() -> Self {
        Self(0)
    }

    pub fn with(self, cap: Capability) -> Self {
        Self(self.0 | cap.flag())
    }

    pub fn has(self, cap: Capability) -> bool {
        self.0 & cap.flag() != 0
    }

    pub fn satisfies(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

// ---------------------------------------------------------------------------
// NodeCapabilityRegistry
// ---------------------------------------------------------------------------

pub struct NodeCapabilityRegistry {
    entries: HashMap<[u8; 32], CapabilitySet>,
}

impl NodeCapabilityRegistry {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn register(&mut self, node_id: [u8; 32], caps: CapabilitySet) {
        self.entries.insert(node_id, caps);
    }

    pub fn update(&mut self, node_id: [u8; 32], caps: CapabilitySet) {
        self.entries.insert(node_id, caps);
    }

    pub fn remove(&mut self, node_id: &[u8; 32]) {
        self.entries.remove(node_id);
    }

    pub fn capabilities(&self, node_id: &[u8; 32]) -> Option<CapabilitySet> {
        self.entries.get(node_id).copied()
    }

    pub fn has_capability(&self, node_id: &[u8; 32], cap: Capability) -> bool {
        self.entries
            .get(node_id)
            .map(|s| s.has(cap))
            .unwrap_or(false)
    }

    /// Return all nodes that satisfy `required` capabilities.
    pub fn nodes_with(&self, required: CapabilitySet) -> Vec<[u8; 32]> {
        self.entries
            .iter()
            .filter(|(_, caps)| caps.satisfies(required))
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn node_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for NodeCapabilityRegistry {
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

    fn full_caps() -> CapabilitySet {
        CapabilitySet::empty()
            .with(Capability::OnionRelay)
            .with(Capability::CoverTraffic)
            .with(Capability::CircuitExtend)
    }

    // NCR1: registered node has correct capabilities.
    #[test]
    fn ncr1_register() {
        let mut r = NodeCapabilityRegistry::new();
        r.register(nid(1), full_caps());
        assert!(r.has_capability(&nid(1), Capability::OnionRelay));
    }

    // NCR2: unregistered node returns None.
    #[test]
    fn ncr2_unknown_node() {
        let r = NodeCapabilityRegistry::new();
        assert_eq!(r.capabilities(&nid(99)), None);
    }

    // NCR3: has_capability returns false for missing cap.
    #[test]
    fn ncr3_missing_cap() {
        let mut r = NodeCapabilityRegistry::new();
        r.register(nid(1), CapabilitySet::empty().with(Capability::OnionRelay));
        assert!(!r.has_capability(&nid(1), Capability::DirectoryServe));
    }

    // NCR4: nodes_with returns only matching nodes.
    #[test]
    fn ncr4_nodes_with() {
        let mut r = NodeCapabilityRegistry::new();
        r.register(nid(1), CapabilitySet::empty().with(Capability::OnionRelay));
        r.register(
            nid(2),
            CapabilitySet::empty().with(Capability::CoverTraffic),
        );
        let required = CapabilitySet::empty().with(Capability::OnionRelay);
        let matches = r.nodes_with(required);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0], nid(1));
    }

    // NCR5: remove deletes entry.
    #[test]
    fn ncr5_remove() {
        let mut r = NodeCapabilityRegistry::new();
        r.register(nid(1), full_caps());
        r.remove(&nid(1));
        assert_eq!(r.capabilities(&nid(1)), None);
    }

    // NCR6: update replaces capabilities.
    #[test]
    fn ncr6_update() {
        let mut r = NodeCapabilityRegistry::new();
        r.register(nid(1), CapabilitySet::empty().with(Capability::OnionRelay));
        r.update(
            nid(1),
            CapabilitySet::empty().with(Capability::DirectoryServe),
        );
        assert!(r.has_capability(&nid(1), Capability::DirectoryServe));
        assert!(!r.has_capability(&nid(1), Capability::OnionRelay));
    }

    // NCR7: satisfies checks all required bits.
    #[test]
    fn ncr7_satisfies() {
        let caps = CapabilitySet::empty()
            .with(Capability::OnionRelay)
            .with(Capability::StreamMux);
        let req = CapabilitySet::empty().with(Capability::OnionRelay);
        assert!(caps.satisfies(req));
        let req2 = CapabilitySet::empty().with(Capability::BandwidthProbe);
        assert!(!caps.satisfies(req2));
    }

    // NCR8: node_count increments on register.
    #[test]
    fn ncr8_node_count() {
        let mut r = NodeCapabilityRegistry::new();
        r.register(nid(1), full_caps());
        r.register(nid(2), full_caps());
        assert_eq!(r.node_count(), 2);
    }

    // NCR9: nodes_with empty required returns all nodes.
    #[test]
    fn ncr9_empty_required_matches_all() {
        let mut r = NodeCapabilityRegistry::new();
        r.register(nid(1), full_caps());
        r.register(nid(2), CapabilitySet::empty());
        let all = r.nodes_with(CapabilitySet::empty());
        assert_eq!(all.len(), 2);
    }

    // NCR10: CapabilitySet is bitwise composable.
    #[test]
    fn ncr10_bitwise() {
        let cs = CapabilitySet::empty()
            .with(Capability::OnionRelay)
            .with(Capability::CoverTraffic);
        assert!(cs.has(Capability::OnionRelay));
        assert!(cs.has(Capability::CoverTraffic));
        assert!(!cs.has(Capability::StreamMux));
    }
}
