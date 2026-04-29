use std::collections::HashMap;

/// Errors produced by the peer directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryError {
    /// A node with this ID is already registered.
    DuplicateNodeId,
    /// No node found for this ID.
    NodeNotFound,
}

/// Identity for a node in the peer directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerDirectoryNodeId(pub u64);

/// Role a node plays in the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    Guard,
    Relay,
    Exit,
}

impl PeerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            PeerRole::Guard => "Guard",
            PeerRole::Relay => "Relay",
            PeerRole::Exit => "Exit",
        }
    }
}

/// A static descriptor for one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerDescriptor {
    pub node_id: PeerDirectoryNodeId,
    pub role: PeerRole,
    pub address: String,
    pub port: u16,
}

impl PeerDescriptor {
    /// Build a deterministic descriptor from a node ID.
    /// Address is always `127.0.0.1` (loopback-only directory).
    pub fn deterministic(node_id: u64, base_port: u16) -> Self {
        let role = match node_id % 3 {
            0 => PeerRole::Guard,
            1 => PeerRole::Relay,
            _ => PeerRole::Exit,
        };
        Self {
            node_id: PeerDirectoryNodeId(node_id),
            role,
            address: "127.0.0.1".to_string(),
            port: base_port + node_id as u16,
        }
    }
}

/// Local-only peer directory.
///
/// Tracks `PeerDescriptor` entries indexed by `PeerDirectoryNodeId`.
/// All lookups are deterministic. No network access.
#[derive(Debug)]
pub struct PeerDirectory {
    peers: HashMap<u64, PeerDescriptor>,
}

impl PeerDirectory {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Register a new node. Returns `Err(DuplicateNodeId)` if the ID is already present.
    pub fn register_node(&mut self, desc: PeerDescriptor) -> Result<(), DirectoryError> {
        if self.peers.contains_key(&desc.node_id.0) {
            return Err(DirectoryError::DuplicateNodeId);
        }
        self.peers.insert(desc.node_id.0, desc);
        Ok(())
    }

    /// Remove a node. Returns `Err(NodeNotFound)` if absent.
    pub fn remove_node(&mut self, node_id: PeerDirectoryNodeId) -> Result<(), DirectoryError> {
        if self.peers.remove(&node_id.0).is_none() {
            return Err(DirectoryError::NodeNotFound);
        }
        Ok(())
    }

    /// List all registered nodes sorted by node_id for deterministic output.
    pub fn list_nodes(&self) -> Vec<&PeerDescriptor> {
        let mut v: Vec<&PeerDescriptor> = self.peers.values().collect();
        v.sort_by_key(|d| d.node_id.0);
        v
    }

    /// Look up one node by ID.
    pub fn lookup_node(&self, node_id: PeerDirectoryNodeId) -> Option<&PeerDescriptor> {
        self.peers.get(&node_id.0)
    }

    /// Assign roles deterministically to a slice of node IDs.
    ///
    /// Role distribution (0-indexed position mod 3):
    ///   0 → Guard, 1 → Relay, 2 → Exit
    pub fn assign_roles(&mut self, node_ids: &[PeerDirectoryNodeId]) {
        for (i, id) in node_ids.iter().enumerate() {
            if let Some(desc) = self.peers.get_mut(&id.0) {
                desc.role = match i % 3 {
                    0 => PeerRole::Guard,
                    1 => PeerRole::Relay,
                    _ => PeerRole::Exit,
                };
            }
        }
    }

    pub fn node_count(&self) -> usize {
        self.peers.len()
    }
}

impl Default for PeerDirectory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desc(id: u64) -> PeerDescriptor {
        PeerDescriptor::deterministic(id, 45000)
    }

    // D1: register node
    #[test]
    fn d1_register_node() {
        let mut dir = PeerDirectory::new();
        dir.register_node(desc(1)).unwrap();
        assert_eq!(dir.node_count(), 1);
    }

    // D2: remove node
    #[test]
    fn d2_remove_node() {
        let mut dir = PeerDirectory::new();
        dir.register_node(desc(1)).unwrap();
        dir.remove_node(PeerDirectoryNodeId(1)).unwrap();
        assert_eq!(dir.node_count(), 0);
    }

    // D3: list nodes returns sorted list
    #[test]
    fn d3_list_nodes() {
        let mut dir = PeerDirectory::new();
        for id in [3u64, 1, 2] {
            dir.register_node(desc(id)).unwrap();
        }
        let list = dir.list_nodes();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].node_id.0, 1);
        assert_eq!(list[1].node_id.0, 2);
        assert_eq!(list[2].node_id.0, 3);
    }

    // D4: lookup node
    #[test]
    fn d4_lookup_node() {
        let mut dir = PeerDirectory::new();
        dir.register_node(desc(5)).unwrap();
        assert!(dir.lookup_node(PeerDirectoryNodeId(5)).is_some());
        assert!(dir.lookup_node(PeerDirectoryNodeId(99)).is_none());
    }

    // D5: deterministic descriptor is reproducible
    #[test]
    fn d5_deterministic_descriptor() {
        let d1 = PeerDescriptor::deterministic(7, 45000);
        let d2 = PeerDescriptor::deterministic(7, 45000);
        assert_eq!(d1, d2);
        assert_eq!(d1.address, "127.0.0.1");
    }

    // D6: role assignment
    #[test]
    fn d6_role_assignment() {
        let mut dir = PeerDirectory::new();
        for id in 1u64..=3 {
            dir.register_node(PeerDescriptor {
                node_id: PeerDirectoryNodeId(id),
                role: PeerRole::Relay,
                address: "127.0.0.1".to_string(),
                port: 45000 + id as u16,
            })
            .unwrap();
        }
        let ids: Vec<PeerDirectoryNodeId> = (1u64..=3).map(PeerDirectoryNodeId).collect();
        dir.assign_roles(&ids);
        let list = dir.list_nodes();
        assert_eq!(list[0].role, PeerRole::Guard);
        assert_eq!(list[1].role, PeerRole::Relay);
        assert_eq!(list[2].role, PeerRole::Exit);
    }

    // D7: duplicate node_id rejected
    #[test]
    fn d7_reject_duplicate_node_id() {
        let mut dir = PeerDirectory::new();
        dir.register_node(desc(1)).unwrap();
        assert_eq!(
            dir.register_node(desc(1)).unwrap_err(),
            DirectoryError::DuplicateNodeId
        );
    }

    // D8: remove non-existent node returns error
    #[test]
    fn d8_remove_nonexistent_error() {
        let mut dir = PeerDirectory::new();
        assert_eq!(
            dir.remove_node(PeerDirectoryNodeId(99)).unwrap_err(),
            DirectoryError::NodeNotFound
        );
    }
}
