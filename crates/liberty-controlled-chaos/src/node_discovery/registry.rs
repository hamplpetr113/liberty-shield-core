use std::collections::HashMap;

use super::types::{DiscoveryNodeId, NodeDescriptor, NodeDiscoveryError};

/// In-memory store of known relay nodes, keyed by `DiscoveryNodeId`.
pub struct NodeRegistry {
    nodes: HashMap<u64, NodeDescriptor>,
}

impl NodeRegistry {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    /// Insert a node.  Returns `DuplicateNode` if the id is already registered.
    pub fn register_node(&mut self, node: NodeDescriptor) -> Result<(), NodeDiscoveryError> {
        let id = node.node_id.0;
        if self.nodes.contains_key(&id) {
            return Err(NodeDiscoveryError::DuplicateNode(node.node_id));
        }
        self.nodes.insert(id, node);
        Ok(())
    }

    /// Remove and return a node.  Returns `NodeNotFound` if absent.
    pub fn remove_node(
        &mut self,
        node_id: DiscoveryNodeId,
    ) -> Result<NodeDescriptor, NodeDiscoveryError> {
        self.nodes
            .remove(&node_id.0)
            .ok_or(NodeDiscoveryError::NodeNotFound(node_id))
    }

    /// Borrow a node by id.  Returns `NodeNotFound` if absent.
    pub fn get_node(
        &self,
        node_id: DiscoveryNodeId,
    ) -> Result<&NodeDescriptor, NodeDiscoveryError> {
        self.nodes
            .get(&node_id.0)
            .ok_or(NodeDiscoveryError::NodeNotFound(node_id))
    }

    /// Return all registered nodes sorted deterministically by `node_id` ascending.
    pub fn list_nodes(&self) -> Vec<&NodeDescriptor> {
        let mut nodes: Vec<&NodeDescriptor> = self.nodes.values().collect();
        nodes.sort_by_key(|n| n.node_id);
        nodes
    }
}

impl Default for NodeRegistry {
    fn default() -> Self {
        Self::new()
    }
}
