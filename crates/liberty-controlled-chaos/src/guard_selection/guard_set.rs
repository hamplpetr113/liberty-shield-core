use crate::node_discovery::DiscoveryNodeId;

use super::types::{GuardNode, GuardSelectionError};

/// An ordered set of active guard nodes.
///
/// Maintains uniqueness by `node_id` and provides deterministic ordering by
/// `node_id` ascending on every `list_guards` call.
pub struct GuardSet {
    guards: Vec<GuardNode>,
}

impl GuardSet {
    pub fn new() -> Self {
        Self { guards: Vec::new() }
    }

    /// Construct from a pre-validated slice; duplicates are silently deduplicated
    /// (first occurrence wins).  Intended for internal construction only.
    pub fn from_guards(guards: Vec<GuardNode>) -> Self {
        let mut set = Self::new();
        for g in guards {
            // Silently ignore duplicates — caller is responsible for clean input.
            let _ = set.add_guard(g);
        }
        set
    }

    /// Insert a guard.  Returns `DuplicateGuard` if the `node_id` is taken.
    pub fn add_guard(&mut self, guard: GuardNode) -> Result<(), GuardSelectionError> {
        if self.contains(guard.node_id) {
            return Err(GuardSelectionError::DuplicateGuard(guard.node_id));
        }
        self.guards.push(guard);
        Ok(())
    }

    /// Remove a guard by `node_id`.  Returns `GuardNotFound` if absent.
    pub fn remove_guard(
        &mut self,
        node_id: DiscoveryNodeId,
    ) -> Result<GuardNode, GuardSelectionError> {
        let pos = self
            .guards
            .iter()
            .position(|g| g.node_id == node_id)
            .ok_or(GuardSelectionError::GuardNotFound(node_id))?;
        Ok(self.guards.remove(pos))
    }

    /// Borrow a guard by `node_id`.  Returns `GuardNotFound` if absent.
    pub fn get_guard(&self, node_id: DiscoveryNodeId) -> Result<&GuardNode, GuardSelectionError> {
        self.guards
            .iter()
            .find(|g| g.node_id == node_id)
            .ok_or(GuardSelectionError::GuardNotFound(node_id))
    }

    /// Return all guards sorted deterministically by `node_id` ascending.
    pub fn list_guards(&self) -> Vec<&GuardNode> {
        let mut sorted: Vec<&GuardNode> = self.guards.iter().collect();
        sorted.sort_by_key(|g| g.node_id);
        sorted
    }

    /// Number of guards currently in the set.
    pub fn active_count(&self) -> usize {
        self.guards.len()
    }

    pub fn contains(&self, node_id: DiscoveryNodeId) -> bool {
        self.guards.iter().any(|g| g.node_id == node_id)
    }

    /// Increment `success_count` and update `last_seen_timestamp`.
    pub fn record_success(
        &mut self,
        node_id: DiscoveryNodeId,
        timestamp: u64,
    ) -> Result<(), GuardSelectionError> {
        let guard = self
            .guards
            .iter_mut()
            .find(|g| g.node_id == node_id)
            .ok_or(GuardSelectionError::GuardNotFound(node_id))?;
        guard.success_count += 1;
        guard.last_seen_timestamp = timestamp;
        Ok(())
    }

    /// Increment `failure_count`.
    pub fn record_failure(&mut self, node_id: DiscoveryNodeId) -> Result<(), GuardSelectionError> {
        let guard = self
            .guards
            .iter_mut()
            .find(|g| g.node_id == node_id)
            .ok_or(GuardSelectionError::GuardNotFound(node_id))?;
        guard.failure_count += 1;
        Ok(())
    }
}

impl Default for GuardSet {
    fn default() -> Self {
        Self::new()
    }
}
