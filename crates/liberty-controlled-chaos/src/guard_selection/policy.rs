use crate::node_discovery::NodeDescriptor;

use super::types::GuardNode;

/// Policy rules that a candidate node or an existing guard must satisfy.
#[derive(Debug, Clone)]
pub struct GuardPolicy {
    /// Minimum number of guard nodes to maintain.
    pub min_guards: usize,
    /// Maximum number of guard nodes to keep.
    pub max_guards: usize,
    /// Maximum acceptable latency in microseconds.
    pub max_latency: u32,
    /// Minimum required reliability score (inclusive).
    pub min_reliability: f64,
    /// Maximum tolerated failure count before a guard is evicted.
    pub max_failure_count: u32,
    /// Observation window in seconds used for stability assessment.
    pub stability_window: u64,
}

impl GuardPolicy {
    /// Whether a discovered `NodeDescriptor` is eligible for guard selection.
    ///
    /// Checks latency and reliability only; `NodeDescriptor` carries no failure
    /// count so that field is not evaluated here.
    pub fn accepts(&self, node: &NodeDescriptor) -> bool {
        if node.latency_estimate > self.max_latency as u64 {
            return false;
        }
        if node.reliability_score < self.min_reliability {
            return false;
        }
        true
    }

    /// Whether an already-selected `GuardNode` still meets policy requirements.
    ///
    /// Checks latency, reliability, and accumulated failure count.
    pub fn accepts_guard(&self, guard: &GuardNode) -> bool {
        if guard.latency_estimate > self.max_latency {
            return false;
        }
        if guard.reliability_score < self.min_reliability {
            return false;
        }
        if guard.failure_count > self.max_failure_count {
            return false;
        }
        true
    }
}

impl Default for GuardPolicy {
    fn default() -> Self {
        Self {
            min_guards: 3,
            max_guards: 5,
            max_latency: 500,
            min_reliability: 0.60,
            max_failure_count: 5,
            stability_window: 3600,
        }
    }
}
