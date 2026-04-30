//! Mesh health runtime — aggregates per-node and per-circuit health signals.
//!
//! Maintains rolling availability scores, detects degraded nodes, and emits
//! health summaries.  No I/O; signals are injected by the caller.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// HealthStatus
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unreachable,
}

// ---------------------------------------------------------------------------
// NodeHealth
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NodeHealth {
    pub node_id: [u8; 32],
    pub consecutive_failures: u32,
    pub total_pings: u64,
    pub total_failures: u64,
    pub last_seen_epoch: u64,
    pub status: HealthStatus,
}

impl NodeHealth {
    fn new(node_id: [u8; 32]) -> Self {
        Self {
            node_id,
            consecutive_failures: 0,
            total_pings: 0,
            total_failures: 0,
            last_seen_epoch: 0,
            status: HealthStatus::Healthy,
        }
    }

    fn recompute_status(&mut self, degraded_threshold: u32, unreachable_threshold: u32) {
        if self.consecutive_failures >= unreachable_threshold {
            self.status = HealthStatus::Unreachable;
        } else if self.consecutive_failures >= degraded_threshold {
            self.status = HealthStatus::Degraded;
        } else {
            self.status = HealthStatus::Healthy;
        }
    }
}

// ---------------------------------------------------------------------------
// HealthSummary
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HealthSummary {
    pub healthy: usize,
    pub degraded: usize,
    pub unreachable: usize,
    pub total: usize,
}

// ---------------------------------------------------------------------------
// MeshHealthRuntime
// ---------------------------------------------------------------------------

pub struct MeshHealthRuntime {
    degraded_threshold: u32,
    unreachable_threshold: u32,
    stale_epoch_window: u64,
    nodes: HashMap<[u8; 32], NodeHealth>,
    health_checks: u64,
}

impl MeshHealthRuntime {
    pub fn new(
        degraded_threshold: u32,
        unreachable_threshold: u32,
        stale_epoch_window: u64,
    ) -> Self {
        Self {
            degraded_threshold,
            unreachable_threshold,
            stale_epoch_window,
            nodes: HashMap::new(),
            health_checks: 0,
        }
    }

    pub fn register_node(&mut self, node_id: [u8; 32]) {
        self.nodes
            .entry(node_id)
            .or_insert_with(|| NodeHealth::new(node_id));
    }

    pub fn remove_node(&mut self, node_id: &[u8; 32]) {
        self.nodes.remove(node_id);
    }

    /// Record a successful ping response.
    pub fn record_success(&mut self, node_id: [u8; 32], epoch: u64) {
        let dg = self.degraded_threshold;
        let un = self.unreachable_threshold;
        let h = self
            .nodes
            .entry(node_id)
            .or_insert_with(|| NodeHealth::new(node_id));
        h.total_pings += 1;
        h.consecutive_failures = 0;
        h.last_seen_epoch = epoch;
        h.recompute_status(dg, un);
        self.health_checks += 1;
    }

    /// Record a failed ping.
    pub fn record_failure(&mut self, node_id: [u8; 32], epoch: u64) {
        let dg = self.degraded_threshold;
        let un = self.unreachable_threshold;
        let h = self
            .nodes
            .entry(node_id)
            .or_insert_with(|| NodeHealth::new(node_id));
        h.total_pings += 1;
        h.total_failures += 1;
        h.consecutive_failures += 1;
        h.last_seen_epoch = epoch;
        h.recompute_status(dg, un);
        self.health_checks += 1;
    }

    pub fn status(&self, node_id: &[u8; 32]) -> Option<HealthStatus> {
        self.nodes.get(node_id).map(|h| h.status)
    }

    pub fn node_health(&self, node_id: &[u8; 32]) -> Option<&NodeHealth> {
        self.nodes.get(node_id)
    }

    pub fn summary(&self) -> HealthSummary {
        let mut healthy = 0usize;
        let mut degraded = 0usize;
        let mut unreachable = 0usize;
        for h in self.nodes.values() {
            match h.status {
                HealthStatus::Healthy => healthy += 1,
                HealthStatus::Degraded => degraded += 1,
                HealthStatus::Unreachable => unreachable += 1,
            }
        }
        HealthSummary {
            healthy,
            degraded,
            unreachable,
            total: self.nodes.len(),
        }
    }

    /// Mark nodes that haven't been seen within `stale_epoch_window` as Unreachable.
    pub fn apply_staleness(&mut self, current_epoch: u64) {
        let window = self.stale_epoch_window;
        for h in self.nodes.values_mut() {
            if current_epoch.saturating_sub(h.last_seen_epoch) > window {
                h.status = HealthStatus::Unreachable;
            }
        }
    }

    pub fn healthy_nodes(&self) -> Vec<[u8; 32]> {
        self.nodes
            .values()
            .filter(|h| h.status == HealthStatus::Healthy)
            .map(|h| h.node_id)
            .collect()
    }

    pub fn health_check_count(&self) -> u64 {
        self.health_checks
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

    fn runtime() -> MeshHealthRuntime {
        MeshHealthRuntime::new(2, 5, 10)
    }

    // MHR1: registered node starts Healthy.
    #[test]
    fn mhr1_initial_healthy() {
        let mut r = runtime();
        r.register_node(nid(1));
        assert_eq!(r.status(&nid(1)), Some(HealthStatus::Healthy));
    }

    // MHR2: failures below degraded_threshold stay Healthy.
    #[test]
    fn mhr2_below_threshold() {
        let mut r = runtime();
        r.register_node(nid(1));
        r.record_failure(nid(1), 1);
        assert_eq!(r.status(&nid(1)), Some(HealthStatus::Healthy));
    }

    // MHR3: failures at degraded_threshold → Degraded.
    #[test]
    fn mhr3_degraded() {
        let mut r = runtime();
        r.register_node(nid(1));
        r.record_failure(nid(1), 1);
        r.record_failure(nid(1), 2);
        assert_eq!(r.status(&nid(1)), Some(HealthStatus::Degraded));
    }

    // MHR4: failures at unreachable_threshold → Unreachable.
    #[test]
    fn mhr4_unreachable() {
        let mut r = runtime();
        r.register_node(nid(1));
        for i in 0..5 {
            r.record_failure(nid(1), i);
        }
        assert_eq!(r.status(&nid(1)), Some(HealthStatus::Unreachable));
    }

    // MHR5: success resets consecutive_failures.
    #[test]
    fn mhr5_recovery() {
        let mut r = runtime();
        r.register_node(nid(1));
        r.record_failure(nid(1), 1);
        r.record_failure(nid(1), 2);
        r.record_success(nid(1), 3);
        assert_eq!(r.status(&nid(1)), Some(HealthStatus::Healthy));
    }

    // MHR6: summary counts are correct.
    #[test]
    fn mhr6_summary() {
        let mut r = runtime();
        r.register_node(nid(1));
        r.register_node(nid(2));
        r.record_failure(nid(2), 1);
        r.record_failure(nid(2), 2);
        let s = r.summary();
        assert_eq!(s.healthy, 1);
        assert_eq!(s.degraded, 1);
        assert_eq!(s.total, 2);
    }

    // MHR7: apply_staleness marks old nodes Unreachable.
    #[test]
    fn mhr7_staleness() {
        let mut r = runtime();
        r.register_node(nid(1));
        r.record_success(nid(1), 0);
        r.apply_staleness(100);
        assert_eq!(r.status(&nid(1)), Some(HealthStatus::Unreachable));
    }

    // MHR8: healthy_nodes excludes degraded/unreachable.
    #[test]
    fn mhr8_healthy_nodes() {
        let mut r = runtime();
        r.register_node(nid(1));
        r.register_node(nid(2));
        r.record_failure(nid(2), 1);
        r.record_failure(nid(2), 2);
        let hn = r.healthy_nodes();
        assert_eq!(hn.len(), 1);
        assert_eq!(hn[0], nid(1));
    }

    // MHR9: remove_node deletes entry.
    #[test]
    fn mhr9_remove_node() {
        let mut r = runtime();
        r.register_node(nid(1));
        r.remove_node(&nid(1));
        assert_eq!(r.status(&nid(1)), None);
    }

    // MHR10: health_check_count increments per record.
    #[test]
    fn mhr10_check_count() {
        let mut r = runtime();
        r.record_success(nid(1), 1);
        r.record_failure(nid(2), 1);
        assert_eq!(r.health_check_count(), 2);
    }
}
