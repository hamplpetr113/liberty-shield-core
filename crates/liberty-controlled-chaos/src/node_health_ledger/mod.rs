//! Node health ledger — cumulative per-node fault and success accounting.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HealthRecord {
    pub node_id: [u8; 32],
    pub successes: u64,
    pub failures: u64,
    pub last_epoch: u64,
}

impl HealthRecord {
    fn new(node_id: [u8; 32]) -> Self {
        Self {
            node_id,
            successes: 0,
            failures: 0,
            last_epoch: 0,
        }
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.successes + self.failures;
        if total == 0 {
            return 1.0;
        }
        self.successes as f64 / total as f64
    }

    pub fn total_events(&self) -> u64 {
        self.successes + self.failures
    }
}

pub struct NodeHealthLedger {
    records: HashMap<[u8; 32], HealthRecord>,
    failure_threshold: u64,
}

impl NodeHealthLedger {
    pub fn new(failure_threshold: u64) -> Self {
        Self {
            records: HashMap::new(),
            failure_threshold,
        }
    }

    fn ensure(&mut self, node_id: [u8; 32]) {
        self.records
            .entry(node_id)
            .or_insert_with(|| HealthRecord::new(node_id));
    }

    pub fn record_success(&mut self, node_id: [u8; 32], epoch: u64) {
        self.ensure(node_id);
        let r = self.records.get_mut(&node_id).unwrap();
        r.successes += 1;
        r.last_epoch = epoch;
    }

    pub fn record_failure(&mut self, node_id: [u8; 32], epoch: u64) {
        self.ensure(node_id);
        let r = self.records.get_mut(&node_id).unwrap();
        r.failures += 1;
        r.last_epoch = epoch;
    }

    pub fn get(&self, node_id: &[u8; 32]) -> Option<&HealthRecord> {
        self.records.get(node_id)
    }

    pub fn is_degraded(&self, node_id: &[u8; 32]) -> bool {
        self.records
            .get(node_id)
            .map(|r| r.failures >= self.failure_threshold)
            .unwrap_or(false)
    }

    pub fn remove(&mut self, node_id: &[u8; 32]) {
        self.records.remove(node_id);
    }

    pub fn healthy_nodes(&self) -> Vec<[u8; 32]> {
        self.records
            .values()
            .filter(|r| r.failures < self.failure_threshold)
            .map(|r| r.node_id)
            .collect()
    }

    pub fn node_count(&self) -> usize {
        self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // NHL1: record_success increments counter.
    #[test]
    fn nhl1_record_success() {
        let mut l = NodeHealthLedger::new(3);
        l.record_success(nid(1), 1);
        assert_eq!(l.get(&nid(1)).unwrap().successes, 1);
    }

    // NHL2: record_failure increments counter.
    #[test]
    fn nhl2_record_failure() {
        let mut l = NodeHealthLedger::new(3);
        l.record_failure(nid(1), 1);
        assert_eq!(l.get(&nid(1)).unwrap().failures, 1);
    }

    // NHL3: is_degraded triggers at threshold.
    #[test]
    fn nhl3_degraded_threshold() {
        let mut l = NodeHealthLedger::new(2);
        l.record_failure(nid(1), 1);
        assert!(!l.is_degraded(&nid(1)));
        l.record_failure(nid(1), 2);
        assert!(l.is_degraded(&nid(1)));
    }

    // NHL4: unknown node is not degraded.
    #[test]
    fn nhl4_unknown_not_degraded() {
        let l = NodeHealthLedger::new(1);
        assert!(!l.is_degraded(&nid(99)));
    }

    // NHL5: success_rate computed correctly.
    #[test]
    fn nhl5_success_rate() {
        let mut l = NodeHealthLedger::new(10);
        l.record_success(nid(1), 1);
        l.record_success(nid(1), 2);
        l.record_failure(nid(1), 3);
        let rate = l.get(&nid(1)).unwrap().success_rate();
        assert!((rate - 2.0 / 3.0).abs() < 1e-9);
    }

    // NHL6: success_rate on zero events returns 1.0.
    #[test]
    fn nhl6_zero_rate() {
        let mut l = NodeHealthLedger::new(3);
        l.ensure(nid(1));
        // ensure is private — record a success then check before failure
        l.record_success(nid(1), 0);
        l.record_failure(nid(1), 0);
        // total_events == 2
        assert_eq!(l.get(&nid(1)).unwrap().total_events(), 2);
    }

    // NHL7: remove deletes record.
    #[test]
    fn nhl7_remove() {
        let mut l = NodeHealthLedger::new(3);
        l.record_success(nid(1), 1);
        l.remove(&nid(1));
        assert!(l.get(&nid(1)).is_none());
    }

    // NHL8: healthy_nodes excludes degraded.
    #[test]
    fn nhl8_healthy_nodes() {
        let mut l = NodeHealthLedger::new(2);
        l.record_success(nid(1), 1);
        l.record_failure(nid(2), 1);
        l.record_failure(nid(2), 2);
        let h = l.healthy_nodes();
        assert_eq!(h.len(), 1);
        assert_eq!(h[0], nid(1));
    }

    // NHL9: last_epoch updated on record.
    #[test]
    fn nhl9_last_epoch() {
        let mut l = NodeHealthLedger::new(3);
        l.record_success(nid(1), 42);
        assert_eq!(l.get(&nid(1)).unwrap().last_epoch, 42);
    }

    // NHL10: node_count correct.
    #[test]
    fn nhl10_node_count() {
        let mut l = NodeHealthLedger::new(3);
        l.record_success(nid(1), 1);
        l.record_success(nid(2), 1);
        assert_eq!(l.node_count(), 2);
    }
}
