//! Chaos harness — failure injection for integration and resilience testing.
//!
//! `ChaosHarness` tracks a set of active fault rules.  Callers query it to
//! decide whether a packet should be dropped, delayed, or corrupted, and
//! whether a node should be considered partitioned.

use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// FaultKind
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    /// Drop the packet entirely.
    Drop,
    /// Delay the packet by `param` epochs.
    Delay,
    /// Flip `param` bytes in the payload (simulated corruption).
    Corrupt,
    /// Simulate a network partition (all packets dropped for this node).
    Partition,
    /// Kill the node (taken offline).
    Kill,
}

// ---------------------------------------------------------------------------
// FaultRule
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FaultRule {
    pub id: u32,
    pub kind: FaultKind,
    /// Probability [0.0, 1.0] that the fault applies when sampled.
    pub probability: f64,
    /// Generic parameter (delay epochs, corrupt bytes, …).
    pub param: u64,
    /// Number of times this rule has fired.
    pub fires: u64,
    /// Optional: only apply to a specific node.
    pub target_node: Option<[u8; 32]>,
}

// ---------------------------------------------------------------------------
// ChaosDecision
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChaosDecision {
    Pass,
    Drop,
    Delay(u64),
    Corrupt(u64),
}

// ---------------------------------------------------------------------------
// ChaosHarness
// ---------------------------------------------------------------------------

pub struct ChaosHarness {
    rules: HashMap<u32, FaultRule>,
    partitioned: HashSet<[u8; 32]>,
    killed: HashSet<[u8; 32]>,
    next_rule_id: u32,
    total_faults: u64,
    /// Deterministic sampling seed (XOR-shifts on each use).
    sample_seed: u64,
}

impl ChaosHarness {
    pub fn new(seed: u64) -> Self {
        Self {
            rules: HashMap::new(),
            partitioned: HashSet::new(),
            killed: HashSet::new(),
            next_rule_id: 1,
            total_faults: 0,
            sample_seed: seed,
        }
    }

    fn next_sample(&mut self) -> f64 {
        // xorshift64
        self.sample_seed ^= self.sample_seed << 13;
        self.sample_seed ^= self.sample_seed >> 7;
        self.sample_seed ^= self.sample_seed << 17;
        (self.sample_seed & 0xFFFF) as f64 / 0x10000 as f64
    }

    pub fn add_rule(
        &mut self,
        kind: FaultKind,
        probability: f64,
        param: u64,
        target_node: Option<[u8; 32]>,
    ) -> u32 {
        let id = self.next_rule_id;
        self.next_rule_id += 1;
        self.rules.insert(
            id,
            FaultRule {
                id,
                kind,
                probability,
                param,
                fires: 0,
                target_node,
            },
        );
        id
    }

    pub fn remove_rule(&mut self, id: u32) -> bool {
        self.rules.remove(&id).is_some()
    }

    /// Evaluate chaos rules for a packet arriving at `node`.
    /// Returns the first matching decision (rules checked in insertion order).
    pub fn evaluate(&mut self, node: &[u8; 32]) -> ChaosDecision {
        if self.killed.contains(node) || self.partitioned.contains(node) {
            self.total_faults += 1;
            return ChaosDecision::Drop;
        }
        let ids: Vec<u32> = self.rules.keys().copied().collect();
        for id in ids {
            let sample = self.next_sample();
            let rule = self.rules.get_mut(&id).unwrap();
            // Skip if rule targets a different node.
            if rule.target_node.is_some_and(|t| &t != node) {
                continue;
            }
            if sample < rule.probability {
                rule.fires += 1;
                self.total_faults += 1;
                return match rule.kind {
                    FaultKind::Drop => ChaosDecision::Drop,
                    FaultKind::Delay => ChaosDecision::Delay(rule.param),
                    FaultKind::Corrupt => ChaosDecision::Corrupt(rule.param),
                    FaultKind::Partition => {
                        self.partitioned.insert(*node);
                        ChaosDecision::Drop
                    }
                    FaultKind::Kill => {
                        self.killed.insert(*node);
                        ChaosDecision::Drop
                    }
                };
            }
        }
        ChaosDecision::Pass
    }

    pub fn partition_node(&mut self, node: [u8; 32]) {
        self.partitioned.insert(node);
        self.total_faults += 1;
    }

    pub fn heal_node(&mut self, node: &[u8; 32]) {
        self.partitioned.remove(node);
        self.killed.remove(node);
    }

    pub fn is_partitioned(&self, node: &[u8; 32]) -> bool {
        self.partitioned.contains(node)
    }

    pub fn is_killed(&self, node: &[u8; 32]) -> bool {
        self.killed.contains(node)
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn total_faults(&self) -> u64 {
        self.total_faults
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

    // CH1: no rules → Pass.
    #[test]
    fn ch1_no_rules_pass() {
        let mut h = ChaosHarness::new(42);
        assert_eq!(h.evaluate(&nid(1)), ChaosDecision::Pass);
    }

    // CH2: probability=1.0 Drop rule always fires.
    #[test]
    fn ch2_certain_drop() {
        let mut h = ChaosHarness::new(1);
        h.add_rule(FaultKind::Drop, 1.0, 0, None);
        assert_eq!(h.evaluate(&nid(1)), ChaosDecision::Drop);
    }

    // CH3: probability=0.0 rule never fires.
    #[test]
    fn ch3_zero_probability_never_fires() {
        let mut h = ChaosHarness::new(7);
        h.add_rule(FaultKind::Drop, 0.0, 0, None);
        for _ in 0..20 {
            assert_eq!(h.evaluate(&nid(1)), ChaosDecision::Pass);
        }
    }

    // CH4: Delay rule returns Delay decision with param.
    #[test]
    fn ch4_delay_rule() {
        let mut h = ChaosHarness::new(1);
        h.add_rule(FaultKind::Delay, 1.0, 3, None);
        assert_eq!(h.evaluate(&nid(1)), ChaosDecision::Delay(3));
    }

    // CH5: Corrupt rule returns Corrupt decision.
    #[test]
    fn ch5_corrupt_rule() {
        let mut h = ChaosHarness::new(1);
        h.add_rule(FaultKind::Corrupt, 1.0, 2, None);
        assert_eq!(h.evaluate(&nid(1)), ChaosDecision::Corrupt(2));
    }

    // CH6: partition_node makes all subsequent evaluations Drop.
    #[test]
    fn ch6_partition_drops_all() {
        let mut h = ChaosHarness::new(99);
        h.partition_node(nid(1));
        assert_eq!(h.evaluate(&nid(1)), ChaosDecision::Drop);
    }

    // CH7: heal_node removes partition.
    #[test]
    fn ch7_heal_removes_partition() {
        let mut h = ChaosHarness::new(99);
        h.partition_node(nid(1));
        h.heal_node(&nid(1));
        assert!(!h.is_partitioned(&nid(1)));
    }

    // CH8: targeted rule only affects specified node.
    #[test]
    fn ch8_targeted_rule() {
        let mut h = ChaosHarness::new(1);
        h.add_rule(FaultKind::Drop, 1.0, 0, Some(nid(1)));
        // nid(2) should pass.
        assert_eq!(h.evaluate(&nid(2)), ChaosDecision::Pass);
        // nid(1) should drop.
        assert_eq!(h.evaluate(&nid(1)), ChaosDecision::Drop);
    }

    // CH9: remove_rule removes the rule.
    #[test]
    fn ch9_remove_rule() {
        let mut h = ChaosHarness::new(1);
        let id = h.add_rule(FaultKind::Drop, 1.0, 0, None);
        h.remove_rule(id);
        assert_eq!(h.rule_count(), 0);
    }

    // CH10: total_faults accumulates.
    #[test]
    fn ch10_total_faults() {
        let mut h = ChaosHarness::new(1);
        h.partition_node(nid(1));
        h.evaluate(&nid(1));
        h.evaluate(&nid(1));
        assert!(h.total_faults() >= 2);
    }
}
