//! Node scoring engine — composite score from latency, uptime, and reputation.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct NodeScore {
    pub node_id: [u8; 32],
    pub latency_score: u32,
    pub uptime_score: u32,
    pub reputation_score: u32,
    pub composite: u32,
}

impl NodeScore {
    fn compute(
        node_id: [u8; 32],
        latency: u32,
        uptime: u32,
        reputation: u32,
        weights: &ScoreWeights,
    ) -> Self {
        let composite = (latency * weights.latency_weight
            + uptime * weights.uptime_weight
            + reputation * weights.reputation_weight)
            / (weights.latency_weight + weights.uptime_weight + weights.reputation_weight).max(1);
        Self {
            node_id,
            latency_score: latency,
            uptime_score: uptime,
            reputation_score: reputation,
            composite,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ScoreWeights {
    pub latency_weight: u32,
    pub uptime_weight: u32,
    pub reputation_weight: u32,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            latency_weight: 1,
            uptime_weight: 1,
            reputation_weight: 1,
        }
    }
}

pub struct NodeScoringEngine {
    weights: ScoreWeights,
    scores: HashMap<[u8; 32], NodeScore>,
    min_composite: u32,
}

impl NodeScoringEngine {
    pub fn new(weights: ScoreWeights, min_composite: u32) -> Self {
        Self {
            weights,
            scores: HashMap::new(),
            min_composite,
        }
    }

    pub fn update(&mut self, node_id: [u8; 32], latency: u32, uptime: u32, reputation: u32) {
        let score = NodeScore::compute(node_id, latency, uptime, reputation, &self.weights);
        self.scores.insert(node_id, score);
    }

    pub fn get(&self, node_id: &[u8; 32]) -> Option<&NodeScore> {
        self.scores.get(node_id)
    }

    pub fn is_eligible(&self, node_id: &[u8; 32]) -> bool {
        self.scores
            .get(node_id)
            .map(|s| s.composite >= self.min_composite)
            .unwrap_or(false)
    }

    pub fn top_n(&self, n: usize) -> Vec<&NodeScore> {
        let mut v: Vec<&NodeScore> = self.scores.values().collect();
        v.sort_by_key(|s| std::cmp::Reverse(s.composite));
        v.truncate(n);
        v
    }

    pub fn eligible_nodes(&self) -> Vec<[u8; 32]> {
        self.scores
            .values()
            .filter(|s| s.composite >= self.min_composite)
            .map(|s| s.node_id)
            .collect()
    }

    pub fn remove(&mut self, node_id: &[u8; 32]) {
        self.scores.remove(node_id);
    }

    pub fn node_count(&self) -> usize {
        self.scores.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn engine() -> NodeScoringEngine {
        NodeScoringEngine::new(ScoreWeights::default(), 50)
    }

    // NSE1: update stores a score.
    #[test]
    fn nse1_update() {
        let mut e = engine();
        e.update(nid(1), 80, 90, 70);
        assert!(e.get(&nid(1)).is_some());
    }

    // NSE2: composite is weighted average.
    #[test]
    fn nse2_composite() {
        let mut e = engine();
        e.update(nid(1), 60, 60, 60);
        assert_eq!(e.get(&nid(1)).unwrap().composite, 60);
    }

    // NSE3: is_eligible true above min_composite.
    #[test]
    fn nse3_eligible() {
        let mut e = engine();
        e.update(nid(1), 80, 80, 80);
        assert!(e.is_eligible(&nid(1)));
    }

    // NSE4: is_eligible false below min_composite.
    #[test]
    fn nse4_not_eligible() {
        let mut e = engine();
        e.update(nid(1), 20, 20, 20);
        assert!(!e.is_eligible(&nid(1)));
    }

    // NSE5: unknown node is not eligible.
    #[test]
    fn nse5_unknown_not_eligible() {
        let e = engine();
        assert!(!e.is_eligible(&nid(99)));
    }

    // NSE6: top_n returns highest scoring nodes.
    #[test]
    fn nse6_top_n() {
        let mut e = engine();
        e.update(nid(1), 90, 90, 90);
        e.update(nid(2), 50, 50, 50);
        e.update(nid(3), 70, 70, 70);
        let top = e.top_n(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].composite, 90);
    }

    // NSE7: eligible_nodes filters by min_composite.
    #[test]
    fn nse7_eligible_nodes() {
        let mut e = engine();
        e.update(nid(1), 80, 80, 80);
        e.update(nid(2), 10, 10, 10);
        assert_eq!(e.eligible_nodes().len(), 1);
    }

    // NSE8: update overwrites previous score.
    #[test]
    fn nse8_overwrite() {
        let mut e = engine();
        e.update(nid(1), 80, 80, 80);
        e.update(nid(1), 10, 10, 10);
        assert_eq!(e.get(&nid(1)).unwrap().composite, 10);
    }

    // NSE9: remove deletes score.
    #[test]
    fn nse9_remove() {
        let mut e = engine();
        e.update(nid(1), 80, 80, 80);
        e.remove(&nid(1));
        assert!(e.get(&nid(1)).is_none());
    }

    // NSE10: custom weights affect composite.
    #[test]
    fn nse10_custom_weights() {
        let w = ScoreWeights {
            latency_weight: 2,
            uptime_weight: 1,
            reputation_weight: 1,
        };
        let mut e = NodeScoringEngine::new(w, 0);
        e.update(nid(1), 100, 0, 0);
        // composite = (100*2 + 0*1 + 0*1) / (2+1+1) = 200/4 = 50
        assert_eq!(e.get(&nid(1)).unwrap().composite, 50);
    }
}
