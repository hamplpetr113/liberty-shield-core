//! Peer reputation engine — tracks per-node success/failure counts and latency,
//! and derives a composite trust score.
//!
//! Score formula:
//! ```text
//! ratio       = successes / (successes + failures)   [0.0–1.0; 0.5 if no data]
//! latency_factor = 1.0 / (1.0 + latency_ms / 100.0)  [0.0–1.0]
//! trust_score    = (ratio * 0.7 + latency_factor * 0.3).clamp(0.0, 1.0)
//! ```
//!
//! `best_peers(limit)` returns peers sorted by `trust_score` descending.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// PeerReputation
// ---------------------------------------------------------------------------

/// Per-node reputation record.
#[derive(Debug, Clone)]
pub struct PeerReputation {
    pub node_id: [u8; 32],
    pub success_count: u64,
    pub failure_count: u64,
    /// Average latency in milliseconds (EWMA, α = 0.2).
    pub latency_ms: f64,
    /// Composite trust score in [0.0, 1.0].
    pub trust_score: f64,
}

impl PeerReputation {
    fn new(node_id: [u8; 32]) -> Self {
        Self {
            node_id,
            success_count: 0,
            failure_count: 0,
            latency_ms: 100.0,
            trust_score: 0.5,
        }
    }

    fn recompute(&mut self) {
        let total = self.success_count + self.failure_count;
        let ratio = if total == 0 {
            0.5
        } else {
            self.success_count as f64 / total as f64
        };
        let latency_factor = 1.0 / (1.0 + self.latency_ms / 100.0);
        self.trust_score = (ratio * 0.7 + latency_factor * 0.3).clamp(0.0, 1.0);
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationError {
    /// No record exists for this node_id.
    NotFound,
}

impl std::fmt::Display for ReputationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "peer not found in reputation engine")
    }
}

// ---------------------------------------------------------------------------
// ReputationEngine
// ---------------------------------------------------------------------------

/// Tracks and scores peer reputations.
pub struct ReputationEngine {
    peers: HashMap<[u8; 32], PeerReputation>,
}

impl ReputationEngine {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    fn get_or_create_mut(&mut self, node_id: [u8; 32]) -> &mut PeerReputation {
        self.peers
            .entry(node_id)
            .or_insert_with(|| PeerReputation::new(node_id))
    }

    /// Record a successful interaction with a peer.
    pub fn record_success(&mut self, node_id: [u8; 32]) {
        let r = self.get_or_create_mut(node_id);
        r.success_count += 1;
        r.recompute();
    }

    /// Record a failed interaction with a peer.
    pub fn record_failure(&mut self, node_id: [u8; 32]) {
        let r = self.get_or_create_mut(node_id);
        r.failure_count += 1;
        r.recompute();
    }

    /// Update latency with an EWMA sample.
    pub fn update_latency(&mut self, node_id: [u8; 32], sample_ms: f64) {
        let r = self.get_or_create_mut(node_id);
        r.latency_ms = 0.8 * r.latency_ms + 0.2 * sample_ms;
        r.recompute();
    }

    /// Get the current trust score for a peer (0.5 if not yet seen).
    pub fn compute_score(&self, node_id: &[u8; 32]) -> f64 {
        self.peers
            .get(node_id)
            .map(|r| r.trust_score)
            .unwrap_or(0.5)
    }

    /// Return up to `limit` peers sorted by trust_score descending.
    pub fn best_peers(&self, limit: usize) -> Vec<&PeerReputation> {
        let mut all: Vec<&PeerReputation> = self.peers.values().collect();
        all.sort_by(|a, b| {
            b.trust_score
                .partial_cmp(&a.trust_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.node_id.cmp(&b.node_id))
        });
        all.truncate(limit);
        all
    }

    /// Reset a peer's reputation record to defaults.
    pub fn reset(&mut self, node_id: &[u8; 32]) {
        if let Some(r) = self.peers.get_mut(node_id) {
            r.success_count = 0;
            r.failure_count = 0;
            r.latency_ms = 100.0;
            r.trust_score = 0.5;
        }
    }

    /// Get a peer record if it exists.
    pub fn get(&self, node_id: &[u8; 32]) -> Option<&PeerReputation> {
        self.peers.get(node_id)
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

impl Default for ReputationEngine {
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

    // PR1: recording a success increases success_count.
    #[test]
    fn pr1_success_update() {
        let mut eng = ReputationEngine::new();
        eng.record_success(nid(1));
        assert_eq!(eng.get(&nid(1)).unwrap().success_count, 1);
    }

    // PR2: recording a failure increases failure_count.
    #[test]
    fn pr2_failure_update() {
        let mut eng = ReputationEngine::new();
        eng.record_failure(nid(1));
        assert_eq!(eng.get(&nid(1)).unwrap().failure_count, 1);
    }

    // PR3: latency update uses EWMA.
    #[test]
    fn pr3_latency_adjustment() {
        let mut eng = ReputationEngine::new();
        eng.update_latency(nid(1), 0.0);
        let lat = eng.get(&nid(1)).unwrap().latency_ms;
        // 0.8*100 + 0.2*0 = 80
        assert!((lat - 80.0).abs() < 0.01);
    }

    // PR4: score is higher after successes than after failures.
    #[test]
    fn pr4_score_calculation() {
        let mut eng = ReputationEngine::new();
        for _ in 0..10 {
            eng.record_success(nid(1));
        }
        let good = eng.compute_score(&nid(1));
        let mut eng2 = ReputationEngine::new();
        for _ in 0..10 {
            eng2.record_failure(nid(2));
        }
        let bad = eng2.compute_score(&nid(2));
        assert!(good > bad);
    }

    // PR5: best_peers returns peers sorted descending by trust_score.
    #[test]
    fn pr5_ordering_peers() {
        let mut eng = ReputationEngine::new();
        for _ in 0..5 {
            eng.record_success(nid(1));
        }
        for _ in 0..5 {
            eng.record_failure(nid(2));
        }
        let best = eng.best_peers(2);
        assert_eq!(best.len(), 2);
        assert!(best[0].trust_score >= best[1].trust_score);
        assert_eq!(best[0].node_id, nid(1));
    }

    // PR6: many failures drive score well below the neutral 0.5 default.
    #[test]
    fn pr6_penalize_failures() {
        let mut eng = ReputationEngine::new();
        for _ in 0..1000 {
            eng.record_failure(nid(1));
        }
        // ratio=0.0, latency_factor=0.5 → score = 0*0.7 + 0.5*0.3 = 0.15
        assert!(eng.compute_score(&nid(1)) < 0.2);
    }

    // PR7: successes after failures improve the score.
    #[test]
    fn pr7_recovery_after_success() {
        let mut eng = ReputationEngine::new();
        for _ in 0..10 {
            eng.record_failure(nid(1));
        }
        let score_after_failures = eng.compute_score(&nid(1));
        for _ in 0..100 {
            eng.record_success(nid(1));
        }
        let score_after_recovery = eng.compute_score(&nid(1));
        assert!(score_after_recovery > score_after_failures);
    }

    // PR8: score is clamped to [0.0, 1.0].
    #[test]
    fn pr8_reputation_scaling() {
        let mut eng = ReputationEngine::new();
        for _ in 0..10000 {
            eng.record_success(nid(1));
        }
        let score = eng.compute_score(&nid(1));
        assert!(score >= 0.0 && score <= 1.0);
    }

    // PR9: peer with all failures scores below a peer with no data.
    #[test]
    fn pr9_malicious_peer_detection() {
        let mut eng = ReputationEngine::new();
        for _ in 0..50 {
            eng.record_failure(nid(99));
        }
        let malicious = eng.compute_score(&nid(99));
        let unknown = eng.compute_score(&nid(0)); // unseen
        assert!(malicious < unknown);
    }

    // PR10: reset restores default values.
    #[test]
    fn pr10_reputation_reset() {
        let mut eng = ReputationEngine::new();
        for _ in 0..20 {
            eng.record_failure(nid(1));
        }
        eng.reset(&nid(1));
        let r = eng.get(&nid(1)).unwrap();
        assert_eq!(r.success_count, 0);
        assert_eq!(r.failure_count, 0);
        assert!((r.trust_score - 0.5).abs() < 0.01);
    }

    // PR11: unknown peer returns default score 0.5.
    #[test]
    fn pr11_unknown_peer_default_score() {
        let eng = ReputationEngine::new();
        assert!((eng.compute_score(&nid(42)) - 0.5).abs() < 0.01);
    }
}
