//! Trust risk engine — scores peers, circuits, and paths for adversarial risk.
//!
//! Risk scores are in [0.0, 1.0] where 0.0 = low risk, 1.0 = high risk.
//!
//! - **Peer risk**: `1.0 - trust_score`.
//! - **Circuit risk**: average peer risk across the 3 hops + age_factor.
//! - **Path risk**: max circuit risk in the path.
//!
//! Circuits above `quarantine_threshold` are flagged for replacement.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// RiskScore
// ---------------------------------------------------------------------------

/// A risk score in [0.0, 1.0] (0 = safe, 1 = high risk).
#[derive(Debug, Clone, Copy)]
pub struct RiskScore(pub f64);

impl RiskScore {
    pub fn new(v: f64) -> Self {
        Self(v.clamp(0.0, 1.0))
    }

    pub fn value(self) -> f64 {
        self.0
    }

    pub fn is_quarantine_recommended(self, threshold: f64) -> bool {
        self.0 >= threshold
    }
}

// ---------------------------------------------------------------------------
// PeerRiskEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PeerRiskEntry {
    pub node_id: [u8; 32],
    /// Pre-computed trust score from reputation engine [0.0, 1.0].
    pub trust_score: f64,
    /// Consecutive suspicious events observed.
    pub suspicious_events: u32,
}

impl PeerRiskEntry {
    pub fn risk_score(&self) -> RiskScore {
        let base = 1.0 - self.trust_score;
        let event_penalty = (self.suspicious_events as f64 * 0.05).min(0.3);
        RiskScore::new(base + event_penalty)
    }
}

// ---------------------------------------------------------------------------
// CircuitRiskEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CircuitRiskEntry {
    pub circuit_id: u64,
    pub guard: [u8; 32],
    pub relay: [u8; 32],
    pub exit: [u8; 32],
    pub created_epoch: u64,
}

impl CircuitRiskEntry {
    pub fn risk_score(
        &self,
        peers: &HashMap<[u8; 32], PeerRiskEntry>,
        current_epoch: u64,
        max_lifetime: u64,
    ) -> RiskScore {
        let default_risk = 0.3;
        let guard_risk = peers
            .get(&self.guard)
            .map(|p| p.risk_score().value())
            .unwrap_or(default_risk);
        let relay_risk = peers
            .get(&self.relay)
            .map(|p| p.risk_score().value())
            .unwrap_or(default_risk);
        let exit_risk = peers
            .get(&self.exit)
            .map(|p| p.risk_score().value())
            .unwrap_or(default_risk);
        let hop_avg = (guard_risk + relay_risk + exit_risk) / 3.0;
        let age_factor = if max_lifetime > 0 {
            (current_epoch.saturating_sub(self.created_epoch) as f64 / max_lifetime as f64).min(0.4)
        } else {
            0.0
        };
        RiskScore::new(hop_avg + age_factor)
    }
}

// ---------------------------------------------------------------------------
// TrustRiskEngine
// ---------------------------------------------------------------------------

pub struct TrustRiskEngine {
    peers: HashMap<[u8; 32], PeerRiskEntry>,
    circuits: HashMap<u64, CircuitRiskEntry>,
    quarantine_threshold: f64,
    max_circuit_lifetime: u64,
}

impl TrustRiskEngine {
    pub fn new(quarantine_threshold: f64, max_circuit_lifetime: u64) -> Self {
        Self {
            peers: HashMap::new(),
            circuits: HashMap::new(),
            quarantine_threshold,
            max_circuit_lifetime,
        }
    }

    pub fn upsert_peer(&mut self, node_id: [u8; 32], trust_score: f64) {
        let e = self.peers.entry(node_id).or_insert(PeerRiskEntry {
            node_id,
            trust_score,
            suspicious_events: 0,
        });
        e.trust_score = trust_score;
    }

    pub fn record_suspicious_event(&mut self, node_id: &[u8; 32]) {
        if let Some(e) = self.peers.get_mut(node_id) {
            e.suspicious_events += 1;
        }
    }

    pub fn register_circuit(
        &mut self,
        circuit_id: u64,
        guard: [u8; 32],
        relay: [u8; 32],
        exit: [u8; 32],
        epoch: u64,
    ) {
        self.circuits.entry(circuit_id).or_insert(CircuitRiskEntry {
            circuit_id,
            guard,
            relay,
            exit,
            created_epoch: epoch,
        });
    }

    pub fn remove_circuit(&mut self, circuit_id: u64) {
        self.circuits.remove(&circuit_id);
    }

    pub fn peer_risk(&self, node_id: &[u8; 32]) -> RiskScore {
        self.peers
            .get(node_id)
            .map(|p| p.risk_score())
            .unwrap_or(RiskScore::new(0.3))
    }

    pub fn circuit_risk(&self, circuit_id: u64, current_epoch: u64) -> RiskScore {
        self.circuits
            .get(&circuit_id)
            .map(|c| c.risk_score(&self.peers, current_epoch, self.max_circuit_lifetime))
            .unwrap_or(RiskScore::new(1.0))
    }

    pub fn path_risk(&self, circuit_ids: &[u64], current_epoch: u64) -> RiskScore {
        let max = circuit_ids
            .iter()
            .map(|&id| self.circuit_risk(id, current_epoch).value())
            .fold(0.0f64, f64::max);
        RiskScore::new(max)
    }

    pub fn quarantined_circuits(&self, current_epoch: u64) -> Vec<u64> {
        self.circuits
            .keys()
            .copied()
            .filter(|&id| {
                self.circuit_risk(id, current_epoch)
                    .is_quarantine_recommended(self.quarantine_threshold)
            })
            .collect()
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

    fn engine() -> TrustRiskEngine {
        TrustRiskEngine::new(0.7, 100)
    }

    // TRE1: high trust peer has low risk.
    #[test]
    fn tre1_high_trust_low_risk() {
        let mut e = engine();
        e.upsert_peer(nid(1), 0.9);
        assert!(e.peer_risk(&nid(1)).value() < 0.2);
    }

    // TRE2: low trust peer has high risk.
    #[test]
    fn tre2_low_trust_high_risk() {
        let mut e = engine();
        e.upsert_peer(nid(1), 0.1);
        assert!(e.peer_risk(&nid(1)).value() > 0.7);
    }

    // TRE3: suspicious events increase risk.
    #[test]
    fn tre3_suspicious_events_increase_risk() {
        let mut e = engine();
        e.upsert_peer(nid(1), 0.7);
        let base = e.peer_risk(&nid(1)).value();
        e.record_suspicious_event(&nid(1));
        e.record_suspicious_event(&nid(1));
        assert!(e.peer_risk(&nid(1)).value() > base);
    }

    // TRE4: circuit with trusted hops has low risk.
    #[test]
    fn tre4_trusted_circuit_low_risk() {
        let mut e = engine();
        e.upsert_peer(nid(1), 0.9);
        e.upsert_peer(nid(2), 0.9);
        e.upsert_peer(nid(3), 0.9);
        e.register_circuit(1, nid(1), nid(2), nid(3), 0);
        assert!(e.circuit_risk(1, 0).value() < 0.3);
    }

    // TRE5: unknown circuit has maximum risk.
    #[test]
    fn tre5_unknown_circuit_max_risk() {
        let e = engine();
        assert_eq!(e.circuit_risk(999, 0).value(), 1.0);
    }

    // TRE6: path risk is the max over circuits.
    #[test]
    fn tre6_path_risk_is_max() {
        let mut e = engine();
        e.upsert_peer(nid(1), 0.9);
        e.upsert_peer(nid(2), 0.9);
        e.upsert_peer(nid(3), 0.9);
        e.register_circuit(1, nid(1), nid(2), nid(3), 0);
        let pr = e.path_risk(&[1, 999], 0); // 999 = unknown → risk 1.0
        assert_eq!(pr.value(), 1.0);
    }

    // TRE7: quarantined_circuits returns high-risk circuits.
    #[test]
    fn tre7_quarantine_detection() {
        let mut e = TrustRiskEngine::new(0.4, 1);
        e.upsert_peer(nid(1), 0.1); // risky
        e.register_circuit(1, nid(1), nid(1), nid(1), 0);
        let q = e.quarantined_circuits(10); // old circuit + risky peers
        assert!(q.contains(&1));
    }

    // TRE8: risk score is clamped to [0, 1].
    #[test]
    fn tre8_risk_clamped() {
        let rs = RiskScore::new(2.5);
        assert_eq!(rs.value(), 1.0);
        let rs2 = RiskScore::new(-0.5);
        assert_eq!(rs2.value(), 0.0);
    }

    // TRE9: remove_circuit eliminates circuit from engine.
    #[test]
    fn tre9_remove_circuit() {
        let mut e = engine();
        e.register_circuit(1, nid(1), nid(2), nid(3), 0);
        e.remove_circuit(1);
        assert_eq!(e.circuit_risk(1, 0).value(), 1.0);
    }

    // TRE10: unknown peer default risk is non-zero.
    #[test]
    fn tre10_unknown_peer_default_risk() {
        let e = engine();
        assert!(e.peer_risk(&nid(99)).value() > 0.0);
    }
}
