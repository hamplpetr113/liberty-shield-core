//! MultiCircuitDistributor — deterministic cell distribution across circuits.
//!
//! Sits between `CircuitRuntime` and `OnionLayer`:
//!   MultiCircuitDistributor → CircuitRuntime → OnionLayer → MeshRouter
//!
//! No randomness, no payload inspection, no network I/O.

mod distributor;
mod types;

pub use distributor::MultiCircuitDistributor;
pub use types::{CircuitWeight, DistributionDecision, DistributionError, DistributionMode};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::circuit_builder::CircuitId;

    use super::*;

    fn cw(id: u64, reliability: f64, latency: u64, active: bool) -> CircuitWeight {
        CircuitWeight {
            circuit_id: CircuitId(id),
            weight: reliability,
            reliability_score: reliability,
            latency_estimate: latency,
            is_active: active,
        }
    }

    fn three_active() -> Vec<CircuitWeight> {
        vec![
            cw(3, 0.80, 300, true),
            cw(1, 0.95, 100, true),
            cw(2, 0.90, 200, true),
        ]
    }

    // ── Single circuit selected ───────────────────────────────────────────────

    #[test]
    fn d1_single_circuit_selects_lowest_id() {
        let mut d = MultiCircuitDistributor::new();
        let dec = d
            .select_circuit(&three_active(), DistributionMode::SingleCircuit)
            .unwrap();
        assert_eq!(dec.circuit_id, CircuitId(1));
        assert_eq!(dec.mode, DistributionMode::SingleCircuit);
    }

    // ── Round-robin deterministic sequence ───────────────────────────────────

    #[test]
    fn d2_round_robin_sequence() {
        let mut d = MultiCircuitDistributor::new();
        let circuits = three_active();
        // Sorted order: [1, 2, 3] → cycles 1 → 2 → 3 → 1 ...
        let r1 = d
            .select_circuit(&circuits, DistributionMode::RoundRobin)
            .unwrap();
        let r2 = d
            .select_circuit(&circuits, DistributionMode::RoundRobin)
            .unwrap();
        let r3 = d
            .select_circuit(&circuits, DistributionMode::RoundRobin)
            .unwrap();
        let r4 = d
            .select_circuit(&circuits, DistributionMode::RoundRobin)
            .unwrap();
        assert_eq!(r1.circuit_id, CircuitId(1));
        assert_eq!(r2.circuit_id, CircuitId(2));
        assert_eq!(r3.circuit_id, CircuitId(3));
        assert_eq!(r4.circuit_id, CircuitId(1)); // wraps around
    }

    #[test]
    fn d2_reset_round_robin() {
        let mut d = MultiCircuitDistributor::new();
        let circuits = three_active();
        d.select_circuit(&circuits, DistributionMode::RoundRobin)
            .unwrap();
        d.select_circuit(&circuits, DistributionMode::RoundRobin)
            .unwrap();
        d.reset_round_robin();
        let r = d
            .select_circuit(&circuits, DistributionMode::RoundRobin)
            .unwrap();
        assert_eq!(r.circuit_id, CircuitId(1)); // back to start
    }

    // ── Weighted reliability chooses best ────────────────────────────────────

    #[test]
    fn d3_weighted_selects_highest_reliability() {
        let mut d = MultiCircuitDistributor::new();
        // Circuit 1 has reliability 0.95 — highest.
        let dec = d
            .select_circuit(&three_active(), DistributionMode::WeightedReliability)
            .unwrap();
        assert_eq!(dec.circuit_id, CircuitId(1));
    }

    // ── Tie-break by circuit_id ───────────────────────────────────────────────

    #[test]
    fn d4_tie_break_by_circuit_id() {
        let mut d = MultiCircuitDistributor::new();
        // All equal reliability and latency → lowest circuit_id wins.
        let tied = vec![
            cw(5, 0.9, 100, true),
            cw(2, 0.9, 100, true),
            cw(8, 0.9, 100, true),
        ];
        let dec = d
            .select_circuit(&tied, DistributionMode::WeightedReliability)
            .unwrap();
        assert_eq!(dec.circuit_id, CircuitId(2));
    }

    // ── Empty circuit list returns error ─────────────────────────────────────

    #[test]
    fn d5_empty_list_error() {
        let mut d = MultiCircuitDistributor::new();
        assert!(matches!(
            d.select_circuit(&[], DistributionMode::SingleCircuit),
            Err(DistributionError::EmptyCircuitList)
        ));
    }

    // ── Shadow mode does not select inactive circuits ─────────────────────────

    #[test]
    fn d6_shadow_skips_inactive() {
        let mut d = MultiCircuitDistributor::new();
        let circuits = vec![
            cw(1, 0.95, 100, false), // inactive — must be skipped
            cw(2, 0.90, 200, true),
        ];
        let dec = d
            .select_circuit(&circuits, DistributionMode::ShadowOnly)
            .unwrap();
        assert_eq!(dec.circuit_id, CircuitId(2));
    }

    #[test]
    fn d6_shadow_all_inactive_returns_error() {
        let mut d = MultiCircuitDistributor::new();
        let circuits = vec![cw(1, 0.95, 100, false), cw(2, 0.90, 200, false)];
        assert!(matches!(
            d.select_circuit(&circuits, DistributionMode::ShadowOnly),
            Err(DistributionError::NoEligibleCircuit)
        ));
    }
}
