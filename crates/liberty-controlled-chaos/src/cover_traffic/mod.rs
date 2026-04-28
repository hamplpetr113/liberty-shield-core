//! CoverTraffic — deterministic cover traffic intent generation.
//!
//! Sits above `MultiCircuitDistributor`:
//!   CoverTrafficGenerator → MultiCircuitDistributor → CircuitRuntime → ...
//!
//! No network I/O; no randomness; all timing is caller-supplied.

mod generator;
mod types;

pub use generator::CoverTrafficGenerator;
pub use types::{CoverTrafficClass, CoverTrafficIntent, CoverTrafficPolicy};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::circuit_builder::CircuitId;

    use super::*;

    fn policy() -> CoverTrafficPolicy {
        CoverTrafficPolicy {
            enabled: true,
            max_cover_per_epoch: 5,
            min_interval_us: 100_000,
            max_interval_us: 1_000_000,
            payload_size: 256,
        }
    }

    fn circuits() -> Vec<CircuitId> {
        vec![CircuitId(3), CircuitId(1), CircuitId(2)]
    }

    // ── Disabled policy emits nothing ─────────────────────────────────────────

    #[test]
    fn ct1_disabled_emits_nothing() {
        let g = CoverTrafficGenerator::new();
        let mut p = policy();
        p.enabled = false;
        let intents = g.generate_epoch(&p, &circuits(), 1_000_000);
        assert!(intents.is_empty());
    }

    // ── Enabled policy emits deterministic intents ────────────────────────────

    #[test]
    fn ct2_enabled_emits_deterministic_intents() {
        let g = CoverTrafficGenerator::new();
        let p = policy();
        let a = g.generate_epoch(&p, &circuits(), 5_000_000);
        let b = g.generate_epoch(&p, &circuits(), 5_000_000);
        assert_eq!(a, b, "same inputs must produce same output");
        assert_eq!(a.len(), 5);
    }

    // ── max_cover_per_epoch enforced ──────────────────────────────────────────

    #[test]
    fn ct3_max_cover_per_epoch_enforced() {
        let g = CoverTrafficGenerator::new();
        let mut p = policy();
        p.max_cover_per_epoch = 3;
        let intents = g.generate_epoch(&p, &circuits(), 0);
        assert_eq!(intents.len(), 3);
    }

    // ── interval enforcement (should_emit) ────────────────────────────────────

    #[test]
    fn ct4_should_emit_respects_min_interval() {
        let p = policy(); // min_interval_us = 100_000
        assert!(!CoverTrafficGenerator::should_emit(
            &p, 1_000_000, 1_050_000
        )); // only 50k elapsed
        assert!(CoverTrafficGenerator::should_emit(&p, 1_000_000, 1_100_000)); // exactly 100k
        assert!(CoverTrafficGenerator::should_emit(&p, 1_000_000, 1_200_000)); // > 100k
    }

    #[test]
    fn ct4_should_emit_disabled_always_false() {
        let mut p = policy();
        p.enabled = false;
        assert!(!CoverTrafficGenerator::should_emit(&p, 0, u64::MAX));
    }

    // ── Empty circuit list emits nothing ──────────────────────────────────────

    #[test]
    fn ct5_empty_circuits_emits_nothing() {
        let g = CoverTrafficGenerator::new();
        let intents = g.generate_epoch(&policy(), &[], 0);
        assert!(intents.is_empty());
    }

    // ── Payload size preserved ────────────────────────────────────────────────

    #[test]
    fn ct6_payload_size_preserved() {
        let g = CoverTrafficGenerator::new();
        let mut p = policy();
        p.payload_size = 1024;
        let intents = g.generate_epoch(&p, &circuits(), 0);
        for intent in &intents {
            assert_eq!(intent.payload_size, 1024);
        }
    }

    // ── Circuit IDs come from sorted input ────────────────────────────────────

    #[test]
    fn ct7_circuits_sorted_ascending() {
        let g = CoverTrafficGenerator::new();
        let mut p = policy();
        p.max_cover_per_epoch = 3;
        // Input: [3, 1, 2] → sorted → [1, 2, 3]
        let intents = g.generate_epoch(&p, &circuits(), 0);
        assert_eq!(intents[0].circuit_id, CircuitId(1));
        assert_eq!(intents[1].circuit_id, CircuitId(2));
        assert_eq!(intents[2].circuit_id, CircuitId(3));
    }

    // ── First intent starts at epoch_start_us ─────────────────────────────────

    #[test]
    fn ct8_first_intent_at_epoch_start() {
        let g = CoverTrafficGenerator::new();
        let intents = g.generate_epoch(&policy(), &circuits(), 7_000_000);
        assert_eq!(intents[0].scheduled_time_us, 7_000_000);
    }
}
