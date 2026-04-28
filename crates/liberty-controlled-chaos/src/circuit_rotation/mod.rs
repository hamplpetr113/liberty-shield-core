//! CircuitRotation — deterministic circuit health tracking and rotation policy.
//!
//! Sits above `CircuitRuntime`:
//!   CircuitRotation → CircuitRuntime → OnionLayer → MeshRouter → UDPTransport
//!
//! No system time calls.  All timestamps are caller-supplied.  No network I/O.

mod policy;
mod rotator;
mod types;

pub use policy::RotationPolicy;
pub use rotator::CircuitRotator;
pub use types::{CircuitHealth, CircuitHealthState, RotationError, RotationReason};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::circuit_builder::CircuitId;

    use super::*;

    fn policy() -> RotationPolicy {
        RotationPolicy {
            max_circuit_age: 1_000,
            max_failures: 3,
            min_success_ratio: 0.5,
            rotation_cooldown: 100,
        }
    }

    fn healthy(id: u64) -> CircuitHealth {
        CircuitHealth::new(CircuitId(id), 0)
    }

    // ── Age-based rotation ────────────────────────────────────────────────────

    #[test]
    fn cr1_age_expired() {
        let rotator = CircuitRotator::new();
        let h = healthy(1);
        // now = 1000 >= max_circuit_age = 1000 → AgeExpired
        assert_eq!(
            rotator.should_rotate(&h, &policy(), 1_000),
            Some(RotationReason::AgeExpired)
        );
    }

    // ── Failure-threshold rotation ────────────────────────────────────────────

    #[test]
    fn cr2_failure_threshold() {
        let rotator = CircuitRotator::new();
        let mut h = healthy(2);
        h.failure_count = 3; // >= max_failures
        assert_eq!(
            rotator.should_rotate(&h, &policy(), 0),
            Some(RotationReason::FailureThreshold)
        );
    }

    // ── Success-ratio rotation ────────────────────────────────────────────────

    #[test]
    fn cr3_success_ratio_too_low() {
        let rotator = CircuitRotator::new();
        let mut h = healthy(3);
        h.success_count = 1;
        h.failure_count = 2; // ratio = 1/3 ≈ 0.33 < 0.5
        assert_eq!(
            rotator.should_rotate(&h, &policy(), 0),
            Some(RotationReason::FailureThreshold)
        );
    }

    // ── Cooldown prevents repeated rotation ──────────────────────────────────

    #[test]
    fn cr4_cooldown_suppresses_rotation() {
        let rotator = CircuitRotator::new();
        let mut h = healthy(4);
        h.failure_count = 3; // would trigger FailureThreshold
        h.last_rotated_at = Some(950); // 50 ago, cooldown = 100
        // now = 1000, elapsed = 50 < 100 → suppressed
        assert_eq!(rotator.should_rotate(&h, &policy(), 1_000), None);
    }

    #[test]
    fn cr4_cooldown_expired_allows_rotation() {
        let rotator = CircuitRotator::new();
        let mut h = healthy(4);
        h.failure_count = 3;
        h.last_rotated_at = Some(800); // 200 ago, cooldown = 100 → allowed
        assert_eq!(
            rotator.should_rotate(&h, &policy(), 1_000),
            Some(RotationReason::FailureThreshold)
        );
    }

    // ── Manual reason preserved ───────────────────────────────────────────────

    #[test]
    fn cr5_manual_reason_preserved() {
        let rotator = CircuitRotator::new();
        let mut h = healthy(5);
        h.manual_rotation_requested = true;
        assert_eq!(
            rotator.should_rotate(&h, &policy(), 0),
            Some(RotationReason::Manual)
        );
    }

    #[test]
    fn cr5_manual_cleared_after_mark_rotated() {
        let mut h = healthy(5);
        h.manual_rotation_requested = true;
        h.mark_rotated(0);
        assert!(!h.manual_rotation_requested);
    }

    // ── No rotation for healthy circuit ──────────────────────────────────────

    #[test]
    fn cr6_healthy_circuit_no_rotation() {
        let rotator = CircuitRotator::new();
        let mut h = healthy(6);
        h.success_count = 10;
        h.failure_count = 1; // ratio = 10/11 ≈ 0.91, well above 0.5
        // now = 0, age = 0 < 1000
        assert_eq!(rotator.should_rotate(&h, &policy(), 0), None);
    }

    // ── GuardDegraded ─────────────────────────────────────────────────────────

    #[test]
    fn cr7_guard_degraded() {
        let rotator = CircuitRotator::new();
        let mut h = healthy(7);
        h.is_guard_degraded = true;
        assert_eq!(
            rotator.should_rotate(&h, &policy(), 0),
            Some(RotationReason::GuardDegraded)
        );
    }

    // ── record_success / record_failure ──────────────────────────────────────

    #[test]
    fn cr8_record_counters() {
        let mut rotator = CircuitRotator::new();
        rotator.register_health(healthy(8)).unwrap();
        rotator.record_success(CircuitId(8));
        rotator.record_success(CircuitId(8));
        rotator.record_failure(CircuitId(8));
        let h = rotator.get_health(CircuitId(8)).unwrap();
        assert_eq!(h.success_count, 2);
        assert_eq!(h.failure_count, 1);
    }

    // ── register / remove ─────────────────────────────────────────────────────

    #[test]
    fn cr9_duplicate_registration_rejected() {
        let mut rotator = CircuitRotator::new();
        rotator.register_health(healthy(9)).unwrap();
        assert!(matches!(
            rotator.register_health(healthy(9)),
            Err(RotationError::CircuitAlreadyRegistered(CircuitId(9)))
        ));
    }

    #[test]
    fn cr10_remove_not_found() {
        let mut rotator = CircuitRotator::new();
        assert!(matches!(
            rotator.remove_health(CircuitId(99)),
            Err(RotationError::CircuitNotFound(CircuitId(99)))
        ));
    }
}
