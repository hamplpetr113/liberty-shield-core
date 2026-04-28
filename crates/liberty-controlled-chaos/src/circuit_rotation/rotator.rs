use std::collections::HashMap;

use crate::circuit_builder::CircuitId;

use super::policy::RotationPolicy;
use super::types::{CircuitHealth, RotationError, RotationReason};

/// Tracks circuit health and emits deterministic rotation recommendations.
///
/// All timestamps must be supplied by the caller — no system time is used.
pub struct CircuitRotator {
    circuits: HashMap<u64, CircuitHealth>,
}

impl CircuitRotator {
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
        }
    }

    /// Store a health record.  Returns `CircuitAlreadyRegistered` if duplicate.
    pub fn register_health(&mut self, health: CircuitHealth) -> Result<(), RotationError> {
        let id = health.circuit_id.0;
        if self.circuits.contains_key(&id) {
            return Err(RotationError::CircuitAlreadyRegistered(health.circuit_id));
        }
        self.circuits.insert(id, health);
        Ok(())
    }

    /// Remove and return a health record.  Returns `CircuitNotFound` if absent.
    pub fn remove_health(&mut self, circuit_id: CircuitId) -> Result<CircuitHealth, RotationError> {
        self.circuits
            .remove(&circuit_id.0)
            .ok_or(RotationError::CircuitNotFound(circuit_id))
    }

    /// Borrow the health record for a circuit.
    pub fn get_health(&self, circuit_id: CircuitId) -> Option<&CircuitHealth> {
        self.circuits.get(&circuit_id.0)
    }

    /// Increment `success_count` for a circuit, if registered.
    pub fn record_success(&mut self, circuit_id: CircuitId) {
        if let Some(h) = self.circuits.get_mut(&circuit_id.0) {
            h.success_count += 1;
        }
    }

    /// Increment `failure_count` for a circuit, if registered.
    pub fn record_failure(&mut self, circuit_id: CircuitId) {
        if let Some(h) = self.circuits.get_mut(&circuit_id.0) {
            h.failure_count += 1;
        }
    }

    /// Evaluate whether `health` should be rotated under `policy` at `now`.
    ///
    /// Checks are applied in priority order:
    ///   1. Cooldown — suppresses all rotation if too recent.
    ///   2. Manual   — explicit request overrides automatic rules.
    ///   3. Age      — circuit has lived beyond `max_circuit_age`.
    ///   4. Failures — count or ratio exceeded threshold.
    ///   5. Guard    — entry guard is degraded.
    ///
    /// Returns `None` when no rotation is warranted.
    pub fn should_rotate(
        &self,
        health: &CircuitHealth,
        policy: &RotationPolicy,
        now: u64,
    ) -> Option<RotationReason> {
        // 1. Cooldown check.
        if let Some(last) = health.last_rotated_at
            && now.saturating_sub(last) < policy.rotation_cooldown
        {
            return None;
        }

        // 2. Manual rotation requested.
        if health.manual_rotation_requested {
            return Some(RotationReason::Manual);
        }

        // 3. Failure threshold — absolute count (checked before age so explicit
        //    failure reason is preserved even when the circuit is also aged).
        if health.failure_count >= policy.max_failures {
            return Some(RotationReason::FailureThreshold);
        }

        // 3b. Failure threshold — success ratio.
        let total = health.success_count + health.failure_count;
        if total > 0 {
            let ratio = health.success_count as f64 / total as f64;
            if ratio < policy.min_success_ratio {
                return Some(RotationReason::FailureThreshold);
            }
        }

        // 4. Age expiry.
        if now.saturating_sub(health.created_at) >= policy.max_circuit_age {
            return Some(RotationReason::AgeExpired);
        }

        // 5. Guard degraded.
        if health.is_guard_degraded {
            return Some(RotationReason::GuardDegraded);
        }

        None
    }
}

impl Default for CircuitRotator {
    fn default() -> Self {
        Self::new()
    }
}
