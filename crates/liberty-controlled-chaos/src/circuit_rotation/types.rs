use crate::circuit_builder::CircuitId;

/// Reason a circuit was flagged for rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationReason {
    /// Circuit has exceeded `max_circuit_age`.
    AgeExpired,
    /// Failure count or success ratio breached the configured threshold.
    FailureThreshold,
    /// The circuit's entry guard is no longer considered reliable.
    GuardDegraded,
    /// Rotation was explicitly requested by the caller.
    Manual,
}

/// Observed lifecycle state of a tracked circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitHealthState {
    Active,
    Rotating,
    Retired,
}

/// Live health record for one circuit.
#[derive(Debug, Clone)]
pub struct CircuitHealth {
    pub circuit_id: CircuitId,
    /// Timestamp when the circuit was first established (microseconds).
    pub created_at: u64,
    /// Timestamp of the most recent successful cell send (microseconds).
    pub last_used_at: u64,
    pub success_count: u32,
    pub failure_count: u32,
    pub state: CircuitHealthState,
    /// Set to `true` when the associated guard node is considered degraded.
    pub is_guard_degraded: bool,
    /// Set to `true` to request an immediate manual rotation.
    pub manual_rotation_requested: bool,
    /// Timestamp of the last completed rotation (microseconds), if any.
    pub last_rotated_at: Option<u64>,
}

impl CircuitHealth {
    pub fn new(circuit_id: CircuitId, created_at: u64) -> Self {
        Self {
            circuit_id,
            created_at,
            last_used_at: created_at,
            success_count: 0,
            failure_count: 0,
            state: CircuitHealthState::Active,
            is_guard_degraded: false,
            manual_rotation_requested: false,
            last_rotated_at: None,
        }
    }

    /// Record that a rotation occurred at `now`.
    pub fn mark_rotated(&mut self, now: u64) {
        self.last_rotated_at = Some(now);
        self.manual_rotation_requested = false;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RotationError {
    /// A health record for this circuit is already registered.
    CircuitAlreadyRegistered(CircuitId),
    /// No health record for this circuit exists.
    CircuitNotFound(CircuitId),
}
