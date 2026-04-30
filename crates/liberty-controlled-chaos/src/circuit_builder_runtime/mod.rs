//! Circuit builder runtime — state-machine for building 3-hop circuits.
//!
//! `CircuitBuildState` drives the build through:
//! ```text
//! Pending → Building → Built
//!                  ↘ Failed (after max_retries)
//! ```
//!
//! `CircuitBuilderRuntime` manages multiple in-flight build attempts and
//! retries on failure.  No real crypto is performed here; this layer tracks
//! lifecycle only.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// CircuitBuildState
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBuildState {
    Pending,
    Building,
    Built,
    Failed,
}

// ---------------------------------------------------------------------------
// CircuitBuildResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CircuitBuildResult {
    pub circuit_id: u64,
    pub guard: [u8; 32],
    pub relay: [u8; 32],
    pub exit: [u8; 32],
    pub built_epoch: u64,
}

// ---------------------------------------------------------------------------
// BuildAttempt (internal)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct BuildAttempt {
    circuit_id: u64,
    guard: [u8; 32],
    relay: [u8; 32],
    exit: [u8; 32],
    state: CircuitBuildState,
    attempts: u32,
    max_retries: u32,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildError {
    NotFound,
    AlreadyBuilt,
    MaxRetriesExceeded,
    InvalidTransition,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::NotFound => write!(f, "circuit not found"),
            BuildError::AlreadyBuilt => write!(f, "circuit already built"),
            BuildError::MaxRetriesExceeded => write!(f, "max retries exceeded"),
            BuildError::InvalidTransition => write!(f, "invalid state transition"),
        }
    }
}

// ---------------------------------------------------------------------------
// CircuitBuilderRuntime
// ---------------------------------------------------------------------------

/// Manages in-flight circuit build attempts.
pub struct CircuitBuilderRuntime {
    attempts: HashMap<u64, BuildAttempt>,
    default_max_retries: u32,
}

impl CircuitBuilderRuntime {
    pub fn new(default_max_retries: u32) -> Self {
        Self {
            attempts: HashMap::new(),
            default_max_retries,
        }
    }

    /// Register a new circuit for building.
    pub fn start_build(
        &mut self,
        circuit_id: u64,
        guard: [u8; 32],
        relay: [u8; 32],
        exit: [u8; 32],
        epoch: u64,
    ) {
        let _ = epoch;
        self.attempts.insert(
            circuit_id,
            BuildAttempt {
                circuit_id,
                guard,
                relay,
                exit,
                state: CircuitBuildState::Pending,
                attempts: 0,
                max_retries: self.default_max_retries,
            },
        );
    }

    /// Advance `Pending → Building`.
    pub fn advance(&mut self, circuit_id: u64) -> Result<(), BuildError> {
        let a = self
            .attempts
            .get_mut(&circuit_id)
            .ok_or(BuildError::NotFound)?;
        match a.state {
            CircuitBuildState::Pending => {
                a.state = CircuitBuildState::Building;
                a.attempts += 1;
                Ok(())
            }
            CircuitBuildState::Built => Err(BuildError::AlreadyBuilt),
            _ => Err(BuildError::InvalidTransition),
        }
    }

    /// Mark a circuit build as successful.
    pub fn complete(
        &mut self,
        circuit_id: u64,
        epoch: u64,
    ) -> Result<CircuitBuildResult, BuildError> {
        let a = self
            .attempts
            .get_mut(&circuit_id)
            .ok_or(BuildError::NotFound)?;
        if a.state != CircuitBuildState::Building {
            return Err(BuildError::InvalidTransition);
        }
        a.state = CircuitBuildState::Built;
        Ok(CircuitBuildResult {
            circuit_id: a.circuit_id,
            guard: a.guard,
            relay: a.relay,
            exit: a.exit,
            built_epoch: epoch,
        })
    }

    /// Record a build failure.  Resets to `Pending` if retries remain,
    /// otherwise marks as `Failed`.
    pub fn record_failure(&mut self, circuit_id: u64) -> Result<CircuitBuildState, BuildError> {
        let a = self
            .attempts
            .get_mut(&circuit_id)
            .ok_or(BuildError::NotFound)?;
        if a.state != CircuitBuildState::Building {
            return Err(BuildError::InvalidTransition);
        }
        if a.attempts >= a.max_retries {
            a.state = CircuitBuildState::Failed;
        } else {
            a.state = CircuitBuildState::Pending;
        }
        Ok(a.state)
    }

    /// Get the current state of a build attempt.
    pub fn state(&self, circuit_id: u64) -> Option<CircuitBuildState> {
        self.attempts.get(&circuit_id).map(|a| a.state)
    }

    pub fn attempt_count(&self, circuit_id: u64) -> Option<u32> {
        self.attempts.get(&circuit_id).map(|a| a.attempts)
    }

    /// Remove a completed or failed attempt.
    pub fn remove(&mut self, circuit_id: u64) -> Result<(), BuildError> {
        self.attempts
            .remove(&circuit_id)
            .map(|_| ())
            .ok_or(BuildError::NotFound)
    }

    /// All in-flight circuit IDs.
    pub fn in_flight(&self) -> impl Iterator<Item = u64> + '_ {
        self.attempts
            .values()
            .filter(|a| {
                matches!(
                    a.state,
                    CircuitBuildState::Pending | CircuitBuildState::Building
                )
            })
            .map(|a| a.circuit_id)
    }

    pub fn len(&self) -> usize {
        self.attempts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.attempts.is_empty()
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

    fn rt() -> CircuitBuilderRuntime {
        CircuitBuilderRuntime::new(3)
    }

    // CBR1: start_build registers a Pending attempt.
    #[test]
    fn cbr1_start_build() {
        let mut r = rt();
        r.start_build(1, nid(1), nid(2), nid(3), 0);
        assert_eq!(r.state(1), Some(CircuitBuildState::Pending));
    }

    // CBR2: advance moves Pending → Building.
    #[test]
    fn cbr2_advance() {
        let mut r = rt();
        r.start_build(1, nid(1), nid(2), nid(3), 0);
        r.advance(1).unwrap();
        assert_eq!(r.state(1), Some(CircuitBuildState::Building));
    }

    // CBR3: complete moves Building → Built and returns result.
    #[test]
    fn cbr3_complete() {
        let mut r = rt();
        r.start_build(1, nid(1), nid(2), nid(3), 0);
        r.advance(1).unwrap();
        let result = r.complete(1, 5).unwrap();
        assert_eq!(result.built_epoch, 5);
        assert_eq!(r.state(1), Some(CircuitBuildState::Built));
    }

    // CBR4: record_failure resets to Pending when retries remain.
    #[test]
    fn cbr4_retry_on_failure() {
        let mut r = CircuitBuilderRuntime::new(3);
        r.start_build(1, nid(1), nid(2), nid(3), 0);
        r.advance(1).unwrap();
        let new_state = r.record_failure(1).unwrap();
        assert_eq!(new_state, CircuitBuildState::Pending);
    }

    // CBR5: record_failure marks Failed after max_retries.
    #[test]
    fn cbr5_max_retries_exceeded() {
        let mut r = CircuitBuilderRuntime::new(1);
        r.start_build(1, nid(1), nid(2), nid(3), 0);
        r.advance(1).unwrap();
        let state = r.record_failure(1).unwrap();
        assert_eq!(state, CircuitBuildState::Failed);
    }

    // CBR6: NotFound returned for unknown circuit_id.
    #[test]
    fn cbr6_not_found() {
        let mut r = rt();
        assert_eq!(r.advance(999).unwrap_err(), BuildError::NotFound);
    }

    // CBR7: AlreadyBuilt returned when advancing a Built circuit.
    #[test]
    fn cbr7_already_built() {
        let mut r = rt();
        r.start_build(1, nid(1), nid(2), nid(3), 0);
        r.advance(1).unwrap();
        r.complete(1, 0).unwrap();
        assert_eq!(r.advance(1).unwrap_err(), BuildError::AlreadyBuilt);
    }

    // CBR8: attempt_count increments on each advance.
    #[test]
    fn cbr8_attempt_counting() {
        let mut r = CircuitBuilderRuntime::new(5);
        r.start_build(1, nid(1), nid(2), nid(3), 0);
        for _ in 0..3 {
            r.advance(1).unwrap();
            r.record_failure(1).unwrap();
        }
        assert_eq!(r.attempt_count(1), Some(3));
    }

    // CBR9: remove cleans up a completed attempt.
    #[test]
    fn cbr9_remove() {
        let mut r = rt();
        r.start_build(1, nid(1), nid(2), nid(3), 0);
        r.advance(1).unwrap();
        r.complete(1, 0).unwrap();
        r.remove(1).unwrap();
        assert_eq!(r.state(1), None);
    }

    // CBR10: in_flight lists only pending/building circuits.
    #[test]
    fn cbr10_in_flight() {
        let mut r = rt();
        r.start_build(1, nid(1), nid(2), nid(3), 0);
        r.start_build(2, nid(4), nid(5), nid(6), 0);
        r.advance(1).unwrap();
        r.complete(1, 0).unwrap(); // Built — not in-flight
        let in_flight: Vec<u64> = r.in_flight().collect();
        assert!(!in_flight.contains(&1));
        assert!(in_flight.contains(&2));
    }

    // CBR11: multiple circuits managed independently.
    #[test]
    fn cbr11_multiple_circuits() {
        let mut r = rt();
        for i in 1u64..=5 {
            r.start_build(i, nid(1), nid(2), nid(3), 0);
            r.advance(i).unwrap();
            r.complete(i, i).unwrap();
        }
        for i in 1u64..=5 {
            assert_eq!(r.state(i), Some(CircuitBuildState::Built));
        }
    }
}
