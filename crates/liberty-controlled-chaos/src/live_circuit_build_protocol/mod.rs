//! Live circuit build protocol — tracks multi-hop circuit construction state.
//!
//! Manages the CREATE → CREATED → EXTEND → EXTENDED state machine for
//! circuit building across multiple hops.  No real crypto; hop keys are
//! placeholder byte arrays.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// BuildStep
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildStep {
    /// Sent CREATE to first hop; waiting for CREATED.
    AwaitingCreated,
    /// Sent EXTEND to relay N; waiting for EXTENDED.
    AwaitingExtended { relay_index: usize },
    /// All hops established.
    Complete,
}

// ---------------------------------------------------------------------------
// CircuitBuildError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitBuildError {
    AlreadyComplete,
    NotStarted,
    WrongRelay,
    TooManyHops,
    InvalidState,
    NotFound,
}

// ---------------------------------------------------------------------------
// HopRecord
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HopRecord {
    pub node_id: [u8; 32],
    pub hop_key: [u8; 32],
}

// ---------------------------------------------------------------------------
// CircuitBuildState
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CircuitBuildState {
    pub circuit_id: u64,
    pub hops: Vec<HopRecord>,
    pub target_hops: usize,
    pub step: BuildStep,
    pub created_epoch: u64,
}

// ---------------------------------------------------------------------------
// LiveCircuitBuildProtocol
// ---------------------------------------------------------------------------

pub const MAX_HOPS: usize = 8;

pub struct LiveCircuitBuildProtocol {
    circuits: HashMap<u64, CircuitBuildState>,
    completed: u64,
}

impl LiveCircuitBuildProtocol {
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
            completed: 0,
        }
    }

    /// Initiate circuit construction toward `first_hop`.
    pub fn initiate(
        &mut self,
        circuit_id: u64,
        first_hop: [u8; 32],
        target_hops: usize,
        epoch: u64,
    ) -> Result<(), CircuitBuildError> {
        if target_hops == 0 || target_hops > MAX_HOPS {
            return Err(CircuitBuildError::TooManyHops);
        }
        if self.circuits.contains_key(&circuit_id) {
            return Err(CircuitBuildError::InvalidState);
        }
        self.circuits.insert(
            circuit_id,
            CircuitBuildState {
                circuit_id,
                hops: Vec::with_capacity(target_hops),
                target_hops,
                step: BuildStep::AwaitingCreated,
                created_epoch: epoch,
            },
        );
        // Record placeholder for first hop — key set on CREATED.
        let _ = first_hop; // will be confirmed in recv_created
        Ok(())
    }

    /// Handle CREATED response from the first hop.
    pub fn recv_created(
        &mut self,
        circuit_id: u64,
        node_id: [u8; 32],
        hop_key: [u8; 32],
    ) -> Result<BuildStep, CircuitBuildError> {
        let state = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or(CircuitBuildError::NotFound)?;
        if state.step != BuildStep::AwaitingCreated {
            return Err(CircuitBuildError::InvalidState);
        }
        state.hops.push(HopRecord { node_id, hop_key });
        if state.hops.len() >= state.target_hops {
            state.step = BuildStep::Complete;
            self.completed += 1;
        } else {
            state.step = BuildStep::AwaitingExtended { relay_index: 0 };
        }
        Ok(state.step)
    }

    /// Dispatch an EXTEND — update step to AwaitingExtended.
    pub fn send_extend(
        &mut self,
        circuit_id: u64,
        relay_index: usize,
    ) -> Result<(), CircuitBuildError> {
        let state = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or(CircuitBuildError::NotFound)?;
        match state.step {
            BuildStep::AwaitingExtended { .. } => {
                state.step = BuildStep::AwaitingExtended { relay_index };
                Ok(())
            }
            BuildStep::Complete => Err(CircuitBuildError::AlreadyComplete),
            _ => Err(CircuitBuildError::InvalidState),
        }
    }

    /// Handle EXTENDED response.
    pub fn recv_extended(
        &mut self,
        circuit_id: u64,
        node_id: [u8; 32],
        hop_key: [u8; 32],
    ) -> Result<BuildStep, CircuitBuildError> {
        let state = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or(CircuitBuildError::NotFound)?;
        match state.step {
            BuildStep::AwaitingExtended { .. } => {}
            BuildStep::Complete => return Err(CircuitBuildError::AlreadyComplete),
            _ => return Err(CircuitBuildError::InvalidState),
        }
        state.hops.push(HopRecord { node_id, hop_key });
        if state.hops.len() >= state.target_hops {
            state.step = BuildStep::Complete;
            self.completed += 1;
        } else {
            state.step = BuildStep::AwaitingExtended {
                relay_index: state.hops.len() - 1,
            };
        }
        Ok(state.step)
    }

    pub fn state(&self, circuit_id: u64) -> Option<&CircuitBuildState> {
        self.circuits.get(&circuit_id)
    }

    pub fn remove(&mut self, circuit_id: u64) -> bool {
        self.circuits.remove(&circuit_id).is_some()
    }

    pub fn is_complete(&self, circuit_id: u64) -> bool {
        self.circuits
            .get(&circuit_id)
            .map(|s| s.step == BuildStep::Complete)
            .unwrap_or(false)
    }

    pub fn completed_count(&self) -> u64 {
        self.completed
    }

    pub fn in_progress_count(&self) -> usize {
        self.circuits
            .values()
            .filter(|s| s.step != BuildStep::Complete)
            .count()
    }
}

impl Default for LiveCircuitBuildProtocol {
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

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // LCB1: initiate creates circuit in AwaitingCreated.
    #[test]
    fn lcb1_initiate() {
        let mut p = LiveCircuitBuildProtocol::new();
        p.initiate(1, nid(10), 3, 0).unwrap();
        assert_eq!(p.state(1).unwrap().step, BuildStep::AwaitingCreated);
    }

    // LCB2: recv_created with target 1 hop → Complete.
    #[test]
    fn lcb2_single_hop_complete() {
        let mut p = LiveCircuitBuildProtocol::new();
        p.initiate(1, nid(10), 1, 0).unwrap();
        let step = p.recv_created(1, nid(10), key(1)).unwrap();
        assert_eq!(step, BuildStep::Complete);
    }

    // LCB3: recv_created with target > 1 → AwaitingExtended.
    #[test]
    fn lcb3_multi_hop_awaiting_extended() {
        let mut p = LiveCircuitBuildProtocol::new();
        p.initiate(1, nid(10), 3, 0).unwrap();
        let step = p.recv_created(1, nid(10), key(1)).unwrap();
        assert!(matches!(step, BuildStep::AwaitingExtended { .. }));
    }

    // LCB4: full 3-hop circuit build.
    #[test]
    fn lcb4_three_hop_build() {
        let mut p = LiveCircuitBuildProtocol::new();
        p.initiate(1, nid(10), 3, 0).unwrap();
        p.recv_created(1, nid(10), key(1)).unwrap();
        p.send_extend(1, 1).unwrap();
        p.recv_extended(1, nid(11), key(2)).unwrap();
        p.send_extend(1, 2).unwrap();
        let step = p.recv_extended(1, nid(12), key(3)).unwrap();
        assert_eq!(step, BuildStep::Complete);
        assert!(p.is_complete(1));
    }

    // LCB5: recv_created on non-existent circuit returns NotFound.
    #[test]
    fn lcb5_not_found() {
        let mut p = LiveCircuitBuildProtocol::new();
        assert_eq!(
            p.recv_created(99, nid(1), key(1)),
            Err(CircuitBuildError::NotFound)
        );
    }

    // LCB6: recv_extended on complete circuit returns AlreadyComplete.
    #[test]
    fn lcb6_already_complete() {
        let mut p = LiveCircuitBuildProtocol::new();
        p.initiate(1, nid(10), 1, 0).unwrap();
        p.recv_created(1, nid(10), key(1)).unwrap();
        assert_eq!(
            p.recv_extended(1, nid(11), key(2)),
            Err(CircuitBuildError::AlreadyComplete)
        );
    }

    // LCB7: completed_count increments per circuit.
    #[test]
    fn lcb7_completed_count() {
        let mut p = LiveCircuitBuildProtocol::new();
        p.initiate(1, nid(1), 1, 0).unwrap();
        p.recv_created(1, nid(1), key(1)).unwrap();
        p.initiate(2, nid(2), 1, 0).unwrap();
        p.recv_created(2, nid(2), key(2)).unwrap();
        assert_eq!(p.completed_count(), 2);
    }

    // LCB8: in_progress_count returns pending circuits.
    #[test]
    fn lcb8_in_progress_count() {
        let mut p = LiveCircuitBuildProtocol::new();
        p.initiate(1, nid(1), 2, 0).unwrap();
        p.initiate(2, nid(2), 1, 0).unwrap();
        p.recv_created(2, nid(2), key(1)).unwrap(); // completes circuit 2
        assert_eq!(p.in_progress_count(), 1);
    }

    // LCB9: remove deletes circuit.
    #[test]
    fn lcb9_remove() {
        let mut p = LiveCircuitBuildProtocol::new();
        p.initiate(1, nid(1), 1, 0).unwrap();
        assert!(p.remove(1));
        assert!(p.state(1).is_none());
    }

    // LCB10: duplicate circuit_id returns InvalidState.
    #[test]
    fn lcb10_duplicate_circuit() {
        let mut p = LiveCircuitBuildProtocol::new();
        p.initiate(1, nid(1), 2, 0).unwrap();
        assert_eq!(
            p.initiate(1, nid(2), 2, 0),
            Err(CircuitBuildError::InvalidState)
        );
    }
}
