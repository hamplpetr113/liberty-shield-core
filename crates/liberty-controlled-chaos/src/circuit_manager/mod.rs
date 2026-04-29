//! Circuit lifecycle manager — create, track, rotate, and close circuits.
//!
//! `CircuitManager` maintains `CircuitInfo` records keyed by `CircuitId` and
//! drives state transitions through Building → Open → Rotating → Closed.
//!
//! NON-PRODUCTION: IDs are assigned from a monotonic counter.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// CircuitId
// ---------------------------------------------------------------------------

/// Opaque circuit identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CircuitId(pub u64);

impl CircuitId {
    pub fn value(self) -> u64 {
        self.0
    }
}

impl From<u64> for CircuitId {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

// ---------------------------------------------------------------------------
// CircuitState
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Building,
    Open,
    Rotating,
    Closed,
}

// ---------------------------------------------------------------------------
// CircuitInfo
// ---------------------------------------------------------------------------

/// Per-circuit metadata.
#[derive(Debug, Clone)]
pub struct CircuitInfo {
    pub id: CircuitId,
    /// node_id of the guard hop.
    pub guard: [u8; 32],
    /// node_id of the relay hop.
    pub relay: [u8; 32],
    /// node_id of the exit hop.
    pub exit: [u8; 32],
    /// Epoch at which the circuit was created.
    pub created_epoch: u64,
    /// Last epoch at which the circuit carried traffic.
    pub last_used_epoch: u64,
    pub state: CircuitState,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitManagerError {
    /// A circuit with this ID already exists.
    DuplicateId,
    /// No circuit with the given ID exists.
    NotFound,
    /// Operation is not valid in the current state.
    InvalidState,
}

impl std::fmt::Display for CircuitManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitManagerError::DuplicateId => write!(f, "circuit id already exists"),
            CircuitManagerError::NotFound => write!(f, "circuit not found"),
            CircuitManagerError::InvalidState => write!(f, "invalid state for operation"),
        }
    }
}

// ---------------------------------------------------------------------------
// CircuitManager
// ---------------------------------------------------------------------------

/// Manages the full lifecycle of onion circuits.
pub struct CircuitManager {
    circuits: HashMap<CircuitId, CircuitInfo>,
    next_id: u64,
}

impl CircuitManager {
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
            next_id: 1,
        }
    }

    /// Create and register a new circuit in the `Building` state.
    ///
    /// Returns the assigned `CircuitId`.
    pub fn create_circuit(
        &mut self,
        guard: [u8; 32],
        relay: [u8; 32],
        exit: [u8; 32],
        current_epoch: u64,
    ) -> CircuitId {
        let id = CircuitId(self.next_id);
        self.next_id += 1;
        let info = CircuitInfo {
            id,
            guard,
            relay,
            exit,
            created_epoch: current_epoch,
            last_used_epoch: current_epoch,
            state: CircuitState::Building,
        };
        self.circuits.insert(id, info);
        id
    }

    /// Create a circuit with an explicit ID.  Returns `DuplicateId` if already present.
    pub fn create_circuit_with_id(
        &mut self,
        id: CircuitId,
        guard: [u8; 32],
        relay: [u8; 32],
        exit: [u8; 32],
        current_epoch: u64,
    ) -> Result<(), CircuitManagerError> {
        if self.circuits.contains_key(&id) {
            return Err(CircuitManagerError::DuplicateId);
        }
        let info = CircuitInfo {
            id,
            guard,
            relay,
            exit,
            created_epoch: current_epoch,
            last_used_epoch: current_epoch,
            state: CircuitState::Building,
        };
        self.circuits.insert(id, info);
        Ok(())
    }

    /// Retrieve circuit info.
    pub fn get_circuit(&self, id: CircuitId) -> Option<&CircuitInfo> {
        self.circuits.get(&id)
    }

    /// Transition circuit from `Building` → `Open`.
    pub fn mark_open(&mut self, id: CircuitId) -> Result<(), CircuitManagerError> {
        let info = self
            .circuits
            .get_mut(&id)
            .ok_or(CircuitManagerError::NotFound)?;
        if info.state != CircuitState::Building {
            return Err(CircuitManagerError::InvalidState);
        }
        info.state = CircuitState::Open;
        Ok(())
    }

    /// Update `last_used_epoch` for an open circuit.
    pub fn mark_used(&mut self, id: CircuitId, epoch: u64) -> Result<(), CircuitManagerError> {
        let info = self
            .circuits
            .get_mut(&id)
            .ok_or(CircuitManagerError::NotFound)?;
        if info.state != CircuitState::Open {
            return Err(CircuitManagerError::InvalidState);
        }
        info.last_used_epoch = epoch;
        Ok(())
    }

    /// Transition open circuits whose `created_epoch` predates `current_epoch`
    /// to the `Rotating` state.
    ///
    /// Returns the IDs of circuits that were moved to Rotating.
    pub fn rotate_expired(&mut self, current_epoch: u64) -> Vec<CircuitId> {
        let mut rotated = Vec::new();
        for info in self.circuits.values_mut() {
            if info.state == CircuitState::Open && info.created_epoch < current_epoch {
                info.state = CircuitState::Rotating;
                rotated.push(info.id);
            }
        }
        rotated
    }

    /// Mark a circuit as `Closed` (any non-Closed state is valid).
    pub fn close_circuit(&mut self, id: CircuitId) -> Result<(), CircuitManagerError> {
        let info = self
            .circuits
            .get_mut(&id)
            .ok_or(CircuitManagerError::NotFound)?;
        if info.state == CircuitState::Closed {
            return Err(CircuitManagerError::InvalidState);
        }
        info.state = CircuitState::Closed;
        Ok(())
    }

    /// Close all `Open` circuits that have been idle for more than `max_idle_epochs`.
    ///
    /// Returns the IDs that were closed.
    pub fn expire_idle(&mut self, current_epoch: u64, max_idle_epochs: u64) -> Vec<CircuitId> {
        let mut expired = Vec::new();
        for info in self.circuits.values_mut() {
            if info.state == CircuitState::Open
                && current_epoch.saturating_sub(info.last_used_epoch) > max_idle_epochs
            {
                info.state = CircuitState::Closed;
                expired.push(info.id);
            }
        }
        expired
    }

    /// Total number of tracked circuits (all states).
    pub fn len(&self) -> usize {
        self.circuits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.circuits.is_empty()
    }

    /// Number of circuits in a given state.
    pub fn count_in_state(&self, state: CircuitState) -> usize {
        self.circuits.values().filter(|c| c.state == state).count()
    }
}

impl Default for CircuitManager {
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

    fn node(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // CM1: create circuit returns unique id and Building state.
    #[test]
    fn cm1_create_circuit() {
        let mut mgr = CircuitManager::new();
        let id = mgr.create_circuit(node(1), node(2), node(3), 0);
        let info = mgr.get_circuit(id).unwrap();
        assert_eq!(info.state, CircuitState::Building);
        assert_eq!(info.guard, node(1));
    }

    // CM2: mark_used updates last_used_epoch.
    #[test]
    fn cm2_mark_used() {
        let mut mgr = CircuitManager::new();
        let id = mgr.create_circuit(node(1), node(2), node(3), 5);
        mgr.mark_open(id).unwrap();
        mgr.mark_used(id, 10).unwrap();
        assert_eq!(mgr.get_circuit(id).unwrap().last_used_epoch, 10);
    }

    // CM3: rotate_expired moves old Open circuits to Rotating.
    #[test]
    fn cm3_rotate_expired() {
        let mut mgr = CircuitManager::new();
        let id = mgr.create_circuit(node(1), node(2), node(3), 1);
        mgr.mark_open(id).unwrap();
        let rotated = mgr.rotate_expired(5);
        assert_eq!(rotated.len(), 1);
        assert_eq!(mgr.get_circuit(id).unwrap().state, CircuitState::Rotating);
    }

    // CM4: close_circuit transitions any open circuit to Closed.
    #[test]
    fn cm4_close_circuit() {
        let mut mgr = CircuitManager::new();
        let id = mgr.create_circuit(node(1), node(2), node(3), 0);
        mgr.mark_open(id).unwrap();
        mgr.close_circuit(id).unwrap();
        assert_eq!(mgr.get_circuit(id).unwrap().state, CircuitState::Closed);
    }

    // CM5: multiple circuits are tracked independently.
    #[test]
    fn cm5_multiple_circuits() {
        let mut mgr = CircuitManager::new();
        let a = mgr.create_circuit(node(1), node(2), node(3), 0);
        let b = mgr.create_circuit(node(4), node(5), node(6), 0);
        assert_ne!(a, b);
        assert_eq!(mgr.len(), 2);
    }

    // CM6: expire_idle closes circuits that have been unused too long.
    #[test]
    fn cm6_idle_expiration() {
        let mut mgr = CircuitManager::new();
        let id = mgr.create_circuit(node(1), node(2), node(3), 0);
        mgr.mark_open(id).unwrap();
        // Used at epoch 0, now at epoch 10, max idle = 5
        let expired = mgr.expire_idle(10, 5);
        assert_eq!(expired.len(), 1);
        assert_eq!(mgr.get_circuit(id).unwrap().state, CircuitState::Closed);
    }

    // CM7: duplicate explicit id is rejected.
    #[test]
    fn cm7_duplicate_id_protection() {
        let mut mgr = CircuitManager::new();
        let id = CircuitId(42);
        mgr.create_circuit_with_id(id, node(1), node(2), node(3), 0)
            .unwrap();
        assert_eq!(
            mgr.create_circuit_with_id(id, node(4), node(5), node(6), 0)
                .unwrap_err(),
            CircuitManagerError::DuplicateId
        );
    }

    // CM8: lifecycle transitions Building → Open → Closed.
    #[test]
    fn cm8_lifecycle_transitions() {
        let mut mgr = CircuitManager::new();
        let id = mgr.create_circuit(node(1), node(2), node(3), 0);
        assert_eq!(mgr.get_circuit(id).unwrap().state, CircuitState::Building);
        mgr.mark_open(id).unwrap();
        assert_eq!(mgr.get_circuit(id).unwrap().state, CircuitState::Open);
        mgr.close_circuit(id).unwrap();
        assert_eq!(mgr.get_circuit(id).unwrap().state, CircuitState::Closed);
    }

    // CM9: rotate_expired then close handles Rotating → Closed.
    #[test]
    fn cm9_rotation_state() {
        let mut mgr = CircuitManager::new();
        let id = mgr.create_circuit(node(1), node(2), node(3), 1);
        mgr.mark_open(id).unwrap();
        mgr.rotate_expired(3);
        assert_eq!(mgr.get_circuit(id).unwrap().state, CircuitState::Rotating);
        mgr.close_circuit(id).unwrap();
        assert_eq!(mgr.get_circuit(id).unwrap().state, CircuitState::Closed);
    }

    // CM10: stress — 100 circuits, rotate half, close remainder.
    #[test]
    fn cm10_stress_100_circuits() {
        let mut mgr = CircuitManager::new();
        let mut ids = Vec::new();
        for i in 0u8..100 {
            let id =
                mgr.create_circuit(node(i), node(i.wrapping_add(1)), node(i.wrapping_add(2)), 1);
            mgr.mark_open(id).unwrap();
            ids.push(id);
        }
        assert_eq!(mgr.count_in_state(CircuitState::Open), 100);
        // Rotate all (created_epoch=1, current=5).
        let rotated = mgr.rotate_expired(5);
        assert_eq!(rotated.len(), 100);
        assert_eq!(mgr.count_in_state(CircuitState::Rotating), 100);
        // Close all.
        for id in &ids {
            mgr.close_circuit(*id).unwrap();
        }
        assert_eq!(mgr.count_in_state(CircuitState::Closed), 100);
    }
}
