use std::collections::HashMap;

use crate::circuit_builder::CircuitId;
use crate::circuit_extension::CircuitExtensionState;
use crate::relay_protocol::RelayNodeId;

use super::errors::ProtocolRuntimeError;

struct CircuitEntry {
    state: CircuitExtensionState,
    confirmed_relays: Vec<u64>,
    pending_relay: Option<u64>,
}

/// Bridges the circuit extension state machine into the integration runtime.
///
/// Maintains per-circuit `CircuitExtensionState`; no network I/O.
pub struct CircuitRuntimeAdapter {
    circuits: HashMap<u64, CircuitEntry>,
}

impl CircuitRuntimeAdapter {
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
        }
    }

    /// Register a circuit in `Building` state.  Error: `InvalidState` if duplicate.
    pub fn create_circuit(&mut self, circuit_id: CircuitId) -> Result<(), ProtocolRuntimeError> {
        if self.circuits.contains_key(&circuit_id.0) {
            return Err(ProtocolRuntimeError::InvalidState);
        }
        self.circuits.insert(
            circuit_id.0,
            CircuitEntry {
                state: CircuitExtensionState::Building,
                confirmed_relays: Vec::new(),
                pending_relay: None,
            },
        );
        Ok(())
    }

    /// Begin extending the circuit to `relay_id`.
    ///
    /// Allowed from `Building` or `Active` states.  Errors: `CircuitNotFound`,
    /// `InvalidState` (if Destroyed or the relay is already in the circuit).
    pub fn extend_circuit(
        &mut self,
        circuit_id: CircuitId,
        relay_id: RelayNodeId,
    ) -> Result<(), ProtocolRuntimeError> {
        let entry = self
            .circuits
            .get_mut(&circuit_id.0)
            .ok_or(ProtocolRuntimeError::CircuitNotFound)?;

        if entry.state == CircuitExtensionState::Destroyed {
            return Err(ProtocolRuntimeError::InvalidState);
        }
        if entry.confirmed_relays.contains(&relay_id.0) {
            return Err(ProtocolRuntimeError::InvalidState);
        }
        entry.state = CircuitExtensionState::Extending;
        entry.pending_relay = Some(relay_id.0);
        Ok(())
    }

    /// Mark the pending extension as successful.  Transitions `Extending → Active`.
    pub fn complete_extension(
        &mut self,
        circuit_id: CircuitId,
    ) -> Result<(), ProtocolRuntimeError> {
        let entry = self
            .circuits
            .get_mut(&circuit_id.0)
            .ok_or(ProtocolRuntimeError::CircuitNotFound)?;

        if entry.state != CircuitExtensionState::Extending {
            return Err(ProtocolRuntimeError::InvalidState);
        }
        if let Some(relay) = entry.pending_relay.take() {
            entry.confirmed_relays.push(relay);
        }
        entry.state = CircuitExtensionState::Active;
        Ok(())
    }

    /// Destroy a circuit regardless of its current state.
    pub fn destroy_circuit(&mut self, circuit_id: CircuitId) -> Result<(), ProtocolRuntimeError> {
        let entry = self
            .circuits
            .get_mut(&circuit_id.0)
            .ok_or(ProtocolRuntimeError::CircuitNotFound)?;
        entry.state = CircuitExtensionState::Destroyed;
        Ok(())
    }

    /// Return the current state of a circuit, if registered.
    pub fn get_state(&self, circuit_id: CircuitId) -> Option<CircuitExtensionState> {
        self.circuits.get(&circuit_id.0).map(|e| e.state)
    }
}

impl Default for CircuitRuntimeAdapter {
    fn default() -> Self {
        Self::new()
    }
}
