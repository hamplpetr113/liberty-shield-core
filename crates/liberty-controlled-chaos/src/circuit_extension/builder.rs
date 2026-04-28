use std::collections::HashMap;

use crate::circuit_builder::CircuitId;
use crate::relay_protocol::RelayNodeId;
use crate::udp_transport::PeerAddress;

use super::state::CircuitExtensionState;
use super::types::{DestroyReason, ExtensionError};

struct CircuitEntry {
    state: CircuitExtensionState,
    /// Relays already confirmed in the circuit.
    confirmed_relays: Vec<u64>,
    /// Relay currently being extended to (pending `complete_extend`).
    pending_relay: Option<u64>,
}

/// Manages the extension lifecycle of multiple circuits.
///
/// No network I/O; all transitions are deterministic.
pub struct CircuitExtensionManager {
    circuits: HashMap<u64, CircuitEntry>,
}

impl CircuitExtensionManager {
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
        }
    }

    /// Register a new circuit in `Building` state.
    pub fn register_circuit(&mut self, circuit_id: CircuitId) -> Result<(), ExtensionError> {
        if self.circuits.contains_key(&circuit_id.0) {
            return Err(ExtensionError::CircuitAlreadyRegistered);
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

    /// Request extension of `circuit_id` by one hop to `relay`.
    ///
    /// Allowed from `Building` or `Active` states.
    pub fn request_extend(
        &mut self,
        circuit_id: CircuitId,
        relay: RelayNodeId,
        _address: PeerAddress,
    ) -> Result<(), ExtensionError> {
        let entry = self
            .circuits
            .get_mut(&circuit_id.0)
            .ok_or(ExtensionError::CircuitNotFound)?;

        match entry.state {
            CircuitExtensionState::Destroyed => {
                return Err(ExtensionError::CircuitDestroyed);
            }
            CircuitExtensionState::Extending => {
                return Err(ExtensionError::InvalidState);
            }
            CircuitExtensionState::Building | CircuitExtensionState::Active => {}
        }

        if entry.confirmed_relays.contains(&relay.0) {
            return Err(ExtensionError::DuplicateRelay);
        }

        entry.state = CircuitExtensionState::Extending;
        entry.pending_relay = Some(relay.0);
        Ok(())
    }

    /// Record the result of a pending extension attempt.
    ///
    /// On success: relay is added to the circuit, state → `Active`.
    /// On failure: pending relay cleared, state → `Building`.
    pub fn complete_extend(
        &mut self,
        circuit_id: CircuitId,
        _relay: RelayNodeId,
        success: bool,
    ) -> Result<(), ExtensionError> {
        let entry = self
            .circuits
            .get_mut(&circuit_id.0)
            .ok_or(ExtensionError::CircuitNotFound)?;

        if entry.state != CircuitExtensionState::Extending {
            return Err(ExtensionError::InvalidState);
        }

        if success {
            if let Some(relay_id) = entry.pending_relay.take() {
                entry.confirmed_relays.push(relay_id);
            }
            entry.state = CircuitExtensionState::Active;
        } else {
            entry.pending_relay = None;
            entry.state = CircuitExtensionState::Building;
        }
        Ok(())
    }

    /// Destroy a circuit, regardless of its current state.
    pub fn destroy_circuit(
        &mut self,
        circuit_id: CircuitId,
        _reason: DestroyReason,
    ) -> Result<(), ExtensionError> {
        let entry = self
            .circuits
            .get_mut(&circuit_id.0)
            .ok_or(ExtensionError::CircuitNotFound)?;
        entry.state = CircuitExtensionState::Destroyed;
        entry.pending_relay = None;
        Ok(())
    }

    /// Return the current state of a circuit, if registered.
    pub fn get_state(&self, circuit_id: CircuitId) -> Option<CircuitExtensionState> {
        self.circuits.get(&circuit_id.0).map(|e| e.state)
    }
}

impl Default for CircuitExtensionManager {
    fn default() -> Self {
        Self::new()
    }
}
