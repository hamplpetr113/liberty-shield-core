use std::collections::HashMap;

use crate::circuit_builder::{Circuit, CircuitId};
use crate::mesh_router::RoutePath;

use super::types::{CircuitRuntimeError, CircuitState};

/// A live circuit entry held in the `CircuitTable`.
pub struct ActiveCircuit {
    /// The fully-built circuit descriptor (hops + onion keys).
    pub circuit: Circuit,
    /// Stateful multi-hop path derived from the circuit's relay hops.
    pub route_path: RoutePath,
    /// Lifecycle state of this circuit.
    pub state: CircuitState,
    /// Opaque creation timestamp supplied by the caller (e.g. Unix ms).
    pub creation_timestamp: u64,
}

/// In-memory store keyed by `CircuitId`.
pub struct CircuitTable {
    circuits: HashMap<u64, ActiveCircuit>,
}

impl CircuitTable {
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
        }
    }

    /// Insert a new entry.  Returns `CircuitAlreadyExists` if the id is taken.
    pub fn insert(&mut self, active: ActiveCircuit) -> Result<(), CircuitRuntimeError> {
        let id = active.circuit.circuit_id.0;
        if self.circuits.contains_key(&id) {
            return Err(CircuitRuntimeError::CircuitAlreadyExists(
                active.circuit.circuit_id,
            ));
        }
        self.circuits.insert(id, active);
        Ok(())
    }

    pub fn get(&self, circuit_id: CircuitId) -> Result<&ActiveCircuit, CircuitRuntimeError> {
        self.circuits
            .get(&circuit_id.0)
            .ok_or(CircuitRuntimeError::CircuitNotFound(circuit_id))
    }

    pub fn get_mut(
        &mut self,
        circuit_id: CircuitId,
    ) -> Result<&mut ActiveCircuit, CircuitRuntimeError> {
        self.circuits
            .get_mut(&circuit_id.0)
            .ok_or(CircuitRuntimeError::CircuitNotFound(circuit_id))
    }

    #[allow(dead_code)]
    pub fn remove(&mut self, circuit_id: CircuitId) -> Result<ActiveCircuit, CircuitRuntimeError> {
        self.circuits
            .remove(&circuit_id.0)
            .ok_or(CircuitRuntimeError::CircuitNotFound(circuit_id))
    }
}

impl Default for CircuitTable {
    fn default() -> Self {
        Self::new()
    }
}
