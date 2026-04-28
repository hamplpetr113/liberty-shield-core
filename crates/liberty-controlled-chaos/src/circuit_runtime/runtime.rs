use crate::circuit_builder::{Circuit, CircuitId};
use crate::mesh_router::{RouteId, RoutePath};
use crate::noise_link::EncryptedCell;
use crate::udp_transport::PeerAddress;

use super::circuit_table::{ActiveCircuit, CircuitTable};
use super::types::{CircuitRuntimeError, CircuitState};

/// Manages the lifecycle of active circuits and routes cells through them.
///
/// Does not perform network I/O.  The caller is responsible for actually
/// dispatching the returned `PeerAddress` to `UDPTransport`.
pub struct CircuitRuntime {
    table: CircuitTable,
}

impl CircuitRuntime {
    pub fn new() -> Self {
        Self {
            table: CircuitTable::new(),
        }
    }

    /// Register a circuit and mark it `Active`.
    ///
    /// A `RoutePath` is built from the circuit's relay hops.
    /// `timestamp` is stored as opaque metadata (e.g. Unix milliseconds).
    pub fn register_circuit(
        &mut self,
        circuit: Circuit,
        timestamp: u64,
    ) -> Result<(), CircuitRuntimeError> {
        let circuit_id = circuit.circuit_id;
        let hops: Vec<PeerAddress> = circuit
            .hops
            .iter()
            .map(|n| n.peer_address.clone())
            .collect();
        // Give the path a generous forwarding budget; it is meant to be
        // traversed many times (one advance per send_cell call).
        let ttl = (hops.len() as u32).saturating_mul(1_000);
        let route_path = RoutePath::new(RouteId(circuit_id.0), hops, ttl);
        self.table.insert(ActiveCircuit {
            circuit,
            route_path,
            state: CircuitState::Active,
            creation_timestamp: timestamp,
        })
    }

    /// Advance the circuit's `RoutePath` by one hop and return the next peer.
    ///
    /// The `cell` payload is never inspected; it is the caller's responsibility
    /// to apply onion encryption before dispatching.
    pub fn send_cell(
        &mut self,
        circuit_id: CircuitId,
        _cell: &EncryptedCell,
    ) -> Result<PeerAddress, CircuitRuntimeError> {
        let active = self.table.get_mut(circuit_id)?;
        if active.state != CircuitState::Active {
            return Err(CircuitRuntimeError::CircuitNotActive(circuit_id));
        }
        active
            .route_path
            .advance()
            .map_err(CircuitRuntimeError::RoutingFailed)
    }

    /// Transition a circuit to `Closed` state.
    ///
    /// Subsequent `send_cell` calls on this circuit will return
    /// `CircuitNotActive`.  Returns `CircuitNotFound` if the id is unknown.
    pub fn close_circuit(&mut self, circuit_id: CircuitId) -> Result<(), CircuitRuntimeError> {
        let active = self.table.get_mut(circuit_id)?;
        active.state = CircuitState::Closed;
        Ok(())
    }

    /// Borrow the `ActiveCircuit` for inspection.
    pub fn get_active_circuit(
        &self,
        circuit_id: CircuitId,
    ) -> Result<&ActiveCircuit, CircuitRuntimeError> {
        self.table.get(circuit_id)
    }
}

impl Default for CircuitRuntime {
    fn default() -> Self {
        Self::new()
    }
}
