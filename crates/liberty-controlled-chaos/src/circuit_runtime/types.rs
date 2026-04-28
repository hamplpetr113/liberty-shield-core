use crate::circuit_builder::CircuitId;
use crate::mesh_router::RoutingError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Building,
    Active,
    Closed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CircuitRuntimeError {
    /// No circuit with this `CircuitId` is registered.
    CircuitNotFound(CircuitId),
    /// The circuit exists but is not in `Active` state.
    CircuitNotActive(CircuitId),
    /// A circuit with the same `CircuitId` is already registered.
    CircuitAlreadyExists(CircuitId),
    /// An error propagated from the underlying `RoutePath` / routing layer.
    RoutingFailed(RoutingError),
}
