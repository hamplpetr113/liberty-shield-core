use crate::circuit_builder::CircuitId;
use crate::relay_protocol::RelayNodeId;
use crate::udp_transport::PeerAddress;

/// Request to extend a circuit by one hop.
#[derive(Debug, Clone)]
pub struct CircuitExtendRequest {
    pub circuit_id: CircuitId,
    pub next_relay: RelayNodeId,
    pub next_peer_address: PeerAddress,
}

/// Response to a circuit extension attempt.
#[derive(Debug, Clone)]
pub struct CircuitExtendResponse {
    pub circuit_id: CircuitId,
    pub success: bool,
    pub relay_id: RelayNodeId,
}

/// Reason a circuit was destroyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestroyReason {
    Manual,
    Timeout,
    Failure,
    GuardDegraded,
}

/// Instruction to tear down a circuit.
#[derive(Debug, Clone)]
pub struct CircuitDestroy {
    pub circuit_id: CircuitId,
    pub reason: DestroyReason,
}

/// Errors produced by the circuit extension layer.
#[derive(Debug, PartialEq, Eq)]
pub enum ExtensionError {
    /// No circuit with this `CircuitId` is registered.
    CircuitNotFound,
    /// The operation is not valid in the current extension state.
    InvalidState,
    /// The relay is already part of this circuit.
    DuplicateRelay,
    /// The circuit has been destroyed and may not be extended.
    CircuitDestroyed,
    /// A circuit with the same `CircuitId` is already registered.
    CircuitAlreadyRegistered,
}
