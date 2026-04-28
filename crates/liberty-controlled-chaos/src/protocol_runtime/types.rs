use crate::circuit_builder::CircuitId;
use crate::relay_protocol::{RelayDescriptor, RelayNodeId};

/// Events that drive the `ProtocolRuntime` state machine.
#[derive(Debug)]
pub enum ProtocolEvent {
    /// A new relay connection was opened; carries the relay's descriptor.
    RelayConnected(RelayDescriptor),
    /// The handshake for an existing relay has been confirmed.
    RelayHandshakeComplete(RelayNodeId),
    /// A new circuit has been allocated.
    CircuitCreated(CircuitId),
    /// A circuit has been extended by one hop to the given relay.
    CircuitExtended(CircuitId, RelayNodeId),
    /// A circuit has been torn down.
    CircuitDestroyed(CircuitId),
    /// Raw cell bytes arrived from the network.
    CellReceived(Vec<u8>),
    /// A cell was forwarded on a specific circuit (external notification).
    CellForwarded(CircuitId),
    /// A cell was rejected by replay detection (external notification).
    ReplayRejected(CircuitId),
}

/// Actions that the `ProtocolRuntime` requests the caller to perform.
#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolAction {
    /// Send encoded cell bytes to the network.
    SendCell(Vec<u8>),
    /// Forward the cell on the given circuit.
    ForwardCell(CircuitId),
    /// Drop the cell silently.
    DropCell,
    /// Destroy the given circuit.
    DestroyCircuit(CircuitId),
    /// Notify the given relay (e.g., handshake progress).
    NotifyRelay(RelayNodeId),
    /// No action required.
    NoAction,
}

/// Snapshot of runtime activity counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtocolRuntimeState {
    pub active_relays: usize,
    pub active_circuits: usize,
    pub rejected_replays: usize,
    pub forwarded_cells: usize,
    pub dropped_cells: usize,
}
