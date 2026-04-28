/// Errors produced by the protocol integration runtime.
#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolRuntimeError {
    /// The relay exists but has not yet completed its handshake.
    RelayNotEstablished,
    /// No circuit with the given `CircuitId` is registered.
    CircuitNotFound,
    /// A replayed cell was detected and rejected.
    ReplayDetected,
    /// The raw bytes could not be decoded as a valid cell.
    InvalidCell,
    /// The operation is not valid in the current state.
    InvalidState,
}
