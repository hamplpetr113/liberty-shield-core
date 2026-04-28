/// Errors produced by the relay protocol layer.
#[derive(Debug, PartialEq, Eq)]
pub enum RelayProtocolError {
    /// The relay rejected the handshake (`accepted == false`).
    HandshakeRejected,
    /// The operation is not valid in the current connection state.
    InvalidState,
    /// No relay with the given `RelayNodeId` is registered.
    RelayNotFound,
    /// The negotiated capabilities do not satisfy the requested capabilities.
    CapabilityMismatch,
    /// A relay with the same `RelayNodeId` is already registered.
    DuplicateRelay,
}
