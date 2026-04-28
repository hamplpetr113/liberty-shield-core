/// A nonce value carried on a cell, used to detect replayed cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CellNonce(pub u64);

/// Errors produced by replay detection.
#[derive(Debug, PartialEq, Eq)]
pub enum ReplayError {
    /// The nonce has already been seen on this circuit.
    DuplicateNonce,
    /// The nonce is older than the replay window allows.
    WindowExpired,
}
