use crate::circuit_builder::CircuitId;

use super::cell_types::OnionCellType;

/// A single protocol cell carrying data across one circuit.
///
/// Invariant: `payload_len == payload.len()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionCell {
    pub circuit_id: CircuitId,
    pub cell_type: OnionCellType,
    pub payload_len: u32,
    pub payload: Vec<u8>,
}

impl OnionCell {
    /// Construct a cell, deriving `payload_len` from `payload`.
    pub fn new(circuit_id: CircuitId, cell_type: OnionCellType, payload: Vec<u8>) -> Self {
        let payload_len = payload.len() as u32;
        Self {
            circuit_id,
            cell_type,
            payload_len,
            payload,
        }
    }
}
