use crate::circuit_builder::CircuitId;

use super::cell::OnionCell;
use super::cell_types::OnionCellType;

/// Errors produced when decoding raw bytes into an `OnionCell`.
#[derive(Debug, PartialEq, Eq)]
pub enum OnionCellError {
    /// The byte slice is too short to contain the fixed header (13 bytes).
    InvalidLength,
    /// The cell-type byte does not correspond to any known `OnionCellType`.
    InvalidCellType,
    /// The `payload_len` field in the header does not match the bytes remaining
    /// after the header.
    PayloadLengthMismatch { stated: u32, actual: usize },
}

const HEADER_LEN: usize = 8 + 1 + 4; // circuit_id + cell_type + payload_len

/// Decode a byte slice into an `OnionCell`.
pub fn decode_cell(bytes: &[u8]) -> Result<OnionCell, OnionCellError> {
    if bytes.len() < HEADER_LEN {
        return Err(OnionCellError::InvalidLength);
    }

    let circuit_id = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let cell_type_byte = bytes[8];
    let payload_len = u32::from_le_bytes(bytes[9..13].try_into().unwrap());

    let cell_type =
        OnionCellType::from_u8(cell_type_byte).ok_or(OnionCellError::InvalidCellType)?;

    let actual = bytes.len() - HEADER_LEN;
    if actual != payload_len as usize {
        return Err(OnionCellError::PayloadLengthMismatch {
            stated: payload_len,
            actual,
        });
    }

    Ok(OnionCell {
        circuit_id: CircuitId(circuit_id),
        cell_type,
        payload_len,
        payload: bytes[HEADER_LEN..].to_vec(),
    })
}
