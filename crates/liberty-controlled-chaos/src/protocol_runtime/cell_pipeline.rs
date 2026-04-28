use crate::onion_cell_protocol::{OnionCell, decode_cell, encode_cell};
use crate::replay_protection::{CellNonce, ReplayDetector};

use super::errors::ProtocolRuntimeError;
use super::types::{ProtocolAction, ProtocolRuntimeState};

/// Derive a deterministic nonce from raw cell bytes.
///
/// Uses an FNV-1a-style fold so identical byte sequences produce the same
/// nonce (replay detection) and different sequences almost certainly differ.
fn derive_nonce(bytes: &[u8]) -> CellNonce {
    CellNonce(bytes.iter().fold(0xcbf29ce484222325u64, |h, &b| {
        h.wrapping_mul(0x100000001b3).wrapping_add(b as u64)
    }))
}

/// Processes cells through the replay / decode pipeline.
///
/// Counter semantics:
/// - `dropped_cells`    — incremented on decode failure.
/// - `rejected_replays` — incremented on duplicate-nonce detection.
/// - `forwarded_cells`  — incremented when a valid cell is accepted.
pub struct CellPipeline {
    replay_detector: ReplayDetector,
    pub state: ProtocolRuntimeState,
}

impl CellPipeline {
    pub fn new() -> Self {
        Self {
            replay_detector: ReplayDetector::new(),
            state: ProtocolRuntimeState::default(),
        }
    }

    /// Process raw incoming bytes through the cell pipeline.
    ///
    /// Steps:
    ///   1. Decode bytes → `OnionCell`.
    ///   2. Check replay window on the cell's circuit.
    ///   3. Accept and return `ForwardCell`.
    pub fn process_incoming(
        &mut self,
        bytes: &[u8],
    ) -> Result<ProtocolAction, ProtocolRuntimeError> {
        // 1. Decode.
        let cell = match decode_cell(bytes) {
            Ok(c) => c,
            Err(_) => {
                self.state.dropped_cells += 1;
                return Err(ProtocolRuntimeError::InvalidCell);
            }
        };

        // 2. Replay check.
        let nonce = derive_nonce(bytes);
        if self
            .replay_detector
            .check_cell(cell.circuit_id, nonce)
            .is_err()
        {
            self.state.rejected_replays += 1;
            return Err(ProtocolRuntimeError::ReplayDetected);
        }

        // 3. Forward.
        self.state.forwarded_cells += 1;
        Ok(ProtocolAction::ForwardCell(cell.circuit_id))
    }

    /// Encode an outgoing `OnionCell` and return the bytes to send.
    pub fn process_outgoing(
        &mut self,
        cell: &OnionCell,
    ) -> Result<ProtocolAction, ProtocolRuntimeError> {
        Ok(ProtocolAction::SendCell(encode_cell(cell)))
    }
}

impl Default for CellPipeline {
    fn default() -> Self {
        Self::new()
    }
}
