use std::collections::HashMap;

use crate::circuit_builder::CircuitId;

use super::types::{CellNonce, ReplayError};
use super::window::ReplayWindow;

const DEFAULT_WINDOW_SIZE: usize = 64;

/// Per-circuit replay detection.
///
/// Each circuit has its own `ReplayWindow` so nonces are isolated between
/// circuits.
pub struct ReplayDetector {
    circuits: HashMap<u64, ReplayWindow>,
}

impl ReplayDetector {
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
        }
    }

    /// Pre-register a circuit with the default window size.
    pub fn register_circuit(&mut self, circuit_id: CircuitId) {
        self.circuits
            .entry(circuit_id.0)
            .or_insert_with(|| ReplayWindow::new(DEFAULT_WINDOW_SIZE));
    }

    /// Remove a circuit's replay state.
    pub fn remove_circuit(&mut self, circuit_id: CircuitId) {
        self.circuits.remove(&circuit_id.0);
    }

    /// Check `nonce` on `circuit_id` and record it if valid.
    ///
    /// If the circuit has not been pre-registered, a default window is
    /// created lazily.
    pub fn check_cell(
        &mut self,
        circuit_id: CircuitId,
        nonce: CellNonce,
    ) -> Result<(), ReplayError> {
        let window = self
            .circuits
            .entry(circuit_id.0)
            .or_insert_with(|| ReplayWindow::new(DEFAULT_WINDOW_SIZE));
        window.check_and_record(nonce)
    }
}

impl Default for ReplayDetector {
    fn default() -> Self {
        Self::new()
    }
}
