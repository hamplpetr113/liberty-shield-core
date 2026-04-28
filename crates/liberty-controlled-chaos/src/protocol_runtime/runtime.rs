use super::cell_pipeline::CellPipeline;
use super::circuit_runtime_adapter::CircuitRuntimeAdapter;
use super::errors::ProtocolRuntimeError;
use super::relay_runtime::RelayRuntime;
use super::types::{ProtocolAction, ProtocolEvent, ProtocolRuntimeState};

/// Orchestrates the relay, circuit, and cell protocol state machines.
///
/// No network I/O; all transitions are driven by caller-supplied events.
pub struct ProtocolRuntime {
    relay_runtime: RelayRuntime,
    circuit_adapter: CircuitRuntimeAdapter,
    cell_pipeline: CellPipeline,
    /// Tracks active relay and circuit counts.
    state: ProtocolRuntimeState,
}

impl ProtocolRuntime {
    pub fn new() -> Self {
        Self {
            relay_runtime: RelayRuntime::new(),
            circuit_adapter: CircuitRuntimeAdapter::new(),
            cell_pipeline: CellPipeline::new(),
            state: ProtocolRuntimeState::default(),
        }
    }

    /// Route a protocol event through the appropriate sub-system and return
    /// the action the caller should perform.
    pub fn handle_event(&mut self, event: ProtocolEvent) -> ProtocolAction {
        match event {
            // ── Relay events ──────────────────���──────────────────────────────
            ProtocolEvent::RelayConnected(desc) => {
                let relay_id = desc.relay_id;
                if self.relay_runtime.register_relay(desc).is_ok() {
                    // Automatically begin the handshake on connect.
                    let _ = self.relay_runtime.begin_handshake(relay_id);
                    self.state.active_relays += 1;
                }
                ProtocolAction::NotifyRelay(relay_id)
            }
            ProtocolEvent::RelayHandshakeComplete(relay_id) => {
                let _ = self.relay_runtime.complete_handshake(relay_id);
                ProtocolAction::NotifyRelay(relay_id)
            }

            // ── Circuit events ────────────────────────────────────────────────
            ProtocolEvent::CircuitCreated(circuit_id) => {
                if self.circuit_adapter.create_circuit(circuit_id).is_ok() {
                    self.state.active_circuits += 1;
                }
                ProtocolAction::NoAction
            }
            ProtocolEvent::CircuitExtended(circuit_id, relay_id) => {
                // Collapse the request+complete into a single event.
                let _ = self.circuit_adapter.extend_circuit(circuit_id, relay_id);
                let _ = self.circuit_adapter.complete_extension(circuit_id);
                ProtocolAction::NoAction
            }
            ProtocolEvent::CircuitDestroyed(circuit_id) => {
                if self.circuit_adapter.destroy_circuit(circuit_id).is_ok() {
                    self.state.active_circuits = self.state.active_circuits.saturating_sub(1);
                }
                ProtocolAction::DestroyCircuit(circuit_id)
            }

            // ── Cell events ───────────────────────────────────────────────────
            ProtocolEvent::CellReceived(bytes) => {
                match self.cell_pipeline.process_incoming(&bytes) {
                    Ok(action) => action,
                    Err(ProtocolRuntimeError::ReplayDetected) => ProtocolAction::DropCell,
                    Err(_) => ProtocolAction::DropCell,
                }
            }
            ProtocolEvent::CellForwarded(circuit_id) => {
                self.cell_pipeline.state.forwarded_cells += 1;
                ProtocolAction::ForwardCell(circuit_id)
            }
            ProtocolEvent::ReplayRejected(_) => {
                self.cell_pipeline.state.rejected_replays += 1;
                ProtocolAction::DropCell
            }
        }
    }

    /// Return a snapshot of all runtime counters, aggregated from both the
    /// relay/circuit layer and the cell pipeline.
    pub fn state(&self) -> ProtocolRuntimeState {
        ProtocolRuntimeState {
            active_relays: self.state.active_relays,
            active_circuits: self.state.active_circuits,
            rejected_replays: self.cell_pipeline.state.rejected_replays,
            forwarded_cells: self.cell_pipeline.state.forwarded_cells,
            dropped_cells: self.cell_pipeline.state.dropped_cells,
        }
    }
}

impl Default for ProtocolRuntime {
    fn default() -> Self {
        Self::new()
    }
}
