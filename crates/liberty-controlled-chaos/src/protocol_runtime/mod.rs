//! ProtocolRuntime — orchestrates relay, circuit, and cell protocol state machines.
//!
//! Connects:
//!   RelayProtocol → CircuitExtension → OnionCellProtocol →
//!   ReplayProtection → OnionLayer → MeshRouter → UDPTransport
//!
//! No network I/O; no randomness; all state is caller-driven.

mod cell_pipeline;
mod circuit_runtime_adapter;
mod errors;
mod relay_runtime;
mod runtime;
mod types;

pub use cell_pipeline::CellPipeline;
pub use circuit_runtime_adapter::CircuitRuntimeAdapter;
pub use errors::ProtocolRuntimeError;
pub use relay_runtime::RelayRuntime;
pub use runtime::ProtocolRuntime;
pub use types::{ProtocolAction, ProtocolEvent, ProtocolRuntimeState};

// ── Tests ─────────────────────────────��───────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::circuit_builder::CircuitId;
    use crate::circuit_extension::CircuitExtensionState;
    use crate::onion_cell_protocol::{OnionCell, OnionCellType, encode_cell};
    use crate::relay_protocol::{RelayCapabilities, RelayDescriptor, RelayNodeId};
    use crate::udp_transport::PeerAddress;

    use super::*;

    // ── helpers ────────────────���──────────────────────────���───────────────────

    fn addr() -> PeerAddress {
        PeerAddress::new("127.0.0.1:9100".parse::<SocketAddr>().unwrap())
    }

    fn caps() -> RelayCapabilities {
        RelayCapabilities {
            supports_onion: true,
            supports_cover: true,
            supports_rotation: true,
            supports_fragmentation: true,
        }
    }

    fn descriptor(id: u64) -> RelayDescriptor {
        RelayDescriptor {
            relay_id: RelayNodeId(id),
            public_key: [0u8; 32],
            peer_address: addr(),
            reliability_score: 0.9,
            latency_estimate: 100,
            capabilities: caps(),
        }
    }

    fn valid_cell_bytes(circuit_id: u64) -> Vec<u8> {
        encode_cell(&OnionCell::new(
            CircuitId(circuit_id),
            OnionCellType::RelayData,
            vec![1, 2, 3, 4],
        ))
    }

    // ════════════════���══════════════════════════════���══════════════════════════
    // Phase 2 — RelayRuntime
    // ════════════════════════════════════��══════════════════════════���══════════

    // ── rr1: relay registration and state ────────────────────────────────────

    #[test]
    fn rr1_relay_registration() {
        let mut rr = RelayRuntime::new();
        rr.register_relay(descriptor(1)).unwrap();
        assert!(!rr.is_established(RelayNodeId(1)));
    }

    // ── rr2: full handshake progression ──────────────────────────────────────

    #[test]
    fn rr2_handshake_progression() {
        let mut rr = RelayRuntime::new();
        rr.register_relay(descriptor(2)).unwrap();
        rr.begin_handshake(RelayNodeId(2)).unwrap();
        rr.complete_handshake(RelayNodeId(2)).unwrap();
        assert!(rr.is_established(RelayNodeId(2)));
    }

    // ── rr3: duplicate relay registration rejected ─────────────────��──────────

    #[test]
    fn rr3_duplicate_relay_rejected() {
        let mut rr = RelayRuntime::new();
        rr.register_relay(descriptor(3)).unwrap();
        let err = rr.register_relay(descriptor(3)).unwrap_err();
        assert_eq!(err, ProtocolRuntimeError::InvalidState);
    }

    // ── rr4: complete_handshake without begin rejected ──────────────────��─────

    #[test]
    fn rr4_complete_without_begin_rejected() {
        let mut rr = RelayRuntime::new();
        rr.register_relay(descriptor(4)).unwrap();
        // Still in Init — complete_handshake requires Handshaking.
        let err = rr.complete_handshake(RelayNodeId(4)).unwrap_err();
        assert_eq!(err, ProtocolRuntimeError::InvalidState);
    }

    // ── rr5: close_relay ────────────────��─────────────────────────────────────

    #[test]
    fn rr5_close_relay() {
        let mut rr = RelayRuntime::new();
        rr.register_relay(descriptor(5)).unwrap();
        rr.begin_handshake(RelayNodeId(5)).unwrap();
        rr.complete_handshake(RelayNodeId(5)).unwrap();
        rr.close_relay(RelayNodeId(5)).unwrap();
        assert!(!rr.is_established(RelayNodeId(5)));
    }

    // ═══════════════════���══════════════════════════════════════════════════════
    // Phase 3 — CircuitRuntimeAdapter
    // ══════════════════════════════════���════════════════════════════���══════════

    // ── ca1: create circuit ────────────────────���──────────────────────────────

    #[test]
    fn ca1_create_circuit() {
        let mut ca = CircuitRuntimeAdapter::new();
        ca.create_circuit(CircuitId(10)).unwrap();
        assert_eq!(
            ca.get_state(CircuitId(10)),
            Some(CircuitExtensionState::Building)
        );
    }

    // ── ca2: extend circuit ─────────────────��─────────────────────────────────

    #[test]
    fn ca2_extend_circuit() {
        let mut ca = CircuitRuntimeAdapter::new();
        ca.create_circuit(CircuitId(11)).unwrap();
        ca.extend_circuit(CircuitId(11), RelayNodeId(100)).unwrap();
        assert_eq!(
            ca.get_state(CircuitId(11)),
            Some(CircuitExtensionState::Extending)
        );
        ca.complete_extension(CircuitId(11)).unwrap();
        assert_eq!(
            ca.get_state(CircuitId(11)),
            Some(CircuitExtensionState::Active)
        );
    }

    // ── ca3: destroy circuit ──────────────────────────────────────────────────

    #[test]
    fn ca3_destroy_circuit() {
        let mut ca = CircuitRuntimeAdapter::new();
        ca.create_circuit(CircuitId(12)).unwrap();
        ca.destroy_circuit(CircuitId(12)).unwrap();
        assert_eq!(
            ca.get_state(CircuitId(12)),
            Some(CircuitExtensionState::Destroyed)
        );
    }

    // ── ca4: duplicate circuit registration rejected ──────────────────────────

    #[test]
    fn ca4_duplicate_circuit_rejected() {
        let mut ca = CircuitRuntimeAdapter::new();
        ca.create_circuit(CircuitId(13)).unwrap();
        let err = ca.create_circuit(CircuitId(13)).unwrap_err();
        assert_eq!(err, ProtocolRuntimeError::InvalidState);
    }

    // ── ca5: extend rejected on destroyed circuit ─────────────────────────────

    #[test]
    fn ca5_extend_destroyed_rejected() {
        let mut ca = CircuitRuntimeAdapter::new();
        ca.create_circuit(CircuitId(14)).unwrap();
        ca.destroy_circuit(CircuitId(14)).unwrap();
        let err = ca
            .extend_circuit(CircuitId(14), RelayNodeId(200))
            .unwrap_err();
        assert_eq!(err, ProtocolRuntimeError::InvalidState);
    }

    // ════════════════════════════════════════════════════════���═════════════════
    // Phase 4 — CellPipeline
    // ══════════════════════════════════════════════════════════════════════════

    // ── cp1: decode valid cell ────────────────────────────────────────���───────

    #[test]
    fn cp1_decode_valid_cell() {
        let mut p = CellPipeline::new();
        let bytes = valid_cell_bytes(42);
        let action = p.process_incoming(&bytes).unwrap();
        assert_eq!(action, ProtocolAction::ForwardCell(CircuitId(42)));
        assert_eq!(p.state.forwarded_cells, 1);
    }

    // ── cp2: reject replay ───────────────────────────��────────────────────────

    #[test]
    fn cp2_reject_replay() {
        let mut p = CellPipeline::new();
        let bytes = valid_cell_bytes(43);
        p.process_incoming(&bytes).unwrap();
        let err = p.process_incoming(&bytes).unwrap_err();
        assert_eq!(err, ProtocolRuntimeError::ReplayDetected);
        assert_eq!(p.state.rejected_replays, 1);
    }

    // ── cp3: invalid cell rejected ───────────────────────��────────────────────

    #[test]
    fn cp3_invalid_cell_rejected() {
        let mut p = CellPipeline::new();
        let err = p.process_incoming(&[0u8; 5]).unwrap_err();
        assert_eq!(err, ProtocolRuntimeError::InvalidCell);
        assert_eq!(p.state.dropped_cells, 1);
    }

    // ── cp4: forward valid cell ─────────────────────────���─────────────────────

    #[test]
    fn cp4_forward_valid_cell() {
        let mut p = CellPipeline::new();
        let bytes = valid_cell_bytes(44);
        let action = p.process_incoming(&bytes).unwrap();
        assert!(matches!(action, ProtocolAction::ForwardCell(_)));
    }

    // ── cp5: process_outgoing encodes cell ──────────────────��─────────────────

    #[test]
    fn cp5_process_outgoing() {
        let mut p = CellPipeline::new();
        let cell = OnionCell::new(CircuitId(99), OnionCellType::Padding, vec![0u8; 8]);
        let action = p.process_outgoing(&cell).unwrap();
        assert!(matches!(action, ProtocolAction::SendCell(_)));
    }

    // ═══════════════════════════���══════════════════════════════════════════════
    // Phase 5 — ProtocolRuntime (orchestrator)
    // ══════════════════════════════════════════════════════════════════════════

    // ── pr1: relay connect event ────────────────────────��─────────────────────

    #[test]
    fn pr1_relay_connect_event() {
        let mut rt = ProtocolRuntime::new();
        let action = rt.handle_event(ProtocolEvent::RelayConnected(descriptor(50)));
        assert_eq!(action, ProtocolAction::NotifyRelay(RelayNodeId(50)));
        assert_eq!(rt.state().active_relays, 1);
    }

    // ── pr2: handshake complete event ─────────────────────────────────────────

    #[test]
    fn pr2_handshake_complete_event() {
        let mut rt = ProtocolRuntime::new();
        rt.handle_event(ProtocolEvent::RelayConnected(descriptor(51)));
        let action = rt.handle_event(ProtocolEvent::RelayHandshakeComplete(RelayNodeId(51)));
        assert_eq!(action, ProtocolAction::NotifyRelay(RelayNodeId(51)));
    }

    // ── pr3: circuit create event ─────────────────────────────────────────────

    #[test]
    fn pr3_circuit_create_event() {
        let mut rt = ProtocolRuntime::new();
        let action = rt.handle_event(ProtocolEvent::CircuitCreated(CircuitId(200)));
        assert_eq!(action, ProtocolAction::NoAction);
        assert_eq!(rt.state().active_circuits, 1);
    }

    // ── pr4: circuit destroy event ────────────────────────────────────────────

    #[test]
    fn pr4_circuit_destroy_event() {
        let mut rt = ProtocolRuntime::new();
        rt.handle_event(ProtocolEvent::CircuitCreated(CircuitId(201)));
        let action = rt.handle_event(ProtocolEvent::CircuitDestroyed(CircuitId(201)));
        assert_eq!(action, ProtocolAction::DestroyCircuit(CircuitId(201)));
        assert_eq!(rt.state().active_circuits, 0);
    }

    // ── pr5: cell received event ────────────────────────���─────────────────────

    #[test]
    fn pr5_cell_received_event() {
        let mut rt = ProtocolRuntime::new();
        let bytes = valid_cell_bytes(300);
        let action = rt.handle_event(ProtocolEvent::CellReceived(bytes));
        assert_eq!(action, ProtocolAction::ForwardCell(CircuitId(300)));
    }

    // ── pr6: replay cell is dropped ───────────────────────────────────────────

    #[test]
    fn pr6_replay_cell_dropped() {
        let mut rt = ProtocolRuntime::new();
        let bytes = valid_cell_bytes(301);
        rt.handle_event(ProtocolEvent::CellReceived(bytes.clone()));
        let action = rt.handle_event(ProtocolEvent::CellReceived(bytes));
        assert_eq!(action, ProtocolAction::DropCell);
    }

    // ── pr7: state counters update ────────────────────────────────────────────

    #[test]
    fn pr7_state_counters_update() {
        let mut rt = ProtocolRuntime::new();
        // Add relay and circuit.
        rt.handle_event(ProtocolEvent::RelayConnected(descriptor(60)));
        rt.handle_event(ProtocolEvent::CircuitCreated(CircuitId(400)));
        // Forward one valid cell, replay one.
        let bytes = valid_cell_bytes(400);
        rt.handle_event(ProtocolEvent::CellReceived(bytes.clone()));
        rt.handle_event(ProtocolEvent::CellReceived(bytes));
        // Drop one invalid cell.
        rt.handle_event(ProtocolEvent::CellReceived(vec![0u8; 3]));

        let s = rt.state();
        assert_eq!(s.active_relays, 1);
        assert_eq!(s.active_circuits, 1);
        assert_eq!(s.forwarded_cells, 1);
        assert_eq!(s.rejected_replays, 1);
        assert_eq!(s.dropped_cells, 1);
    }

    // ── pr8: event routing — extended circuit ───────────────���─────────────────

    #[test]
    fn pr8_circuit_extended_event() {
        let mut rt = ProtocolRuntime::new();
        rt.handle_event(ProtocolEvent::CircuitCreated(CircuitId(500)));
        let action = rt.handle_event(ProtocolEvent::CircuitExtended(
            CircuitId(500),
            RelayNodeId(70),
        ));
        assert_eq!(action, ProtocolAction::NoAction);
    }
}
