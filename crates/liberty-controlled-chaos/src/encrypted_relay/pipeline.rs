//! Relay processing pipeline: decrypt → replay-check → forward.
//!
//! `RelayPipeline` combines `EncryptedRelayCell` decryption with per-circuit
//! replay detection.  It operates entirely in-process with no I/O.

use std::collections::HashMap;

use crate::crypto::SessionKeys;
use crate::replay_protection::{CellNonce, ReplayDetector, ReplayError};
use crate::transport::TransportReplayFilter;

use super::cell::EncryptedRelayCell;
use super::errors::EncryptedRelayError;
use super::types::RelayCellPlaintext;

/// Default capacity of the per-circuit `TransportReplayFilter`.
const TRANSPORT_FILTER_CAPACITY: usize = 512;

/// Decision returned after processing one cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineResult {
    /// Cell was decrypted and accepted; carries the plaintext.
    Accepted(RelayCellPlaintext),
    /// Cell was rejected as a replay.
    ReplayRejected,
    /// Cell was rejected due to authentication failure.
    AuthFailed,
    /// No session registered for this circuit.
    NoSession,
}

/// Combines session key management and replay detection for multiple circuits.
pub struct RelayPipeline {
    /// Per-circuit receive sessions (keyed by circuit_id).
    recv_sessions: HashMap<u64, SessionKeys>,
    /// Per-circuit send sessions.
    send_sessions: HashMap<u64, SessionKeys>,
    /// Sliding-window replay detector.
    replay: ReplayDetector,
    /// Per-circuit transport-layer LRU replay filter (fast first-pass check).
    transport_filters: HashMap<u64, TransportReplayFilter>,
}

impl RelayPipeline {
    pub fn new() -> Self {
        Self {
            recv_sessions: HashMap::new(),
            send_sessions: HashMap::new(),
            replay: ReplayDetector::new(),
            transport_filters: HashMap::new(),
        }
    }

    /// Register send and receive sessions for a circuit.
    pub fn register_circuit(
        &mut self,
        circuit_id: u64,
        send_session: SessionKeys,
        recv_session: SessionKeys,
    ) {
        self.send_sessions.insert(circuit_id, send_session);
        self.recv_sessions.insert(circuit_id, recv_session);
        self.replay
            .register_circuit(crate::circuit_builder::CircuitId(circuit_id));
        self.transport_filters.insert(
            circuit_id,
            TransportReplayFilter::new(TRANSPORT_FILTER_CAPACITY),
        );
    }

    /// Remove all state for a circuit.
    pub fn remove_circuit(&mut self, circuit_id: u64) {
        self.send_sessions.remove(&circuit_id);
        self.recv_sessions.remove(&circuit_id);
        self.replay
            .remove_circuit(crate::circuit_builder::CircuitId(circuit_id));
        self.transport_filters.remove(&circuit_id);
    }

    /// Encrypt a plaintext cell on the send path.
    pub fn send_cell(
        &mut self,
        circuit_id: u64,
        stream_id: u64,
        plaintext: RelayCellPlaintext,
    ) -> Result<EncryptedRelayCell, EncryptedRelayError> {
        let session = self
            .send_sessions
            .get_mut(&circuit_id)
            .ok_or(EncryptedRelayError::AuthenticationFailed)?;
        let _ = stream_id; // used via AAD inside seal
        EncryptedRelayCell::seal(session, &plaintext)
    }

    /// Process an incoming encrypted cell: replay-check then decrypt.
    pub fn receive_cell(
        &mut self,
        circuit_id: u64,
        stream_id: u64,
        enc: &EncryptedRelayCell,
    ) -> PipelineResult {
        // Transport-layer LRU filter: fast first-pass duplicate check.
        if let Some(filter) = self.transport_filters.get_mut(&circuit_id)
            && !filter.check_and_record(enc.sequence)
        {
            return PipelineResult::ReplayRejected;
        }

        // Sequence-window replay check (before decryption — fail fast).
        let cid = crate::circuit_builder::CircuitId(circuit_id);
        match self.replay.check_cell(cid, CellNonce(enc.sequence)) {
            Err(ReplayError::DuplicateNonce) | Err(ReplayError::WindowExpired) => {
                return PipelineResult::ReplayRejected;
            }
            Ok(()) => {}
        }

        // Decrypt.
        let session = match self.recv_sessions.get(&circuit_id) {
            Some(s) => s,
            None => return PipelineResult::NoSession,
        };
        match enc.open(session, circuit_id, stream_id) {
            Ok(plain) => PipelineResult::Accepted(plain),
            Err(_) => PipelineResult::AuthFailed,
        }
    }
}

impl Default for RelayPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::RelayCellCommand;
    use super::*;
    use crate::crypto::SessionKeys;

    fn make_pipeline() -> RelayPipeline {
        let mut p = RelayPipeline::new();
        let send = SessionKeys::new([0x11u8; 32], [0x11u8; 32]);
        let recv = SessionKeys::new([0x11u8; 32], [0x11u8; 32]);
        p.register_circuit(1, send, recv);
        p
    }

    fn data_cell(seq: u64) -> RelayCellPlaintext {
        RelayCellPlaintext::new(1, 2, RelayCellCommand::Data, seq, b"payload".to_vec())
    }

    // RP1: send → receive roundtrip
    #[test]
    fn rp1_send_receive_roundtrip() {
        let mut p = make_pipeline();
        let pt = data_cell(0);
        let enc = p.send_cell(1, 2, pt.clone()).unwrap();
        match p.receive_cell(1, 2, &enc) {
            PipelineResult::Accepted(dec) => assert_eq!(dec, pt),
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    // RP2: replay of the same cell is rejected
    #[test]
    fn rp2_replay_rejected() {
        let mut p = make_pipeline();
        let enc = p.send_cell(1, 2, data_cell(0)).unwrap();
        p.receive_cell(1, 2, &enc); // first accept
        assert_eq!(p.receive_cell(1, 2, &enc), PipelineResult::ReplayRejected);
    }

    // RP3: tampered cell → auth failure (after replay window records the nonce)
    #[test]
    fn rp3_auth_failure_on_tamper() {
        let mut p = make_pipeline();
        let mut enc = p.send_cell(1, 2, data_cell(0)).unwrap();
        enc.ciphertext_and_tag[0] ^= 0xFF;
        // Replay window accepts the nonce (first time), then auth fails.
        let result = p.receive_cell(1, 2, &enc);
        assert!(
            matches!(
                result,
                PipelineResult::AuthFailed | PipelineResult::ReplayRejected
            ),
            "expected auth failure or replay, got {result:?}"
        );
    }

    // RP4: no session registered
    #[test]
    fn rp4_no_session() {
        let mut p = RelayPipeline::new();
        // Build an encrypted cell with a separate pipeline
        let mut other = make_pipeline();
        let enc = other.send_cell(1, 2, data_cell(0)).unwrap();
        // p has no circuit 1 registered
        assert_eq!(p.receive_cell(1, 2, &enc), PipelineResult::NoSession);
    }

    // RP5: sequential cells all accepted
    #[test]
    fn rp5_sequential_cells_accepted() {
        let mut p = make_pipeline();
        for seq in 0u64..10 {
            let enc = p.send_cell(1, 2, data_cell(seq)).unwrap();
            assert!(matches!(
                p.receive_cell(1, 2, &enc),
                PipelineResult::Accepted(_)
            ));
        }
    }

    // RP6: remove circuit clears state
    #[test]
    fn rp6_remove_circuit() {
        let mut p = make_pipeline();
        let enc = p.send_cell(1, 2, data_cell(0)).unwrap();
        p.receive_cell(1, 2, &enc);
        p.remove_circuit(1);
        // After removal, no session is registered
        let enc2 = {
            let mut other = make_pipeline();
            other.send_cell(1, 2, data_cell(1)).unwrap()
        };
        assert_eq!(p.receive_cell(1, 2, &enc2), PipelineResult::NoSession);
    }
}
