use crate::cell_encoder::CELL_SIZE;
use crate::noise_link::{ENCRYPTED_CELL_SIZE, EncryptedCell};

/// A simulated circuit: an ordered list of node IDs (guard → relay… → exit).
#[derive(Debug, Clone)]
pub struct SimCircuit {
    pub circuit_id: u64,
    /// Ordered node IDs traversed by this circuit.
    pub route: Vec<u64>,
}

impl SimCircuit {
    pub fn new(circuit_id: u64, route: Vec<u64>) -> Self {
        Self { circuit_id, route }
    }

    pub fn hop_count(&self) -> usize {
        self.route.len()
    }
}

/// Why a packet was rejected at a hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowRejection {
    ReplayDetected,
    ReplayWindowExpired,
    NodeNotFound,
}

/// Result of processing one hop.
#[derive(Debug, Clone)]
pub struct HopResult {
    pub node_id: u64,
    pub accepted: bool,
    pub rejection: Option<FlowRejection>,
}

/// Result of sending one packet across a full circuit.
#[derive(Debug)]
pub struct PacketFlowResult {
    /// Circuit the packet was sent on.
    pub circuit_id: u64,
    /// Per-hop outcomes, in traversal order.
    pub hops: Vec<HopResult>,
    /// `true` iff every hop accepted the packet.
    pub delivered: bool,
    /// Wire size of every simulated packet (always `ENCRYPTED_CELL_SIZE`).
    pub packet_size_bytes: usize,
}

/// Stateless factory for simulated `EncryptedCell` values.
///
/// Every packet is a fixed-size `EncryptedCell` (1482 bytes on the wire).
/// The payload is written into the ciphertext field; remaining bytes are zero.
pub struct PacketFlowEngine;

impl PacketFlowEngine {
    /// Build a fixed-size `EncryptedCell` for simulation.
    ///
    /// `circuit_id` is stored in `path_id` so it can be recovered at any hop.
    /// `nonce` is the per-packet sequence number used for replay detection.
    /// `payload` is copied verbatim into the start of the ciphertext; remainder is zeroed.
    pub fn make_cell(circuit_id: u64, nonce: u64, payload: &[u8]) -> EncryptedCell {
        let mut ciphertext = [0u8; CELL_SIZE];
        let copy_len = payload.len().min(CELL_SIZE);
        ciphertext[..copy_len].copy_from_slice(&payload[..copy_len]);
        EncryptedCell {
            path_id: circuit_id,
            nonce,
            ciphertext,
            auth_tag: derive_sim_tag(circuit_id, nonce),
        }
    }

    /// Constant wire size of every simulated packet.
    pub fn packet_size() -> usize {
        ENCRYPTED_CELL_SIZE
    }
}

/// Deterministic authentication tag for simulation cells (not cryptographically secure).
fn derive_sim_tag(circuit_id: u64, nonce: u64) -> [u8; 16] {
    let mut tag = [0u8; 16];
    tag[0..8].copy_from_slice(&circuit_id.to_le_bytes());
    tag[8..16].copy_from_slice(&nonce.to_le_bytes());
    tag
}
