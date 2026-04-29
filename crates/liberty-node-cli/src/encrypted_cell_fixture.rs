// NON-PRODUCTION: deterministic fixture builder for EncryptedCell values.
// Used only for the loopback UDP testnet. Keys are derived from numeric seeds,
// not from a real Noise handshake.

use std::collections::HashSet;

use liberty_controlled_chaos::cell_encoder::{CellEncoder, MAX_PAYLOAD};
use liberty_controlled_chaos::noise_link::{EncryptedCell, NoiseLinkEncoder, NoiseSession};
use liberty_controlled_chaos::runtime_boundary::{
    ControlledChaosOutput, KillSwitchState, PacketClass, PayloadRef, RuntimeBoundaryValidator,
    RuntimePacketIntent, RuntimeValidationResult, ShadowBudgetTracker, TunnelState,
};
use liberty_controlled_chaos::stream_mux::{StreamFrame, StreamMux};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptedCellFixtureError {
    PayloadTooLarge,
    FrameBuildFailed,
    EncodeFailed,
}

/// Expand an 8-byte seed to a 32-byte key by repeating the LE bytes four times.
/// NON-PRODUCTION: not a secure KDF.
pub fn seed_to_key(seed: u64) -> [u8; 32] {
    let bytes = seed.to_le_bytes();
    let mut key = [0u8; 32];
    for chunk in key.chunks_mut(8) {
        chunk.copy_from_slice(&bytes);
    }
    key
}

/// Build a validated `RuntimePacketIntent` with the given payload length.
/// Uses path_id=1, flow_id=1, fragment_id=1, deadline=u64::MAX.
pub fn make_runtime_intent(payload_len: usize) -> RuntimePacketIntent {
    let mut paths = HashSet::new();
    paths.insert(1u64);
    let v = RuntimeBoundaryValidator::new(KillSwitchState::Inactive, TunnelState::TunnelUp, paths);
    let mut budget = ShadowBudgetTracker::new(1_000_000);
    // PayloadRef requires length in [64, 1500]; use a valid dummy length.
    let ref_len = if payload_len < 64 {
        64u16
    } else {
        payload_len as u16
    };
    let out = ControlledChaosOutput {
        path_id: 1,
        flow_id: 1,
        fragment_id: 1,
        scheduled_send_time: 0,
        shadow_flag: false,
        packet_class: PacketClass::Real,
        latency_deadline: u64::MAX,
        payload_ref: PayloadRef::new(0, ref_len).unwrap(),
    };
    match v.validate(out, 0, &mut budget) {
        RuntimeValidationResult::Accept(i) => i,
        RuntimeValidationResult::Reject(r) => panic!("fixture intent rejected: {r:?}"),
    }
}

/// Build a `StreamFrame` suitable for use with `CellEncoder`.
pub fn make_stream_frame(payload_len: usize) -> StreamFrame {
    let intent = make_runtime_intent(payload_len);
    let mut mux = StreamMux::with_defaults();
    mux.submit(intent, 0).unwrap();
    let (mut frames, _) = mux.drain_ready(u64::MAX);
    frames.remove(0)
}

/// Encode `payload` into a fixed-size `Cell` using a deterministic `CellEncoder`.
/// `cell_seed` controls the PRNG used for padding.
pub fn make_cell(
    payload: &[u8],
    cell_seed: u64,
) -> Result<liberty_controlled_chaos::cell_encoder::Cell, EncryptedCellFixtureError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(EncryptedCellFixtureError::PayloadTooLarge);
    }
    let frame = make_stream_frame(payload.len());
    let mut encoder = CellEncoder::new(cell_seed);
    encoder
        .encode(frame, payload)
        .map_err(|_| EncryptedCellFixtureError::EncodeFailed)
}

/// Build a deterministic `NoiseSession` from a seed.
/// NON-PRODUCTION: send_key == recv_key, both derived from seed.
pub fn make_noise_session(seed: u64) -> NoiseSession {
    let key = seed_to_key(seed);
    NoiseSession::new(key, key)
}

/// Build a fully encrypted `EncryptedCell` from raw payload bytes and a seed.
/// `seed` controls both the cell encoder padding and the session keys.
pub fn make_encrypted_cell(
    payload: &[u8],
    seed: u64,
) -> Result<EncryptedCell, EncryptedCellFixtureError> {
    let cell = make_cell(payload, seed)?;
    let session = make_noise_session(seed);
    let mut encoder = NoiseLinkEncoder::new(session);
    Ok(encoder.encode(cell))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypted_udp_packet::{ENCRYPTED_UDP_HEADER_SIZE, encrypted_cell_to_bytes};
    use liberty_controlled_chaos::noise_link::ENCRYPTED_CELL_SIZE;

    // EF1: same payload + seed gives deterministic encrypted cell
    #[test]
    fn ef1_deterministic_encrypted_cell() {
        let payload = b"hello liberty";
        let cell_a = make_encrypted_cell(payload, 0xABCD).unwrap();
        let cell_b = make_encrypted_cell(payload, 0xABCD).unwrap();
        assert_eq!(cell_a.nonce, cell_b.nonce);
        assert_eq!(cell_a.ciphertext, cell_b.ciphertext);
        assert_eq!(cell_a.auth_tag, cell_b.auth_tag);
    }

    // EF2: different seed gives different encrypted cell
    #[test]
    fn ef2_different_seed_different_cell() {
        let payload = b"hello liberty";
        let cell_a = make_encrypted_cell(payload, 0x1111).unwrap();
        let cell_b = make_encrypted_cell(payload, 0x2222).unwrap();
        assert_ne!(
            cell_a.ciphertext, cell_b.ciphertext,
            "different seeds must yield different ciphertext"
        );
    }

    // EF3: oversized payload rejected
    #[test]
    fn ef3_oversized_payload_rejected() {
        let oversized = vec![0u8; MAX_PAYLOAD + 1];
        assert_eq!(
            make_encrypted_cell(&oversized, 42).unwrap_err(),
            EncryptedCellFixtureError::PayloadTooLarge
        );
    }

    // EF4: serialized encrypted cell has exactly ENCRYPTED_CELL_SIZE bytes
    #[test]
    fn ef4_encrypted_cell_byte_length() {
        let cell = make_encrypted_cell(b"test", 1).unwrap();
        let bytes = encrypted_cell_to_bytes(&cell);
        assert_eq!(
            bytes.len(),
            ENCRYPTED_CELL_SIZE,
            "serialized EncryptedCell must be exactly {ENCRYPTED_CELL_SIZE} bytes"
        );
        // Confirm the header size is different from the total payload
        assert!(ENCRYPTED_CELL_SIZE > ENCRYPTED_UDP_HEADER_SIZE);
    }

    // EF5: empty payload is supported
    #[test]
    fn ef5_empty_payload_supported() {
        let cell = make_encrypted_cell(&[], 99).unwrap();
        let bytes = encrypted_cell_to_bytes(&cell);
        assert_eq!(bytes.len(), ENCRYPTED_CELL_SIZE);
    }
}
