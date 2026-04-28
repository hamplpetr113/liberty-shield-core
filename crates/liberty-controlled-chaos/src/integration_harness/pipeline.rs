use std::collections::HashSet;

use crate::cell_encoder::{Cell, CellEncoder};
use crate::noise_link::{EncryptedCell, NoiseLinkEncoder, NoiseSession};
use crate::onion_layer::{LayerEncryptor, OnionLayerKey, OnionPacket};
use crate::runtime_boundary::{
    ControlledChaosOutput, KillSwitchState, PacketClass, PayloadRef, RuntimeBoundaryValidator,
    RuntimeValidationResult, ShadowBudgetTracker, TunnelState,
};
use crate::stream_mux::{StreamFrame, StreamMux};

/// Build a `StreamFrame` by routing a `ControlledChaosOutput` through the
/// `RuntimeBoundaryValidator → StreamMux` pipeline.
///
/// Mirrors the test helper in `cell_encoder` — the only way to obtain a
/// `StreamFrame` is through validation (since `StreamId` is opaque outside
/// `stream_mux`).
pub fn make_stream_frame(flow_id: u64, fragment_id: u64, payload_len: u16) -> StreamFrame {
    let mut paths = HashSet::new();
    paths.insert(1u64);
    let v = RuntimeBoundaryValidator::new(KillSwitchState::Inactive, TunnelState::TunnelUp, paths);
    let mut budget = ShadowBudgetTracker::new(1_000_000);
    let out = ControlledChaosOutput {
        path_id: 1,
        flow_id,
        fragment_id,
        scheduled_send_time: 0,
        shadow_flag: false,
        packet_class: PacketClass::Real,
        latency_deadline: u64::MAX,
        payload_ref: PayloadRef::new(fragment_id as u32 % 1_000_000, payload_len).unwrap(),
    };
    let intent = match v.validate(out, 0, &mut budget) {
        RuntimeValidationResult::Accept(i) => i,
        RuntimeValidationResult::Reject(r) => panic!("validation rejected: {r:?}"),
    };
    let mut mux = StreamMux::with_defaults();
    mux.submit(intent, 0).unwrap();
    let (mut frames, _) = mux.drain_ready(u64::MAX);
    frames.remove(0)
}

/// Encode a `StreamFrame` into a fixed-size `Cell` using a deterministic seed encoder.
pub fn encode_to_cell(frame: StreamFrame, payload: &[u8]) -> Cell {
    let mut enc = CellEncoder::new(0xdead_beef_cafe_1234);
    enc.encode(frame, payload).expect("encode_to_cell failed")
}

/// Encrypt a `Cell` into an `EncryptedCell` using the supplied session.
pub fn encrypt_cell(cell: Cell, session: NoiseSession) -> EncryptedCell {
    let mut enc = NoiseLinkEncoder::new(session);
    enc.encode(cell)
}

/// Wrap an `EncryptedCell` in N onion layers.
pub fn wrap_onion(enc: &EncryptedCell, keys: &[OnionLayerKey]) -> OnionPacket {
    LayerEncryptor::wrap(enc, keys).expect("wrap_onion failed")
}
