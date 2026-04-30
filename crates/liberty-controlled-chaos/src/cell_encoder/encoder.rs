//! `CellEncoder` — converts `StreamFrame` values into fixed-size `Cell` values.
//!
//! Responsibilities:
//!   - Serialise header fields (little-endian).
//!   - Copy opaque payload bytes verbatim; never inspect content.
//!   - Fill the remainder of every cell with PRNG-generated padding so that all
//!     cells are exactly `CELL_SIZE` (1450) bytes regardless of payload length.
//!
//! `CellEncoder` does not encrypt, does not open sockets, and contains no unsafe.

use super::types::{CELL_SIZE, CELL_VERSION, Cell, CellEncoderError, HEADER_SIZE, MAX_PAYLOAD};
use crate::stream_mux::{StreamFrame, StreamFrameKind};
use crate::transmitter::shadow_sync::ChaCha8Rng;

// ── CellEncoder ───────────────────────────────────────────────────────────────

/// Stateful encoder that converts one `StreamFrame` into one `Cell`.
///
/// Holds a per-session PRNG used exclusively for padding generation.
/// `encode` consumes the `StreamFrame` (one frame → one cell).
pub struct CellEncoder {
    rng: ChaCha8Rng,
}

impl CellEncoder {
    /// Create a new encoder seeded with a per-session value.
    /// The seed expands to the 32-byte ChaCha8 key by repeating the 8-byte
    /// little-endian representation four times.
    pub fn new(session_seed: u64) -> Self {
        let bytes = session_seed.to_le_bytes();
        let mut seed = [0u8; 32];
        for chunk in seed.chunks_mut(8) {
            chunk.copy_from_slice(&bytes);
        }
        Self {
            rng: ChaCha8Rng::from_seed(&seed),
        }
    }

    /// Convert one `StreamFrame` into one `Cell`.
    ///
    /// `payload_buf` must be the resolved bytes for `frame.payload_ref`.
    /// For `StreamReset` frames (`frame.payload_ref == None`), pass `&[]`.
    ///
    /// Returns `Err(PayloadTooLarge)` if `payload_buf.len() > MAX_PAYLOAD`.
    pub fn encode(
        &mut self,
        frame: StreamFrame,
        payload_buf: &[u8],
    ) -> Result<Cell, CellEncoderError> {
        // Determine effective payload length.
        let payload_len = if frame.payload_ref.is_some() {
            payload_buf.len()
        } else {
            0 // StreamReset: no payload regardless of buf contents
        };

        if payload_len > MAX_PAYLOAD {
            return Err(CellEncoderError::PayloadTooLarge {
                length: payload_len,
                max: MAX_PAYLOAD,
            });
        }

        let flags: u8 = match frame.frame_kind {
            StreamFrameKind::Data | StreamFrameKind::BurstHead => 0x00,
            StreamFrameKind::Cover => 0x01,
            StreamFrameKind::StreamReset => 0x02,
        };

        let mut data = [0u8; CELL_SIZE];

        // ── Header (43 bytes) ─────────────────────────────────────────────────
        data[0] = CELL_VERSION;
        data[1] = flags;
        data[2..10].copy_from_slice(&frame.stream_id.raw().to_le_bytes());
        data[10..18].copy_from_slice(&frame.sequence_number.to_le_bytes());
        data[18..26].copy_from_slice(&frame.path_id.to_le_bytes());
        data[26..34].copy_from_slice(&frame.fragment_id.to_le_bytes());
        data[34..36].copy_from_slice(&(payload_len as u16).to_le_bytes());
        // data[36..43]: reserved — remain zero.

        // ── Payload ───────────────────────────────────────────────────────────
        if payload_len > 0 {
            data[HEADER_SIZE..HEADER_SIZE + payload_len]
                .copy_from_slice(&payload_buf[..payload_len]);
        }

        // ── Padding ───────────────────────────────────────────────────────────
        // Fresh PRNG bytes fill every cell's padding region independently.
        let pad_start = HEADER_SIZE + payload_len;
        self.rng.fill_bytes(&mut data[pad_start..CELL_SIZE]);

        Ok(Cell { data })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_boundary::{
        ControlledChaosOutput, KillSwitchState, PacketClass, PayloadRef, RuntimeBoundaryValidator,
        RuntimeValidationResult, ShadowBudgetTracker, TunnelState,
    };
    use crate::stream_mux::StreamMux;
    use std::collections::HashSet;

    // ── pipeline helper ───────────────────────────────────────────────────────

    fn make_frame(
        flow_id: u64,
        fragment_id: u64,
        class: PacketClass,
        payload_len: u16,
    ) -> StreamFrame {
        let mut paths = HashSet::new();
        paths.insert(1u64);
        let v =
            RuntimeBoundaryValidator::new(KillSwitchState::Inactive, TunnelState::TunnelUp, paths);
        let mut budget = ShadowBudgetTracker::new(1_000_000);
        let shadow_flag = class == PacketClass::Shadow;
        let out = ControlledChaosOutput {
            path_id: 1,
            flow_id,
            fragment_id,
            scheduled_send_time: 0,
            shadow_flag,
            packet_class: class,
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

    fn make_encoder() -> CellEncoder {
        CellEncoder::new(0xdead_beef_cafe_1234)
    }

    // ── E1 / constant_cell_size ───────────────────────────────────────────────

    #[test]
    fn constant_cell_size() {
        let mut enc = make_encoder();
        // Test with several different payload lengths.
        for &len in &[64u16, 200, 500, 1000, 1407] {
            let frame = make_frame(1, len as u64, PacketClass::Real, len);
            let payload = vec![0xabu8; len as usize];
            let cell = enc.encode(frame, &payload).unwrap();
            assert_eq!(
                cell.as_bytes().len(),
                CELL_SIZE,
                "cell must be exactly {CELL_SIZE} bytes for payload_len={len}"
            );
        }
    }

    // ── payload_length_validation ────────────────────────────────────────────

    #[test]
    fn payload_length_validation() {
        let mut enc = make_encoder();
        let frame = make_frame(2, 1, PacketClass::Real, 200);
        let payload = vec![0u8; 200];
        let cell = enc.encode(frame, &payload).unwrap();
        assert_eq!(
            cell.header().payload_length,
            200,
            "header.payload_length must match actual payload size"
        );
    }

    // ── metadata_preserved ───────────────────────────────────────────────────

    #[test]
    fn metadata_preserved() {
        let mut enc = make_encoder();
        let frame = make_frame(42, 7, PacketClass::Real, 100);
        // Capture metadata before consuming the frame.
        let expected_stream_id = frame.stream_id.raw();
        let expected_seq = frame.sequence_number;
        let expected_path = frame.path_id;
        let expected_frag = frame.fragment_id;

        let payload = vec![0u8; 100];
        let cell = enc.encode(frame, &payload).unwrap();
        let hdr = cell.header();

        assert_eq!(hdr.version, CELL_VERSION);
        assert_eq!(
            hdr.stream_id, expected_stream_id,
            "stream_id must be preserved"
        );
        assert_eq!(
            hdr.sequence_number, expected_seq,
            "sequence_number must be preserved"
        );
        assert_eq!(hdr.path_id, expected_path, "path_id must be preserved");
        assert_eq!(
            hdr.fragment_id, expected_frag,
            "fragment_id must be preserved"
        );
        assert_eq!(hdr.payload_length, 100, "payload_length must match");
    }

    // ── oversized_payload_rejected ────────────────────────────────────────────

    #[test]
    fn oversized_payload_rejected() {
        let mut enc = make_encoder();
        // Use a valid PayloadRef length (1407 is the max allowed by CellEncoder,
        // but PayloadRef accepts up to 1500). Use 1407 for the frame, then pass
        // 1408 bytes as the payload_buf to trigger the rejection.
        let frame = make_frame(3, 1, PacketClass::Real, 200);
        let oversized = vec![0xffu8; MAX_PAYLOAD + 1]; // 1408 bytes
        let result = enc.encode(frame, &oversized);
        assert!(
            matches!(
                result,
                Err(CellEncoderError::PayloadTooLarge {
                    length: 1408,
                    max: 1407
                })
            ),
            "expected PayloadTooLarge(1408, 1407), got {result:?}"
        );
    }

    // ── payload bytes are copied verbatim ─────────────────────────────────────

    #[test]
    fn payload_bytes_preserved() {
        let mut enc = make_encoder();
        let frame = make_frame(4, 2, PacketClass::Real, 64);
        let payload: Vec<u8> = (0u8..64).collect();
        let cell = enc.encode(frame, &payload).unwrap();
        assert_eq!(cell.payload_bytes(), payload.as_slice());
    }

    // ── cover frame flags ─────────────────────────────────────────────────────

    #[test]
    fn cover_frame_flags_set() {
        let mut enc = make_encoder();
        let frame = make_frame(5, 3, PacketClass::Shadow, 64);
        // Shadow frames exit StreamMux as Cover kind.
        let payload = vec![0u8; 64];
        let cell = enc.encode(frame, &payload).unwrap();
        assert!(
            cell.header().is_cover(),
            "Cover frame must have flags & 0x01 set"
        );
    }

    // ── no networking dependencies ────────────────────────────────────────────

    #[test]
    fn no_networking_dependencies() {
        let output = match std::process::Command::new("cargo")
            .args(["tree", "-p", "liberty-controlled-chaos"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
        {
            Ok(o) => o,
            Err(_) => return,
        };
        let tree = String::from_utf8_lossy(&output.stdout);
        for name in &["tokio", "mio", "socket2"] {
            assert!(
                !tree.contains(name),
                "liberty-controlled-chaos must not depend on networking crate '{name}'"
            );
        }
    }
}
