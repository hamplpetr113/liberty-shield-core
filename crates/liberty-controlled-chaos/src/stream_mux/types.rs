//! Public types for the StreamMux layer.

use crate::runtime_boundary::{PacketClass, PayloadRef};

// ── StreamId ──────────────────────────────────────────────────────────────────

/// Stable identifier for a (flow_id, path_id, stream_class) triple.
/// Derived deterministically via SipHash-1-3 over the triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamId(pub(super) u64);

impl StreamId {
    pub fn raw(self) -> u64 {
        self.0
    }
}

// ── StreamFrameKind ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamFrameKind {
    Data,
    BurstHead,
    Cover,
    StreamReset,
}

// ── StreamFrame ───────────────────────────────────────────────────────────────

/// The output unit of StreamMux; the input unit of CellEncoder.
/// Contains only metadata and an opaque PayloadRef — no plaintext bytes.
/// `payload_ref` is `None` only for `StreamReset` frames.
#[derive(Debug, Clone)]
pub struct StreamFrame {
    pub stream_id: StreamId,
    pub sequence_number: u64,
    pub path_id: u64,
    pub packet_class: PacketClass,
    pub payload_ref: Option<PayloadRef>,
    pub deadline_us: u64,
    pub frame_kind: StreamFrameKind,
    pub fragment_id: u64,
}

// ── StreamMuxError ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum StreamMuxError {
    /// No stream exists for the given path and one cannot be created.
    InvalidStream { path_id: u64 },
    /// Real queue reached the hard depth limit; caller must decide to drop or back-pressure.
    RealQueueFull { stream_id: StreamId },
    /// A real frame missed its latency deadline at dequeue time.
    DeadlineMissed {
        stream_id: StreamId,
        late_by_us: u64,
    },
    /// A stream was reset; drained real frames are returned for the caller to surface.
    StreamReset {
        stream_id: StreamId,
        drained_real_frames: Vec<StreamFrame>,
    },
    /// Two intents with the same fragment_id arrived on the same stream.
    DuplicateFragment {
        stream_id: StreamId,
        fragment_id: u64,
    },
    /// stream_id hash space exhausted after 3 collision-resolution attempts.
    StreamIdExhausted,
}

// ── StreamMuxStats ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct StreamMuxStats {
    pub active_stream_count: usize,
    pub real_frames_enqueued: u64,
    pub shadow_frames_evicted: u64,
    pub real_frames_expired: u64,
    pub shadow_frames_expired: u64,
    /// Advisory counter: times the real queue exceeded the warning threshold.
    /// Never causes a frame rejection; increment only.
    pub real_queue_pressure_events: u64,
}
