//! StreamMux — sequencing, queueing, and stream-identity layer.
//!
//! Sits between `RuntimeBoundaryValidator` and `CellEncoder`.
//! Accepts `RuntimePacketIntent` values (proof tokens) and emits `StreamFrame`
//! values with stable stream identities, monotonic sequence numbers, and
//! priority-separated queues (real before shadow/cover).

mod mux;
mod queues;
pub mod types;

pub use mux::StreamMux;
pub use types::{StreamFrame, StreamFrameKind, StreamId, StreamMuxError, StreamMuxStats};
