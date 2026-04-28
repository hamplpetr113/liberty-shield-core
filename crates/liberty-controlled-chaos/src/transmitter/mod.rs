//! Transmitter / ShadowSync Layer — Sprint 6 Phase 3.
//!
//! Sub-modules added progressively each phase-3 step:
//!   types      — shared public types
//!   dispatcher — deterministic path assignment (SipHash-1-3)
//!   timing     — per-path TokenBucket
//!   queue      — per-path priority FragmentQueue
//!   scheduler  — epoch-based scheduling, latency-guard enforcement

pub mod dispatcher;
pub mod queue;
pub mod scheduler;
pub mod shadow_sync;
pub mod timing;
pub mod types;

pub use dispatcher::PacketDispatcher;
pub use scheduler::Scheduler;
pub use shadow_sync::ShadowSyncEngine;
pub use types::{
    Clock, FlowType, InvalidationReason, PacketPayload, PathEvent, PathQueueStats, PathStats,
    PlanInvalidationEvent, RealPacket, ScheduledPacket, SendError, ShadowSlot, TransmitterConfig,
    TransmitterStats,
};
