use crate::circuit_builder::CircuitId;

/// Whether a scheduled transmission carries real application data or cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficKind {
    Real,
    Cover,
}

/// A single transmission scheduled for a specific circuit at a specific time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledTransmission {
    pub circuit_id: CircuitId,
    /// Absolute µs timestamp by which this transmission must be sent.
    pub deadline_us: u64,
    pub kind: TrafficKind,
    /// Payload size in bytes.
    pub payload_size: usize,
}

/// Policy for the anti-correlation scheduler.
#[derive(Debug, Clone)]
pub struct AntiCorrelationPolicy {
    /// If `true`, real traffic is always drained before cover traffic.
    pub drain_real_first: bool,
    /// Cover transmissions whose deadline has passed by more than this are dropped.
    pub cover_expiry_slack_us: u64,
}

impl Default for AntiCorrelationPolicy {
    fn default() -> Self {
        Self {
            drain_real_first: true,
            cover_expiry_slack_us: 500_000, // 500 ms
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SchedulerError {
    /// The queue is empty — nothing to drain.
    EmptyQueue,
}
