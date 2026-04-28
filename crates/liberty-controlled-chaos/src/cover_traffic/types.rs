use crate::circuit_builder::CircuitId;

/// Class of cover traffic intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverTrafficClass {
    /// Periodic keep-alive on an established circuit.
    Heartbeat,
    /// Burst to mimic shadow-route activity.
    ShadowBurst,
    /// Zero-content padding cell.
    Padding,
    /// Decoy intent that mimics real application traffic shape.
    Decoy,
}

/// Policy governing cover traffic generation for one epoch.
#[derive(Debug, Clone)]
pub struct CoverTrafficPolicy {
    /// If `false`, `generate_epoch` always returns an empty vec.
    pub enabled: bool,
    /// Maximum cover intents emitted per epoch.
    pub max_cover_per_epoch: usize,
    /// Minimum µs between successive cover emissions.
    pub min_interval_us: u64,
    /// Maximum µs between successive cover emissions.
    pub max_interval_us: u64,
    /// Fixed payload size for every cover intent in this policy.
    pub payload_size: usize,
}

impl Default for CoverTrafficPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            max_cover_per_epoch: 10,
            min_interval_us: 100_000,   // 100 ms
            max_interval_us: 1_000_000, // 1 s
            payload_size: 512,
        }
    }
}

/// A scheduled cover traffic emission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverTrafficIntent {
    pub class: CoverTrafficClass,
    /// Absolute µs timestamp at which this intent should fire.
    pub scheduled_time_us: u64,
    pub payload_size: usize,
    pub circuit_id: CircuitId,
}
