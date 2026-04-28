use crate::circuit_builder::CircuitId;

use super::types::{CoverTrafficClass, CoverTrafficIntent, CoverTrafficPolicy};

/// Generates deterministic cover traffic intents for one epoch.
///
/// No network I/O; no randomness; all timing is caller-supplied.
pub struct CoverTrafficGenerator;

impl CoverTrafficGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Return all cover intents to schedule within `[epoch_start_us, ...)`.
    ///
    /// Deterministic: the schedule is derived from `epoch_start_us` and the
    /// sorted list of `circuit_ids`.  Two identical inputs always produce the
    /// same output.
    pub fn generate_epoch(
        &self,
        policy: &CoverTrafficPolicy,
        circuits: &[CircuitId],
        epoch_start_us: u64,
    ) -> Vec<CoverTrafficIntent> {
        if !policy.enabled || circuits.is_empty() {
            return Vec::new();
        }

        let interval = Self::stable_interval(policy);
        let class_seq = Self::class_sequence();

        let mut sorted_circuits = circuits.to_vec();
        sorted_circuits.sort_by_key(|c| c.0);

        let mut intents = Vec::new();
        let mut time = epoch_start_us;
        let mut class_idx = 0usize;
        let mut circuit_idx = 0usize;

        while intents.len() < policy.max_cover_per_epoch {
            let circuit_id = sorted_circuits[circuit_idx % sorted_circuits.len()];
            let class = class_seq[class_idx % class_seq.len()];

            intents.push(CoverTrafficIntent {
                class,
                scheduled_time_us: time,
                payload_size: policy.payload_size,
                circuit_id,
            });

            // Advance time deterministically using a simple hash of epoch + index.
            let step = Self::derive_step(epoch_start_us, intents.len() as u64, interval);
            time = time.wrapping_add(step);
            class_idx += 1;
            circuit_idx += 1;
        }

        intents
    }

    /// Return `true` if enough time has elapsed since the last emission.
    pub fn should_emit(policy: &CoverTrafficPolicy, last_emit_us: u64, now_us: u64) -> bool {
        if !policy.enabled {
            return false;
        }
        now_us.saturating_sub(last_emit_us) >= policy.min_interval_us
    }

    // ── private helpers ───────────────────────────────────────────────────────

    /// Deterministic interval midpoint between min and max.
    fn stable_interval(policy: &CoverTrafficPolicy) -> u64 {
        policy.min_interval_us + (policy.max_interval_us - policy.min_interval_us) / 2
    }

    /// Fixed rotation of cover traffic classes.
    fn class_sequence() -> [CoverTrafficClass; 4] {
        [
            CoverTrafficClass::Heartbeat,
            CoverTrafficClass::Padding,
            CoverTrafficClass::ShadowBurst,
            CoverTrafficClass::Decoy,
        ]
    }

    /// Derive a per-slot time step so each slot has a unique offset.
    /// Uses a simple multiply-xor mix on `(epoch_start ^ index)` clamped to
    /// `[min_interval, max_interval]`.
    fn derive_step(epoch_start_us: u64, index: u64, base_interval: u64) -> u64 {
        let mixed = epoch_start_us.wrapping_add(index.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        // Map into [base_interval, base_interval + base_interval/4) for variance.
        base_interval + (mixed >> 2) % (base_interval / 4 + 1)
    }
}

impl Default for CoverTrafficGenerator {
    fn default() -> Self {
        Self::new()
    }
}
