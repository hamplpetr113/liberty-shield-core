//! Backpressure engine — prevents memory exhaustion from deep queues.
//!
//! `BackpressureEngine` tracks queue depth for each circuit and stream.
//! It signals pressure when depths exceed soft limits, and mandates packet
//! drops when hard limits are reached.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// PressureLevel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PressureLevel {
    None,
    Soft,
    Hard,
}

// ---------------------------------------------------------------------------
// BackpressureLimits
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct BackpressureLimits {
    pub soft_limit: usize,
    pub hard_limit: usize,
}

impl BackpressureLimits {
    pub fn new(soft: usize, hard: usize) -> Self {
        Self {
            soft_limit: soft,
            hard_limit: hard,
        }
    }

    pub fn level(&self, depth: usize) -> PressureLevel {
        if depth >= self.hard_limit {
            PressureLevel::Hard
        } else if depth >= self.soft_limit {
            PressureLevel::Soft
        } else {
            PressureLevel::None
        }
    }
}

impl Default for BackpressureLimits {
    fn default() -> Self {
        Self {
            soft_limit: 64,
            hard_limit: 128,
        }
    }
}

// ---------------------------------------------------------------------------
// BackpressureEngine
// ---------------------------------------------------------------------------

pub struct BackpressureEngine {
    circuit_depths: HashMap<u64, usize>,
    stream_depths: HashMap<(u64, u32), usize>,
    limits: BackpressureLimits,
    total_drops: u64,
}

impl BackpressureEngine {
    pub fn new(limits: BackpressureLimits) -> Self {
        Self {
            circuit_depths: HashMap::new(),
            stream_depths: HashMap::new(),
            limits,
            total_drops: 0,
        }
    }

    // ----- Circuit-level -----

    pub fn set_circuit_depth(&mut self, circuit_id: u64, depth: usize) {
        self.circuit_depths.insert(circuit_id, depth);
    }

    pub fn circuit_pressure(&self, circuit_id: u64) -> PressureLevel {
        let depth = self.circuit_depths.get(&circuit_id).copied().unwrap_or(0);
        self.limits.level(depth)
    }

    /// Returns true if the packet should be dropped (hard pressure).
    pub fn should_drop_circuit(&mut self, circuit_id: u64) -> bool {
        if self.circuit_pressure(circuit_id) == PressureLevel::Hard {
            self.total_drops += 1;
            true
        } else {
            false
        }
    }

    pub fn remove_circuit(&mut self, circuit_id: u64) {
        self.circuit_depths.remove(&circuit_id);
    }

    // ----- Stream-level -----

    pub fn set_stream_depth(&mut self, circuit_id: u64, stream_id: u32, depth: usize) {
        self.stream_depths.insert((circuit_id, stream_id), depth);
    }

    pub fn stream_pressure(&self, circuit_id: u64, stream_id: u32) -> PressureLevel {
        let depth = self
            .stream_depths
            .get(&(circuit_id, stream_id))
            .copied()
            .unwrap_or(0);
        self.limits.level(depth)
    }

    pub fn should_drop_stream(&mut self, circuit_id: u64, stream_id: u32) -> bool {
        if self.stream_pressure(circuit_id, stream_id) == PressureLevel::Hard {
            self.total_drops += 1;
            true
        } else {
            false
        }
    }

    pub fn total_drops(&self) -> u64 {
        self.total_drops
    }

    pub fn tracked_circuits(&self) -> usize {
        self.circuit_depths.len()
    }
}

impl Default for BackpressureEngine {
    fn default() -> Self {
        Self::new(BackpressureLimits::default())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn bp() -> BackpressureEngine {
        BackpressureEngine::new(BackpressureLimits::new(4, 8))
    }

    // BP1: depth below soft limit gives None pressure.
    #[test]
    fn bp1_no_pressure() {
        let mut e = bp();
        e.set_circuit_depth(1, 2);
        assert_eq!(e.circuit_pressure(1), PressureLevel::None);
    }

    // BP2: depth at soft limit gives Soft pressure.
    #[test]
    fn bp2_soft_pressure() {
        let mut e = bp();
        e.set_circuit_depth(1, 4);
        assert_eq!(e.circuit_pressure(1), PressureLevel::Soft);
    }

    // BP3: depth at hard limit gives Hard pressure.
    #[test]
    fn bp3_hard_pressure() {
        let mut e = bp();
        e.set_circuit_depth(1, 8);
        assert_eq!(e.circuit_pressure(1), PressureLevel::Hard);
    }

    // BP4: should_drop_circuit increments drop counter.
    #[test]
    fn bp4_drop_increments_counter() {
        let mut e = bp();
        e.set_circuit_depth(1, 10);
        assert!(e.should_drop_circuit(1));
        assert_eq!(e.total_drops(), 1);
    }

    // BP5: should_drop_circuit returns false when no pressure.
    #[test]
    fn bp5_no_drop_when_clear() {
        let mut e = bp();
        e.set_circuit_depth(1, 1);
        assert!(!e.should_drop_circuit(1));
        assert_eq!(e.total_drops(), 0);
    }

    // BP6: stream-level pressure is tracked independently.
    #[test]
    fn bp6_stream_pressure() {
        let mut e = bp();
        e.set_stream_depth(1, 7, 8);
        assert_eq!(e.stream_pressure(1, 7), PressureLevel::Hard);
        assert_eq!(e.stream_pressure(1, 8), PressureLevel::None);
    }

    // BP7: remove_circuit clears circuit depth.
    #[test]
    fn bp7_remove_circuit() {
        let mut e = bp();
        e.set_circuit_depth(1, 10);
        e.remove_circuit(1);
        assert_eq!(e.circuit_pressure(1), PressureLevel::None);
    }

    // BP8: unknown circuit returns None pressure.
    #[test]
    fn bp8_unknown_circuit() {
        let e = bp();
        assert_eq!(e.circuit_pressure(999), PressureLevel::None);
    }

    // BP9: PressureLevel ordering is correct.
    #[test]
    fn bp9_pressure_level_ordering() {
        assert!(PressureLevel::None < PressureLevel::Soft);
        assert!(PressureLevel::Soft < PressureLevel::Hard);
    }

    // BP10: should_drop_stream increments counter.
    #[test]
    fn bp10_drop_stream() {
        let mut e = bp();
        e.set_stream_depth(1, 1, 9);
        assert!(e.should_drop_stream(1, 1));
        assert_eq!(e.total_drops(), 1);
    }
}
