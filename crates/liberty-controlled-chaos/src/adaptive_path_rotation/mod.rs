//! Adaptive path rotation — detects traffic bursts and schedules circuit
//! rotation to preserve anonymity.
//!
//! `PathRotationEngine` tracks per-circuit packet rates and idle time.
//! On each call to `evaluate()` it returns a `RotationDecision`:
//! - `Rotate(Burst)` — packets/epoch exceeded `burst_threshold`.
//! - `Rotate(Scheduled)` — circuit has lived >= `rotation_interval_epochs`.
//! - `Rotate(Idle)` — no packets for >= `idle_threshold` epochs.
//! - `Keep` — circuit is healthy and not yet due for rotation.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// RotationReason / RotationDecision
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationReason {
    Burst,
    Scheduled,
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationDecision {
    Keep,
    Rotate(RotationReason),
}

// ---------------------------------------------------------------------------
// RotationPolicy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RotationPolicy {
    /// Rotate after this many epochs regardless of traffic.
    pub rotation_interval_epochs: u64,
    /// Packets-per-epoch threshold that triggers burst detection.
    pub burst_threshold: u64,
    /// Epochs without any packets that triggers idle rotation.
    pub idle_threshold: u64,
}

impl RotationPolicy {
    pub fn new(rotation_interval_epochs: u64, burst_threshold: u64, idle_threshold: u64) -> Self {
        Self {
            rotation_interval_epochs,
            burst_threshold,
            idle_threshold,
        }
    }
}

// ---------------------------------------------------------------------------
// CircuitTracker (internal)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CircuitTracker {
    last_rotation_epoch: u64,
    last_active_epoch: u64,
    /// Epoch for which `packets_this_epoch` was last reset.
    epoch_marker: u64,
    packets_this_epoch: u64,
}

impl CircuitTracker {
    fn new(epoch: u64) -> Self {
        Self {
            last_rotation_epoch: epoch,
            last_active_epoch: epoch,
            epoch_marker: epoch,
            packets_this_epoch: 0,
        }
    }

    /// Record a packet.  Resets per-epoch counter when the epoch advances.
    fn record_packet(&mut self, epoch: u64) {
        if epoch != self.epoch_marker {
            self.epoch_marker = epoch;
            self.packets_this_epoch = 0;
        }
        self.packets_this_epoch += 1;
        self.last_active_epoch = epoch;
    }
}

// ---------------------------------------------------------------------------
// PathRotationEngine
// ---------------------------------------------------------------------------

/// Monitors per-circuit traffic and advises when to rotate.
pub struct PathRotationEngine {
    policy: RotationPolicy,
    circuits: HashMap<u64, CircuitTracker>,
}

impl PathRotationEngine {
    pub fn new(policy: RotationPolicy) -> Self {
        Self {
            policy,
            circuits: HashMap::new(),
        }
    }

    /// Register a new circuit at `epoch`.
    pub fn add_circuit(&mut self, circuit_id: u64, epoch: u64) {
        self.circuits
            .entry(circuit_id)
            .or_insert_with(|| CircuitTracker::new(epoch));
    }

    /// Remove a circuit.
    pub fn remove_circuit(&mut self, circuit_id: u64) {
        self.circuits.remove(&circuit_id);
    }

    /// Record a packet on a circuit at `epoch`.
    pub fn record_packet(&mut self, circuit_id: u64, epoch: u64) {
        if let Some(t) = self.circuits.get_mut(&circuit_id) {
            t.record_packet(epoch);
        }
    }

    /// Decide whether `circuit_id` should be rotated at `current_epoch`.
    ///
    /// Priority: Burst > Scheduled > Idle > Keep.
    pub fn evaluate(&self, circuit_id: u64, current_epoch: u64) -> RotationDecision {
        let t = match self.circuits.get(&circuit_id) {
            Some(t) => t,
            None => return RotationDecision::Keep,
        };

        let current_epoch_packets = if t.epoch_marker == current_epoch {
            t.packets_this_epoch
        } else {
            0
        };

        if current_epoch_packets > self.policy.burst_threshold {
            return RotationDecision::Rotate(RotationReason::Burst);
        }

        let age = current_epoch.saturating_sub(t.last_rotation_epoch);
        if age >= self.policy.rotation_interval_epochs {
            return RotationDecision::Rotate(RotationReason::Scheduled);
        }

        let idle = current_epoch.saturating_sub(t.last_active_epoch);
        if idle >= self.policy.idle_threshold {
            return RotationDecision::Rotate(RotationReason::Idle);
        }

        RotationDecision::Keep
    }

    /// Apply a rotation — resets counters so the circuit starts a new interval.
    pub fn apply_rotation(&mut self, circuit_id: u64, epoch: u64) {
        if let Some(t) = self.circuits.get_mut(&circuit_id) {
            t.last_rotation_epoch = epoch;
            t.last_active_epoch = epoch;
            t.epoch_marker = epoch;
            t.packets_this_epoch = 0;
        }
    }

    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.circuits.is_empty()
    }

    /// IDs of all tracked circuits that need rotation at `current_epoch`.
    pub fn circuits_needing_rotation(&self, current_epoch: u64) -> Vec<u64> {
        self.circuits
            .keys()
            .copied()
            .filter(|&id| self.evaluate(id, current_epoch) != RotationDecision::Keep)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RotationPolicy {
        RotationPolicy::new(10, 50, 5)
    }

    fn engine() -> PathRotationEngine {
        PathRotationEngine::new(policy())
    }

    // APR1: add_circuit registers a circuit.
    #[test]
    fn apr1_add_circuit() {
        let mut e = engine();
        e.add_circuit(1, 0);
        assert_eq!(e.circuit_count(), 1);
    }

    // APR2: new circuit evaluates to Keep.
    #[test]
    fn apr2_new_circuit_keep() {
        let mut e = engine();
        e.add_circuit(1, 0);
        assert_eq!(e.evaluate(1, 0), RotationDecision::Keep);
    }

    // APR3: burst triggers Rotate(Burst).
    #[test]
    fn apr3_burst_triggers_rotation() {
        let mut e = engine();
        e.add_circuit(1, 0);
        for _ in 0..51 {
            e.record_packet(1, 0);
        }
        assert_eq!(
            e.evaluate(1, 0),
            RotationDecision::Rotate(RotationReason::Burst)
        );
    }

    // APR4: scheduled rotation triggers at interval boundary.
    #[test]
    fn apr4_scheduled_rotation() {
        let mut e = engine();
        e.add_circuit(1, 0);
        // epoch=10: age = 10-0 = 10 >= 10 → Scheduled
        assert_eq!(
            e.evaluate(1, 10),
            RotationDecision::Rotate(RotationReason::Scheduled)
        );
    }

    // APR5: idle triggers rotation.
    #[test]
    fn apr5_idle_rotation() {
        let mut e = engine();
        e.add_circuit(1, 0);
        e.record_packet(1, 0); // active at epoch 0
        // epoch=5: idle = 5-0 = 5 >= 5 → Idle (scheduled age=5 < 10 so not scheduled)
        assert_eq!(
            e.evaluate(1, 5),
            RotationDecision::Rotate(RotationReason::Idle)
        );
    }

    // APR6: burst takes priority over scheduled.
    #[test]
    fn apr6_burst_priority_over_scheduled() {
        let mut e = engine();
        e.add_circuit(1, 0);
        for _ in 0..51 {
            e.record_packet(1, 10);
        }
        // Both burst and scheduled conditions met at epoch 10
        assert_eq!(
            e.evaluate(1, 10),
            RotationDecision::Rotate(RotationReason::Burst)
        );
    }

    // APR7: apply_rotation resets interval.
    #[test]
    fn apr7_apply_rotation_resets() {
        // Use idle_threshold=20 so idle doesn't fire before the scheduled check
        let mut e = PathRotationEngine::new(RotationPolicy::new(10, 50, 20));
        e.add_circuit(1, 0);
        e.apply_rotation(1, 5);
        // After rotation at 5, next scheduled at 15; idle_threshold=20 won't trigger at 10
        assert_eq!(e.evaluate(1, 10), RotationDecision::Keep);
        assert_eq!(
            e.evaluate(1, 15),
            RotationDecision::Rotate(RotationReason::Scheduled)
        );
    }

    // APR8: remove_circuit removes it.
    #[test]
    fn apr8_remove_circuit() {
        let mut e = engine();
        e.add_circuit(1, 0);
        e.remove_circuit(1);
        assert!(e.is_empty());
    }

    // APR9: unknown circuit evaluates to Keep without panic.
    #[test]
    fn apr9_unknown_circuit_keep() {
        let e = engine();
        assert_eq!(e.evaluate(999, 0), RotationDecision::Keep);
    }

    // APR10: record_packet on unknown circuit is a no-op.
    #[test]
    fn apr10_record_unknown_noop() {
        let mut e = engine();
        e.record_packet(999, 0); // should not panic
        assert!(e.is_empty());
    }

    // APR11: circuits_needing_rotation returns correct IDs.
    #[test]
    fn apr11_needing_rotation_batch() {
        let mut e = engine();
        e.add_circuit(1, 0);
        e.add_circuit(2, 0);
        // Force circuit 1 to need rotation (burst)
        for _ in 0..51 {
            e.record_packet(1, 0);
        }
        let need_rot = e.circuits_needing_rotation(0);
        assert!(need_rot.contains(&1));
        assert!(!need_rot.contains(&2));
    }

    // APR12: packets on different epoch reset counter.
    #[test]
    fn apr12_epoch_resets_counter() {
        let mut e = engine();
        e.add_circuit(1, 0);
        for _ in 0..51 {
            e.record_packet(1, 0); // burst at epoch 0
        }
        // New epoch: counter resets
        e.record_packet(1, 1); // one packet at epoch 1
        assert_eq!(e.evaluate(1, 1), RotationDecision::Keep);
    }

    // APR13: add_circuit is idempotent.
    #[test]
    fn apr13_add_idempotent() {
        let mut e = engine();
        e.add_circuit(1, 0);
        e.add_circuit(1, 5); // second add is ignored
        assert_eq!(e.circuit_count(), 1);
    }

    // APR14: multiple circuits evaluated independently.
    #[test]
    fn apr14_multiple_circuits_independent() {
        let mut e = engine();
        e.add_circuit(1, 0);
        e.add_circuit(2, 0);
        for _ in 0..51 {
            e.record_packet(1, 0); // burst on circuit 1 only
        }
        assert_eq!(
            e.evaluate(1, 0),
            RotationDecision::Rotate(RotationReason::Burst)
        );
        assert_eq!(e.evaluate(2, 0), RotationDecision::Keep);
    }

    // APR15: scheduled fires exactly at rotation_interval boundary.
    #[test]
    fn apr15_scheduled_exact_boundary() {
        let mut e = PathRotationEngine::new(RotationPolicy::new(10, 50, 100));
        e.add_circuit(1, 0);
        assert_eq!(e.evaluate(1, 9), RotationDecision::Keep);
        assert_eq!(
            e.evaluate(1, 10),
            RotationDecision::Rotate(RotationReason::Scheduled)
        );
    }

    // APR16: circuits_needing_rotation is empty when all healthy.
    #[test]
    fn apr16_needing_rotation_empty_when_healthy() {
        let mut e = engine();
        e.add_circuit(1, 0);
        e.add_circuit(2, 0);
        assert!(e.circuits_needing_rotation(0).is_empty());
    }

    // APR17: packet below burst threshold keeps circuit healthy.
    #[test]
    fn apr17_below_burst_keeps() {
        let mut e = engine(); // burst_threshold = 50
        e.add_circuit(1, 0);
        for _ in 0..50 {
            // exactly 50, threshold is >50
            e.record_packet(1, 0);
        }
        assert_eq!(e.evaluate(1, 0), RotationDecision::Keep);
    }
}
