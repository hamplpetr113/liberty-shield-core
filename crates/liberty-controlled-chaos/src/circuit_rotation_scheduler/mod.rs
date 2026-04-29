//! Circuit rotation scheduler — decides when circuits should be replaced to
//! improve anonymity.
//!
//! `RotationPolicy` encodes three independent expiry conditions:
//! - `max_lifetime_epochs`: circuit has been open longer than this.
//! - `max_packets`: circuit has forwarded more packets than this.
//! - `idle_epochs`: circuit has been idle (no traffic) for this many epochs.
//!
//! `CircuitRotationScheduler` evaluates each condition against live
//! `RotatableCircuit` records.  When `should_rotate` returns `true`, the
//! caller is expected to close the old circuit and open a replacement.

// ---------------------------------------------------------------------------
// RotationPolicy
// ---------------------------------------------------------------------------

/// Conditions that trigger circuit rotation.
#[derive(Debug, Clone)]
pub struct RotationPolicy {
    /// Close and replace a circuit after this many epochs.
    pub max_lifetime_epochs: u64,
    /// Close and replace after forwarding this many packets.
    pub max_packets: u64,
    /// Close after being idle for this many epochs.
    pub idle_epochs: u64,
}

impl RotationPolicy {
    /// Sensible defaults for a privacy-preserving node.
    pub fn default_policy() -> Self {
        Self {
            max_lifetime_epochs: 20,
            max_packets: 1000,
            idle_epochs: 5,
        }
    }
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self::default_policy()
    }
}

// ---------------------------------------------------------------------------
// RotatableCircuit
// ---------------------------------------------------------------------------

/// Snapshot of a circuit's state used for rotation decisions.
#[derive(Debug, Clone)]
pub struct RotatableCircuit {
    pub circuit_id: u64,
    pub created_epoch: u64,
    pub last_used_epoch: u64,
    pub packets_forwarded: u64,
    pub is_open: bool,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationError {
    /// The circuit_id is not tracked.
    NotFound,
}

impl std::fmt::Display for RotationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "circuit not found")
    }
}

// ---------------------------------------------------------------------------
// CircuitRotationScheduler
// ---------------------------------------------------------------------------

/// Schedules circuit rotation according to a `RotationPolicy`.
pub struct CircuitRotationScheduler {
    policy: RotationPolicy,
    circuits: Vec<RotatableCircuit>,
}

impl CircuitRotationScheduler {
    pub fn new(policy: RotationPolicy) -> Self {
        Self {
            policy,
            circuits: Vec::new(),
        }
    }

    /// Register a circuit for rotation tracking.
    pub fn add_circuit(&mut self, circuit: RotatableCircuit) {
        self.circuits.push(circuit);
    }

    /// Remove a circuit by ID.
    pub fn remove_circuit(&mut self, circuit_id: u64) -> Result<(), RotationError> {
        let pos = self
            .circuits
            .iter()
            .position(|c| c.circuit_id == circuit_id)
            .ok_or(RotationError::NotFound)?;
        self.circuits.swap_remove(pos);
        Ok(())
    }

    /// Record that `count` packets were forwarded on a circuit.
    pub fn record_packets(
        &mut self,
        circuit_id: u64,
        count: u64,
        current_epoch: u64,
    ) -> Result<(), RotationError> {
        let c = self
            .circuits
            .iter_mut()
            .find(|c| c.circuit_id == circuit_id)
            .ok_or(RotationError::NotFound)?;
        c.packets_forwarded = c.packets_forwarded.saturating_add(count);
        c.last_used_epoch = current_epoch;
        Ok(())
    }

    /// Return `true` if the given circuit should be rotated at `current_epoch`.
    pub fn should_rotate(&self, circuit: &RotatableCircuit, current_epoch: u64) -> bool {
        if !circuit.is_open {
            return false;
        }
        let age = current_epoch.saturating_sub(circuit.created_epoch);
        let idle = current_epoch.saturating_sub(circuit.last_used_epoch);
        age >= self.policy.max_lifetime_epochs
            || circuit.packets_forwarded >= self.policy.max_packets
            || idle >= self.policy.idle_epochs
    }

    /// Return the IDs of all circuits that should be rotated now.
    pub fn select_rotation_targets(&self, current_epoch: u64) -> Vec<u64> {
        self.circuits
            .iter()
            .filter(|c| self.should_rotate(c, current_epoch))
            .map(|c| c.circuit_id)
            .collect()
    }

    /// Mark rotation targets as closed and return their IDs.
    ///
    /// The caller is responsible for creating replacement circuits.
    pub fn trigger_rotation(&mut self, current_epoch: u64) -> Vec<u64> {
        let targets = self.select_rotation_targets(current_epoch);
        for c in self.circuits.iter_mut() {
            if targets.contains(&c.circuit_id) {
                c.is_open = false;
            }
        }
        targets
    }

    /// Number of currently tracked circuits.
    pub fn len(&self) -> usize {
        self.circuits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.circuits.is_empty()
    }

    pub fn policy(&self) -> &RotationPolicy {
        &self.policy
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> RotationPolicy {
        RotationPolicy {
            max_lifetime_epochs: 10,
            max_packets: 100,
            idle_epochs: 3,
        }
    }

    fn sched() -> CircuitRotationScheduler {
        CircuitRotationScheduler::new(policy())
    }

    fn open_circuit(id: u64, created: u64) -> RotatableCircuit {
        RotatableCircuit {
            circuit_id: id,
            created_epoch: created,
            last_used_epoch: created,
            packets_forwarded: 0,
            is_open: true,
        }
    }

    // CRS1: circuit exceeding max_lifetime_epochs should rotate.
    #[test]
    fn crs1_lifetime_expiration() {
        let mut s = sched();
        s.add_circuit(open_circuit(1, 0));
        assert!(s.should_rotate(s.circuits.first().unwrap(), 10));
    }

    // CRS2: circuit exceeding max_packets should rotate.
    #[test]
    fn crs2_packet_threshold() {
        let mut s = sched();
        s.add_circuit(open_circuit(1, 0));
        s.record_packets(1, 100, 1).unwrap();
        assert!(s.should_rotate(s.circuits.first().unwrap(), 2));
    }

    // CRS3: idle circuit should rotate.
    #[test]
    fn crs3_idle_expiration() {
        let mut s = sched();
        s.add_circuit(open_circuit(1, 0));
        // idle since epoch 0, now epoch 4 → idle=4 >= idle_epochs=3
        assert!(s.should_rotate(s.circuits.first().unwrap(), 4));
    }

    // CRS4: trigger_rotation returns and marks circuits as closed.
    #[test]
    fn crs4_rotation_triggers() {
        let mut s = sched();
        s.add_circuit(open_circuit(1, 0));
        let ids = s.trigger_rotation(10);
        assert_eq!(ids, vec![1]);
        assert!(!s.circuits.first().unwrap().is_open);
    }

    // CRS5: fresh active circuit should not rotate.
    #[test]
    fn crs5_no_rotation_when_active() {
        let mut s = sched();
        s.add_circuit(open_circuit(1, 5));
        s.record_packets(1, 10, 6).unwrap();
        // age=1, packets=10, idle=0 — all below thresholds
        assert!(!s.should_rotate(s.circuits.first().unwrap(), 6));
    }

    // CRS6: multiple circuits, only expired ones are targeted.
    #[test]
    fn crs6_multiple_circuits() {
        let mut s = sched();
        s.add_circuit(open_circuit(1, 0)); // old
        s.add_circuit(open_circuit(2, 8)); // fresh
        let targets = s.select_rotation_targets(10);
        assert!(targets.contains(&1));
        assert!(!targets.contains(&2));
    }

    // CRS7: stress — 50 circuits, all hit packet threshold.
    #[test]
    fn crs7_stress_rotation() {
        let mut s = sched();
        for i in 1u64..=50 {
            s.add_circuit(open_circuit(i, 0));
            s.record_packets(i, 100, 1).unwrap();
        }
        let targets = s.trigger_rotation(2);
        assert_eq!(targets.len(), 50);
    }

    // CRS8: rotation ordering — all expired circuits returned.
    #[test]
    fn crs8_rotation_ordering() {
        let mut s = sched();
        for i in 1u64..=5 {
            s.add_circuit(open_circuit(i, 0));
        }
        let mut targets = s.select_rotation_targets(10);
        targets.sort();
        assert_eq!(targets, vec![1, 2, 3, 4, 5]);
    }

    // CRS9: lifecycle consistency — closed circuit is never re-targeted.
    #[test]
    fn crs9_lifecycle_consistency() {
        let mut s = sched();
        s.add_circuit(open_circuit(1, 0));
        s.trigger_rotation(10);
        // Already closed — should not appear again.
        let second = s.select_rotation_targets(20);
        assert!(second.is_empty());
    }

    // CRS10: integration — remove_circuit clears it from tracking.
    #[test]
    fn crs10_rotation_integration() {
        let mut s = sched();
        s.add_circuit(open_circuit(1, 0));
        s.remove_circuit(1).unwrap();
        assert_eq!(s.len(), 0);
        assert_eq!(s.remove_circuit(1).unwrap_err(), RotationError::NotFound);
    }
}
