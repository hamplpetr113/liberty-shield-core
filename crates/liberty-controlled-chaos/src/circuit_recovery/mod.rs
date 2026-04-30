//! Circuit failure recovery — detects broken circuits, selects replacement
//! paths, migrates the traffic queue, and marks failed peers.
//!
//! `RecoveryEngine` tracks in-flight circuits by `circuit_id`.  When a
//! failure is reported it moves to `Recovering` state and allocates a
//! replacement slot.  Once the replacement is built it transitions to
//! `Recovered`.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// CircuitRecoveryState
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitRecoveryState {
    Healthy,
    Recovering,
    Recovered,
    Abandoned,
}

// ---------------------------------------------------------------------------
// FailureReason
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    HealthScoreLow,
    PeerUnreachable,
    TimeoutExpired,
    ReplayViolation,
}

// ---------------------------------------------------------------------------
// RecoveryEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RecoveryEntry {
    pub original_circuit_id: u64,
    pub state: CircuitRecoveryState,
    pub reason: Option<FailureReason>,
    pub replacement_circuit_id: Option<u64>,
    pub failed_peer: Option<[u8; 32]>,
    pub packets_queued: u64,
    pub packets_migrated: u64,
    pub failure_epoch: u64,
}

impl RecoveryEntry {
    fn new(circuit_id: u64, epoch: u64) -> Self {
        Self {
            original_circuit_id: circuit_id,
            state: CircuitRecoveryState::Healthy,
            reason: None,
            replacement_circuit_id: None,
            failed_peer: None,
            packets_queued: 0,
            packets_migrated: 0,
            failure_epoch: 0,
        }
        .with_epoch(epoch)
    }

    fn with_epoch(mut self, epoch: u64) -> Self {
        self.failure_epoch = epoch;
        self
    }
}

// ---------------------------------------------------------------------------
// RecoveryEngine
// ---------------------------------------------------------------------------

pub struct RecoveryEngine {
    circuits: HashMap<u64, RecoveryEntry>,
    failed_peers: HashMap<[u8; 32], u64>,
}

impl RecoveryEngine {
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
            failed_peers: HashMap::new(),
        }
    }

    /// Register a circuit for health tracking.
    pub fn register(&mut self, circuit_id: u64, epoch: u64) {
        self.circuits
            .entry(circuit_id)
            .or_insert_with(|| RecoveryEntry::new(circuit_id, epoch));
    }

    /// Report a failure on a circuit.
    pub fn report_failure(
        &mut self,
        circuit_id: u64,
        reason: FailureReason,
        failed_peer: Option<[u8; 32]>,
        queued_packets: u64,
        epoch: u64,
    ) {
        if let Some(e) = self.circuits.get_mut(&circuit_id) {
            e.state = CircuitRecoveryState::Recovering;
            e.reason = Some(reason);
            e.failed_peer = failed_peer;
            e.packets_queued = queued_packets;
            e.failure_epoch = epoch;
        }
        if let Some(peer) = failed_peer {
            self.failed_peers.insert(peer, epoch);
        }
    }

    /// Assign a replacement circuit and migrate the queued packets.
    pub fn assign_replacement(&mut self, original_id: u64, replacement_id: u64) {
        if let Some(e) = self.circuits.get_mut(&original_id) {
            e.replacement_circuit_id = Some(replacement_id);
            e.packets_migrated = e.packets_queued;
            e.state = CircuitRecoveryState::Recovered;
        }
    }

    /// Mark a recovery as abandoned (no replacement available).
    pub fn abandon(&mut self, circuit_id: u64) {
        if let Some(e) = self.circuits.get_mut(&circuit_id) {
            e.state = CircuitRecoveryState::Abandoned;
        }
    }

    pub fn remove(&mut self, circuit_id: u64) {
        self.circuits.remove(&circuit_id);
    }

    pub fn state(&self, circuit_id: u64) -> Option<CircuitRecoveryState> {
        self.circuits.get(&circuit_id).map(|e| e.state)
    }

    pub fn entry(&self, circuit_id: u64) -> Option<&RecoveryEntry> {
        self.circuits.get(&circuit_id)
    }

    pub fn is_peer_failed(&self, peer: &[u8; 32]) -> bool {
        self.failed_peers.contains_key(peer)
    }

    pub fn recovering_count(&self) -> usize {
        self.circuits
            .values()
            .filter(|e| e.state == CircuitRecoveryState::Recovering)
            .count()
    }

    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }
}

impl Default for RecoveryEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // CR1: register creates a healthy entry.
    #[test]
    fn cr1_register_healthy() {
        let mut e = RecoveryEngine::new();
        e.register(1, 0);
        assert_eq!(e.state(1), Some(CircuitRecoveryState::Healthy));
    }

    // CR2: report_failure moves circuit to Recovering.
    #[test]
    fn cr2_report_failure() {
        let mut e = RecoveryEngine::new();
        e.register(1, 0);
        e.report_failure(1, FailureReason::PeerUnreachable, None, 5, 1);
        assert_eq!(e.state(1), Some(CircuitRecoveryState::Recovering));
    }

    // CR3: assign_replacement moves to Recovered.
    #[test]
    fn cr3_assign_replacement() {
        let mut e = RecoveryEngine::new();
        e.register(1, 0);
        e.report_failure(1, FailureReason::TimeoutExpired, None, 3, 1);
        e.assign_replacement(1, 99);
        assert_eq!(e.state(1), Some(CircuitRecoveryState::Recovered));
        assert_eq!(e.entry(1).unwrap().replacement_circuit_id, Some(99));
    }

    // CR4: migrated packets == queued packets after replacement.
    #[test]
    fn cr4_packets_migrated() {
        let mut e = RecoveryEngine::new();
        e.register(1, 0);
        e.report_failure(1, FailureReason::HealthScoreLow, None, 10, 1);
        e.assign_replacement(1, 2);
        assert_eq!(e.entry(1).unwrap().packets_migrated, 10);
    }

    // CR5: failed peer is tracked.
    #[test]
    fn cr5_failed_peer_tracked() {
        let mut e = RecoveryEngine::new();
        e.register(1, 0);
        e.report_failure(1, FailureReason::PeerUnreachable, Some(nid(5)), 0, 1);
        assert!(e.is_peer_failed(&nid(5)));
    }

    // CR6: unknown circuit returns None state.
    #[test]
    fn cr6_unknown_circuit() {
        let e = RecoveryEngine::new();
        assert_eq!(e.state(999), None);
    }

    // CR7: abandon marks circuit as Abandoned.
    #[test]
    fn cr7_abandon() {
        let mut e = RecoveryEngine::new();
        e.register(1, 0);
        e.report_failure(1, FailureReason::TimeoutExpired, None, 0, 0);
        e.abandon(1);
        assert_eq!(e.state(1), Some(CircuitRecoveryState::Abandoned));
    }

    // CR8: recovering_count counts Recovering circuits.
    #[test]
    fn cr8_recovering_count() {
        let mut e = RecoveryEngine::new();
        e.register(1, 0);
        e.register(2, 0);
        e.report_failure(1, FailureReason::ReplayViolation, None, 0, 0);
        assert_eq!(e.recovering_count(), 1);
    }

    // CR9: remove cleans up entry.
    #[test]
    fn cr9_remove() {
        let mut e = RecoveryEngine::new();
        e.register(1, 0);
        e.remove(1);
        assert_eq!(e.circuit_count(), 0);
    }

    // CR10: register is idempotent.
    #[test]
    fn cr10_register_idempotent() {
        let mut e = RecoveryEngine::new();
        e.register(1, 0);
        e.register(1, 5); // second register is ignored
        assert_eq!(e.circuit_count(), 1);
    }
}
