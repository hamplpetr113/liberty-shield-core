//! Failure recovery runtime — coordinates failure detection and circuit replacement.
//!
//! `FailureRecoveryRuntime` wires together:
//! - `RecoveryEngine` — tracks in-flight circuit recovery state
//! - `PeerBanList` — bans persistently-failing peers
//! - `LinkStateTracker` — records per-peer link up/down transitions
//! - `CircuitTeardownManager` — gracefully closes superseded circuits
//! - `RelayPathCache` — caches relay paths for the replacement circuit
//! - `PeerScoreLedger` — penalizes failing peers; drives ban decisions
//!
//! ## Failure lifecycle
//! 1. `handle_link_failure` → link marked Down, circuit enters Recovering, peer penalized.
//! 2. `assign_replacement` → replacement circuit assigned, old circuit queued for teardown.
//! 3. `close_circuit` → drive teardown state machine to Closed.
//! 4. `advance_epoch` → purge closed circuits, evict stale path cache entries.

use crate::circuit_recovery::{FailureReason, RecoveryEngine};
use crate::circuit_teardown_manager::CircuitTeardownManager;
use crate::link_state_tracker::LinkStateTracker;
use crate::peer_ban_list::PeerBanList;
use crate::peer_score_ledger::PeerScoreLedger;
use crate::relay_path_cache::{NodeId, RelayPathCache};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    CircuitNotRegistered,
    AlreadyClosed,
    LinkNotRegistered,
    CacheCapacityExceeded,
}

// ---------------------------------------------------------------------------
// FailureRecoveryRuntime
// ---------------------------------------------------------------------------

pub struct FailureRecoveryRuntime {
    recovery: RecoveryEngine,
    ban_list: PeerBanList,
    links: LinkStateTracker,
    teardown: CircuitTeardownManager,
    path_cache: RelayPathCache,
    scores: PeerScoreLedger,
    /// Score threshold below which a peer is automatically banned.
    ban_threshold: i64,
    /// Duration (epochs) for automatic bans.
    ban_duration_epochs: u64,
    /// Penalty applied per link failure.
    failure_penalty: i64,
    recoveries_initiated: u64,
    circuits_closed: u64,
}

impl FailureRecoveryRuntime {
    pub fn new(
        ban_threshold: i64,
        ban_duration_epochs: u64,
        failure_penalty: i64,
        path_cache_capacity: usize,
    ) -> Self {
        Self {
            recovery: RecoveryEngine::new(),
            ban_list: PeerBanList::new(),
            links: LinkStateTracker::new(),
            teardown: CircuitTeardownManager::new(),
            path_cache: RelayPathCache::new(path_cache_capacity),
            scores: PeerScoreLedger::new(-1000, 1000),
            ban_threshold,
            ban_duration_epochs,
            failure_penalty,
            recoveries_initiated: 0,
            circuits_closed: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------------

    /// Register a peer link. Must be called before `handle_link_failure`.
    pub fn register_peer(&mut self, peer_id: [u8; 32], epoch: u64) {
        self.links.register(peer_id, epoch);
    }

    /// Register a circuit for recovery tracking.
    pub fn register_circuit(&mut self, circuit_id: u64, epoch: u64) {
        self.recovery.register(circuit_id, epoch);
        self.teardown.register(circuit_id, epoch);
    }

    // -----------------------------------------------------------------------
    // Failure handling
    // -----------------------------------------------------------------------

    /// Handle a link-level failure for `peer_id`. All circuits through that peer
    /// are marked as Recovering; the peer is penalized and optionally banned.
    pub fn handle_link_failure(
        &mut self,
        peer_id: [u8; 32],
        circuit_id: u64,
        epoch: u64,
    ) -> Result<(), RecoveryError> {
        // 1. Mark link down.
        self.links
            .mark_down(peer_id, epoch)
            .map_err(|_| RecoveryError::LinkNotRegistered)?;

        // 2. Report circuit failure to recovery engine.
        self.recovery.report_failure(
            circuit_id,
            FailureReason::PeerUnreachable,
            Some(peer_id),
            0,
            epoch,
        );
        self.recoveries_initiated += 1;

        // 3. Penalize peer score.
        self.scores.penalize(peer_id, self.failure_penalty, epoch);

        // 4. Auto-ban if score falls below threshold.
        let current_score = self.scores.score(&peer_id).unwrap_or(0);
        if current_score < self.ban_threshold && !self.ban_list.is_banned(&peer_id, epoch) {
            let _ = self.ban_list.ban(
                peer_id,
                "low score".into(),
                epoch,
                Some(self.ban_duration_epochs),
            );
        }

        Ok(())
    }

    /// Restore a link after repair (e.g., peer reconnected).
    pub fn handle_link_recovery(&mut self, peer_id: [u8; 32], epoch: u64) {
        let _ = self.links.mark_up(peer_id, epoch);
        // Reward a small amount for reconnection.
        self.scores.reward(peer_id, self.failure_penalty / 2, epoch);
    }

    // -----------------------------------------------------------------------
    // Replacement selection
    // -----------------------------------------------------------------------

    /// Assign a replacement circuit for a failed one and cache the relay path.
    pub fn assign_replacement(
        &mut self,
        original_id: u64,
        replacement_id: u64,
        src: NodeId,
        dst: NodeId,
        path: Vec<NodeId>,
        epoch: u64,
    ) -> Result<(), RecoveryError> {
        self.recovery
            .assign_replacement(original_id, replacement_id);

        self.path_cache
            .insert(src, dst, path, epoch, 50)
            .map_err(|_| RecoveryError::CacheCapacityExceeded)?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Circuit closure
    // -----------------------------------------------------------------------

    /// Drive an old circuit through the teardown state machine to Closed.
    pub fn close_circuit(&mut self, circuit_id: u64, epoch: u64) -> Result<(), RecoveryError> {
        self.teardown
            .initiate_drain(circuit_id)
            .map_err(|_| RecoveryError::CircuitNotRegistered)?;
        self.teardown
            .advance_closing(circuit_id)
            .map_err(|_| RecoveryError::CircuitNotRegistered)?;
        self.teardown
            .close(circuit_id, epoch)
            .map_err(|_| RecoveryError::AlreadyClosed)?;
        self.circuits_closed += 1;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Epoch advance
    // -----------------------------------------------------------------------

    /// Purge closed circuits and evict stale path cache entries.
    pub fn advance_epoch(&mut self, epoch: u64) {
        self.teardown.purge_closed();
        self.path_cache.evict_expired(epoch);
        self.ban_list.evict_expired(epoch);
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn is_peer_banned(&self, peer_id: &[u8; 32], epoch: u64) -> bool {
        self.ban_list.is_banned(peer_id, epoch)
    }

    pub fn peer_score(&self, peer_id: &[u8; 32]) -> Option<i64> {
        self.scores.score(peer_id)
    }

    pub fn is_link_up(&self, peer_id: &[u8; 32]) -> bool {
        self.links.is_up(peer_id)
    }

    pub fn recovery_state(
        &self,
        circuit_id: u64,
    ) -> Option<crate::circuit_recovery::CircuitRecoveryState> {
        self.recovery.state(circuit_id)
    }

    pub fn teardown_state(
        &self,
        circuit_id: u64,
    ) -> Option<crate::circuit_teardown_manager::TeardownState> {
        self.teardown.state(circuit_id)
    }

    pub fn recoveries_initiated(&self) -> u64 {
        self.recoveries_initiated
    }
    pub fn circuits_closed(&self) -> u64 {
        self.circuits_closed
    }
    pub fn active_teardowns(&self) -> usize {
        self.teardown.active_count()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit_recovery::CircuitRecoveryState;
    use crate::circuit_teardown_manager::TeardownState;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn make_rt() -> FailureRecoveryRuntime {
        FailureRecoveryRuntime::new(-50, 100, 10, 32)
    }

    // FRR1: link down marks circuit recovering.
    #[test]
    fn frr1_link_down_triggers_failure() {
        let mut rt = make_rt();
        rt.register_peer(nid(5), 1);
        rt.register_circuit(42, 1);
        rt.handle_link_failure(nid(5), 42, 2).unwrap();
        assert!(!rt.is_link_up(&nid(5)));
        assert_eq!(rt.recoveries_initiated(), 1);
    }

    // FRR2: circuit recovery state is Recovering after failure.
    #[test]
    fn frr2_circuit_recovery_state() {
        let mut rt = make_rt();
        rt.register_peer(nid(6), 1);
        rt.register_circuit(10, 1);
        rt.handle_link_failure(nid(6), 10, 2).unwrap();
        assert_eq!(
            rt.recovery_state(10),
            Some(CircuitRecoveryState::Recovering)
        );
    }

    // FRR3: replacement assigned and path cached.
    #[test]
    fn frr3_replacement_path_cached() {
        let mut rt = make_rt();
        rt.register_peer(nid(1), 1);
        rt.register_circuit(1, 1);
        rt.handle_link_failure(nid(1), 1, 2).unwrap();
        rt.assign_replacement(1, 2, nid(10), nid(11), vec![nid(12)], 2)
            .unwrap();
        // Path is now in cache.
        assert_eq!(rt.recovery_state(1), Some(CircuitRecoveryState::Recovered));
    }

    // FRR4: close_circuit drives teardown to Closed.
    #[test]
    fn frr4_old_circuit_closed() {
        let mut rt = make_rt();
        rt.register_circuit(7, 1);
        rt.close_circuit(7, 2).unwrap();
        assert_eq!(rt.teardown_state(7), Some(TeardownState::Closed));
        assert_eq!(rt.circuits_closed(), 1);
    }

    // FRR5: peer score penalized on failure.
    #[test]
    fn frr5_peer_score_penalized() {
        let mut rt = make_rt();
        rt.register_peer(nid(3), 1);
        rt.register_circuit(5, 1);
        rt.handle_link_failure(nid(3), 5, 2).unwrap();
        let score = rt.peer_score(&nid(3)).unwrap();
        assert!(score < 0);
    }

    // FRR6: peer banned when score drops below threshold.
    #[test]
    fn frr6_peer_banned_on_low_score() {
        // threshold=-50, penalty=10, recovery_reward=5.
        // Score after N failures + (N-1) recoveries = -5N - 5.
        // Need N=10 to reach -55 < -50.
        let mut rt = FailureRecoveryRuntime::new(-50, 100, 10, 32);
        rt.register_peer(nid(7), 1);
        for cid in 0..10u64 {
            rt.register_circuit(cid + 100, 1);
            rt.handle_link_failure(nid(7), cid + 100, 2).unwrap();
            // reset link to Up for next iteration (without calling mark_up through recovery)
            if cid < 9 {
                let _ = rt.handle_link_recovery(nid(7), 3);
                rt.links.register(nid(7), 3);
            }
        }
        assert!(rt.is_peer_banned(&nid(7), 2));
    }

    // FRR7: relay path cache hit after assignment.
    #[test]
    fn frr7_relay_path_cache_hit() {
        let mut rt = make_rt();
        rt.register_peer(nid(1), 1);
        rt.register_circuit(1, 1);
        rt.handle_link_failure(nid(1), 1, 2).unwrap();
        rt.assign_replacement(1, 2, nid(20), nid(21), vec![nid(22), nid(23)], 2)
            .unwrap();
        // The path should be in the cache (not expired at epoch 5).
        let result = rt.path_cache.lookup(&nid(20), &nid(21), 5);
        assert!(result.is_ok());
    }

    // FRR8: link recovery marks link Up again.
    #[test]
    fn frr8_link_recovery() {
        let mut rt = make_rt();
        rt.register_peer(nid(8), 1);
        rt.register_circuit(88, 1);
        rt.handle_link_failure(nid(8), 88, 2).unwrap();
        assert!(!rt.is_link_up(&nid(8)));
        rt.handle_link_recovery(nid(8), 5);
        assert!(rt.is_link_up(&nid(8)));
    }

    // FRR9: two circuits fail independently.
    #[test]
    fn frr9_multiple_failed_circuits() {
        let mut rt = make_rt();
        rt.register_peer(nid(2), 1);
        rt.register_peer(nid(3), 1);
        rt.register_circuit(10, 1);
        rt.register_circuit(20, 1);
        rt.handle_link_failure(nid(2), 10, 2).unwrap();
        let _ = rt.handle_link_recovery(nid(2), 3);
        rt.links.register(nid(2), 3);
        rt.handle_link_failure(nid(3), 20, 3).unwrap();
        assert_eq!(rt.recoveries_initiated(), 2);
        assert_eq!(
            rt.recovery_state(10),
            Some(CircuitRecoveryState::Recovering)
        );
        assert_eq!(
            rt.recovery_state(20),
            Some(CircuitRecoveryState::Recovering)
        );
    }

    // FRR10: advance_epoch purges closed circuits.
    #[test]
    fn frr10_purge_clears_teardown() {
        let mut rt = make_rt();
        rt.register_circuit(99, 1);
        rt.close_circuit(99, 2).unwrap();
        assert_eq!(rt.active_teardowns(), 0); // already purged by close
        rt.advance_epoch(10);
        // No panic; teardown manager is clean.
        assert_eq!(rt.circuits_closed(), 1);
    }
}
