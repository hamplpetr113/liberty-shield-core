//! Network runtime — glues peer table, circuit manager, scheduler,
//! congestion controller, and optional UDP transport into a single epoch-driven
//! runtime loop.
//!
//! `run_epoch(epoch)` is the main tick:
//!   1. Rotate expired/idle circuits.
//!   2. Try to drain the circuit scheduler through the congestion controller.
//!   3. Collect and return metrics.
//!
//! The UDP link is optional: when present, `process_incoming()` drains the
//! socket; when absent the runtime operates in pure in-memory mode (useful for
//! tests).
//!
//! NON-PRODUCTION: no authentication, no real encryption at this layer.

use crate::circuit_manager::{CircuitManager, CircuitState};
use crate::circuit_scheduler::CircuitScheduler;
use crate::congestion_controller::CongestionController;
use crate::peer_table::PeerTable;
use crate::transport::UdpLink;

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Snapshot of runtime metrics for one epoch.
#[derive(Debug, Clone, Default)]
pub struct NetworkMetrics {
    pub epoch: u64,
    /// Packets drained from the scheduler this epoch.
    pub packets_scheduled: u32,
    /// Packets received from the UDP socket this epoch (0 if no socket).
    pub packets_received: u32,
    /// Circuits rotated to the `Rotating` state.
    pub circuits_rotated: u32,
    /// Circuits closed due to idleness.
    pub circuits_expired: u32,
    /// Number of packets blocked by congestion control.
    pub congestion_drops: u32,
    /// Active (Open) circuits at end of epoch.
    pub active_circuits: u32,
    /// Connected peers.
    pub connected_peers: u32,
}

// ---------------------------------------------------------------------------
// NetworkRuntime
// ---------------------------------------------------------------------------

/// Integrated network runtime.
pub struct NetworkRuntime {
    pub peer_table: PeerTable,
    pub circuit_manager: CircuitManager,
    pub circuit_scheduler: CircuitScheduler,
    pub congestion_controller: CongestionController,
    /// Optional UDP transport.  `None` in pure in-memory mode.
    pub udp_link: Option<UdpLink>,
    /// Maximum epochs a circuit may remain idle before expiry.
    pub max_idle_epochs: u64,
    /// Last epoch number processed.
    current_epoch: u64,
}

impl NetworkRuntime {
    /// Create a runtime without a UDP socket.
    pub fn new(congestion_window: u32, max_window: u32) -> Self {
        Self {
            peer_table: PeerTable::new(),
            circuit_manager: CircuitManager::new(),
            circuit_scheduler: CircuitScheduler::new(),
            congestion_controller: CongestionController::new(congestion_window, max_window),
            udp_link: None,
            max_idle_epochs: 10,
            current_epoch: 0,
        }
    }

    /// Attach a UDP link.
    pub fn with_udp(mut self, link: UdpLink) -> Self {
        self.udp_link = Some(link);
        self
    }

    // -----------------------------------------------------------------------
    // Core API
    // -----------------------------------------------------------------------

    /// Drive one epoch of work.  Returns epoch metrics.
    pub fn run_epoch(&mut self, epoch: u64) -> NetworkMetrics {
        self.current_epoch = epoch;

        let mut metrics = NetworkMetrics {
            epoch,
            ..Default::default()
        };

        // 1. Rotate and expire circuits.
        let rotated = self.rotate_circuits(epoch);
        metrics.circuits_rotated = rotated as u32;

        let expired = self
            .circuit_manager
            .expire_idle(epoch, self.max_idle_epochs);
        metrics.circuits_expired = expired.len() as u32;

        // 2. Process incoming UDP datagrams (non-blocking; errors ignored).
        metrics.packets_received = self.process_incoming();

        // 3. Schedule outgoing packets.
        let (scheduled, blocked) = self.schedule_outgoing();
        metrics.packets_scheduled = scheduled;
        metrics.congestion_drops = blocked;

        // 4. Collect counts.
        metrics.active_circuits = self.circuit_manager.count_in_state(CircuitState::Open) as u32;
        metrics.connected_peers = self.peer_table.best_peers(usize::MAX).len() as u32;

        metrics
    }

    /// Drain the UDP socket until it would block.
    ///
    /// Returns the number of datagrams received.  Always returns 0 if there is
    /// no UDP link.
    pub fn process_incoming(&mut self) -> u32 {
        let Some(link) = &self.udp_link else {
            return 0;
        };
        link.set_nonblocking(true).ok();
        let mut count = 0u32;
        while link.recv().is_ok() {
            count += 1;
            // In a real runtime we'd decrypt and dispatch here.
        }
        count
    }

    /// Drain the circuit scheduler up to the congestion window.
    ///
    /// Returns `(packets_scheduled, packets_blocked_by_congestion)`.
    pub fn schedule_outgoing(&mut self) -> (u32, u32) {
        let mut scheduled = 0u32;
        let mut blocked = 0u32;

        while self.circuit_scheduler.total_queued() > 0 {
            if !self.congestion_controller.can_send() {
                blocked += 1;
                break;
            }
            if let Some(_cid) = self.circuit_scheduler.select_next() {
                self.congestion_controller.on_packet_sent();
                scheduled += 1;
            } else {
                break;
            }
        }
        (scheduled, blocked)
    }

    /// Transition Open circuits to Rotating when they exceed the epoch budget.
    ///
    /// Returns the number of circuits rotated.
    pub fn rotate_circuits(&mut self, current_epoch: u64) -> usize {
        self.circuit_manager.rotate_expired(current_epoch).len()
    }

    /// Collect a metrics snapshot without running an epoch.
    pub fn collect_metrics(&self) -> NetworkMetrics {
        NetworkMetrics {
            epoch: self.current_epoch,
            active_circuits: self.circuit_manager.count_in_state(CircuitState::Open) as u32,
            connected_peers: self.peer_table.best_peers(usize::MAX).len() as u32,
            ..Default::default()
        }
    }

    // -----------------------------------------------------------------------
    // Helpers for tests
    // -----------------------------------------------------------------------

    /// Simulate an ACK for all in-flight packets (collapses inflight to 0).
    pub fn ack_all(&mut self) {
        while self.congestion_controller.inflight_packets() > 0 {
            self.congestion_controller.on_ack(10.0);
        }
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> NetworkRuntime {
        NetworkRuntime::new(16, 128)
    }

    // NR1: runtime starts with sensible defaults.
    #[test]
    fn nr1_runtime_start() {
        let r = rt();
        assert_eq!(r.circuit_manager.len(), 0);
        assert_eq!(r.circuit_scheduler.len(), 0);
        assert_eq!(r.congestion_controller.send_window(), 16);
        assert!(r.udp_link.is_none());
    }

    // NR2: process_incoming returns 0 when no UDP link is attached.
    #[test]
    fn nr2_process_incoming_no_udp() {
        let mut r = rt();
        assert_eq!(r.process_incoming(), 0);
    }

    // NR3: schedule_outgoing drains queued packets through the congestion window.
    #[test]
    fn nr3_schedule_outgoing() {
        let mut r = rt();
        // Set up a circuit and enqueue packets.
        let cid = r
            .circuit_manager
            .create_circuit([1u8; 32], [2u8; 32], [3u8; 32], 0);
        r.circuit_manager.mark_open(cid).unwrap();
        for _ in 0..8 {
            r.circuit_scheduler.enqueue_packet(cid.value());
        }
        let (scheduled, blocked) = r.schedule_outgoing();
        assert_eq!(scheduled, 8);
        assert_eq!(blocked, 0);
    }

    // NR4: circuit rotation moves old circuits to Rotating.
    #[test]
    fn nr4_circuit_rotation() {
        let mut r = rt();
        let cid = r
            .circuit_manager
            .create_circuit([1u8; 32], [2u8; 32], [3u8; 32], 1);
        r.circuit_manager.mark_open(cid).unwrap();
        let rotated = r.rotate_circuits(5);
        assert_eq!(rotated, 1);
        assert_eq!(
            r.circuit_manager.get_circuit(cid).unwrap().state,
            CircuitState::Rotating
        );
    }

    // NR5: congestion limit blocks send when window is full.
    #[test]
    fn nr5_congestion_limit() {
        let mut r = NetworkRuntime::new(2, 2);
        let cid = r
            .circuit_manager
            .create_circuit([1u8; 32], [2u8; 32], [3u8; 32], 0);
        r.circuit_manager.mark_open(cid).unwrap();
        // Enqueue 10 packets but window is only 2.
        for _ in 0..10 {
            r.circuit_scheduler.enqueue_packet(cid.value());
        }
        let (scheduled, blocked) = r.schedule_outgoing();
        assert_eq!(scheduled, 2);
        assert!(blocked > 0);
    }

    // NR6: peer scoring integration — reward a peer and verify score improves.
    #[test]
    fn nr6_peer_scoring_integration() {
        let mut r = rt();
        let node = [0xABu8; 32];
        r.peer_table.add_peer(node, 0).unwrap();
        r.peer_table.reward_peer(&node).unwrap();
        let score = r.peer_table.get(&node).unwrap().reputation_score;
        assert_eq!(score, 55);
    }

    // NR7: scheduler integration — enqueue on multiple circuits, select rotates.
    #[test]
    fn nr7_scheduler_integration() {
        let mut r = rt();
        r.circuit_scheduler.enqueue_packet(10);
        r.circuit_scheduler.enqueue_packet(20);
        let mut seen = std::collections::HashSet::new();
        while r.circuit_scheduler.total_queued() > 0 {
            if r.congestion_controller.can_send() {
                if let Some(cid) = r.circuit_scheduler.select_next() {
                    r.congestion_controller.on_packet_sent();
                    seen.insert(cid);
                }
            }
        }
        assert!(seen.contains(&10));
        assert!(seen.contains(&20));
    }

    // NR8: multi-circuit send via run_epoch schedules from all circuits.
    #[test]
    fn nr8_multi_circuit_send() {
        let mut r = rt();
        for i in 1u64..=4 {
            r.circuit_scheduler.enqueue_packet(i);
        }
        let metrics = r.run_epoch(1);
        assert_eq!(metrics.packets_scheduled, 4);
    }

    // NR9: runtime stability — 10 epochs of run_epoch without panic.
    #[test]
    fn nr9_runtime_stability() {
        let mut r = rt();
        let cid = r
            .circuit_manager
            .create_circuit([1u8; 32], [2u8; 32], [3u8; 32], 1);
        r.circuit_manager.mark_open(cid).unwrap();
        for epoch in 1u64..=10 {
            r.circuit_scheduler.enqueue_packet(cid.value());
            let metrics = r.run_epoch(epoch);
            r.ack_all();
            assert_eq!(metrics.epoch, epoch);
        }
    }

    // NR10: stress — 1000 packets across 10 circuits, all drain within budget.
    #[test]
    fn nr10_stress_1000_packets() {
        let mut r = NetworkRuntime::new(128, 1024);
        for cid in 1u64..=10 {
            for _ in 0..100 {
                r.circuit_scheduler.enqueue_packet(cid);
            }
        }
        assert_eq!(r.circuit_scheduler.total_queued(), 1000);
        let mut total_scheduled = 0u32;
        // Run epochs until the queue drains.
        for epoch in 1u64..=20 {
            let metrics = r.run_epoch(epoch);
            total_scheduled += metrics.packets_scheduled;
            r.ack_all();
            if r.circuit_scheduler.total_queued() == 0 {
                break;
            }
        }
        assert_eq!(total_scheduled, 1000);
        assert_eq!(r.circuit_scheduler.total_queued(), 0);
    }
}
