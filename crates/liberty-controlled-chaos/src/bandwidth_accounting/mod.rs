//! Bandwidth accounting — tracks bytes sent/received per peer and per circuit.
//!
//! `reset_epoch()` clears epoch-level counters while preserving all-time totals.
//! Peer and circuit records are created on first access (lazy initialisation).

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// BandwidthCounter
// ---------------------------------------------------------------------------

/// Per-entity byte counters.
#[derive(Debug, Clone, Default)]
pub struct BandwidthCounter {
    /// Bytes sent this epoch.
    pub bytes_sent_epoch: u64,
    /// Bytes received this epoch.
    pub bytes_recv_epoch: u64,
    /// All-time bytes sent.
    pub bytes_sent_total: u64,
    /// All-time bytes received.
    pub bytes_recv_total: u64,
}

impl BandwidthCounter {
    fn record_send(&mut self, bytes: u64) {
        self.bytes_sent_epoch = self.bytes_sent_epoch.saturating_add(bytes);
        self.bytes_sent_total = self.bytes_sent_total.saturating_add(bytes);
    }

    fn record_recv(&mut self, bytes: u64) {
        self.bytes_recv_epoch = self.bytes_recv_epoch.saturating_add(bytes);
        self.bytes_recv_total = self.bytes_recv_total.saturating_add(bytes);
    }

    fn reset_epoch(&mut self) {
        self.bytes_sent_epoch = 0;
        self.bytes_recv_epoch = 0;
    }
}

// ---------------------------------------------------------------------------
// BandwidthAccounting
// ---------------------------------------------------------------------------

/// Tracks bandwidth usage per peer (identified by `[u8; 32]`) and per circuit
/// (identified by `u64`).
pub struct BandwidthAccounting {
    peer_stats: HashMap<[u8; 32], BandwidthCounter>,
    circuit_stats: HashMap<u64, BandwidthCounter>,
    /// Current epoch number.
    current_epoch: u64,
}

impl BandwidthAccounting {
    pub fn new() -> Self {
        Self {
            peer_stats: HashMap::new(),
            circuit_stats: HashMap::new(),
            current_epoch: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Peer accounting
    // -----------------------------------------------------------------------

    /// Record `bytes` sent to a peer.
    pub fn record_send(&mut self, peer: [u8; 32], bytes: u64) {
        self.peer_stats.entry(peer).or_default().record_send(bytes);
    }

    /// Record `bytes` received from a peer.
    pub fn record_recv(&mut self, peer: [u8; 32], bytes: u64) {
        self.peer_stats.entry(peer).or_default().record_recv(bytes);
    }

    /// Get a peer's bandwidth counters.
    pub fn peer(&self, peer: &[u8; 32]) -> Option<&BandwidthCounter> {
        self.peer_stats.get(peer)
    }

    // -----------------------------------------------------------------------
    // Circuit accounting
    // -----------------------------------------------------------------------

    /// Record `bytes` sent on a circuit.
    pub fn record_circuit_send(&mut self, circuit_id: u64, bytes: u64) {
        self.circuit_stats
            .entry(circuit_id)
            .or_default()
            .record_send(bytes);
    }

    /// Record `bytes` received on a circuit.
    pub fn record_circuit_recv(&mut self, circuit_id: u64, bytes: u64) {
        self.circuit_stats
            .entry(circuit_id)
            .or_default()
            .record_recv(bytes);
    }

    /// Get a circuit's bandwidth counters.
    pub fn circuit(&self, circuit_id: u64) -> Option<&BandwidthCounter> {
        self.circuit_stats.get(&circuit_id)
    }

    // -----------------------------------------------------------------------
    // Epoch management
    // -----------------------------------------------------------------------

    /// Advance to `epoch` and reset per-epoch counters.
    pub fn reset_epoch(&mut self, epoch: u64) {
        self.current_epoch = epoch;
        for c in self.peer_stats.values_mut() {
            c.reset_epoch();
        }
        for c in self.circuit_stats.values_mut() {
            c.reset_epoch();
        }
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    // -----------------------------------------------------------------------
    // Aggregates
    // -----------------------------------------------------------------------

    /// Total bytes sent across all peers this epoch.
    pub fn total_sent_epoch(&self) -> u64 {
        self.peer_stats.values().map(|c| c.bytes_sent_epoch).sum()
    }

    /// Total bytes received across all peers this epoch.
    pub fn total_recv_epoch(&self) -> u64 {
        self.peer_stats.values().map(|c| c.bytes_recv_epoch).sum()
    }

    /// Total bytes sent across all peers all time.
    pub fn total_sent_all_time(&self) -> u64 {
        self.peer_stats.values().map(|c| c.bytes_sent_total).sum()
    }

    pub fn peer_count(&self) -> usize {
        self.peer_stats.len()
    }

    pub fn circuit_count(&self) -> usize {
        self.circuit_stats.len()
    }
}

impl Default for BandwidthAccounting {
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

    // BA1: record_send updates peer bytes_sent counters.
    #[test]
    fn ba1_send_accounting() {
        let mut ba = BandwidthAccounting::new();
        ba.record_send(nid(1), 512);
        let c = ba.peer(&nid(1)).unwrap();
        assert_eq!(c.bytes_sent_epoch, 512);
        assert_eq!(c.bytes_sent_total, 512);
    }

    // BA2: record_recv updates peer bytes_recv counters.
    #[test]
    fn ba2_recv_accounting() {
        let mut ba = BandwidthAccounting::new();
        ba.record_recv(nid(1), 1024);
        let c = ba.peer(&nid(1)).unwrap();
        assert_eq!(c.bytes_recv_epoch, 1024);
        assert_eq!(c.bytes_recv_total, 1024);
    }

    // BA3: record_circuit_send tracks circuit bytes.
    #[test]
    fn ba3_circuit_accounting() {
        let mut ba = BandwidthAccounting::new();
        ba.record_circuit_send(42, 256);
        let c = ba.circuit(42).unwrap();
        assert_eq!(c.bytes_sent_epoch, 256);
        assert_eq!(c.bytes_sent_total, 256);
    }

    // BA4: reset_epoch clears per-epoch counters but not totals.
    #[test]
    fn ba4_epoch_reset() {
        let mut ba = BandwidthAccounting::new();
        ba.record_send(nid(1), 100);
        ba.record_recv(nid(1), 200);
        ba.reset_epoch(1);
        let c = ba.peer(&nid(1)).unwrap();
        assert_eq!(c.bytes_sent_epoch, 0);
        assert_eq!(c.bytes_recv_epoch, 0);
        assert_eq!(c.bytes_sent_total, 100);
        assert_eq!(c.bytes_recv_total, 200);
    }

    // BA5: multiple peers are tracked independently.
    #[test]
    fn ba5_multi_peer_stats() {
        let mut ba = BandwidthAccounting::new();
        ba.record_send(nid(1), 100);
        ba.record_send(nid(2), 200);
        assert_eq!(ba.peer(&nid(1)).unwrap().bytes_sent_total, 100);
        assert_eq!(ba.peer(&nid(2)).unwrap().bytes_sent_total, 200);
        assert_eq!(ba.peer_count(), 2);
    }

    // BA6: multiple circuits are tracked independently.
    #[test]
    fn ba6_multi_circuit_stats() {
        let mut ba = BandwidthAccounting::new();
        ba.record_circuit_send(1, 50);
        ba.record_circuit_send(2, 150);
        assert_eq!(ba.circuit(1).unwrap().bytes_sent_total, 50);
        assert_eq!(ba.circuit(2).unwrap().bytes_sent_total, 150);
        assert_eq!(ba.circuit_count(), 2);
    }

    // BA7: large transfers accumulate correctly.
    #[test]
    fn ba7_large_transfers() {
        let mut ba = BandwidthAccounting::new();
        let gb = 1024 * 1024 * 1024u64;
        ba.record_send(nid(1), gb);
        ba.record_send(nid(1), gb);
        assert_eq!(ba.peer(&nid(1)).unwrap().bytes_sent_total, 2 * gb);
    }

    // BA8: zero-byte transfer is a no-op for totals but still registers entry.
    #[test]
    fn ba8_zero_transfers() {
        let mut ba = BandwidthAccounting::new();
        ba.record_send(nid(1), 0);
        let c = ba.peer(&nid(1)).unwrap();
        assert_eq!(c.bytes_sent_total, 0);
    }

    // BA9: stress — 1000 peers, 1000 circuits, all accounted.
    #[test]
    fn ba9_stress_accounting() {
        let mut ba = BandwidthAccounting::new();
        for i in 0u8..=255 {
            for j in 0u8..4 {
                let peer = {
                    let mut id = [0u8; 32];
                    id[0] = i;
                    id[1] = j;
                    id
                };
                ba.record_send(peer, 64);
            }
        }
        assert_eq!(ba.peer_count(), 256 * 4);
        assert_eq!(ba.total_sent_all_time(), 256 * 4 * 64);
    }

    // BA10: accuracy — total_sent_epoch matches sum of individual send calls.
    #[test]
    fn ba10_accuracy_validation() {
        let mut ba = BandwidthAccounting::new();
        let amounts = [100u64, 200, 300, 400, 500];
        for (i, &amt) in amounts.iter().enumerate() {
            ba.record_send(nid(i as u8), amt);
        }
        let expected: u64 = amounts.iter().sum();
        assert_eq!(ba.total_sent_epoch(), expected);
        assert_eq!(ba.total_sent_all_time(), expected);
    }

    // BA11: epoch counter advances correctly with reset_epoch.
    #[test]
    fn ba11_epoch_counter() {
        let mut ba = BandwidthAccounting::new();
        assert_eq!(ba.current_epoch(), 0);
        ba.reset_epoch(5);
        assert_eq!(ba.current_epoch(), 5);
        ba.record_send(nid(1), 100);
        ba.reset_epoch(6);
        assert_eq!(ba.current_epoch(), 6);
        assert_eq!(ba.peer(&nid(1)).unwrap().bytes_sent_epoch, 0);
        assert_eq!(ba.peer(&nid(1)).unwrap().bytes_sent_total, 100);
    }
}
