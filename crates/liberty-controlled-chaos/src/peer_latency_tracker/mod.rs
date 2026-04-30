//! Peer latency tracker — EWMA RTT estimation per peer.

use std::collections::HashMap;

const EWMA_ALPHA_NUM: u64 = 1;
const EWMA_ALPHA_DEN: u64 = 8;

#[derive(Debug, Clone)]
pub struct LatencyRecord {
    pub peer_id: [u8; 32],
    pub ewma_us: u64,
    pub samples: u64,
    pub min_us: u64,
    pub max_us: u64,
}

impl LatencyRecord {
    fn new(peer_id: [u8; 32]) -> Self {
        Self {
            peer_id,
            ewma_us: 0,
            samples: 0,
            min_us: u64::MAX,
            max_us: 0,
        }
    }

    fn record(&mut self, rtt_us: u64) {
        if self.samples == 0 {
            self.ewma_us = rtt_us;
        } else {
            self.ewma_us = (EWMA_ALPHA_NUM * rtt_us
                + (EWMA_ALPHA_DEN - EWMA_ALPHA_NUM) * self.ewma_us)
                / EWMA_ALPHA_DEN;
        }
        self.samples += 1;
        if rtt_us < self.min_us {
            self.min_us = rtt_us;
        }
        if rtt_us > self.max_us {
            self.max_us = rtt_us;
        }
    }
}

pub struct PeerLatencyTracker {
    records: HashMap<[u8; 32], LatencyRecord>,
    high_latency_threshold_us: u64,
}

impl PeerLatencyTracker {
    pub fn new(high_latency_threshold_us: u64) -> Self {
        Self {
            records: HashMap::new(),
            high_latency_threshold_us,
        }
    }

    pub fn record_rtt(&mut self, peer_id: [u8; 32], rtt_us: u64) {
        self.records
            .entry(peer_id)
            .or_insert_with(|| LatencyRecord::new(peer_id))
            .record(rtt_us);
    }

    pub fn get(&self, peer_id: &[u8; 32]) -> Option<&LatencyRecord> {
        self.records.get(peer_id)
    }

    pub fn is_high_latency(&self, peer_id: &[u8; 32]) -> bool {
        self.records
            .get(peer_id)
            .map(|r| r.ewma_us >= self.high_latency_threshold_us)
            .unwrap_or(false)
    }

    pub fn remove(&mut self, peer_id: &[u8; 32]) {
        self.records.remove(peer_id);
    }

    pub fn low_latency_peers(&self) -> Vec<[u8; 32]> {
        self.records
            .values()
            .filter(|r| r.ewma_us < self.high_latency_threshold_us)
            .map(|r| r.peer_id)
            .collect()
    }

    pub fn peer_count(&self) -> usize {
        self.records.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // PLT1: first sample sets ewma directly.
    #[test]
    fn plt1_first_sample() {
        let mut t = PeerLatencyTracker::new(1000);
        t.record_rtt(nid(1), 500);
        assert_eq!(t.get(&nid(1)).unwrap().ewma_us, 500);
    }

    // PLT2: samples counter increments.
    #[test]
    fn plt2_sample_count() {
        let mut t = PeerLatencyTracker::new(1000);
        t.record_rtt(nid(1), 100);
        t.record_rtt(nid(1), 200);
        assert_eq!(t.get(&nid(1)).unwrap().samples, 2);
    }

    // PLT3: min_us tracks minimum.
    #[test]
    fn plt3_min() {
        let mut t = PeerLatencyTracker::new(1000);
        t.record_rtt(nid(1), 300);
        t.record_rtt(nid(1), 100);
        t.record_rtt(nid(1), 500);
        assert_eq!(t.get(&nid(1)).unwrap().min_us, 100);
    }

    // PLT4: max_us tracks maximum.
    #[test]
    fn plt4_max() {
        let mut t = PeerLatencyTracker::new(1000);
        t.record_rtt(nid(1), 300);
        t.record_rtt(nid(1), 800);
        assert_eq!(t.get(&nid(1)).unwrap().max_us, 800);
    }

    // PLT5: is_high_latency true above threshold.
    #[test]
    fn plt5_high_latency() {
        let mut t = PeerLatencyTracker::new(200);
        t.record_rtt(nid(1), 500);
        assert!(t.is_high_latency(&nid(1)));
    }

    // PLT6: is_high_latency false below threshold.
    #[test]
    fn plt6_low_latency() {
        let mut t = PeerLatencyTracker::new(1000);
        t.record_rtt(nid(1), 50);
        assert!(!t.is_high_latency(&nid(1)));
    }

    // PLT7: unknown peer is not high latency.
    #[test]
    fn plt7_unknown_peer() {
        let t = PeerLatencyTracker::new(100);
        assert!(!t.is_high_latency(&nid(99)));
    }

    // PLT8: remove peer.
    #[test]
    fn plt8_remove() {
        let mut t = PeerLatencyTracker::new(1000);
        t.record_rtt(nid(1), 100);
        t.remove(&nid(1));
        assert!(t.get(&nid(1)).is_none());
    }

    // PLT9: low_latency_peers excludes high-latency.
    #[test]
    fn plt9_low_latency_peers() {
        let mut t = PeerLatencyTracker::new(300);
        t.record_rtt(nid(1), 100);
        t.record_rtt(nid(2), 500);
        let low = t.low_latency_peers();
        assert_eq!(low.len(), 1);
        assert_eq!(low[0], nid(1));
    }

    // PLT10: peer_count correct.
    #[test]
    fn plt10_peer_count() {
        let mut t = PeerLatencyTracker::new(1000);
        t.record_rtt(nid(1), 100);
        t.record_rtt(nid(2), 200);
        assert_eq!(t.peer_count(), 2);
    }
}
