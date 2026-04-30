//! Link quality monitor — tracks packet loss and jitter per link.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct LinkStats {
    pub peer_id: [u8; 32],
    pub sent: u64,
    pub lost: u64,
    pub jitter_sum_us: u64,
    pub jitter_samples: u64,
    pub last_epoch: u64,
}

impl LinkStats {
    fn new(peer_id: [u8; 32]) -> Self {
        Self {
            peer_id,
            sent: 0,
            lost: 0,
            jitter_sum_us: 0,
            jitter_samples: 0,
            last_epoch: 0,
        }
    }

    pub fn loss_rate(&self) -> f64 {
        if self.sent == 0 {
            return 0.0;
        }
        self.lost as f64 / self.sent as f64
    }

    pub fn mean_jitter_us(&self) -> u64 {
        if self.jitter_samples == 0 {
            return 0;
        }
        self.jitter_sum_us / self.jitter_samples
    }
}

pub struct LinkQualityMonitor {
    links: HashMap<[u8; 32], LinkStats>,
    loss_threshold: f64,
}

impl LinkQualityMonitor {
    pub fn new(loss_threshold: f64) -> Self {
        Self {
            links: HashMap::new(),
            loss_threshold,
        }
    }

    fn ensure(&mut self, peer_id: [u8; 32]) {
        self.links
            .entry(peer_id)
            .or_insert_with(|| LinkStats::new(peer_id));
    }

    pub fn record_sent(&mut self, peer_id: [u8; 32], epoch: u64) {
        self.ensure(peer_id);
        let s = self.links.get_mut(&peer_id).unwrap();
        s.sent += 1;
        s.last_epoch = epoch;
    }

    pub fn record_lost(&mut self, peer_id: [u8; 32], epoch: u64) {
        self.ensure(peer_id);
        let s = self.links.get_mut(&peer_id).unwrap();
        s.lost += 1;
        s.last_epoch = epoch;
    }

    pub fn record_jitter(&mut self, peer_id: [u8; 32], jitter_us: u64) {
        self.ensure(peer_id);
        let s = self.links.get_mut(&peer_id).unwrap();
        s.jitter_sum_us = s.jitter_sum_us.saturating_add(jitter_us);
        s.jitter_samples += 1;
    }

    pub fn stats(&self, peer_id: &[u8; 32]) -> Option<&LinkStats> {
        self.links.get(peer_id)
    }

    pub fn is_degraded(&self, peer_id: &[u8; 32]) -> bool {
        self.links
            .get(peer_id)
            .map(|s| s.loss_rate() >= self.loss_threshold)
            .unwrap_or(false)
    }

    pub fn remove(&mut self, peer_id: &[u8; 32]) {
        self.links.remove(peer_id);
    }

    pub fn degraded_peers(&self) -> Vec<[u8; 32]> {
        self.links
            .values()
            .filter(|s| s.loss_rate() >= self.loss_threshold)
            .map(|s| s.peer_id)
            .collect()
    }

    pub fn link_count(&self) -> usize {
        self.links.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // LQM1: record_sent increments sent counter.
    #[test]
    fn lqm1_record_sent() {
        let mut m = LinkQualityMonitor::new(0.5);
        m.record_sent(nid(1), 1);
        assert_eq!(m.stats(&nid(1)).unwrap().sent, 1);
    }

    // LQM2: record_lost increments lost counter.
    #[test]
    fn lqm2_record_lost() {
        let mut m = LinkQualityMonitor::new(0.5);
        m.record_lost(nid(1), 1);
        assert_eq!(m.stats(&nid(1)).unwrap().lost, 1);
    }

    // LQM3: loss_rate computed correctly.
    #[test]
    fn lqm3_loss_rate() {
        let mut m = LinkQualityMonitor::new(0.5);
        m.record_sent(nid(1), 1);
        m.record_sent(nid(1), 1);
        m.record_lost(nid(1), 1);
        let rate = m.stats(&nid(1)).unwrap().loss_rate();
        assert!((rate - 0.5).abs() < 1e-9);
    }

    // LQM4: is_degraded true when loss at threshold.
    #[test]
    fn lqm4_degraded() {
        let mut m = LinkQualityMonitor::new(0.5);
        m.record_sent(nid(1), 1);
        m.record_lost(nid(1), 1);
        assert!(m.is_degraded(&nid(1)));
    }

    // LQM5: is_degraded false below threshold.
    #[test]
    fn lqm5_not_degraded() {
        let mut m = LinkQualityMonitor::new(0.5);
        m.record_sent(nid(1), 1);
        assert!(!m.is_degraded(&nid(1)));
    }

    // LQM6: record_jitter accumulates.
    #[test]
    fn lqm6_jitter() {
        let mut m = LinkQualityMonitor::new(0.5);
        m.record_jitter(nid(1), 100);
        m.record_jitter(nid(1), 200);
        assert_eq!(m.stats(&nid(1)).unwrap().mean_jitter_us(), 150);
    }

    // LQM7: unknown peer is not degraded.
    #[test]
    fn lqm7_unknown_peer() {
        let m = LinkQualityMonitor::new(0.1);
        assert!(!m.is_degraded(&nid(99)));
    }

    // LQM8: remove peer.
    #[test]
    fn lqm8_remove() {
        let mut m = LinkQualityMonitor::new(0.5);
        m.record_sent(nid(1), 1);
        m.remove(&nid(1));
        assert!(m.stats(&nid(1)).is_none());
    }

    // LQM9: degraded_peers filters correctly.
    #[test]
    fn lqm9_degraded_peers() {
        let mut m = LinkQualityMonitor::new(0.5);
        m.record_sent(nid(1), 1);
        m.record_sent(nid(2), 1);
        m.record_lost(nid(2), 1);
        let d = m.degraded_peers();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0], nid(2));
    }

    // LQM10: link_count correct.
    #[test]
    fn lqm10_link_count() {
        let mut m = LinkQualityMonitor::new(0.5);
        m.record_sent(nid(1), 1);
        m.record_sent(nid(2), 1);
        assert_eq!(m.link_count(), 2);
    }
}
