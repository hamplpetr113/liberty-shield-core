//! Relay heartbeat — tracks liveness pings and peer keepalive state.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatState {
    Alive,
    Suspicious,
    Dead,
}

#[derive(Debug, Clone)]
pub struct HeartbeatRecord {
    pub peer_id: [u8; 32],
    pub state: HeartbeatState,
    pub last_pong_epoch: u64,
    pub missed: u64,
    pub total_pings: u64,
    pub total_pongs: u64,
}

impl HeartbeatRecord {
    fn new(peer_id: [u8; 32]) -> Self {
        Self {
            peer_id,
            state: HeartbeatState::Alive,
            last_pong_epoch: 0,
            missed: 0,
            total_pings: 0,
            total_pongs: 0,
        }
    }
}

pub struct RelayHeartbeat {
    records: HashMap<[u8; 32], HeartbeatRecord>,
    suspicious_threshold: u64,
    dead_threshold: u64,
}

impl RelayHeartbeat {
    pub fn new(suspicious_threshold: u64, dead_threshold: u64) -> Self {
        Self {
            records: HashMap::new(),
            suspicious_threshold,
            dead_threshold,
        }
    }

    pub fn register(&mut self, peer_id: [u8; 32]) {
        self.records
            .entry(peer_id)
            .or_insert_with(|| HeartbeatRecord::new(peer_id));
    }

    pub fn send_ping(&mut self, peer_id: [u8; 32]) {
        let r = self
            .records
            .entry(peer_id)
            .or_insert_with(|| HeartbeatRecord::new(peer_id));
        r.total_pings += 1;
        r.missed += 1;
        r.state = if r.missed >= self.dead_threshold {
            HeartbeatState::Dead
        } else if r.missed >= self.suspicious_threshold {
            HeartbeatState::Suspicious
        } else {
            HeartbeatState::Alive
        };
    }

    pub fn recv_pong(&mut self, peer_id: [u8; 32], epoch: u64) {
        if let Some(r) = self.records.get_mut(&peer_id) {
            r.total_pongs += 1;
            r.missed = 0;
            r.last_pong_epoch = epoch;
            r.state = HeartbeatState::Alive;
        }
    }

    pub fn get(&self, peer_id: &[u8; 32]) -> Option<&HeartbeatRecord> {
        self.records.get(peer_id)
    }

    pub fn is_alive(&self, peer_id: &[u8; 32]) -> bool {
        self.records
            .get(peer_id)
            .map(|r| r.state == HeartbeatState::Alive)
            .unwrap_or(false)
    }

    pub fn dead_peers(&self) -> Vec<[u8; 32]> {
        self.records
            .values()
            .filter(|r| r.state == HeartbeatState::Dead)
            .map(|r| r.peer_id)
            .collect()
    }

    pub fn remove(&mut self, peer_id: &[u8; 32]) {
        self.records.remove(peer_id);
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

    // RH1: freshly registered peer is Alive.
    #[test]
    fn rh1_registered_alive() {
        let mut h = RelayHeartbeat::new(2, 4);
        h.register(nid(1));
        assert!(h.is_alive(&nid(1)));
    }

    // RH2: missed pings make peer Suspicious.
    #[test]
    fn rh2_suspicious() {
        let mut h = RelayHeartbeat::new(2, 4);
        h.send_ping(nid(1));
        h.send_ping(nid(1));
        assert_eq!(h.get(&nid(1)).unwrap().state, HeartbeatState::Suspicious);
    }

    // RH3: missed pings at dead_threshold mark Dead.
    #[test]
    fn rh3_dead() {
        let mut h = RelayHeartbeat::new(2, 3);
        h.send_ping(nid(1));
        h.send_ping(nid(1));
        h.send_ping(nid(1));
        assert_eq!(h.get(&nid(1)).unwrap().state, HeartbeatState::Dead);
    }

    // RH4: pong resets missed count.
    #[test]
    fn rh4_pong_reset() {
        let mut h = RelayHeartbeat::new(2, 4);
        h.send_ping(nid(1));
        h.send_ping(nid(1));
        h.recv_pong(nid(1), 5);
        assert_eq!(h.get(&nid(1)).unwrap().missed, 0);
    }

    // RH5: pong marks Alive.
    #[test]
    fn rh5_pong_alive() {
        let mut h = RelayHeartbeat::new(2, 4);
        h.send_ping(nid(1));
        h.send_ping(nid(1));
        h.recv_pong(nid(1), 5);
        assert!(h.is_alive(&nid(1)));
    }

    // RH6: total_pings counter increments.
    #[test]
    fn rh6_total_pings() {
        let mut h = RelayHeartbeat::new(2, 4);
        h.send_ping(nid(1));
        h.send_ping(nid(1));
        assert_eq!(h.get(&nid(1)).unwrap().total_pings, 2);
    }

    // RH7: total_pongs counter increments.
    #[test]
    fn rh7_total_pongs() {
        let mut h = RelayHeartbeat::new(2, 4);
        h.register(nid(1));
        h.recv_pong(nid(1), 1);
        assert_eq!(h.get(&nid(1)).unwrap().total_pongs, 1);
    }

    // RH8: dead_peers returns correct list.
    #[test]
    fn rh8_dead_peers() {
        let mut h = RelayHeartbeat::new(2, 2);
        h.send_ping(nid(1));
        h.send_ping(nid(1));
        h.register(nid(2));
        assert_eq!(h.dead_peers().len(), 1);
    }

    // RH9: remove deletes peer.
    #[test]
    fn rh9_remove() {
        let mut h = RelayHeartbeat::new(2, 4);
        h.register(nid(1));
        h.remove(&nid(1));
        assert_eq!(h.peer_count(), 0);
    }

    // RH10: unknown peer is_alive returns false.
    #[test]
    fn rh10_unknown_alive() {
        let h = RelayHeartbeat::new(2, 4);
        assert!(!h.is_alive(&nid(99)));
    }
}
