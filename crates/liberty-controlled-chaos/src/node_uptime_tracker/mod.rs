//! Node uptime tracker — epoch-granularity uptime/downtime accounting.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    Online,
    Offline,
}

#[derive(Debug, Clone)]
pub struct UptimeRecord {
    pub node_id: [u8; 32],
    pub status: NodeStatus,
    pub online_epochs: u64,
    pub offline_epochs: u64,
    pub last_seen_epoch: u64,
    pub transitions: u64,
}

impl UptimeRecord {
    fn new(node_id: [u8; 32]) -> Self {
        Self {
            node_id,
            status: NodeStatus::Offline,
            online_epochs: 0,
            offline_epochs: 0,
            last_seen_epoch: 0,
            transitions: 0,
        }
    }

    pub fn uptime_ratio(&self) -> f64 {
        let total = self.online_epochs + self.offline_epochs;
        if total == 0 {
            return 0.0;
        }
        self.online_epochs as f64 / total as f64
    }
}

pub struct NodeUptimeTracker {
    records: HashMap<[u8; 32], UptimeRecord>,
}

impl NodeUptimeTracker {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    pub fn register(&mut self, node_id: [u8; 32]) {
        self.records
            .entry(node_id)
            .or_insert_with(|| UptimeRecord::new(node_id));
    }

    pub fn mark_online(&mut self, node_id: [u8; 32], epoch: u64) {
        let r = self
            .records
            .entry(node_id)
            .or_insert_with(|| UptimeRecord::new(node_id));
        if r.status != NodeStatus::Online {
            r.transitions += 1;
        }
        r.status = NodeStatus::Online;
        r.last_seen_epoch = epoch;
    }

    pub fn mark_offline(&mut self, node_id: [u8; 32], epoch: u64) {
        let r = self
            .records
            .entry(node_id)
            .or_insert_with(|| UptimeRecord::new(node_id));
        if r.status != NodeStatus::Offline {
            r.transitions += 1;
        }
        r.status = NodeStatus::Offline;
        r.last_seen_epoch = epoch;
    }

    /// Tick all known nodes — increments appropriate epoch counters.
    pub fn tick(&mut self, epoch: u64) {
        for r in self.records.values_mut() {
            match r.status {
                NodeStatus::Online => r.online_epochs += 1,
                NodeStatus::Offline => r.offline_epochs += 1,
            }
            let _ = epoch;
        }
    }

    pub fn get(&self, node_id: &[u8; 32]) -> Option<&UptimeRecord> {
        self.records.get(node_id)
    }

    pub fn online_nodes(&self) -> Vec<[u8; 32]> {
        self.records
            .values()
            .filter(|r| r.status == NodeStatus::Online)
            .map(|r| r.node_id)
            .collect()
    }

    pub fn remove(&mut self, node_id: &[u8; 32]) {
        self.records.remove(node_id);
    }

    pub fn node_count(&self) -> usize {
        self.records.len()
    }
}

impl Default for NodeUptimeTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // NUT1: new node starts offline.
    #[test]
    fn nut1_starts_offline() {
        let mut t = NodeUptimeTracker::new();
        t.register(nid(1));
        assert_eq!(t.get(&nid(1)).unwrap().status, NodeStatus::Offline);
    }

    // NUT2: mark_online changes status.
    #[test]
    fn nut2_mark_online() {
        let mut t = NodeUptimeTracker::new();
        t.mark_online(nid(1), 1);
        assert_eq!(t.get(&nid(1)).unwrap().status, NodeStatus::Online);
    }

    // NUT3: mark_offline changes status.
    #[test]
    fn nut3_mark_offline() {
        let mut t = NodeUptimeTracker::new();
        t.mark_online(nid(1), 1);
        t.mark_offline(nid(1), 2);
        assert_eq!(t.get(&nid(1)).unwrap().status, NodeStatus::Offline);
    }

    // NUT4: tick increments online_epochs for online nodes.
    #[test]
    fn nut4_tick_online() {
        let mut t = NodeUptimeTracker::new();
        t.mark_online(nid(1), 0);
        t.tick(1);
        t.tick(2);
        assert_eq!(t.get(&nid(1)).unwrap().online_epochs, 2);
    }

    // NUT5: tick increments offline_epochs for offline nodes.
    #[test]
    fn nut5_tick_offline() {
        let mut t = NodeUptimeTracker::new();
        t.register(nid(1));
        t.tick(1);
        assert_eq!(t.get(&nid(1)).unwrap().offline_epochs, 1);
    }

    // NUT6: transitions count state changes.
    #[test]
    fn nut6_transitions() {
        let mut t = NodeUptimeTracker::new();
        t.mark_online(nid(1), 1);
        t.mark_offline(nid(1), 2);
        t.mark_online(nid(1), 3);
        assert_eq!(t.get(&nid(1)).unwrap().transitions, 3);
    }

    // NUT7: uptime_ratio correct.
    #[test]
    fn nut7_uptime_ratio() {
        let mut t = NodeUptimeTracker::new();
        t.mark_online(nid(1), 0);
        t.tick(1);
        t.tick(2); // 2 online
        t.mark_offline(nid(1), 2);
        t.tick(3); // 1 offline
        let ratio = t.get(&nid(1)).unwrap().uptime_ratio();
        assert!((ratio - 2.0 / 3.0).abs() < 1e-9);
    }

    // NUT8: online_nodes filters correctly.
    #[test]
    fn nut8_online_nodes() {
        let mut t = NodeUptimeTracker::new();
        t.mark_online(nid(1), 1);
        t.register(nid(2));
        assert_eq!(t.online_nodes().len(), 1);
    }

    // NUT9: remove deletes record.
    #[test]
    fn nut9_remove() {
        let mut t = NodeUptimeTracker::new();
        t.register(nid(1));
        t.remove(&nid(1));
        assert!(t.get(&nid(1)).is_none());
    }

    // NUT10: node_count correct.
    #[test]
    fn nut10_node_count() {
        let mut t = NodeUptimeTracker::new();
        t.register(nid(1));
        t.register(nid(2));
        assert_eq!(t.node_count(), 2);
    }
}
