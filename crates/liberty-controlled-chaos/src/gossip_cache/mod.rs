//! Gossip cache — deduplicates and stores gossip messages with TTL.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct GossipMessage {
    pub msg_id: [u8; 32],
    pub origin: [u8; 32],
    pub topic: String,
    pub body: Vec<u8>,
    pub received_epoch: u64,
    pub ttl_epochs: u64,
}

impl GossipMessage {
    pub fn is_expired(&self, current_epoch: u64) -> bool {
        current_epoch >= self.received_epoch + self.ttl_epochs
    }
}

pub struct GossipCache {
    messages: HashMap<[u8; 32], GossipMessage>,
    max_capacity: usize,
    total_seen: u64,
    total_expired: u64,
}

impl GossipCache {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            messages: HashMap::new(),
            max_capacity,
            total_seen: 0,
            total_expired: 0,
        }
    }

    /// Returns true if the message was new and accepted, false if duplicate or capacity exceeded.
    pub fn insert(&mut self, msg: GossipMessage) -> bool {
        self.total_seen += 1;
        if self.messages.contains_key(&msg.msg_id) {
            return false;
        }
        if self.messages.len() >= self.max_capacity {
            return false;
        }
        self.messages.insert(msg.msg_id, msg);
        true
    }

    pub fn contains(&self, msg_id: &[u8; 32]) -> bool {
        self.messages.contains_key(msg_id)
    }

    pub fn get(&self, msg_id: &[u8; 32]) -> Option<&GossipMessage> {
        self.messages.get(msg_id)
    }

    pub fn evict_expired(&mut self, current_epoch: u64) -> usize {
        let before = self.messages.len();
        self.messages.retain(|_, m| !m.is_expired(current_epoch));
        let evicted = before - self.messages.len();
        self.total_expired += evicted as u64;
        evicted
    }

    pub fn messages_for_topic(&self, topic: &str) -> Vec<&GossipMessage> {
        self.messages
            .values()
            .filter(|m| m.topic == topic)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn total_seen(&self) -> u64 {
        self.total_seen
    }

    pub fn total_expired(&self) -> u64 {
        self.total_expired
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mid(b: u8) -> [u8; 32] {
        [b; 32]
    }
    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn msg(id: u8, topic: &str, received: u64, ttl: u64) -> GossipMessage {
        GossipMessage {
            msg_id: mid(id),
            origin: nid(id),
            topic: topic.to_string(),
            body: vec![id],
            received_epoch: received,
            ttl_epochs: ttl,
        }
    }

    // GC1: insert new message returns true.
    #[test]
    fn gc1_insert_new() {
        let mut c = GossipCache::new(10);
        assert!(c.insert(msg(1, "peers", 0, 100)));
    }

    // GC2: duplicate insert returns false.
    #[test]
    fn gc2_duplicate() {
        let mut c = GossipCache::new(10);
        c.insert(msg(1, "peers", 0, 100));
        assert!(!c.insert(msg(1, "peers", 1, 100)));
    }

    // GC3: contains returns true for known message.
    #[test]
    fn gc3_contains() {
        let mut c = GossipCache::new(10);
        c.insert(msg(1, "peers", 0, 100));
        assert!(c.contains(&mid(1)));
    }

    // GC4: capacity limit rejects insertion.
    #[test]
    fn gc4_capacity() {
        let mut c = GossipCache::new(1);
        c.insert(msg(1, "peers", 0, 100));
        assert!(!c.insert(msg(2, "peers", 0, 100)));
    }

    // GC5: evict_expired removes expired messages.
    #[test]
    fn gc5_evict_expired() {
        let mut c = GossipCache::new(10);
        c.insert(msg(1, "peers", 0, 5));
        c.insert(msg(2, "peers", 0, 100));
        let evicted = c.evict_expired(10);
        assert_eq!(evicted, 1);
        assert_eq!(c.len(), 1);
    }

    // GC6: messages_for_topic filters correctly.
    #[test]
    fn gc6_topic_filter() {
        let mut c = GossipCache::new(10);
        c.insert(msg(1, "peers", 0, 100));
        c.insert(msg(2, "routes", 0, 100));
        assert_eq!(c.messages_for_topic("peers").len(), 1);
    }

    // GC7: total_seen counts all attempts.
    #[test]
    fn gc7_total_seen() {
        let mut c = GossipCache::new(10);
        c.insert(msg(1, "x", 0, 10));
        c.insert(msg(1, "x", 0, 10)); // duplicate
        assert_eq!(c.total_seen(), 2);
    }

    // GC8: total_expired increments on eviction.
    #[test]
    fn gc8_total_expired() {
        let mut c = GossipCache::new(10);
        c.insert(msg(1, "x", 0, 1));
        c.evict_expired(5);
        assert_eq!(c.total_expired(), 1);
    }

    // GC9: get returns message body.
    #[test]
    fn gc9_get_body() {
        let mut c = GossipCache::new(10);
        c.insert(msg(7, "x", 0, 100));
        let m = c.get(&mid(7)).unwrap();
        assert_eq!(m.body, vec![7]);
    }

    // GC10: is_empty correct.
    #[test]
    fn gc10_is_empty() {
        let mut c = GossipCache::new(10);
        assert!(c.is_empty());
        c.insert(msg(1, "x", 0, 100));
        assert!(!c.is_empty());
    }
}
