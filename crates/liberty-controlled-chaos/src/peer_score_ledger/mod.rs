//! Peer score ledger — aggregates behavioral scores for peer selection decisions.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct PeerScoreEntry {
    pub peer_id: [u8; 32],
    pub score: i64,
    pub positive_events: u64,
    pub negative_events: u64,
    pub last_epoch: u64,
}

impl PeerScoreEntry {
    fn new(peer_id: [u8; 32]) -> Self {
        Self {
            peer_id,
            score: 0,
            positive_events: 0,
            negative_events: 0,
            last_epoch: 0,
        }
    }
}

pub struct PeerScoreLedger {
    entries: HashMap<[u8; 32], PeerScoreEntry>,
    min_score: i64,
    max_score: i64,
}

impl PeerScoreLedger {
    pub fn new(min_score: i64, max_score: i64) -> Self {
        Self {
            entries: HashMap::new(),
            min_score,
            max_score,
        }
    }

    fn ensure(&mut self, peer_id: [u8; 32]) {
        self.entries
            .entry(peer_id)
            .or_insert_with(|| PeerScoreEntry::new(peer_id));
    }

    pub fn reward(&mut self, peer_id: [u8; 32], delta: i64, epoch: u64) {
        self.ensure(peer_id);
        let e = self.entries.get_mut(&peer_id).unwrap();
        e.score = (e.score + delta).min(self.max_score);
        e.positive_events += 1;
        e.last_epoch = epoch;
    }

    pub fn penalize(&mut self, peer_id: [u8; 32], delta: i64, epoch: u64) {
        self.ensure(peer_id);
        let e = self.entries.get_mut(&peer_id).unwrap();
        e.score = (e.score - delta).max(self.min_score);
        e.negative_events += 1;
        e.last_epoch = epoch;
    }

    pub fn get(&self, peer_id: &[u8; 32]) -> Option<&PeerScoreEntry> {
        self.entries.get(peer_id)
    }

    pub fn score(&self, peer_id: &[u8; 32]) -> Option<i64> {
        self.entries.get(peer_id).map(|e| e.score)
    }

    pub fn is_eligible(&self, peer_id: &[u8; 32], threshold: i64) -> bool {
        self.entries
            .get(peer_id)
            .map(|e| e.score >= threshold)
            .unwrap_or(false)
    }

    pub fn remove(&mut self, peer_id: &[u8; 32]) {
        self.entries.remove(peer_id);
    }

    pub fn top_peers(&self, n: usize, threshold: i64) -> Vec<[u8; 32]> {
        let mut v: Vec<&PeerScoreEntry> = self
            .entries
            .values()
            .filter(|e| e.score >= threshold)
            .collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.score));
        v.into_iter().take(n).map(|e| e.peer_id).collect()
    }

    pub fn peer_count(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn ledger() -> PeerScoreLedger {
        PeerScoreLedger::new(-100, 100)
    }

    // PSL1: reward increases score.
    #[test]
    fn psl1_reward() {
        let mut l = ledger();
        l.reward(nid(1), 10, 1);
        assert_eq!(l.score(&nid(1)), Some(10));
    }

    // PSL2: penalize decreases score.
    #[test]
    fn psl2_penalize() {
        let mut l = ledger();
        l.penalize(nid(1), 5, 1);
        assert_eq!(l.score(&nid(1)), Some(-5));
    }

    // PSL3: score capped at max.
    #[test]
    fn psl3_max_cap() {
        let mut l = ledger();
        l.reward(nid(1), 200, 1);
        assert_eq!(l.score(&nid(1)), Some(100));
    }

    // PSL4: score floored at min.
    #[test]
    fn psl4_min_floor() {
        let mut l = ledger();
        l.penalize(nid(1), 200, 1);
        assert_eq!(l.score(&nid(1)), Some(-100));
    }

    // PSL5: positive_events increments on reward.
    #[test]
    fn psl5_positive_events() {
        let mut l = ledger();
        l.reward(nid(1), 1, 1);
        l.reward(nid(1), 1, 2);
        assert_eq!(l.get(&nid(1)).unwrap().positive_events, 2);
    }

    // PSL6: negative_events increments on penalize.
    #[test]
    fn psl6_negative_events() {
        let mut l = ledger();
        l.penalize(nid(1), 1, 1);
        assert_eq!(l.get(&nid(1)).unwrap().negative_events, 1);
    }

    // PSL7: is_eligible true above threshold.
    #[test]
    fn psl7_eligible() {
        let mut l = ledger();
        l.reward(nid(1), 50, 1);
        assert!(l.is_eligible(&nid(1), 0));
    }

    // PSL8: unknown peer is not eligible.
    #[test]
    fn psl8_unknown_not_eligible() {
        let l = ledger();
        assert!(!l.is_eligible(&nid(99), 0));
    }

    // PSL9: top_peers returns sorted by score.
    #[test]
    fn psl9_top_peers() {
        let mut l = ledger();
        l.reward(nid(1), 80, 1);
        l.reward(nid(2), 50, 1);
        l.reward(nid(3), 30, 1);
        let top = l.top_peers(2, -100);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0], nid(1));
    }

    // PSL10: remove deletes entry.
    #[test]
    fn psl10_remove() {
        let mut l = ledger();
        l.reward(nid(1), 10, 1);
        l.remove(&nid(1));
        assert!(l.get(&nid(1)).is_none());
    }
}
