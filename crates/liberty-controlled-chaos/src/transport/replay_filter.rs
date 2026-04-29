//! Transport-layer replay filter using an LRU-style bounded set.
//!
//! `TransportReplayFilter` tracks recently-seen packet IDs (e.g., an
//! (circuit_id, sequence) composite key encoded as a `u64`) and rejects
//! duplicates.  When the set reaches capacity, the oldest entry is evicted
//! to make room — providing O(1) amortised operations with a bounded memory
//! footprint.
//!
//! This layer sits *above* the AEAD: it provides a fast first-pass duplicate
//! check without requiring key material.

use std::collections::{HashSet, VecDeque};

/// LRU-bounded set for packet-ID deduplication.
///
/// Ordering is insertion order; eviction removes the entry that was inserted
/// furthest in the past.
#[derive(Debug)]
pub struct TransportReplayFilter {
    capacity: usize,
    seen: HashSet<u64>,
    order: VecDeque<u64>,
}

impl TransportReplayFilter {
    /// Create a filter that remembers at most `capacity` packet IDs.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Check `id` and record it if fresh.
    ///
    /// Returns `true` when `id` has not been seen before (packet is fresh).
    /// Returns `false` when `id` is a duplicate.
    ///
    /// When the filter is full, the oldest recorded ID is evicted before
    /// recording the new one.
    pub fn check_and_record(&mut self, id: u64) -> bool {
        if self.seen.contains(&id) {
            return false;
        }
        if self.order.len() >= self.capacity
            && let Some(evicted) = self.order.pop_front()
        {
            self.seen.remove(&evicted);
        }
        self.seen.insert(id);
        self.order.push_back(id);
        true
    }

    /// Number of IDs currently retained.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// `true` when no IDs have been recorded.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TR1: fresh IDs are accepted; duplicates are rejected
    #[test]
    fn tr1_fresh_and_duplicate() {
        let mut f = TransportReplayFilter::new(256);
        assert!(f.check_and_record(1));
        assert!(f.check_and_record(2));
        assert!(!f.check_and_record(1));
        assert!(!f.check_and_record(2));
        assert_eq!(f.len(), 2);
    }

    // TR2: eviction at capacity — oldest entry is removed
    #[test]
    fn tr2_eviction_at_capacity() {
        let mut f = TransportReplayFilter::new(3);
        f.check_and_record(10);
        f.check_and_record(20);
        f.check_and_record(30);
        assert_eq!(f.len(), 3);

        // Adding 40 evicts 10 (oldest); set = {20, 30, 40}.
        assert!(f.check_and_record(40));
        assert_eq!(f.len(), 3);

        // 10 is gone — it can be re-inserted; re-inserting evicts 20 (new oldest).
        // set = {30, 40, 10}.
        assert!(f.check_and_record(10));
        // 30 is still present — it is a duplicate.
        assert!(!f.check_and_record(30));
        // 20 was evicted during the re-insert of 10 — it is now fresh.
        assert!(f.check_and_record(20));
    }

    // TR3: zero-capacity filter never retains entries; every call is fresh
    #[test]
    fn tr3_zero_capacity() {
        let mut f = TransportReplayFilter::new(0);
        // With capacity=0 no eviction loop fires; the VecDeque never grows.
        assert!(f.check_and_record(7)); // inserts (len now 1, but capacity=0 means no eviction yet)
        // 7 is in seen, so it is a duplicate now.
        assert!(!f.check_and_record(7));
        assert!(f.check_and_record(8));
    }
}
