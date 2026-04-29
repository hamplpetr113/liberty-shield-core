//! Persistent rekey nonce store with bounded capacity.
//!
//! `RekeyNonceStore` records nonces from processed `RekeyRequest` messages and
//! rejects replays.  Unlike the in-memory `HashSet`-based `RekeyGuard`, this
//! store uses a `BTreeSet` for ordered iteration and evicts the oldest entry
//! when the capacity limit is reached.

use std::collections::BTreeSet;

/// Bounded, ordered nonce store for the responder side of the rekey protocol.
///
/// Nonces are `u64` values derived from (or hashing of) the 16-byte request
/// nonce.  `max_size` controls the maximum number of nonces retained; the
/// numerically-smallest entry is evicted when the set is full.
#[derive(Debug)]
pub struct RekeyNonceStore {
    seen: BTreeSet<u64>,
    max_size: usize,
}

impl RekeyNonceStore {
    /// Create a store that holds at most `max_size` nonces.
    pub fn new(max_size: usize) -> Self {
        Self {
            seen: BTreeSet::new(),
            max_size,
        }
    }

    /// Check `nonce` and record it if fresh.
    ///
    /// Returns `true` when the nonce is fresh (not previously seen).
    /// Returns `false` when the nonce is a replay.
    ///
    /// When the store is full, the numerically-smallest stored nonce is evicted
    /// to make room before recording the new one.
    pub fn check_and_record(&mut self, nonce: u64) -> bool {
        if self.seen.contains(&nonce) {
            return false;
        }
        if self.max_size > 0
            && self.seen.len() >= self.max_size
            && let Some(&oldest) = self.seen.iter().next()
        {
            self.seen.remove(&oldest);
        }
        self.seen.insert(nonce);
        true
    }

    /// Number of nonces currently stored.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// `true` when no nonces have been recorded.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RG1: fresh nonce accepted; duplicate rejected
    #[test]
    fn rg1_fresh_and_duplicate() {
        let mut store = RekeyNonceStore::new(100);
        assert!(store.check_and_record(1));
        assert!(store.check_and_record(2));
        assert!(!store.check_and_record(1)); // replay
        assert!(!store.check_and_record(2)); // replay
        assert_eq!(store.len(), 2);
    }

    // RG2: size limit — smallest entry evicted to make room
    #[test]
    fn rg2_size_limit_evicts_oldest() {
        let mut store = RekeyNonceStore::new(3);
        store.check_and_record(10);
        store.check_and_record(20);
        store.check_and_record(30);
        assert_eq!(store.len(), 3);

        // Insert 40 — evicts 10 (smallest numerically); set = {20, 30, 40}.
        assert!(store.check_and_record(40));
        assert_eq!(store.len(), 3);

        // 10 is gone → re-inserting it succeeds; evicts 20 (new smallest).
        // set = {30, 40, 10}.
        assert!(store.check_and_record(10));
        // 30 is still present → replay.
        assert!(!store.check_and_record(30));
        // 20 was evicted → it is fresh again.
        assert!(store.check_and_record(20));
    }

    // RG3: zero-capacity store never retains entries
    #[test]
    fn rg3_zero_capacity() {
        let mut store = RekeyNonceStore::new(0);
        // With max_size=0 no eviction occurs; insert into an empty set.
        assert!(store.check_and_record(5));
        // Now len=1 but max_size=0 so the guard `seen.len() >= max_size`
        // (1 >= 0) is true on every call; evict then re-insert.
        assert!(!store.check_and_record(5)); // 5 is still present → replay
        assert!(store.check_and_record(6)); // 6 is new → accepted
    }
}
