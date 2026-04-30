//! Node discovery engine — finds new peers via bootstrap seeds and gossip.
//!
//! `DiscoveryEngine` maintains a pool of `PeerCandidate` entries.  Candidates
//! are added by bootstrap (hard-coded seeds) or via `DiscoveryMessage` gossip
//! from other nodes.  Each candidate has a TTL; stale entries are pruned on
//! every `tick()` call.
//!
//! Duplicates are detected by `node_id`.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// PeerCandidate
// ---------------------------------------------------------------------------

/// A discovered (but not yet verified) peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCandidate {
    pub node_id: [u8; 32],
    pub address: String,
    /// Epoch at which this candidate was first seen.
    pub first_seen_epoch: u64,
    /// Candidate is valid until `first_seen_epoch + ttl_epochs`.
    pub ttl_epochs: u64,
}

impl PeerCandidate {
    pub fn is_valid_at(&self, epoch: u64) -> bool {
        epoch < self.first_seen_epoch + self.ttl_epochs
    }
}

// ---------------------------------------------------------------------------
// DiscoveryMessage
// ---------------------------------------------------------------------------

/// A gossip message carrying a list of peer candidates.
#[derive(Debug, Clone)]
pub struct DiscoveryMessage {
    /// node_id of the sender.
    pub sender_id: [u8; 32],
    pub epoch: u64,
    pub candidates: Vec<PeerCandidate>,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryError {
    /// The node_id is already in the candidate pool.
    AlreadyKnown,
}

// ---------------------------------------------------------------------------
// DiscoveryEngine
// ---------------------------------------------------------------------------

/// Discovers and maintains a pool of peer candidates.
pub struct DiscoveryEngine {
    /// node_id → candidate.
    candidates: HashMap<[u8; 32], PeerCandidate>,
    /// Our own node_id (never added as a candidate).
    own_id: [u8; 32],
    /// Default TTL assigned to bootstrap seeds.
    default_ttl: u64,
}

impl DiscoveryEngine {
    pub fn new(own_id: [u8; 32], default_ttl: u64) -> Self {
        Self {
            candidates: HashMap::new(),
            own_id,
            default_ttl,
        }
    }

    /// Add a bootstrap seed at `epoch`.
    pub fn add_seed(&mut self, node_id: [u8; 32], address: String, epoch: u64) {
        if node_id == self.own_id {
            return;
        }
        self.candidates
            .entry(node_id)
            .or_insert_with(|| PeerCandidate {
                node_id,
                address,
                first_seen_epoch: epoch,
                ttl_epochs: self.default_ttl,
            });
    }

    /// Process a gossip `DiscoveryMessage`, adding new candidates.
    ///
    /// Returns the number of new (previously unknown) candidates added.
    pub fn process_message(&mut self, msg: &DiscoveryMessage) -> usize {
        let mut added = 0;
        for cand in &msg.candidates {
            if cand.node_id == self.own_id {
                continue;
            }
            if let std::collections::hash_map::Entry::Vacant(e) =
                self.candidates.entry(cand.node_id)
            {
                e.insert(cand.clone());
                added += 1;
            }
        }
        added
    }

    /// Remove candidates whose TTL has expired at `current_epoch`.
    ///
    /// Returns the number of candidates pruned.
    pub fn tick(&mut self, current_epoch: u64) -> usize {
        let before = self.candidates.len();
        self.candidates.retain(|_, c| c.is_valid_at(current_epoch));
        before - self.candidates.len()
    }

    /// Get a candidate by node_id.
    pub fn get(&self, node_id: &[u8; 32]) -> Option<&PeerCandidate> {
        self.candidates.get(node_id)
    }

    /// All currently valid candidates.
    pub fn candidates(&self) -> impl Iterator<Item = &PeerCandidate> {
        self.candidates.values()
    }

    /// Number of tracked candidates.
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
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

    fn engine() -> DiscoveryEngine {
        DiscoveryEngine::new(nid(0), 10)
    }

    // ND1: add_seed adds a candidate.
    #[test]
    fn nd1_add_seed() {
        let mut e = engine();
        e.add_seed(nid(1), "127.0.0.1:9001".into(), 0);
        assert_eq!(e.len(), 1);
    }

    // ND2: add_seed is idempotent (duplicate ignored).
    #[test]
    fn nd2_add_seed_idempotent() {
        let mut e = engine();
        e.add_seed(nid(1), "127.0.0.1:9001".into(), 0);
        e.add_seed(nid(1), "127.0.0.1:9001".into(), 0);
        assert_eq!(e.len(), 1);
    }

    // ND3: own node_id is never added.
    #[test]
    fn nd3_own_id_excluded() {
        let mut e = engine();
        e.add_seed(nid(0), "127.0.0.1:9000".into(), 0); // own_id = nid(0)
        assert!(e.is_empty());
    }

    // ND4: process_message adds new candidates.
    #[test]
    fn nd4_process_message() {
        let mut e = engine();
        let msg = DiscoveryMessage {
            sender_id: nid(99),
            epoch: 0,
            candidates: vec![
                PeerCandidate {
                    node_id: nid(1),
                    address: "a".into(),
                    first_seen_epoch: 0,
                    ttl_epochs: 5,
                },
                PeerCandidate {
                    node_id: nid(2),
                    address: "b".into(),
                    first_seen_epoch: 0,
                    ttl_epochs: 5,
                },
            ],
        };
        let added = e.process_message(&msg);
        assert_eq!(added, 2);
        assert_eq!(e.len(), 2);
    }

    // ND5: process_message skips duplicates.
    #[test]
    fn nd5_deduplication() {
        let mut e = engine();
        let cand = PeerCandidate {
            node_id: nid(1),
            address: "a".into(),
            first_seen_epoch: 0,
            ttl_epochs: 5,
        };
        let msg = DiscoveryMessage {
            sender_id: nid(99),
            epoch: 0,
            candidates: vec![cand],
        };
        e.process_message(&msg);
        let added = e.process_message(&msg);
        assert_eq!(added, 0);
    }

    // ND6: TTL expiry — tick removes stale candidates.
    #[test]
    fn nd6_ttl_expiry() {
        let mut e = DiscoveryEngine::new(nid(0), 3);
        e.add_seed(nid(1), "a".into(), 0); // valid until epoch 3
        assert_eq!(e.tick(3), 1); // epoch 3: first_seen=0, ttl=3 → 3 < 0+3 false → pruned
        assert!(e.is_empty());
    }

    // ND7: tick keeps valid candidates.
    #[test]
    fn nd7_tick_keeps_valid() {
        let mut e = DiscoveryEngine::new(nid(0), 10);
        e.add_seed(nid(1), "a".into(), 0);
        assert_eq!(e.tick(5), 0);
        assert_eq!(e.len(), 1);
    }

    // ND8: get retrieves a known candidate.
    #[test]
    fn nd8_get_candidate() {
        let mut e = engine();
        e.add_seed(nid(5), "127.0.0.1:9005".into(), 0);
        let cand = e.get(&nid(5)).unwrap();
        assert_eq!(cand.address, "127.0.0.1:9005");
    }

    // ND9: process_message skips own node_id from gossip.
    #[test]
    fn nd9_own_id_excluded_from_gossip() {
        let mut e = engine();
        let msg = DiscoveryMessage {
            sender_id: nid(99),
            epoch: 0,
            candidates: vec![PeerCandidate {
                node_id: nid(0),
                address: "self".into(),
                first_seen_epoch: 0,
                ttl_epochs: 5,
            }],
        };
        let added = e.process_message(&msg);
        assert_eq!(added, 0);
    }

    // ND10: is_valid_at respects boundaries.
    #[test]
    fn nd10_validity_boundaries() {
        let c = PeerCandidate {
            node_id: nid(1),
            address: "a".into(),
            first_seen_epoch: 5,
            ttl_epochs: 3,
        };
        assert!(c.is_valid_at(5));
        assert!(c.is_valid_at(7));
        assert!(!c.is_valid_at(8));
    }

    // ND11: multiple ticks prune incrementally.
    #[test]
    fn nd11_incremental_pruning() {
        let mut e = DiscoveryEngine::new(nid(0), 5);
        e.add_seed(nid(1), "a".into(), 0); // expires at epoch 5
        e.add_seed(nid(2), "b".into(), 3); // expires at epoch 8
        assert_eq!(e.tick(5), 1); // nid(1) expires
        assert_eq!(e.len(), 1);
        assert_eq!(e.tick(8), 1); // nid(2) expires
        assert!(e.is_empty());
    }
}
