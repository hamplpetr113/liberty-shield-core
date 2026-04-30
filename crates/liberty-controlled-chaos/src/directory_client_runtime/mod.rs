//! Directory client runtime — caches consensus documents and tracks freshness.
//!
//! `ConsensusCache` stores the latest `CachedConsensus` (epoch + node list)
//! and marks it stale after `max_cache_epochs` epochs.
//!
//! `DirectoryClientRuntime` ingests new consensuses (verifying a simple HMAC
//! signature), updates the cache, and exposes the current node list.

use std::collections::HashMap;

use crate::crypto::hmac_sha256;

// ---------------------------------------------------------------------------
// CachedNode
// ---------------------------------------------------------------------------

/// Minimal node entry stored in the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedNode {
    pub node_id: [u8; 32],
    pub address: String,
}

// ---------------------------------------------------------------------------
// CachedConsensus
// ---------------------------------------------------------------------------

/// A consensus document stored in the local cache.
#[derive(Debug, Clone)]
pub struct CachedConsensus {
    pub epoch: u64,
    pub nodes: Vec<CachedNode>,
    /// HMAC-SHA256(authority_key, payload) — NON-PRODUCTION.
    pub signature: [u8; 32],
}

impl CachedConsensus {
    fn payload_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.epoch.to_le_bytes());
        for n in &self.nodes {
            b.extend_from_slice(&n.node_id);
            b.extend_from_slice(n.address.as_bytes());
        }
        b
    }

    pub fn verify(&self, authority_key: &[u8; 32]) -> bool {
        hmac_sha256(authority_key, &self.payload_bytes()) == self.signature
    }
}

// ---------------------------------------------------------------------------
// ConsensusCache
// ---------------------------------------------------------------------------

/// Stores and ages the most recent consensus.
pub struct ConsensusCache {
    consensus: Option<CachedConsensus>,
    max_cache_epochs: u64,
}

impl ConsensusCache {
    pub fn new(max_cache_epochs: u64) -> Self {
        Self {
            consensus: None,
            max_cache_epochs,
        }
    }

    pub fn store(&mut self, c: CachedConsensus) {
        self.consensus = Some(c);
    }

    pub fn get(&self) -> Option<&CachedConsensus> {
        self.consensus.as_ref()
    }

    /// Returns `true` if no consensus is cached or the cache is stale at `epoch`.
    pub fn is_stale(&self, current_epoch: u64) -> bool {
        match &self.consensus {
            None => true,
            Some(c) => current_epoch.saturating_sub(c.epoch) >= self.max_cache_epochs,
        }
    }

    pub fn clear(&mut self) {
        self.consensus = None;
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryError {
    InvalidSignature,
    StaleEpoch { current: u64, proposed: u64 },
    EmptyConsensus,
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectoryError::InvalidSignature => write!(f, "invalid consensus signature"),
            DirectoryError::StaleEpoch { current, proposed } => {
                write!(f, "stale epoch: proposed {proposed} <= current {current}")
            }
            DirectoryError::EmptyConsensus => write!(f, "empty consensus"),
        }
    }
}

// ---------------------------------------------------------------------------
// DirectoryClientRuntime
// ---------------------------------------------------------------------------

/// Downloads, verifies, and caches consensus documents.
pub struct DirectoryClientRuntime {
    authority_key: [u8; 32],
    current_epoch: u64,
    pub cache: ConsensusCache,
    /// node_id → CachedNode (the live peer table populated from consensus).
    peer_map: HashMap<[u8; 32], CachedNode>,
}

impl DirectoryClientRuntime {
    pub fn new(authority_key: [u8; 32], max_cache_epochs: u64) -> Self {
        Self {
            authority_key,
            current_epoch: 0,
            cache: ConsensusCache::new(max_cache_epochs),
            peer_map: HashMap::new(),
        }
    }

    /// Ingest a new consensus document.
    ///
    /// 1. Verify signature.
    /// 2. Ensure epoch is strictly newer.
    /// 3. Ensure non-empty.
    /// 4. Update cache and peer_map.
    pub fn ingest(&mut self, consensus: CachedConsensus) -> Result<(), DirectoryError> {
        if !consensus.verify(&self.authority_key) {
            return Err(DirectoryError::InvalidSignature);
        }
        if consensus.epoch <= self.current_epoch && self.current_epoch > 0 {
            return Err(DirectoryError::StaleEpoch {
                current: self.current_epoch,
                proposed: consensus.epoch,
            });
        }
        if consensus.nodes.is_empty() {
            return Err(DirectoryError::EmptyConsensus);
        }
        self.current_epoch = consensus.epoch;
        self.peer_map.clear();
        for node in &consensus.nodes {
            self.peer_map.insert(node.node_id, node.clone());
        }
        self.cache.store(consensus);
        Ok(())
    }

    /// Build a signed consensus (utility for testing — simulates "fetching").
    pub fn build_consensus(
        authority_key: &[u8; 32],
        epoch: u64,
        nodes: Vec<CachedNode>,
    ) -> CachedConsensus {
        let mut c = CachedConsensus {
            epoch,
            nodes,
            signature: [0u8; 32],
        };
        c.signature = hmac_sha256(authority_key, &c.payload_bytes());
        c
    }

    pub fn peers(&self) -> impl Iterator<Item = &CachedNode> {
        self.peer_map.values()
    }

    pub fn peer(&self, node_id: &[u8; 32]) -> Option<&CachedNode> {
        self.peer_map.get(node_id)
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn peer_count(&self) -> usize {
        self.peer_map.len()
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

    fn akey() -> [u8; 32] {
        [0xAAu8; 32]
    }

    fn node(id: u8) -> CachedNode {
        CachedNode {
            node_id: nid(id),
            address: format!("127.0.0.1:{}", 9000 + id as u16),
        }
    }

    fn make_consensus(epoch: u64, nodes: Vec<CachedNode>) -> CachedConsensus {
        DirectoryClientRuntime::build_consensus(&akey(), epoch, nodes)
    }

    // DCL1: valid consensus is ingested.
    #[test]
    fn dcl1_valid_ingest() {
        let mut dc = DirectoryClientRuntime::new(akey(), 5);
        let c = make_consensus(1, vec![node(1), node(2)]);
        dc.ingest(c).unwrap();
        assert_eq!(dc.peer_count(), 2);
        assert_eq!(dc.current_epoch(), 1);
    }

    // DCL2: tampered signature is rejected.
    #[test]
    fn dcl2_invalid_signature() {
        let mut dc = DirectoryClientRuntime::new(akey(), 5);
        let mut c = make_consensus(1, vec![node(1)]);
        c.signature[0] ^= 0xFF;
        assert_eq!(dc.ingest(c).unwrap_err(), DirectoryError::InvalidSignature);
    }

    // DCL3: stale epoch is rejected after first ingest.
    #[test]
    fn dcl3_stale_epoch() {
        let mut dc = DirectoryClientRuntime::new(akey(), 5);
        dc.ingest(make_consensus(5, vec![node(1)])).unwrap();
        let stale = make_consensus(5, vec![node(2)]);
        assert!(matches!(
            dc.ingest(stale).unwrap_err(),
            DirectoryError::StaleEpoch { .. }
        ));
    }

    // DCL4: empty consensus is rejected.
    #[test]
    fn dcl4_empty_consensus() {
        let mut dc = DirectoryClientRuntime::new(akey(), 5);
        let c = make_consensus(1, vec![]);
        assert_eq!(dc.ingest(c).unwrap_err(), DirectoryError::EmptyConsensus);
    }

    // DCL5: peer_map is updated on ingest.
    #[test]
    fn dcl5_peer_map_updated() {
        let mut dc = DirectoryClientRuntime::new(akey(), 5);
        dc.ingest(make_consensus(1, vec![node(1), node(2)]))
            .unwrap();
        assert!(dc.peer(&nid(1)).is_some());
        assert!(dc.peer(&nid(2)).is_some());
    }

    // DCL6: second ingest replaces peer_map.
    #[test]
    fn dcl6_peer_map_replaced() {
        let mut dc = DirectoryClientRuntime::new(akey(), 5);
        dc.ingest(make_consensus(1, vec![node(1)])).unwrap();
        dc.ingest(make_consensus(2, vec![node(2)])).unwrap();
        assert!(dc.peer(&nid(1)).is_none());
        assert!(dc.peer(&nid(2)).is_some());
    }

    // DCL7: cache is_stale respects max_cache_epochs.
    #[test]
    fn dcl7_cache_stale() {
        let mut dc = DirectoryClientRuntime::new(akey(), 3);
        dc.ingest(make_consensus(1, vec![node(1)])).unwrap();
        assert!(!dc.cache.is_stale(3)); // age=2 < 3
        assert!(dc.cache.is_stale(4)); // age=3 >= 3
    }

    // DCL8: ConsensusCache::verify works with correct/wrong key.
    #[test]
    fn dcl8_verify_signature() {
        let c = make_consensus(1, vec![node(1)]);
        assert!(c.verify(&akey()));
        assert!(!c.verify(&[0u8; 32]));
    }

    // DCL9: empty cache is_stale returns true.
    #[test]
    fn dcl9_empty_cache_stale() {
        let cache = ConsensusCache::new(5);
        assert!(cache.is_stale(0));
    }

    // DCL10: peers() iterator yields all nodes.
    #[test]
    fn dcl10_peers_iterator() {
        let mut dc = DirectoryClientRuntime::new(akey(), 5);
        dc.ingest(make_consensus(1, vec![node(1), node(2), node(3)]))
            .unwrap();
        assert_eq!(dc.peers().count(), 3);
    }

    // DCL11: first ingest at any epoch (no current_epoch check on epoch=0).
    #[test]
    fn dcl11_first_ingest_any_epoch() {
        let mut dc = DirectoryClientRuntime::new(akey(), 5);
        // First ingest at epoch 10 should succeed (current_epoch starts at 0).
        dc.ingest(make_consensus(10, vec![node(1)])).unwrap();
        assert_eq!(dc.current_epoch(), 10);
    }
}
