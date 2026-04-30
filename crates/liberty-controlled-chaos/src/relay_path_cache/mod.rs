//! Relay path cache — stores recently computed relay paths for reuse.

use std::collections::HashMap;

pub type NodeId = [u8; 32];

#[derive(Debug, Clone)]
pub struct CachedPath {
    pub hops: Vec<NodeId>,
    pub created_epoch: u64,
    pub ttl_epochs: u64,
    pub use_count: u64,
}

impl CachedPath {
    pub fn is_expired(&self, current_epoch: u64) -> bool {
        current_epoch >= self.created_epoch + self.ttl_epochs
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheError {
    NotFound,
    Expired,
    CapacityExceeded,
}

pub struct RelayPathCache {
    entries: HashMap<(NodeId, NodeId), CachedPath>,
    capacity: usize,
    hits: u64,
    misses: u64,
    evictions: u64,
}

impl RelayPathCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity,
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }

    pub fn insert(
        &mut self,
        src: NodeId,
        dst: NodeId,
        hops: Vec<NodeId>,
        epoch: u64,
        ttl: u64,
    ) -> Result<(), CacheError> {
        if self.entries.len() >= self.capacity && !self.entries.contains_key(&(src, dst)) {
            return Err(CacheError::CapacityExceeded);
        }
        self.entries.insert(
            (src, dst),
            CachedPath {
                hops,
                created_epoch: epoch,
                ttl_epochs: ttl,
                use_count: 0,
            },
        );
        Ok(())
    }

    pub fn lookup(
        &mut self,
        src: &NodeId,
        dst: &NodeId,
        current_epoch: u64,
    ) -> Result<&CachedPath, CacheError> {
        match self.entries.get_mut(&(*src, *dst)) {
            None => {
                self.misses += 1;
                Err(CacheError::NotFound)
            }
            Some(path) if path.is_expired(current_epoch) => {
                self.misses += 1;
                Err(CacheError::Expired)
            }
            Some(path) => {
                path.use_count += 1;
                self.hits += 1;
                Ok(path)
            }
        }
    }

    pub fn evict_expired(&mut self, current_epoch: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, p| !p.is_expired(current_epoch));
        let removed = before - self.entries.len();
        self.evictions += removed as u64;
        removed
    }

    pub fn remove(&mut self, src: &NodeId, dst: &NodeId) -> bool {
        self.entries.remove(&(*src, *dst)).is_some()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn hits(&self) -> u64 {
        self.hits
    }
    pub fn misses(&self) -> u64 {
        self.misses
    }
    pub fn evictions(&self) -> u64 {
        self.evictions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    // RPC1: insert and lookup succeeds.
    #[test]
    fn rpc1_insert_lookup() {
        let mut c = RelayPathCache::new(16);
        c.insert(nid(1), nid(2), vec![nid(5), nid(6)], 10, 20)
            .unwrap();
        let p = c.lookup(&nid(1), &nid(2), 15).unwrap();
        assert_eq!(p.hops, vec![nid(5), nid(6)]);
    }

    // RPC2: lookup missing key returns NotFound.
    #[test]
    fn rpc2_not_found() {
        let mut c = RelayPathCache::new(16);
        assert_eq!(
            c.lookup(&nid(1), &nid(2), 1).err(),
            Some(CacheError::NotFound)
        );
    }

    // RPC3: expired entry returns Expired.
    #[test]
    fn rpc3_expired() {
        let mut c = RelayPathCache::new(16);
        c.insert(nid(1), nid(2), vec![], 1, 5).unwrap();
        assert_eq!(
            c.lookup(&nid(1), &nid(2), 10).err(),
            Some(CacheError::Expired)
        );
    }

    // RPC4: hits counter increments on successful lookup.
    #[test]
    fn rpc4_hits() {
        let mut c = RelayPathCache::new(16);
        c.insert(nid(1), nid(2), vec![], 1, 100).unwrap();
        c.lookup(&nid(1), &nid(2), 5).unwrap();
        c.lookup(&nid(1), &nid(2), 5).unwrap();
        assert_eq!(c.hits(), 2);
    }

    // RPC5: misses counter increments on miss or expired.
    #[test]
    fn rpc5_misses() {
        let mut c = RelayPathCache::new(16);
        let _ = c.lookup(&nid(1), &nid(2), 1);
        assert_eq!(c.misses(), 1);
    }

    // RPC6: capacity exceeded returns error.
    #[test]
    fn rpc6_capacity() {
        let mut c = RelayPathCache::new(1);
        c.insert(nid(1), nid(2), vec![], 1, 100).unwrap();
        assert_eq!(
            c.insert(nid(3), nid(4), vec![], 1, 100),
            Err(CacheError::CapacityExceeded)
        );
    }

    // RPC7: evict_expired removes stale entries.
    #[test]
    fn rpc7_evict_expired() {
        let mut c = RelayPathCache::new(16);
        c.insert(nid(1), nid(2), vec![], 1, 5).unwrap();
        c.insert(nid(3), nid(4), vec![], 1, 100).unwrap();
        assert_eq!(c.evict_expired(10), 1);
        assert_eq!(c.len(), 1);
    }

    // RPC8: use_count increments on each successful lookup.
    #[test]
    fn rpc8_use_count() {
        let mut c = RelayPathCache::new(16);
        c.insert(nid(1), nid(2), vec![], 1, 100).unwrap();
        c.lookup(&nid(1), &nid(2), 5).unwrap();
        c.lookup(&nid(1), &nid(2), 5).unwrap();
        assert_eq!(c.lookup(&nid(1), &nid(2), 5).unwrap().use_count, 3);
    }

    // RPC9: remove deletes entry.
    #[test]
    fn rpc9_remove() {
        let mut c = RelayPathCache::new(16);
        c.insert(nid(1), nid(2), vec![], 1, 100).unwrap();
        assert!(c.remove(&nid(1), &nid(2)));
        assert!(c.is_empty());
    }

    // RPC10: evictions counter tracks removed count.
    #[test]
    fn rpc10_evictions_counter() {
        let mut c = RelayPathCache::new(16);
        c.insert(nid(1), nid(2), vec![], 1, 3).unwrap();
        c.insert(nid(3), nid(4), vec![], 1, 3).unwrap();
        c.evict_expired(10);
        assert_eq!(c.evictions(), 2);
    }
}
