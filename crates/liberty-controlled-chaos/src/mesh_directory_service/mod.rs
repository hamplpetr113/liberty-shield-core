//! Mesh directory service — stores and queries `NodeDescriptor` records.
//!
//! Provides insert/lookup/eviction with epoch-based freshness enforcement.
//! Supports tag-based filtering and capacity limits.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// NodeDescriptor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDescriptor {
    pub node_id: [u8; 32],
    pub address: String,
    pub epoch: u64,
    pub tags: Vec<String>,
}

// ---------------------------------------------------------------------------
// DirectoryError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectoryError {
    Duplicate,
    NotFound,
    CapacityExceeded,
    StaleEpoch,
}

// ---------------------------------------------------------------------------
// MeshDirectoryService
// ---------------------------------------------------------------------------

pub struct MeshDirectoryService {
    max_entries: usize,
    max_epoch_skew: u64,
    entries: HashMap<[u8; 32], NodeDescriptor>,
    eviction_count: u64,
}

impl MeshDirectoryService {
    pub fn new(max_entries: usize, max_epoch_skew: u64) -> Self {
        Self {
            max_entries,
            max_epoch_skew,
            entries: HashMap::new(),
            eviction_count: 0,
        }
    }

    pub fn insert(&mut self, desc: NodeDescriptor, local_epoch: u64) -> Result<(), DirectoryError> {
        let skew = desc.epoch.abs_diff(local_epoch);
        if skew > self.max_epoch_skew {
            return Err(DirectoryError::StaleEpoch);
        }
        if self.entries.contains_key(&desc.node_id) {
            return Err(DirectoryError::Duplicate);
        }
        if self.entries.len() >= self.max_entries {
            return Err(DirectoryError::CapacityExceeded);
        }
        self.entries.insert(desc.node_id, desc);
        Ok(())
    }

    /// Update an existing entry (replace epoch and tags).
    pub fn update(&mut self, desc: NodeDescriptor, local_epoch: u64) -> Result<(), DirectoryError> {
        let skew = desc.epoch.abs_diff(local_epoch);
        if skew > self.max_epoch_skew {
            return Err(DirectoryError::StaleEpoch);
        }
        if !self.entries.contains_key(&desc.node_id) {
            return Err(DirectoryError::NotFound);
        }
        self.entries.insert(desc.node_id, desc);
        Ok(())
    }

    pub fn lookup(&self, node_id: &[u8; 32]) -> Option<&NodeDescriptor> {
        self.entries.get(node_id)
    }

    pub fn remove(&mut self, node_id: &[u8; 32]) -> bool {
        self.entries.remove(node_id).is_some()
    }

    /// Return all descriptors whose tags include `tag`.
    pub fn query_by_tag(&self, tag: &str) -> Vec<&NodeDescriptor> {
        self.entries
            .values()
            .filter(|d| d.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Evict entries whose epoch differs from `current_epoch` by more than `max_epoch_skew`.
    pub fn evict_stale(&mut self, current_epoch: u64) -> usize {
        let before = self.entries.len();
        let skew = self.max_epoch_skew;
        self.entries
            .retain(|_, d| d.epoch.abs_diff(current_epoch) <= skew);
        let evicted = before - self.entries.len();
        self.eviction_count += evicted as u64;
        evicted
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn eviction_count(&self) -> u64 {
        self.eviction_count
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

    fn desc(b: u8, epoch: u64, tags: &[&str]) -> NodeDescriptor {
        NodeDescriptor {
            node_id: nid(b),
            address: format!("127.0.0.1:{}", 9000 + b as u16),
            epoch,
            tags: tags.iter().map(|s| s.to_string()).collect(),
        }
    }

    // MDS1: insert and lookup.
    #[test]
    fn mds1_insert_lookup() {
        let mut svc = MeshDirectoryService::new(10, 5);
        svc.insert(desc(1, 10, &["relay"]), 10).unwrap();
        assert!(svc.lookup(&nid(1)).is_some());
    }

    // MDS2: duplicate insert rejected.
    #[test]
    fn mds2_duplicate_rejected() {
        let mut svc = MeshDirectoryService::new(10, 5);
        svc.insert(desc(1, 10, &[]), 10).unwrap();
        assert_eq!(
            svc.insert(desc(1, 10, &[]), 10),
            Err(DirectoryError::Duplicate)
        );
    }

    // MDS3: stale epoch rejected.
    #[test]
    fn mds3_stale_epoch_rejected() {
        let mut svc = MeshDirectoryService::new(10, 3);
        assert_eq!(
            svc.insert(desc(1, 99, &[]), 10),
            Err(DirectoryError::StaleEpoch)
        );
    }

    // MDS4: capacity limit enforced.
    #[test]
    fn mds4_capacity_exceeded() {
        let mut svc = MeshDirectoryService::new(2, 5);
        svc.insert(desc(1, 10, &[]), 10).unwrap();
        svc.insert(desc(2, 10, &[]), 10).unwrap();
        assert_eq!(
            svc.insert(desc(3, 10, &[]), 10),
            Err(DirectoryError::CapacityExceeded)
        );
    }

    // MDS5: remove decrements entry count.
    #[test]
    fn mds5_remove() {
        let mut svc = MeshDirectoryService::new(10, 5);
        svc.insert(desc(1, 10, &[]), 10).unwrap();
        assert!(svc.remove(&nid(1)));
        assert_eq!(svc.entry_count(), 0);
    }

    // MDS6: query_by_tag returns matching entries.
    #[test]
    fn mds6_query_by_tag() {
        let mut svc = MeshDirectoryService::new(10, 5);
        svc.insert(desc(1, 10, &["guard"]), 10).unwrap();
        svc.insert(desc(2, 10, &["relay"]), 10).unwrap();
        svc.insert(desc(3, 10, &["guard", "relay"]), 10).unwrap();
        let guards = svc.query_by_tag("guard");
        assert_eq!(guards.len(), 2);
    }

    // MDS7: evict_stale removes outdated entries.
    #[test]
    fn mds7_evict_stale() {
        let mut svc = MeshDirectoryService::new(10, 3);
        svc.insert(desc(1, 0, &[]), 0).unwrap();
        svc.insert(desc(2, 1, &[]), 0).unwrap();
        let evicted = svc.evict_stale(100);
        assert_eq!(evicted, 2);
        assert_eq!(svc.entry_count(), 0);
    }

    // MDS8: eviction_count accumulates.
    #[test]
    fn mds8_eviction_count() {
        let mut svc = MeshDirectoryService::new(10, 0);
        svc.insert(desc(1, 0, &[]), 0).unwrap();
        svc.evict_stale(10);
        assert!(svc.eviction_count() >= 1);
    }

    // MDS9: update replaces entry.
    #[test]
    fn mds9_update() {
        let mut svc = MeshDirectoryService::new(10, 5);
        svc.insert(desc(1, 10, &["relay"]), 10).unwrap();
        svc.update(desc(1, 11, &["guard"]), 11).unwrap();
        let d = svc.lookup(&nid(1)).unwrap();
        assert!(d.tags.contains(&"guard".to_string()));
    }

    // MDS10: update non-existent returns NotFound.
    #[test]
    fn mds10_update_not_found() {
        let mut svc = MeshDirectoryService::new(10, 5);
        assert_eq!(
            svc.update(desc(9, 10, &[]), 10),
            Err(DirectoryError::NotFound)
        );
    }
}
