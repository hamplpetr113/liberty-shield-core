//! Node version registry — tracks software versions and compatibility constraints.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl Version {
    pub fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn is_compatible_with(&self, min: &Version) -> bool {
        self >= min
    }
}

#[derive(Debug, Clone)]
pub struct NodeVersionEntry {
    pub node_id: [u8; 32],
    pub version: Version,
    pub registered_epoch: u64,
    pub last_seen_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionError {
    NotFound,
    IncompatibleVersion,
    AlreadyRegistered,
}

pub struct NodeVersionRegistry {
    entries: HashMap<[u8; 32], NodeVersionEntry>,
    min_version: Version,
    incompatible_count: u64,
}

impl NodeVersionRegistry {
    pub fn new(min_version: Version) -> Self {
        Self {
            entries: HashMap::new(),
            min_version,
            incompatible_count: 0,
        }
    }

    pub fn register(
        &mut self,
        node_id: [u8; 32],
        version: Version,
        epoch: u64,
    ) -> Result<(), VersionError> {
        if self.entries.contains_key(&node_id) {
            return Err(VersionError::AlreadyRegistered);
        }
        if !version.is_compatible_with(&self.min_version) {
            self.incompatible_count += 1;
            return Err(VersionError::IncompatibleVersion);
        }
        self.entries.insert(
            node_id,
            NodeVersionEntry {
                node_id,
                version,
                registered_epoch: epoch,
                last_seen_epoch: epoch,
            },
        );
        Ok(())
    }

    pub fn update_seen(&mut self, node_id: &[u8; 32], epoch: u64) -> Result<(), VersionError> {
        self.entries
            .get_mut(node_id)
            .ok_or(VersionError::NotFound)
            .map(|e| e.last_seen_epoch = epoch)
    }

    pub fn get(&self, node_id: &[u8; 32]) -> Option<&NodeVersionEntry> {
        self.entries.get(node_id)
    }

    pub fn remove(&mut self, node_id: &[u8; 32]) -> bool {
        self.entries.remove(node_id).is_some()
    }

    pub fn compatible_nodes(&self) -> Vec<[u8; 32]> {
        self.entries.keys().copied().collect()
    }

    pub fn node_count(&self) -> usize {
        self.entries.len()
    }

    pub fn incompatible_count(&self) -> u64 {
        self.incompatible_count
    }

    pub fn stale_nodes(&self, current_epoch: u64, max_age: u64) -> Vec<[u8; 32]> {
        self.entries
            .values()
            .filter(|e| current_epoch.saturating_sub(e.last_seen_epoch) > max_age)
            .map(|e| e.node_id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }
    fn v(maj: u16, min: u16, pat: u16) -> Version {
        Version::new(maj, min, pat)
    }

    // NVR1: register and retrieve.
    #[test]
    fn nvr1_register_get() {
        let mut r = NodeVersionRegistry::new(v(1, 0, 0));
        r.register(nid(1), v(1, 2, 3), 10).unwrap();
        assert_eq!(r.get(&nid(1)).unwrap().version, v(1, 2, 3));
    }

    // NVR2: duplicate registration fails.
    #[test]
    fn nvr2_duplicate() {
        let mut r = NodeVersionRegistry::new(v(1, 0, 0));
        r.register(nid(1), v(2, 0, 0), 1).unwrap();
        assert_eq!(
            r.register(nid(1), v(2, 0, 0), 2),
            Err(VersionError::AlreadyRegistered)
        );
    }

    // NVR3: incompatible version rejected.
    #[test]
    fn nvr3_incompatible() {
        let mut r = NodeVersionRegistry::new(v(2, 0, 0));
        assert_eq!(
            r.register(nid(1), v(1, 9, 9), 1),
            Err(VersionError::IncompatibleVersion)
        );
    }

    // NVR4: incompatible_count increments.
    #[test]
    fn nvr4_incompatible_count() {
        let mut r = NodeVersionRegistry::new(v(3, 0, 0));
        let _ = r.register(nid(1), v(1, 0, 0), 1);
        let _ = r.register(nid(2), v(2, 0, 0), 1);
        assert_eq!(r.incompatible_count(), 2);
    }

    // NVR5: update_seen advances last_seen_epoch.
    #[test]
    fn nvr5_update_seen() {
        let mut r = NodeVersionRegistry::new(v(1, 0, 0));
        r.register(nid(1), v(1, 0, 0), 5).unwrap();
        r.update_seen(&nid(1), 20).unwrap();
        assert_eq!(r.get(&nid(1)).unwrap().last_seen_epoch, 20);
    }

    // NVR6: update_seen unknown node fails.
    #[test]
    fn nvr6_update_seen_missing() {
        let mut r = NodeVersionRegistry::new(v(1, 0, 0));
        assert_eq!(r.update_seen(&nid(99), 1), Err(VersionError::NotFound));
    }

    // NVR7: remove deletes entry.
    #[test]
    fn nvr7_remove() {
        let mut r = NodeVersionRegistry::new(v(1, 0, 0));
        r.register(nid(1), v(1, 0, 0), 1).unwrap();
        assert!(r.remove(&nid(1)));
        assert_eq!(r.node_count(), 0);
    }

    // NVR8: node_count correct.
    #[test]
    fn nvr8_node_count() {
        let mut r = NodeVersionRegistry::new(v(1, 0, 0));
        r.register(nid(1), v(1, 0, 0), 1).unwrap();
        r.register(nid(2), v(2, 0, 0), 1).unwrap();
        assert_eq!(r.node_count(), 2);
    }

    // NVR9: stale_nodes detects old last_seen.
    #[test]
    fn nvr9_stale_nodes() {
        let mut r = NodeVersionRegistry::new(v(1, 0, 0));
        r.register(nid(1), v(1, 0, 0), 1).unwrap();
        r.register(nid(2), v(1, 0, 0), 50).unwrap();
        let stale = r.stale_nodes(60, 20);
        assert_eq!(stale.len(), 1);
        assert!(stale.contains(&nid(1)));
    }

    // NVR10: Version ordering correct.
    #[test]
    fn nvr10_version_ordering() {
        assert!(v(2, 0, 0) > v(1, 9, 9));
        assert!(v(1, 1, 0) > v(1, 0, 9));
        assert!(v(1, 0, 1) > v(1, 0, 0));
    }
}
