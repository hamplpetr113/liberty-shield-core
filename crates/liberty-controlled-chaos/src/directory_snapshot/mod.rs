//! Directory snapshot — immutable point-in-time view of the node directory.

#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    pub node_id: [u8; 32],
    pub address: String,
    pub capabilities: u32,
    pub epoch: u64,
}

#[derive(Debug, Clone)]
pub struct DirectorySnapshot {
    pub epoch: u64,
    entries: Vec<DirectoryEntry>,
    total_entries: usize,
}

impl DirectorySnapshot {
    pub fn new(epoch: u64, entries: Vec<DirectoryEntry>) -> Self {
        let total_entries = entries.len();
        Self {
            epoch,
            entries,
            total_entries,
        }
    }

    pub fn entries(&self) -> &[DirectoryEntry] {
        &self.entries
    }

    pub fn get(&self, node_id: &[u8; 32]) -> Option<&DirectoryEntry> {
        self.entries.iter().find(|e| &e.node_id == node_id)
    }

    pub fn with_capability(&self, cap_flag: u32) -> Vec<&DirectoryEntry> {
        self.entries
            .iter()
            .filter(|e| e.capabilities & cap_flag != 0)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.total_entries
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn node_ids(&self) -> Vec<[u8; 32]> {
        self.entries.iter().map(|e| e.node_id).collect()
    }

    pub fn is_stale(&self, current_epoch: u64, max_age: u64) -> bool {
        current_epoch.saturating_sub(self.epoch) > max_age
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn entry(b: u8, caps: u32) -> DirectoryEntry {
        DirectoryEntry {
            node_id: nid(b),
            address: format!("127.0.0.{b}:9000"),
            capabilities: caps,
            epoch: 1,
        }
    }

    // DS1: new snapshot has correct epoch.
    #[test]
    fn ds1_epoch() {
        let s = DirectorySnapshot::new(5, vec![]);
        assert_eq!(s.epoch, 5);
    }

    // DS2: len returns entry count.
    #[test]
    fn ds2_len() {
        let s = DirectorySnapshot::new(1, vec![entry(1, 0), entry(2, 0)]);
        assert_eq!(s.len(), 2);
    }

    // DS3: get returns correct entry.
    #[test]
    fn ds3_get() {
        let s = DirectorySnapshot::new(1, vec![entry(1, 0xf)]);
        assert!(s.get(&nid(1)).is_some());
    }

    // DS4: get returns None for unknown node.
    #[test]
    fn ds4_get_unknown() {
        let s = DirectorySnapshot::new(1, vec![]);
        assert!(s.get(&nid(99)).is_none());
    }

    // DS5: with_capability filters by flag.
    #[test]
    fn ds5_with_capability() {
        let s = DirectorySnapshot::new(1, vec![entry(1, 0b01), entry(2, 0b10)]);
        let with = s.with_capability(0b01);
        assert_eq!(with.len(), 1);
    }

    // DS6: is_empty correct.
    #[test]
    fn ds6_is_empty() {
        let s = DirectorySnapshot::new(1, vec![]);
        assert!(s.is_empty());
    }

    // DS7: node_ids returns all IDs.
    #[test]
    fn ds7_node_ids() {
        let s = DirectorySnapshot::new(1, vec![entry(1, 0), entry(2, 0)]);
        assert_eq!(s.node_ids().len(), 2);
    }

    // DS8: is_stale false within max_age.
    #[test]
    fn ds8_not_stale() {
        let s = DirectorySnapshot::new(10, vec![]);
        assert!(!s.is_stale(15, 10));
    }

    // DS9: is_stale true beyond max_age.
    #[test]
    fn ds9_stale() {
        let s = DirectorySnapshot::new(0, vec![]);
        assert!(s.is_stale(100, 10));
    }

    // DS10: entries returns slice.
    #[test]
    fn ds10_entries_slice() {
        let s = DirectorySnapshot::new(1, vec![entry(1, 0)]);
        assert_eq!(s.entries().len(), 1);
    }
}
