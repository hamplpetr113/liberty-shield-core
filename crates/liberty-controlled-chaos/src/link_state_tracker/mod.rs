//! Link state tracker — monitors per-peer link up/down transitions and uptime.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Up,
    Down,
}

#[derive(Debug, Clone)]
pub struct LinkRecord {
    pub peer_id: [u8; 32],
    pub state: LinkState,
    pub up_since: Option<u64>,
    pub up_epochs: u64,
    pub down_epochs: u64,
    pub transitions: u64,
}

impl LinkRecord {
    fn new(peer_id: [u8; 32], initial_epoch: u64) -> Self {
        Self {
            peer_id,
            state: LinkState::Up,
            up_since: Some(initial_epoch),
            up_epochs: 0,
            down_epochs: 0,
            transitions: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    NotFound,
    AlreadyInState,
}

pub struct LinkStateTracker {
    records: HashMap<[u8; 32], LinkRecord>,
    total_up_events: u64,
    total_down_events: u64,
}

impl LinkStateTracker {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            total_up_events: 0,
            total_down_events: 0,
        }
    }

    pub fn register(&mut self, peer_id: [u8; 32], epoch: u64) {
        self.records
            .entry(peer_id)
            .or_insert_with(|| LinkRecord::new(peer_id, epoch));
    }

    pub fn mark_up(&mut self, peer_id: [u8; 32], epoch: u64) -> Result<(), LinkError> {
        let r = self.records.get_mut(&peer_id).ok_or(LinkError::NotFound)?;
        if r.state == LinkState::Up {
            return Err(LinkError::AlreadyInState);
        }
        r.state = LinkState::Up;
        r.up_since = Some(epoch);
        r.transitions += 1;
        self.total_up_events += 1;
        Ok(())
    }

    pub fn mark_down(&mut self, peer_id: [u8; 32], epoch: u64) -> Result<(), LinkError> {
        let r = self.records.get_mut(&peer_id).ok_or(LinkError::NotFound)?;
        if r.state == LinkState::Down {
            return Err(LinkError::AlreadyInState);
        }
        r.state = LinkState::Down;
        r.up_since = None;
        r.transitions += 1;
        self.total_down_events += 1;
        let _ = epoch;
        Ok(())
    }

    pub fn tick(&mut self, epoch: u64) {
        let _ = epoch;
        for r in self.records.values_mut() {
            match r.state {
                LinkState::Up => r.up_epochs += 1,
                LinkState::Down => r.down_epochs += 1,
            }
        }
    }

    pub fn get(&self, peer_id: &[u8; 32]) -> Option<&LinkRecord> {
        self.records.get(peer_id)
    }

    pub fn is_up(&self, peer_id: &[u8; 32]) -> bool {
        self.records
            .get(peer_id)
            .map(|r| r.state == LinkState::Up)
            .unwrap_or(false)
    }

    pub fn down_peers(&self) -> Vec<[u8; 32]> {
        self.records
            .values()
            .filter(|r| r.state == LinkState::Down)
            .map(|r| r.peer_id)
            .collect()
    }

    pub fn peer_count(&self) -> usize {
        self.records.len()
    }

    pub fn total_up_events(&self) -> u64 {
        self.total_up_events
    }
    pub fn total_down_events(&self) -> u64 {
        self.total_down_events
    }
}

impl Default for LinkStateTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // LST1: registered peer is Up.
    #[test]
    fn lst1_registered_up() {
        let mut t = LinkStateTracker::new();
        t.register(nid(1), 1);
        assert!(t.is_up(&nid(1)));
    }

    // LST2: mark_down transitions to Down.
    #[test]
    fn lst2_mark_down() {
        let mut t = LinkStateTracker::new();
        t.register(nid(1), 1);
        t.mark_down(nid(1), 2).unwrap();
        assert!(!t.is_up(&nid(1)));
    }

    // LST3: mark_up transitions to Up.
    #[test]
    fn lst3_mark_up() {
        let mut t = LinkStateTracker::new();
        t.register(nid(1), 1);
        t.mark_down(nid(1), 2).unwrap();
        t.mark_up(nid(1), 3).unwrap();
        assert!(t.is_up(&nid(1)));
    }

    // LST4: mark_down twice returns AlreadyInState.
    #[test]
    fn lst4_already_down() {
        let mut t = LinkStateTracker::new();
        t.register(nid(1), 1);
        t.mark_down(nid(1), 2).unwrap();
        assert_eq!(t.mark_down(nid(1), 3), Err(LinkError::AlreadyInState));
    }

    // LST5: mark_up twice returns AlreadyInState.
    #[test]
    fn lst5_already_up() {
        let mut t = LinkStateTracker::new();
        t.register(nid(1), 1);
        assert_eq!(t.mark_up(nid(1), 2), Err(LinkError::AlreadyInState));
    }

    // LST6: transitions counter increments.
    #[test]
    fn lst6_transitions() {
        let mut t = LinkStateTracker::new();
        t.register(nid(1), 1);
        t.mark_down(nid(1), 2).unwrap();
        t.mark_up(nid(1), 3).unwrap();
        assert_eq!(t.get(&nid(1)).unwrap().transitions, 2);
    }

    // LST7: tick increments up_epochs for Up peer.
    #[test]
    fn lst7_tick_up() {
        let mut t = LinkStateTracker::new();
        t.register(nid(1), 1);
        t.tick(2);
        t.tick(3);
        assert_eq!(t.get(&nid(1)).unwrap().up_epochs, 2);
    }

    // LST8: tick increments down_epochs for Down peer.
    #[test]
    fn lst8_tick_down() {
        let mut t = LinkStateTracker::new();
        t.register(nid(1), 1);
        t.mark_down(nid(1), 2).unwrap();
        t.tick(3);
        assert_eq!(t.get(&nid(1)).unwrap().down_epochs, 1);
    }

    // LST9: down_peers returns correct list.
    #[test]
    fn lst9_down_peers() {
        let mut t = LinkStateTracker::new();
        t.register(nid(1), 1);
        t.register(nid(2), 1);
        t.mark_down(nid(1), 2).unwrap();
        let down = t.down_peers();
        assert_eq!(down.len(), 1);
        assert!(down.contains(&nid(1)));
    }

    // LST10: unknown peer mark_down returns NotFound.
    #[test]
    fn lst10_unknown_peer() {
        let mut t = LinkStateTracker::new();
        assert_eq!(t.mark_down(nid(99), 1), Err(LinkError::NotFound));
    }
}
