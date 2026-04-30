//! Mesh session store — persists authenticated peer sessions across epoch boundaries.
//!
//! Sessions are keyed by peer node ID and carry a symmetric key pair,
//! creation epoch, and a message counter.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// SessionKeys
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MeshSession {
    pub peer_id: [u8; 32],
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub created_epoch: u64,
    pub last_used_epoch: u64,
    pub messages_sent: u64,
    pub messages_recv: u64,
}

impl MeshSession {
    pub fn new(peer_id: [u8; 32], send_key: [u8; 32], recv_key: [u8; 32], epoch: u64) -> Self {
        Self {
            peer_id,
            send_key,
            recv_key,
            created_epoch: epoch,
            last_used_epoch: epoch,
            messages_sent: 0,
            messages_recv: 0,
        }
    }

    pub fn age(&self, current_epoch: u64) -> u64 {
        current_epoch.saturating_sub(self.created_epoch)
    }
}

// ---------------------------------------------------------------------------
// SessionStoreError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionStoreError {
    Duplicate,
    NotFound,
}

// ---------------------------------------------------------------------------
// MeshSessionStore
// ---------------------------------------------------------------------------

pub struct MeshSessionStore {
    max_sessions: usize,
    max_session_age: u64,
    sessions: HashMap<[u8; 32], MeshSession>,
    evicted: u64,
}

impl MeshSessionStore {
    pub fn new(max_sessions: usize, max_session_age: u64) -> Self {
        Self {
            max_sessions,
            max_session_age,
            sessions: HashMap::new(),
            evicted: 0,
        }
    }

    pub fn insert(&mut self, session: MeshSession) -> Result<(), SessionStoreError> {
        if self.sessions.contains_key(&session.peer_id) {
            return Err(SessionStoreError::Duplicate);
        }
        if self.sessions.len() >= self.max_sessions {
            // Evict the oldest session.
            let oldest = self
                .sessions
                .iter()
                .min_by_key(|(_, s)| s.last_used_epoch)
                .map(|(id, _)| *id);
            if let Some(id) = oldest {
                self.sessions.remove(&id);
                self.evicted += 1;
            }
        }
        self.sessions.insert(session.peer_id, session);
        Ok(())
    }

    pub fn replace(&mut self, session: MeshSession) {
        self.sessions.insert(session.peer_id, session);
    }

    pub fn get(&self, peer_id: &[u8; 32]) -> Option<&MeshSession> {
        self.sessions.get(peer_id)
    }

    pub fn get_mut(&mut self, peer_id: &[u8; 32]) -> Option<&mut MeshSession> {
        self.sessions.get_mut(peer_id)
    }

    pub fn remove(&mut self, peer_id: &[u8; 32]) -> Result<(), SessionStoreError> {
        if self.sessions.remove(peer_id).is_none() {
            return Err(SessionStoreError::NotFound);
        }
        Ok(())
    }

    /// Evict sessions older than `max_session_age`.
    pub fn evict_stale(&mut self, current_epoch: u64) -> usize {
        let max_age = self.max_session_age;
        let before = self.sessions.len();
        self.sessions.retain(|_, s| s.age(current_epoch) <= max_age);
        let evicted = before - self.sessions.len();
        self.evicted += evicted as u64;
        evicted
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn evicted_total(&self) -> u64 {
        self.evicted
    }

    pub fn record_sent(&mut self, peer_id: &[u8; 32], epoch: u64) {
        if let Some(s) = self.sessions.get_mut(peer_id) {
            s.messages_sent += 1;
            s.last_used_epoch = epoch;
        }
    }

    pub fn record_recv(&mut self, peer_id: &[u8; 32], epoch: u64) {
        if let Some(s) = self.sessions.get_mut(peer_id) {
            s.messages_recv += 1;
            s.last_used_epoch = epoch;
        }
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

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn session(peer: u8, epoch: u64) -> MeshSession {
        MeshSession::new(nid(peer), key(peer), key(peer + 1), epoch)
    }

    fn store() -> MeshSessionStore {
        MeshSessionStore::new(10, 100)
    }

    // MSS1: insert and get.
    #[test]
    fn mss1_insert_get() {
        let mut s = store();
        s.insert(session(1, 0)).unwrap();
        assert!(s.get(&nid(1)).is_some());
    }

    // MSS2: duplicate insert returns Duplicate.
    #[test]
    fn mss2_duplicate() {
        let mut s = store();
        s.insert(session(1, 0)).unwrap();
        assert_eq!(s.insert(session(1, 0)), Err(SessionStoreError::Duplicate));
    }

    // MSS3: remove session.
    #[test]
    fn mss3_remove() {
        let mut s = store();
        s.insert(session(1, 0)).unwrap();
        s.remove(&nid(1)).unwrap();
        assert!(s.get(&nid(1)).is_none());
    }

    // MSS4: remove non-existent returns NotFound.
    #[test]
    fn mss4_remove_not_found() {
        let mut s = store();
        assert_eq!(s.remove(&nid(99)), Err(SessionStoreError::NotFound));
    }

    // MSS5: evict_stale removes old sessions.
    #[test]
    fn mss5_evict_stale() {
        let mut s = MeshSessionStore::new(10, 5);
        s.insert(session(1, 0)).unwrap();
        let evicted = s.evict_stale(10);
        assert_eq!(evicted, 1);
        assert_eq!(s.session_count(), 0);
    }

    // MSS6: fresh sessions are not evicted.
    #[test]
    fn mss6_fresh_not_evicted() {
        let mut s = MeshSessionStore::new(10, 100);
        s.insert(session(1, 50)).unwrap();
        s.evict_stale(60);
        assert_eq!(s.session_count(), 1);
    }

    // MSS7: record_sent increments counter.
    #[test]
    fn mss7_record_sent() {
        let mut s = store();
        s.insert(session(1, 0)).unwrap();
        s.record_sent(&nid(1), 1);
        assert_eq!(s.get(&nid(1)).unwrap().messages_sent, 1);
    }

    // MSS8: record_recv increments counter.
    #[test]
    fn mss8_record_recv() {
        let mut s = store();
        s.insert(session(1, 0)).unwrap();
        s.record_recv(&nid(1), 1);
        assert_eq!(s.get(&nid(1)).unwrap().messages_recv, 1);
    }

    // MSS9: replace overwrites duplicate.
    #[test]
    fn mss9_replace() {
        let mut s = store();
        s.insert(session(1, 0)).unwrap();
        s.replace(session(1, 50));
        assert_eq!(s.get(&nid(1)).unwrap().created_epoch, 50);
    }

    // MSS10: capacity limit evicts oldest.
    #[test]
    fn mss10_capacity_eviction() {
        let mut s = MeshSessionStore::new(2, 1000);
        s.insert(session(1, 0)).unwrap();
        s.insert(session(2, 0)).unwrap();
        s.insert(session(3, 0)).unwrap(); // evicts one
        assert_eq!(s.session_count(), 2);
        assert!(s.evicted_total() >= 1);
    }
}
