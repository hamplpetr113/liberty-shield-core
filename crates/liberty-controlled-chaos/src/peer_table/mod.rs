//! Peer table — tracks connected peers with latency, reputation, and state.
//!
//! `best_peers(limit)` returns up to `limit` peers in descending order of
//! `reputation_score`, filtered to `Connected` state.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// PeerId
// ---------------------------------------------------------------------------

/// Opaque peer identifier (32-byte node_id).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    pub fn new(node_id: [u8; 32]) -> Self {
        Self(node_id)
    }
}

impl From<[u8; 32]> for PeerId {
    fn from(v: [u8; 32]) -> Self {
        Self(v)
    }
}

// ---------------------------------------------------------------------------
// PeerState
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Connected,
    Unreachable,
    Banned,
}

// ---------------------------------------------------------------------------
// PeerInfo
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_id: [u8; 32],
    /// Epoch at which we last heard from this peer.
    pub last_seen_epoch: u64,
    /// Most recent measured latency in milliseconds.
    pub latency_ms: u64,
    /// Higher is better; starts at 50, capped [0, 100].
    pub reputation_score: i32,
    pub state: PeerState,
}

impl PeerInfo {
    fn new(node_id: [u8; 32], epoch: u64) -> Self {
        Self {
            node_id,
            last_seen_epoch: epoch,
            latency_ms: 0,
            reputation_score: 50,
            state: PeerState::Connected,
        }
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTableError {
    /// The peer is already in the table.
    DuplicatePeer,
    /// No peer with that ID exists.
    NotFound,
    /// Operation not valid in current state (e.g. updating a Banned peer).
    InvalidState,
}

impl std::fmt::Display for PeerTableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerTableError::DuplicatePeer => write!(f, "peer already exists"),
            PeerTableError::NotFound => write!(f, "peer not found"),
            PeerTableError::InvalidState => write!(f, "invalid state for operation"),
        }
    }
}

// ---------------------------------------------------------------------------
// PeerTable
// ---------------------------------------------------------------------------

/// Table of known peers.
pub struct PeerTable {
    peers: HashMap<PeerId, PeerInfo>,
}

impl PeerTable {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Register a new peer.  Fails if the peer is already known.
    pub fn add_peer(&mut self, node_id: [u8; 32], epoch: u64) -> Result<(), PeerTableError> {
        let id = PeerId(node_id);
        if self.peers.contains_key(&id) {
            return Err(PeerTableError::DuplicatePeer);
        }
        self.peers.insert(id, PeerInfo::new(node_id, epoch));
        Ok(())
    }

    /// Remove a peer entirely.
    pub fn remove_peer(&mut self, node_id: &[u8; 32]) -> Result<(), PeerTableError> {
        self.peers
            .remove(&PeerId(*node_id))
            .map(|_| ())
            .ok_or(PeerTableError::NotFound)
    }

    /// Update the measured latency for a peer.
    pub fn update_latency(
        &mut self,
        node_id: &[u8; 32],
        latency_ms: u64,
    ) -> Result<(), PeerTableError> {
        let info = self
            .peers
            .get_mut(&PeerId(*node_id))
            .ok_or(PeerTableError::NotFound)?;
        info.latency_ms = latency_ms;
        Ok(())
    }

    /// Mark a peer as unreachable and penalise its reputation.
    pub fn mark_unreachable(&mut self, node_id: &[u8; 32]) -> Result<(), PeerTableError> {
        let info = self
            .peers
            .get_mut(&PeerId(*node_id))
            .ok_or(PeerTableError::NotFound)?;
        if info.state == PeerState::Banned {
            return Err(PeerTableError::InvalidState);
        }
        info.state = PeerState::Unreachable;
        info.reputation_score = (info.reputation_score - 10).max(0);
        Ok(())
    }

    /// Ban a peer permanently.
    pub fn ban_peer(&mut self, node_id: &[u8; 32]) -> Result<(), PeerTableError> {
        let info = self
            .peers
            .get_mut(&PeerId(*node_id))
            .ok_or(PeerTableError::NotFound)?;
        info.state = PeerState::Banned;
        info.reputation_score = 0;
        Ok(())
    }

    /// Reward a peer's reputation (+5, capped at 100).
    pub fn reward_peer(&mut self, node_id: &[u8; 32]) -> Result<(), PeerTableError> {
        let info = self
            .peers
            .get_mut(&PeerId(*node_id))
            .ok_or(PeerTableError::NotFound)?;
        if info.state == PeerState::Banned {
            return Err(PeerTableError::InvalidState);
        }
        info.reputation_score = (info.reputation_score + 5).min(100);
        Ok(())
    }

    /// Return up to `limit` connected peers sorted by reputation descending.
    pub fn best_peers(&self, limit: usize) -> Vec<&PeerInfo> {
        let mut connected: Vec<&PeerInfo> = self
            .peers
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .collect();
        connected.sort_by(|a, b| {
            b.reputation_score
                .cmp(&a.reputation_score)
                .then_with(|| a.node_id.cmp(&b.node_id))
        });
        connected.truncate(limit);
        connected
    }

    /// Get peer info by node_id.
    pub fn get(&self, node_id: &[u8; 32]) -> Option<&PeerInfo> {
        self.peers.get(&PeerId(*node_id))
    }

    /// Total number of tracked peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::new()
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

    // PT1: add peer succeeds and stores connected state.
    #[test]
    fn pt1_add_peer() {
        let mut t = PeerTable::new();
        t.add_peer(nid(1), 0).unwrap();
        let p = t.get(&nid(1)).unwrap();
        assert_eq!(p.state, PeerState::Connected);
        assert_eq!(p.reputation_score, 50);
    }

    // PT2: remove peer succeeds; second remove returns NotFound.
    #[test]
    fn pt2_remove_peer() {
        let mut t = PeerTable::new();
        t.add_peer(nid(1), 0).unwrap();
        t.remove_peer(&nid(1)).unwrap();
        assert_eq!(
            t.remove_peer(&nid(1)).unwrap_err(),
            PeerTableError::NotFound
        );
    }

    // PT3: update_latency stores the new value.
    #[test]
    fn pt3_update_latency() {
        let mut t = PeerTable::new();
        t.add_peer(nid(1), 0).unwrap();
        t.update_latency(&nid(1), 42).unwrap();
        assert_eq!(t.get(&nid(1)).unwrap().latency_ms, 42);
    }

    // PT4: mark_unreachable changes state and reduces reputation.
    #[test]
    fn pt4_unreachable_state() {
        let mut t = PeerTable::new();
        t.add_peer(nid(1), 0).unwrap();
        t.mark_unreachable(&nid(1)).unwrap();
        let p = t.get(&nid(1)).unwrap();
        assert_eq!(p.state, PeerState::Unreachable);
        assert_eq!(p.reputation_score, 40);
    }

    // PT5: ban_peer sets Banned state and zeroes reputation.
    #[test]
    fn pt5_ban_peer() {
        let mut t = PeerTable::new();
        t.add_peer(nid(1), 0).unwrap();
        t.ban_peer(&nid(1)).unwrap();
        let p = t.get(&nid(1)).unwrap();
        assert_eq!(p.state, PeerState::Banned);
        assert_eq!(p.reputation_score, 0);
    }

    // PT6: best_peers returns connected peers sorted by reputation.
    #[test]
    fn pt6_best_peers_ordering() {
        let mut t = PeerTable::new();
        t.add_peer(nid(1), 0).unwrap();
        t.add_peer(nid(2), 0).unwrap();
        t.add_peer(nid(3), 0).unwrap();
        t.reward_peer(&nid(2)).unwrap(); // score: 55
        t.reward_peer(&nid(2)).unwrap(); // score: 60
        let best = t.best_peers(2);
        assert_eq!(best.len(), 2);
        assert_eq!(best[0].node_id, nid(2));
    }

    // PT7: reputation scoring stays in [0, 100].
    #[test]
    fn pt7_reputation_scoring() {
        let mut t = PeerTable::new();
        t.add_peer(nid(1), 0).unwrap();
        for _ in 0..20 {
            t.reward_peer(&nid(1)).unwrap();
        }
        assert_eq!(t.get(&nid(1)).unwrap().reputation_score, 100);
        for _ in 0..20 {
            t.mark_unreachable(&nid(1)).unwrap();
        }
        assert_eq!(t.get(&nid(1)).unwrap().reputation_score, 0);
    }

    // PT8: adding duplicate peer returns DuplicatePeer.
    #[test]
    fn pt8_duplicate_prevention() {
        let mut t = PeerTable::new();
        t.add_peer(nid(1), 0).unwrap();
        assert_eq!(
            t.add_peer(nid(1), 1).unwrap_err(),
            PeerTableError::DuplicatePeer
        );
    }

    // PT9: latency update on missing peer returns NotFound.
    #[test]
    fn pt9_latency_update_not_found() {
        let mut t = PeerTable::new();
        assert_eq!(
            t.update_latency(&nid(99), 10).unwrap_err(),
            PeerTableError::NotFound
        );
    }

    // PT10: table scales to 100 peers.
    #[test]
    fn pt10_table_scaling() {
        let mut t = PeerTable::new();
        for i in 0u8..100 {
            t.add_peer(nid(i), 0).unwrap();
        }
        assert_eq!(t.len(), 100);
        let best = t.best_peers(10);
        assert_eq!(best.len(), 10);
    }
}
