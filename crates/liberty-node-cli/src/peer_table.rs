#[derive(Debug, Clone, PartialEq)]
pub struct PeerInfo {
    pub peer_id: u64,
    pub address: String,
    pub port: u16,
    pub reliability_score: f64,
    pub latency_estimate: u64,
    pub connected: bool,
}

#[derive(Debug, PartialEq)]
pub enum PeerTableError {
    DuplicatePeer,
    PeerNotFound,
    TableFull,
}

pub struct PeerTable {
    peers: Vec<PeerInfo>,
    max_peers: usize,
}

impl PeerTable {
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: Vec::new(),
            max_peers,
        }
    }

    /// Add a peer. Rejects duplicates and enforces `max_peers`.
    /// Peers are kept sorted by `peer_id` for deterministic ordering.
    pub fn add_peer(&mut self, peer: PeerInfo) -> Result<(), PeerTableError> {
        if self.peers.len() >= self.max_peers {
            return Err(PeerTableError::TableFull);
        }
        if self.peers.iter().any(|p| p.peer_id == peer.peer_id) {
            return Err(PeerTableError::DuplicatePeer);
        }
        self.peers.push(peer);
        self.peers.sort_by_key(|p| p.peer_id);
        Ok(())
    }

    pub fn remove_peer(&mut self, peer_id: u64) -> Result<(), PeerTableError> {
        let pos = self
            .peers
            .iter()
            .position(|p| p.peer_id == peer_id)
            .ok_or(PeerTableError::PeerNotFound)?;
        self.peers.remove(pos);
        Ok(())
    }

    pub fn get_peer(&self, peer_id: u64) -> Option<&PeerInfo> {
        self.peers.iter().find(|p| p.peer_id == peer_id)
    }

    pub fn list_peers(&self) -> &[PeerInfo] {
        &self.peers
    }

    pub fn connected_peers(&self) -> Vec<&PeerInfo> {
        self.peers.iter().filter(|p| p.connected).collect()
    }

    pub fn mark_connected(&mut self, peer_id: u64) -> Result<(), PeerTableError> {
        self.peers
            .iter_mut()
            .find(|p| p.peer_id == peer_id)
            .ok_or(PeerTableError::PeerNotFound)?
            .connected = true;
        Ok(())
    }

    pub fn mark_disconnected(&mut self, peer_id: u64) -> Result<(), PeerTableError> {
        self.peers
            .iter_mut()
            .find(|p| p.peer_id == peer_id)
            .ok_or(PeerTableError::PeerNotFound)?
            .connected = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer(id: u64) -> PeerInfo {
        PeerInfo {
            peer_id: id,
            address: "127.0.0.1".to_string(),
            port: (9000 + id) as u16,
            reliability_score: 0.9,
            latency_estimate: 100,
            connected: false,
        }
    }

    // P1: add peer
    #[test]
    fn p1_add_peer() {
        let mut table = PeerTable::new(10);
        table.add_peer(make_peer(1)).unwrap();
        assert_eq!(table.list_peers().len(), 1);
        assert_eq!(table.get_peer(1).unwrap().peer_id, 1);
    }

    // P2: duplicate peer rejected
    #[test]
    fn p2_duplicate_rejected() {
        let mut table = PeerTable::new(10);
        table.add_peer(make_peer(1)).unwrap();
        assert_eq!(
            table.add_peer(make_peer(1)).unwrap_err(),
            PeerTableError::DuplicatePeer
        );
    }

    // P3: max peers enforced
    #[test]
    fn p3_max_peers_enforced() {
        let mut table = PeerTable::new(2);
        table.add_peer(make_peer(1)).unwrap();
        table.add_peer(make_peer(2)).unwrap();
        assert_eq!(
            table.add_peer(make_peer(3)).unwrap_err(),
            PeerTableError::TableFull
        );
    }

    // P4: mark connected
    #[test]
    fn p4_mark_connected() {
        let mut table = PeerTable::new(10);
        table.add_peer(make_peer(5)).unwrap();
        assert!(!table.get_peer(5).unwrap().connected);
        table.mark_connected(5).unwrap();
        assert!(table.get_peer(5).unwrap().connected);
        assert_eq!(table.connected_peers().len(), 1);
        table.mark_disconnected(5).unwrap();
        assert!(!table.get_peer(5).unwrap().connected);
        assert_eq!(table.connected_peers().len(), 0);
    }

    // P5: list is sorted by peer_id regardless of insertion order
    #[test]
    fn p5_list_deterministic_order() {
        let mut table = PeerTable::new(10);
        table.add_peer(make_peer(3)).unwrap();
        table.add_peer(make_peer(1)).unwrap();
        table.add_peer(make_peer(2)).unwrap();
        let peers = table.list_peers();
        assert_eq!(peers[0].peer_id, 1);
        assert_eq!(peers[1].peer_id, 2);
        assert_eq!(peers[2].peer_id, 3);
    }

    // P6: remove peer
    #[test]
    fn p6_remove_peer() {
        let mut table = PeerTable::new(10);
        table.add_peer(make_peer(10)).unwrap();
        table.add_peer(make_peer(20)).unwrap();
        table.remove_peer(10).unwrap();
        assert_eq!(table.list_peers().len(), 1);
        assert!(table.get_peer(10).is_none());
        assert_eq!(
            table.remove_peer(10).unwrap_err(),
            PeerTableError::PeerNotFound
        );
    }
}
