//! Peer connection pool — manages a bounded set of active peer connections.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Active,
    Draining,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolError {
    PoolFull,
    AlreadyConnected,
    NotFound,
}

#[derive(Debug, Clone)]
pub struct Connection {
    pub peer_id: [u8; 32],
    pub state: ConnectionState,
    pub created_epoch: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl Connection {
    fn new(peer_id: [u8; 32], epoch: u64) -> Self {
        Self {
            peer_id,
            state: ConnectionState::Connecting,
            created_epoch: epoch,
            bytes_in: 0,
            bytes_out: 0,
        }
    }
}

pub struct PeerConnectionPool {
    max_connections: usize,
    connections: HashMap<[u8; 32], Connection>,
    total_accepted: u64,
    total_closed: u64,
}

impl PeerConnectionPool {
    pub fn new(max_connections: usize) -> Self {
        Self {
            max_connections,
            connections: HashMap::new(),
            total_accepted: 0,
            total_closed: 0,
        }
    }

    pub fn connect(&mut self, peer_id: [u8; 32], epoch: u64) -> Result<(), PoolError> {
        if self.connections.contains_key(&peer_id) {
            return Err(PoolError::AlreadyConnected);
        }
        if self.connections.len() >= self.max_connections {
            return Err(PoolError::PoolFull);
        }
        self.connections
            .insert(peer_id, Connection::new(peer_id, epoch));
        self.total_accepted += 1;
        Ok(())
    }

    pub fn activate(&mut self, peer_id: &[u8; 32]) -> Result<(), PoolError> {
        let conn = self
            .connections
            .get_mut(peer_id)
            .ok_or(PoolError::NotFound)?;
        conn.state = ConnectionState::Active;
        Ok(())
    }

    pub fn drain(&mut self, peer_id: &[u8; 32]) -> Result<(), PoolError> {
        let conn = self
            .connections
            .get_mut(peer_id)
            .ok_or(PoolError::NotFound)?;
        conn.state = ConnectionState::Draining;
        Ok(())
    }

    pub fn close(&mut self, peer_id: &[u8; 32]) -> Result<(), PoolError> {
        if self.connections.remove(peer_id).is_none() {
            return Err(PoolError::NotFound);
        }
        self.total_closed += 1;
        Ok(())
    }

    pub fn record_bytes(&mut self, peer_id: &[u8; 32], bytes_in: u64, bytes_out: u64) {
        if let Some(c) = self.connections.get_mut(peer_id) {
            c.bytes_in += bytes_in;
            c.bytes_out += bytes_out;
        }
    }

    pub fn get(&self, peer_id: &[u8; 32]) -> Option<&Connection> {
        self.connections.get(peer_id)
    }

    pub fn active_connections(&self) -> Vec<[u8; 32]> {
        self.connections
            .values()
            .filter(|c| c.state == ConnectionState::Active)
            .map(|c| c.peer_id)
            .collect()
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
    pub fn total_accepted(&self) -> u64 {
        self.total_accepted
    }
    pub fn total_closed(&self) -> u64 {
        self.total_closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // PCP1: connect creates entry in Connecting state.
    #[test]
    fn pcp1_connect() {
        let mut p = PeerConnectionPool::new(10);
        p.connect(nid(1), 0).unwrap();
        assert_eq!(p.get(&nid(1)).unwrap().state, ConnectionState::Connecting);
    }

    // PCP2: activate moves to Active.
    #[test]
    fn pcp2_activate() {
        let mut p = PeerConnectionPool::new(10);
        p.connect(nid(1), 0).unwrap();
        p.activate(&nid(1)).unwrap();
        assert_eq!(p.get(&nid(1)).unwrap().state, ConnectionState::Active);
    }

    // PCP3: duplicate connect returns AlreadyConnected.
    #[test]
    fn pcp3_duplicate() {
        let mut p = PeerConnectionPool::new(10);
        p.connect(nid(1), 0).unwrap();
        assert_eq!(p.connect(nid(1), 1), Err(PoolError::AlreadyConnected));
    }

    // PCP4: pool full returns PoolFull.
    #[test]
    fn pcp4_pool_full() {
        let mut p = PeerConnectionPool::new(1);
        p.connect(nid(1), 0).unwrap();
        assert_eq!(p.connect(nid(2), 0), Err(PoolError::PoolFull));
    }

    // PCP5: close removes connection.
    #[test]
    fn pcp5_close() {
        let mut p = PeerConnectionPool::new(10);
        p.connect(nid(1), 0).unwrap();
        p.close(&nid(1)).unwrap();
        assert!(p.get(&nid(1)).is_none());
    }

    // PCP6: close unknown returns NotFound.
    #[test]
    fn pcp6_close_not_found() {
        let mut p = PeerConnectionPool::new(10);
        assert_eq!(p.close(&nid(99)), Err(PoolError::NotFound));
    }

    // PCP7: record_bytes accumulates.
    #[test]
    fn pcp7_record_bytes() {
        let mut p = PeerConnectionPool::new(10);
        p.connect(nid(1), 0).unwrap();
        p.record_bytes(&nid(1), 100, 200);
        let c = p.get(&nid(1)).unwrap();
        assert_eq!(c.bytes_in, 100);
        assert_eq!(c.bytes_out, 200);
    }

    // PCP8: active_connections filters.
    #[test]
    fn pcp8_active_connections() {
        let mut p = PeerConnectionPool::new(10);
        p.connect(nid(1), 0).unwrap();
        p.connect(nid(2), 0).unwrap();
        p.activate(&nid(1)).unwrap();
        assert_eq!(p.active_connections().len(), 1);
    }

    // PCP9: total_accepted accumulates.
    #[test]
    fn pcp9_total_accepted() {
        let mut p = PeerConnectionPool::new(10);
        p.connect(nid(1), 0).unwrap();
        p.connect(nid(2), 0).unwrap();
        assert_eq!(p.total_accepted(), 2);
    }

    // PCP10: total_closed accumulates.
    #[test]
    fn pcp10_total_closed() {
        let mut p = PeerConnectionPool::new(10);
        p.connect(nid(1), 0).unwrap();
        p.close(&nid(1)).unwrap();
        assert_eq!(p.total_closed(), 1);
    }
}
