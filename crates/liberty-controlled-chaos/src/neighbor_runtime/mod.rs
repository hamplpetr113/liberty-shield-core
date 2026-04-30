//! Neighbor runtime — manages direct neighbor connections with health tracking.
//!
//! `NeighborRuntime` maintains a set of `NeighborEntry` records.  Each entry
//! tracks connection state, bytes transferred, and health, integrating with
//! the peer table's reputation model.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// NeighborState
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborState {
    Connecting,
    Connected,
    Disconnected,
    Banned,
}

// ---------------------------------------------------------------------------
// NeighborEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NeighborEntry {
    pub node_id: [u8; 32],
    pub address: String,
    pub state: NeighborState,
    pub connected_epoch: u64,
    pub last_active_epoch: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub frames_sent: u64,
    pub frames_received: u64,
    pub latency_ms: u64,
}

impl NeighborEntry {
    fn new(node_id: [u8; 32], address: String, epoch: u64) -> Self {
        Self {
            node_id,
            address,
            state: NeighborState::Connecting,
            connected_epoch: epoch,
            last_active_epoch: epoch,
            bytes_sent: 0,
            bytes_received: 0,
            frames_sent: 0,
            frames_received: 0,
            latency_ms: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// NeighborError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborError {
    NotFound,
    Banned,
    NotConnected,
    AlreadyExists,
}

// ---------------------------------------------------------------------------
// NeighborRuntime
// ---------------------------------------------------------------------------

pub struct NeighborRuntime {
    neighbors: HashMap<[u8; 32], NeighborEntry>,
}

impl NeighborRuntime {
    pub fn new() -> Self {
        Self {
            neighbors: HashMap::new(),
        }
    }

    pub fn connect(
        &mut self,
        node_id: [u8; 32],
        address: String,
        epoch: u64,
    ) -> Result<(), NeighborError> {
        if let Some(e) = self.neighbors.get(&node_id) {
            if e.state == NeighborState::Banned {
                return Err(NeighborError::Banned);
            }
            if e.state == NeighborState::Connected {
                return Err(NeighborError::AlreadyExists);
            }
        }
        let entry = NeighborEntry::new(node_id, address, epoch);
        self.neighbors.insert(node_id, entry);
        Ok(())
    }

    pub fn mark_connected(&mut self, node_id: &[u8; 32]) -> Result<(), NeighborError> {
        self.neighbors
            .get_mut(node_id)
            .ok_or(NeighborError::NotFound)
            .map(|e| {
                e.state = NeighborState::Connected;
            })
    }

    pub fn disconnect(&mut self, node_id: &[u8; 32]) -> Result<(), NeighborError> {
        self.neighbors
            .get_mut(node_id)
            .ok_or(NeighborError::NotFound)
            .map(|e| {
                e.state = NeighborState::Disconnected;
            })
    }

    pub fn ban(&mut self, node_id: &[u8; 32]) -> Result<(), NeighborError> {
        self.neighbors
            .get_mut(node_id)
            .ok_or(NeighborError::NotFound)
            .map(|e| {
                e.state = NeighborState::Banned;
            })
    }

    pub fn send_frame(
        &mut self,
        node_id: &[u8; 32],
        bytes: u64,
        epoch: u64,
    ) -> Result<(), NeighborError> {
        let e = self
            .neighbors
            .get_mut(node_id)
            .ok_or(NeighborError::NotFound)?;
        if e.state != NeighborState::Connected {
            return Err(NeighborError::NotConnected);
        }
        e.bytes_sent += bytes;
        e.frames_sent += 1;
        e.last_active_epoch = epoch;
        Ok(())
    }

    pub fn recv_frame(
        &mut self,
        node_id: &[u8; 32],
        bytes: u64,
        latency_ms: u64,
        epoch: u64,
    ) -> Result<(), NeighborError> {
        let e = self
            .neighbors
            .get_mut(node_id)
            .ok_or(NeighborError::NotFound)?;
        if e.state != NeighborState::Connected {
            return Err(NeighborError::NotConnected);
        }
        e.bytes_received += bytes;
        e.frames_received += 1;
        e.latency_ms = latency_ms;
        e.last_active_epoch = epoch;
        Ok(())
    }

    pub fn neighbor(&self, node_id: &[u8; 32]) -> Option<&NeighborEntry> {
        self.neighbors.get(node_id)
    }

    pub fn connected_count(&self) -> usize {
        self.neighbors
            .values()
            .filter(|e| e.state == NeighborState::Connected)
            .count()
    }

    pub fn neighbor_count(&self) -> usize {
        self.neighbors.len()
    }
}

impl Default for NeighborRuntime {
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

    // NR1: connect registers a Connecting neighbor.
    #[test]
    fn nr1_connect() {
        let mut r = NeighborRuntime::new();
        r.connect(nid(1), "a:9000".into(), 0).unwrap();
        assert_eq!(
            r.neighbor(&nid(1)).unwrap().state,
            NeighborState::Connecting
        );
    }

    // NR2: mark_connected moves to Connected.
    #[test]
    fn nr2_mark_connected() {
        let mut r = NeighborRuntime::new();
        r.connect(nid(1), "a:9000".into(), 0).unwrap();
        r.mark_connected(&nid(1)).unwrap();
        assert_eq!(r.neighbor(&nid(1)).unwrap().state, NeighborState::Connected);
    }

    // NR3: send_frame increments bytes_sent.
    #[test]
    fn nr3_send_frame() {
        let mut r = NeighborRuntime::new();
        r.connect(nid(1), "a:9000".into(), 0).unwrap();
        r.mark_connected(&nid(1)).unwrap();
        r.send_frame(&nid(1), 100, 1).unwrap();
        assert_eq!(r.neighbor(&nid(1)).unwrap().bytes_sent, 100);
    }

    // NR4: send_frame on disconnected neighbor fails.
    #[test]
    fn nr4_send_disconnected_fails() {
        let mut r = NeighborRuntime::new();
        r.connect(nid(1), "a:9000".into(), 0).unwrap();
        assert_eq!(
            r.send_frame(&nid(1), 100, 0),
            Err(NeighborError::NotConnected)
        );
    }

    // NR5: recv_frame updates latency.
    #[test]
    fn nr5_recv_updates_latency() {
        let mut r = NeighborRuntime::new();
        r.connect(nid(1), "a:9000".into(), 0).unwrap();
        r.mark_connected(&nid(1)).unwrap();
        r.recv_frame(&nid(1), 50, 15, 1).unwrap();
        assert_eq!(r.neighbor(&nid(1)).unwrap().latency_ms, 15);
    }

    // NR6: ban marks neighbor Banned.
    #[test]
    fn nr6_ban() {
        let mut r = NeighborRuntime::new();
        r.connect(nid(1), "a:9000".into(), 0).unwrap();
        r.ban(&nid(1)).unwrap();
        assert_eq!(r.neighbor(&nid(1)).unwrap().state, NeighborState::Banned);
    }

    // NR7: connect banned neighbor returns Banned.
    #[test]
    fn nr7_connect_banned_returns_error() {
        let mut r = NeighborRuntime::new();
        r.connect(nid(1), "a:9000".into(), 0).unwrap();
        r.ban(&nid(1)).unwrap();
        assert_eq!(
            r.connect(nid(1), "a:9000".into(), 1),
            Err(NeighborError::Banned)
        );
    }

    // NR8: connected_count reflects only Connected state.
    #[test]
    fn nr8_connected_count() {
        let mut r = NeighborRuntime::new();
        r.connect(nid(1), "a:9000".into(), 0).unwrap();
        r.connect(nid(2), "b:9000".into(), 0).unwrap();
        r.mark_connected(&nid(1)).unwrap();
        assert_eq!(r.connected_count(), 1);
    }

    // NR9: disconnect moves to Disconnected.
    #[test]
    fn nr9_disconnect() {
        let mut r = NeighborRuntime::new();
        r.connect(nid(1), "a:9000".into(), 0).unwrap();
        r.mark_connected(&nid(1)).unwrap();
        r.disconnect(&nid(1)).unwrap();
        assert_eq!(
            r.neighbor(&nid(1)).unwrap().state,
            NeighborState::Disconnected
        );
    }

    // NR10: unknown neighbor returns NotFound.
    #[test]
    fn nr10_unknown_not_found() {
        let mut r = NeighborRuntime::new();
        assert_eq!(r.mark_connected(&nid(99)), Err(NeighborError::NotFound));
    }
}
