//! `PeerTable` — an in-memory registry of known mesh peers.

use std::collections::HashMap;

use super::descriptor::NodeDescriptor;

/// In-memory table of known peer descriptors, keyed by `node_id`.
#[derive(Debug, Default)]
pub struct PeerTable {
    peers: HashMap<[u8; 32], NodeDescriptor>,
}

impl PeerTable {
    pub fn new() -> Self {
        Self { peers: HashMap::new() }
    }

    /// Insert or update a peer.  If a peer with the same `node_id` already
    /// exists its descriptor is replaced.
    pub fn add_peer(&mut self, descriptor: NodeDescriptor) {
        self.peers.insert(descriptor.node_id, descriptor);
    }

    /// Remove a peer by `node_id`.  Returns the removed descriptor or `None`.
    pub fn remove_peer(&mut self, node_id: &[u8; 32]) -> Option<NodeDescriptor> {
        self.peers.remove(node_id)
    }

    /// Look up a peer by `node_id`.
    pub fn lookup_peer(&self, node_id: &[u8; 32]) -> Option<&NodeDescriptor> {
        self.peers.get(node_id)
    }

    /// Number of peers currently in the table.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Return `true` if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Iterate over all peer descriptors (unordered).
    pub fn peers(&self) -> impl Iterator<Item = &NodeDescriptor> {
        self.peers.values()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn desc(key_byte: u8, port: u16) -> NodeDescriptor {
        NodeDescriptor::new([key_byte; 32], addr(port))
    }

    // MN4: add_peer + lookup_peer returns the correct descriptor.
    #[test]
    fn mn4_add_and_lookup() {
        let mut table = PeerTable::new();
        let d = desc(0xAA, 8001);
        let id = d.node_id;
        table.add_peer(d.clone());
        assert_eq!(table.lookup_peer(&id), Some(&d));
        assert_eq!(table.len(), 1);
    }

    // MN5: lookup_peer returns None for an unknown node_id.
    #[test]
    fn mn5_lookup_unknown_returns_none() {
        let table = PeerTable::new();
        assert!(table.lookup_peer(&[0u8; 32]).is_none());
    }

    // MN6: remove_peer removes the peer and returns its descriptor.
    #[test]
    fn mn6_remove_peer() {
        let mut table = PeerTable::new();
        let d = desc(0xBB, 8002);
        let id = d.node_id;
        table.add_peer(d.clone());
        let removed = table.remove_peer(&id);
        assert_eq!(removed, Some(d));
        assert!(table.is_empty());
    }

    // MN7: add_peer with the same node_id replaces the old descriptor.
    #[test]
    fn mn7_add_peer_updates_existing() {
        let mut table = PeerTable::new();
        let d1 = desc(0xCC, 8003);
        let id = d1.node_id;
        table.add_peer(d1);

        let mut d2 = desc(0xCC, 9999); // same public key → same node_id, different address
        d2.node_id = id;
        table.add_peer(d2.clone());

        assert_eq!(table.len(), 1);
        assert_eq!(table.lookup_peer(&id), Some(&d2));
    }

    // MN8: PeerTable can hold multiple distinct peers.
    #[test]
    fn mn8_multiple_peers() {
        let mut table = PeerTable::new();
        for i in 0u8..5 {
            table.add_peer(desc(i, 8010 + i as u16));
        }
        assert_eq!(table.len(), 5);
    }
}
