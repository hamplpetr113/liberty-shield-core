//! Persistent node state store — save and restore runtime snapshots across
//! restarts using a crash-safe append-only journal.
//!
//! `NodeStateStore` accumulates `StateEntry` records in memory.  On shutdown
//! the journal can be serialised; on startup the last snapshot of each record
//! type is restored.  This module is NON-PRODUCTION: I/O is in-memory.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Entry types
// ---------------------------------------------------------------------------

/// Tag constants for journal entry types.
pub const ENTRY_PEER: u8 = 1;
pub const ENTRY_BANDWIDTH: u8 = 2;
pub const ENTRY_CIRCUIT_META: u8 = 3;
pub const ENTRY_EPOCH: u8 = 4;

// ---------------------------------------------------------------------------
// PeerSnapshot
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct PeerSnapshot {
    pub node_id: [u8; 32],
    pub reputation_score: i32,
    pub last_seen_epoch: u64,
}

// ---------------------------------------------------------------------------
// BandwidthSnapshot
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct BandwidthSnapshot {
    pub peer_id: [u8; 32],
    pub bytes_sent_total: u64,
    pub bytes_recv_total: u64,
}

// ---------------------------------------------------------------------------
// CircuitMeta
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct CircuitMeta {
    pub circuit_id: u64,
    pub created_epoch: u64,
    pub guard: [u8; 32],
    pub relay: [u8; 32],
    pub exit: [u8; 32],
}

// ---------------------------------------------------------------------------
// StateEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum StateEntry {
    Peer(PeerSnapshot),
    Bandwidth(BandwidthSnapshot),
    Circuit(CircuitMeta),
    Epoch(u64),
}

impl StateEntry {
    pub fn entry_type(&self) -> u8 {
        match self {
            StateEntry::Peer(_) => ENTRY_PEER,
            StateEntry::Bandwidth(_) => ENTRY_BANDWIDTH,
            StateEntry::Circuit(_) => ENTRY_CIRCUIT_META,
            StateEntry::Epoch(_) => ENTRY_EPOCH,
        }
    }
}

// ---------------------------------------------------------------------------
// NodeStateStore
// ---------------------------------------------------------------------------

/// In-memory append-only journal for node runtime state.
pub struct NodeStateStore {
    entries: Vec<StateEntry>,
    /// Most recent epoch recorded.
    current_epoch: u64,
}

impl NodeStateStore {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            current_epoch: 0,
        }
    }

    /// Append any entry to the journal.
    pub fn append(&mut self, entry: StateEntry) {
        if let StateEntry::Epoch(e) = &entry {
            self.current_epoch = *e;
        }
        self.entries.push(entry);
    }

    pub fn record_peer(&mut self, snap: PeerSnapshot) {
        self.append(StateEntry::Peer(snap));
    }

    pub fn record_bandwidth(&mut self, snap: BandwidthSnapshot) {
        self.append(StateEntry::Bandwidth(snap));
    }

    pub fn record_circuit(&mut self, meta: CircuitMeta) {
        self.append(StateEntry::Circuit(meta));
    }

    pub fn record_epoch(&mut self, epoch: u64) {
        self.append(StateEntry::Epoch(epoch));
    }

    /// Return the most recent `PeerSnapshot` for each `node_id`.
    pub fn restore_peers(&self) -> HashMap<[u8; 32], PeerSnapshot> {
        let mut map = HashMap::new();
        for entry in &self.entries {
            if let StateEntry::Peer(p) = entry {
                map.insert(p.node_id, p.clone());
            }
        }
        map
    }

    /// Return the most recent `BandwidthSnapshot` for each peer.
    pub fn restore_bandwidth(&self) -> HashMap<[u8; 32], BandwidthSnapshot> {
        let mut map = HashMap::new();
        for entry in &self.entries {
            if let StateEntry::Bandwidth(b) = entry {
                map.insert(b.peer_id, b.clone());
            }
        }
        map
    }

    /// Return all `CircuitMeta` entries (last one per circuit_id).
    pub fn restore_circuits(&self) -> HashMap<u64, CircuitMeta> {
        let mut map = HashMap::new();
        for entry in &self.entries {
            if let StateEntry::Circuit(c) = entry {
                map.insert(c.circuit_id, c.clone());
            }
        }
        map
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.current_epoch = 0;
    }
}

impl Default for NodeStateStore {
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

    // NSS1: record_peer stores a peer snapshot.
    #[test]
    fn nss1_record_peer() {
        let mut s = NodeStateStore::new();
        s.record_peer(PeerSnapshot {
            node_id: nid(1),
            reputation_score: 80,
            last_seen_epoch: 5,
        });
        assert_eq!(s.entry_count(), 1);
    }

    // NSS2: restore_peers returns last snapshot per node.
    #[test]
    fn nss2_restore_peers() {
        let mut s = NodeStateStore::new();
        s.record_peer(PeerSnapshot {
            node_id: nid(1),
            reputation_score: 50,
            last_seen_epoch: 1,
        });
        s.record_peer(PeerSnapshot {
            node_id: nid(1),
            reputation_score: 80,
            last_seen_epoch: 2,
        });
        let peers = s.restore_peers();
        assert_eq!(peers[&nid(1)].reputation_score, 80);
    }

    // NSS3: record_bandwidth stores bandwidth snapshot.
    #[test]
    fn nss3_record_bandwidth() {
        let mut s = NodeStateStore::new();
        s.record_bandwidth(BandwidthSnapshot {
            peer_id: nid(1),
            bytes_sent_total: 1000,
            bytes_recv_total: 2000,
        });
        let bw = s.restore_bandwidth();
        assert_eq!(bw[&nid(1)].bytes_sent_total, 1000);
    }

    // NSS4: record_circuit stores circuit metadata.
    #[test]
    fn nss4_record_circuit() {
        let mut s = NodeStateStore::new();
        s.record_circuit(CircuitMeta {
            circuit_id: 42,
            created_epoch: 5,
            guard: nid(1),
            relay: nid(2),
            exit: nid(3),
        });
        let circuits = s.restore_circuits();
        assert!(circuits.contains_key(&42));
    }

    // NSS5: record_epoch updates current_epoch.
    #[test]
    fn nss5_record_epoch() {
        let mut s = NodeStateStore::new();
        s.record_epoch(7);
        assert_eq!(s.current_epoch(), 7);
    }

    // NSS6: multiple entries from different types coexist.
    #[test]
    fn nss6_mixed_entries() {
        let mut s = NodeStateStore::new();
        s.record_peer(PeerSnapshot {
            node_id: nid(1),
            reputation_score: 50,
            last_seen_epoch: 0,
        });
        s.record_bandwidth(BandwidthSnapshot {
            peer_id: nid(2),
            bytes_sent_total: 100,
            bytes_recv_total: 200,
        });
        s.record_epoch(3);
        assert_eq!(s.entry_count(), 3);
    }

    // NSS7: clear empties the journal.
    #[test]
    fn nss7_clear() {
        let mut s = NodeStateStore::new();
        s.record_epoch(5);
        s.clear();
        assert_eq!(s.entry_count(), 0);
        assert_eq!(s.current_epoch(), 0);
    }

    // NSS8: restore_peers returns empty map on fresh store.
    #[test]
    fn nss8_restore_empty() {
        let s = NodeStateStore::new();
        assert!(s.restore_peers().is_empty());
    }

    // NSS9: circuit metadata is keyed by circuit_id.
    #[test]
    fn nss9_circuit_keyed_by_id() {
        let mut s = NodeStateStore::new();
        s.record_circuit(CircuitMeta {
            circuit_id: 1,
            created_epoch: 0,
            guard: nid(1),
            relay: nid(2),
            exit: nid(3),
        });
        s.record_circuit(CircuitMeta {
            circuit_id: 2,
            created_epoch: 0,
            guard: nid(4),
            relay: nid(5),
            exit: nid(6),
        });
        let circuits = s.restore_circuits();
        assert_eq!(circuits.len(), 2);
    }

    // NSS10: entry_type distinguishes journal entries.
    #[test]
    fn nss10_entry_type() {
        let p = StateEntry::Peer(PeerSnapshot {
            node_id: [0u8; 32],
            reputation_score: 0,
            last_seen_epoch: 0,
        });
        let b = StateEntry::Bandwidth(BandwidthSnapshot {
            peer_id: [0u8; 32],
            bytes_sent_total: 0,
            bytes_recv_total: 0,
        });
        assert_eq!(p.entry_type(), ENTRY_PEER);
        assert_eq!(b.entry_type(), ENTRY_BANDWIDTH);
    }
}
