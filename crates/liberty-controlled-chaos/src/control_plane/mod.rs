//! Control plane — in-process admin API for querying and controlling node state.
//!
//! `ControlPlane` aggregates read-only views from multiple subsystems and
//! accepts command requests.  It does NOT own any subsystem state — callers
//! push snapshots into it and pull aggregated status out.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// NodeStatus
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeStatus {
    Starting,
    Running,
    Degraded,
    Stopping,
    Stopped,
}

// ---------------------------------------------------------------------------
// PeerSummary
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PeerSummary {
    pub node_id: [u8; 32],
    pub trust_score: f64,
    pub is_connected: bool,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

// ---------------------------------------------------------------------------
// CircuitSummary
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CircuitSummary {
    pub circuit_id: u64,
    pub hop_count: u32,
    pub created_epoch: u64,
    pub packets_forwarded: u64,
}

// ---------------------------------------------------------------------------
// ControlCommand
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum ControlCommand {
    SetStatus(NodeStatus),
    UpsertPeer(PeerSummary),
    RemovePeer([u8; 32]),
    UpsertCircuit(CircuitSummary),
    RemoveCircuit(u64),
    Shutdown,
}

// ---------------------------------------------------------------------------
// ControlPlaneError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlPlaneError {
    NotFound,
    InvalidTransition,
    AlreadyShutdown,
}

// ---------------------------------------------------------------------------
// ControlPlane
// ---------------------------------------------------------------------------

pub struct ControlPlane {
    status: NodeStatus,
    peers: HashMap<[u8; 32], PeerSummary>,
    circuits: HashMap<u64, CircuitSummary>,
    commands_processed: u64,
}

impl ControlPlane {
    pub fn new() -> Self {
        Self {
            status: NodeStatus::Starting,
            peers: HashMap::new(),
            circuits: HashMap::new(),
            commands_processed: 0,
        }
    }

    pub fn execute(&mut self, cmd: ControlCommand) -> Result<(), ControlPlaneError> {
        if self.status == NodeStatus::Stopped && !matches!(cmd, ControlCommand::SetStatus(_)) {
            return Err(ControlPlaneError::AlreadyShutdown);
        }
        self.commands_processed += 1;
        match cmd {
            ControlCommand::SetStatus(s) => {
                self.status = s;
            }
            ControlCommand::UpsertPeer(p) => {
                self.peers.insert(p.node_id, p);
            }
            ControlCommand::RemovePeer(id) => {
                if self.peers.remove(&id).is_none() {
                    return Err(ControlPlaneError::NotFound);
                }
            }
            ControlCommand::UpsertCircuit(c) => {
                self.circuits.insert(c.circuit_id, c);
            }
            ControlCommand::RemoveCircuit(id) => {
                if self.circuits.remove(&id).is_none() {
                    return Err(ControlPlaneError::NotFound);
                }
            }
            ControlCommand::Shutdown => {
                self.status = NodeStatus::Stopped;
            }
        }
        Ok(())
    }

    pub fn status(&self) -> &NodeStatus {
        &self.status
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    pub fn peer(&self, id: &[u8; 32]) -> Option<&PeerSummary> {
        self.peers.get(id)
    }

    pub fn circuit(&self, id: u64) -> Option<&CircuitSummary> {
        self.circuits.get(&id)
    }

    pub fn commands_processed(&self) -> u64 {
        self.commands_processed
    }

    pub fn connected_peers(&self) -> Vec<&PeerSummary> {
        self.peers.values().filter(|p| p.is_connected).collect()
    }
}

impl Default for ControlPlane {
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

    fn peer(b: u8) -> PeerSummary {
        PeerSummary {
            node_id: nid(b),
            trust_score: 0.8,
            is_connected: true,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    // CPA1: initial status is Starting.
    #[test]
    fn cpa1_initial_status() {
        let cp = ControlPlane::new();
        assert_eq!(*cp.status(), NodeStatus::Starting);
    }

    // CPA2: SetStatus changes status.
    #[test]
    fn cpa2_set_status() {
        let mut cp = ControlPlane::new();
        cp.execute(ControlCommand::SetStatus(NodeStatus::Running))
            .unwrap();
        assert_eq!(*cp.status(), NodeStatus::Running);
    }

    // CPA3: UpsertPeer adds peer.
    #[test]
    fn cpa3_upsert_peer() {
        let mut cp = ControlPlane::new();
        cp.execute(ControlCommand::UpsertPeer(peer(1))).unwrap();
        assert_eq!(cp.peer_count(), 1);
    }

    // CPA4: RemovePeer removes peer.
    #[test]
    fn cpa4_remove_peer() {
        let mut cp = ControlPlane::new();
        cp.execute(ControlCommand::UpsertPeer(peer(1))).unwrap();
        cp.execute(ControlCommand::RemovePeer(nid(1))).unwrap();
        assert_eq!(cp.peer_count(), 0);
    }

    // CPA5: RemovePeer on unknown returns NotFound.
    #[test]
    fn cpa5_remove_unknown_peer() {
        let mut cp = ControlPlane::new();
        assert_eq!(
            cp.execute(ControlCommand::RemovePeer(nid(99))),
            Err(ControlPlaneError::NotFound)
        );
    }

    // CPA6: UpsertCircuit adds circuit.
    #[test]
    fn cpa6_upsert_circuit() {
        let mut cp = ControlPlane::new();
        cp.execute(ControlCommand::UpsertCircuit(CircuitSummary {
            circuit_id: 1,
            hop_count: 3,
            created_epoch: 0,
            packets_forwarded: 0,
        }))
        .unwrap();
        assert_eq!(cp.circuit_count(), 1);
    }

    // CPA7: Shutdown sets status to Stopped.
    #[test]
    fn cpa7_shutdown() {
        let mut cp = ControlPlane::new();
        cp.execute(ControlCommand::Shutdown).unwrap();
        assert_eq!(*cp.status(), NodeStatus::Stopped);
    }

    // CPA8: commands after shutdown are rejected.
    #[test]
    fn cpa8_commands_after_shutdown() {
        let mut cp = ControlPlane::new();
        cp.execute(ControlCommand::Shutdown).unwrap();
        assert_eq!(
            cp.execute(ControlCommand::UpsertPeer(peer(1))),
            Err(ControlPlaneError::AlreadyShutdown)
        );
    }

    // CPA9: commands_processed counter increments.
    #[test]
    fn cpa9_commands_processed() {
        let mut cp = ControlPlane::new();
        cp.execute(ControlCommand::SetStatus(NodeStatus::Running))
            .unwrap();
        cp.execute(ControlCommand::UpsertPeer(peer(1))).unwrap();
        assert_eq!(cp.commands_processed(), 2);
    }

    // CPA10: connected_peers filters by is_connected.
    #[test]
    fn cpa10_connected_peers() {
        let mut cp = ControlPlane::new();
        cp.execute(ControlCommand::UpsertPeer(PeerSummary {
            node_id: nid(1),
            trust_score: 0.9,
            is_connected: true,
            bytes_sent: 0,
            bytes_received: 0,
        }))
        .unwrap();
        cp.execute(ControlCommand::UpsertPeer(PeerSummary {
            node_id: nid(2),
            trust_score: 0.9,
            is_connected: false,
            bytes_sent: 0,
            bytes_received: 0,
        }))
        .unwrap();
        assert_eq!(cp.connected_peers().len(), 1);
    }
}
