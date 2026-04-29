use crate::encrypted_udp_node::{EncryptedUdpNode, EncryptedUdpNodeSnapshot};
use crate::encrypted_udp_types::{EncryptedUdpError, EncryptedUdpNodeConfig, EncryptedUdpNodeId};

/// Ring-topology cluster of `EncryptedUdpNode` instances, all bound to loopback.
///
/// NON-PRODUCTION: deterministic session seeds, loopback only.
#[derive(Debug)]
pub struct EncryptedUdpCluster {
    nodes: Vec<EncryptedUdpNode>,
}

/// Derive a pair seed from two node ids: seed(A→B) = A * 1000 + B.
fn pair_seed(from_id: u64, to_id: u64) -> u64 {
    from_id.wrapping_mul(1000).wrapping_add(to_id)
}

impl EncryptedUdpCluster {
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Create `count` nodes on contiguous ports starting at `base_port`.
    pub fn start_loopback_cluster(count: usize, base_port: u16) -> Result<Self, EncryptedUdpError> {
        if count == 0 {
            return Err(EncryptedUdpError::InvalidNode);
        }
        let mut nodes = Vec::with_capacity(count);
        for i in 0..count {
            let config = EncryptedUdpNodeConfig {
                node_id: EncryptedUdpNodeId(i as u64 + 1),
                bind_address: "127.0.0.1".to_string(),
                bind_port: base_port + i as u16,
                allow_real_udp: true,
                simulation_mode: false,
            };
            nodes.push(EncryptedUdpNode::start(config)?);
        }
        Ok(Self { nodes })
    }

    /// Wire deterministic per-peer sessions for the ring topology.
    /// Node i gets a send session to node (i+1)%n and a recv session from node (i+1)%n.
    ///
    /// For direction i → next (where next = (i+1)%n), both use pair_seed(i_id, next_id) as the
    /// forward seed and pair_seed(next_id, i_id) as the reverse seed.
    ///
    /// In short: for direction A→B, both A.send_seed and B.recv_seed are pair_seed(A,B).
    pub fn wire_deterministic_sessions(&mut self) {
        let count = self.nodes.len();
        let snapshots: Vec<EncryptedUdpNodeSnapshot> =
            self.nodes.iter().map(|n| n.snapshot()).collect();

        for i in 0..count {
            let next = (i + 1) % count;
            let from_id = snapshots[i].node_id.0;
            let to_id = snapshots[next].node_id.0;
            let fwd_seed = pair_seed(from_id, to_id);
            let rev_seed = pair_seed(to_id, from_id);
            // Node i: sends to next with fwd_seed, receives from next with rev_seed
            let _ = self.nodes[i].add_peer_session(snapshots[next].node_id, fwd_seed, rev_seed);
            // Node next: receives from i with fwd_seed, sends to i with rev_seed
            let _ = self.nodes[next].add_peer_session(snapshots[i].node_id, rev_seed, fwd_seed);
        }
    }

    /// Ring topology: node i sends encrypted payload to node (i+1) % n.
    pub fn send_encrypted_ring(&mut self, payload: &[u8]) -> Result<(), EncryptedUdpError> {
        let count = self.nodes.len();
        let snapshots: Vec<EncryptedUdpNodeSnapshot> =
            self.nodes.iter().map(|n| n.snapshot()).collect();
        for i in 0..count {
            let next = (i + 1) % count;
            let target_id = snapshots[next].node_id;
            let target_addr = snapshots[next].local_addr;
            self.nodes[i].send_payload_encrypted(target_id, target_addr, payload)?;
        }
        Ok(())
    }

    /// Drain all nodes' receive buffers. Returns total successfully received packets.
    /// Replay errors are counted as drops and do not abort the drain.
    pub fn poll_all(&mut self) -> usize {
        let mut received = 0;
        for node in &mut self.nodes {
            loop {
                match node.poll_once() {
                    Ok(Some(_)) => received += 1,
                    Ok(None) => break,
                    Err(EncryptedUdpError::ReplayDetected) => {}
                    Err(_) => break,
                }
            }
        }
        received
    }

    pub fn snapshots(&self) -> Vec<EncryptedUdpNodeSnapshot> {
        self.nodes.iter().map(|n| n.snapshot()).collect()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn stop_all(&mut self) {
        self.nodes.clear();
    }
}

impl Default for EncryptedUdpCluster {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // EC1: start 3-node encrypted cluster
    #[test]
    fn ec1_start_3_node_cluster() {
        let cluster = EncryptedUdpCluster::start_loopback_cluster(3, 43040).unwrap();
        assert_eq!(cluster.node_count(), 3);
        let snaps = cluster.snapshots();
        assert_eq!(snaps[0].node_id, EncryptedUdpNodeId(1));
        assert_eq!(snaps[1].node_id, EncryptedUdpNodeId(2));
        assert_eq!(snaps[2].node_id, EncryptedUdpNodeId(3));
    }

    // EC2: wire_deterministic_sessions adds peer sessions
    #[test]
    fn ec2_wire_sessions() {
        let mut cluster = EncryptedUdpCluster::start_loopback_cluster(3, 43050).unwrap();
        cluster.wire_deterministic_sessions();
        // Each node should have at least one peer session (ring: each node has session to next)
        for snap in cluster.snapshots() {
            assert!(
                snap.peer_count >= 1,
                "each node must have at least one peer session"
            );
        }
    }

    // EC3: encrypted ring sends one packet per node
    #[test]
    fn ec3_encrypted_ring_sends_packets() {
        let mut cluster = EncryptedUdpCluster::start_loopback_cluster(3, 43060).unwrap();
        cluster.wire_deterministic_sessions();
        cluster.send_encrypted_ring(b"probe payload").unwrap();
        let snaps = cluster.snapshots();
        for snap in &snaps {
            assert_eq!(snap.packets_sent, 1);
            assert_eq!(snap.encrypted_cells_sent, 1);
        }
    }

    // EC4: poll_all receives all ring packets
    #[test]
    fn ec4_poll_all_receives_packets() {
        let mut cluster = EncryptedUdpCluster::start_loopback_cluster(3, 43070).unwrap();
        cluster.wire_deterministic_sessions();
        cluster.send_encrypted_ring(b"data payload").unwrap();
        let received = cluster.poll_all();
        assert_eq!(received, 3);
        let snaps = cluster.snapshots();
        for snap in &snaps {
            assert_eq!(snap.packets_received, 1);
            assert_eq!(snap.encrypted_cells_received, 1);
        }
    }

    // EC5: zero node count rejected
    #[test]
    fn ec5_zero_cluster_rejected() {
        assert_eq!(
            EncryptedUdpCluster::start_loopback_cluster(0, 43080).unwrap_err(),
            EncryptedUdpError::InvalidNode
        );
    }

    // EC6: deterministic port assignment
    #[test]
    fn ec6_deterministic_ports() {
        let cluster = EncryptedUdpCluster::start_loopback_cluster(3, 43090).unwrap();
        let snaps = cluster.snapshots();
        assert_eq!(snaps[0].local_addr.port(), 43090);
        assert_eq!(snaps[1].local_addr.port(), 43091);
        assert_eq!(snaps[2].local_addr.port(), 43092);
    }
}
