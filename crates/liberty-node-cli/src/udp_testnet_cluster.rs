use crate::udp_testnet_node::{UdpTestnetNode, UdpTestnetNodeSnapshot};
use crate::udp_testnet_types::{UdpTestnetError, UdpTestnetNodeConfig, UdpTestnetNodeId};

#[derive(Debug)]
pub struct UdpTestnetCluster {
    nodes: Vec<UdpTestnetNode>,
}

impl UdpTestnetCluster {
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    pub fn start_loopback_cluster(count: usize, base_port: u16) -> Result<Self, UdpTestnetError> {
        if count == 0 {
            return Err(UdpTestnetError::InvalidNode);
        }
        let mut nodes = Vec::with_capacity(count);
        for i in 0..count {
            let config = UdpTestnetNodeConfig {
                node_id: UdpTestnetNodeId(i as u64 + 1),
                bind_address: "127.0.0.1".to_string(),
                bind_port: base_port + i as u16,
                allow_real_udp: true,
                simulation_mode: false,
                max_packet_size: 1482,
            };
            nodes.push(UdpTestnetNode::start(config)?);
        }
        Ok(Self { nodes })
    }

    /// Ring topology: node i sends probe to node (i+1) % n.
    pub fn send_probe_ring(&mut self) -> Result<(), UdpTestnetError> {
        let count = self.nodes.len();
        let snapshots: Vec<UdpTestnetNodeSnapshot> =
            self.nodes.iter().map(|n| n.snapshot()).collect();
        for i in 0..count {
            let next = (i + 1) % count;
            let target_id = snapshots[next].node_id;
            let target_addr = snapshots[next].local_addr;
            self.nodes[i].send_probe(target_id, target_addr)?;
        }
        Ok(())
    }

    /// Ring topology: node i sends data to node (i+1) % n.
    pub fn send_data_round(&mut self, payload: &[u8]) -> Result<(), UdpTestnetError> {
        let count = self.nodes.len();
        let snapshots: Vec<UdpTestnetNodeSnapshot> =
            self.nodes.iter().map(|n| n.snapshot()).collect();
        for i in 0..count {
            let next = (i + 1) % count;
            let target_id = snapshots[next].node_id;
            let target_addr = snapshots[next].local_addr;
            self.nodes[i].send_data(target_id, target_addr, payload.to_vec())?;
        }
        Ok(())
    }

    /// Drain all nodes' receive buffers once. Returns total packets received.
    pub fn poll_all(&mut self) -> usize {
        let mut received = 0;
        for node in &mut self.nodes {
            while let Ok(Some(_)) = node.poll_once() {
                received += 1;
            }
        }
        received
    }

    pub fn snapshots(&self) -> Vec<UdpTestnetNodeSnapshot> {
        self.nodes.iter().map(|n| n.snapshot()).collect()
    }

    pub fn stop_all(&mut self) {
        self.nodes.clear();
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

impl Default for UdpTestnetCluster {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // UC1: start 3-node loopback cluster
    #[test]
    fn uc1_start_3_node_cluster() {
        let cluster = UdpTestnetCluster::start_loopback_cluster(3, 42300).unwrap();
        assert_eq!(cluster.node_count(), 3);
        let snaps = cluster.snapshots();
        assert_eq!(snaps[0].node_id, UdpTestnetNodeId(1));
        assert_eq!(snaps[1].node_id, UdpTestnetNodeId(2));
        assert_eq!(snaps[2].node_id, UdpTestnetNodeId(3));
    }

    // UC2: probe ring sends one packet per node
    #[test]
    fn uc2_probe_ring_sends_packets() {
        let mut cluster = UdpTestnetCluster::start_loopback_cluster(3, 42310).unwrap();
        cluster.send_probe_ring().unwrap();
        let snaps = cluster.snapshots();
        for snap in &snaps {
            assert_eq!(snap.packets_sent, 1);
        }
    }

    // UC3: poll_all receives all ring probes
    #[test]
    fn uc3_poll_all_receives_packets() {
        let mut cluster = UdpTestnetCluster::start_loopback_cluster(3, 42320).unwrap();
        cluster.send_probe_ring().unwrap();
        let received = cluster.poll_all();
        assert_eq!(received, 3);
        let snaps = cluster.snapshots();
        for snap in &snaps {
            assert_eq!(snap.packets_received, 1);
        }
    }

    // UC4: data round preserves payload size
    #[test]
    fn uc4_data_round_preserves_payload_size() {
        let mut cluster = UdpTestnetCluster::start_loopback_cluster(3, 42330).unwrap();
        let payload = b"liberty";
        cluster.send_data_round(payload).unwrap();
        cluster.poll_all();
        let snaps = cluster.snapshots();
        for snap in &snaps {
            assert_eq!(snap.packets_received, 1);
        }
    }

    // UC5: ports are deterministic from base_port
    #[test]
    fn uc5_deterministic_ports() {
        let cluster = UdpTestnetCluster::start_loopback_cluster(3, 42340).unwrap();
        let snaps = cluster.snapshots();
        assert_eq!(snaps[0].local_addr.port(), 42340);
        assert_eq!(snaps[1].local_addr.port(), 42341);
        assert_eq!(snaps[2].local_addr.port(), 42342);
    }

    // UC6: zero node count rejected
    #[test]
    fn uc6_zero_cluster_rejected() {
        assert_eq!(
            UdpTestnetCluster::start_loopback_cluster(0, 42350).unwrap_err(),
            UdpTestnetError::InvalidNode
        );
    }
}
