use liberty_controlled_chaos::cell_encoder::CELL_SIZE;
use liberty_controlled_chaos::noise_link::ENCRYPTED_CELL_SIZE;
use liberty_controlled_chaos::onion_layer::ONION_PACKET_SIZE;

use crate::cluster_manager::LocalCluster;
use crate::cluster_types::{ClusterError, ClusterNodeId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterPacketKind {
    Real,
    Cover,
}

#[derive(Debug)]
pub struct ClusterPacketResult {
    pub packet_kind: ClusterPacketKind,
    pub source_node: ClusterNodeId,
    pub first_hop: Option<u64>,
    pub final_hop: Option<u64>,
    pub path_length: usize,
    pub cell_size: usize,
    pub encrypted_cell_size: usize,
    pub onion_packet_size: usize,
    pub udp_wire_size: usize,
    pub delivered: bool,
}

pub fn send_cluster_payload(
    cluster: &mut LocalCluster,
    source_node_id: ClusterNodeId,
    payload: &[u8],
) -> Result<ClusterPacketResult, ClusterError> {
    if !cluster.is_running() {
        return Err(ClusterError::ClusterNotStarted);
    }
    if cluster
        .node_configs()
        .iter()
        .all(|c| c.node_id != source_node_id)
    {
        return Err(ClusterError::NodeNotFound);
    }
    let result = cluster
        .send_payload_via_sim(payload)
        .ok_or(ClusterError::SimulationFailed)?;

    Ok(ClusterPacketResult {
        packet_kind: ClusterPacketKind::Real,
        source_node: source_node_id,
        first_hop: result.hops.first().map(|h| h.node_id),
        final_hop: result.hops.last().map(|h| h.node_id),
        path_length: result.hops.len(),
        cell_size: CELL_SIZE,
        encrypted_cell_size: result.packet_size_bytes,
        onion_packet_size: ONION_PACKET_SIZE,
        udp_wire_size: ENCRYPTED_CELL_SIZE,
        delivered: result.delivered,
    })
}

pub fn send_cluster_cover_tick(
    cluster: &mut LocalCluster,
    epoch_us: u64,
) -> Result<ClusterPacketResult, ClusterError> {
    if !cluster.is_running() {
        return Err(ClusterError::ClusterNotStarted);
    }
    let sim = cluster
        .cluster_sim_mut()
        .ok_or(ClusterError::SimulationFailed)?;
    let before = sim.metrics().cover_packets;
    sim.tick_cover_traffic(epoch_us);
    let after = sim.metrics().cover_packets;
    let generated = after > before;

    Ok(ClusterPacketResult {
        packet_kind: ClusterPacketKind::Cover,
        source_node: ClusterNodeId(0),
        first_hop: None,
        final_hop: None,
        path_length: 0,
        cell_size: CELL_SIZE,
        encrypted_cell_size: ENCRYPTED_CELL_SIZE,
        onion_packet_size: ONION_PACKET_SIZE,
        udp_wire_size: ENCRYPTED_CELL_SIZE,
        delivered: generated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_topology::{ClusterTopologyProfile, build_cluster_configs};

    fn running_tiny() -> LocalCluster {
        let mut cluster = LocalCluster::new();
        for cfg in build_cluster_configs(&ClusterTopologyProfile::Tiny) {
            cluster.add_node(cfg).unwrap();
        }
        cluster.start_all().unwrap();
        cluster
    }

    // PF1: send payload through running cluster
    #[test]
    fn pf1_send_payload_running_cluster() {
        let mut cluster = running_tiny();
        let result = send_cluster_payload(&mut cluster, ClusterNodeId(1), b"hello").unwrap();
        assert_eq!(result.packet_kind, ClusterPacketKind::Real);
        assert!(result.path_length > 0);
        assert!(result.delivered);
    }

    // PF2: send before start rejected
    #[test]
    fn pf2_send_before_start_rejected() {
        let mut cluster = LocalCluster::new();
        for cfg in build_cluster_configs(&ClusterTopologyProfile::Tiny) {
            cluster.add_node(cfg).unwrap();
        }
        let err = send_cluster_payload(&mut cluster, ClusterNodeId(1), b"x").unwrap_err();
        assert_eq!(err, ClusterError::ClusterNotStarted);
    }

    // PF3: unknown source node rejected
    #[test]
    fn pf3_unknown_source_rejected() {
        let mut cluster = running_tiny();
        let err = send_cluster_payload(&mut cluster, ClusterNodeId(9999), b"x").unwrap_err();
        assert_eq!(err, ClusterError::NodeNotFound);
    }

    // PF4: packet size constants match known values
    #[test]
    fn pf4_packet_size_constants_preserved() {
        let mut cluster = running_tiny();
        let result = send_cluster_payload(&mut cluster, ClusterNodeId(1), b"test").unwrap();
        assert_eq!(result.cell_size, 1450);
        assert_eq!(result.encrypted_cell_size, 1482);
        assert_eq!(result.onion_packet_size, 1507);
        assert_eq!(result.udp_wire_size, 1482);
    }

    // PF5: cover tick produces cover results
    #[test]
    fn pf5_cover_tick_produces_results() {
        let mut cluster = running_tiny();
        let result = send_cluster_cover_tick(&mut cluster, 1_000_000).unwrap();
        assert_eq!(result.packet_kind, ClusterPacketKind::Cover);
    }

    // PF6: repeated sends are deterministic (same source gives same path structure)
    #[test]
    fn pf6_repeated_send_deterministic() {
        let mut c1 = running_tiny();
        let mut c2 = running_tiny();
        let r1 = send_cluster_payload(&mut c1, ClusterNodeId(1), b"payload").unwrap();
        let r2 = send_cluster_payload(&mut c2, ClusterNodeId(1), b"payload").unwrap();
        assert_eq!(r1.path_length, r2.path_length);
        assert_eq!(r1.delivered, r2.delivered);
        assert_eq!(r1.first_hop, r2.first_hop);
        assert_eq!(r1.final_hop, r2.final_hop);
    }
}
