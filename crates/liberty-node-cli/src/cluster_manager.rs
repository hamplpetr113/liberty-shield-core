use liberty_controlled_chaos::mesh_simulator::{MeshMetrics, MeshSimulator, PacketFlowResult};

use crate::cluster_types::{
    ClusterError, ClusterNodeConfig, ClusterNodeId, ClusterNodeSnapshot, ClusterNodeStatus,
};
use crate::node_service::NodeService;
use crate::peer_table::PeerInfo;
use crate::runtime_state::NodeServiceState;

fn state_to_status(state: &NodeServiceState) -> ClusterNodeStatus {
    match state {
        NodeServiceState::Created => ClusterNodeStatus::Created,
        NodeServiceState::Configured => ClusterNodeStatus::Configured,
        NodeServiceState::IdentityReady | NodeServiceState::PeersReady => {
            ClusterNodeStatus::Configured
        }
        NodeServiceState::Running => ClusterNodeStatus::Running,
        NodeServiceState::Stopped => ClusterNodeStatus::Stopped,
        NodeServiceState::Error(_) => ClusterNodeStatus::Failed,
    }
}

pub struct LocalCluster {
    services: Vec<NodeService>,
    configs: Vec<ClusterNodeConfig>,
    cluster_sim: Option<MeshSimulator>,
    running: bool,
}

impl LocalCluster {
    pub fn new() -> Self {
        Self {
            services: Vec::new(),
            configs: Vec::new(),
            cluster_sim: None,
            running: false,
        }
    }

    pub fn with_default_topology(node_count: usize) -> Result<Self, ClusterError> {
        use crate::cluster_topology::build_cluster_configs_with_count;
        let configs = build_cluster_configs_with_count(node_count);
        if configs.is_empty() {
            return Err(ClusterError::EmptyCluster);
        }
        let mut cluster = LocalCluster::new();
        for cfg in configs {
            cluster.add_node(cfg)?;
        }
        Ok(cluster)
    }

    pub fn add_node(&mut self, config: ClusterNodeConfig) -> Result<(), ClusterError> {
        config.validate().map_err(|_| ClusterError::InvalidConfig)?;
        if self.configs.iter().any(|c| c.node_id == config.node_id) {
            return Err(ClusterError::DuplicateNode);
        }
        let node_cfg = config.to_node_config();
        let svc = NodeService::new(node_cfg).map_err(|_| ClusterError::InvalidConfig)?;
        self.services.push(svc);
        self.configs.push(config);
        Ok(())
    }

    pub fn remove_node(&mut self, node_id: ClusterNodeId) -> Result<(), ClusterError> {
        let idx = self
            .services
            .iter()
            .position(|s| s.node_id() == node_id.0)
            .ok_or(ClusterError::NodeNotFound)?;
        self.services[idx].stop();
        self.services.remove(idx);
        self.configs.remove(idx);
        Ok(())
    }

    pub fn start_all(&mut self) -> Result<(), ClusterError> {
        if self.configs.is_empty() {
            return Err(ClusterError::EmptyCluster);
        }
        if self.running {
            return Err(ClusterError::ClusterAlreadyRunning);
        }
        for svc in &mut self.services {
            svc.start().map_err(|_| ClusterError::SimulationFailed)?;
        }
        let node_count = self.configs.len();
        let circuit_count = (node_count / 5).max(1);
        let mut sim = MeshSimulator::new(node_count);
        sim.build_random_circuits(circuit_count);
        self.cluster_sim = Some(sim);
        self.running = true;
        Ok(())
    }

    pub fn stop_all(&mut self) {
        for svc in self.services.iter_mut().rev() {
            svc.stop();
        }
        self.running = false;
    }

    pub fn is_running(&self) -> bool {
        self.running
    }

    pub fn node_count(&self) -> usize {
        self.configs.len()
    }

    pub fn node_configs(&self) -> &[ClusterNodeConfig] {
        &self.configs
    }

    pub fn add_peer_to_node(
        &mut self,
        node_id: ClusterNodeId,
        peer: PeerInfo,
    ) -> Result<(), ClusterError> {
        let idx = self
            .services
            .iter()
            .position(|s| s.node_id() == node_id.0)
            .ok_or(ClusterError::NodeNotFound)?;
        self.services[idx]
            .add_peer(peer)
            .map_err(|_| ClusterError::InvalidConfig)
    }

    pub fn snapshots(&self) -> Vec<ClusterNodeSnapshot> {
        let mut snaps: Vec<ClusterNodeSnapshot> = self
            .services
            .iter()
            .zip(self.configs.iter())
            .map(|(svc, cfg)| {
                let snap = svc.snapshot();
                ClusterNodeSnapshot {
                    node_id: cfg.node_id,
                    role: cfg.role.clone(),
                    status: state_to_status(&snap.state),
                    peer_count: snap.peer_count,
                    connected_peer_count: snap.connected_peer_count,
                    packets_simulated: snap.packets_simulated,
                    packets_forwarded: snap.packets_forwarded,
                }
            })
            .collect();
        snaps.sort_by_key(|s| s.node_id);
        snaps
    }

    pub fn run_rounds(&mut self, rounds: usize) -> Result<(), ClusterError> {
        if !self.running {
            return Err(ClusterError::ClusterNotStarted);
        }
        if let Some(sim) = &mut self.cluster_sim {
            sim.run_simulation(rounds);
        }
        Ok(())
    }

    pub fn sim_metrics(&self) -> Option<&MeshMetrics> {
        self.cluster_sim.as_ref().map(|s| s.metrics())
    }

    pub fn send_payload_via_sim(&mut self, payload: &[u8]) -> Option<PacketFlowResult> {
        self.cluster_sim
            .as_mut()
            .map(|sim| sim.send_payload(payload))
    }

    pub fn cluster_sim_mut(&mut self) -> Option<&mut MeshSimulator> {
        self.cluster_sim.as_mut()
    }
}

impl Default for LocalCluster {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_topology::ClusterTopologyProfile;

    fn make_node_config(id: u64) -> ClusterNodeConfig {
        use crate::cluster_types::ClusterNodeRole;
        ClusterNodeConfig {
            node_id: ClusterNodeId(id),
            role: ClusterNodeRole::Relay,
            node_name: format!("relay-{id}"),
            bind_address: "127.0.0.1".to_string(),
            bind_port: 39000 + id as u16,
            max_peers: 16,
            simulation_mode: true,
            allow_real_udp: false,
        }
    }

    // CM1: create empty cluster
    #[test]
    fn cm1_create_empty_cluster() {
        let cluster = LocalCluster::new();
        assert_eq!(cluster.node_count(), 0);
        assert!(!cluster.is_running());
    }

    // CM2: add node
    #[test]
    fn cm2_add_node() {
        let mut cluster = LocalCluster::new();
        cluster.add_node(make_node_config(1)).unwrap();
        assert_eq!(cluster.node_count(), 1);
    }

    // CM3: duplicate node rejected
    #[test]
    fn cm3_duplicate_node_rejected() {
        let mut cluster = LocalCluster::new();
        cluster.add_node(make_node_config(1)).unwrap();
        assert_eq!(
            cluster.add_node(make_node_config(1)).unwrap_err(),
            ClusterError::DuplicateNode
        );
    }

    // CM4: start empty cluster rejected
    #[test]
    fn cm4_start_empty_rejected() {
        let mut cluster = LocalCluster::new();
        assert_eq!(cluster.start_all().unwrap_err(), ClusterError::EmptyCluster);
    }

    // CM5: start default topology
    #[test]
    fn cm5_start_default_topology() {
        use crate::cluster_topology::build_cluster_configs;
        let configs = build_cluster_configs(&ClusterTopologyProfile::Tiny);
        let mut cluster = LocalCluster::new();
        for cfg in configs {
            cluster.add_node(cfg).unwrap();
        }
        cluster.start_all().unwrap();
        assert!(cluster.is_running());
    }

    // CM6: stop all
    #[test]
    fn cm6_stop_all() {
        let mut cluster = LocalCluster::with_default_topology(5).unwrap();
        cluster.start_all().unwrap();
        assert!(cluster.is_running());
        cluster.stop_all();
        assert!(!cluster.is_running());
    }

    // CM7: snapshots sorted by node_id
    #[test]
    fn cm7_snapshots_deterministic() {
        let mut cluster = LocalCluster::new();
        cluster.add_node(make_node_config(3)).unwrap();
        cluster.add_node(make_node_config(1)).unwrap();
        cluster.add_node(make_node_config(2)).unwrap();
        let snaps = cluster.snapshots();
        assert_eq!(snaps[0].node_id, ClusterNodeId(1));
        assert_eq!(snaps[1].node_id, ClusterNodeId(2));
        assert_eq!(snaps[2].node_id, ClusterNodeId(3));
    }

    // CM8: run_rounds updates metrics
    #[test]
    fn cm8_run_rounds_updates_metrics() {
        let mut cluster = LocalCluster::with_default_topology(10).unwrap();
        cluster.start_all().unwrap();
        cluster.run_rounds(20).unwrap();
        let m = cluster.sim_metrics().unwrap();
        assert_eq!(m.packets_sent, 20);
        assert_eq!(m.packets_forwarded, 60); // 20 × 3 hops
    }

    // CM9: cannot run before start
    #[test]
    fn cm9_cannot_run_before_start() {
        let mut cluster = LocalCluster::with_default_topology(5).unwrap();
        assert_eq!(
            cluster.run_rounds(10).unwrap_err(),
            ClusterError::ClusterNotStarted
        );
    }

    // CM10: remove node
    #[test]
    fn cm10_remove_node() {
        let mut cluster = LocalCluster::new();
        cluster.add_node(make_node_config(1)).unwrap();
        cluster.add_node(make_node_config(2)).unwrap();
        cluster.remove_node(ClusterNodeId(1)).unwrap();
        assert_eq!(cluster.node_count(), 1);
        assert_eq!(
            cluster.remove_node(ClusterNodeId(1)).unwrap_err(),
            ClusterError::NodeNotFound
        );
    }
}
