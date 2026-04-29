use crate::config::{ConfigError, NodeConfig};
use crate::identity::NodeIdentity;
use crate::node_runtime::NodeRuntime;
use crate::peer_table::{PeerInfo, PeerTable, PeerTableError};
use crate::runtime_state::{NodeRuntimeSnapshot, NodeServiceState};

#[derive(Debug, PartialEq)]
pub enum ServiceError {
    Config(ConfigError),
    PeerTable(PeerTableError),
    NotStarted,
    AlreadyRunning,
    RealUdpNotAllowed,
}

pub struct NodeService {
    config: NodeConfig,
    identity: NodeIdentity,
    peer_table: PeerTable,
    state: NodeServiceState,
    simulator: Option<NodeRuntime>,
    packets_simulated: u64,
    packets_forwarded: u64,
}

impl NodeService {
    pub fn new(config: NodeConfig) -> Result<Self, ServiceError> {
        config.validate().map_err(ServiceError::Config)?;
        let identity = NodeIdentity::derive_from_config(&config);
        let peer_table = PeerTable::new(config.max_peers);
        Ok(Self {
            config,
            identity,
            peer_table,
            state: NodeServiceState::Created,
            simulator: None,
            packets_simulated: 0,
            packets_forwarded: 0,
        })
    }

    pub fn bootstrap_simulation(&mut self, node_count: usize, circuits: usize) {
        let mut rt = NodeRuntime::new(node_count);
        rt.build_circuits(circuits);
        self.simulator = Some(rt);
        self.state = NodeServiceState::Configured;
    }

    pub fn start(&mut self) -> Result<(), ServiceError> {
        if self.config.allow_real_udp {
            return Err(ServiceError::RealUdpNotAllowed);
        }
        self.state = NodeServiceState::Running;
        Ok(())
    }

    pub fn stop(&mut self) {
        self.state = NodeServiceState::Stopped;
    }

    pub fn add_peer(&mut self, peer: PeerInfo) -> Result<(), ServiceError> {
        self.peer_table
            .add_peer(peer)
            .map_err(ServiceError::PeerTable)
    }

    pub fn peers(&self) -> &[PeerInfo] {
        self.peer_table.list_peers()
    }

    pub fn snapshot(&self) -> NodeRuntimeSnapshot {
        NodeRuntimeSnapshot {
            state: self.state.clone(),
            node_id: self.config.node_id,
            peer_count: self.peer_table.list_peers().len(),
            connected_peer_count: self.peer_table.connected_peers().len(),
            simulation_mode: self.config.simulation_mode,
            packets_simulated: self.packets_simulated,
            packets_forwarded: self.packets_forwarded,
        }
    }

    pub fn run_simulation_rounds(&mut self, rounds: usize) -> Result<(), ServiceError> {
        if self.state != NodeServiceState::Running {
            return Err(ServiceError::NotStarted);
        }
        let rt = self.simulator.get_or_insert_with(|| {
            let mut r = NodeRuntime::new(100);
            r.build_circuits(5);
            r
        });
        rt.run_rounds(rounds);
        self.packets_simulated = rt.metrics().packets_sent;
        self.packets_forwarded = rt.metrics().packets_forwarded;
        Ok(())
    }

    pub fn node_id(&self) -> u64 {
        self.config.node_id
    }

    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // S1: service initializes from valid config
    #[test]
    fn s1_service_initializes() {
        let svc = NodeService::new(NodeConfig::default()).unwrap();
        let snap = svc.snapshot();
        assert_eq!(snap.state, NodeServiceState::Created);
        assert_eq!(snap.node_id, 1);
        assert!(snap.simulation_mode);
    }

    // S2: service starts in simulation mode
    #[test]
    fn s2_service_starts_simulation_mode() {
        let mut svc = NodeService::new(NodeConfig::default()).unwrap();
        svc.start().unwrap();
        assert_eq!(svc.snapshot().state, NodeServiceState::Running);
    }

    // S3: simulation rounds update packets_simulated
    #[test]
    fn s3_simulation_rounds_update_metrics() {
        let mut svc = NodeService::new(NodeConfig::default()).unwrap();
        svc.start().unwrap();
        svc.run_simulation_rounds(10).unwrap();
        let snap = svc.snapshot();
        assert_eq!(snap.packets_simulated, 10);
        assert_eq!(snap.packets_forwarded, 30); // 10 packets × 3 hops
    }

    // S4: run_simulation_rounds before start is rejected
    #[test]
    fn s4_run_rounds_before_start_rejected() {
        let mut svc = NodeService::new(NodeConfig::default()).unwrap();
        let err = svc.run_simulation_rounds(10).unwrap_err();
        assert_eq!(err, ServiceError::NotStarted);
    }

    // S5: stop transitions to Stopped
    #[test]
    fn s5_stop_transitions_state() {
        let mut svc = NodeService::new(NodeConfig::default()).unwrap();
        svc.start().unwrap();
        assert_eq!(svc.snapshot().state, NodeServiceState::Running);
        svc.stop();
        assert_eq!(svc.snapshot().state, NodeServiceState::Stopped);
    }

    // S6: add_peer updates peer_count in snapshot
    #[test]
    fn s6_add_peer_updates_table() {
        let mut svc = NodeService::new(NodeConfig::default()).unwrap();
        let peer = PeerInfo {
            peer_id: 42,
            address: "127.0.0.1".to_string(),
            port: 9001,
            reliability_score: 0.9,
            latency_estimate: 100,
            connected: false,
        };
        svc.add_peer(peer).unwrap();
        assert_eq!(svc.snapshot().peer_count, 1);
    }

    // S7: allow_real_udp rejected by start()
    #[test]
    fn s7_real_udp_rejected() {
        let config = NodeConfig {
            allow_real_udp: true,
            simulation_mode: false,
            ..NodeConfig::default()
        };
        let mut svc = NodeService::new(config).unwrap();
        assert_eq!(svc.start().unwrap_err(), ServiceError::RealUdpNotAllowed);
    }
}
