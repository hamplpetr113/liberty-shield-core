use crate::config::NodeConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClusterNodeId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterNodeRole {
    Client,
    Guard,
    Relay,
    Exit,
}

impl ClusterNodeRole {
    pub fn as_str(&self) -> &str {
        match self {
            ClusterNodeRole::Client => "Client",
            ClusterNodeRole::Guard => "Guard",
            ClusterNodeRole::Relay => "Relay",
            ClusterNodeRole::Exit => "Exit",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterNodeStatus {
    Created,
    Configured,
    Running,
    Stopped,
    Failed,
}

impl ClusterNodeStatus {
    pub fn as_str(&self) -> &str {
        match self {
            ClusterNodeStatus::Created => "Created",
            ClusterNodeStatus::Configured => "Configured",
            ClusterNodeStatus::Running => "Running",
            ClusterNodeStatus::Stopped => "Stopped",
            ClusterNodeStatus::Failed => "Failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ClusterNodeConfig {
    pub node_id: ClusterNodeId,
    pub role: ClusterNodeRole,
    pub node_name: String,
    pub bind_address: String,
    pub bind_port: u16,
    pub max_peers: usize,
    pub simulation_mode: bool,
    pub allow_real_udp: bool,
}

impl ClusterNodeConfig {
    pub fn validate(&self) -> Result<(), ClusterError> {
        if self.bind_port == 0 {
            return Err(ClusterError::InvalidConfig);
        }
        if self.max_peers == 0 {
            return Err(ClusterError::InvalidConfig);
        }
        if self.allow_real_udp && self.simulation_mode {
            return Err(ClusterError::InvalidConfig);
        }
        Ok(())
    }

    pub fn to_node_config(&self) -> NodeConfig {
        NodeConfig {
            node_name: self.node_name.clone(),
            node_id: self.node_id.0,
            bind_address: self.bind_address.clone(),
            bind_port: self.bind_port,
            max_peers: self.max_peers,
            simulation_mode: self.simulation_mode,
            allow_real_udp: self.allow_real_udp,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterError {
    DuplicateNode,
    NodeNotFound,
    InvalidConfig,
    ClusterNotStarted,
    ClusterAlreadyRunning,
    EmptyCluster,
    RouteFailed,
    SimulationFailed,
}

pub struct ClusterNodeSnapshot {
    pub node_id: ClusterNodeId,
    pub role: ClusterNodeRole,
    pub status: ClusterNodeStatus,
    pub peer_count: usize,
    pub connected_peer_count: usize,
    pub packets_simulated: u64,
    pub packets_forwarded: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(id: u64) -> ClusterNodeConfig {
        ClusterNodeConfig {
            node_id: ClusterNodeId(id),
            role: ClusterNodeRole::Guard,
            node_name: format!("node-{id}"),
            bind_address: "127.0.0.1".to_string(),
            bind_port: 39000 + id as u16,
            max_peers: 64,
            simulation_mode: true,
            allow_real_udp: false,
        }
    }

    // CT1: role as_str returns expected values
    #[test]
    fn ct1_role_as_str() {
        assert_eq!(ClusterNodeRole::Client.as_str(), "Client");
        assert_eq!(ClusterNodeRole::Guard.as_str(), "Guard");
        assert_eq!(ClusterNodeRole::Relay.as_str(), "Relay");
        assert_eq!(ClusterNodeRole::Exit.as_str(), "Exit");
    }

    // CT2: zero port rejected
    #[test]
    fn ct2_zero_port_rejected() {
        let mut cfg = make_config(1);
        cfg.bind_port = 0;
        assert_eq!(cfg.validate(), Err(ClusterError::InvalidConfig));
    }

    // CT3: zero max_peers rejected
    #[test]
    fn ct3_zero_max_peers_rejected() {
        let mut cfg = make_config(1);
        cfg.max_peers = 0;
        assert_eq!(cfg.validate(), Err(ClusterError::InvalidConfig));
    }

    // CT4: allow_real_udp + simulation_mode rejected
    #[test]
    fn ct4_real_udp_with_simulation_mode_rejected() {
        let mut cfg = make_config(1);
        cfg.allow_real_udp = true;
        cfg.simulation_mode = true;
        assert_eq!(cfg.validate(), Err(ClusterError::InvalidConfig));
    }
}
