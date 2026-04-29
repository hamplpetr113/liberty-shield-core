#[derive(Debug, Clone, PartialEq)]
pub enum NodeServiceState {
    Created,
    Configured,
    IdentityReady,
    PeersReady,
    Running,
    Stopped,
    Error(String),
}

impl NodeServiceState {
    pub fn as_str(&self) -> &str {
        match self {
            NodeServiceState::Created => "Created",
            NodeServiceState::Configured => "Configured",
            NodeServiceState::IdentityReady => "IdentityReady",
            NodeServiceState::PeersReady => "PeersReady",
            NodeServiceState::Running => "Running",
            NodeServiceState::Stopped => "Stopped",
            NodeServiceState::Error(_) => "Error",
        }
    }
}

pub struct NodeRuntimeSnapshot {
    pub state: NodeServiceState,
    pub node_id: u64,
    pub peer_count: usize,
    pub connected_peer_count: usize,
    pub simulation_mode: bool,
    pub packets_simulated: u64,
    pub packets_forwarded: u64,
}
