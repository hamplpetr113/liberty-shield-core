use crate::cluster_types::{ClusterNodeConfig, ClusterNodeId, ClusterNodeRole};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClusterTopologyProfile {
    Tiny,
    Small,
    Medium,
    Large,
}

impl ClusterTopologyProfile {
    pub fn as_str(&self) -> &str {
        match self {
            ClusterTopologyProfile::Tiny => "tiny",
            ClusterTopologyProfile::Small => "small",
            ClusterTopologyProfile::Medium => "medium",
            ClusterTopologyProfile::Large => "large",
        }
    }

    pub fn role_counts(&self) -> (usize, usize, usize, usize) {
        // returns (clients, guards, relays, exits)
        match self {
            ClusterTopologyProfile::Tiny => (1, 1, 2, 1),
            ClusterTopologyProfile::Small => (2, 3, 12, 3),
            ClusterTopologyProfile::Medium => (5, 10, 75, 10),
            ClusterTopologyProfile::Large => (10, 25, 190, 25),
        }
    }
}

pub fn parse_profile(s: &str) -> Option<ClusterTopologyProfile> {
    match s {
        "tiny" => Some(ClusterTopologyProfile::Tiny),
        "small" => Some(ClusterTopologyProfile::Small),
        "medium" => Some(ClusterTopologyProfile::Medium),
        "large" => Some(ClusterTopologyProfile::Large),
        _ => None,
    }
}

pub fn build_cluster_configs(profile: &ClusterTopologyProfile) -> Vec<ClusterNodeConfig> {
    let (clients, guards, relays, exits) = profile.role_counts();
    build_from_role_counts(clients, guards, relays, exits)
}

pub fn build_cluster_configs_with_count(node_count: usize) -> Vec<ClusterNodeConfig> {
    if node_count == 0 {
        return Vec::new();
    }
    let guard_count = (node_count / 10).max(1);
    let exit_count = (node_count / 10).max(1);
    let client_count = (node_count / 20).max(1);
    let relay_count = node_count
        .saturating_sub(guard_count + exit_count + client_count)
        .max(1);
    build_from_role_counts(client_count, guard_count, relay_count, exit_count)
}

fn build_from_role_counts(
    clients: usize,
    guards: usize,
    relays: usize,
    exits: usize,
) -> Vec<ClusterNodeConfig> {
    let mut configs = Vec::with_capacity(clients + guards + relays + exits);
    let mut id = 1u64;
    const BASE_PORT: u16 = 39000;

    for _ in 0..clients {
        configs.push(ClusterNodeConfig {
            node_id: ClusterNodeId(id),
            role: ClusterNodeRole::Client,
            node_name: format!("client-{id}"),
            bind_address: "127.0.0.1".to_string(),
            bind_port: BASE_PORT + (id - 1) as u16,
            max_peers: 16,
            simulation_mode: true,
            allow_real_udp: false,
        });
        id += 1;
    }

    for _ in 0..guards {
        configs.push(ClusterNodeConfig {
            node_id: ClusterNodeId(id),
            role: ClusterNodeRole::Guard,
            node_name: format!("guard-{id}"),
            bind_address: "127.0.0.1".to_string(),
            bind_port: BASE_PORT + (id - 1) as u16,
            max_peers: 64,
            simulation_mode: true,
            allow_real_udp: false,
        });
        id += 1;
    }

    for _ in 0..relays {
        configs.push(ClusterNodeConfig {
            node_id: ClusterNodeId(id),
            role: ClusterNodeRole::Relay,
            node_name: format!("relay-{id}"),
            bind_address: "127.0.0.1".to_string(),
            bind_port: BASE_PORT + (id - 1) as u16,
            max_peers: 128,
            simulation_mode: true,
            allow_real_udp: false,
        });
        id += 1;
    }

    for _ in 0..exits {
        configs.push(ClusterNodeConfig {
            node_id: ClusterNodeId(id),
            role: ClusterNodeRole::Exit,
            node_name: format!("exit-{id}"),
            bind_address: "127.0.0.1".to_string(),
            bind_port: BASE_PORT + (id - 1) as u16,
            max_peers: 64,
            simulation_mode: true,
            allow_real_udp: false,
        });
        id += 1;
    }

    configs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn count_roles(configs: &[ClusterNodeConfig]) -> (usize, usize, usize, usize) {
        let clients = configs
            .iter()
            .filter(|c| c.role == ClusterNodeRole::Client)
            .count();
        let guards = configs
            .iter()
            .filter(|c| c.role == ClusterNodeRole::Guard)
            .count();
        let relays = configs
            .iter()
            .filter(|c| c.role == ClusterNodeRole::Relay)
            .count();
        let exits = configs
            .iter()
            .filter(|c| c.role == ClusterNodeRole::Exit)
            .count();
        (clients, guards, relays, exits)
    }

    // TB1: tiny profile has correct node counts
    #[test]
    fn tb1_tiny_profile_counts() {
        let configs = build_cluster_configs(&ClusterTopologyProfile::Tiny);
        assert_eq!(configs.len(), 5);
        assert_eq!(count_roles(&configs), (1, 1, 2, 1));
    }

    // TB2: small profile has correct counts
    #[test]
    fn tb2_small_profile_counts() {
        let configs = build_cluster_configs(&ClusterTopologyProfile::Small);
        assert_eq!(configs.len(), 20);
        assert_eq!(count_roles(&configs), (2, 3, 12, 3));
    }

    // TB3: medium profile has correct counts
    #[test]
    fn tb3_medium_profile_counts() {
        let configs = build_cluster_configs(&ClusterTopologyProfile::Medium);
        assert_eq!(configs.len(), 100);
        assert_eq!(count_roles(&configs), (5, 10, 75, 10));
    }

    // TB4: ports are deterministic and sequential from 39000
    #[test]
    fn tb4_deterministic_ports() {
        let configs = build_cluster_configs(&ClusterTopologyProfile::Tiny);
        assert_eq!(configs[0].bind_port, 39000);
        assert_eq!(configs[1].bind_port, 39001);
        assert_eq!(configs[2].bind_port, 39002);
        assert_eq!(configs[3].bind_port, 39003);
        assert_eq!(configs[4].bind_port, 39004);
    }

    // TB5: custom count produces valid non-empty configs
    #[test]
    fn tb5_custom_count_valid() {
        let configs = build_cluster_configs_with_count(30);
        assert!(!configs.is_empty());
        assert!(configs.len() >= 4); // at least 1 of each role type
        for cfg in &configs {
            assert!(cfg.validate().is_ok());
        }
    }

    // TB6: node IDs are unique across all configs
    #[test]
    fn tb6_node_ids_unique() {
        let configs = build_cluster_configs(&ClusterTopologyProfile::Large);
        assert_eq!(configs.len(), 250);
        let mut ids: Vec<u64> = configs.iter().map(|c| c.node_id.0).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 250);
    }
}
