//! Node configuration — central runtime configuration for a Liberty Shield node.
//!
//! `NodeConfig` holds all tunable parameters for identity, networking,
//! resource limits, privacy profile, rotation policy, cover traffic, and
//! directory authority connectivity.

use crate::resource_guard::ResourceBudget;

// ---------------------------------------------------------------------------
// Sub-configs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DirectoryAuthorityConfig {
    pub authority_id: [u8; 32],
    pub address: String,
    pub fetch_interval_epochs: u64,
}

impl Default for DirectoryAuthorityConfig {
    fn default() -> Self {
        Self {
            authority_id: [0u8; 32],
            address: "127.0.0.1:9100".to_string(),
            fetch_interval_epochs: 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoverTrafficConfig {
    pub base_rate_packets_per_epoch: u64,
    pub adaptive_multiplier: f64,
    pub max_multiplier: f64,
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            base_rate_packets_per_epoch: 10,
            adaptive_multiplier: 1.0,
            max_multiplier: 5.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RotationConfig {
    pub max_lifetime_epochs: u64,
    pub max_packets_per_circuit: u64,
    pub idle_rotation_epochs: u64,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            max_lifetime_epochs: 100,
            max_packets_per_circuit: 10_000,
            idle_rotation_epochs: 20,
        }
    }
}

// ---------------------------------------------------------------------------
// PrivacyProfile
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyProfile {
    Standard,
    Strong,
    Paranoid,
}

impl PrivacyProfile {
    pub fn rotation_config(&self) -> RotationConfig {
        match self {
            PrivacyProfile::Standard => RotationConfig::default(),
            PrivacyProfile::Strong => RotationConfig {
                max_lifetime_epochs: 50,
                max_packets_per_circuit: 5_000,
                idle_rotation_epochs: 10,
            },
            PrivacyProfile::Paranoid => RotationConfig {
                max_lifetime_epochs: 20,
                max_packets_per_circuit: 1_000,
                idle_rotation_epochs: 5,
            },
        }
    }

    pub fn cover_traffic_config(&self) -> CoverTrafficConfig {
        match self {
            PrivacyProfile::Standard => CoverTrafficConfig::default(),
            PrivacyProfile::Strong => CoverTrafficConfig {
                base_rate_packets_per_epoch: 20,
                adaptive_multiplier: 1.5,
                max_multiplier: 5.0,
            },
            PrivacyProfile::Paranoid => CoverTrafficConfig {
                base_rate_packets_per_epoch: 50,
                adaptive_multiplier: 2.0,
                max_multiplier: 8.0,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// NodeConfig
// ---------------------------------------------------------------------------

/// Central runtime configuration for a Liberty Shield node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub node_id: [u8; 32],
    pub listen_address: String,
    pub bootstrap_peers: Vec<String>,
    pub resource_budget: ResourceBudget,
    pub privacy_profile: PrivacyProfile,
    pub rotation: RotationConfig,
    pub cover_traffic: CoverTrafficConfig,
    pub directory: DirectoryAuthorityConfig,
    pub max_epoch_skew: u64,
}

impl NodeConfig {
    pub fn new(node_id: [u8; 32]) -> Self {
        Self {
            node_id,
            listen_address: "0.0.0.0:4430".to_string(),
            bootstrap_peers: Vec::new(),
            resource_budget: ResourceBudget::default_budget(),
            privacy_profile: PrivacyProfile::Standard,
            rotation: RotationConfig::default(),
            cover_traffic: CoverTrafficConfig::default(),
            directory: DirectoryAuthorityConfig::default(),
            max_epoch_skew: 5,
        }
    }

    pub fn with_privacy_profile(mut self, profile: PrivacyProfile) -> Self {
        self.privacy_profile = profile;
        self.rotation = profile.rotation_config();
        self.cover_traffic = profile.cover_traffic_config();
        self
    }

    pub fn with_listen_address(mut self, addr: String) -> Self {
        self.listen_address = addr;
        self
    }

    pub fn with_bootstrap_peer(mut self, addr: String) -> Self {
        self.bootstrap_peers.push(addr);
        self
    }

    pub fn with_resource_budget(mut self, budget: ResourceBudget) -> Self {
        self.resource_budget = budget;
        self
    }

    pub fn with_directory_authority(mut self, cfg: DirectoryAuthorityConfig) -> Self {
        self.directory = cfg;
        self
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

    // NC1: default config has standard privacy profile.
    #[test]
    fn nc1_default_standard() {
        let c = NodeConfig::new(nid(1));
        assert_eq!(c.privacy_profile, PrivacyProfile::Standard);
    }

    // NC2: strong profile shortens rotation lifetime.
    #[test]
    fn nc2_strong_profile_rotation() {
        let c = NodeConfig::new(nid(1)).with_privacy_profile(PrivacyProfile::Strong);
        assert!(c.rotation.max_lifetime_epochs < 100);
    }

    // NC3: paranoid profile has shortest rotation lifetime.
    #[test]
    fn nc3_paranoid_shorter_than_strong() {
        let strong = NodeConfig::new(nid(1)).with_privacy_profile(PrivacyProfile::Strong);
        let paranoid = NodeConfig::new(nid(1)).with_privacy_profile(PrivacyProfile::Paranoid);
        assert!(paranoid.rotation.max_lifetime_epochs < strong.rotation.max_lifetime_epochs);
    }

    // NC4: paranoid has higher cover traffic rate.
    #[test]
    fn nc4_paranoid_cover_rate_higher() {
        let std = NodeConfig::new(nid(1)).with_privacy_profile(PrivacyProfile::Standard);
        let par = NodeConfig::new(nid(1)).with_privacy_profile(PrivacyProfile::Paranoid);
        assert!(
            par.cover_traffic.base_rate_packets_per_epoch
                > std.cover_traffic.base_rate_packets_per_epoch
        );
    }

    // NC5: bootstrap peers accumulate via builder.
    #[test]
    fn nc5_bootstrap_peers() {
        let c = NodeConfig::new(nid(1))
            .with_bootstrap_peer("a:9000".into())
            .with_bootstrap_peer("b:9000".into());
        assert_eq!(c.bootstrap_peers.len(), 2);
    }

    // NC6: listen address is configurable.
    #[test]
    fn nc6_listen_address() {
        let c = NodeConfig::new(nid(1)).with_listen_address("127.0.0.1:9999".into());
        assert_eq!(c.listen_address, "127.0.0.1:9999");
    }

    // NC7: resource budget is configurable.
    #[test]
    fn nc7_resource_budget() {
        let budget = ResourceBudget {
            max_circuits: 8,
            max_peers: 16,
            max_pending_handshakes: 2,
            max_bytes_per_epoch: 1024,
        };
        let c = NodeConfig::new(nid(1)).with_resource_budget(budget);
        assert_eq!(c.resource_budget.max_circuits, 8);
    }

    // NC8: node_id is preserved.
    #[test]
    fn nc8_node_id_preserved() {
        let c = NodeConfig::new(nid(42));
        assert_eq!(c.node_id, nid(42));
    }

    // NC9: max_epoch_skew has a default.
    #[test]
    fn nc9_epoch_skew_default() {
        let c = NodeConfig::new(nid(1));
        assert!(c.max_epoch_skew > 0);
    }

    // NC10: directory fetch interval is positive.
    #[test]
    fn nc10_directory_fetch_interval() {
        let c = NodeConfig::new(nid(1));
        assert!(c.directory.fetch_interval_epochs > 0);
    }
}
