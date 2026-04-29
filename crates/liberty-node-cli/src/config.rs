#[derive(Debug, Clone, PartialEq)]
pub struct NodeConfig {
    pub node_name: String,
    pub node_id: u64,
    pub bind_address: String,
    pub bind_port: u16,
    pub max_peers: usize,
    pub simulation_mode: bool,
    pub allow_real_udp: bool,
}

#[derive(Debug, PartialEq)]
pub enum ConfigError {
    ZeroPort,
    ZeroMaxPeers,
    RealUdpWithSimulationMode,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_name: "liberty-node-local".to_string(),
            node_id: 1,
            bind_address: "127.0.0.1".to_string(),
            bind_port: 39000,
            max_peers: 64,
            simulation_mode: true,
            allow_real_udp: false,
        }
    }
}

impl NodeConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.bind_port == 0 {
            return Err(ConfigError::ZeroPort);
        }
        if self.max_peers == 0 {
            return Err(ConfigError::ZeroMaxPeers);
        }
        if self.allow_real_udp && self.simulation_mode {
            return Err(ConfigError::RealUdpWithSimulationMode);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // C1: default config is valid
    #[test]
    fn c1_default_config_valid() {
        assert_eq!(NodeConfig::default().validate(), Ok(()));
    }

    // C2: zero port rejected
    #[test]
    fn c2_zero_port_rejected() {
        let config = NodeConfig {
            bind_port: 0,
            ..NodeConfig::default()
        };
        assert_eq!(config.validate(), Err(ConfigError::ZeroPort));
    }

    // C3: zero max_peers rejected
    #[test]
    fn c3_zero_max_peers_rejected() {
        let config = NodeConfig {
            max_peers: 0,
            ..NodeConfig::default()
        };
        assert_eq!(config.validate(), Err(ConfigError::ZeroMaxPeers));
    }

    // C4: allow_real_udp + simulation_mode rejected
    #[test]
    fn c4_real_udp_with_simulation_mode_rejected() {
        let config = NodeConfig {
            allow_real_udp: true,
            simulation_mode: true,
            ..NodeConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(ConfigError::RealUdpWithSimulationMode)
        );
    }
}
