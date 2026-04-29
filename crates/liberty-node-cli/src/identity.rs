use crate::config::NodeConfig;

/// NON-PRODUCTION identity placeholder.
///
/// Keys are derived deterministically from node_id only.
/// These are NOT real cryptographic keys and MUST NOT be used in production.
/// Real key generation (X25519 / Ed25519) is deferred to a future sprint.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeIdentity {
    pub node_id: u64,
    pub public_key: [u8; 32],
    pub private_key_placeholder: [u8; 32],
}

impl NodeIdentity {
    /// Derive a deterministic identity from `config`.
    ///
    /// No randomness, no real crypto. Both keys are derived from `node_id` only.
    pub fn derive_from_config(config: &NodeConfig) -> Self {
        let node_id = config.node_id;
        let public_key: [u8; 32] = std::array::from_fn(|i| node_id.wrapping_add(i as u64) as u8);
        let private_key_placeholder: [u8; 32] =
            std::array::from_fn(|i| node_id.wrapping_mul(3).wrapping_add(i as u64) as u8);
        Self {
            node_id,
            public_key,
            private_key_placeholder,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // I1: same config gives same identity
    #[test]
    fn i1_same_config_same_identity() {
        let cfg = NodeConfig::default();
        let id1 = NodeIdentity::derive_from_config(&cfg);
        let id2 = NodeIdentity::derive_from_config(&cfg);
        assert_eq!(id1, id2);
    }

    // I2: different node_id gives different identity
    #[test]
    fn i2_different_node_id_different_identity() {
        let cfg1 = NodeConfig {
            node_id: 1,
            ..NodeConfig::default()
        };
        let cfg2 = NodeConfig {
            node_id: 2,
            ..NodeConfig::default()
        };
        let id1 = NodeIdentity::derive_from_config(&cfg1);
        let id2 = NodeIdentity::derive_from_config(&cfg2);
        assert_ne!(id1.public_key, id2.public_key);
        assert_ne!(id1.private_key_placeholder, id2.private_key_placeholder);
    }

    // I3: keys are 32 bytes
    #[test]
    fn i3_key_lengths_32_bytes() {
        let id = NodeIdentity::derive_from_config(&NodeConfig::default());
        assert_eq!(id.public_key.len(), 32);
        assert_eq!(id.private_key_placeholder.len(), 32);
    }
}
