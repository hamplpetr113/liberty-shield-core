// NON-PRODUCTION: loopback-only encrypted UDP testnet.
// Real UDP is opt-in; loopback enforcement is in both validate() and socket layer.

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum EncryptedUdpMode {
    #[default]
    Disabled,
    LoopbackOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EncryptedUdpNodeId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedUdpPacketKind {
    EncryptedCell,
    ProbeEncrypted,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptedUdpError {
    RealUdpDisabled,
    PublicBindRejected,
    InvalidNode,
    NodeNotRunning,
    SocketBindFailed,
    SendFailed,
    ReceiveFailed,
    PacketDecodeFailed,
    InvalidPacketKind,
    InvalidEncryptedCellSize,
    ReplayDetected,
    SessionNotFound,
    EncryptionFailed,
    DecryptionFailed,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedUdpNodeConfig {
    pub node_id: EncryptedUdpNodeId,
    pub bind_address: String,
    pub bind_port: u16,
    pub allow_real_udp: bool,
    pub simulation_mode: bool,
}

impl EncryptedUdpNodeConfig {
    pub fn validate(&self) -> Result<(), EncryptedUdpError> {
        if !self.allow_real_udp {
            return Err(EncryptedUdpError::RealUdpDisabled);
        }
        if self.simulation_mode {
            return Err(EncryptedUdpError::RealUdpDisabled);
        }
        if self.bind_address != "127.0.0.1" {
            return Err(EncryptedUdpError::PublicBindRejected);
        }
        if self.bind_port == 0 {
            return Err(EncryptedUdpError::InvalidNode);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config(port: u16) -> EncryptedUdpNodeConfig {
        EncryptedUdpNodeConfig {
            node_id: EncryptedUdpNodeId(1),
            bind_address: "127.0.0.1".to_string(),
            bind_port: port,
            allow_real_udp: true,
            simulation_mode: false,
        }
    }

    // ET1: default mode is Disabled
    #[test]
    fn et1_default_mode_is_disabled() {
        assert_eq!(EncryptedUdpMode::default(), EncryptedUdpMode::Disabled);
        assert_ne!(EncryptedUdpMode::default(), EncryptedUdpMode::LoopbackOnly);
    }

    // ET2: public bind address rejected
    #[test]
    fn et2_public_bind_rejected() {
        let mut cfg = valid_config(43001);
        cfg.bind_address = "0.0.0.0".to_string();
        assert_eq!(cfg.validate(), Err(EncryptedUdpError::PublicBindRejected));
    }

    // ET3: allow_real_udp=false rejected
    #[test]
    fn et3_allow_real_udp_false_rejected() {
        let mut cfg = valid_config(43002);
        cfg.allow_real_udp = false;
        assert_eq!(cfg.validate(), Err(EncryptedUdpError::RealUdpDisabled));
    }

    // ET4: simulation_mode=true rejected
    #[test]
    fn et4_simulation_mode_true_rejected() {
        let mut cfg = valid_config(43003);
        cfg.simulation_mode = true;
        assert_eq!(cfg.validate(), Err(EncryptedUdpError::RealUdpDisabled));
    }

    // ET5: valid loopback config accepted
    #[test]
    fn et5_valid_loopback_config_accepted() {
        assert_eq!(valid_config(43004).validate(), Ok(()));
    }
}
