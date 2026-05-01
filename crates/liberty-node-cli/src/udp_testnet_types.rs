#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum UdpTestnetMode {
    #[default]
    Disabled,
    LoopbackOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UdpTestnetNodeId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpTestnetPacketKind {
    Probe,
    Data,
    Cover,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpTestnetError {
    RealUdpDisabled,
    PublicBindRejected,
    InvalidNode,
    NodeNotRunning,
    SocketBindFailed,
    SendFailed,
    ReceiveFailed,
    PacketDecodeFailed,
    Timeout,
}

#[derive(Debug, Clone, PartialEq)]
pub struct UdpTestnetNodeConfig {
    pub node_id: UdpTestnetNodeId,
    pub bind_address: String,
    pub bind_port: u16,
    pub allow_real_udp: bool,
    pub simulation_mode: bool,
    pub max_packet_size: usize,
}

impl UdpTestnetNodeConfig {
    pub fn validate(&self) -> Result<(), UdpTestnetError> {
        if !self.allow_real_udp {
            return Err(UdpTestnetError::RealUdpDisabled);
        }
        if self.simulation_mode {
            return Err(UdpTestnetError::RealUdpDisabled);
        }
        if self.bind_address != "127.0.0.1" {
            return Err(UdpTestnetError::PublicBindRejected);
        }
        if self.bind_port == 0 {
            return Err(UdpTestnetError::InvalidNode);
        }
        if self.max_packet_size < 1482 {
            return Err(UdpTestnetError::InvalidNode);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config(port: u16) -> UdpTestnetNodeConfig {
        UdpTestnetNodeConfig {
            node_id: UdpTestnetNodeId(1),
            bind_address: "127.0.0.1".to_string(),
            bind_port: port,
            allow_real_udp: true,
            simulation_mode: false,
            max_packet_size: 1482,
        }
    }

    // UT1: default mode is Disabled
    #[test]
    fn ut1_default_mode_is_disabled() {
        assert_eq!(UdpTestnetMode::default(), UdpTestnetMode::Disabled);
        assert_ne!(UdpTestnetMode::default(), UdpTestnetMode::LoopbackOnly);
    }

    // UT2: reject public bind address
    #[test]
    fn ut2_reject_public_bind() {
        let mut cfg = valid_config(41001);
        cfg.bind_address = "0.0.0.0".to_string();
        assert_eq!(cfg.validate(), Err(UdpTestnetError::PublicBindRejected));
    }

    // UT3: reject allow_real_udp=false
    #[test]
    fn ut3_reject_allow_real_udp_false() {
        let mut cfg = valid_config(41002);
        cfg.allow_real_udp = false;
        assert_eq!(cfg.validate(), Err(UdpTestnetError::RealUdpDisabled));
    }

    // UT4: reject simulation_mode=true
    #[test]
    fn ut4_reject_simulation_mode_true() {
        let mut cfg = valid_config(41003);
        cfg.simulation_mode = true;
        assert_eq!(cfg.validate(), Err(UdpTestnetError::RealUdpDisabled));
    }

    // UT5: valid loopback config accepted
    #[test]
    fn ut5_valid_loopback_config_accepted() {
        assert_eq!(valid_config(41004).validate(), Ok(()));
    }
}
