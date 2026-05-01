use std::io;
use std::net::{SocketAddr, UdpSocket};

use crate::udp_testnet_packet::{UdpTestnetPacket, decode_packet, encode_packet};
use crate::udp_testnet_types::{UdpTestnetError, UdpTestnetNodeConfig, UdpTestnetNodeId};

#[derive(Debug)]
pub struct UdpLoopbackSocket {
    pub node_id: UdpTestnetNodeId,
    socket: UdpSocket,
    local_addr: SocketAddr,
}

impl UdpLoopbackSocket {
    pub fn bind(config: &UdpTestnetNodeConfig) -> Result<Self, UdpTestnetError> {
        if config.bind_address != "127.0.0.1" {
            return Err(UdpTestnetError::PublicBindRejected);
        }
        let addr = format!("127.0.0.1:{}", config.bind_port);
        let socket = UdpSocket::bind(&addr).map_err(|_| UdpTestnetError::SocketBindFailed)?;
        socket
            .set_nonblocking(true)
            .map_err(|_| UdpTestnetError::SocketBindFailed)?;
        let local_addr = socket
            .local_addr()
            .map_err(|_| UdpTestnetError::SocketBindFailed)?;
        Ok(Self {
            node_id: config.node_id,
            socket,
            local_addr,
        })
    }

    pub fn send_to(
        &self,
        packet: &UdpTestnetPacket,
        target_addr: SocketAddr,
    ) -> Result<(), UdpTestnetError> {
        if !target_addr.ip().is_loopback() {
            return Err(UdpTestnetError::PublicBindRejected);
        }
        let bytes = encode_packet(packet);
        self.socket
            .send_to(&bytes, target_addr)
            .map_err(|_| UdpTestnetError::SendFailed)?;
        Ok(())
    }

    pub fn try_recv(&self) -> Result<Option<(UdpTestnetPacket, SocketAddr)>, UdpTestnetError> {
        let mut buf = [0u8; 65536];
        match self.socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                let packet = decode_packet(&buf[..n])?;
                Ok(Some((packet, from)))
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(_) => Err(UdpTestnetError::ReceiveFailed),
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp_testnet_packet::UdpTestnetPacket;
    use crate::udp_testnet_types::{UdpTestnetNodeId, UdpTestnetPacketKind};

    fn loopback_config(id: u64, port: u16) -> UdpTestnetNodeConfig {
        UdpTestnetNodeConfig {
            node_id: UdpTestnetNodeId(id),
            bind_address: "127.0.0.1".to_string(),
            bind_port: port,
            allow_real_udp: true,
            simulation_mode: false,
            max_packet_size: 1482,
        }
    }

    fn probe(src: u64, dst: u64) -> UdpTestnetPacket {
        UdpTestnetPacket {
            source_node: UdpTestnetNodeId(src),
            target_node: UdpTestnetNodeId(dst),
            packet_kind: UdpTestnetPacketKind::Probe,
            sequence_number: 0,
            payload: Vec::new(),
        }
    }

    // SO1: bind loopback socket succeeds
    #[test]
    fn so1_bind_loopback_socket() {
        let cfg = loopback_config(1, 42100);
        let sock = UdpLoopbackSocket::bind(&cfg).unwrap();
        assert_eq!(sock.local_addr().port(), 42100);
        assert!(sock.local_addr().ip().is_loopback());
    }

    // SO2: reject public bind address
    #[test]
    fn so2_reject_public_bind() {
        let mut cfg = loopback_config(1, 42101);
        cfg.bind_address = "0.0.0.0".to_string();
        assert_eq!(
            UdpLoopbackSocket::bind(&cfg).unwrap_err(),
            UdpTestnetError::PublicBindRejected
        );
    }

    // SO3: send probe between two local sockets
    #[test]
    fn so3_send_probe_between_two_sockets() {
        let sender = UdpLoopbackSocket::bind(&loopback_config(1, 42102)).unwrap();
        let receiver = UdpLoopbackSocket::bind(&loopback_config(2, 42103)).unwrap();
        let pkt = probe(1, 2);
        sender.send_to(&pkt, receiver.local_addr()).unwrap();
        let (received, _from) = receiver.try_recv().unwrap().unwrap();
        assert_eq!(received.source_node, UdpTestnetNodeId(1));
        assert_eq!(received.target_node, UdpTestnetNodeId(2));
        assert_eq!(received.packet_kind, UdpTestnetPacketKind::Probe);
    }

    // SO4: try_recv returns None when socket is empty
    #[test]
    fn so4_try_recv_returns_none_if_empty() {
        let sock = UdpLoopbackSocket::bind(&loopback_config(1, 42104)).unwrap();
        assert_eq!(sock.try_recv().unwrap(), None);
    }

    // SO5: send_to rejects non-loopback target address
    #[test]
    fn so5_reject_non_loopback_target() {
        let sock = UdpLoopbackSocket::bind(&loopback_config(1, 42105)).unwrap();
        let pkt = probe(1, 99);
        let non_loopback: SocketAddr = "8.8.8.8:12345".parse().unwrap();
        assert_eq!(
            sock.send_to(&pkt, non_loopback).unwrap_err(),
            UdpTestnetError::PublicBindRejected
        );
    }
}
