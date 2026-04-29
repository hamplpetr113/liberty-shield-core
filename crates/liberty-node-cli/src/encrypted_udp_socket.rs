use std::io;
use std::net::{SocketAddr, UdpSocket};

use crate::encrypted_udp_packet::{
    EncryptedUdpPacket, decode_encrypted_udp_packet, encode_encrypted_udp_packet,
};
use crate::encrypted_udp_types::{EncryptedUdpError, EncryptedUdpNodeConfig, EncryptedUdpNodeId};

#[derive(Debug)]
pub struct EncryptedUdpSocket {
    pub node_id: EncryptedUdpNodeId,
    socket: UdpSocket,
    local_addr: SocketAddr,
}

impl EncryptedUdpSocket {
    pub fn bind(config: &EncryptedUdpNodeConfig) -> Result<Self, EncryptedUdpError> {
        if config.bind_address != "127.0.0.1" {
            return Err(EncryptedUdpError::PublicBindRejected);
        }
        let addr = format!("127.0.0.1:{}", config.bind_port);
        let socket = UdpSocket::bind(&addr).map_err(|_| EncryptedUdpError::SocketBindFailed)?;
        socket
            .set_nonblocking(true)
            .map_err(|_| EncryptedUdpError::SocketBindFailed)?;
        let local_addr = socket
            .local_addr()
            .map_err(|_| EncryptedUdpError::SocketBindFailed)?;
        Ok(Self {
            node_id: config.node_id,
            socket,
            local_addr,
        })
    }

    pub fn send_to(
        &self,
        packet: &EncryptedUdpPacket,
        target_addr: SocketAddr,
    ) -> Result<(), EncryptedUdpError> {
        if !target_addr.ip().is_loopback() {
            return Err(EncryptedUdpError::PublicBindRejected);
        }
        let bytes =
            encode_encrypted_udp_packet(packet).map_err(|_| EncryptedUdpError::SendFailed)?;
        self.socket
            .send_to(&bytes, target_addr)
            .map_err(|_| EncryptedUdpError::SendFailed)?;
        Ok(())
    }

    pub fn try_recv(&self) -> Result<Option<(EncryptedUdpPacket, SocketAddr)>, EncryptedUdpError> {
        let mut buf = [0u8; 65536];
        match self.socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                let packet = decode_encrypted_udp_packet(&buf[..n])
                    .map_err(|_| EncryptedUdpError::ReceiveFailed)?;
                Ok(Some((packet, from)))
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(None)
            }
            Err(_) => Err(EncryptedUdpError::ReceiveFailed),
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypted_udp_packet::ENCRYPTED_UDP_HEADER_SIZE;
    use crate::encrypted_udp_types::{EncryptedUdpNodeId, EncryptedUdpPacketKind};
    use liberty_controlled_chaos::noise_link::ENCRYPTED_CELL_SIZE;

    fn sock_config(id: u64, port: u16) -> EncryptedUdpNodeConfig {
        EncryptedUdpNodeConfig {
            node_id: EncryptedUdpNodeId(id),
            bind_address: "127.0.0.1".to_string(),
            bind_port: port,
            allow_real_udp: true,
            simulation_mode: false,
        }
    }

    fn shutdown_pkt(src: u64, dst: u64) -> EncryptedUdpPacket {
        EncryptedUdpPacket {
            source_node: EncryptedUdpNodeId(src),
            target_node: EncryptedUdpNodeId(dst),
            packet_kind: EncryptedUdpPacketKind::Shutdown,
            sequence_number: 0,
            encrypted_cell_bytes: Vec::new(),
        }
    }

    fn cell_pkt(src: u64, dst: u64) -> EncryptedUdpPacket {
        EncryptedUdpPacket {
            source_node: EncryptedUdpNodeId(src),
            target_node: EncryptedUdpNodeId(dst),
            packet_kind: EncryptedUdpPacketKind::EncryptedCell,
            sequence_number: 0,
            encrypted_cell_bytes: vec![0xBBu8; ENCRYPTED_CELL_SIZE],
        }
    }

    // ES1: bind loopback socket succeeds
    #[test]
    fn es1_bind_loopback_socket() {
        let sock = EncryptedUdpSocket::bind(&sock_config(1, 43000)).unwrap();
        assert_eq!(sock.local_addr().port(), 43000);
        assert!(sock.local_addr().ip().is_loopback());
    }

    // ES2: reject public bind address
    #[test]
    fn es2_reject_public_bind() {
        let mut cfg = sock_config(1, 43001);
        cfg.bind_address = "0.0.0.0".to_string();
        assert_eq!(
            EncryptedUdpSocket::bind(&cfg).unwrap_err(),
            EncryptedUdpError::PublicBindRejected
        );
    }

    // ES3: send encrypted packet between two local sockets
    #[test]
    fn es3_send_encrypted_packet_between_sockets() {
        let sender = EncryptedUdpSocket::bind(&sock_config(1, 43002)).unwrap();
        let receiver = EncryptedUdpSocket::bind(&sock_config(2, 43003)).unwrap();
        let pkt = cell_pkt(1, 2);
        sender.send_to(&pkt, receiver.local_addr()).unwrap();
        let (received, _from) = receiver.try_recv().unwrap().unwrap();
        assert_eq!(received.source_node, EncryptedUdpNodeId(1));
        assert_eq!(received.target_node, EncryptedUdpNodeId(2));
        assert_eq!(received.packet_kind, EncryptedUdpPacketKind::EncryptedCell);
        assert_eq!(received.encrypted_cell_bytes.len(), ENCRYPTED_CELL_SIZE);
        let _ = ENCRYPTED_UDP_HEADER_SIZE; // used to silence unused import warning
    }

    // ES4: try_recv returns None when socket is empty
    #[test]
    fn es4_try_recv_none_if_empty() {
        let sock = EncryptedUdpSocket::bind(&sock_config(1, 43004)).unwrap();
        assert_eq!(sock.try_recv().unwrap(), None);
    }

    // ES5: reject non-loopback send target
    #[test]
    fn es5_reject_non_loopback_target() {
        let sock = EncryptedUdpSocket::bind(&sock_config(1, 43005)).unwrap();
        let pkt = shutdown_pkt(1, 99);
        let non_loopback: SocketAddr = "8.8.8.8:12345".parse().unwrap();
        assert_eq!(
            sock.send_to(&pkt, non_loopback).unwrap_err(),
            EncryptedUdpError::PublicBindRejected
        );
    }
}
