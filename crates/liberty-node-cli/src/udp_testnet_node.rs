use std::net::SocketAddr;

use crate::udp_loopback_socket::UdpLoopbackSocket;
use crate::udp_testnet_packet::UdpTestnetPacket;
use crate::udp_testnet_types::{
    UdpTestnetError, UdpTestnetNodeConfig, UdpTestnetNodeId, UdpTestnetPacketKind,
};

#[derive(Debug)]
pub struct UdpTestnetNode {
    config: UdpTestnetNodeConfig,
    socket: UdpLoopbackSocket,
    sequence_counter: u64,
    packets_sent: u64,
    packets_received: u64,
    packets_dropped: u64,
}

#[derive(Debug, Clone)]
pub struct UdpTestnetNodeSnapshot {
    pub node_id: UdpTestnetNodeId,
    pub local_addr: SocketAddr,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub next_sequence: u64,
}

impl UdpTestnetNode {
    pub fn start(config: UdpTestnetNodeConfig) -> Result<Self, UdpTestnetError> {
        config.validate()?;
        let socket = UdpLoopbackSocket::bind(&config)?;
        Ok(Self {
            config,
            socket,
            sequence_counter: 0,
            packets_sent: 0,
            packets_received: 0,
            packets_dropped: 0,
        })
    }

    pub fn send_probe(
        &mut self,
        target_node: UdpTestnetNodeId,
        target_addr: SocketAddr,
    ) -> Result<(), UdpTestnetError> {
        let seq = self.next_seq();
        let packet = UdpTestnetPacket {
            source_node: self.config.node_id,
            target_node,
            packet_kind: UdpTestnetPacketKind::Probe,
            sequence_number: seq,
            payload: Vec::new(),
        };
        self.socket.send_to(&packet, target_addr)?;
        self.packets_sent += 1;
        Ok(())
    }

    pub fn send_data(
        &mut self,
        target_node: UdpTestnetNodeId,
        target_addr: SocketAddr,
        payload: Vec<u8>,
    ) -> Result<(), UdpTestnetError> {
        let seq = self.next_seq();
        let packet = UdpTestnetPacket {
            source_node: self.config.node_id,
            target_node,
            packet_kind: UdpTestnetPacketKind::Data,
            sequence_number: seq,
            payload,
        };
        self.socket.send_to(&packet, target_addr)?;
        self.packets_sent += 1;
        Ok(())
    }

    pub fn shutdown_packet(
        &mut self,
        target_node: UdpTestnetNodeId,
        target_addr: SocketAddr,
    ) -> Result<(), UdpTestnetError> {
        let seq = self.next_seq();
        let packet = UdpTestnetPacket {
            source_node: self.config.node_id,
            target_node,
            packet_kind: UdpTestnetPacketKind::Shutdown,
            sequence_number: seq,
            payload: Vec::new(),
        };
        self.socket.send_to(&packet, target_addr)?;
        self.packets_sent += 1;
        Ok(())
    }

    pub fn poll_once(&mut self) -> Result<Option<UdpTestnetPacket>, UdpTestnetError> {
        match self.socket.try_recv() {
            Ok(Some((packet, _from))) => {
                self.packets_received += 1;
                Ok(Some(packet))
            }
            Ok(None) => Ok(None),
            Err(UdpTestnetError::PacketDecodeFailed) => {
                self.packets_dropped += 1;
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    pub fn snapshot(&self) -> UdpTestnetNodeSnapshot {
        UdpTestnetNodeSnapshot {
            node_id: self.config.node_id,
            local_addr: self.socket.local_addr(),
            packets_sent: self.packets_sent,
            packets_received: self.packets_received,
            packets_dropped: self.packets_dropped,
            next_sequence: self.sequence_counter,
        }
    }

    fn next_seq(&mut self) -> u64 {
        let seq = self.sequence_counter;
        self.sequence_counter += 1;
        seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_config(id: u64, port: u16) -> UdpTestnetNodeConfig {
        UdpTestnetNodeConfig {
            node_id: UdpTestnetNodeId(id),
            bind_address: "127.0.0.1".to_string(),
            bind_port: port,
            allow_real_udp: true,
            simulation_mode: false,
            max_packet_size: 1482,
        }
    }

    // UN1: start node binds socket and returns snapshot
    #[test]
    fn un1_start_node() {
        let node = UdpTestnetNode::start(node_config(1, 42200)).unwrap();
        let snap = node.snapshot();
        assert_eq!(snap.node_id, UdpTestnetNodeId(1));
        assert_eq!(snap.packets_sent, 0);
        assert_eq!(snap.packets_received, 0);
        assert_eq!(snap.next_sequence, 0);
    }

    // UN2: send_probe increments packets_sent and sequence
    #[test]
    fn un2_send_probe_increments_sent() {
        let mut sender = UdpTestnetNode::start(node_config(1, 42201)).unwrap();
        let receiver = UdpTestnetNode::start(node_config(2, 42202)).unwrap();
        let target_addr = receiver.snapshot().local_addr;
        sender.send_probe(UdpTestnetNodeId(2), target_addr).unwrap();
        let snap = sender.snapshot();
        assert_eq!(snap.packets_sent, 1);
        assert_eq!(snap.next_sequence, 1);
    }

    // UN3: two nodes exchange probe — receiver gets the packet
    #[test]
    fn un3_two_nodes_exchange_probe() {
        let mut node_a = UdpTestnetNode::start(node_config(1, 42203)).unwrap();
        let mut node_b = UdpTestnetNode::start(node_config(2, 42204)).unwrap();
        let b_addr = node_b.snapshot().local_addr;
        node_a.send_probe(UdpTestnetNodeId(2), b_addr).unwrap();
        let received = node_b.poll_once().unwrap().unwrap();
        assert_eq!(received.source_node, UdpTestnetNodeId(1));
        assert_eq!(received.target_node, UdpTestnetNodeId(2));
        assert_eq!(received.packet_kind, UdpTestnetPacketKind::Probe);
        assert_eq!(node_b.snapshot().packets_received, 1);
    }

    // UN4: data payload delivered intact
    #[test]
    fn un4_data_payload_delivered() {
        let mut node_a = UdpTestnetNode::start(node_config(1, 42205)).unwrap();
        let mut node_b = UdpTestnetNode::start(node_config(2, 42206)).unwrap();
        let b_addr = node_b.snapshot().local_addr;
        node_a
            .send_data(UdpTestnetNodeId(2), b_addr, b"testdata".to_vec())
            .unwrap();
        let received = node_b.poll_once().unwrap().unwrap();
        assert_eq!(received.packet_kind, UdpTestnetPacketKind::Data);
        assert_eq!(received.payload, b"testdata");
    }

    // UN5: sequence increments deterministically per send
    #[test]
    fn un5_sequence_increments_deterministically() {
        let mut node_a = UdpTestnetNode::start(node_config(1, 42207)).unwrap();
        let node_b = UdpTestnetNode::start(node_config(2, 42208)).unwrap();
        let b_addr = node_b.snapshot().local_addr;
        node_a.send_probe(UdpTestnetNodeId(2), b_addr).unwrap();
        node_a.send_probe(UdpTestnetNodeId(2), b_addr).unwrap();
        node_a.send_probe(UdpTestnetNodeId(2), b_addr).unwrap();
        let snap = node_a.snapshot();
        assert_eq!(snap.next_sequence, 3);
        assert_eq!(snap.packets_sent, 3);
    }

    // UN6: snapshot reflects accurate state
    #[test]
    fn un6_snapshot_accurate() {
        let mut node_a = UdpTestnetNode::start(node_config(1, 42209)).unwrap();
        let mut node_b = UdpTestnetNode::start(node_config(2, 42210)).unwrap();
        let b_addr = node_b.snapshot().local_addr;
        node_a.send_probe(UdpTestnetNodeId(2), b_addr).unwrap();
        node_b.poll_once().unwrap();
        let snap_a = node_a.snapshot();
        let snap_b = node_b.snapshot();
        assert_eq!(snap_a.packets_sent, 1);
        assert_eq!(snap_a.packets_received, 0);
        assert_eq!(snap_b.packets_sent, 0);
        assert_eq!(snap_b.packets_received, 1);
    }
}
