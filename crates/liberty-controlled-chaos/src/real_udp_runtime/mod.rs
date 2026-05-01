//! Real UDP runtime — wraps `transport::UdpLink` with a peer address table.
//!
//! `RealUdpRuntime` maintains a mapping from logical node IDs to UDP socket
//! addresses, and enforces packet size limits before forwarding.
//!
//! NON-PRODUCTION: no authentication at the UDP layer.

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::transport::{UdpLink, UdpLinkError};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum UdpRuntimeError {
    UnknownPeer,
    PacketTooLarge,
    Transport(String),
}

impl From<UdpLinkError> for UdpRuntimeError {
    fn from(e: UdpLinkError) -> Self {
        UdpRuntimeError::Transport(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// ReceivedPacket
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct ReceivedPacket {
    pub from_addr: SocketAddr,
    pub payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// RealUdpRuntime
// ---------------------------------------------------------------------------

pub struct RealUdpRuntime {
    link: UdpLink,
    peers: HashMap<[u8; 32], SocketAddr>,
    max_packet: usize,
    packets_sent: u64,
    packets_recv: u64,
}

impl RealUdpRuntime {
    /// Bind to `local_addr`.
    pub fn bind(local_addr: &str) -> Result<Self, UdpRuntimeError> {
        let link = UdpLink::bind(local_addr)?;
        link.set_nonblocking(true)?;
        Ok(Self {
            link,
            peers: HashMap::new(),
            max_packet: crate::transport::udp_link::MAX_PACKET,
            packets_sent: 0,
            packets_recv: 0,
        })
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.link.local_addr().ok()
    }

    /// Register a peer node.
    pub fn connect_peer(&mut self, node_id: [u8; 32], addr: SocketAddr) {
        self.peers.insert(node_id, addr);
    }

    pub fn remove_peer(&mut self, node_id: &[u8; 32]) {
        self.peers.remove(node_id);
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn peer_addr(&self, node_id: &[u8; 32]) -> Option<SocketAddr> {
        self.peers.get(node_id).copied()
    }

    /// Reverse lookup: find the node_id for a given socket address.
    pub fn peer_id_by_addr(&self, addr: SocketAddr) -> Option<[u8; 32]> {
        self.peers
            .iter()
            .find(|(_, a)| **a == addr)
            .map(|(id, _)| *id)
    }

    /// Send bytes to a known peer.
    pub fn send_to_peer(
        &mut self,
        node_id: &[u8; 32],
        payload: &[u8],
    ) -> Result<(), UdpRuntimeError> {
        if payload.len() > self.max_packet {
            return Err(UdpRuntimeError::PacketTooLarge);
        }
        let addr = self
            .peers
            .get(node_id)
            .copied()
            .ok_or(UdpRuntimeError::UnknownPeer)?;
        self.link.send(addr, payload)?;
        self.packets_sent += 1;
        Ok(())
    }

    /// Non-blocking receive. Returns `None` if no packet is ready.
    pub fn poll_recv(&mut self) -> Option<ReceivedPacket> {
        match self.link.recv() {
            Ok((payload, from_addr)) => {
                self.packets_recv += 1;
                Some(ReceivedPacket { from_addr, payload })
            }
            Err(_) => None,
        }
    }

    pub fn packets_sent(&self) -> u64 {
        self.packets_sent
    }

    pub fn packets_recv(&self) -> u64 {
        self.packets_recv
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

    fn runtime() -> RealUdpRuntime {
        RealUdpRuntime::bind("127.0.0.1:0").expect("bind")
    }

    // RUR1: bind succeeds and local_addr is set.
    #[test]
    fn rur1_bind_succeeds() {
        let r = runtime();
        assert!(r.local_addr().is_some());
    }

    // RUR2: connect_peer adds peer.
    #[test]
    fn rur2_connect_peer() {
        let mut r = runtime();
        r.connect_peer(nid(1), "127.0.0.1:9999".parse().unwrap());
        assert_eq!(r.peer_count(), 1);
    }

    // RUR3: send to unknown peer returns error.
    #[test]
    fn rur3_unknown_peer_rejected() {
        let mut r = runtime();
        assert!(matches!(
            r.send_to_peer(&nid(99), b"hello"),
            Err(UdpRuntimeError::UnknownPeer)
        ));
    }

    // RUR4: oversized packet rejected.
    #[test]
    fn rur4_oversized_rejected() {
        let mut r = runtime();
        r.connect_peer(nid(1), "127.0.0.1:9999".parse().unwrap());
        let big = vec![0u8; crate::transport::udp_link::MAX_PACKET + 1];
        assert!(matches!(
            r.send_to_peer(&nid(1), &big),
            Err(UdpRuntimeError::PacketTooLarge)
        ));
    }

    // RUR5: poll_recv on empty socket returns None.
    #[test]
    fn rur5_poll_empty_safe() {
        let mut r = runtime();
        assert!(r.poll_recv().is_none());
    }

    // RUR6: send datagram between two runtimes.
    #[test]
    fn rur6_send_recv_loopback() {
        let mut sender = runtime();
        let mut receiver = runtime();
        let recv_addr = receiver.local_addr().unwrap();
        receiver.connect_peer(nid(1), recv_addr); // dummy, not used for receive
        sender.connect_peer(nid(2), recv_addr);
        // Allow receiver to get the packet.
        receiver.link.set_nonblocking(false).ok();
        receiver
            .link
            .set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .ok();
        sender.send_to_peer(&nid(2), b"ping").unwrap();
        let pkt = receiver.poll_recv();
        assert!(pkt.is_some());
        assert_eq!(pkt.unwrap().payload, b"ping");
    }

    // RUR7: remove_peer reduces count.
    #[test]
    fn rur7_remove_peer() {
        let mut r = runtime();
        r.connect_peer(nid(1), "127.0.0.1:9999".parse().unwrap());
        r.remove_peer(&nid(1));
        assert_eq!(r.peer_count(), 0);
    }

    // RUR8: packets_sent counter increments.
    #[test]
    fn rur8_packets_sent_counter() {
        let mut sender = runtime();
        let receiver = runtime();
        let addr = receiver.local_addr().unwrap();
        sender.connect_peer(nid(1), addr);
        sender.send_to_peer(&nid(1), b"x").unwrap();
        assert_eq!(sender.packets_sent(), 1);
    }

    // RUR9: peer_addr returns registered address.
    #[test]
    fn rur9_peer_addr() {
        let mut r = runtime();
        let addr: SocketAddr = "127.0.0.1:5555".parse().unwrap();
        r.connect_peer(nid(3), addr);
        assert_eq!(r.peer_addr(&nid(3)), Some(addr));
    }

    // RUR10: two peers can be registered independently.
    #[test]
    fn rur10_multiple_peers() {
        let mut r = runtime();
        r.connect_peer(nid(1), "127.0.0.1:1111".parse().unwrap());
        r.connect_peer(nid(2), "127.0.0.1:2222".parse().unwrap());
        assert_eq!(r.peer_count(), 2);
        assert_ne!(r.peer_addr(&nid(1)), r.peer_addr(&nid(2)));
    }
}
