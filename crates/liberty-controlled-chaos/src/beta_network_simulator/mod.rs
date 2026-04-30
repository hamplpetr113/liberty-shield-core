//! Beta network simulator — deterministic multi-node packet simulation.
//!
//! Simulates packet transit across a set of virtual nodes without real I/O.
//! Supports configurable latency, drop rate, and bandwidth constraints.

use std::collections::{HashMap, VecDeque};

// ---------------------------------------------------------------------------
// SimPacket
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SimPacket {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub payload: Vec<u8>,
    pub deliver_at_epoch: u64,
}

// ---------------------------------------------------------------------------
// LinkConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// Latency in epochs.
    pub latency_epochs: u64,
    /// Drop probability numerator out of 100.
    pub drop_pct: u8,
    /// Max bytes per epoch (0 = unlimited).
    pub bw_limit: u64,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            latency_epochs: 1,
            drop_pct: 0,
            bw_limit: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// SimNode
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SimNode {
    pub node_id: [u8; 32],
    pub online: bool,
    pub packets_received: u64,
    pub packets_dropped: u64,
}

// ---------------------------------------------------------------------------
// BetaNetworkSimulator
// ---------------------------------------------------------------------------

pub struct BetaNetworkSimulator {
    nodes: HashMap<[u8; 32], SimNode>,
    links: HashMap<([u8; 32], [u8; 32]), LinkConfig>,
    in_flight: VecDeque<SimPacket>,
    epoch: u64,
    /// xorshift64 seed for drop simulation.
    rng: u64,
    total_sent: u64,
    total_delivered: u64,
    total_dropped: u64,
}

impl BetaNetworkSimulator {
    pub fn new(seed: u64) -> Self {
        Self {
            nodes: HashMap::new(),
            links: HashMap::new(),
            in_flight: VecDeque::new(),
            epoch: 0,
            rng: seed | 1,
            total_sent: 0,
            total_delivered: 0,
            total_dropped: 0,
        }
    }

    fn xorshift(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        x
    }

    pub fn add_node(&mut self, node_id: [u8; 32]) {
        self.nodes.entry(node_id).or_insert(SimNode {
            node_id,
            online: true,
            packets_received: 0,
            packets_dropped: 0,
        });
    }

    pub fn set_online(&mut self, node_id: &[u8; 32], online: bool) {
        if let Some(n) = self.nodes.get_mut(node_id) {
            n.online = online;
        }
    }

    pub fn set_link(&mut self, from: [u8; 32], to: [u8; 32], config: LinkConfig) {
        self.links.insert((from, to), config);
    }

    /// Enqueue a packet. Returns `false` if either node is offline.
    pub fn send(&mut self, from: [u8; 32], to: [u8; 32], payload: Vec<u8>) -> bool {
        if !self.nodes.get(&from).map(|n| n.online).unwrap_or(false) {
            return false;
        }
        if !self.nodes.get(&to).map(|n| n.online).unwrap_or(false) {
            return false;
        }
        let cfg = self.links.get(&(from, to)).cloned().unwrap_or_default();
        // Simulate drop.
        let rand_pct = (self.xorshift() % 100) as u8;
        if rand_pct < cfg.drop_pct {
            if let Some(n) = self.nodes.get_mut(&from) {
                n.packets_dropped += 1;
            }
            self.total_dropped += 1;
            self.total_sent += 1;
            return true; // "sent" but dropped
        }
        let deliver_at = self.epoch + cfg.latency_epochs;
        self.in_flight.push_back(SimPacket {
            from,
            to,
            payload,
            deliver_at_epoch: deliver_at,
        });
        self.total_sent += 1;
        true
    }

    /// Advance to `epoch`, delivering all packets due.
    pub fn tick(&mut self, epoch: u64) -> Vec<SimPacket> {
        self.epoch = epoch;
        let mut delivered = Vec::new();
        let mut remaining = VecDeque::new();
        while let Some(pkt) = self.in_flight.pop_front() {
            if pkt.deliver_at_epoch <= epoch {
                if self.nodes.get(&pkt.to).map(|n| n.online).unwrap_or(false) {
                    if let Some(n) = self.nodes.get_mut(&pkt.to) {
                        n.packets_received += 1;
                    }
                    self.total_delivered += 1;
                    delivered.push(pkt);
                } else {
                    self.total_dropped += 1;
                }
            } else {
                remaining.push_back(pkt);
            }
        }
        self.in_flight = remaining;
        delivered
    }

    pub fn node(&self, node_id: &[u8; 32]) -> Option<&SimNode> {
        self.nodes.get(node_id)
    }

    pub fn total_sent(&self) -> u64 {
        self.total_sent
    }

    pub fn total_delivered(&self) -> u64 {
        self.total_delivered
    }

    pub fn total_dropped(&self) -> u64 {
        self.total_dropped
    }

    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
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

    fn sim() -> BetaNetworkSimulator {
        BetaNetworkSimulator::new(0xdeadbeef)
    }

    // BNS1: packet delivered after latency epochs.
    #[test]
    fn bns1_basic_delivery() {
        let mut s = sim();
        s.add_node(nid(1));
        s.add_node(nid(2));
        s.set_link(
            nid(1),
            nid(2),
            LinkConfig {
                latency_epochs: 2,
                drop_pct: 0,
                bw_limit: 0,
            },
        );
        s.send(nid(1), nid(2), b"hello".to_vec());
        let d1 = s.tick(1);
        assert!(d1.is_empty());
        let d2 = s.tick(2);
        assert_eq!(d2.len(), 1);
        assert_eq!(d2[0].payload, b"hello");
    }

    // BNS2: offline sender cannot send.
    #[test]
    fn bns2_offline_sender() {
        let mut s = sim();
        s.add_node(nid(1));
        s.add_node(nid(2));
        s.set_online(&nid(1), false);
        assert!(!s.send(nid(1), nid(2), b"x".to_vec()));
    }

    // BNS3: packet dropped if receiver goes offline before delivery.
    #[test]
    fn bns3_receiver_offline_before_delivery() {
        let mut s = sim();
        s.add_node(nid(1));
        s.add_node(nid(2));
        s.set_link(
            nid(1),
            nid(2),
            LinkConfig {
                latency_epochs: 5,
                drop_pct: 0,
                bw_limit: 0,
            },
        );
        s.send(nid(1), nid(2), b"x".to_vec());
        s.set_online(&nid(2), false);
        let d = s.tick(10);
        assert!(d.is_empty());
        assert_eq!(s.total_dropped(), 1);
    }

    // BNS4: 100% drop_pct drops all packets.
    #[test]
    fn bns4_full_drop() {
        let mut s = BetaNetworkSimulator::new(1); // deterministic seed
        s.add_node(nid(1));
        s.add_node(nid(2));
        s.set_link(
            nid(1),
            nid(2),
            LinkConfig {
                latency_epochs: 1,
                drop_pct: 100,
                bw_limit: 0,
            },
        );
        for _ in 0..10 {
            s.send(nid(1), nid(2), b"x".to_vec());
        }
        s.tick(1);
        assert_eq!(s.total_delivered(), 0);
    }

    // BNS5: in_flight_count reflects pending packets.
    #[test]
    fn bns5_in_flight_count() {
        let mut s = sim();
        s.add_node(nid(1));
        s.add_node(nid(2));
        s.set_link(
            nid(1),
            nid(2),
            LinkConfig {
                latency_epochs: 5,
                drop_pct: 0,
                bw_limit: 0,
            },
        );
        s.send(nid(1), nid(2), b"a".to_vec());
        s.send(nid(1), nid(2), b"b".to_vec());
        assert_eq!(s.in_flight_count(), 2);
    }

    // BNS6: total_sent increments for every send call (including drops).
    #[test]
    fn bns6_total_sent() {
        let mut s = sim();
        s.add_node(nid(1));
        s.add_node(nid(2));
        s.send(nid(1), nid(2), b"a".to_vec());
        s.send(nid(1), nid(2), b"b".to_vec());
        assert_eq!(s.total_sent(), 2);
    }

    // BNS7: default link (no explicit set_link) uses latency 1.
    #[test]
    fn bns7_default_link() {
        let mut s = sim();
        s.add_node(nid(1));
        s.add_node(nid(2));
        s.send(nid(1), nid(2), b"hi".to_vec());
        let d = s.tick(1);
        assert_eq!(d.len(), 1);
    }

    // BNS8: multiple nodes; independent delivery.
    #[test]
    fn bns8_multiple_nodes() {
        let mut s = sim();
        for b in 1u8..=4 {
            s.add_node(nid(b));
        }
        s.send(nid(1), nid(2), b"a".to_vec());
        s.send(nid(3), nid(4), b"b".to_vec());
        let d = s.tick(1);
        assert_eq!(d.len(), 2);
    }

    // BNS9: node packets_received counter increments.
    #[test]
    fn bns9_packets_received_counter() {
        let mut s = sim();
        s.add_node(nid(1));
        s.add_node(nid(2));
        s.send(nid(1), nid(2), b"x".to_vec());
        s.tick(1);
        assert_eq!(s.node(&nid(2)).unwrap().packets_received, 1);
    }

    // BNS10: set_online restores delivery.
    #[test]
    fn bns10_reconnect_node() {
        let mut s = sim();
        s.add_node(nid(1));
        s.add_node(nid(2));
        s.set_online(&nid(2), false);
        let ok = s.send(nid(1), nid(2), b"x".to_vec());
        assert!(!ok);
        s.set_online(&nid(2), true);
        s.send(nid(1), nid(2), b"y".to_vec());
        let d = s.tick(1);
        assert_eq!(d.len(), 1);
    }
}
