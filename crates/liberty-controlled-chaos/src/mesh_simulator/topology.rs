use std::net::SocketAddr;

use crate::udp_transport::PeerAddress;

/// Role a node plays in the simulated mesh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    Guard,
    Relay,
    Exit,
}

/// A single node in the simulated topology.
#[derive(Debug, Clone)]
pub struct TopologyNode {
    pub node_id: u64,
    pub peer_address: PeerAddress,
    pub role: NodeRole,
    /// Maximum concurrent circuits this node can support.
    pub capacity: usize,
}

/// A directed link between two nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopologyLink {
    pub from: u64,
    pub to: u64,
}

/// Deterministic in-memory mesh topology.
///
/// Node ID ranges (for `node_count = N`):
///   Guards : 1 ..= guard_count                              (~10% of N, min 1)
///   Relays : guard_count+1 ..= guard_count+relay_count      (~80%, min 1)
///   Exits  : guard_count+relay_count+1 ..= actual_count     (~10%, min 1)
///
/// Minimum effective `node_count` is 3 (one of each role).
pub struct MeshTopology {
    pub nodes: Vec<TopologyNode>,
    /// IDs of Guard nodes, in ascending order.
    pub guards: Vec<u64>,
    /// IDs of Relay nodes, in ascending order.
    pub relays: Vec<u64>,
    /// IDs of Exit nodes, in ascending order.
    pub exits: Vec<u64>,
    /// Directed links (guard→relay, relay→exit).
    pub links: Vec<TopologyLink>,
}

impl MeshTopology {
    /// Build a deterministic topology from `node_count` nodes.
    pub fn generate_deterministic(node_count: usize) -> Self {
        let guard_count = (node_count / 10).max(1);
        let exit_count = (node_count / 10).max(1);
        let relay_count = node_count.saturating_sub(guard_count + exit_count).max(1);

        let mut nodes = Vec::new();
        let mut guards = Vec::new();
        let mut relays = Vec::new();
        let mut exits = Vec::new();
        let mut links = Vec::new();

        // Guards: IDs 1 ..= guard_count
        for id in 1u64..=(guard_count as u64) {
            nodes.push(TopologyNode {
                node_id: id,
                peer_address: make_addr(id),
                role: NodeRole::Guard,
                capacity: 1000,
            });
            guards.push(id);
        }

        // Relays: IDs guard_count+1 ..= guard_count+relay_count
        let relay_base = guard_count as u64;
        for i in 0u64..(relay_count as u64) {
            let id = relay_base + 1 + i;
            nodes.push(TopologyNode {
                node_id: id,
                peer_address: make_addr(id),
                role: NodeRole::Relay,
                capacity: 2000,
            });
            relays.push(id);
        }

        // Exits: IDs guard_count+relay_count+1 ..= actual_count
        let exit_base = relay_base + relay_count as u64;
        for i in 0u64..(exit_count as u64) {
            let id = exit_base + 1 + i;
            nodes.push(TopologyNode {
                node_id: id,
                peer_address: make_addr(id),
                role: NodeRole::Exit,
                capacity: 500,
            });
            exits.push(id);
        }

        // Links: each guard → the relay at the same modular index.
        for (gi, &g) in guards.iter().enumerate() {
            let r = relays[gi % relays.len()];
            links.push(TopologyLink { from: g, to: r });
        }
        // Links: each relay → the exit at the same modular index.
        for (ri, &r) in relays.iter().enumerate() {
            let e = exits[ri % exits.len()];
            links.push(TopologyLink { from: r, to: e });
        }

        Self {
            nodes,
            guards,
            relays,
            exits,
            links,
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn get_node(&self, node_id: u64) -> Option<&TopologyNode> {
        self.nodes.iter().find(|n| n.node_id == node_id)
    }

    pub fn guard_count(&self) -> usize {
        self.guards.len()
    }

    pub fn relay_count(&self) -> usize {
        self.relays.len()
    }

    pub fn exit_count(&self) -> usize {
        self.exits.len()
    }

    pub fn link_count(&self) -> usize {
        self.links.len()
    }
}

fn make_addr(node_id: u64) -> PeerAddress {
    let port = 9000u64 + node_id;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    PeerAddress::new(addr)
}
