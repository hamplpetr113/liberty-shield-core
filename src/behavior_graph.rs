use std::collections::HashMap;
use std::time::{Duration, Instant};

const PENDING_TTL: Duration = Duration::from_secs(30);

pub enum GraphNode {
    Process { pid: u32, name: String },

    Network { remote_ip: String, remote_port: u16 },
}

pub enum GraphEdge {
    Spawned,

    ConnectedTo,
}

pub struct BehaviorGraph {
    nodes: Vec<GraphNode>,

    edges: Vec<(usize, usize, GraphEdge)>,

    pid_index: HashMap<u32, usize>,

    pending: HashMap<u32, Vec<(usize, Instant)>>,

    ttl: Duration,
}

impl BehaviorGraph {
    pub fn new() -> Self {
        Self::with_ttl(PENDING_TTL)
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        BehaviorGraph {
            nodes: Vec::new(),
            edges: Vec::new(),
            pid_index: HashMap::new(),
            pending: HashMap::new(),
            ttl,
        }
    }

    pub fn add_process(&mut self, parent_pid: u32, pid: u32, name: String) {
        let child_idx = self.nodes.len();

        self.nodes.push(GraphNode::Process { pid, name });

        self.pid_index.insert(pid, child_idx);

        if let Some(&parent_idx) = self.pid_index.get(&parent_pid) {
            self.edges.push((parent_idx, child_idx, GraphEdge::Spawned));
        }

        if let Some(entries) = self.pending.remove(&pid) {
            let now = Instant::now();
            for (net_idx, inserted_at) in entries {
                if now.saturating_duration_since(inserted_at) < self.ttl {
                    self.edges
                        .push((child_idx, net_idx, GraphEdge::ConnectedTo));
                }
            }
        }
    }

    pub fn add_network_connection(
        &mut self,
        remote_ip: String,
        remote_port: u16,
        pid: Option<u32>,
    ) {
        let net_idx = self.nodes.len();
        self.nodes.push(GraphNode::Network {
            remote_ip,
            remote_port,
        });
        if let Some(p) = pid {
            if let Some(&proc_idx) = self.pid_index.get(&p) {
                self.edges.push((proc_idx, net_idx, GraphEdge::ConnectedTo));
            } else {
                let now = Instant::now();
                self.pending.retain(|_, entries| {
                    entries.retain(|(_, t)| now.saturating_duration_since(*t) < self.ttl);
                    !entries.is_empty()
                });
                self.pending.entry(p).or_default().push((net_idx, now));
            }
        }
    }

    pub fn summarize_recent_activity(&self) -> String {
        let process_count = self
            .nodes
            .iter()
            .filter(|n| matches!(n, GraphNode::Process { .. }))
            .count();

        let network_count = self
            .nodes
            .iter()
            .filter(|n| matches!(n, GraphNode::Network { .. }))
            .count();

        let spawned = self
            .edges
            .iter()
            .filter(|(_, _, e)| matches!(e, GraphEdge::Spawned))
            .count();

        let connected_to = self
            .edges
            .iter()
            .filter(|(_, _, e)| matches!(e, GraphEdge::ConnectedTo))
            .count();

        format!(
            "BehaviorGraph: {} processes, {} network connections, {} edges ({} spawned, {} connected_to)",
            process_count,
            network_count,
            self.edges.len(),
            spawned,
            connected_to
        )
    }

    pub fn process_node(&self, pid: u32) -> Option<usize> {
        self.pid_index.get(&pid).copied()
    }

    pub fn connections_of(&self, pid: u32) -> Vec<(String, u16)> {
        let Some(&proc_idx) = self.pid_index.get(&pid) else {
            return Vec::new();
        };
        self.edges
            .iter()
            .filter(|(from, _, edge)| *from == proc_idx && matches!(edge, GraphEdge::ConnectedTo))
            .filter_map(|(_, to, _)| match &self.nodes[*to] {
                GraphNode::Network {
                    remote_ip,
                    remote_port,
                } => Some((remote_ip.clone(), *remote_port)),
                _ => None,
            })
            .collect()
    }

    pub fn children_of(&self, pid: u32) -> Vec<u32> {
        let Some(&proc_idx) = self.pid_index.get(&pid) else {
            return Vec::new();
        };
        self.edges
            .iter()
            .filter(|(from, _, edge)| *from == proc_idx && matches!(edge, GraphEdge::Spawned))
            .filter_map(|(_, to, _)| match &self.nodes[*to] {
                GraphNode::Process { pid, .. } => Some(*pid),
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_insertion() {
        let mut g = BehaviorGraph::new();
        g.add_process(0, 1, "explorer.exe".to_string());
        g.add_process(1, 2, "cmd.exe".to_string());
        assert_eq!(g.nodes.len(), 2);
        assert_eq!(g.edges.len(), 1);
    }

    #[test]
    fn test_network_insertion() {
        let mut g = BehaviorGraph::new();
        g.add_network_connection("192.168.1.1".to_string(), 4444, None);
        assert_eq!(g.nodes.len(), 1);
        assert_eq!(g.edges.len(), 0);
    }

    #[test]
    fn test_process_to_network_link() {
        let mut g = BehaviorGraph::new();
        g.add_process(0, 1, "chrome.exe".to_string());
        g.add_network_connection("1.2.3.4".to_string(), 443, Some(1));
        assert_eq!(g.nodes.len(), 2);
        assert_eq!(g.edges.len(), 1);
        assert!(matches!(g.edges[0].2, GraphEdge::ConnectedTo));
    }

    #[test]
    fn test_deferred_process_to_network_link() {
        let mut g = BehaviorGraph::new();
        g.add_network_connection("1.2.3.4".to_string(), 443, Some(1));
        assert_eq!(g.edges.len(), 0);
        g.add_process(0, 1, "chrome.exe".to_string());
        assert_eq!(g.edges.len(), 1);
        assert!(matches!(g.edges[0].2, GraphEdge::ConnectedTo));
    }

    #[test]
    fn test_pending_fresh_link_connects() {
        let mut g = BehaviorGraph::new();
        g.add_network_connection("5.6.7.8".to_string(), 80, Some(2));
        g.add_process(0, 2, "curl.exe".to_string());
        assert_eq!(g.edges.len(), 1);
        assert!(matches!(g.edges[0].2, GraphEdge::ConnectedTo));
    }

    #[test]
    fn test_pending_expired_link_does_not_connect() {
        let mut g = BehaviorGraph::with_ttl(Duration::ZERO);
        g.add_network_connection("5.6.7.8".to_string(), 80, Some(2));
        g.add_process(0, 2, "curl.exe".to_string());
        assert_eq!(g.edges.len(), 0);
    }

    #[test]
    fn test_network_without_pid_is_unlinked() {
        let mut g = BehaviorGraph::new();
        g.add_process(0, 1, "chrome.exe".to_string());
        g.add_network_connection("1.2.3.4".to_string(), 443, None);
        assert_eq!(g.nodes.len(), 2);
        assert_eq!(g.edges.len(), 0);
    }
}
