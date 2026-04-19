use std::collections::HashMap;



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

    pending: HashMap<u32, Vec<usize>>,

}



impl BehaviorGraph {

    pub fn new() -> Self {

        BehaviorGraph {

            nodes: Vec::new(),

            edges: Vec::new(),

            pid_index: HashMap::new(),

            pending: HashMap::new(),

        }

    }



    pub fn add_process(&mut self, parent_pid: u32, pid: u32, name: String) {

        let child_idx = self.nodes.len();

        self.nodes.push(GraphNode::Process { pid, name });

        self.pid_index.insert(pid, child_idx);

        if let Some(&parent_idx) = self.pid_index.get(&parent_pid) {

            self.edges.push((parent_idx, child_idx, GraphEdge::Spawned));

        }

        if let Some(net_indices) = self.pending.remove(&pid) {
            for net_idx in net_indices {
                self.edges.push((child_idx, net_idx, GraphEdge::ConnectedTo));
            }
        }

    }



    pub fn add_network_connection(&mut self, remote_ip: String, remote_port: u16, pid: Option<u32>) {
        let net_idx = self.nodes.len();
        self.nodes.push(GraphNode::Network { remote_ip, remote_port });
        if let Some(p) = pid {
            if let Some(&proc_idx) = self.pid_index.get(&p) {
                self.edges.push((proc_idx, net_idx, GraphEdge::ConnectedTo));
            } else {
                self.pending.entry(p).or_default().push(net_idx);
            }
        }
    }



    pub fn summarize_recent_activity(&self) -> String {

        let process_count = self.nodes.iter()

            .filter(|n| matches!(n, GraphNode::Process { .. }))

            .count();

        let network_count = self.nodes.iter()

            .filter(|n| matches!(n, GraphNode::Network { .. }))

            .count();

        format!(

            "BehaviorGraph: {} processes, {} network connections, {} edges",
            process_count, network_count, self.edges.len()
        )
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
    fn test_network_without_pid_is_unlinked() {
        let mut g = BehaviorGraph::new();
        g.add_process(0, 1, "chrome.exe".to_string());
        g.add_network_connection("1.2.3.4".to_string(), 443, None);
        assert_eq!(g.nodes.len(), 2);
        assert_eq!(g.edges.len(), 0);
    }
}