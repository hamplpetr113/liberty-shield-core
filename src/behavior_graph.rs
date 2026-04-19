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

}



impl BehaviorGraph {

    pub fn new() -> Self {

        BehaviorGraph {

            nodes: Vec::new(),

            edges: Vec::new(),

            pid_index: HashMap::new(),

        }

    }



    pub fn add_process(&mut self, parent_pid: u32, pid: u32, name: String) {

        let child_idx = self.nodes.len();

        self.nodes.push(GraphNode::Process { pid, name });

        self.pid_index.insert(pid, child_idx);

        if let Some(&parent_idx) = self.pid_index.get(&parent_pid) {

            self.edges.push((parent_idx, child_idx, GraphEdge::Spawned));

        }

    }



    pub fn add_network_connection(&mut self, remote_ip: String, remote_port: u16) {

        self.nodes.push(GraphNode::Network { remote_ip, remote_port });

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
        g.add_network_connection("192.168.1.1".to_string(), 4444);
        assert_eq!(g.nodes.len(), 1);
        assert_eq!(g.edges.len(), 0);
    }
}