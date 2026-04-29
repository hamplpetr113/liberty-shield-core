use crate::cluster_manager::LocalCluster;
use crate::cluster_types::ClusterNodeStatus;

#[derive(Debug, Clone)]
pub struct ClusterMetrics {
    pub node_count: usize,
    pub running_nodes: usize,
    pub stopped_nodes: usize,
    pub total_peers: usize,
    pub connected_peers: usize,
    pub packets_sent: u64,
    pub packets_forwarded: u64,
    pub packets_dropped: u64,
    pub cover_packets: u64,
    pub average_path_length: f64,
}

impl ClusterMetrics {
    pub fn from_cluster(cluster: &LocalCluster) -> Self {
        let snaps = cluster.snapshots();
        let running_nodes = snaps
            .iter()
            .filter(|s| s.status == ClusterNodeStatus::Running)
            .count();
        let stopped_nodes = snaps
            .iter()
            .filter(|s| s.status == ClusterNodeStatus::Stopped)
            .count();
        let total_peers: usize = snaps.iter().map(|s| s.peer_count).sum();
        let connected_peers: usize = snaps.iter().map(|s| s.connected_peer_count).sum();

        let (packets_sent, packets_forwarded, packets_dropped, cover_packets, avg) =
            if let Some(m) = cluster.sim_metrics() {
                (
                    m.packets_sent,
                    m.packets_forwarded,
                    m.packets_dropped,
                    m.cover_packets,
                    m.average_path_length(),
                )
            } else {
                (0, 0, 0, 0, 0.0)
            };

        ClusterMetrics {
            node_count: snaps.len(),
            running_nodes,
            stopped_nodes,
            total_peers,
            connected_peers,
            packets_sent,
            packets_forwarded,
            packets_dropped,
            cover_packets,
            average_path_length: avg,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_topology::{ClusterTopologyProfile, build_cluster_configs};

    fn tiny_started() -> LocalCluster {
        let mut cluster = LocalCluster::new();
        for cfg in build_cluster_configs(&ClusterTopologyProfile::Tiny) {
            cluster.add_node(cfg).unwrap();
        }
        cluster.start_all().unwrap();
        cluster
    }

    // MT1: metrics from empty cluster
    #[test]
    fn mt1_metrics_empty_cluster() {
        let cluster = LocalCluster::new();
        let m = ClusterMetrics::from_cluster(&cluster);
        assert_eq!(m.node_count, 0);
        assert_eq!(m.running_nodes, 0);
        assert_eq!(m.packets_sent, 0);
    }

    // MT2: metrics after start
    #[test]
    fn mt2_metrics_after_start() {
        let cluster = tiny_started();
        let m = ClusterMetrics::from_cluster(&cluster);
        assert_eq!(m.node_count, 5);
        assert_eq!(m.running_nodes, 5);
        assert_eq!(m.stopped_nodes, 0);
        assert_eq!(m.packets_sent, 0);
    }

    // MT3: metrics update after simulation rounds
    #[test]
    fn mt3_metrics_after_rounds() {
        let mut cluster = tiny_started();
        cluster.run_rounds(10).unwrap();
        let m = ClusterMetrics::from_cluster(&cluster);
        assert_eq!(m.packets_sent, 10);
        assert_eq!(m.packets_forwarded, 30);
        assert_eq!(m.packets_dropped, 0);
    }

    // MT4: metrics deterministic across two identical runs
    #[test]
    fn mt4_metrics_deterministic() {
        let mut c1 = tiny_started();
        let mut c2 = tiny_started();
        c1.run_rounds(5).unwrap();
        c2.run_rounds(5).unwrap();
        let m1 = ClusterMetrics::from_cluster(&c1);
        let m2 = ClusterMetrics::from_cluster(&c2);
        assert_eq!(m1.packets_sent, m2.packets_sent);
        assert_eq!(m1.packets_forwarded, m2.packets_forwarded);
    }

    // MT5: average path length is nonzero after delivering packets
    #[test]
    fn mt5_average_path_length_nonzero_after_packets() {
        let mut cluster = tiny_started();
        cluster.run_rounds(1).unwrap();
        let m = ClusterMetrics::from_cluster(&cluster);
        assert!(m.average_path_length > 0.0);
    }
}
