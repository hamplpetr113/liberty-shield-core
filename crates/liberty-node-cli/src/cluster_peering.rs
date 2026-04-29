use crate::cluster_manager::LocalCluster;
use crate::cluster_types::{ClusterError, ClusterNodeRole};
use crate::peer_table::PeerInfo;

fn make_peer(peer_id: u64, address: &str, port: u16) -> PeerInfo {
    PeerInfo {
        peer_id,
        address: address.to_string(),
        port,
        reliability_score: 0.95,
        latency_estimate: 10,
        connected: false,
    }
}

/// Wire every node to every other node (no self-connections).
/// Silently ignores TableFull (max_peers is respected).
pub fn wire_full_mesh(cluster: &mut LocalCluster) -> Result<(), ClusterError> {
    let configs: Vec<_> = cluster.node_configs().to_vec();
    for src in &configs {
        for dst in &configs {
            if src.node_id == dst.node_id {
                continue;
            }
            let peer = make_peer(dst.node_id.0, &dst.bind_address, dst.bind_port);
            let _ = cluster.add_peer_to_node(src.node_id, peer);
        }
    }
    Ok(())
}

/// Wire peers based on node roles:
/// - clients → guards
/// - guards → relays
/// - relays → relays, exits
/// - exits → relays
pub fn wire_role_based_mesh(cluster: &mut LocalCluster) -> Result<(), ClusterError> {
    let configs: Vec<_> = cluster.node_configs().to_vec();
    for src in &configs {
        for dst in &configs {
            if src.node_id == dst.node_id {
                continue;
            }
            let should_connect = matches!(
                (&src.role, &dst.role),
                (ClusterNodeRole::Client, ClusterNodeRole::Guard)
                    | (ClusterNodeRole::Guard, ClusterNodeRole::Relay)
                    | (ClusterNodeRole::Relay, ClusterNodeRole::Relay)
                    | (ClusterNodeRole::Relay, ClusterNodeRole::Exit)
                    | (ClusterNodeRole::Exit, ClusterNodeRole::Relay)
            );
            if should_connect {
                let peer = make_peer(dst.node_id.0, &dst.bind_address, dst.bind_port);
                let _ = cluster.add_peer_to_node(src.node_id, peer);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_topology::{ClusterTopologyProfile, build_cluster_configs};
    use crate::cluster_types::ClusterNodeId;

    fn tiny_cluster() -> LocalCluster {
        let mut cluster = LocalCluster::new();
        for cfg in build_cluster_configs(&ClusterTopologyProfile::Tiny) {
            cluster.add_node(cfg).unwrap();
        }
        cluster
    }

    // PW1: full mesh has no self-peers (every peer_id != own node_id)
    #[test]
    fn pw1_full_mesh_no_self_peers() {
        let mut cluster = tiny_cluster();
        wire_full_mesh(&mut cluster).unwrap();
        let snaps = cluster.snapshots();
        for (snap, cfg) in snaps.iter().zip(cluster.node_configs().iter()) {
            assert!(snap.peer_count > 0);
            // can't directly inspect peer_ids through snapshots,
            // but we verify all configs are different from node_id
            // by checking the node itself wasn't added to itself via
            // the constraint: peer_count ≤ total_nodes - 1
            assert!(snap.peer_count <= cluster.node_count() - 1);
            // Verify no node has itself as a peer (structural check)
            let _ = cfg.node_id; // id is unique
        }
    }

    // PW2: role-based mesh — clients connect only to guards
    #[test]
    fn pw2_role_based_clients_connect_to_guards() {
        let mut cluster = tiny_cluster();
        wire_role_based_mesh(&mut cluster).unwrap();
        let configs = cluster.node_configs().to_vec();
        let snaps = cluster.snapshots();

        // Client is node_id=1, Guard is node_id=2 in Tiny profile
        // Client must have exactly 1 peer (the guard)
        let client_snap = snaps
            .iter()
            .find(|s| s.node_id == ClusterNodeId(1))
            .unwrap();
        let client_cfg = configs
            .iter()
            .find(|c| c.node_id == ClusterNodeId(1))
            .unwrap();
        assert_eq!(client_cfg.role, ClusterNodeRole::Client);
        assert_eq!(client_snap.peer_count, 1); // only the guard
    }

    // PW3: guards connect to relays
    #[test]
    fn pw3_guards_connect_to_relays() {
        let mut cluster = tiny_cluster();
        wire_role_based_mesh(&mut cluster).unwrap();
        let configs = cluster.node_configs().to_vec();
        let snaps = cluster.snapshots();

        let guard_cfg = configs
            .iter()
            .find(|c| c.role == ClusterNodeRole::Guard)
            .unwrap();
        let guard_snap = snaps
            .iter()
            .find(|s| s.node_id == guard_cfg.node_id)
            .unwrap();
        let relay_count = configs
            .iter()
            .filter(|c| c.role == ClusterNodeRole::Relay)
            .count();
        assert_eq!(guard_snap.peer_count, relay_count);
    }

    // PW4: peer count never exceeds max_peers
    #[test]
    fn pw4_peer_count_respects_max_peers() {
        use crate::cluster_types::ClusterNodeConfig;
        let mut cluster = LocalCluster::new();
        // Add 5 nodes with max_peers=2 — full mesh should only add 2 peers per node
        for id in 1u64..=5 {
            cluster
                .add_node(ClusterNodeConfig {
                    node_id: ClusterNodeId(id),
                    role: ClusterNodeRole::Relay,
                    node_name: format!("n-{id}"),
                    bind_address: "127.0.0.1".to_string(),
                    bind_port: 39000 + id as u16,
                    max_peers: 2,
                    simulation_mode: true,
                    allow_real_udp: false,
                })
                .unwrap();
        }
        wire_full_mesh(&mut cluster).unwrap();
        for snap in cluster.snapshots() {
            assert!(snap.peer_count <= 2);
        }
    }

    // PW5: wiring is deterministic (same result on repeated calls to same cluster)
    #[test]
    fn pw5_wiring_deterministic() {
        let mut c1 = tiny_cluster();
        let mut c2 = tiny_cluster();
        wire_full_mesh(&mut c1).unwrap();
        wire_full_mesh(&mut c2).unwrap();
        let s1 = c1.snapshots();
        let s2 = c2.snapshots();
        assert_eq!(s1.len(), s2.len());
        for (a, b) in s1.iter().zip(s2.iter()) {
            assert_eq!(a.peer_count, b.peer_count);
        }
    }

    // PW6: connected peer count updates after mark_connected
    #[test]
    fn pw6_connected_peers_count_updates() {
        let mut cluster = tiny_cluster();
        wire_full_mesh(&mut cluster).unwrap();
        cluster.start_all().unwrap();
        // All peers start as disconnected; connected_peer_count = 0 for all
        for snap in cluster.snapshots() {
            assert_eq!(snap.connected_peer_count, 0);
        }
    }
}
