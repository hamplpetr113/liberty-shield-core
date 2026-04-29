use serde_json::{Value, json};

use crate::cluster_metrics::ClusterMetrics;
use crate::cluster_types::ClusterNodeSnapshot;
use crate::node_runtime::{RunResult, TopologySummary};
use crate::node_service::ServiceError;
use crate::peer_table::PeerInfo;
use crate::runtime_state::NodeRuntimeSnapshot;
use liberty_controlled_chaos::mesh_simulator::MeshMetrics;

// ── Single-node outputs ───────────────────────────────────────────────────────

pub fn metrics_json(m: &MeshMetrics, node_count: usize, circuits: usize, rounds: usize) -> Value {
    json!({
        "node_count": node_count,
        "circuits": circuits,
        "rounds": rounds,
        "metrics": {
            "packets_sent": m.packets_sent,
            "packets_forwarded": m.packets_forwarded,
            "packets_dropped": m.packets_dropped,
            "replay_rejected": m.replay_rejected,
            "cover_packets": m.cover_packets,
            "paths_completed": m.paths_completed,
            "avg_path_length": m.average_path_length()
        }
    })
}

pub fn bench_json(result: &RunResult, node_count: usize, circuits: usize) -> Value {
    let throughput = (result.rounds as u64 * 1_000_000)
        .checked_div(result.elapsed_us)
        .unwrap_or(0);
    json!({
        "node_count": node_count,
        "circuits": circuits,
        "rounds": result.rounds,
        "delivered": result.delivered,
        "dropped": result.dropped,
        "avg_path_length": result.avg_path_length,
        "elapsed_us": result.elapsed_us,
        "throughput_packets_per_sec": throughput
    })
}

pub fn topology_json(summary: &TopologySummary) -> Value {
    json!({
        "node_count": summary.node_count,
        "guard_count": summary.guard_count,
        "relay_count": summary.relay_count,
        "exit_count": summary.exit_count,
        "link_count": summary.link_count
    })
}

pub fn start_json(snap: &NodeRuntimeSnapshot) -> Value {
    json!({
        "command": "start",
        "state": snap.state.as_str(),
        "simulation_mode": snap.simulation_mode,
        "node_id": snap.node_id
    })
}

pub fn status_json(snap: &NodeRuntimeSnapshot) -> Value {
    json!({
        "command": "status",
        "state": snap.state.as_str(),
        "simulation_mode": snap.simulation_mode,
        "node_id": snap.node_id,
        "peer_count": snap.peer_count,
        "connected_peers": snap.connected_peer_count,
        "packets_simulated": snap.packets_simulated,
        "packets_forwarded": snap.packets_forwarded
    })
}

pub fn peers_json(peers: &[PeerInfo]) -> Value {
    let list: Vec<Value> = peers
        .iter()
        .map(|p| {
            json!({
                "peer_id": p.peer_id,
                "address": p.address,
                "port": p.port,
                "reliability_score": p.reliability_score,
                "latency_estimate": p.latency_estimate,
                "connected": p.connected
            })
        })
        .collect();
    json!({ "command": "peers", "peers": list })
}

pub fn service_error_json(e: &ServiceError) -> Value {
    use crate::config::ConfigError;
    use crate::peer_table::PeerTableError;
    let msg = match e {
        ServiceError::Config(ConfigError::ZeroPort) => "bind_port must be > 0",
        ServiceError::Config(ConfigError::ZeroMaxPeers) => "max_peers must be > 0",
        ServiceError::Config(ConfigError::RealUdpWithSimulationMode) => {
            "allow_real_udp cannot be true when simulation_mode is true"
        }
        ServiceError::PeerTable(PeerTableError::DuplicatePeer) => "duplicate peer",
        ServiceError::PeerTable(PeerTableError::PeerNotFound) => "peer not found",
        ServiceError::PeerTable(PeerTableError::TableFull) => "peer table full",
        ServiceError::NotStarted => "service is not running",
        ServiceError::AlreadyRunning => "service is already running",
        ServiceError::RealUdpNotAllowed => "real UDP is not allowed in this build",
    };
    json!({ "error": msg })
}

// ── Cluster outputs ───────────────────────────────────────────────────────────

pub fn cluster_start_json(profile: &str, node_count: usize) -> Value {
    json!({
        "command": "cluster-start",
        "profile": profile,
        "nodes": node_count,
        "state": "Running"
    })
}

pub fn cluster_status_json(profile: &str, snaps: &[ClusterNodeSnapshot]) -> Value {
    let node_list: Vec<Value> = snaps
        .iter()
        .map(|s| {
            json!({
                "node_id": s.node_id.0,
                "role": s.role.as_str(),
                "status": s.status.as_str(),
                "peer_count": s.peer_count,
                "packets_simulated": s.packets_simulated
            })
        })
        .collect();
    json!({
        "command": "cluster-status",
        "profile": profile,
        "nodes": snaps.len(),
        "node_list": node_list
    })
}

pub fn cluster_run_json(
    profile: &str,
    rounds: usize,
    packets_sent: u64,
    packets_forwarded: u64,
) -> Value {
    json!({
        "command": "cluster-run",
        "profile": profile,
        "rounds": rounds,
        "packets_sent": packets_sent,
        "packets_forwarded": packets_forwarded
    })
}

pub fn cluster_topology_json(
    profile: &str,
    clients: usize,
    guards: usize,
    relays: usize,
    exits: usize,
) -> Value {
    json!({
        "command": "cluster-topology",
        "profile": profile,
        "clients": clients,
        "guards": guards,
        "relays": relays,
        "exits": exits
    })
}

pub fn cluster_peers_json(profile: &str, snaps: &[ClusterNodeSnapshot]) -> Value {
    let node_list: Vec<Value> = snaps
        .iter()
        .map(|s| {
            json!({
                "node_id": s.node_id.0,
                "role": s.role.as_str(),
                "peer_count": s.peer_count
            })
        })
        .collect();
    json!({
        "command": "cluster-peers",
        "profile": profile,
        "nodes": node_list
    })
}

pub fn cluster_metrics_json(m: &ClusterMetrics) -> Value {
    json!({
        "node_count": m.node_count,
        "running_nodes": m.running_nodes,
        "stopped_nodes": m.stopped_nodes,
        "total_peers": m.total_peers,
        "connected_peers": m.connected_peers,
        "packets_sent": m.packets_sent,
        "packets_forwarded": m.packets_forwarded,
        "packets_dropped": m.packets_dropped,
        "cover_packets": m.cover_packets,
        "average_path_length": m.average_path_length
    })
}

pub fn cluster_bench_json(
    profile: &str,
    rounds: usize,
    packets_sent: u64,
    packets_forwarded: u64,
    elapsed_us: u64,
) -> Value {
    let throughput = (packets_sent * 1_000_000)
        .checked_div(elapsed_us)
        .unwrap_or(0);
    json!({
        "command": "cluster-bench",
        "profile": profile,
        "rounds": rounds,
        "packets_sent": packets_sent,
        "packets_forwarded": packets_forwarded,
        "elapsed_us": elapsed_us,
        "throughput_packets_per_sec": throughput
    })
}

pub fn cluster_error_json(msg: &str) -> Value {
    json!({ "error": msg })
}
