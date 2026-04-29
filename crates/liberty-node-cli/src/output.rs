use serde_json::{Value, json};

use crate::node_runtime::{RunResult, TopologySummary};
use crate::node_service::ServiceError;
use crate::peer_table::PeerInfo;
use crate::runtime_state::NodeRuntimeSnapshot;
use liberty_controlled_chaos::mesh_simulator::MeshMetrics;

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
