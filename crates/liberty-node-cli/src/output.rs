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

// ── UDP testnet outputs ───────────────────────────────────────────────────────

pub fn udp_testnet_start_json(nodes: usize, base_port: u16) -> Value {
    json!({
        "command": "udp-testnet-start",
        "mode": "loopback-only",
        "nodes": nodes,
        "base_port": base_port,
        "state": "started"
    })
}

pub fn udp_testnet_probe_json(nodes: usize, packets_sent: u64, packets_received: u64) -> Value {
    json!({
        "command": "udp-testnet-probe",
        "nodes": nodes,
        "packets_sent": packets_sent,
        "packets_received": packets_received
    })
}

pub fn udp_testnet_data_json(
    nodes: usize,
    payload_len: usize,
    packets_sent: u64,
    packets_received: u64,
) -> Value {
    json!({
        "command": "udp-testnet-data",
        "nodes": nodes,
        "payload_len": payload_len,
        "packets_sent": packets_sent,
        "packets_received": packets_received
    })
}

pub fn udp_testnet_status_json(
    nodes: usize,
    snaps: &[crate::udp_testnet_node::UdpTestnetNodeSnapshot],
) -> Value {
    let snapshot_list: Vec<Value> = snaps
        .iter()
        .map(|s| {
            json!({
                "node_id": s.node_id.0,
                "local_addr": s.local_addr.to_string(),
                "packets_sent": s.packets_sent,
                "packets_received": s.packets_received,
                "packets_dropped": s.packets_dropped,
                "next_sequence": s.next_sequence
            })
        })
        .collect();
    json!({
        "command": "udp-testnet-status",
        "nodes": nodes,
        "snapshots": snapshot_list
    })
}

pub fn udp_testnet_bench_json(
    nodes: usize,
    rounds: usize,
    packets_sent: u64,
    packets_received: u64,
    elapsed_us: u64,
) -> Value {
    let throughput = (packets_sent * 1_000_000)
        .checked_div(elapsed_us)
        .unwrap_or(0);
    json!({
        "command": "udp-testnet-bench",
        "nodes": nodes,
        "rounds": rounds,
        "packets_sent": packets_sent,
        "packets_received": packets_received,
        "elapsed_us": elapsed_us,
        "throughput_packets_per_sec": throughput
    })
}

pub fn udp_testnet_error_json(msg: &str) -> Value {
    json!({ "error": msg })
}

// ── Encrypted UDP outputs ─────────────────────────────────────────────────────

pub fn encrypted_udp_start_json(nodes: usize, base_port: u16) -> Value {
    json!({
        "command": "encrypted-udp-start",
        "mode": "loopback-only",
        "nodes": nodes,
        "base_port": base_port,
        "state": "started"
    })
}

pub fn encrypted_udp_probe_json(nodes: usize, packets_sent: u64, packets_received: u64) -> Value {
    json!({
        "command": "encrypted-udp-probe",
        "nodes": nodes,
        "packets_sent": packets_sent,
        "packets_received": packets_received
    })
}

pub fn encrypted_udp_send_json(
    nodes: usize,
    payload_len: usize,
    packets_sent: u64,
    packets_received: u64,
    encrypted_cells_sent: u64,
    encrypted_cells_received: u64,
) -> Value {
    json!({
        "command": "encrypted-udp-send",
        "nodes": nodes,
        "payload_len": payload_len,
        "packets_sent": packets_sent,
        "packets_received": packets_received,
        "encrypted_cells_sent": encrypted_cells_sent,
        "encrypted_cells_received": encrypted_cells_received
    })
}

pub fn encrypted_udp_status_json(
    nodes: usize,
    snaps: &[crate::encrypted_udp_node::EncryptedUdpNodeSnapshot],
) -> Value {
    let snapshot_list: Vec<Value> = snaps
        .iter()
        .map(|s| {
            json!({
                "node_id": s.node_id.0,
                "local_addr": s.local_addr.to_string(),
                "peer_count": s.peer_count,
                "packets_sent": s.packets_sent,
                "packets_received": s.packets_received,
                "packets_dropped": s.packets_dropped,
                "encrypted_cells_sent": s.encrypted_cells_sent,
                "encrypted_cells_received": s.encrypted_cells_received
            })
        })
        .collect();
    json!({
        "command": "encrypted-udp-status",
        "nodes": nodes,
        "snapshots": snapshot_list
    })
}

pub fn encrypted_udp_bench_json(
    nodes: usize,
    rounds: usize,
    packets_sent: u64,
    packets_received: u64,
    elapsed_us: u64,
) -> Value {
    let throughput = (packets_sent * 1_000_000)
        .checked_div(elapsed_us)
        .unwrap_or(0);
    json!({
        "command": "encrypted-udp-bench",
        "nodes": nodes,
        "rounds": rounds,
        "packets_sent": packets_sent,
        "packets_received": packets_received,
        "elapsed_us": elapsed_us,
        "throughput_packets_per_sec": throughput
    })
}

pub fn encrypted_udp_error_json(msg: &str) -> Value {
    json!({ "error": msg })
}

// ── Sprint 19-23 outputs ──────────────────────────────────────────────────────

pub fn handshake_ring_json(nodes: usize, base_port: u16, sessions_established: usize) -> Value {
    json!({
        "command": "handshake-ring",
        "mode": "loopback-only",
        "nodes": nodes,
        "base_port": base_port,
        "sessions_established": sessions_established,
        "state": "established"
    })
}

pub fn circuit_run_json(rounds: usize, packets_forwarded: u64, circuits: usize) -> Value {
    json!({
        "command": "circuit-run",
        "rounds": rounds,
        "circuits": circuits,
        "packets_forwarded": packets_forwarded
    })
}

pub fn circuit_status_json(circuits_registered: usize) -> Value {
    json!({
        "command": "circuit-status",
        "circuits_registered": circuits_registered
    })
}

pub fn directory_status_json(
    node_count: usize,
    guard_count: usize,
    relay_count: usize,
    exit_count: usize,
) -> Value {
    json!({
        "command": "directory-status",
        "node_count": node_count,
        "guard_count": guard_count,
        "relay_count": relay_count,
        "exit_count": exit_count
    })
}

pub fn cover_traffic_run_json(
    node_id: u64,
    seed: u64,
    count: usize,
    packet_size: usize,
    all_correct_size: bool,
) -> Value {
    json!({
        "command": "cover-traffic-run",
        "node_id": node_id,
        "seed": seed,
        "count": count,
        "packet_size": packet_size,
        "all_correct_size": all_correct_size
    })
}

pub fn handshake_error_json(msg: &str) -> Value {
    json!({ "error": msg })
}

// ── Onion routing outputs ─────────────────────────────────────────────────────

pub fn onion_circuit_build_json(nodes: usize, hops: usize) -> Value {
    json!({
        "command": "onion-circuit-build",
        "nodes": nodes,
        "hops": hops,
        "status": "built"
    })
}

pub fn onion_send_json(nodes: usize, payload_len: usize, hops: usize, delivered: bool) -> Value {
    json!({
        "command": "onion-send",
        "nodes": nodes,
        "payload_len": payload_len,
        "hops": hops,
        "delivered": delivered
    })
}

pub fn onion_simulate_json(nodes: usize, rounds: usize, delivered: usize) -> Value {
    json!({
        "command": "onion-simulate",
        "nodes": nodes,
        "rounds": rounds,
        "delivered": delivered
    })
}

pub fn onion_error_json(msg: &str) -> Value {
    json!({ "error": msg })
}
