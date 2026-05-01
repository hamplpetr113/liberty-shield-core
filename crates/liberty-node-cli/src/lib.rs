pub mod adversarial_simulator;
pub mod args;
pub mod circuit_builder;
pub mod circuit_extend_protocol;
pub mod circuit_extend_state;
pub mod cluster_manager;
pub mod cluster_metrics;
pub mod cluster_packet_flow;
pub mod cluster_peering;
pub mod cluster_topology;
pub mod cluster_types;
pub mod config;
pub mod cover_traffic_engine;
pub mod directory_consensus;
pub mod encrypted_cell_fixture;
pub mod encrypted_circuit_path;
pub mod encrypted_circuit_runtime;
pub mod encrypted_peer_session;
pub mod encrypted_udp_cluster;
pub mod encrypted_udp_node;
pub mod encrypted_udp_packet;
pub mod encrypted_udp_socket;
pub mod encrypted_udp_types;
pub mod guard_selection;
pub mod handshake_manager;
pub mod handshake_message;
pub mod handshake_state;
pub mod handshake_types;
pub mod identity;
pub mod node_runtime;
pub mod node_service;
pub mod onion_crypto;
pub mod onion_packet;
pub mod onion_router;
pub mod output;
pub mod path_selection;
pub mod peer_directory;
pub mod peer_table;
pub mod relay_cell;
pub mod relay_cell_codec;
pub mod runtime_state;
pub mod traffic_scheduler;
pub mod udp_loopback_socket;
pub mod udp_testnet_cluster;
pub mod udp_testnet_node;
pub mod udp_testnet_packet;
pub mod udp_testnet_types;

use adversarial_simulator::{
    run_packet_size_observation, run_replay_attempt, run_route_guessing, run_timing_observation,
};
use args::{Command, parse_args};
use circuit_builder::CircuitBuilder;
use circuit_extend_protocol::CircuitExtendProtocol;
use cluster_manager::LocalCluster;
use cluster_topology::{build_cluster_configs, parse_profile};
use config::NodeConfig;
use cover_traffic_engine::CoverTrafficEngine;
use directory_consensus::{DirectoryAuthorityId, build_deterministic_consensus};
use encrypted_circuit_path::EncryptedCircuitPath;
use encrypted_circuit_runtime::EncryptedCircuitRuntime;
use encrypted_udp_cluster::EncryptedUdpCluster;
use encrypted_udp_types::EncryptedUdpNodeId;
use node_runtime::NodeRuntime;
use node_service::NodeService;
use onion_router::OnionRouter;
use output::{
    adversarial_sim_json, bench_json, circuit_extend_test_json, circuit_run_json,
    circuit_status_json, cluster_bench_json, cluster_error_json, cluster_peers_json,
    cluster_run_json, cluster_start_json, cluster_status_json, cluster_topology_json,
    cover_traffic_run_json, directory_consensus_json, directory_status_json,
    encrypted_udp_bench_json, encrypted_udp_error_json, encrypted_udp_probe_json,
    encrypted_udp_send_json, encrypted_udp_start_json, encrypted_udp_status_json,
    handshake_error_json, handshake_ring_json, metrics_json, onion_circuit_build_json,
    onion_error_json, onion_send_json, onion_simulate_json, path_select_json, peers_json,
    relay_cell_test_json, service_error_json, sprint25_30_error_json, start_json, status_json,
    topology_json, traffic_schedule_json, udp_testnet_bench_json, udp_testnet_data_json,
    udp_testnet_error_json, udp_testnet_probe_json, udp_testnet_start_json,
    udp_testnet_status_json,
};
use path_selection::{PathSelectionPolicy, PathSelector};
use peer_directory::{PeerDescriptor, PeerDirectory, PeerRole};
use relay_cell::{RelayCell, RelayCommand};
use relay_cell_codec::{decode_relay_cell, encode_relay_cell};
use traffic_scheduler::{SchedulerPolicy, TrafficScheduler};
use udp_testnet_cluster::UdpTestnetCluster;

pub fn run_cli(args: &[String]) -> String {
    match parse_args(args) {
        Ok(cli_args) => execute(cli_args.command),
        Err(e) => serde_json::json!({ "error": e }).to_string(),
    }
}

fn execute(cmd: Command) -> String {
    match cmd {
        // ── Single-node commands ──────────────────────────────────────────────
        Command::Start => {
            let config = NodeConfig::default();
            match NodeService::new(config) {
                Ok(mut svc) => {
                    svc.bootstrap_simulation(100, 5);
                    match svc.start() {
                        Ok(()) => start_json(&svc.snapshot()).to_string(),
                        Err(e) => service_error_json(&e).to_string(),
                    }
                }
                Err(e) => service_error_json(&e).to_string(),
            }
        }
        Command::Status => {
            let config = NodeConfig::default();
            match NodeService::new(config) {
                Ok(svc) => status_json(&svc.snapshot()).to_string(),
                Err(e) => service_error_json(&e).to_string(),
            }
        }
        Command::Peers => {
            let config = NodeConfig::default();
            match NodeService::new(config) {
                Ok(svc) => peers_json(svc.peers()).to_string(),
                Err(e) => service_error_json(&e).to_string(),
            }
        }

        // ── Cluster commands ──────────────────────────────────────────────────
        Command::ClusterStart { profile } => {
            let Some(prof) = parse_profile(&profile) else {
                return cluster_error_json(&format!("unknown profile: {profile}")).to_string();
            };
            let configs = build_cluster_configs(&prof);
            let node_count = configs.len();
            let mut cluster = LocalCluster::new();
            for cfg in configs {
                if cluster.add_node(cfg).is_err() {
                    return cluster_error_json("failed to build cluster").to_string();
                }
            }
            match cluster.start_all() {
                Ok(()) => cluster_start_json(&profile, node_count).to_string(),
                Err(e) => cluster_error_json(&format!("{e:?}")).to_string(),
            }
        }
        Command::ClusterStatus { profile } => {
            let Some(prof) = parse_profile(&profile) else {
                return cluster_error_json(&format!("unknown profile: {profile}")).to_string();
            };
            let configs = build_cluster_configs(&prof);
            let mut cluster = LocalCluster::new();
            for cfg in configs {
                let _ = cluster.add_node(cfg);
            }
            let snaps = cluster.snapshots();
            cluster_status_json(&profile, &snaps).to_string()
        }
        Command::ClusterRun { profile, rounds } => {
            let Some(prof) = parse_profile(&profile) else {
                return cluster_error_json(&format!("unknown profile: {profile}")).to_string();
            };
            let configs = build_cluster_configs(&prof);
            let mut cluster = LocalCluster::new();
            for cfg in configs {
                let _ = cluster.add_node(cfg);
            }
            if cluster.start_all().is_err() {
                return cluster_error_json("failed to start cluster").to_string();
            }
            if cluster.run_rounds(rounds).is_err() {
                return cluster_error_json("simulation failed").to_string();
            }
            let (sent, forwarded) = cluster
                .sim_metrics()
                .map(|m| (m.packets_sent, m.packets_forwarded))
                .unwrap_or((0, 0));
            cluster_run_json(&profile, rounds, sent, forwarded).to_string()
        }
        Command::ClusterTopology { profile } => {
            let Some(prof) = parse_profile(&profile) else {
                return cluster_error_json(&format!("unknown profile: {profile}")).to_string();
            };
            let (clients, guards, relays, exits) = prof.role_counts();
            cluster_topology_json(&profile, clients, guards, relays, exits).to_string()
        }
        Command::ClusterPeers { profile } => {
            let Some(prof) = parse_profile(&profile) else {
                return cluster_error_json(&format!("unknown profile: {profile}")).to_string();
            };
            let configs = build_cluster_configs(&prof);
            let mut cluster = LocalCluster::new();
            for cfg in configs {
                let _ = cluster.add_node(cfg);
            }
            let snaps = cluster.snapshots();
            cluster_peers_json(&profile, &snaps).to_string()
        }
        Command::ClusterBench { profile, rounds } => {
            let Some(prof) = parse_profile(&profile) else {
                return cluster_error_json(&format!("unknown profile: {profile}")).to_string();
            };
            let configs = build_cluster_configs(&prof);
            let mut cluster = LocalCluster::new();
            for cfg in configs {
                let _ = cluster.add_node(cfg);
            }
            if cluster.start_all().is_err() {
                return cluster_error_json("failed to start cluster").to_string();
            }
            let t0 = std::time::Instant::now();
            if cluster.run_rounds(rounds).is_err() {
                return cluster_error_json("simulation failed").to_string();
            }
            let elapsed_us = t0.elapsed().as_micros() as u64;
            let (sent, forwarded) = cluster
                .sim_metrics()
                .map(|m| (m.packets_sent, m.packets_forwarded))
                .unwrap_or((0, 0));
            cluster_bench_json(&profile, rounds, sent, forwarded, elapsed_us).to_string()
        }

        // ── UDP testnet commands ──────────────────────────────────────────────
        Command::UdpTestnetStart { nodes, base_port } => {
            if nodes == 0 {
                return udp_testnet_error_json("nodes must be > 0").to_string();
            }
            match UdpTestnetCluster::start_loopback_cluster(nodes, base_port) {
                Ok(_) => udp_testnet_start_json(nodes, base_port).to_string(),
                Err(e) => udp_testnet_error_json(&format!("{e:?}")).to_string(),
            }
        }
        Command::UdpTestnetProbe { nodes, base_port } => {
            if nodes == 0 {
                return udp_testnet_error_json("nodes must be > 0").to_string();
            }
            let mut cluster = match UdpTestnetCluster::start_loopback_cluster(nodes, base_port) {
                Ok(c) => c,
                Err(e) => return udp_testnet_error_json(&format!("{e:?}")).to_string(),
            };
            if let Err(e) = cluster.send_probe_ring() {
                return udp_testnet_error_json(&format!("{e:?}")).to_string();
            }
            let mut total_received: u64 = 0;
            for _ in 0..200 {
                total_received += cluster.poll_all() as u64;
                if total_received >= nodes as u64 {
                    break;
                }
            }
            let total_sent: u64 = cluster.snapshots().iter().map(|s| s.packets_sent).sum();
            udp_testnet_probe_json(nodes, total_sent, total_received).to_string()
        }
        Command::UdpTestnetData {
            nodes,
            base_port,
            payload,
        } => {
            if nodes == 0 {
                return udp_testnet_error_json("nodes must be > 0").to_string();
            }
            let payload_bytes = payload.as_bytes();
            let payload_len = payload_bytes.len();
            let mut cluster = match UdpTestnetCluster::start_loopback_cluster(nodes, base_port) {
                Ok(c) => c,
                Err(e) => return udp_testnet_error_json(&format!("{e:?}")).to_string(),
            };
            if let Err(e) = cluster.send_data_round(payload_bytes) {
                return udp_testnet_error_json(&format!("{e:?}")).to_string();
            }
            let mut total_received: u64 = 0;
            for _ in 0..200 {
                total_received += cluster.poll_all() as u64;
                if total_received >= nodes as u64 {
                    break;
                }
            }
            let total_sent: u64 = cluster.snapshots().iter().map(|s| s.packets_sent).sum();
            udp_testnet_data_json(nodes, payload_len, total_sent, total_received).to_string()
        }
        Command::UdpTestnetStatus { nodes, base_port } => {
            if nodes == 0 {
                return udp_testnet_error_json("nodes must be > 0").to_string();
            }
            match UdpTestnetCluster::start_loopback_cluster(nodes, base_port) {
                Ok(cluster) => {
                    let snaps = cluster.snapshots();
                    udp_testnet_status_json(nodes, &snaps).to_string()
                }
                Err(e) => udp_testnet_error_json(&format!("{e:?}")).to_string(),
            }
        }
        Command::UdpTestnetBench {
            nodes,
            base_port,
            rounds,
        } => {
            if nodes == 0 {
                return udp_testnet_error_json("nodes must be > 0").to_string();
            }
            let mut cluster = match UdpTestnetCluster::start_loopback_cluster(nodes, base_port) {
                Ok(c) => c,
                Err(e) => return udp_testnet_error_json(&format!("{e:?}")).to_string(),
            };
            let t0 = std::time::Instant::now();
            let mut total_sent: u64 = 0;
            let mut total_received: u64 = 0;
            for _ in 0..rounds {
                if cluster.send_probe_ring().is_err() {
                    break;
                }
                total_sent += nodes as u64;
                total_received += cluster.poll_all() as u64;
            }
            let elapsed_us = t0.elapsed().as_micros() as u64;
            udp_testnet_bench_json(nodes, rounds, total_sent, total_received, elapsed_us)
                .to_string()
        }

        // ── Encrypted UDP commands ────────────────────────────────────────────
        Command::EncryptedUdpStart { nodes, base_port } => {
            if nodes == 0 {
                return encrypted_udp_error_json("nodes must be > 0").to_string();
            }
            match EncryptedUdpCluster::start_loopback_cluster(nodes, base_port) {
                Ok(_) => encrypted_udp_start_json(nodes, base_port).to_string(),
                Err(e) => encrypted_udp_error_json(&format!("{e:?}")).to_string(),
            }
        }
        Command::EncryptedUdpProbe { nodes, base_port } => {
            if nodes == 0 {
                return encrypted_udp_error_json("nodes must be > 0").to_string();
            }
            let mut cluster = match EncryptedUdpCluster::start_loopback_cluster(nodes, base_port) {
                Ok(c) => c,
                Err(e) => return encrypted_udp_error_json(&format!("{e:?}")).to_string(),
            };
            cluster.wire_deterministic_sessions();
            if cluster.send_encrypted_ring(&[0u8; 64]).is_err() {
                return encrypted_udp_error_json("send failed").to_string();
            }
            let mut total_received: u64 = 0;
            for _ in 0..200 {
                total_received += cluster.poll_all() as u64;
                if total_received >= nodes as u64 {
                    break;
                }
            }
            let total_sent: u64 = cluster.snapshots().iter().map(|s| s.packets_sent).sum();
            encrypted_udp_probe_json(nodes, total_sent, total_received).to_string()
        }
        Command::EncryptedUdpSend {
            nodes,
            base_port,
            payload,
        } => {
            if nodes == 0 {
                return encrypted_udp_error_json("nodes must be > 0").to_string();
            }
            let payload_bytes = payload.as_bytes();
            let payload_len = payload_bytes.len();
            let mut cluster = match EncryptedUdpCluster::start_loopback_cluster(nodes, base_port) {
                Ok(c) => c,
                Err(e) => return encrypted_udp_error_json(&format!("{e:?}")).to_string(),
            };
            cluster.wire_deterministic_sessions();
            if cluster.send_encrypted_ring(payload_bytes).is_err() {
                return encrypted_udp_error_json("send failed").to_string();
            }
            let mut total_received: u64 = 0;
            for _ in 0..200 {
                total_received += cluster.poll_all() as u64;
                if total_received >= nodes as u64 {
                    break;
                }
            }
            let snaps = cluster.snapshots();
            let total_sent: u64 = snaps.iter().map(|s| s.packets_sent).sum();
            let cells_sent: u64 = snaps.iter().map(|s| s.encrypted_cells_sent).sum();
            let cells_recv: u64 = snaps.iter().map(|s| s.encrypted_cells_received).sum();
            encrypted_udp_send_json(
                nodes,
                payload_len,
                total_sent,
                total_received,
                cells_sent,
                cells_recv,
            )
            .to_string()
        }
        Command::EncryptedUdpStatus { nodes, base_port } => {
            if nodes == 0 {
                return encrypted_udp_error_json("nodes must be > 0").to_string();
            }
            match EncryptedUdpCluster::start_loopback_cluster(nodes, base_port) {
                Ok(cluster) => {
                    let snaps = cluster.snapshots();
                    encrypted_udp_status_json(nodes, &snaps).to_string()
                }
                Err(e) => encrypted_udp_error_json(&format!("{e:?}")).to_string(),
            }
        }
        Command::EncryptedUdpBench {
            nodes,
            base_port,
            rounds,
        } => {
            if nodes == 0 {
                return encrypted_udp_error_json("nodes must be > 0").to_string();
            }
            let mut cluster = match EncryptedUdpCluster::start_loopback_cluster(nodes, base_port) {
                Ok(c) => c,
                Err(e) => return encrypted_udp_error_json(&format!("{e:?}")).to_string(),
            };
            cluster.wire_deterministic_sessions();
            let t0 = std::time::Instant::now();
            let mut total_sent: u64 = 0;
            let mut total_received: u64 = 0;
            for _ in 0..rounds {
                if cluster.send_encrypted_ring(&[0u8; 64]).is_err() {
                    break;
                }
                total_sent += nodes as u64;
                total_received += cluster.poll_all() as u64;
            }
            let elapsed_us = t0.elapsed().as_micros() as u64;
            encrypted_udp_bench_json(nodes, rounds, total_sent, total_received, elapsed_us)
                .to_string()
        }

        // ── Sprint 19-23 commands ─────────────────────────────────────────────
        Command::HandshakeRing { nodes, base_port } => {
            if nodes < 2 {
                return handshake_error_json("nodes must be >= 2").to_string();
            }
            let mut cluster = match EncryptedUdpCluster::start_loopback_cluster(nodes, base_port) {
                Ok(c) => c,
                Err(e) => return handshake_error_json(&format!("{e:?}")).to_string(),
            };
            if let Err(e) = cluster.handshake_ring() {
                return handshake_error_json(&format!("{e:?}")).to_string();
            }
            let sessions_established = cluster
                .snapshots()
                .iter()
                .map(|s| s.peer_count)
                .sum::<usize>();
            handshake_ring_json(nodes, base_port, sessions_established).to_string()
        }
        Command::CircuitRun {
            nodes,
            base_port: _,
            rounds,
        } => {
            if nodes < 3 {
                return handshake_error_json("nodes must be >= 3 for a circuit").to_string();
            }
            let mut rt = EncryptedCircuitRuntime::new();
            let hops: Vec<EncryptedUdpNodeId> =
                (1..=nodes as u64).map(EncryptedUdpNodeId).collect();
            if let Err(e) =
                EncryptedCircuitPath::new(1, hops, 1000).and_then(|path| rt.register_circuit(path))
            {
                return handshake_error_json(&format!("{e:?}")).to_string();
            }
            let mut packets_forwarded: u64 = 0;
            for r in 0..rounds as u64 {
                let payload = r.to_le_bytes().to_vec();
                let mut pkt = match rt.send_on_circuit(1, &payload) {
                    Ok(p) => p,
                    Err(_) => break,
                };
                loop {
                    match rt.forward_next(pkt) {
                        Ok(Some(next)) => {
                            packets_forwarded += 1;
                            pkt = next;
                        }
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            }
            circuit_run_json(rounds, packets_forwarded, 1).to_string()
        }
        Command::CircuitStatus {
            nodes,
            base_port: _,
        } => {
            let mut rt = EncryptedCircuitRuntime::new();
            // Register one circuit per valid hop count
            for cid in 1..=(nodes.max(3) as u64) {
                let hops: Vec<EncryptedUdpNodeId> =
                    (1..=3).map(|h| EncryptedUdpNodeId(h * cid)).collect();
                if let Ok(path) = EncryptedCircuitPath::new(cid, hops, 100) {
                    let _ = rt.register_circuit(path);
                }
            }
            circuit_status_json(rt.circuit_count()).to_string()
        }
        Command::DirectoryStatus { node_count } => {
            let mut dir = PeerDirectory::new();
            for id in 1..=node_count as u64 {
                let desc = PeerDescriptor::deterministic(id, 45000);
                let _ = dir.register_node(desc);
            }
            let list = dir.list_nodes();
            let guard_count = list.iter().filter(|d| d.role == PeerRole::Guard).count();
            let relay_count = list.iter().filter(|d| d.role == PeerRole::Relay).count();
            let exit_count = list.iter().filter(|d| d.role == PeerRole::Exit).count();
            directory_status_json(node_count, guard_count, relay_count, exit_count).to_string()
        }
        Command::CoverTrafficRun {
            node_id,
            seed,
            count,
        } => {
            use liberty_controlled_chaos::noise_link::ENCRYPTED_CELL_SIZE;
            let mut engine = CoverTrafficEngine::new(node_id, seed);
            let mut all_correct = true;
            for _ in 0..count {
                let pkt = engine.generate_cover_packet();
                if pkt.bytes.len() != ENCRYPTED_CELL_SIZE {
                    all_correct = false;
                }
            }
            cover_traffic_run_json(node_id, seed, count, ENCRYPTED_CELL_SIZE, all_correct)
                .to_string()
        }

        // ── Onion routing commands ────────────────────────────────────────────
        Command::OnionCircuitBuild { nodes } => {
            if nodes < 3 {
                return onion_error_json("nodes must be >= 3").to_string();
            }
            let peers: Vec<_> = (1..=nodes as u64)
                .map(|id| PeerDescriptor::deterministic(id, 45000))
                .collect();
            match CircuitBuilder::build_circuit(&peers) {
                Ok(circuit) => onion_circuit_build_json(nodes, circuit.hop_count()).to_string(),
                Err(e) => onion_error_json(&format!("{e:?}")).to_string(),
            }
        }
        Command::OnionSend { nodes, payload } => {
            if nodes < 3 {
                return onion_error_json("nodes must be >= 3").to_string();
            }
            let peers: Vec<_> = (1..=nodes as u64)
                .map(|id| PeerDescriptor::deterministic(id, 45000))
                .collect();
            let circuit = match CircuitBuilder::build_circuit(&peers) {
                Ok(c) => c,
                Err(e) => return onion_error_json(&format!("{e:?}")).to_string(),
            };
            let hop_ids: Vec<u64> = circuit.hops.iter().map(|id| id.0).collect();
            let hops = hop_ids.len();
            let mut router = OnionRouter::new();
            if let Err(e) = router.register_circuit(1, hop_ids) {
                return onion_error_json(&format!("{e:?}")).to_string();
            }
            let pkt = match router.build_packet(1, payload.as_bytes()) {
                Ok(p) => p,
                Err(e) => return onion_error_json(&format!("{e:?}")).to_string(),
            };
            let mut current = pkt;
            let delivered = loop {
                match router.process_packet(current) {
                    Ok(onion_router::ProcessResult::Forward(next)) => current = next,
                    Ok(onion_router::ProcessResult::Delivered(_)) => break true,
                    Err(e) => return onion_error_json(&format!("{e:?}")).to_string(),
                }
            };
            onion_send_json(nodes, payload.len(), hops, delivered).to_string()
        }
        Command::OnionSimulate { nodes, rounds } => {
            if nodes < 3 {
                return onion_error_json("nodes must be >= 3").to_string();
            }
            let peers: Vec<_> = (1..=nodes as u64)
                .map(|id| PeerDescriptor::deterministic(id, 45000))
                .collect();
            let circuit = match CircuitBuilder::build_circuit(&peers) {
                Ok(c) => c,
                Err(e) => return onion_error_json(&format!("{e:?}")).to_string(),
            };
            let hop_ids: Vec<u64> = circuit.hops.iter().map(|id| id.0).collect();
            let mut router = OnionRouter::new();
            if let Err(e) = router.register_circuit(1, hop_ids) {
                return onion_error_json(&format!("{e:?}")).to_string();
            }
            let mut delivered_count = 0usize;
            for r in 0..rounds {
                let payload = format!("round-{r}");
                let pkt = match router.build_packet(1, payload.as_bytes()) {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let mut current = pkt;
                loop {
                    match router.process_packet(current) {
                        Ok(onion_router::ProcessResult::Forward(next)) => current = next,
                        Ok(onion_router::ProcessResult::Delivered(_)) => {
                            delivered_count += 1;
                            break;
                        }
                        Err(_) => break,
                    }
                }
            }
            onion_simulate_json(nodes, rounds, delivered_count).to_string()
        }

        // ── Simulation commands ───────────────────────────────────────────────
        Command::Run {
            node_count,
            circuits,
            rounds,
        } => {
            let mut rt = NodeRuntime::new(node_count);
            rt.build_circuits(circuits);
            rt.run_rounds(rounds);
            metrics_json(rt.metrics(), node_count, circuits, rounds).to_string()
        }
        Command::Topology { node_count } => {
            let rt = NodeRuntime::new(node_count);
            topology_json(&rt.topology_summary()).to_string()
        }
        Command::Bench {
            node_count,
            circuits,
            rounds,
        } => {
            let mut rt = NodeRuntime::new(node_count);
            rt.build_circuits(circuits);
            let result = rt.run_rounds(rounds);
            bench_json(&result, node_count, circuits).to_string()
        }

        // ── Sprint 25-30 commands ─────────────────────────────────────────────
        Command::RelayCellTest { payload } => {
            let cell = RelayCell::new(
                1,
                1,
                RelayCommand::RelayData,
                0,
                payload.as_bytes().to_vec(),
            );
            match encode_relay_cell(&cell) {
                Ok(encoded) => match decode_relay_cell(&encoded) {
                    Ok(decoded) => {
                        relay_cell_test_json(payload.len(), decoded == cell, "RelayData")
                            .to_string()
                    }
                    Err(e) => sprint25_30_error_json(&format!("{e:?}")).to_string(),
                },
                Err(e) => sprint25_30_error_json(&format!("{e:?}")).to_string(),
            }
        }
        Command::CircuitExtendTest { hops } => {
            if hops < 3 {
                return sprint25_30_error_json("hops must be >= 3").to_string();
            }
            let mut proto = CircuitExtendProtocol::new(1, 10);
            for hop in 1..hops as u64 {
                let target = 20 + hop;
                let next = target;
                if proto.begin_extend(target, next).is_err() {
                    return sprint25_30_error_json("extend failed").to_string();
                }
                if proto
                    .handle_extend_response(&circuit_extend_protocol::make_ok_response(hop))
                    .is_err()
                {
                    return sprint25_30_error_json("response failed").to_string();
                }
            }
            circuit_extend_test_json(proto.state.hop_count(), proto.is_ready()).to_string()
        }
        Command::PathSelect { nodes } => {
            if nodes < 3 {
                return sprint25_30_error_json("nodes must be >= 3").to_string();
            }
            let peers: Vec<_> = (1..=nodes as u64)
                .map(|id| PeerDescriptor::deterministic(id, 45000))
                .collect();
            let sel = PathSelector::new(&peers, PathSelectionPolicy::default());
            match sel.select_path() {
                Ok(path) => {
                    let guard = path.guard().0;
                    let exit = path.exit().0;
                    let relay = path.hops.get(1).map(|id| id.0).unwrap_or(0);
                    path_select_json(nodes, guard, relay, exit).to_string()
                }
                Err(e) => sprint25_30_error_json(&format!("{e:?}")).to_string(),
            }
        }
        Command::DirectoryConsensus { nodes, epoch } => {
            let auth = DirectoryAuthorityId(0xABCD_1234);
            let ids: Vec<u64> = (1..=nodes as u64).collect();
            match build_deterministic_consensus(epoch, auth, &ids, 45000) {
                Ok(consensus) => {
                    let guards = consensus.list_guards().len();
                    let relays = consensus.list_relays().len();
                    let exits = consensus.list_exits().len();
                    directory_consensus_json(epoch, nodes, guards, relays, exits).to_string()
                }
                Err(e) => sprint25_30_error_json(&format!("{e:?}")).to_string(),
            }
        }
        Command::TrafficSchedule {
            real_packets,
            cover_packets,
            epochs,
        } => {
            let policy = SchedulerPolicy {
                max_real_per_epoch: real_packets.max(1),
                min_cover_per_epoch: cover_packets,
                ..SchedulerPolicy::default()
            };
            let mut sched = TrafficScheduler::new(policy);
            for i in 0..real_packets {
                sched.enqueue_real(vec![i as u8]);
            }
            for i in 0..cover_packets {
                sched.enqueue_cover(vec![i as u8]);
            }
            let mut total_drained = 0;
            for _ in 0..epochs {
                sched.tick_epoch();
                total_drained += sched.drain_epoch().len();
            }
            traffic_schedule_json(epochs, real_packets, cover_packets, total_drained).to_string()
        }
        Command::AdversarialSim { model, count } => {
            let result = match model.as_str() {
                "packet-size" | "size" => run_packet_size_observation(1, 0xABCD, count),
                "timing" => run_timing_observation(count),
                "route-guess" | "route" => run_route_guessing(count / 2 + 1, count / 2),
                "replay" => run_replay_attempt(),
                other => {
                    return sprint25_30_error_json(&format!("unknown model: {other}")).to_string();
                }
            };
            adversarial_sim_json(
                &model,
                result.packets_observed,
                result.size_uniform,
                result.replay_succeeded,
            )
            .to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster_topology::{ClusterTopologyProfile, build_cluster_configs_with_count};
    use crate::cluster_types::ClusterNodeRole;
    use runtime_state::NodeServiceState;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sprint 14/15 legacy tests — N1–N10, CLI1–CLI5
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn n1_run_defaults_produces_metrics_json() {
        let out = run_cli(&args("run"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("metrics").is_some());
        assert_eq!(v["node_count"], 100);
        assert_eq!(v["circuits"], 5);
        assert_eq!(v["rounds"], 100);
    }

    #[test]
    fn n2_topology_100_nodes() {
        let out = run_cli(&args("topology --node-count 100"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["node_count"], 100);
        assert_eq!(v["guard_count"], 10);
        assert_eq!(v["relay_count"], 80);
        assert_eq!(v["exit_count"], 10);
        assert_eq!(v["link_count"], 90);
    }

    #[test]
    fn n3_run_50_rounds_all_delivered() {
        let out = run_cli(&args("run --node-count 100 --circuits 5 --rounds 50"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let m = &v["metrics"];
        assert_eq!(m["packets_sent"], 50);
        assert_eq!(m["packets_dropped"], 0);
        assert_eq!(m["paths_completed"], 50);
        assert_eq!(m["avg_path_length"], 3.0);
    }

    #[test]
    fn n4_bench_has_timing_keys() {
        let out = run_cli(&args("bench --rounds 100"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("elapsed_us").is_some());
        assert!(v.get("throughput_packets_per_sec").is_some());
        assert_eq!(v["rounds"], 100);
    }

    #[test]
    fn n5_unknown_command_returns_error_json() {
        let out = run_cli(&args("foobar"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("error").is_some());
        assert!(
            v["error"]
                .as_str()
                .unwrap()
                .contains("unknown command: foobar")
        );
    }

    #[test]
    fn n6_run_zero_rounds_no_panic() {
        let out = run_cli(&args("run --rounds 0"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let m = &v["metrics"];
        assert_eq!(m["packets_sent"], 0);
        assert_eq!(m["paths_completed"], 0);
        assert_eq!(m["packets_dropped"], 0);
    }

    #[test]
    fn n7_topology_50_nodes() {
        let out = run_cli(&args("topology --node-count 50"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["node_count"], 50);
        assert_eq!(v["guard_count"], 5);
        assert_eq!(v["relay_count"], 40);
        assert_eq!(v["exit_count"], 5);
    }

    #[test]
    fn n8_node_runtime_topology_summary() {
        let rt = NodeRuntime::new(100);
        let s = rt.topology_summary();
        assert_eq!(s.node_count, 100);
        assert_eq!(s.guard_count, 10);
        assert_eq!(s.relay_count, 80);
        assert_eq!(s.exit_count, 10);
        assert_eq!(s.link_count, 90);
    }

    #[test]
    fn n9_node_runtime_run_rounds() {
        let mut rt = NodeRuntime::new(100);
        rt.build_circuits(3);
        let result = rt.run_rounds(30);
        assert_eq!(result.rounds, 30);
        assert_eq!(result.delivered, 30);
        assert_eq!(result.dropped, 0);
        assert!((result.avg_path_length - 3.0).abs() < f64::EPSILON);
    }

    #[test]
    fn n10_1000_rounds_forwarded_triple_sent() {
        let out = run_cli(&args("run --rounds 1000 --circuits 5"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let m = &v["metrics"];
        let sent = m["packets_sent"].as_u64().unwrap();
        let forwarded = m["packets_forwarded"].as_u64().unwrap();
        assert_eq!(sent, 1000);
        assert_eq!(forwarded, 3000);
    }

    #[test]
    fn cli1_start_returns_running_json() {
        let out = run_cli(&args("start"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "start");
        assert_eq!(v["state"], "Running");
        assert_eq!(v["simulation_mode"], true);
        assert_eq!(v["node_id"], 1);
    }

    #[test]
    fn cli2_status_returns_created_json() {
        let out = run_cli(&args("status"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "status");
        assert_eq!(v["state"], "Created");
        assert_eq!(v["simulation_mode"], true);
    }

    #[test]
    fn cli3_peers_returns_empty_array() {
        let out = run_cli(&args("peers"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "peers");
        assert!(v["peers"].as_array().unwrap().is_empty());
    }

    #[test]
    fn cli4_invalid_config_error_json() {
        let config = NodeConfig {
            bind_port: 0,
            ..NodeConfig::default()
        };
        match NodeService::new(config) {
            Ok(_) => panic!("expected ServiceError"),
            Err(e) => {
                let v = output::service_error_json(&e);
                assert!(v.get("error").is_some());
                assert_eq!(v["error"], "bind_port must be > 0");
            }
        }
    }

    #[test]
    fn cli5_legacy_commands_still_work() {
        let run_out = run_cli(&args("run --rounds 5"));
        let topo_out = run_cli(&args("topology"));
        let bench_out = run_cli(&args("bench --rounds 10"));
        let run_v: serde_json::Value = serde_json::from_str(&run_out).unwrap();
        let topo_v: serde_json::Value = serde_json::from_str(&topo_out).unwrap();
        let bench_v: serde_json::Value = serde_json::from_str(&bench_out).unwrap();
        assert_eq!(run_v["metrics"]["packets_sent"], 5);
        assert_eq!(topo_v["node_count"], 100);
        assert!(bench_v.get("elapsed_us").is_some());
    }

    #[test]
    fn node_service_state_as_str() {
        assert_eq!(NodeServiceState::Created.as_str(), "Created");
        assert_eq!(NodeServiceState::Running.as_str(), "Running");
        assert_eq!(NodeServiceState::Stopped.as_str(), "Stopped");
        assert_eq!(
            NodeServiceState::Error("oops".to_string()).as_str(),
            "Error"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sprint 16 — CLI cluster tests
    // ─────────────────────────────────────────────────────────────────────────

    // CLI-C1: cluster-start tiny returns Running JSON
    #[test]
    fn cli_c1_cluster_start_tiny() {
        let out = run_cli(&args("cluster-start --profile tiny"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "cluster-start");
        assert_eq!(v["profile"], "tiny");
        assert_eq!(v["nodes"], 5);
        assert_eq!(v["state"], "Running");
    }

    // CLI-C2: cluster-status tiny returns JSON with node list
    #[test]
    fn cli_c2_cluster_status_tiny() {
        let out = run_cli(&args("cluster-status --profile tiny"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "cluster-status");
        assert_eq!(v["profile"], "tiny");
        assert_eq!(v["nodes"], 5);
        assert!(v["node_list"].as_array().is_some());
    }

    // CLI-C3: cluster-run tiny 100 rounds → packets_forwarded = 3 × sent
    #[test]
    fn cli_c3_cluster_run_tiny_100_rounds() {
        let out = run_cli(&args("cluster-run --profile tiny --rounds 100"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "cluster-run");
        assert_eq!(v["profile"], "tiny");
        assert_eq!(v["rounds"], 100);
        let sent = v["packets_sent"].as_u64().unwrap();
        let forwarded = v["packets_forwarded"].as_u64().unwrap();
        assert_eq!(sent, 100);
        assert_eq!(forwarded, sent * 3);
    }

    // CLI-C4: cluster-topology tiny has correct role counts
    #[test]
    fn cli_c4_cluster_topology_tiny() {
        let out = run_cli(&args("cluster-topology --profile tiny"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "cluster-topology");
        assert_eq!(v["profile"], "tiny");
        assert_eq!(v["clients"], 1);
        assert_eq!(v["guards"], 1);
        assert_eq!(v["relays"], 2);
        assert_eq!(v["exits"], 1);
    }

    // CLI-C5: cluster-peers returns JSON with nodes array
    #[test]
    fn cli_c5_cluster_peers_tiny() {
        let out = run_cli(&args("cluster-peers --profile tiny"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "cluster-peers");
        assert_eq!(v["profile"], "tiny");
        assert!(v["nodes"].as_array().is_some());
        assert_eq!(v["nodes"].as_array().unwrap().len(), 5);
    }

    // CLI-C6: invalid profile returns JSON error
    #[test]
    fn cli_c6_invalid_profile_returns_error() {
        let out = run_cli(&args("cluster-start --profile bogus"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("error").is_some());
        assert!(v["error"].as_str().unwrap().contains("bogus"));
    }

    // CLI-C7: legacy start/status/run/bench still pass
    #[test]
    fn cli_c7_legacy_commands_unaffected() {
        let s = run_cli(&args("start"));
        let st = run_cli(&args("status"));
        let r = run_cli(&args("run --rounds 3"));
        let b = run_cli(&args("bench --rounds 5"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&s).unwrap()["state"],
            "Running"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&st).unwrap()["state"],
            "Created"
        );
        assert!(
            serde_json::from_str::<serde_json::Value>(&r)
                .unwrap()
                .get("metrics")
                .is_some()
        );
        assert!(
            serde_json::from_str::<serde_json::Value>(&b)
                .unwrap()
                .get("elapsed_us")
                .is_some()
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sprint 16 Phase 9 — Hardening tests
    // ─────────────────────────────────────────────────────────────────────────

    // H1: repeated start does not corrupt cluster state
    #[test]
    fn h1_repeated_start_rejected() {
        let mut cluster = LocalCluster::with_default_topology(5).unwrap();
        cluster.start_all().unwrap();
        assert!(cluster.is_running());
        let err = cluster.start_all().unwrap_err();
        assert_eq!(err, cluster_types::ClusterError::ClusterAlreadyRunning);
        // State must still be Running, not corrupted
        assert!(cluster.is_running());
    }

    // H2: stop before start is safe (no error, running = false)
    #[test]
    fn h2_stop_before_start_safe() {
        let mut cluster = LocalCluster::with_default_topology(5).unwrap();
        cluster.stop_all(); // should not panic
        assert!(!cluster.is_running());
    }

    // H3: removing a node from a running cluster is handled deterministically
    #[test]
    fn h3_remove_running_node_deterministic() {
        let mut cluster = LocalCluster::new();
        for cfg in build_cluster_configs(&ClusterTopologyProfile::Tiny) {
            cluster.add_node(cfg).unwrap();
        }
        cluster.start_all().unwrap();
        assert_eq!(cluster.node_count(), 5);
        cluster
            .remove_node(cluster_types::ClusterNodeId(1))
            .unwrap();
        assert_eq!(cluster.node_count(), 4);
        // Cluster is still running (remaining nodes)
        assert!(cluster.is_running());
    }

    // H4: zero-node topology produces empty configs
    #[test]
    fn h4_zero_node_topology_empty() {
        let configs = build_cluster_configs_with_count(0);
        assert!(configs.is_empty());
    }

    // H5: max_peers enforced under full mesh
    #[test]
    fn h5_max_peers_enforced_full_mesh() {
        use cluster_peering::wire_full_mesh;
        use cluster_types::ClusterNodeConfig;
        let mut cluster = LocalCluster::new();
        for id in 1u64..=5 {
            cluster
                .add_node(ClusterNodeConfig {
                    node_id: cluster_types::ClusterNodeId(id),
                    role: ClusterNodeRole::Relay,
                    node_name: format!("r{id}"),
                    bind_address: "127.0.0.1".to_string(),
                    bind_port: 39000 + id as u16,
                    max_peers: 1,
                    simulation_mode: true,
                    allow_real_udp: false,
                })
                .unwrap();
        }
        wire_full_mesh(&mut cluster).unwrap();
        for snap in cluster.snapshots() {
            assert!(snap.peer_count <= 1);
        }
    }

    // H6: JSON output is parseable for every new cluster command
    #[test]
    fn h6_all_cluster_commands_produce_valid_json() {
        let cmds = [
            "cluster-start --profile tiny",
            "cluster-status --profile tiny",
            "cluster-run --profile tiny --rounds 1",
            "cluster-topology --profile tiny",
            "cluster-peers --profile tiny",
        ];
        for cmd in &cmds {
            let out = run_cli(&args(cmd));
            let parsed = serde_json::from_str::<serde_json::Value>(&out);
            assert!(parsed.is_ok(), "JSON parse failed for `{cmd}`: {out}");
        }
    }

    // H7: all node snapshots sorted by node_id
    #[test]
    fn h7_snapshots_sorted_by_node_id() {
        let configs = build_cluster_configs(&ClusterTopologyProfile::Small);
        let mut cluster = LocalCluster::new();
        // Add in reverse order
        for cfg in configs.into_iter().rev() {
            cluster.add_node(cfg).unwrap();
        }
        let snaps = cluster.snapshots();
        for w in snaps.windows(2) {
            assert!(w[0].node_id < w[1].node_id);
        }
    }

    // H8: cluster run with zero rounds returns zero metrics
    #[test]
    fn h8_cluster_run_zero_rounds() {
        let out = run_cli(&args("cluster-run --profile tiny --rounds 0"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["packets_sent"], 0);
        assert_eq!(v["packets_forwarded"], 0);
    }

    // H9: large profile creation does not panic
    #[test]
    fn h9_large_profile_creation_no_panic() {
        let configs = build_cluster_configs(&ClusterTopologyProfile::Large);
        assert_eq!(configs.len(), 250);
        // Verify all configs are valid
        for cfg in &configs {
            assert!(cfg.validate().is_ok());
        }
    }

    // H10: medium profile simulation runs deterministically
    #[test]
    fn h10_medium_profile_deterministic() {
        fn run_medium(rounds: usize) -> (u64, u64) {
            let configs = build_cluster_configs(&ClusterTopologyProfile::Medium);
            let mut cluster = LocalCluster::new();
            for cfg in configs {
                cluster.add_node(cfg).unwrap();
            }
            cluster.start_all().unwrap();
            cluster.run_rounds(rounds).unwrap();
            cluster
                .sim_metrics()
                .map(|m| (m.packets_sent, m.packets_forwarded))
                .unwrap_or((0, 0))
        }
        let (s1, f1) = run_medium(10);
        let (s2, f2) = run_medium(10);
        assert_eq!(s1, s2);
        assert_eq!(f1, f2);
        assert_eq!(s1, 10);
        assert_eq!(f1, 30);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Extension B — cluster-bench command
    // ─────────────────────────────────────────────────────────────────────────

    // CB1: cluster-bench returns JSON with timing and throughput keys
    #[test]
    fn cb1_cluster_bench_returns_timing_json() {
        let out = run_cli(&args("cluster-bench --profile tiny --rounds 100"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "cluster-bench");
        assert_eq!(v["profile"], "tiny");
        assert_eq!(v["rounds"], 100);
        assert_eq!(v["packets_sent"], 100);
        assert_eq!(v["packets_forwarded"], 300);
        assert!(v.get("elapsed_us").is_some());
        assert!(v.get("throughput_packets_per_sec").is_some());
    }

    // CB2: cluster-bench default profile is medium
    #[test]
    fn cb2_cluster_bench_default_medium_profile() {
        let out = run_cli(&args("cluster-bench --rounds 10"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["profile"], "medium");
        assert_eq!(v["packets_sent"], 10);
        assert_eq!(v["packets_forwarded"], 30);
    }

    // CB3: cluster-bench invalid profile returns error
    #[test]
    fn cb3_cluster_bench_invalid_profile_error() {
        let out = run_cli(&args("cluster-bench --profile bogus"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("error").is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Extension C — deterministic scenario tests
    // ─────────────────────────────────────────────────────────────────────────

    // SC1: 5-node tiny cluster — full round-trip scenario
    #[test]
    fn sc1_tiny_5_node_scenario() {
        let configs = build_cluster_configs(&ClusterTopologyProfile::Tiny);
        assert_eq!(configs.len(), 5);
        let mut cluster = LocalCluster::new();
        for cfg in configs {
            cluster.add_node(cfg).unwrap();
        }
        cluster.start_all().unwrap();
        cluster.run_rounds(10).unwrap();
        let m = cluster.sim_metrics().unwrap();
        assert_eq!(m.packets_sent, 10);
        assert_eq!(m.packets_forwarded, 30);
        assert_eq!(m.packets_dropped, 0);
        assert!(m.paths_completed > 0);
    }

    // SC2: 20-node small cluster — metrics scale correctly
    #[test]
    fn sc2_small_20_node_scenario() {
        let configs = build_cluster_configs(&ClusterTopologyProfile::Small);
        assert_eq!(configs.len(), 20);
        let mut cluster = LocalCluster::new();
        for cfg in configs {
            cluster.add_node(cfg).unwrap();
        }
        cluster.start_all().unwrap();
        cluster.run_rounds(20).unwrap();
        let m = cluster.sim_metrics().unwrap();
        assert_eq!(m.packets_sent, 20);
        assert_eq!(m.packets_forwarded, 60);
        assert_eq!(m.packets_dropped, 0);
    }

    // SC3: 100-node medium cluster — correct packet invariant holds
    #[test]
    fn sc3_medium_100_node_scenario() {
        let configs = build_cluster_configs(&ClusterTopologyProfile::Medium);
        assert_eq!(configs.len(), 100);
        let mut cluster = LocalCluster::new();
        for cfg in configs {
            cluster.add_node(cfg).unwrap();
        }
        cluster.start_all().unwrap();
        cluster.run_rounds(50).unwrap();
        let m = cluster.sim_metrics().unwrap();
        assert_eq!(m.packets_sent, 50);
        assert_eq!(m.packets_forwarded, 150);
        assert!(m.average_path_length() - 3.0 < f64::EPSILON);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sprint 17 — CLI UDP testnet tests
    // ─────────────────────────────────────────────────────────────────────────

    // CLI-UDP1: udp-testnet-start returns JSON with mode and state
    #[test]
    fn cli_udp1_start_command_json() {
        let out = run_cli(&args("udp-testnet-start --nodes 3 --base-port 42400"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "udp-testnet-start");
        assert_eq!(v["mode"], "loopback-only");
        assert_eq!(v["nodes"], 3);
        assert_eq!(v["base_port"], 42400);
        assert_eq!(v["state"], "started");
    }

    // CLI-UDP2: udp-testnet-probe sends and receives all probes
    #[test]
    fn cli_udp2_probe_command_json() {
        let out = run_cli(&args("udp-testnet-probe --nodes 3 --base-port 42410"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "udp-testnet-probe");
        assert_eq!(v["nodes"], 3);
        assert_eq!(v["packets_sent"], 3);
        assert_eq!(v["packets_received"], 3);
    }

    // CLI-UDP3: udp-testnet-data sends and receives data
    #[test]
    fn cli_udp3_data_command_json() {
        let out = run_cli(&args(
            "udp-testnet-data --nodes 3 --base-port 42420 --payload hello",
        ));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "udp-testnet-data");
        assert_eq!(v["nodes"], 3);
        assert_eq!(v["payload_len"], 5);
        assert_eq!(v["packets_sent"], 3);
        assert_eq!(v["packets_received"], 3);
    }

    // CLI-UDP4: udp-testnet-status returns snapshot array
    #[test]
    fn cli_udp4_status_command_json() {
        let out = run_cli(&args("udp-testnet-status --nodes 3 --base-port 42430"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "udp-testnet-status");
        assert_eq!(v["nodes"], 3);
        let snaps = v["snapshots"].as_array().unwrap();
        assert_eq!(snaps.len(), 3);
        assert!(snaps[0].get("node_id").is_some());
        assert!(snaps[0].get("local_addr").is_some());
        assert!(snaps[0].get("packets_sent").is_some());
    }

    // CLI-UDP5: zero node count returns error JSON
    #[test]
    fn cli_udp5_invalid_node_count_rejected() {
        let out = run_cli(&args("udp-testnet-start --nodes 0 --base-port 42440"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("error").is_some());
    }

    // CLI-UDP6: old cluster commands still pass after UDP additions
    #[test]
    fn cli_udp6_old_cluster_commands_unaffected() {
        let out = run_cli(&args("cluster-run --profile tiny --rounds 5"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "cluster-run");
        assert_eq!(v["packets_sent"], 5);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sprint 17 Phase 7 — Safety gate tests
    // ─────────────────────────────────────────────────────────────────────────

    // SG1: public bind address rejected at config level
    #[test]
    fn sg1_public_bind_address_rejected() {
        use crate::udp_testnet_types::{UdpTestnetError, UdpTestnetNodeConfig, UdpTestnetNodeId};
        let cfg = UdpTestnetNodeConfig {
            node_id: UdpTestnetNodeId(1),
            bind_address: "0.0.0.0".to_string(),
            bind_port: 41900,
            allow_real_udp: true,
            simulation_mode: false,
            max_packet_size: 1482,
        };
        assert_eq!(cfg.validate(), Err(UdpTestnetError::PublicBindRejected));
    }

    // SG2: allow_real_udp=false rejected at config level
    #[test]
    fn sg2_allow_real_udp_false_rejected() {
        use crate::udp_testnet_types::{UdpTestnetError, UdpTestnetNodeConfig, UdpTestnetNodeId};
        let cfg = UdpTestnetNodeConfig {
            node_id: UdpTestnetNodeId(1),
            bind_address: "127.0.0.1".to_string(),
            bind_port: 41901,
            allow_real_udp: false,
            simulation_mode: false,
            max_packet_size: 1482,
        };
        assert_eq!(cfg.validate(), Err(UdpTestnetError::RealUdpDisabled));
    }

    // SG3: simulation_mode=true rejected at config level
    #[test]
    fn sg3_simulation_mode_true_rejected() {
        use crate::udp_testnet_types::{UdpTestnetError, UdpTestnetNodeConfig, UdpTestnetNodeId};
        let cfg = UdpTestnetNodeConfig {
            node_id: UdpTestnetNodeId(1),
            bind_address: "127.0.0.1".to_string(),
            bind_port: 41902,
            allow_real_udp: true,
            simulation_mode: true,
            max_packet_size: 1482,
        };
        assert_eq!(cfg.validate(), Err(UdpTestnetError::RealUdpDisabled));
    }

    // SG4: send_to rejects non-loopback target at socket level
    #[test]
    fn sg4_non_loopback_send_target_rejected() {
        use crate::udp_loopback_socket::UdpLoopbackSocket;
        use crate::udp_testnet_packet::UdpTestnetPacket;
        use crate::udp_testnet_types::{
            UdpTestnetError, UdpTestnetNodeConfig, UdpTestnetNodeId, UdpTestnetPacketKind,
        };
        let cfg = UdpTestnetNodeConfig {
            node_id: UdpTestnetNodeId(1),
            bind_address: "127.0.0.1".to_string(),
            bind_port: 42500,
            allow_real_udp: true,
            simulation_mode: false,
            max_packet_size: 1482,
        };
        let sock = UdpLoopbackSocket::bind(&cfg).unwrap();
        let pkt = UdpTestnetPacket {
            source_node: UdpTestnetNodeId(1),
            target_node: UdpTestnetNodeId(99),
            packet_kind: UdpTestnetPacketKind::Probe,
            sequence_number: 0,
            payload: Vec::new(),
        };
        let public_addr: std::net::SocketAddr = "8.8.8.8:9999".parse().unwrap();
        assert_eq!(
            sock.send_to(&pkt, public_addr).unwrap_err(),
            UdpTestnetError::PublicBindRejected
        );
    }

    // SG5: UDP testnet CLI commands never produce "0.0.0.0" in JSON output
    #[test]
    fn sg5_udp_commands_never_use_public_address() {
        let cmds = [
            "udp-testnet-start --nodes 3 --base-port 42510",
            "udp-testnet-status --nodes 3 --base-port 42520",
        ];
        for cmd in &cmds {
            let out = run_cli(&args(cmd));
            assert!(
                !out.contains("0.0.0.0"),
                "command `{cmd}` output contained 0.0.0.0: {out}"
            );
        }
    }

    // SG6: default NodeConfig is simulation-only (no real UDP)
    #[test]
    fn sg6_default_node_config_simulation_only() {
        let cfg = NodeConfig::default();
        assert!(cfg.simulation_mode);
        assert!(!cfg.allow_real_udp);
    }

    // SG7: Sprint 16 dry-run cluster does not open UDP sockets (start_all succeeds without UDP)
    #[test]
    fn sg7_dry_run_cluster_no_udp_sockets() {
        let mut cluster = LocalCluster::with_default_topology(5).unwrap();
        // start_all() must succeed — it uses simulation mode, not UDP
        cluster.start_all().unwrap();
        assert!(cluster.is_running());
        // Verify all configs have allow_real_udp=false
        for cfg in cluster.node_configs() {
            assert!(!cfg.allow_real_udp);
        }
    }

    // SG8: UDP testnet requires explicit allow_real_udp=true config
    #[test]
    fn sg8_udp_testnet_requires_explicit_udp_config() {
        use crate::udp_testnet_node::UdpTestnetNode;
        use crate::udp_testnet_types::{UdpTestnetError, UdpTestnetNodeConfig, UdpTestnetNodeId};
        // A config with allow_real_udp=false must be rejected
        let cfg = UdpTestnetNodeConfig {
            node_id: UdpTestnetNodeId(1),
            bind_address: "127.0.0.1".to_string(),
            bind_port: 41910,
            allow_real_udp: false,
            simulation_mode: true,
            max_packet_size: 1482,
        };
        assert_eq!(
            UdpTestnetNode::start(cfg).unwrap_err(),
            UdpTestnetError::RealUdpDisabled
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Extension B — udp-testnet-bench command
    // ─────────────────────────────────────────────────────────────────────────

    // EBench1: bench command returns timing and throughput JSON
    #[test]
    fn ebench1_udp_testnet_bench_json() {
        let out = run_cli(&args(
            "udp-testnet-bench --nodes 3 --base-port 42540 --rounds 10",
        ));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "udp-testnet-bench");
        assert_eq!(v["nodes"], 3);
        assert_eq!(v["rounds"], 10);
        assert_eq!(v["packets_sent"], 30);
        assert_eq!(v["packets_received"], 30);
        assert!(v.get("elapsed_us").is_some());
        assert!(v.get("throughput_packets_per_sec").is_some());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Extension C — payload size boundary tests
    // ─────────────────────────────────────────────────────────────────────────

    // EPL1: empty payload (0 bytes) encodes and delivers
    #[test]
    fn epl1_empty_payload() {
        use crate::udp_testnet_node::UdpTestnetNode;
        use crate::udp_testnet_types::{UdpTestnetNodeConfig, UdpTestnetNodeId};
        let cfg_a = UdpTestnetNodeConfig {
            node_id: UdpTestnetNodeId(1),
            bind_address: "127.0.0.1".to_string(),
            bind_port: 42600,
            allow_real_udp: true,
            simulation_mode: false,
            max_packet_size: 1482,
        };
        let cfg_b = UdpTestnetNodeConfig {
            node_id: UdpTestnetNodeId(2),
            bind_address: "127.0.0.1".to_string(),
            bind_port: 42601,
            allow_real_udp: true,
            simulation_mode: false,
            max_packet_size: 1482,
        };
        let mut a = UdpTestnetNode::start(cfg_a).unwrap();
        let mut b = UdpTestnetNode::start(cfg_b).unwrap();
        let b_addr = b.snapshot().local_addr;
        a.send_data(UdpTestnetNodeId(2), b_addr, vec![]).unwrap();
        let pkt = b.poll_once().unwrap().unwrap();
        assert!(pkt.payload.is_empty());
    }

    // EPL2: 1-byte payload encodes and delivers
    #[test]
    fn epl2_one_byte_payload() {
        let out = run_cli(&args(
            "udp-testnet-data --nodes 2 --base-port 42610 --payload x",
        ));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["payload_len"], 1);
        assert_eq!(v["packets_received"], 2);
    }

    // EPL3: 1407-byte payload encodes and delivers (below ENCRYPTED_CELL_SIZE)
    #[test]
    fn epl3_1407_byte_payload() {
        use crate::udp_testnet_packet::UdpTestnetPacket;
        use crate::udp_testnet_packet::{PACKET_HEADER_SIZE, decode_packet, encode_packet};
        use crate::udp_testnet_types::{UdpTestnetNodeId, UdpTestnetPacketKind};
        let payload = vec![0xABu8; 1407];
        let pkt = UdpTestnetPacket {
            source_node: UdpTestnetNodeId(1),
            target_node: UdpTestnetNodeId(2),
            packet_kind: UdpTestnetPacketKind::Data,
            sequence_number: 0,
            payload: payload.clone(),
        };
        let encoded = encode_packet(&pkt);
        assert_eq!(encoded.len(), PACKET_HEADER_SIZE + 1407);
        let decoded = decode_packet(&encoded).unwrap();
        assert_eq!(decoded.payload.len(), 1407);
        assert_eq!(decoded.payload, payload);
    }

    // EPL4: 1482-byte payload (ENCRYPTED_CELL_SIZE) encodes and delivers
    #[test]
    fn epl4_1482_byte_payload() {
        use crate::udp_testnet_packet::UdpTestnetPacket;
        use crate::udp_testnet_packet::{PACKET_HEADER_SIZE, decode_packet, encode_packet};
        use crate::udp_testnet_types::{UdpTestnetNodeId, UdpTestnetPacketKind};
        let payload = vec![0xCCu8; 1482];
        let pkt = UdpTestnetPacket {
            source_node: UdpTestnetNodeId(1),
            target_node: UdpTestnetNodeId(2),
            packet_kind: UdpTestnetPacketKind::Data,
            sequence_number: 0,
            payload: payload.clone(),
        };
        let encoded = encode_packet(&pkt);
        assert_eq!(encoded.len(), PACKET_HEADER_SIZE + 1482);
        let decoded = decode_packet(&encoded).unwrap();
        assert_eq!(decoded.payload.len(), 1482);
        assert_eq!(decoded.payload, payload);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sprint 18 — Phase 8 CLI tests
    // ─────────────────────────────────────────────────────────────────────────

    // CLI-E1: encrypted-udp-start returns started JSON
    #[test]
    fn cli_e1_encrypted_udp_start_json() {
        let out = run_cli(&args("encrypted-udp-start --nodes 3 --base-port 43100"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "encrypted-udp-start");
        assert_eq!(v["nodes"], 3);
        assert_eq!(v["base_port"], 43100);
        assert_eq!(v["state"], "started");
        assert_eq!(v["mode"], "loopback-only");
    }

    // CLI-E2: encrypted-udp-probe returns ring probe results
    #[test]
    fn cli_e2_encrypted_udp_probe_json() {
        let out = run_cli(&args("encrypted-udp-probe --nodes 3 --base-port 43110"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "encrypted-udp-probe");
        assert_eq!(v["nodes"], 3);
        assert_eq!(v["packets_sent"], 3);
        assert_eq!(v["packets_received"], 3);
    }

    // CLI-E3: encrypted-udp-send returns send + encrypted cell counters
    #[test]
    fn cli_e3_encrypted_udp_send_json() {
        let out = run_cli(&args(
            "encrypted-udp-send --nodes 3 --base-port 43120 --payload hello",
        ));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "encrypted-udp-send");
        assert_eq!(v["payload_len"], 5);
        assert_eq!(v["packets_sent"], 3);
        assert_eq!(v["packets_received"], 3);
        assert_eq!(v["encrypted_cells_sent"], 3);
        assert_eq!(v["encrypted_cells_received"], 3);
    }

    // CLI-E4: encrypted-udp-status returns snapshot list
    #[test]
    fn cli_e4_encrypted_udp_status_json() {
        let out = run_cli(&args("encrypted-udp-status --nodes 3 --base-port 43130"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "encrypted-udp-status");
        assert_eq!(v["nodes"], 3);
        let snaps = v["snapshots"].as_array().unwrap();
        assert_eq!(snaps.len(), 3);
    }

    // CLI-E5: encrypted-udp-bench returns timing and throughput JSON
    #[test]
    fn cli_e5_encrypted_udp_bench_json() {
        let out = run_cli(&args(
            "encrypted-udp-bench --nodes 3 --base-port 43140 --rounds 5",
        ));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "encrypted-udp-bench");
        assert_eq!(v["nodes"], 3);
        assert_eq!(v["rounds"], 5);
        assert_eq!(v["packets_sent"], 15);
        assert_eq!(v["packets_received"], 15);
        assert!(v.get("elapsed_us").is_some());
        assert!(v.get("throughput_packets_per_sec").is_some());
    }

    // CLI-E6: invalid node count returns error JSON
    #[test]
    fn cli_e6_invalid_node_count_rejected() {
        let out = run_cli(&args("encrypted-udp-start --nodes 0 --base-port 43150"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("error").is_some());
    }

    // CLI-E7: legacy udp-testnet commands still pass after Sprint 18 additions
    #[test]
    fn cli_e7_legacy_udp_testnet_commands_unaffected() {
        let out = run_cli(&args("udp-testnet-start --nodes 3 --base-port 43160"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "udp-testnet-start");
        assert_eq!(v["nodes"], 3);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sprint 18 — Phase 9 security gate tests
    // ─────────────────────────────────────────────────────────────────────────

    // EG1: public bind address rejected at config level
    #[test]
    fn eg1_public_bind_address_rejected() {
        use crate::encrypted_udp_types::{
            EncryptedUdpError, EncryptedUdpNodeConfig, EncryptedUdpNodeId,
        };
        let cfg = EncryptedUdpNodeConfig {
            node_id: EncryptedUdpNodeId(1),
            bind_address: "0.0.0.0".to_string(),
            bind_port: 43170,
            allow_real_udp: true,
            simulation_mode: false,
        };
        assert_eq!(cfg.validate(), Err(EncryptedUdpError::PublicBindRejected));
    }

    // EG2: non-loopback send target rejected at socket level
    #[test]
    fn eg2_non_loopback_send_target_rejected() {
        use crate::encrypted_udp_packet::EncryptedUdpPacket;
        use crate::encrypted_udp_socket::EncryptedUdpSocket;
        use crate::encrypted_udp_types::{
            EncryptedUdpError, EncryptedUdpNodeConfig, EncryptedUdpNodeId, EncryptedUdpPacketKind,
        };
        let cfg = EncryptedUdpNodeConfig {
            node_id: EncryptedUdpNodeId(1),
            bind_address: "127.0.0.1".to_string(),
            bind_port: 43171,
            allow_real_udp: true,
            simulation_mode: false,
        };
        let sock = EncryptedUdpSocket::bind(&cfg).unwrap();
        let pkt = EncryptedUdpPacket {
            source_node: EncryptedUdpNodeId(1),
            target_node: EncryptedUdpNodeId(2),
            packet_kind: EncryptedUdpPacketKind::Shutdown,
            sequence_number: 0,
            encrypted_cell_bytes: Vec::new(),
        };
        let non_loopback: std::net::SocketAddr = "8.8.8.8:12345".parse().unwrap();
        assert_eq!(
            sock.send_to(&pkt, non_loopback).unwrap_err(),
            EncryptedUdpError::PublicBindRejected
        );
    }

    // EG3: encrypted packet with wrong cell size rejected at codec level
    #[test]
    fn eg3_encrypted_packet_wrong_size_rejected() {
        use crate::encrypted_udp_packet::{EncryptedUdpPacket, encode_encrypted_udp_packet};
        use crate::encrypted_udp_types::{
            EncryptedUdpError, EncryptedUdpNodeId, EncryptedUdpPacketKind,
        };
        let pkt = EncryptedUdpPacket {
            source_node: EncryptedUdpNodeId(1),
            target_node: EncryptedUdpNodeId(2),
            packet_kind: EncryptedUdpPacketKind::EncryptedCell,
            sequence_number: 0,
            encrypted_cell_bytes: vec![0u8; 500], // wrong size
        };
        assert_eq!(
            encode_encrypted_udp_packet(&pkt).unwrap_err(),
            EncryptedUdpError::InvalidEncryptedCellSize
        );
    }

    // EG4: send_payload_encrypted without session returns SessionNotFound
    #[test]
    fn eg4_send_without_session_rejected() {
        use crate::encrypted_udp_node::EncryptedUdpNode;
        use crate::encrypted_udp_types::{
            EncryptedUdpError, EncryptedUdpNodeConfig, EncryptedUdpNodeId,
        };
        let mut node = EncryptedUdpNode::start(EncryptedUdpNodeConfig {
            node_id: EncryptedUdpNodeId(1),
            bind_address: "127.0.0.1".to_string(),
            bind_port: 43172,
            allow_real_udp: true,
            simulation_mode: false,
        })
        .unwrap();
        let dummy_addr: std::net::SocketAddr = "127.0.0.1:43173".parse().unwrap();
        assert_eq!(
            node.send_payload_encrypted(EncryptedUdpNodeId(2), dummy_addr, b"data")
                .unwrap_err(),
            EncryptedUdpError::SessionNotFound
        );
    }

    // EG5: duplicate packet sequence (replay) rejected
    #[test]
    fn eg5_duplicate_packet_sequence_rejected() {
        use crate::encrypted_cell_fixture::make_encrypted_cell;
        use crate::encrypted_udp_node::EncryptedUdpNode;
        use crate::encrypted_udp_packet::encrypted_cell_to_bytes;
        use crate::encrypted_udp_types::{
            EncryptedUdpError, EncryptedUdpNodeConfig, EncryptedUdpNodeId,
        };
        use liberty_controlled_chaos::noise_link::ENCRYPTED_CELL_SIZE;

        let sender_cfg = EncryptedUdpNodeConfig {
            node_id: EncryptedUdpNodeId(1),
            bind_address: "127.0.0.1".to_string(),
            bind_port: 43174,
            allow_real_udp: true,
            simulation_mode: false,
        };
        let receiver_cfg = EncryptedUdpNodeConfig {
            node_id: EncryptedUdpNodeId(2),
            bind_address: "127.0.0.1".to_string(),
            bind_port: 43175,
            allow_real_udp: true,
            simulation_mode: false,
        };
        let mut sender = EncryptedUdpNode::start(sender_cfg).unwrap();
        let mut receiver = EncryptedUdpNode::start(receiver_cfg).unwrap();
        let r_addr = receiver.snapshot().local_addr;
        sender
            .add_peer_session(EncryptedUdpNodeId(2), 0xEEEE, 0xFFFF)
            .unwrap();
        receiver
            .add_peer_session(EncryptedUdpNodeId(1), 0xFFFF, 0xEEEE)
            .unwrap();

        // Craft two packets with the same nonce (replay)
        let enc = make_encrypted_cell(b"guard", 0xEEEE).unwrap();
        let cell_bytes = encrypted_cell_to_bytes(&enc);
        assert_eq!(cell_bytes.len(), ENCRYPTED_CELL_SIZE);

        sender
            .send_encrypted_cell(EncryptedUdpNodeId(2), r_addr, cell_bytes.clone())
            .unwrap();
        sender
            .send_encrypted_cell(EncryptedUdpNodeId(2), r_addr, cell_bytes)
            .unwrap();
        receiver.poll_once().unwrap(); // first: ok
        assert_eq!(
            receiver.poll_once().unwrap_err(),
            EncryptedUdpError::ReplayDetected
        );
    }

    // EG6: default NodeConfig still has simulation_mode=true, allow_real_udp=false
    #[test]
    fn eg6_default_node_config_simulation_only() {
        let cfg = NodeConfig::default();
        assert!(
            cfg.simulation_mode,
            "default NodeConfig must be simulation-only"
        );
        assert!(
            !cfg.allow_real_udp,
            "default NodeConfig must not allow real UDP"
        );
    }

    // EG7: Sprint 17 plaintext UDP testnet still works alongside encrypted testnet
    #[test]
    fn eg7_plaintext_udp_testnet_still_available() {
        let out = run_cli(&args("udp-testnet-probe --nodes 3 --base-port 43176"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "udp-testnet-probe");
        assert_eq!(v["packets_sent"], 3);
        assert_eq!(v["packets_received"], 3);
    }

    // EG8: encrypted UDP commands never output "0.0.0.0"
    #[test]
    fn eg8_encrypted_udp_commands_never_use_public_address() {
        let commands = [
            "encrypted-udp-start --nodes 3 --base-port 43180",
            "encrypted-udp-probe --nodes 3 --base-port 43190",
            "encrypted-udp-status --nodes 3 --base-port 43200",
        ];
        for cmd in commands {
            let out = run_cli(&args(cmd));
            assert!(
                !out.contains("0.0.0.0"),
                "encrypted UDP command '{cmd}' must not output 0.0.0.0; got: {out}"
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sprint 18 — Extension B: payload size boundary tests
    // ─────────────────────────────────────────────────────────────────────────

    // EXT-B1: empty payload (0 bytes) encrypts and delivers
    #[test]
    fn ext_b1_empty_payload_encrypted() {
        use crate::encrypted_udp_node::EncryptedUdpNode;
        use crate::encrypted_udp_types::{EncryptedUdpNodeConfig, EncryptedUdpNodeId};
        let mut node_a = EncryptedUdpNode::start(EncryptedUdpNodeConfig {
            node_id: EncryptedUdpNodeId(1),
            bind_address: "127.0.0.1".to_string(),
            bind_port: 43210,
            allow_real_udp: true,
            simulation_mode: false,
        })
        .unwrap();
        let mut node_b = EncryptedUdpNode::start(EncryptedUdpNodeConfig {
            node_id: EncryptedUdpNodeId(2),
            bind_address: "127.0.0.1".to_string(),
            bind_port: 43211,
            allow_real_udp: true,
            simulation_mode: false,
        })
        .unwrap();
        let b_addr = node_b.snapshot().local_addr;
        node_a
            .add_peer_session(EncryptedUdpNodeId(2), 0x1111, 0x2222)
            .unwrap();
        node_b
            .add_peer_session(EncryptedUdpNodeId(1), 0x2222, 0x1111)
            .unwrap();
        node_a
            .send_payload_encrypted(EncryptedUdpNodeId(2), b_addr, &[])
            .unwrap();
        let received = node_b.poll_once().unwrap().unwrap();
        assert!(
            received.is_empty(),
            "empty payload must decode to empty bytes"
        );
    }

    // EXT-B2: 1-byte payload via CLI
    #[test]
    fn ext_b2_one_byte_payload_cli() {
        let out = run_cli(&args(
            "encrypted-udp-send --nodes 2 --base-port 43220 --payload x",
        ));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["payload_len"], 1);
        assert_eq!(v["packets_received"], 2);
    }

    // EXT-B3: MAX_PAYLOAD-byte payload encodes and delivers via cluster
    #[test]
    fn ext_b3_max_payload_encrypted() {
        use liberty_controlled_chaos::cell_encoder::MAX_PAYLOAD;
        let mut cluster = EncryptedUdpCluster::start_loopback_cluster(2, 43230).unwrap();
        cluster.wire_deterministic_sessions();
        let payload = vec![0xABu8; MAX_PAYLOAD];
        cluster.send_encrypted_ring(&payload).unwrap();
        let received = cluster.poll_all();
        assert_eq!(received, 2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sprint 18 — Extension C: stress test
    // ─────────────────────────────────────────────────────────────────────────

    // EXT-C1: 5-node, 100-round encrypted ring — sent == received
    #[test]
    fn ext_c1_encrypted_stress_5_nodes_100_rounds() {
        let mut cluster = EncryptedUdpCluster::start_loopback_cluster(5, 43240).unwrap();
        cluster.wire_deterministic_sessions();
        let mut total_sent: u64 = 0;
        let mut total_received: u64 = 0;
        for _ in 0..100 {
            cluster.send_encrypted_ring(b"stress").unwrap();
            total_sent += 5;
            total_received += cluster.poll_all() as u64;
        }
        assert_eq!(total_sent, 500);
        assert_eq!(
            total_received, 500,
            "all encrypted packets must be received"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sprint 19-23 — CLI integration tests
    // ─────────────────────────────────────────────────────────────────────────

    // CLI-S1: handshake-ring returns established JSON
    #[test]
    fn cli_s1_handshake_ring_json() {
        let out = run_cli(&args("handshake-ring --nodes 3 --base-port 44300"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "handshake-ring");
        assert_eq!(v["nodes"], 3);
        assert_eq!(v["state"], "established");
        assert_eq!(v["mode"], "loopback-only");
        assert!(v["sessions_established"].as_u64().unwrap() > 0);
    }

    // CLI-S2: circuit-run returns forwarded packet count
    #[test]
    fn cli_s2_circuit_run_json() {
        let out = run_cli(&args("circuit-run --nodes 3 --rounds 10"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "circuit-run");
        assert_eq!(v["rounds"], 10);
        assert_eq!(v["circuits"], 1);
        assert!(v["packets_forwarded"].as_u64().unwrap() > 0);
    }

    // CLI-S3: circuit-status returns circuit count JSON
    #[test]
    fn cli_s3_circuit_status_json() {
        let out = run_cli(&args("circuit-status --nodes 3"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "circuit-status");
        assert!(v["circuits_registered"].as_u64().unwrap() > 0);
    }

    // CLI-S4: directory-status returns role breakdown
    #[test]
    fn cli_s4_directory_status_json() {
        let out = run_cli(&args("directory-status --node-count 9"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "directory-status");
        assert_eq!(v["node_count"], 9);
        // Roles determined by node_id % 3: IDs 1..9 → 3 Guard, 3 Relay, 3 Exit
        assert_eq!(v["guard_count"], 3);
        assert_eq!(v["relay_count"], 3);
        assert_eq!(v["exit_count"], 3);
    }

    // CLI-S5: cover-traffic-run returns correct packet size
    #[test]
    fn cli_s5_cover_traffic_run_json() {
        use liberty_controlled_chaos::noise_link::ENCRYPTED_CELL_SIZE;
        let out = run_cli(&args(
            "cover-traffic-run --node-id 1 --seed 12345 --count 5",
        ));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "cover-traffic-run");
        assert_eq!(v["count"], 5);
        assert_eq!(v["packet_size"], ENCRYPTED_CELL_SIZE as u64);
        assert_eq!(v["all_correct_size"], true);
    }

    // CLI-S6: handshake-ring nodes < 2 returns error
    #[test]
    fn cli_s6_handshake_ring_invalid_node_count() {
        let out = run_cli(&args("handshake-ring --nodes 1 --base-port 44310"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("error").is_some());
    }

    // CLI-S7: handshake-ring output never contains "0.0.0.0"
    #[test]
    fn cli_s7_handshake_ring_no_public_address() {
        let out = run_cli(&args("handshake-ring --nodes 3 --base-port 44320"));
        assert!(
            !out.contains("0.0.0.0"),
            "handshake-ring must not output 0.0.0.0: {out}"
        );
    }

    // CLI-S8: all Sprint 19-23 commands produce valid JSON
    #[test]
    fn cli_s8_all_new_commands_produce_valid_json() {
        let cmds = [
            "handshake-ring --nodes 3 --base-port 44330",
            "circuit-run --nodes 3 --rounds 5",
            "circuit-status --nodes 3",
            "directory-status --node-count 6",
            "cover-traffic-run --node-id 2 --seed 9999 --count 3",
        ];
        for cmd in &cmds {
            let out = run_cli(&args(cmd));
            let parsed = serde_json::from_str::<serde_json::Value>(&out);
            assert!(parsed.is_ok(), "JSON parse failed for `{cmd}`: {out}");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Security hardening tests S1–S8
    // ─────────────────────────────────────────────────────────────────────────

    // S1: public bind rejected at EncryptedUdpNodeConfig level
    #[test]
    fn s1_public_bind_rejected_in_handshake_layer() {
        use crate::encrypted_udp_types::{
            EncryptedUdpError, EncryptedUdpNodeConfig, EncryptedUdpNodeId,
        };
        let cfg = EncryptedUdpNodeConfig {
            node_id: EncryptedUdpNodeId(1),
            bind_address: "0.0.0.0".to_string(),
            bind_port: 44400,
            allow_real_udp: true,
            simulation_mode: false,
        };
        assert_eq!(cfg.validate(), Err(EncryptedUdpError::PublicBindRejected));
    }

    // S2: send_payload_encrypted without any session returns SessionNotFound
    #[test]
    fn s2_send_before_session_rejected() {
        use crate::encrypted_udp_node::EncryptedUdpNode;
        use crate::encrypted_udp_types::{
            EncryptedUdpError, EncryptedUdpNodeConfig, EncryptedUdpNodeId,
        };
        let mut node = EncryptedUdpNode::start(EncryptedUdpNodeConfig {
            node_id: EncryptedUdpNodeId(1),
            bind_address: "127.0.0.1".to_string(),
            bind_port: 44401,
            allow_real_udp: true,
            simulation_mode: false,
        })
        .unwrap();
        let dummy: std::net::SocketAddr = "127.0.0.1:44402".parse().unwrap();
        assert_eq!(
            node.send_payload_encrypted(EncryptedUdpNodeId(2), dummy, b"data")
                .unwrap_err(),
            EncryptedUdpError::SessionNotFound
        );
    }

    // S3: replaying a handshake message returns Duplicate
    #[test]
    fn s3_handshake_replay_rejected() {
        use crate::handshake_manager::HandshakeManager;
        use crate::handshake_types::{HandshakeError, HandshakeNodeId};
        let id_a = HandshakeNodeId(1);
        let id_b = HandshakeNodeId(2);
        let mut a = HandshakeManager::new(id_a);
        let mut b = HandshakeManager::new(id_b);
        let m1 = a.start_handshake(id_b).unwrap();
        b.receive_message(m1.clone()).unwrap(); // first receive ok
        assert_eq!(
            b.receive_message(m1).unwrap_err(),
            HandshakeError::Duplicate
        );
    }

    // S4: circuit with repeated node ID detected as loop
    #[test]
    fn s4_circuit_loop_rejected() {
        use crate::encrypted_circuit_path::{CircuitError, EncryptedCircuitPath};
        use crate::encrypted_udp_types::EncryptedUdpNodeId;
        let hops = vec![
            EncryptedUdpNodeId(1),
            EncryptedUdpNodeId(2),
            EncryptedUdpNodeId(1),
        ];
        assert_eq!(
            EncryptedCircuitPath::new(1, hops, 10).unwrap_err(),
            CircuitError::LoopDetected
        );
    }

    // S5: duplicate circuit ID rejected
    #[test]
    fn s5_duplicate_circuit_rejected() {
        use crate::encrypted_circuit_path::EncryptedCircuitPath;
        use crate::encrypted_circuit_runtime::EncryptedCircuitRuntime;
        use crate::encrypted_udp_types::EncryptedUdpNodeId;
        let hops = vec![
            EncryptedUdpNodeId(1),
            EncryptedUdpNodeId(2),
            EncryptedUdpNodeId(3),
        ];
        let mut rt = EncryptedCircuitRuntime::new();
        rt.register_circuit(EncryptedCircuitPath::new(42, hops.clone(), 10).unwrap())
            .unwrap();
        // Attempting to register circuit ID 42 again must fail
        assert!(
            rt.register_circuit(EncryptedCircuitPath::new(42, hops, 10).unwrap())
                .is_err()
        );
    }

    // S6: TTL expiry is deterministic — circuit with TTL=2 expires after exactly 2 ticks
    #[test]
    fn s6_ttl_expiry_deterministic() {
        use crate::encrypted_circuit_path::EncryptedCircuitPath;
        use crate::encrypted_circuit_runtime::EncryptedCircuitRuntime;
        use crate::encrypted_udp_types::EncryptedUdpNodeId;
        let hops = vec![
            EncryptedUdpNodeId(1),
            EncryptedUdpNodeId(2),
            EncryptedUdpNodeId(3),
        ];
        let mut rt = EncryptedCircuitRuntime::new();
        rt.register_circuit(EncryptedCircuitPath::new(99, hops, 2).unwrap())
            .unwrap();
        assert!(rt.tick_ttl(99).unwrap()); // ttl=1, alive
        assert!(!rt.tick_ttl(99).unwrap()); // ttl=0, expired
        // Send should now fail with TtlExpired
        assert!(rt.send_on_circuit(99, b"late").is_err());
    }

    // S7: default NodeConfig is simulation-only (no real UDP permitted)
    #[test]
    fn s7_default_config_simulation_only() {
        let cfg = config::NodeConfig::default();
        assert!(cfg.simulation_mode, "default must be simulation mode");
        assert!(!cfg.allow_real_udp, "default must not allow real UDP");
    }

    // S8: encrypted-udp commands never emit "0.0.0.0" in their JSON output
    #[test]
    fn s8_encrypted_commands_no_public_address_in_output() {
        let cmds = [
            "handshake-ring --nodes 3 --base-port 44410",
            "encrypted-udp-start --nodes 3 --base-port 44420",
            "encrypted-udp-status --nodes 3 --base-port 44430",
        ];
        for cmd in &cmds {
            let out = run_cli(&args(cmd));
            assert!(
                !out.contains("0.0.0.0"),
                "command `{cmd}` must not output public address; got: {out}"
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sprint 24 — Onion routing CLI integration tests
    // ─────────────────────────────────────────────────────────────────────────

    // OR-CLI1: onion-circuit-build returns built JSON with correct field names
    #[test]
    fn or_cli1_onion_circuit_build_json() {
        let out = run_cli(&args("onion-circuit-build --nodes 5"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "onion-circuit-build");
        assert_eq!(v["nodes"], 5);
        assert_eq!(v["status"], "built");
        assert_eq!(v["hops"], 3);
    }

    // OR-CLI2: onion-circuit-build < 3 nodes returns error
    #[test]
    fn or_cli2_onion_circuit_build_too_few_nodes_error() {
        let out = run_cli(&args("onion-circuit-build --nodes 2"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("error").is_some());
    }

    // OR-CLI3: onion-send delivers payload and returns valid JSON
    #[test]
    fn or_cli3_onion_send_delivers_payload() {
        let out = run_cli(&args("onion-send --nodes 5 --payload testpayload"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "onion-send");
        assert_eq!(v["nodes"], 5);
        assert_eq!(v["delivered"], true);
        assert_eq!(v["payload_len"], 11);
        assert_eq!(v["hops"], 3);
    }

    // OR-CLI4: onion-send < 3 nodes returns error
    #[test]
    fn or_cli4_onion_send_too_few_nodes_error() {
        let out = run_cli(&args("onion-send --nodes 2 --payload hello"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("error").is_some());
    }

    // OR-CLI5: onion-simulate completes all rounds and delivers them
    #[test]
    fn or_cli5_onion_simulate_delivers_all_rounds() {
        let out = run_cli(&args("onion-simulate --nodes 5 --rounds 10"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "onion-simulate");
        assert_eq!(v["nodes"], 5);
        assert_eq!(v["rounds"], 10);
        assert_eq!(v["delivered"], 10);
    }

    // OR-CLI6: onion-simulate < 3 nodes returns error
    #[test]
    fn or_cli6_onion_simulate_too_few_nodes_error() {
        let out = run_cli(&args("onion-simulate --nodes 1 --rounds 5"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("error").is_some());
    }

    // OR-CLI7: all three onion commands produce valid JSON
    #[test]
    fn or_cli7_all_onion_commands_valid_json() {
        let cmds = [
            "onion-circuit-build --nodes 5",
            "onion-send --nodes 5 --payload hello",
            "onion-simulate --nodes 5 --rounds 3",
        ];
        for cmd in &cmds {
            let out = run_cli(&args(cmd));
            let parsed = serde_json::from_str::<serde_json::Value>(&out);
            assert!(parsed.is_ok(), "JSON parse failed for `{cmd}`: {out}");
        }
    }

    // OR-CLI8: onion-circuit-build is deterministic (same nodes → same hops)
    #[test]
    fn or_cli8_onion_circuit_build_deterministic() {
        let out1 = run_cli(&args("onion-circuit-build --nodes 5"));
        let out2 = run_cli(&args("onion-circuit-build --nodes 5"));
        let v1: serde_json::Value = serde_json::from_str(&out1).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&out2).unwrap();
        assert_eq!(v1["hops"], v2["hops"]);
        assert_eq!(v1["status"], v2["status"]);
    }

    // OR-CLI9: legacy Sprint 19-23 commands unaffected by onion additions
    #[test]
    fn or_cli9_legacy_commands_unaffected() {
        let out = run_cli(&args("circuit-run --nodes 3 --rounds 5"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "circuit-run");
        assert_eq!(v["rounds"], 5);
    }

    // OR-SEC1: onion commands never produce "0.0.0.0" in output
    #[test]
    fn or_sec1_onion_commands_no_public_address() {
        let cmds = [
            "onion-circuit-build --nodes 5",
            "onion-send --nodes 5 --payload hello",
            "onion-simulate --nodes 5 --rounds 3",
        ];
        for cmd in &cmds {
            let out = run_cli(&args(cmd));
            assert!(
                !out.contains("0.0.0.0"),
                "onion command `{cmd}` must not output 0.0.0.0: {out}"
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sprint 25-30 — CLI integration tests
    // ─────────────────────────────────────────────────────────────────────────

    // SP25-CLI1: relay-cell-test returns roundtrip_ok=true
    #[test]
    fn sp25_cli1_relay_cell_test_json() {
        let out = run_cli(&args("relay-cell-test --payload hello"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "relay-cell-test");
        assert_eq!(v["roundtrip_ok"], true);
        assert_eq!(v["payload_len"], 5);
        assert_eq!(v["relay_command"], "RelayData");
    }

    // SP25-CLI2: relay-cell-test with empty payload
    #[test]
    fn sp25_cli2_relay_cell_empty_payload() {
        let out = run_cli(&args("relay-cell-test --payload "));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["roundtrip_ok"], true);
    }

    // SP26-CLI1: circuit-extend-test with 3 hops returns is_ready=true
    #[test]
    fn sp26_cli1_circuit_extend_test_json() {
        let out = run_cli(&args("circuit-extend-test --hops 3"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "circuit-extend-test");
        assert_eq!(v["hops"], 3);
        assert_eq!(v["is_ready"], true);
        assert_eq!(v["status"], "extended");
    }

    // SP26-CLI2: circuit-extend-test with < 3 hops returns error
    #[test]
    fn sp26_cli2_circuit_extend_too_few_hops() {
        let out = run_cli(&args("circuit-extend-test --hops 2"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("error").is_some());
    }

    // SP27-CLI1: path-select returns valid 3-hop path JSON
    #[test]
    fn sp27_cli1_path_select_json() {
        let out = run_cli(&args("path-select --nodes 9"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "path-select");
        assert_eq!(v["hops"], 3);
        assert_eq!(v["status"], "selected");
        assert!(
            v["guard"].as_u64().unwrap() % 3 == 0,
            "guard must have Guard role"
        );
        assert!(
            v["exit"].as_u64().unwrap() % 3 == 2,
            "exit must have Exit role"
        );
    }

    // SP27-CLI2: path-select with too few nodes returns error
    #[test]
    fn sp27_cli2_path_select_too_few_nodes() {
        let out = run_cli(&args("path-select --nodes 2"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("error").is_some());
    }

    // SP28-CLI1: directory-consensus returns epoch + role counts
    #[test]
    fn sp28_cli1_directory_consensus_json() {
        let out = run_cli(&args("directory-consensus --nodes 9 --epoch 5"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "directory-consensus");
        assert_eq!(v["epoch"], 5);
        assert_eq!(v["nodes"], 9);
        assert_eq!(v["guards"], 3);
        assert_eq!(v["relays"], 3);
        assert_eq!(v["exits"], 3);
        assert_eq!(v["status"], "built");
    }

    // SP29-CLI1: traffic-schedule returns drain count JSON
    #[test]
    fn sp29_cli1_traffic_schedule_json() {
        let out = run_cli(&args("traffic-schedule --real 5 --cover 3 --epochs 2"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "traffic-schedule");
        assert_eq!(v["epochs"], 2);
        assert_eq!(v["real_enqueued"], 5);
        assert_eq!(v["cover_enqueued"], 3);
        // All packets should have been drained across 2 epochs
        let drained = v["total_drained"].as_u64().unwrap();
        assert!(drained > 0);
    }

    // SP30-CLI1: adversarial-sim packet-size returns size_uniform=true
    #[test]
    fn sp30_cli1_adversarial_sim_packet_size() {
        let out = run_cli(&args("adversarial-sim --model packet-size --count 10"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "adversarial-sim");
        assert_eq!(v["size_uniform"], true);
        assert_eq!(v["replay_succeeded"], false);
        assert_eq!(v["packets_observed"], 10);
    }

    // SP30-CLI2: adversarial-sim replay model
    #[test]
    fn sp30_cli2_adversarial_sim_replay() {
        let out = run_cli(&args("adversarial-sim --model replay --count 2"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["replay_succeeded"], false);
    }

    // SP30-CLI3: adversarial-sim timing model
    #[test]
    fn sp30_cli3_adversarial_sim_timing() {
        let out = run_cli(&args("adversarial-sim --model timing --count 5"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["packets_observed"], 5);
    }

    // SP30-CLI4: unknown adversarial model returns error
    #[test]
    fn sp30_cli4_adversarial_sim_unknown_model() {
        let out = run_cli(&args("adversarial-sim --model bogus --count 1"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("error").is_some());
    }

    // All Sprint 25-30 commands produce valid JSON
    #[test]
    fn sp_all_commands_valid_json() {
        let cmds = [
            "relay-cell-test --payload test",
            "circuit-extend-test --hops 3",
            "path-select --nodes 9",
            "directory-consensus --nodes 9 --epoch 1",
            "traffic-schedule --real 3 --cover 2 --epochs 1",
            "adversarial-sim --model packet-size --count 5",
        ];
        for cmd in &cmds {
            let out = run_cli(&args(cmd));
            let parsed = serde_json::from_str::<serde_json::Value>(&out);
            assert!(parsed.is_ok(), "JSON parse failed for `{cmd}`: {out}");
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sprint 25-30 — Security hardening tests
    // ─────────────────────────────────────────────────────────────────────────

    // SEC25: relay unknown command rejected
    #[test]
    fn sec25_relay_unknown_command_rejected() {
        use crate::relay_cell::{RelayCell, RelayCommand};
        use crate::relay_cell_codec::{RELAY_HEADER_SIZE, decode_relay_cell, encode_relay_cell};
        let cell = RelayCell::new(1, 1, RelayCommand::RelayData, 0, b"x".to_vec());
        let mut encoded = encode_relay_cell(&cell).unwrap();
        encoded[16] = 200;
        assert!(decode_relay_cell(&encoded).is_err());
    }

    // SEC26: circuit duplicate hop rejected
    #[test]
    fn sec26_circuit_duplicate_hop_rejected() {
        use crate::circuit_extend_protocol::{
            CircuitExtendProtocol, ExtendError, make_ok_response,
        };
        let mut p = CircuitExtendProtocol::new(1, 10);
        p.begin_extend(20, 20).unwrap();
        p.handle_extend_response(&make_ok_response(1)).unwrap();
        assert_eq!(
            p.begin_extend(20, 20).unwrap_err(),
            ExtendError::DuplicateHop
        );
    }

    // SEC27: path duplicate node rejected
    #[test]
    fn sec27_path_duplicate_node_rejected() {
        use crate::path_selection::{PathSelectionError, PathSelectionPolicy, PathSelector};
        // Only 2 nodes available — can't build 3-hop without duplicates
        let p: Vec<_> = (1u64..=2)
            .map(|id| PeerDescriptor::deterministic(id, 45000))
            .collect();
        let sel = PathSelector::new(&p, PathSelectionPolicy::default());
        assert!(sel.select_path().is_err());
    }

    // SEC28: invalid consensus signature rejected
    #[test]
    fn sec28_invalid_consensus_signature_rejected() {
        use crate::directory_consensus::{
            ConsensusError, DirectoryAuthorityId, DirectoryConsensus, NodeDescriptor,
        };
        let auth = DirectoryAuthorityId(42);
        let c = DirectoryConsensus::new(1, auth);
        let mut s = c.sign_descriptor(NodeDescriptor::deterministic(3, 45000));
        s.signature ^= 0xFF;
        assert_eq!(
            DirectoryConsensus::verify_descriptor(&s).unwrap_err(),
            ConsensusError::InvalidSignature
        );
    }

    // SEC29: scheduler never exceeds max_real_per_epoch
    #[test]
    fn sec29_scheduler_never_exceeds_max_real() {
        use crate::traffic_scheduler::{SchedulerPolicy, TrafficKind, TrafficScheduler};
        let policy = SchedulerPolicy {
            max_real_per_epoch: 3,
            min_cover_per_epoch: 0,
            padding_floor: 0,
            ..SchedulerPolicy::default()
        };
        let mut s = TrafficScheduler::new(policy);
        for i in 0..20u8 {
            s.enqueue_real(vec![i]);
        }
        let drained = s.drain_epoch();
        let real_count = drained
            .iter()
            .filter(|p| p.kind == TrafficKind::Real)
            .count();
        assert!(real_count <= 3);
    }

    // SEC30: replay attacker never succeeds
    #[test]
    fn sec30_replay_attacker_rejected() {
        use crate::adversarial_simulator::run_replay_attempt;
        let result = run_replay_attempt();
        assert!(!result.replay_succeeded);
    }

    // SEC31: default config remains simulation-only
    #[test]
    fn sec31_default_config_simulation_only() {
        let cfg = config::NodeConfig::default();
        assert!(cfg.simulation_mode);
        assert!(!cfg.allow_real_udp);
    }

    // SEC32: no new Sprint 25-30 command outputs 0.0.0.0
    #[test]
    fn sec32_no_new_command_outputs_public_address() {
        let cmds = [
            "relay-cell-test --payload hello",
            "circuit-extend-test --hops 3",
            "path-select --nodes 9",
            "directory-consensus --nodes 9 --epoch 1",
            "traffic-schedule --real 3 --cover 2 --epochs 1",
            "adversarial-sim --model packet-size --count 5",
        ];
        for cmd in &cmds {
            let out = run_cli(&args(cmd));
            assert!(
                !out.contains("0.0.0.0"),
                "`{cmd}` must not output 0.0.0.0: {out}"
            );
        }
    }
}
