pub mod args;
pub mod cluster_manager;
pub mod cluster_metrics;
pub mod cluster_packet_flow;
pub mod cluster_peering;
pub mod cluster_topology;
pub mod cluster_types;
pub mod config;
pub mod identity;
pub mod node_runtime;
pub mod node_service;
pub mod output;
pub mod peer_table;
pub mod runtime_state;

use args::{Command, parse_args};
use cluster_manager::LocalCluster;
use cluster_topology::{build_cluster_configs, parse_profile};
use config::NodeConfig;
use node_runtime::NodeRuntime;
use node_service::NodeService;
use output::{
    bench_json, cluster_bench_json, cluster_error_json, cluster_peers_json, cluster_run_json,
    cluster_start_json, cluster_status_json, cluster_topology_json, metrics_json, peers_json,
    service_error_json, start_json, status_json, topology_json,
};

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
}
