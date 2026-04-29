pub mod args;
pub mod config;
pub mod identity;
pub mod node_runtime;
pub mod node_service;
pub mod output;
pub mod peer_table;
pub mod runtime_state;

use args::{Command, parse_args};
use config::NodeConfig;
use node_runtime::NodeRuntime;
use node_service::NodeService;
use output::{
    bench_json, metrics_json, peers_json, service_error_json, start_json, status_json,
    topology_json,
};

pub fn run_cli(args: &[String]) -> String {
    match parse_args(args) {
        Ok(cli_args) => execute(cli_args.command),
        Err(e) => serde_json::json!({ "error": e }).to_string(),
    }
}

fn execute(cmd: Command) -> String {
    match cmd {
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
    use runtime_state::NodeServiceState;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    // ── N1: run defaults produces valid JSON with metrics key ─────────────────

    #[test]
    fn n1_run_defaults_produces_metrics_json() {
        let out = run_cli(&args("run"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("metrics").is_some());
        assert_eq!(v["node_count"], 100);
        assert_eq!(v["circuits"], 5);
        assert_eq!(v["rounds"], 100);
    }

    // ── N2: topology 100 nodes — correct role counts ──────────────────────────

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

    // ── N3: run 50 rounds — all delivered, zero drops, avg_path = 3.0 ─────────

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

    // ── N4: bench produces elapsed_us and throughput keys ─────────────────────

    #[test]
    fn n4_bench_has_timing_keys() {
        let out = run_cli(&args("bench --rounds 100"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("elapsed_us").is_some());
        assert!(v.get("throughput_packets_per_sec").is_some());
        assert_eq!(v["rounds"], 100);
    }

    // ── N5: unknown command returns JSON error ────────────────────────────────

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

    // ── N6: run 0 rounds — no panic, zero metrics ─────────────────────────────

    #[test]
    fn n6_run_zero_rounds_no_panic() {
        let out = run_cli(&args("run --rounds 0"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let m = &v["metrics"];
        assert_eq!(m["packets_sent"], 0);
        assert_eq!(m["paths_completed"], 0);
        assert_eq!(m["packets_dropped"], 0);
    }

    // ── N7: topology 50 nodes — 5 guards, 40 relays, 5 exits ─────────────────

    #[test]
    fn n7_topology_50_nodes() {
        let out = run_cli(&args("topology --node-count 50"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["node_count"], 50);
        assert_eq!(v["guard_count"], 5);
        assert_eq!(v["relay_count"], 40);
        assert_eq!(v["exit_count"], 5);
    }

    // ── N8: NodeRuntime topology_summary correct for 100 nodes ───────────────

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

    // ── N9: NodeRuntime::run_rounds returns correct RunResult ─────────────────

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

    // ── N10: 1000 rounds — packets_forwarded == 3 × packets_sent ─────────────

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

    // ── CLI1: start returns JSON with state=Running ───────────────────────────

    #[test]
    fn cli1_start_returns_running_json() {
        let out = run_cli(&args("start"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "start");
        assert_eq!(v["state"], "Running");
        assert_eq!(v["simulation_mode"], true);
        assert_eq!(v["node_id"], 1);
    }

    // ── CLI2: status returns JSON with state=Created ──────────────────────────

    #[test]
    fn cli2_status_returns_created_json() {
        let out = run_cli(&args("status"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "status");
        assert_eq!(v["state"], "Created");
        assert_eq!(v["simulation_mode"], true);
    }

    // ── CLI3: peers returns JSON with empty peers array ───────────────────────

    #[test]
    fn cli3_peers_returns_empty_array() {
        let out = run_cli(&args("peers"));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["command"], "peers");
        assert!(v["peers"].as_array().unwrap().is_empty());
    }

    // ── CLI4: invalid config error propagates to JSON ─────────────────────────

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

    // ── CLI5: existing run/topology/bench tests still pass ────────────────────

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

    // ── NodeService state tests also live here for integration coverage ────────

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
}
