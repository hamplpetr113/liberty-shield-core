#[derive(Debug, PartialEq)]
pub enum Command {
    Start,
    Status,
    Peers,
    ClusterStart {
        profile: String,
    },
    ClusterStatus {
        profile: String,
    },
    ClusterRun {
        profile: String,
        rounds: usize,
    },
    ClusterTopology {
        profile: String,
    },
    ClusterPeers {
        profile: String,
    },
    ClusterBench {
        profile: String,
        rounds: usize,
    },
    Run {
        node_count: usize,
        circuits: usize,
        rounds: usize,
    },
    Topology {
        node_count: usize,
    },
    Bench {
        node_count: usize,
        circuits: usize,
        rounds: usize,
    },
}

pub struct CliArgs {
    pub command: Command,
}

pub fn parse_args(args: &[String]) -> Result<CliArgs, String> {
    let cmd = args.first().map(String::as_str).unwrap_or("");
    match cmd {
        "start" => Ok(CliArgs {
            command: Command::Start,
        }),
        "status" => Ok(CliArgs {
            command: Command::Status,
        }),
        "peers" => Ok(CliArgs {
            command: Command::Peers,
        }),
        "cluster-start" => Ok(CliArgs {
            command: Command::ClusterStart {
                profile: extract_string(&args[1..], "--profile").unwrap_or("tiny".to_string()),
            },
        }),
        "cluster-status" => Ok(CliArgs {
            command: Command::ClusterStatus {
                profile: extract_string(&args[1..], "--profile").unwrap_or("tiny".to_string()),
            },
        }),
        "cluster-run" => Ok(CliArgs {
            command: Command::ClusterRun {
                profile: extract_string(&args[1..], "--profile").unwrap_or("tiny".to_string()),
                rounds: extract_usize(&args[1..], "--rounds").unwrap_or(100),
            },
        }),
        "cluster-topology" => Ok(CliArgs {
            command: Command::ClusterTopology {
                profile: extract_string(&args[1..], "--profile").unwrap_or("tiny".to_string()),
            },
        }),
        "cluster-peers" => Ok(CliArgs {
            command: Command::ClusterPeers {
                profile: extract_string(&args[1..], "--profile").unwrap_or("tiny".to_string()),
            },
        }),
        "cluster-bench" => Ok(CliArgs {
            command: Command::ClusterBench {
                profile: extract_string(&args[1..], "--profile").unwrap_or("medium".to_string()),
                rounds: extract_usize(&args[1..], "--rounds").unwrap_or(1000),
            },
        }),
        "run" => Ok(CliArgs {
            command: Command::Run {
                node_count: extract_usize(&args[1..], "--node-count").unwrap_or(100),
                circuits: extract_usize(&args[1..], "--circuits").unwrap_or(5),
                rounds: extract_usize(&args[1..], "--rounds").unwrap_or(100),
            },
        }),
        "topology" => Ok(CliArgs {
            command: Command::Topology {
                node_count: extract_usize(&args[1..], "--node-count").unwrap_or(100),
            },
        }),
        "bench" => Ok(CliArgs {
            command: Command::Bench {
                node_count: extract_usize(&args[1..], "--node-count").unwrap_or(100),
                circuits: extract_usize(&args[1..], "--circuits").unwrap_or(5),
                rounds: extract_usize(&args[1..], "--rounds").unwrap_or(1000),
            },
        }),
        "" => Err(
            "no command provided. Usage: liberty-node <start|status|peers|cluster-start|cluster-status|cluster-run|cluster-topology|cluster-peers|cluster-bench|run|topology|bench>"
                .to_string(),
        ),
        other => Err(format!(
            "unknown command: {other}. Usage: liberty-node <start|status|peers|cluster-start|cluster-status|cluster-run|cluster-topology|cluster-peers|cluster-bench|run|topology|bench>"
        )),
    }
}

fn extract_usize(args: &[String], flag: &str) -> Option<usize> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .and_then(|w| w[1].parse().ok())
}

fn extract_string(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}
