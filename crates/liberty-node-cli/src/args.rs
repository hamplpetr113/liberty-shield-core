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
    UdpTestnetStart {
        nodes: usize,
        base_port: u16,
    },
    UdpTestnetProbe {
        nodes: usize,
        base_port: u16,
    },
    UdpTestnetData {
        nodes: usize,
        base_port: u16,
        payload: String,
    },
    UdpTestnetStatus {
        nodes: usize,
        base_port: u16,
    },
    UdpTestnetBench {
        nodes: usize,
        base_port: u16,
        rounds: usize,
    },
    EncryptedUdpStart {
        nodes: usize,
        base_port: u16,
    },
    EncryptedUdpProbe {
        nodes: usize,
        base_port: u16,
    },
    EncryptedUdpSend {
        nodes: usize,
        base_port: u16,
        payload: String,
    },
    EncryptedUdpStatus {
        nodes: usize,
        base_port: u16,
    },
    EncryptedUdpBench {
        nodes: usize,
        base_port: u16,
        rounds: usize,
    },
    HandshakeRing {
        nodes: usize,
        base_port: u16,
    },
    CircuitRun {
        nodes: usize,
        base_port: u16,
        rounds: usize,
    },
    CircuitStatus {
        nodes: usize,
        base_port: u16,
    },
    DirectoryStatus {
        node_count: usize,
    },
    CoverTrafficRun {
        node_id: u64,
        seed: u64,
        count: usize,
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
        "udp-testnet-start" => Ok(CliArgs {
            command: Command::UdpTestnetStart {
                nodes: extract_usize(&args[1..], "--nodes").unwrap_or(3),
                base_port: extract_usize(&args[1..], "--base-port")
                    .map(|p| p as u16)
                    .unwrap_or(41000),
            },
        }),
        "udp-testnet-probe" => Ok(CliArgs {
            command: Command::UdpTestnetProbe {
                nodes: extract_usize(&args[1..], "--nodes").unwrap_or(3),
                base_port: extract_usize(&args[1..], "--base-port")
                    .map(|p| p as u16)
                    .unwrap_or(41000),
            },
        }),
        "udp-testnet-data" => Ok(CliArgs {
            command: Command::UdpTestnetData {
                nodes: extract_usize(&args[1..], "--nodes").unwrap_or(3),
                base_port: extract_usize(&args[1..], "--base-port")
                    .map(|p| p as u16)
                    .unwrap_or(41000),
                payload: extract_string(&args[1..], "--payload").unwrap_or_default(),
            },
        }),
        "udp-testnet-status" => Ok(CliArgs {
            command: Command::UdpTestnetStatus {
                nodes: extract_usize(&args[1..], "--nodes").unwrap_or(3),
                base_port: extract_usize(&args[1..], "--base-port")
                    .map(|p| p as u16)
                    .unwrap_or(41000),
            },
        }),
        "udp-testnet-bench" => Ok(CliArgs {
            command: Command::UdpTestnetBench {
                nodes: extract_usize(&args[1..], "--nodes").unwrap_or(5),
                base_port: extract_usize(&args[1..], "--base-port")
                    .map(|p| p as u16)
                    .unwrap_or(41100),
                rounds: extract_usize(&args[1..], "--rounds").unwrap_or(100),
            },
        }),
        "encrypted-udp-start" => Ok(CliArgs {
            command: Command::EncryptedUdpStart {
                nodes: extract_usize(&args[1..], "--nodes").unwrap_or(3),
                base_port: extract_usize(&args[1..], "--base-port")
                    .map(|p| p as u16)
                    .unwrap_or(43000),
            },
        }),
        "encrypted-udp-probe" => Ok(CliArgs {
            command: Command::EncryptedUdpProbe {
                nodes: extract_usize(&args[1..], "--nodes").unwrap_or(3),
                base_port: extract_usize(&args[1..], "--base-port")
                    .map(|p| p as u16)
                    .unwrap_or(43000),
            },
        }),
        "encrypted-udp-send" => Ok(CliArgs {
            command: Command::EncryptedUdpSend {
                nodes: extract_usize(&args[1..], "--nodes").unwrap_or(3),
                base_port: extract_usize(&args[1..], "--base-port")
                    .map(|p| p as u16)
                    .unwrap_or(43000),
                payload: extract_string(&args[1..], "--payload").unwrap_or_default(),
            },
        }),
        "encrypted-udp-status" => Ok(CliArgs {
            command: Command::EncryptedUdpStatus {
                nodes: extract_usize(&args[1..], "--nodes").unwrap_or(3),
                base_port: extract_usize(&args[1..], "--base-port")
                    .map(|p| p as u16)
                    .unwrap_or(43000),
            },
        }),
        "encrypted-udp-bench" => Ok(CliArgs {
            command: Command::EncryptedUdpBench {
                nodes: extract_usize(&args[1..], "--nodes").unwrap_or(5),
                base_port: extract_usize(&args[1..], "--base-port")
                    .map(|p| p as u16)
                    .unwrap_or(43100),
                rounds: extract_usize(&args[1..], "--rounds").unwrap_or(100),
            },
        }),
        "handshake-ring" => Ok(CliArgs {
            command: Command::HandshakeRing {
                nodes: extract_usize(&args[1..], "--nodes").unwrap_or(3),
                base_port: extract_usize(&args[1..], "--base-port")
                    .map(|p| p as u16)
                    .unwrap_or(44300),
            },
        }),
        "circuit-run" => Ok(CliArgs {
            command: Command::CircuitRun {
                nodes: extract_usize(&args[1..], "--nodes").unwrap_or(3),
                base_port: extract_usize(&args[1..], "--base-port")
                    .map(|p| p as u16)
                    .unwrap_or(44310),
                rounds: extract_usize(&args[1..], "--rounds").unwrap_or(10),
            },
        }),
        "circuit-status" => Ok(CliArgs {
            command: Command::CircuitStatus {
                nodes: extract_usize(&args[1..], "--nodes").unwrap_or(3),
                base_port: extract_usize(&args[1..], "--base-port")
                    .map(|p| p as u16)
                    .unwrap_or(44320),
            },
        }),
        "directory-status" => Ok(CliArgs {
            command: Command::DirectoryStatus {
                node_count: extract_usize(&args[1..], "--node-count").unwrap_or(10),
            },
        }),
        "cover-traffic-run" => Ok(CliArgs {
            command: Command::CoverTrafficRun {
                node_id: extract_usize(&args[1..], "--node-id")
                    .unwrap_or(1) as u64,
                seed: extract_usize(&args[1..], "--seed")
                    .unwrap_or(0xABCD) as u64,
                count: extract_usize(&args[1..], "--count").unwrap_or(5),
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
            "no command provided. Usage: liberty-node <start|status|peers|cluster-start|cluster-status|cluster-run|cluster-topology|cluster-peers|cluster-bench|udp-testnet-start|udp-testnet-probe|udp-testnet-data|udp-testnet-status|udp-testnet-bench|encrypted-udp-start|encrypted-udp-probe|encrypted-udp-send|encrypted-udp-status|encrypted-udp-bench|handshake-ring|circuit-run|circuit-status|directory-status|cover-traffic-run|run|topology|bench>"
                .to_string(),
        ),
        other => Err(format!(
            "unknown command: {other}. Usage: liberty-node <start|status|peers|cluster-start|cluster-status|cluster-run|cluster-topology|cluster-peers|cluster-bench|udp-testnet-start|udp-testnet-probe|udp-testnet-data|udp-testnet-status|udp-testnet-bench|encrypted-udp-start|encrypted-udp-probe|encrypted-udp-send|encrypted-udp-status|encrypted-udp-bench|handshake-ring|circuit-run|circuit-status|directory-status|cover-traffic-run|run|topology|bench>"
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
