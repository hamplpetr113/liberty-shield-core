#[derive(Debug, PartialEq)]
pub enum Command {
    Start,
    Status,
    Peers,
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
            "no command provided. Usage: liberty-node <start|status|peers|run|topology|bench>"
                .to_string(),
        ),
        other => Err(format!(
            "unknown command: {other}. Usage: liberty-node <start|status|peers|run|topology|bench>"
        )),
    }
}

fn extract_usize(args: &[String], flag: &str) -> Option<usize> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .and_then(|w| w[1].parse().ok())
}
