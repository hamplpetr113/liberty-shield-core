use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::behavior_graph::BehaviorGraph;
use crate::engine::{Detector, SensorEvent, Severity, ThreatAlert};

const SHELL_PROCESSES: [&str; 4] = ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"];
const COOLDOWN: Duration = Duration::from_secs(60);
const PID_TTL: Duration  = Duration::from_secs(300);

fn is_shell_like(name: &str) -> bool {
    SHELL_PROCESSES.iter().any(|s| name.eq_ignore_ascii_case(s))
}

fn is_safe_destination(ip: &str, port: u16) -> bool {
    if port == 53 { return true; }
    if ip == "::1" { return true; }
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 { return false; }
    match octets[0] {
        "127" => true,
        "10"  => true,
        "192" if octets[1] == "168" => true,
        "172" => octets[1].parse::<u8>().map_or(false, |n| (16..=31).contains(&n)),
        _ => false,
    }
}

pub struct LateralMovementDetector {
    graph: Arc<Mutex<BehaviorGraph>>,
    pid_names: Mutex<HashMap<u32, (String, Instant)>>,
    alerted: Mutex<HashMap<u32, Instant>>,
}

impl LateralMovementDetector {
    pub fn new(graph: Arc<Mutex<BehaviorGraph>>) -> Self {
        LateralMovementDetector {
            graph,
            pid_names: Mutex::new(HashMap::new()),
            alerted: Mutex::new(HashMap::new()),
        }
    }
}

impl Detector for LateralMovementDetector {
    fn name(&self) -> &str { "LateralMovementDetector" }

    fn evaluate(&self, event: &SensorEvent) -> Option<ThreatAlert> {
        match event {
            SensorEvent::ProcessStarted { name, pid, .. } => {
                let now = Instant::now();
                {
                    let mut names = self.pid_names.lock().unwrap();
                    names.retain(|_, (_, t)| now.saturating_duration_since(*t) < PID_TTL);
                    names.insert(*pid, (name.clone(), now));
                }
                self.alerted.lock().unwrap().retain(|_, t| now.saturating_duration_since(*t) < COOLDOWN);
                None
            }
            SensorEvent::NetworkConnection { pid, .. } => {
                let p = (*pid)?;
                let name = {
                    let names = self.pid_names.lock().unwrap();
                    names.get(&p).map(|(n, _)| n.clone())?
                };
                if !is_shell_like(&name) {
                    return None;
                }
                let (child_count, suspicious_count) = {
                    let graph = self.graph.lock().unwrap();
                    let children = graph.children_of(p);
                    let connections = graph.connections_of(p);
                    let suspicious = connections.into_iter()
                        .filter(|(ip, port)| !is_safe_destination(ip, *port))
                        .collect::<Vec<_>>();
                    if children.is_empty() || suspicious.is_empty() {
                        return None;
                    }
                    (children.len(), suspicious.len())
                };
                {
                    let mut alerted = self.alerted.lock().unwrap();
                    let now = Instant::now();
                    if let Some(&last) = alerted.get(&p) {
                        if now.saturating_duration_since(last) < COOLDOWN {
                            return None;
                        }
                    }
                    alerted.insert(p, now);
                }
                Some(ThreatAlert {
                    severity: Severity::Critical,
                    source: "LateralMovementDetector".to_string(),
                    message: format!(
                        "[ALERT] lateral movement: {} (pid {}) has {} child process(es) and {} suspicious outbound connection(s)",
                        name, p, child_count, suspicious_count
                    ),
                    score: 50,
                })
            }
        }
    }
}
