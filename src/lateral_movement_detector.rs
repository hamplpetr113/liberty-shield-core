use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::behavior_graph::BehaviorGraph;
use crate::config::ShieldConfig;
use crate::engine::{Detector, SensorEvent, Severity, ThreatAlert};

const PID_TTL: Duration = Duration::from_secs(300);

pub struct LateralMovementDetector {
    graph: Arc<Mutex<BehaviorGraph>>,
    pid_names: Mutex<HashMap<u32, (String, Instant)>>,
    alerted: Mutex<HashMap<u32, Instant>>,
    shell_processes: Vec<String>,
    cooldown: Duration,
    safe_ports: Vec<u16>,
    safe_ip_prefixes: Vec<String>,
    safe_172_range: (u8, u8),
}

impl LateralMovementDetector {
    pub fn new(graph: Arc<Mutex<BehaviorGraph>>, cfg: &ShieldConfig) -> Self {
        LateralMovementDetector {
            graph,
            pid_names: Mutex::new(HashMap::new()),
            alerted: Mutex::new(HashMap::new()),
            shell_processes: cfg.lateral_shell_processes.clone(),
            cooldown: cfg.lateral_cooldown,
            safe_ports: cfg.safe_ports.clone(),
            safe_ip_prefixes: cfg.safe_ip_prefixes.clone(),
            safe_172_range: cfg.safe_172_range,
        }
    }

    fn is_shell_like(&self, name: &str) -> bool {
        self.shell_processes.iter().any(|s| name.eq_ignore_ascii_case(s))
    }

    fn is_safe_destination(&self, ip: &str, port: u16) -> bool {
        if self.safe_ports.contains(&port) { return true; }
        if self.safe_ip_prefixes.iter().any(|p| ip.starts_with(p.as_str()) || ip == p.as_str()) {
            return true;
        }
        if ip.split('.').next() == Some("172") {
            if let Some(second) = ip.split('.').nth(1) {
                if let Ok(n) = second.parse::<u8>() {
                    let (lo, hi) = self.safe_172_range;
                    return (lo..=hi).contains(&n);
                }
            }
        }
        false
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
                self.alerted.lock().unwrap().retain(|_, t| now.saturating_duration_since(*t) < self.cooldown);
                None
            }
            SensorEvent::NetworkConnection { pid, .. } => {
                let p = (*pid)?;
                let name = {
                    let names = self.pid_names.lock().unwrap();
                    names.get(&p).map(|(n, _)| n.clone())?
                };
                if !self.is_shell_like(&name) {
                    return None;
                }
                let (child_count, suspicious_count) = {
                    let graph = self.graph.lock().unwrap();
                    let children = graph.children_of(p);
                    let connections = graph.connections_of(p);
                    let suspicious = connections.into_iter()
                        .filter(|(ip, port)| !self.is_safe_destination(ip, *port))
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
                        if now.saturating_duration_since(last) < self.cooldown {
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
