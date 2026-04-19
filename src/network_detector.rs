use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::ShieldConfig;
use crate::engine::{Detector, SensorEvent, Severity, ThreatAlert};

const REPEAT_THRESHOLD: u32 = 3;
const SCAN_THRESHOLD: u32 = 20;

struct State {
    recent: Vec<(Instant, String)>,
}

pub struct NetworkThreatDetector {
    state: Mutex<State>,
    suspicious_ports: Vec<u16>,
}

impl NetworkThreatDetector {
    pub fn new(cfg: &ShieldConfig) -> Self {
        NetworkThreatDetector {
            state: Mutex::new(State { recent: Vec::new() }),
            suspicious_ports: cfg.suspicious_ports.clone(),
        }
    }
}

impl Detector for NetworkThreatDetector {
    fn name(&self) -> &str {
        "NetworkThreatDetector"
    }

    fn evaluate(&self, event: &SensorEvent) -> Option<ThreatAlert> {
        let (remote_ip, remote_port) = match event {
            SensorEvent::NetworkConnection { remote_ip, remote_port, .. } => (remote_ip, remote_port),
            SensorEvent::ProcessStarted { .. } => return None,
        };

        let window = Duration::from_secs(60);
        let mut s = self.state.lock().unwrap();

        let cutoff = Instant::now() - window;
        s.recent.retain(|(t, _)| *t >= cutoff);

        s.recent.push((Instant::now(), remote_ip.clone()));

        let ip_count = s.recent.iter().filter(|(_, ip)| ip == remote_ip).count() as u32;
        let total = s.recent.len() as u32;

        if self.suspicious_ports.contains(remote_port) {
            return Some(ThreatAlert {
                severity: Severity::Critical,
                source: "NetworkThreatDetector".to_string(),
                message: format!("[ALERT] connection to suspicious port {} ({})", remote_port, remote_ip),
                score: 40,
            });
        }

        if ip_count == REPEAT_THRESHOLD {
            return Some(ThreatAlert {
                severity: Severity::Warning,
                source: "NetworkThreatDetector".to_string(),
                message: format!("[ALERT] repeated connections from {} ({} in 60s)", remote_ip, ip_count),
                score: 20,
            });
        }

        if total == SCAN_THRESHOLD {
            return Some(ThreatAlert {
                severity: Severity::Info,
                source: "NetworkThreatDetector".to_string(),
                message: format!("[ALERT] high connection volume: {} connections in 60s", total),
                score: 0,
            });
        }

        None
    }
}