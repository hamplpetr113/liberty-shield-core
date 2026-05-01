use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::config::ShieldConfig;
use crate::engine::{AttackPattern, PatternAlert, SensorEvent};

const PATTERN_WINDOW: Duration = Duration::from_secs(60);

struct MinerState {
    saw_miner: Option<Instant>,
    saw_port: Option<Instant>,
}

pub struct MinerPattern {
    state: Mutex<MinerState>,
    keywords: Vec<String>,
    ports: Vec<u16>,
}

impl MinerPattern {
    pub fn new(cfg: &ShieldConfig) -> Self {
        MinerPattern {
            state: Mutex::new(MinerState {
                saw_miner: None,
                saw_port: None,
            }),
            keywords: cfg.pattern_miner_keywords.clone(),
            ports: cfg.pattern_miner_ports.clone(),
        }
    }
}

impl AttackPattern for MinerPattern {
    fn name(&self) -> &str {
        "MinerPattern"
    }

    fn evaluate(&self, event: &SensorEvent) -> Option<PatternAlert> {
        let mut s = self.state.lock().unwrap();
        let now = Instant::now();

        if s.saw_miner.map_or(false, |t| now - t > PATTERN_WINDOW) {
            s.saw_miner = None;
        }
        if s.saw_port.map_or(false, |t| now - t > PATTERN_WINDOW) {
            s.saw_port = None;
        }

        match event {
            SensorEvent::ProcessStarted { name, .. } => {
                if self.keywords.iter().any(|k| name.eq_ignore_ascii_case(k)) {
                    s.saw_miner = Some(now);
                }
            }
            SensorEvent::NetworkConnection { remote_port, .. } => {
                if self.ports.contains(remote_port) {
                    s.saw_port = Some(now);
                }
            }
        }

        if s.saw_miner.is_some() && s.saw_port.is_some() {
            s.saw_miner = None;
            s.saw_port = None;
            Some(PatternAlert {
                pattern: "MinerPattern".to_string(),
                message: "[PATTERN] MinerPattern: miner process + connection to mining port"
                    .to_string(),
            })
        } else {
            None
        }
    }
}

struct KeyloggerState {
    saw_process: Option<Instant>,
}

pub struct KeyloggerPattern {
    state: Mutex<KeyloggerState>,
    keywords: Vec<String>,
}

impl KeyloggerPattern {
    pub fn new(cfg: &ShieldConfig) -> Self {
        KeyloggerPattern {
            state: Mutex::new(KeyloggerState { saw_process: None }),
            keywords: cfg.pattern_keylogger_keywords.clone(),
        }
    }
}

impl AttackPattern for KeyloggerPattern {
    fn name(&self) -> &str {
        "KeyloggerPattern"
    }

    fn evaluate(&self, event: &SensorEvent) -> Option<PatternAlert> {
        let mut s = self.state.lock().unwrap();
        let now = Instant::now();

        if s.saw_process.map_or(false, |t| now - t > PATTERN_WINDOW) {
            s.saw_process = None;
        }

        match event {
            SensorEvent::ProcessStarted { name, .. } => {
                if self.keywords.iter().any(|k| name.eq_ignore_ascii_case(k)) {
                    s.saw_process = Some(now);
                }
            }
            SensorEvent::NetworkConnection { remote_ip, .. } => {
                if s.saw_process.is_some() {
                    s.saw_process = None;
                    return Some(PatternAlert {
                        pattern: "KeyloggerPattern".to_string(),
                        message: format!(
                            "[PATTERN] KeyloggerPattern: keylogger process followed by network connection to {} (suspected exfiltration)",
                            remote_ip
                        ),
                    });
                }
            }
        }
        None
    }
}

struct BotnetState {
    recent: Vec<(Instant, String)>,
}

pub struct BotnetPattern {
    state: Mutex<BotnetState>,
    ports: Vec<u16>,
    host_threshold: usize,
}

impl BotnetPattern {
    pub fn new(cfg: &ShieldConfig) -> Self {
        BotnetPattern {
            state: Mutex::new(BotnetState { recent: Vec::new() }),
            ports: cfg.pattern_botnet_ports.clone(),
            host_threshold: cfg.pattern_botnet_host_threshold as usize,
        }
    }
}

impl AttackPattern for BotnetPattern {
    fn name(&self) -> &str {
        "BotnetPattern"
    }

    fn evaluate(&self, event: &SensorEvent) -> Option<PatternAlert> {
        let (remote_ip, remote_port) = match event {
            SensorEvent::NetworkConnection {
                remote_ip,
                remote_port,
                ..
            } => (remote_ip, remote_port),
            SensorEvent::ProcessStarted { .. } => return None,
        };

        if !self.ports.contains(remote_port) {
            return None;
        }

        let mut s = self.state.lock().unwrap();
        let now = Instant::now();

        s.recent.retain(|(t, _)| now - *t <= PATTERN_WINDOW);
        if !s.recent.iter().any(|(_, ip)| ip == remote_ip) {
            s.recent.push((now, remote_ip.clone()));
        }

        if s.recent.len() >= self.host_threshold {
            let ips: Vec<String> = s.recent.iter().map(|(_, ip)| ip.clone()).collect();
            s.recent.clear();
            return Some(PatternAlert {
                pattern: "BotnetPattern".to_string(),
                message: format!(
                    "[PATTERN] BotnetPattern: C2 connections to {} hosts: {}",
                    ips.len(),
                    ips.join(", ")
                ),
            });
        }
        None
    }
}
