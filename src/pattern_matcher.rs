use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::engine::{AttackPattern, PatternAlert, SensorEvent};

const PATTERN_WINDOW: Duration = Duration::from_secs(60);

struct MinerState {
    saw_miner: Option<Instant>,
    saw_port:  Option<Instant>,
}

pub struct MinerPattern {
    state: Mutex<MinerState>,
}

impl MinerPattern {
    pub fn new() -> Self {
        MinerPattern {
            state: Mutex::new(MinerState { saw_miner: None, saw_port: None }),
        }
    }
}

impl AttackPattern for MinerPattern {
    fn name(&self) -> &str { "MinerPattern" }

    fn evaluate(&self, event: &SensorEvent) -> Option<PatternAlert> {
        let mut s = self.state.lock().unwrap();
        let now = Instant::now();

        if s.saw_miner.map_or(false, |t| now - t > PATTERN_WINDOW) { s.saw_miner = None; }
        if s.saw_port.map_or(false,  |t| now - t > PATTERN_WINDOW) { s.saw_port  = None; }

        match event {
            SensorEvent::ProcessStarted { name, .. }
                if name.eq_ignore_ascii_case("xmrig.exe") => { s.saw_miner = Some(now); }
            SensorEvent::NetworkConnection { remote_port, .. }
                if *remote_port == 4444 => { s.saw_port = Some(now); }
            _ => {}
        }

        if s.saw_miner.is_some() && s.saw_port.is_some() {
            s.saw_miner = None;
            s.saw_port  = None;
            Some(PatternAlert {
                pattern: "MinerPattern".to_string(),
                message: "[PATTERN] MinerPattern: xmrig.exe + connection to port 4444".to_string(),
            })
        } else {
            None
        }
    }
}

const BOTNET_THRESHOLD: usize = 2;
const SUSPICIOUS_C2_PORTS: [u16; 4] = [4444, 1337, 5555, 6666];

struct KeyloggerState {
    saw_process: Option<Instant>,
}

pub struct KeyloggerPattern {
    state: Mutex<KeyloggerState>,
}

impl KeyloggerPattern {
    pub fn new() -> Self {
        KeyloggerPattern {
            state: Mutex::new(KeyloggerState { saw_process: None }),
        }
    }
}

impl AttackPattern for KeyloggerPattern {
    fn name(&self) -> &str { "KeyloggerPattern" }

    fn evaluate(&self, event: &SensorEvent) -> Option<PatternAlert> {
        let mut s = self.state.lock().unwrap();
        let now = Instant::now();

        if s.saw_process.map_or(false, |t| now - t > PATTERN_WINDOW) {
            s.saw_process = None;
        }

        match event {
            SensorEvent::ProcessStarted { name, .. }
                if name.eq_ignore_ascii_case("keylogger.exe") => {
                s.saw_process = Some(now);
            }
            SensorEvent::NetworkConnection { remote_ip, .. } if s.saw_process.is_some() => {
                s.saw_process = None;
                return Some(PatternAlert {
                    pattern: "KeyloggerPattern".to_string(),
                    message: format!(
                        "[PATTERN] KeyloggerPattern: keylogger.exe followed by network connection to {} (suspected exfiltration)",
                        remote_ip
                    ),
                });
            }
            _ => {}
        }
        None
    }
}

struct BotnetState {
    recent: Vec<(Instant, String)>,
}

pub struct BotnetPattern {
    state: Mutex<BotnetState>,
}

impl BotnetPattern {
    pub fn new() -> Self {
        BotnetPattern {
            state: Mutex::new(BotnetState { recent: Vec::new() }),
        }
    }
}

impl AttackPattern for BotnetPattern {
    fn name(&self) -> &str { "BotnetPattern" }

    fn evaluate(&self, event: &SensorEvent) -> Option<PatternAlert> {
        let (remote_ip, remote_port) = match event {
            SensorEvent::NetworkConnection { remote_ip, remote_port, .. } => (remote_ip, remote_port),
            SensorEvent::ProcessStarted { .. } => return None,
        };

        if !SUSPICIOUS_C2_PORTS.contains(remote_port) {
            return None;
        }

        let mut s = self.state.lock().unwrap();
        let now = Instant::now();

        s.recent.retain(|(t, _)| now - *t <= PATTERN_WINDOW);
        if !s.recent.iter().any(|(_, ip)| ip == remote_ip) {
            s.recent.push((now, remote_ip.clone()));
        }

        if s.recent.len() >= BOTNET_THRESHOLD {
            let ips: Vec<String> = s.recent.iter().map(|(_, ip)| ip.clone()).collect();
            s.recent.clear();
            return Some(PatternAlert {
                pattern: "BotnetPattern".to_string(),
                message: format!(
                    "[PATTERN] BotnetPattern: C2 connections to {} hosts: {}",
                    ips.len(), ips.join(", ")
                ),
            });
        }
        None
    }
}
