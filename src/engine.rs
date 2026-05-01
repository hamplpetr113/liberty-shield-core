use crate::behavior_graph::BehaviorGraph;
use crate::config::ShieldConfig;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub enum SensorEvent {
    ProcessStarted {
        name: String,
        pid: u32,
        parent_pid: u32,
    },
    NetworkConnection {
        remote_ip: String,
        remote_port: u16,
        pid: Option<u32>,
    },
}

pub enum Severity {
    Info,
    Warning,
    Critical,
}

pub struct ThreatAlert {
    pub severity: Severity,
    pub source: String,
    pub message: String,
    pub score: u32,
}

pub struct ThreatScore {
    pub score: u32,
    last_event: Option<Instant>,
}

pub trait Sensor: Send + 'static {
    fn name(&self) -> &str;
    fn run(self, tx: mpsc::Sender<SensorEvent>);
}

pub trait Detector: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, event: &SensorEvent) -> Option<ThreatAlert>;
}

pub trait Sink: Send + Sync {
    fn emit(&self, alert: &ThreatAlert);
}

pub struct PatternAlert {
    pub pattern: String,
    pub message: String,
}

pub trait AttackPattern: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, event: &SensorEvent) -> Option<PatternAlert>;
}

pub struct ShieldEngine {
    detectors: Vec<Box<dyn Detector>>,
    sinks: Vec<Box<dyn Sink>>,
    score: Mutex<ThreatScore>,
    patterns: Vec<Box<dyn AttackPattern>>,
    graph: Arc<Mutex<BehaviorGraph>>,
    threshold: u32,
    attack_window: Duration,
    pattern_match_score: u32,
}

impl ShieldEngine {
    pub fn new(cfg: &ShieldConfig) -> Self {
        ShieldEngine {
            detectors: Vec::new(),
            sinks: Vec::new(),
            score: Mutex::new(ThreatScore {
                score: 0,
                last_event: None,
            }),
            patterns: Vec::new(),
            graph: Arc::new(Mutex::new(BehaviorGraph::new())),
            threshold: cfg.threat_score_threshold,
            attack_window: Duration::from_secs(cfg.engine_attack_window_secs),
            pattern_match_score: cfg.pattern_match_score,
        }
    }

    pub fn graph_handle(&self) -> Arc<Mutex<BehaviorGraph>> {
        Arc::clone(&self.graph)
    }

    pub fn add_detector(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    pub fn add_sink(&mut self, sink: Box<dyn Sink>) {
        self.sinks.push(sink);
    }

    pub fn add_pattern(&mut self, pattern: Box<dyn AttackPattern>) {
        self.patterns.push(pattern);
    }

    pub fn handle(&self, event: SensorEvent) {
        match &event {
            SensorEvent::ProcessStarted {
                name,
                pid,
                parent_pid,
            } => {
                self.graph
                    .lock()
                    .unwrap()
                    .add_process(*parent_pid, *pid, name.clone());
            }
            SensorEvent::NetworkConnection {
                remote_ip,
                remote_port,
                pid,
            } => {
                self.graph.lock().unwrap().add_network_connection(
                    remote_ip.clone(),
                    *remote_port,
                    *pid,
                );
            }
        }
        for detector in &self.detectors {
            if let Some(alert) = detector.evaluate(&event) {
                let crossed = {
                    let mut ts = self.score.lock().unwrap();
                    let now = Instant::now();
                    if let Some(last) = ts.last_event {
                        if now - last > self.attack_window {
                            ts.score = 0;
                        }
                    }
                    ts.score += alert.score;
                    ts.last_event = Some(now);
                    if ts.score >= self.threshold {
                        let total = ts.score;
                        ts.score = 0;
                        ts.last_event = None;
                        Some(total)
                    } else {
                        None
                    }
                };
                for sink in &self.sinks {
                    sink.emit(&alert);
                }
                if let Some(total) = crossed {
                    let composite = ThreatAlert {
                        severity: Severity::Critical,
                        source: "ThreatScore".to_string(),
                        message: format!(
                            "[ALERT] threat score {} exceeded threshold ({})",
                            total, self.threshold
                        ),
                        score: 0,
                    };
                    for sink in &self.sinks {
                        sink.emit(&composite);
                    }
                }
            }
        }
        for pattern in &self.patterns {
            if let Some(palert) = pattern.evaluate(&event) {
                let threat = ThreatAlert {
                    severity: Severity::Critical,
                    source: palert.pattern,
                    message: palert.message,
                    score: self.pattern_match_score,
                };
                for sink in &self.sinks {
                    sink.emit(&threat);
                }
                let mut ts = self.score.lock().unwrap();
                let now = Instant::now();
                if ts
                    .last_event
                    .map_or(false, |t| now - t > self.attack_window)
                {
                    ts.score = 0;
                }
                ts.score += self.pattern_match_score;
                ts.last_event = Some(now);
            }
        }
    }

    pub fn run(&self, rx: mpsc::Receiver<SensorEvent>) {
        for event in rx {
            self.handle(event);
        }
    }
}
