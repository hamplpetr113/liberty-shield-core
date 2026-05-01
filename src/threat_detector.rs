use std::collections::HashMap;
use std::sync::Mutex;

use crate::config::ShieldConfig;
use crate::engine::{Detector, SensorEvent, Severity, ThreatAlert};

pub struct ProcessThreatDetector {
    pid_map: Mutex<HashMap<u32, String>>,
    suspicious_names: Vec<String>,
    suspicious_lineage: Vec<(String, String)>,
    suspicious_name_score: u32,
    suspicious_lineage_score: u32,
}

impl ProcessThreatDetector {
    pub fn new(cfg: &ShieldConfig) -> Self {
        ProcessThreatDetector {
            pid_map: Mutex::new(HashMap::new()),
            suspicious_names: cfg.suspicious_process_names.clone(),
            suspicious_lineage: cfg.suspicious_lineage.clone(),
            suspicious_name_score: cfg.process_suspicious_name_score,
            suspicious_lineage_score: cfg.process_suspicious_lineage_score,
        }
    }
}

impl Detector for ProcessThreatDetector {
    fn name(&self) -> &str {
        "ProcessThreatDetector"
    }

    fn evaluate(&self, event: &SensorEvent) -> Option<ThreatAlert> {
        match event {
            SensorEvent::ProcessStarted {
                name,
                pid,
                parent_pid,
            } => {
                let mut map = self.pid_map.lock().unwrap();
                let parent_name = map.get(parent_pid).cloned().unwrap_or_default();
                map.insert(*pid, name.clone());
                drop(map);

                let parent_lc = parent_name.to_lowercase();
                let child_lc = name.to_lowercase();

                for (p, c) in &self.suspicious_lineage {
                    if parent_lc == p.as_str() && child_lc == c.as_str() {
                        return Some(ThreatAlert {
                            severity: Severity::Warning,
                            source: "ProcessThreatDetector".to_string(),
                            message: format!(
                                "[ALERT] suspicious process lineage: {} -> {}",
                                parent_name, name
                            ),
                            score: self.suspicious_lineage_score,
                        });
                    }
                }

                if self
                    .suspicious_names
                    .iter()
                    .any(|n| name.eq_ignore_ascii_case(n))
                {
                    Some(ThreatAlert {
                        severity: Severity::Critical,
                        source: self.name().to_string(),
                        message: format!("[ALERT] suspicious process {}", name),
                        score: self.suspicious_name_score,
                    })
                } else {
                    None
                }
            }
            SensorEvent::NetworkConnection { .. } => None,
        }
    }
}
