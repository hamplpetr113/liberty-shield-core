use std::collections::HashMap;
use std::sync::Mutex;

use crate::engine::{Detector, SensorEvent, Severity, ThreatAlert};

const SUSPICIOUS_LINEAGE: [(&str, &str); 3] = [
    ("powershell.exe", "cmd.exe"),
    ("powershell.exe", "wscript.exe"),
    ("powershell.exe", "mshta.exe"),
];

pub struct ProcessThreatDetector {
    pid_map: Mutex<HashMap<u32, String>>,
}

impl ProcessThreatDetector {
    pub fn new() -> Self {
        ProcessThreatDetector {
            pid_map: Mutex::new(HashMap::new()),
        }
    }
}

impl Detector for ProcessThreatDetector {
    fn name(&self) -> &str {
        "ProcessThreatDetector"
    }

    fn evaluate(&self, event: &SensorEvent) -> Option<ThreatAlert> {
        match event {
            SensorEvent::ProcessStarted { name, pid, parent_pid } => {
                let mut map = self.pid_map.lock().unwrap();
                let parent_name = map.get(parent_pid).cloned().unwrap_or_default();
                map.insert(*pid, name.clone());
                drop(map);

                let parent_lc = parent_name.to_lowercase();
                let child_lc = name.to_lowercase();

                for (p, c) in &SUSPICIOUS_LINEAGE {
                    if parent_lc == *p && child_lc == *c {
                        return Some(ThreatAlert {
                            severity: Severity::Warning,
                            source: "ProcessThreatDetector".to_string(),
                            message: format!(
                                "[ALERT] suspicious process lineage: {} -> {}",
                                parent_name, name
                            ),
                            score: 30,
                        });
                    }
                }

                if is_suspicious(name) {
                    Some(ThreatAlert {
                        severity: Severity::Critical,
                        source: self.name().to_string(),
                        message: format!("[ALERT] suspicious process {}", name),
                        score: 40,
                    })
                } else {
                    None
                }
            }
            SensorEvent::NetworkConnection { .. } => None,
        }
    }
}

pub fn is_suspicious(process_name: &str) -> bool {
    let suspicious = [
        "xmrig.exe",
        "miner.exe",
        "keylogger.exe",
        "mimikatz.exe",
        "hacktool.exe",
        "rat.exe",
        "trojan.exe",
    ];

    suspicious
        .iter()
        .any(|name| process_name.eq_ignore_ascii_case(name))
}
