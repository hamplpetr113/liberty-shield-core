use crate::engine::{Detector, SensorEvent, Severity, ThreatAlert};

pub struct ProcessThreatDetector;

impl Detector for ProcessThreatDetector {
    fn name(&self) -> &str {
        "ProcessThreatDetector"
    }

    fn evaluate(&self, event: &SensorEvent) -> Option<ThreatAlert> {
        match event {
            SensorEvent::ProcessStarted { name, .. } => {
                if is_suspicious(name) {
                    Some(ThreatAlert {
                        severity: Severity::Critical,
                        source: self.name().to_string(),
                        message: format!("[ALERT] suspicious process {}", name),
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