use std::sync::mpsc;

pub enum SensorEvent {
    ProcessStarted { name: String, pid: u32 },
    NetworkConnection { remote_ip: String, remote_port: u16 },
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

pub struct ShieldEngine {
    detectors: Vec<Box<dyn Detector>>,
    sinks: Vec<Box<dyn Sink>>,
}

impl ShieldEngine {
    pub fn new() -> Self {
        ShieldEngine {
            detectors: Vec::new(),
            sinks: Vec::new(),
        }
    }

    pub fn add_detector(&mut self, detector: Box<dyn Detector>) {
        self.detectors.push(detector);
    }

    pub fn add_sink(&mut self, sink: Box<dyn Sink>) {
        self.sinks.push(sink);
    }

    pub fn handle(&self, event: SensorEvent) {
        for detector in &self.detectors {
            if let Some(alert) = detector.evaluate(&event) {
                for sink in &self.sinks {
                    sink.emit(&alert);
                }
            }
        }
    }

    pub fn run(&self, rx: mpsc::Receiver<SensorEvent>) {
        for event in rx {
            self.handle(event);
        }
    }
}
