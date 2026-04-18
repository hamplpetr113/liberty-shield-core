mod alert_sink;
mod engine;
mod network_detector;
mod network_sensor;
mod logger;
mod process_monitor;
mod threat_detector;
mod self_protection;

use std::sync::mpsc;
use engine::ShieldEngine;
use threat_detector::ProcessThreatDetector;
use network_detector::NetworkThreatDetector;
use alert_sink::LoggerSink;

fn main() {
    let _lock = match self_protection::acquire_lock() {
        Ok(lock) => lock,
        Err(err) => {
            eprintln!("[LIBERTY SHIELD] {}", err);
            return;
        }
    };

    let (tx, rx) = mpsc::channel::<engine::SensorEvent>();

    logger::log("Liberty Shield core starting...");

    std::thread::spawn({
        let tx = tx.clone();
        move || process_monitor::list_processes(tx)
    });

    std::thread::spawn(move || {
        network_sensor::monitor_connections(tx);
    });

    let mut engine = ShieldEngine::new();
    engine.add_detector(Box::new(ProcessThreatDetector));
    engine.add_detector(Box::new(NetworkThreatDetector::new()));
    engine.add_sink(Box::new(LoggerSink));
    engine.run(rx);
}