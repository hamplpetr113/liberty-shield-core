mod pattern_matcher;
mod attack_simulator;
mod alert_sink;
mod engine;
mod response_engine;
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
use pattern_matcher::{MinerPattern, KeyloggerPattern, BotnetPattern};
use response_engine::{ResponseEngine, ProcessKillHandler, NetworkBlockHandler, EscalationHandler, PatternResponseHandler};

fn main() {
    let _lock = match self_protection::acquire_lock() {
        Ok(lock) => lock,
        Err(err) => {
            eprintln!("[LIBERTY SHIELD] {}", err);
            return;
        }
    };

    let simulate = std::env::args().any(|a| a == "--simulate");

    let (tx, rx) = mpsc::channel::<engine::SensorEvent>();

    logger::log("Liberty Shield core starting...");

    std::thread::spawn({
        let tx = tx.clone();
        move || process_monitor::list_processes(tx)
    });

    std::thread::spawn({
        let tx = tx.clone();
        move || network_sensor::monitor_connections(tx)
    });

    if simulate {
        attack_simulator::simulate_suspicious_process(&tx);
        attack_simulator::simulate_suspicious_network(&tx);
        attack_simulator::simulate_keylogger(&tx);
        attack_simulator::simulate_botnet(&tx);
    }

    let mut engine = ShieldEngine::new();
    engine.add_detector(Box::new(ProcessThreatDetector::new()));
    engine.add_detector(Box::new(NetworkThreatDetector::new()));
    engine.add_pattern(Box::new(MinerPattern::new()));
    engine.add_pattern(Box::new(KeyloggerPattern::new()));
    engine.add_pattern(Box::new(BotnetPattern::new()));
    engine.add_sink(Box::new(LoggerSink));
    let mut responder = ResponseEngine::new();
    responder.add_handler(Box::new(ProcessKillHandler));
    responder.add_handler(Box::new(NetworkBlockHandler));
    responder.add_handler(Box::new(EscalationHandler));
    responder.add_handler(Box::new(PatternResponseHandler));
    engine.add_sink(Box::new(responder));
    engine.run(rx);
}