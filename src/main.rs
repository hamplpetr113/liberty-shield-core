mod alert_sink;
mod attack_simulator;
mod behavior_graph;
mod config;
mod engine;
mod gateway;
mod lateral_movement_detector;
mod logger;
mod network_detector;
mod network_sensor;
mod pattern_matcher;
mod process_monitor;
mod response_engine;
mod self_protection;
mod threat_detector;

use alert_sink::LoggerSink;
use config::ShieldConfig;
use engine::ShieldEngine;
use lateral_movement_detector::LateralMovementDetector;
use network_detector::NetworkThreatDetector;
use pattern_matcher::{BotnetPattern, KeyloggerPattern, MinerPattern};
use response_engine::{
    EscalationHandler, NetworkBlockHandler, PatternResponseHandler, ProcessKillHandler,
    ResponseEngine,
};
use std::sync::mpsc;
use threat_detector::ProcessThreatDetector;

#[tokio::main]
async fn main() {
    let _lock = match self_protection::acquire_lock() {
        Ok(lock) => lock,
        Err(err) => {
            eprintln!("[LIBERTY SHIELD] {}", err);
            return;
        }
    };

    let simulate = std::env::args().any(|a| a == "--simulate");

    let (tx, rx) = mpsc::channel::<engine::SensorEvent>();

    let cfg = ShieldConfig::load("liberty-shield.conf");

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

    let mut engine = ShieldEngine::new(&cfg);
    engine.add_detector(Box::new(ProcessThreatDetector::new(&cfg)));
    engine.add_detector(Box::new(NetworkThreatDetector::new(&cfg)));
    let graph = engine.graph_handle();
    engine.add_detector(Box::new(LateralMovementDetector::new(graph, &cfg)));
    engine.add_pattern(Box::new(MinerPattern::new(&cfg)));
    engine.add_pattern(Box::new(KeyloggerPattern::new(&cfg)));
    engine.add_pattern(Box::new(BotnetPattern::new(&cfg)));
    engine.add_sink(Box::new(LoggerSink));
    let mut responder = ResponseEngine::new();
    responder.add_handler(Box::new(ProcessKillHandler));
    responder.add_handler(Box::new(NetworkBlockHandler));
    responder.add_handler(Box::new(EscalationHandler));
    responder.add_handler(Box::new(PatternResponseHandler));
    engine.add_sink(Box::new(responder));
    tokio::spawn(gateway::start(tx.clone()));

    tokio::task::spawn_blocking(move || engine.run(rx))
        .await
        .unwrap();
}
