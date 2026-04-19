use std::sync::mpsc;
use crate::engine::SensorEvent;

pub fn simulate_suspicious_process(tx: &mpsc::Sender<SensorEvent>) {
    let _ = tx.send(SensorEvent::ProcessStarted {
        name: "xmrig.exe".to_string(),
        pid: 9999,
        parent_pid: 1,
    });
}

pub fn simulate_suspicious_network(tx: &mpsc::Sender<SensorEvent>) {
    let _ = tx.send(SensorEvent::NetworkConnection {
        remote_ip: "127.0.0.1".to_string(),
        remote_port: 4444,
    });
}

pub fn simulate_keylogger(tx: &mpsc::Sender<SensorEvent>) {
    let _ = tx.send(SensorEvent::ProcessStarted {
        name: "keylogger.exe".to_string(),
        pid: 7777,
        parent_pid: 1,
    });
    let _ = tx.send(SensorEvent::NetworkConnection {
        remote_ip: "192.168.1.100".to_string(),
        remote_port: 80,
    });
}

pub fn simulate_botnet(tx: &mpsc::Sender<SensorEvent>) {
    let _ = tx.send(SensorEvent::NetworkConnection {
        remote_ip: "10.0.0.1".to_string(),
        remote_port: 1337,
    });
    let _ = tx.send(SensorEvent::NetworkConnection {
        remote_ip: "10.0.0.2".to_string(),
        remote_port: 1337,
    });
}
