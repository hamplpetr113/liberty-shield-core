use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::mpsc;
use std::{thread, time};

use crate::engine::SensorEvent;
use crate::logger;

// IPv4-only MVP. IPv6 connections are skipped until a future sensor revision.
pub fn monitor_connections(tx: mpsc::Sender<SensorEvent>) {
    let mut known: HashSet<String> = HashSet::new();

    loop {
        if let Ok(output) = Command::new("netstat").args(["-n", "-o"]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);

            for line in stdout.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();

                // TCP line: TCP  local_addr  remote_addr  STATE  PID
                if parts.len() < 5 || parts[0] != "TCP" {
                    continue;
                }

                let remote = parts[2];
                let state = parts[3];
                let pid = parts[4].parse::<u32>().ok();

                if state == "LISTENING" {
                    continue;
                }

                if known.contains(remote) {
                    continue;
                }

                // Only emit for clean IPv4 addresses; skip IPv6 and anything else
                if let Some((ip_str, port_str)) = remote.rsplit_once(':')
                    && ip_str.parse::<Ipv4Addr>().is_ok()
                    && let Ok(port) = port_str.parse::<u16>()
                {
                    known.insert(remote.to_string());
                    logger::log(&format!("[NETWORK] new connection {}:{}", ip_str, port));
                    let _ = tx.send(SensorEvent::NetworkConnection {
                        remote_ip: ip_str.to_string(),
                        remote_port: port,
                        pid,
                    });
                }
            }
        }

        thread::sleep(time::Duration::from_secs(10));
    }
}
