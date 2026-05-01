use std::collections::HashSet;
use std::sync::mpsc;
use std::{thread, time};
use sysinfo::System;

use crate::engine::SensorEvent;
use crate::logger;

pub fn list_processes(tx: mpsc::Sender<SensorEvent>) {
    let mut system = System::new_all();
    let mut known_processes: HashSet<String> = HashSet::new();

    loop {
        system.refresh_all();

        println!("\n=== Liberty Shield Scan ===");

        for (pid, process) in system.processes() {
            let process_name = process.name().to_string();

            if !known_processes.contains(&process_name) {
                logger::log(&format!("[PROCESS START] {}", process_name));

                let parent_pid = process.parent().map(|p| p.as_u32()).unwrap_or(0);

                let _ = tx.send(SensorEvent::ProcessStarted {
                    name: process_name.clone(),
                    pid: pid.as_u32(),
                    parent_pid,
                });

                known_processes.insert(process_name.clone());
            }
        }

        let delay = time::Duration::from_secs(5);
        thread::sleep(delay);
    }
}
