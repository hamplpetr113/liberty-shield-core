use std::sync::atomic::{AtomicU64, Ordering};

pub struct Metrics {
    pub packets_rx: AtomicU64,
    pub packets_tx: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub bytes_tx: AtomicU64,
    pub active_sessions: AtomicU64,
    pub parse_errors: AtomicU64,
    pub auth_failures: AtomicU64,
}

#[derive(Debug)]
pub struct MetricsSnapshot {
    pub packets_rx: u64,
    pub packets_tx: u64,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub active_sessions: u64,
    pub parse_errors: u64,
    pub auth_failures: u64,
}

impl Metrics {
    pub const fn new() -> Self {
        Self {
            packets_rx: AtomicU64::new(0),
            packets_tx: AtomicU64::new(0),
            bytes_rx: AtomicU64::new(0),
            bytes_tx: AtomicU64::new(0),
            active_sessions: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            packets_rx: self.packets_rx.load(Ordering::Relaxed),
            packets_tx: self.packets_tx.load(Ordering::Relaxed),
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
        }
    }
}

pub static METRICS: Metrics = Metrics::new();
