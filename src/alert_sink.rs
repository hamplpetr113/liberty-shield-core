use crate::engine::{Sink, ThreatAlert};
use crate::logger;

pub struct LoggerSink;

impl Sink for LoggerSink {
    fn emit(&self, alert: &ThreatAlert) {
        let severity = match alert.severity {
            crate::engine::Severity::Info     => "INFO",
            crate::engine::Severity::Warning  => "WARNING",
            crate::engine::Severity::Critical => "CRITICAL",
        };
        logger::log(&format!("[{}][{}] {}", severity, alert.source, alert.message));
    }
}
