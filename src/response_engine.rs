use crate::engine::{Severity, Sink, ThreatAlert};
use crate::logger;

pub trait ResponseHandler: Send + Sync {
    fn name(&self) -> &str;
    fn can_handle(&self, alert: &ThreatAlert) -> bool;
    fn respond(&self, alert: &ThreatAlert);
}

pub struct ResponseEngine {
    handlers: Vec<Box<dyn ResponseHandler>>,
}

impl ResponseEngine {
    pub fn new() -> Self {
        ResponseEngine { handlers: Vec::new() }
    }

    pub fn add_handler(&mut self, handler: Box<dyn ResponseHandler>) {
        self.handlers.push(handler);
    }
}

impl Sink for ResponseEngine {
    fn emit(&self, alert: &ThreatAlert) {
        for handler in &self.handlers {
            if handler.can_handle(alert) {
                handler.respond(alert);
            }
        }
    }
}

pub struct ProcessKillHandler;

impl ResponseHandler for ProcessKillHandler {
    fn name(&self) -> &str { "ProcessKillHandler" }

    fn can_handle(&self, alert: &ThreatAlert) -> bool {
        matches!(alert.severity, Severity::Critical) && alert.source.contains("Process")
    }

    fn respond(&self, alert: &ThreatAlert) {
        logger::log(&format!("[RESPONSE][ProcessKillHandler] Terminating threat: {}", alert.message));
    }
}

pub struct NetworkBlockHandler;

impl ResponseHandler for NetworkBlockHandler {
    fn name(&self) -> &str { "NetworkBlockHandler" }

    fn can_handle(&self, alert: &ThreatAlert) -> bool {
        matches!(alert.severity, Severity::Critical) && alert.source.contains("Network")
    }

    fn respond(&self, alert: &ThreatAlert) {
        logger::log(&format!("[RESPONSE][NetworkBlockHandler] Blocking connection: {}", alert.message));
    }
}

pub struct EscalationHandler;

impl ResponseHandler for EscalationHandler {
    fn name(&self) -> &str { "EscalationHandler" }

    fn can_handle(&self, alert: &ThreatAlert) -> bool {
        alert.source == "ThreatScore"
    }

    fn respond(&self, alert: &ThreatAlert) {
        logger::log(&format!(
            "[RESPONSE][EscalationHandler] Composite threat score crossed threshold: {}",
            alert.message
        ));
    }
}

pub struct PatternResponseHandler;

impl ResponseHandler for PatternResponseHandler {
    fn name(&self) -> &str { "PatternResponseHandler" }

    fn can_handle(&self, alert: &ThreatAlert) -> bool {
        alert.message.contains("[PATTERN]")
    }

    fn respond(&self, alert: &ThreatAlert) {
        logger::log(&format!(
            "[RESPONSE][PatternResponseHandler] Attack pattern confirmed: {}",
            alert.message
        ));
    }
}