use crate::engine::{Sink, ThreatAlert};
use crate::logger;

pub struct LoggerSink;

impl Sink for LoggerSink {
    fn emit(&self, alert: &ThreatAlert) {
        logger::log(&alert.message);
    }
}
