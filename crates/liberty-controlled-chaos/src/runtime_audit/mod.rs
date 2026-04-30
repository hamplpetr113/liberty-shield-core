//! Runtime audit log — append-only record of significant security events.
//!
//! All events are stored in memory in order of insertion.  The log supports
//! filtering by severity and by epoch range so callers can retrieve relevant
//! slices without scanning everything.

// ---------------------------------------------------------------------------
// AuditSeverity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

// ---------------------------------------------------------------------------
// AuditEventKind
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEventKind {
    NodeStarted,
    NodeStopped,
    PeerAdmitted,
    PeerBanned,
    CircuitBuilt,
    CircuitTornDown,
    CircuitRotated,
    PolicyDenied,
    ReplayDetected,
    KeyRotated,
    BootstrapCompleted,
    Custom(String),
}

// ---------------------------------------------------------------------------
// AuditEvent
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub sequence: u64,
    pub epoch: u64,
    pub severity: AuditSeverity,
    pub kind: AuditEventKind,
    /// Optional peer or circuit identifier for context.
    pub node_id: Option<[u8; 32]>,
    pub circuit_id: Option<u64>,
}

// ---------------------------------------------------------------------------
// RuntimeAuditLog
// ---------------------------------------------------------------------------

pub struct RuntimeAuditLog {
    events: Vec<AuditEvent>,
    next_sequence: u64,
    max_entries: usize,
    dropped: u64,
}

impl RuntimeAuditLog {
    pub fn new(max_entries: usize) -> Self {
        Self {
            events: Vec::new(),
            next_sequence: 0,
            max_entries,
            dropped: 0,
        }
    }

    pub fn append(&mut self, epoch: u64, severity: AuditSeverity, kind: AuditEventKind) -> u64 {
        self.append_with(epoch, severity, kind, None, None)
    }

    pub fn append_with(
        &mut self,
        epoch: u64,
        severity: AuditSeverity,
        kind: AuditEventKind,
        node_id: Option<[u8; 32]>,
        circuit_id: Option<u64>,
    ) -> u64 {
        if self.events.len() >= self.max_entries {
            self.dropped += 1;
            return self.next_sequence;
        }
        let seq = self.next_sequence;
        self.next_sequence += 1;
        self.events.push(AuditEvent {
            sequence: seq,
            epoch,
            severity,
            kind,
            node_id,
            circuit_id,
        });
        seq
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Return events at or above the given severity.
    pub fn by_severity(&self, min: AuditSeverity) -> Vec<&AuditEvent> {
        self.events.iter().filter(|e| e.severity >= min).collect()
    }

    /// Return events within an epoch range [from, to].
    pub fn by_epoch_range(&self, from: u64, to: u64) -> Vec<&AuditEvent> {
        self.events
            .iter()
            .filter(|e| e.epoch >= from && e.epoch <= to)
            .collect()
    }

    /// Return the last `n` events.
    pub fn tail(&self, n: usize) -> &[AuditEvent] {
        let start = self.events.len().saturating_sub(n);
        &self.events[start..]
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }
}

impl Default for RuntimeAuditLog {
    fn default() -> Self {
        Self::new(10_000)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // RAL1: append adds an event.
    #[test]
    fn ral1_append_adds_event() {
        let mut log = RuntimeAuditLog::new(100);
        log.append(1, AuditSeverity::Info, AuditEventKind::NodeStarted);
        assert_eq!(log.len(), 1);
    }

    // RAL2: sequence numbers increment.
    #[test]
    fn ral2_sequence_increments() {
        let mut log = RuntimeAuditLog::new(100);
        let s1 = log.append(1, AuditSeverity::Info, AuditEventKind::NodeStarted);
        let s2 = log.append(1, AuditSeverity::Info, AuditEventKind::NodeStopped);
        assert!(s2 > s1);
    }

    // RAL3: by_severity filters correctly.
    #[test]
    fn ral3_by_severity() {
        let mut log = RuntimeAuditLog::new(100);
        log.append(1, AuditSeverity::Info, AuditEventKind::NodeStarted);
        log.append(1, AuditSeverity::Critical, AuditEventKind::ReplayDetected);
        let crit = log.by_severity(AuditSeverity::Critical);
        assert_eq!(crit.len(), 1);
    }

    // RAL4: by_epoch_range returns events in range.
    #[test]
    fn ral4_by_epoch_range() {
        let mut log = RuntimeAuditLog::new(100);
        log.append(5, AuditSeverity::Info, AuditEventKind::NodeStarted);
        log.append(10, AuditSeverity::Info, AuditEventKind::NodeStarted);
        log.append(15, AuditSeverity::Info, AuditEventKind::NodeStopped);
        let r = log.by_epoch_range(8, 12);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].epoch, 10);
    }

    // RAL5: tail returns last n events.
    #[test]
    fn ral5_tail() {
        let mut log = RuntimeAuditLog::new(100);
        for i in 0..10 {
            log.append(i, AuditSeverity::Info, AuditEventKind::NodeStarted);
        }
        assert_eq!(log.tail(3).len(), 3);
    }

    // RAL6: max_entries cap causes drops.
    #[test]
    fn ral6_max_entries_drops() {
        let mut log = RuntimeAuditLog::new(2);
        log.append(1, AuditSeverity::Info, AuditEventKind::NodeStarted);
        log.append(2, AuditSeverity::Info, AuditEventKind::NodeStarted);
        log.append(3, AuditSeverity::Info, AuditEventKind::NodeStarted); // dropped
        assert_eq!(log.len(), 2);
        assert_eq!(log.dropped(), 1);
    }

    // RAL7: append_with stores node_id.
    #[test]
    fn ral7_append_with_node_id() {
        let mut log = RuntimeAuditLog::new(100);
        let nid = [7u8; 32];
        log.append_with(
            1,
            AuditSeverity::Warning,
            AuditEventKind::PeerBanned,
            Some(nid),
            None,
        );
        assert_eq!(log.events()[0].node_id, Some(nid));
    }

    // RAL8: append_with stores circuit_id.
    #[test]
    fn ral8_append_with_circuit_id() {
        let mut log = RuntimeAuditLog::new(100);
        log.append_with(
            1,
            AuditSeverity::Info,
            AuditEventKind::CircuitBuilt,
            None,
            Some(42),
        );
        assert_eq!(log.events()[0].circuit_id, Some(42));
    }

    // RAL9: Custom kind is stored.
    #[test]
    fn ral9_custom_kind() {
        let mut log = RuntimeAuditLog::new(100);
        log.append(
            1,
            AuditSeverity::Info,
            AuditEventKind::Custom("test".into()),
        );
        assert!(matches!(&log.events()[0].kind, AuditEventKind::Custom(s) if s == "test"));
    }

    // RAL10: is_empty reflects empty state.
    #[test]
    fn ral10_is_empty() {
        let mut log = RuntimeAuditLog::new(100);
        assert!(log.is_empty());
        log.append(1, AuditSeverity::Info, AuditEventKind::NodeStarted);
        assert!(!log.is_empty());
    }
}
