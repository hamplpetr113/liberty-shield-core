//! Runtime event bridge — connects NodeEventBus, RuntimeAuditLog, NetworkTelemetry,
//! and MeshHealthRuntime into a single unified event fan-out.
//!
//! `RuntimeEventBridge::emit()` takes a `BridgeEvent`, then:
//! 1. Publishes a `NodeEvent` to the `NodeEventBus` for in-process fan-out.
//! 2. Appends an `AuditEvent` to `RuntimeAuditLog` for persistent security records.
//! 3. Updates `NetworkTelemetry` counters for relay metrics.
//! 4. Records peer health signals into `MeshHealthRuntime` on connect/disconnect.

use crate::mesh_health_runtime::MeshHealthRuntime;
use crate::network_telemetry::NetworkTelemetry;
use crate::node_event_bus::{EventKind, EventPayload, NodeEvent, NodeEventBus};
use crate::runtime_audit::{AuditEventKind, AuditSeverity, RuntimeAuditLog};

// ---------------------------------------------------------------------------
// BridgeEvent
// ---------------------------------------------------------------------------

/// High-level runtime events that flow through the bridge.
#[derive(Debug, Clone)]
pub enum BridgeEvent {
    NodeStarted {
        epoch: u64,
    },
    PeerConnected {
        peer_id: [u8; 32],
        epoch: u64,
    },
    PeerDisconnected {
        peer_id: [u8; 32],
        epoch: u64,
    },
    CircuitBuilt {
        circuit_id: u64,
        epoch: u64,
    },
    PacketRelayed {
        circuit_id: u64,
        bytes: u64,
        epoch: u64,
    },
    PolicyDenied {
        circuit_id: Option<u64>,
        epoch: u64,
    },
    RuntimeDegraded {
        reason: String,
        epoch: u64,
    },
    NodeStopped {
        epoch: u64,
    },
}

// ---------------------------------------------------------------------------
// RuntimeEventBridge
// ---------------------------------------------------------------------------

pub struct RuntimeEventBridge {
    bus: NodeEventBus,
    audit: RuntimeAuditLog,
    telemetry: NetworkTelemetry,
    health: MeshHealthRuntime,
    emitted: u64,
}

impl RuntimeEventBridge {
    pub fn new(max_audit_entries: usize, max_telemetry_snapshots: usize) -> Self {
        Self {
            bus: NodeEventBus::new(),
            audit: RuntimeAuditLog::new(max_audit_entries),
            telemetry: NetworkTelemetry::new(max_telemetry_snapshots),
            health: MeshHealthRuntime::new(3, 6, 20),
            emitted: 0,
        }
    }

    /// Emit a bridge event, fan out to all subsystems.
    pub fn emit(&mut self, event: BridgeEvent) {
        self.emitted += 1;
        match &event {
            BridgeEvent::NodeStarted { epoch } => {
                let epoch = *epoch;
                self.bus.publish(NodeEvent {
                    kind: EventKind::BootstrapComplete,
                    epoch,
                    payload: EventPayload::None,
                });
                self.audit
                    .append(epoch, AuditSeverity::Info, AuditEventKind::NodeStarted);
            }

            BridgeEvent::PeerConnected { peer_id, epoch } => {
                let (peer_id, epoch) = (*peer_id, *epoch);
                self.bus.publish(NodeEvent {
                    kind: EventKind::PeerConnected,
                    epoch,
                    payload: EventPayload::NodeId(peer_id),
                });
                self.audit.append_with(
                    epoch,
                    AuditSeverity::Info,
                    AuditEventKind::PeerAdmitted,
                    Some(peer_id),
                    None,
                );
                self.health.record_success(peer_id, epoch);
            }

            BridgeEvent::PeerDisconnected { peer_id, epoch } => {
                let (peer_id, epoch) = (*peer_id, *epoch);
                self.bus.publish(NodeEvent {
                    kind: EventKind::PeerDisconnected,
                    epoch,
                    payload: EventPayload::NodeId(peer_id),
                });
                self.health.record_failure(peer_id, epoch);
            }

            BridgeEvent::CircuitBuilt { circuit_id, epoch } => {
                let (circuit_id, epoch) = (*circuit_id, *epoch);
                self.bus.publish(NodeEvent {
                    kind: EventKind::CircuitBuilt,
                    epoch,
                    payload: EventPayload::CircuitId(circuit_id),
                });
                self.audit.append_with(
                    epoch,
                    AuditSeverity::Info,
                    AuditEventKind::CircuitBuilt,
                    None,
                    Some(circuit_id),
                );
            }

            BridgeEvent::PacketRelayed {
                circuit_id,
                bytes,
                epoch,
            } => {
                let (circuit_id, bytes, epoch) = (*circuit_id, *bytes, *epoch);
                self.bus.publish(NodeEvent {
                    kind: EventKind::EpochAdvanced,
                    epoch,
                    payload: EventPayload::CircuitId(circuit_id),
                });
                self.telemetry.record_packet_sent(bytes);
            }

            BridgeEvent::PolicyDenied { circuit_id, epoch } => {
                let (circuit_id, epoch) = (*circuit_id, *epoch);
                self.bus.publish(NodeEvent {
                    kind: EventKind::PolicyTriggered,
                    epoch,
                    payload: circuit_id.map_or(EventPayload::None, EventPayload::CircuitId),
                });
                self.audit.append_with(
                    epoch,
                    AuditSeverity::Warning,
                    AuditEventKind::PolicyDenied,
                    None,
                    circuit_id,
                );
            }

            BridgeEvent::RuntimeDegraded { reason, epoch } => {
                let (reason, epoch) = (reason.clone(), *epoch);
                self.bus.publish(NodeEvent {
                    kind: EventKind::HealthAlert,
                    epoch,
                    payload: EventPayload::Text(reason.clone()),
                });
                self.audit.append(
                    epoch,
                    AuditSeverity::Warning,
                    AuditEventKind::Custom(reason),
                );
            }

            BridgeEvent::NodeStopped { epoch } => {
                let epoch = *epoch;
                self.bus.publish(NodeEvent {
                    kind: EventKind::EpochAdvanced,
                    epoch,
                    payload: EventPayload::None,
                });
                self.audit
                    .append(epoch, AuditSeverity::Info, AuditEventKind::NodeStopped);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// Subscribe to bus events of specific kinds. Returns subscriber ID.
    pub fn subscribe(&mut self, kinds: Vec<EventKind>) -> u64 {
        self.bus.subscribe(kinds)
    }

    pub fn bus(&self) -> &NodeEventBus {
        &self.bus
    }
    pub fn audit(&self) -> &RuntimeAuditLog {
        &self.audit
    }
    pub fn telemetry(&self) -> &NetworkTelemetry {
        &self.telemetry
    }
    pub fn health(&self) -> &MeshHealthRuntime {
        &self.health
    }
    pub fn emitted(&self) -> u64 {
        self.emitted
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_event_bus::EventKind;
    use crate::runtime_audit::AuditEventKind;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn make_bridge() -> RuntimeEventBridge {
        RuntimeEventBridge::new(256, 16)
    }

    // REB1: NodeStarted fans out to subscribers.
    #[test]
    fn reb1_node_started_fanout() {
        let mut b = make_bridge();
        let sub = b.subscribe(vec![EventKind::BootstrapComplete]);
        b.emit(BridgeEvent::NodeStarted { epoch: 1 });
        assert_eq!(b.bus().subscriber(sub).unwrap().count(), 1);
    }

    // REB2: PeerConnected records success in health runtime.
    #[test]
    fn reb2_peer_connected_health() {
        let mut b = make_bridge();
        b.emit(BridgeEvent::PeerConnected {
            peer_id: nid(5),
            epoch: 2,
        });
        assert!(b.health().node_health(&nid(5)).is_some());
    }

    // REB3: CircuitBuilt appears in audit log.
    #[test]
    fn reb3_circuit_built_audit() {
        let mut b = make_bridge();
        b.emit(BridgeEvent::CircuitBuilt {
            circuit_id: 42,
            epoch: 3,
        });
        let events = b.audit().events();
        assert!(
            events
                .iter()
                .any(|e| e.kind == AuditEventKind::CircuitBuilt)
        );
    }

    // REB4: PacketRelayed updates telemetry bytes_sent.
    #[test]
    fn reb4_packet_relayed_telemetry() {
        let mut b = make_bridge();
        b.emit(BridgeEvent::PacketRelayed {
            circuit_id: 1,
            bytes: 1450,
            epoch: 4,
        });
        let snap = b.telemetry().collect_snapshot();
        assert_eq!(snap.bytes_sent, 1450);
    }

    // REB5: PolicyDenied appears in audit with Warning severity.
    #[test]
    fn reb5_policy_denied_audit() {
        let mut b = make_bridge();
        b.emit(BridgeEvent::PolicyDenied {
            circuit_id: Some(7),
            epoch: 5,
        });
        let events = b.audit().by_severity(AuditSeverity::Warning);
        assert!(
            events
                .iter()
                .any(|e| e.kind == AuditEventKind::PolicyDenied)
        );
    }

    // REB6: RuntimeDegraded audit entry has Warning severity.
    #[test]
    fn reb6_runtime_degraded_warning() {
        let mut b = make_bridge();
        b.emit(BridgeEvent::RuntimeDegraded {
            reason: "too many errors".into(),
            epoch: 6,
        });
        let warnings = b.audit().by_severity(AuditSeverity::Warning);
        assert!(!warnings.is_empty());
        assert!(matches!(&warnings[0].kind, AuditEventKind::Custom(s) if s.contains("errors")));
    }

    // REB7: NodeStopped appears in audit.
    #[test]
    fn reb7_node_stopped_audit() {
        let mut b = make_bridge();
        b.emit(BridgeEvent::NodeStopped { epoch: 10 });
        let events = b.audit().events();
        assert!(events.iter().any(|e| e.kind == AuditEventKind::NodeStopped));
    }

    // REB8: two subscribers both receive CircuitBuilt event.
    #[test]
    fn reb8_event_fanout_multiple_subscribers() {
        let mut b = make_bridge();
        let s1 = b.subscribe(vec![EventKind::CircuitBuilt]);
        let s2 = b.subscribe(vec![EventKind::CircuitBuilt]);
        b.emit(BridgeEvent::CircuitBuilt {
            circuit_id: 9,
            epoch: 7,
        });
        assert_eq!(b.bus().subscriber(s1).unwrap().count(), 1);
        assert_eq!(b.bus().subscriber(s2).unwrap().count(), 1);
    }

    // REB9: audit events arrive in emission order.
    #[test]
    fn reb9_audit_persistence_order() {
        let mut b = make_bridge();
        b.emit(BridgeEvent::NodeStarted { epoch: 1 });
        b.emit(BridgeEvent::CircuitBuilt {
            circuit_id: 1,
            epoch: 2,
        });
        b.emit(BridgeEvent::NodeStopped { epoch: 3 });
        let events = b.audit().events();
        assert_eq!(events.len(), 3);
        assert!(events[0].sequence < events[1].sequence);
        assert!(events[1].sequence < events[2].sequence);
    }

    // REB10: two PacketRelayed events accumulate telemetry bytes.
    #[test]
    fn reb10_telemetry_packet_count() {
        let mut b = make_bridge();
        b.emit(BridgeEvent::PacketRelayed {
            circuit_id: 1,
            bytes: 100,
            epoch: 1,
        });
        b.emit(BridgeEvent::PacketRelayed {
            circuit_id: 2,
            bytes: 200,
            epoch: 1,
        });
        let snap = b.telemetry().collect_snapshot();
        assert_eq!(snap.bytes_sent, 300);
        assert_eq!(snap.packets_sent, 2);
    }
}
