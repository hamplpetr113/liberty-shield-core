//! Mesh node runtime — beta node composition.
//!
//! Composes `NodeConfig`, `OnionRelayRuntime`, `PolicyEngine`, `RuntimeAuditLog`,
//! `NetworkTelemetry`, and `ResourceGuard` into a single lifecycle object.
//! No real I/O is performed here; the UDP layer is injected externally.

use crate::control_plane::{ControlCommand, ControlPlane, NodeStatus};
use crate::network_telemetry::NetworkTelemetry;
use crate::onion_cell_v2::OnionCellV2;
use crate::onion_relay_runtime::{OnionRelayRuntime, RouteDecision};
use crate::policy_engine::{PolicyAction, PolicyEngine, PolicyRequest};
use crate::resource_guard::{ResourceBudget, ResourceGuard};
use crate::runtime_audit::{AuditEventKind, AuditSeverity, RuntimeAuditLog};

// ---------------------------------------------------------------------------
// NodePhase
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodePhase {
    Init,
    Running,
    Stopped,
}

// ---------------------------------------------------------------------------
// NodeRuntimeError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRuntimeError {
    AlreadyStopped,
    NotRunning,
    PolicyDenied,
    ResourceExhausted,
    InvalidPhase,
}

// ---------------------------------------------------------------------------
// MeshNodeRuntime
// ---------------------------------------------------------------------------

pub struct MeshNodeRuntime {
    pub node_id: [u8; 32],
    phase: NodePhase,
    epoch: u64,
    relay: OnionRelayRuntime,
    policy: PolicyEngine,
    audit: RuntimeAuditLog,
    telemetry: NetworkTelemetry,
    resource_guard: ResourceGuard,
    control: ControlPlane,
    packets_processed: u64,
    policy_denials: u64,
}

impl MeshNodeRuntime {
    pub fn new(node_id: [u8; 32], budget: ResourceBudget) -> Self {
        Self {
            node_id,
            phase: NodePhase::Init,
            epoch: 0,
            relay: OnionRelayRuntime::new(node_id),
            policy: PolicyEngine::new(),
            audit: RuntimeAuditLog::new(1000),
            telemetry: NetworkTelemetry::new(50),
            resource_guard: ResourceGuard::new(budget),
            control: ControlPlane::new(),
            packets_processed: 0,
            policy_denials: 0,
        }
    }

    pub fn start(&mut self) -> Result<(), NodeRuntimeError> {
        if self.phase != NodePhase::Init {
            return Err(NodeRuntimeError::InvalidPhase);
        }
        self.phase = NodePhase::Running;
        self.control
            .execute(ControlCommand::SetStatus(NodeStatus::Running))
            .ok();
        self.audit
            .append(self.epoch, AuditSeverity::Info, AuditEventKind::NodeStarted);
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), NodeRuntimeError> {
        if self.phase == NodePhase::Stopped {
            return Err(NodeRuntimeError::AlreadyStopped);
        }
        self.phase = NodePhase::Stopped;
        self.control.execute(ControlCommand::Shutdown).ok();
        self.audit
            .append(self.epoch, AuditSeverity::Info, AuditEventKind::NodeStopped);
        Ok(())
    }

    pub fn tick(&mut self, epoch: u64) {
        self.epoch = epoch;
        self.resource_guard.reset_epoch();
        self.telemetry.advance_epoch();
    }

    /// Process a received cell through the relay runtime.
    pub fn receive_cell(&mut self, cell: &OnionCellV2) -> Result<RouteDecision, NodeRuntimeError> {
        if self.phase != NodePhase::Running {
            return Err(NodeRuntimeError::NotRunning);
        }
        // Policy check.
        let action = self.policy.evaluate(&PolicyRequest::TrafficSend {
            circuit_id: cell.circuit_id,
            class: crate::policy_engine::TrafficClass::Normal,
        });
        if action != PolicyAction::Allow {
            self.policy_denials += 1;
            self.audit.append_with(
                self.epoch,
                AuditSeverity::Warning,
                AuditEventKind::PolicyDenied,
                None,
                Some(cell.circuit_id),
            );
            return Err(NodeRuntimeError::PolicyDenied);
        }
        // Resource check.
        if self
            .resource_guard
            .try_consume_bytes(cell.payload.len() as u64)
            .is_err()
        {
            return Err(NodeRuntimeError::ResourceExhausted);
        }
        let decision = self.relay.process_inbound_cell(cell);
        self.packets_processed += 1;
        Ok(decision)
    }

    /// Register a circuit in the relay runtime.
    pub fn register_circuit(&mut self, circuit_id: u64, next_hop: Option<[u8; 32]>) {
        self.relay.register_circuit(circuit_id, next_hop);
        self.audit.append_with(
            self.epoch,
            AuditSeverity::Info,
            AuditEventKind::CircuitBuilt,
            None,
            Some(circuit_id),
        );
    }

    pub fn deregister_circuit(&mut self, circuit_id: u64) {
        self.relay.remove_circuit(circuit_id);
        self.audit.append_with(
            self.epoch,
            AuditSeverity::Info,
            AuditEventKind::CircuitTornDown,
            None,
            Some(circuit_id),
        );
    }

    pub fn phase(&self) -> NodePhase {
        self.phase
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn packets_processed(&self) -> u64 {
        self.packets_processed
    }

    pub fn policy_denials(&self) -> u64 {
        self.policy_denials
    }

    pub fn audit(&self) -> &RuntimeAuditLog {
        &self.audit
    }

    pub fn policy_mut(&mut self) -> &mut PolicyEngine {
        &mut self.policy
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion_cell_v2::{CMD_DATA, OnionCellV2};
    use crate::onion_relay_runtime::DropReason;
    use crate::policy_engine::{PolicyRule, TrafficClass};
    use crate::resource_guard::ResourceBudget;
    use crate::runtime_audit::AuditSeverity;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn node() -> MeshNodeRuntime {
        MeshNodeRuntime::new(nid(1), ResourceBudget::default())
    }

    fn cell(circuit_id: u64, seq: u64) -> OnionCellV2 {
        OnionCellV2 {
            command: CMD_DATA,
            circuit_id,
            stream_id: 0,
            sequence: seq,
            header_mac: [0u8; 32],
            payload: [0u8; 1364],
        }
    }

    // MNR1: initial phase is Init.
    #[test]
    fn mnr1_initial_phase_init() {
        let n = node();
        assert_eq!(n.phase(), NodePhase::Init);
    }

    // MNR2: start transitions to Running.
    #[test]
    fn mnr2_start() {
        let mut n = node();
        n.start().unwrap();
        assert_eq!(n.phase(), NodePhase::Running);
    }

    // MNR3: stop transitions to Stopped.
    #[test]
    fn mnr3_stop() {
        let mut n = node();
        n.start().unwrap();
        n.stop().unwrap();
        assert_eq!(n.phase(), NodePhase::Stopped);
    }

    // MNR4: tick advances epoch.
    #[test]
    fn mnr4_tick_epoch() {
        let mut n = node();
        n.start().unwrap();
        n.tick(5);
        assert_eq!(n.epoch(), 5);
    }

    // MNR5: stopped node rejects receive_cell.
    #[test]
    fn mnr5_stopped_rejects_cells() {
        let mut n = node();
        n.start().unwrap();
        n.stop().unwrap();
        n.register_circuit(1, None);
        assert_eq!(
            n.receive_cell(&cell(1, 0)),
            Err(NodeRuntimeError::NotRunning)
        );
    }

    // MNR6: policy violation audited.
    #[test]
    fn mnr6_policy_violation_audited() {
        let mut n = node();
        n.start().unwrap();
        n.register_circuit(1, None);
        n.policy_mut().add_rule(PolicyRule {
            name: "deny-all".into(),
            action: PolicyAction::Deny,
            min_trust: 0.0,
            denied_classes: vec![TrafficClass::Normal],
            max_privacy_mode: 0,
        });
        let _ = n.receive_cell(&cell(1, 0));
        assert_eq!(n.policy_denials(), 1);
        let warns = n.audit().by_severity(AuditSeverity::Warning);
        assert!(!warns.is_empty());
    }

    // MNR7: register_circuit enables cell routing.
    #[test]
    fn mnr7_register_circuit() {
        let mut n = node();
        n.start().unwrap();
        n.register_circuit(1, Some(nid(2)));
        let d = n.receive_cell(&cell(1, 0)).unwrap();
        assert_eq!(d, RouteDecision::Forward(nid(2)));
    }

    // MNR8: packets_processed counter increments.
    #[test]
    fn mnr8_packets_processed() {
        let mut n = node();
        n.start().unwrap();
        n.register_circuit(1, None);
        n.receive_cell(&cell(1, 0)).unwrap();
        assert_eq!(n.packets_processed(), 1);
    }

    // MNR9: double stop returns AlreadyStopped.
    #[test]
    fn mnr9_double_stop() {
        let mut n = node();
        n.start().unwrap();
        n.stop().unwrap();
        assert_eq!(n.stop(), Err(NodeRuntimeError::AlreadyStopped));
    }

    // MNR10: audit log records NodeStarted.
    #[test]
    fn mnr10_audit_started() {
        let mut n = node();
        n.start().unwrap();
        let events = n.audit().by_severity(AuditSeverity::Info);
        assert!(events.iter().any(|e| e.kind == AuditEventKind::NodeStarted));
    }
}
