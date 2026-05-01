//! Integrated node runtime — composes all subsystems into a single lifecycle-managed node.
//!
//! `IntegratedNodeRuntime` owns:
//! - Identity and configuration (`NodeConfig`)
//! - Peer handshake session management (`PeerHandshakeRuntime`, `MeshSessionStore`)
//! - Onion relay layer (`OnionRelayRuntime`)
//! - Circuit lifecycle (`CircuitManager`, `LiveCircuitBuildProtocol`)
//! - Stream multiplexing (`StreamMuxV2`)
//! - Observability (`NetworkTelemetry`, `RuntimeAuditLog`)
//! - Policy and resource enforcement (`PolicyEngine`, `ResourceGuard`)
//!
//! The runtime progresses through: New → Configured → Bootstrapping → Running → Degraded → Stopped.
//! Packets are accepted only in Running state; all other states return `RuntimeError::WrongState`.
//!
//! NON-PRODUCTION: no real UDP socket is bound here; transport integration is in Sprint 157.

use crate::circuit_manager::{CircuitId, CircuitManager, CircuitManagerError};
use crate::live_circuit_build_protocol::LiveCircuitBuildProtocol;
use crate::mesh_session_store::MeshSessionStore;
use crate::network_telemetry::NetworkTelemetry;
use crate::node_config::NodeConfig;
use crate::onion_relay_runtime::OnionRelayRuntime;
use crate::peer_handshake_runtime::PeerHandshakeRuntime;
use crate::policy_engine::{PolicyAction, PolicyEngine, PolicyRequest, TrafficClass};
use crate::resource_guard::{ResourceError, ResourceGuard};
use crate::runtime_audit::{AuditEventKind, AuditSeverity, RuntimeAuditLog};
use crate::stream_mux_v2::StreamMuxV2;

// ---------------------------------------------------------------------------
// RuntimeState
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeState {
    New,
    Configured,
    Bootstrapping,
    Running,
    Degraded,
    Stopped,
}

impl std::fmt::Display for RuntimeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeState::New => write!(f, "New"),
            RuntimeState::Configured => write!(f, "Configured"),
            RuntimeState::Bootstrapping => write!(f, "Bootstrapping"),
            RuntimeState::Running => write!(f, "Running"),
            RuntimeState::Degraded => write!(f, "Degraded"),
            RuntimeState::Stopped => write!(f, "Stopped"),
        }
    }
}

// ---------------------------------------------------------------------------
// RuntimeError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    /// Attempted operation is not valid in the current lifecycle state.
    WrongState(RuntimeState),
    /// Policy engine denied the operation.
    PolicyDenied,
    /// Resource budget exceeded.
    Resource(ResourceError),
    /// Circuit layer error.
    Circuit(CircuitManagerError),
    /// Packet is too short to be a valid frame.
    MalformedPacket,
    /// Already stopped; terminal state.
    AlreadyStopped,
}

// ---------------------------------------------------------------------------
// PacketDecision
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketDecision {
    Accepted { circuit_id: u64 },
    Relayed { circuit_id: u64, next_hop: [u8; 32] },
    PolicyDenied,
}

// ---------------------------------------------------------------------------
// IntegratedNodeRuntime
// ---------------------------------------------------------------------------

pub struct IntegratedNodeRuntime {
    config: NodeConfig,
    state: RuntimeState,
    handshake_rt: PeerHandshakeRuntime,
    sessions: MeshSessionStore,
    relay: OnionRelayRuntime,
    circuits: CircuitManager,
    build_proto: LiveCircuitBuildProtocol,
    /// Primary stream mux (circuit_id=0; replaced when circuits are opened).
    mux: StreamMuxV2,
    telemetry: NetworkTelemetry,
    audit: RuntimeAuditLog,
    policy: PolicyEngine,
    guard: ResourceGuard,
    current_epoch: u64,
}

impl IntegratedNodeRuntime {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Create a new runtime from config. State = New.
    pub fn new(config: NodeConfig) -> Self {
        let node_id = config.node_id;
        let budget = config.resource_budget.clone();
        Self {
            handshake_rt: PeerHandshakeRuntime::new(node_id, config.max_epoch_skew, 100),
            sessions: MeshSessionStore::new(budget.max_peers as usize, 200),
            relay: OnionRelayRuntime::new(node_id),
            circuits: CircuitManager::new(),
            build_proto: LiveCircuitBuildProtocol::new(),
            mux: StreamMuxV2::new(0, 64),
            telemetry: NetworkTelemetry::new(32),
            audit: RuntimeAuditLog::new(4096),
            policy: PolicyEngine::new(),
            guard: ResourceGuard::new(budget),
            config,
            state: RuntimeState::New,
            current_epoch: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /// Validate config and move to Configured.
    pub fn configure(&mut self) -> Result<(), RuntimeError> {
        if self.state != RuntimeState::New {
            return Err(RuntimeError::WrongState(self.state));
        }
        self.state = RuntimeState::Configured;
        Ok(())
    }

    /// Begin bootstrapping (connect to peers, fetch directory). Moves to Bootstrapping.
    /// In tests, call `complete_bootstrap()` immediately after.
    pub fn start_bootstrap(&mut self, epoch: u64) -> Result<(), RuntimeError> {
        if self.state != RuntimeState::Configured {
            return Err(RuntimeError::WrongState(self.state));
        }
        self.current_epoch = epoch;
        self.state = RuntimeState::Bootstrapping;
        self.audit
            .append(epoch, AuditSeverity::Info, AuditEventKind::NodeStarted);
        Ok(())
    }

    /// Finish bootstrap and enter Running state.
    pub fn complete_bootstrap(&mut self, epoch: u64) -> Result<(), RuntimeError> {
        if self.state != RuntimeState::Bootstrapping {
            return Err(RuntimeError::WrongState(self.state));
        }
        self.current_epoch = epoch;
        self.state = RuntimeState::Running;
        self.audit.append(
            epoch,
            AuditSeverity::Info,
            AuditEventKind::BootstrapCompleted,
        );
        Ok(())
    }

    /// Graceful shutdown. Moves to Stopped.
    pub fn stop(&mut self, epoch: u64) -> Result<(), RuntimeError> {
        if self.state == RuntimeState::Stopped {
            return Err(RuntimeError::AlreadyStopped);
        }
        self.current_epoch = epoch;
        self.state = RuntimeState::Stopped;
        self.audit
            .append(epoch, AuditSeverity::Info, AuditEventKind::NodeStopped);
        Ok(())
    }

    /// Mark runtime as degraded (e.g. too many errors). Running and Bootstrapping → Degraded.
    pub fn mark_degraded(&mut self, epoch: u64) -> Result<(), RuntimeError> {
        match self.state {
            RuntimeState::Running | RuntimeState::Bootstrapping => {
                self.current_epoch = epoch;
                self.state = RuntimeState::Degraded;
                self.audit.append(
                    epoch,
                    AuditSeverity::Warning,
                    AuditEventKind::Custom("runtime degraded".into()),
                );
                Ok(())
            }
            other => Err(RuntimeError::WrongState(other)),
        }
    }

    /// Attempt recovery from Degraded → Running.
    pub fn recover(&mut self, epoch: u64) -> Result<(), RuntimeError> {
        if self.state != RuntimeState::Degraded {
            return Err(RuntimeError::WrongState(self.state));
        }
        self.current_epoch = epoch;
        self.state = RuntimeState::Running;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Packet ingestion
    // -----------------------------------------------------------------------

    /// Ingest an inbound datagram. Requires Running state.
    ///
    /// `data` must be at least 8 bytes (circuit_id header). The first 8 bytes
    /// are interpreted as a little-endian circuit ID for routing purposes.
    pub fn ingest_packet(
        &mut self,
        data: &[u8],
        epoch: u64,
    ) -> Result<PacketDecision, RuntimeError> {
        if self.state != RuntimeState::Running {
            return Err(RuntimeError::WrongState(self.state));
        }
        if data.len() < 8 {
            return Err(RuntimeError::MalformedPacket);
        }

        self.current_epoch = epoch;

        // Extract circuit_id from first 8 bytes.
        let circuit_id = u64::from_le_bytes(data[..8].try_into().unwrap());

        // Policy gate: evaluate as TrafficSend.
        let req = PolicyRequest::TrafficSend {
            circuit_id,
            class: TrafficClass::Normal,
        };
        if self.policy.evaluate(&req) == PolicyAction::Deny {
            self.audit.append_with(
                epoch,
                AuditSeverity::Warning,
                AuditEventKind::PolicyDenied,
                None,
                Some(circuit_id),
            );
            return Ok(PacketDecision::PolicyDenied);
        }

        // Resource accounting: consume bytes.
        self.guard
            .try_consume_bytes(data.len() as u64)
            .map_err(RuntimeError::Resource)?;

        // Update telemetry.
        self.telemetry.record_packet_received(data.len() as u64);

        // Relay lookup.
        let payload = &data[8..];
        if payload.len() >= 8 {
            let next_id = u64::from_le_bytes(payload[..8].try_into().unwrap());
            if next_id != 0 {
                return Ok(PacketDecision::Relayed {
                    circuit_id,
                    next_hop: {
                        let mut hop = [0u8; 32];
                        hop[..8].copy_from_slice(&next_id.to_le_bytes());
                        hop
                    },
                });
            }
        }

        Ok(PacketDecision::Accepted { circuit_id })
    }

    // -----------------------------------------------------------------------
    // Circuit helpers
    // -----------------------------------------------------------------------

    /// Open a circuit through guard→relay→exit. Returns the new CircuitId.
    pub fn open_circuit(
        &mut self,
        guard: [u8; 32],
        relay: [u8; 32],
        exit: [u8; 32],
        epoch: u64,
    ) -> Result<CircuitId, RuntimeError> {
        if self.state != RuntimeState::Running {
            return Err(RuntimeError::WrongState(self.state));
        }
        self.guard
            .try_add_circuit()
            .map_err(RuntimeError::Resource)?;
        let id = self.circuits.create_circuit(guard, relay, exit, epoch);
        self.circuits.mark_open(id).map_err(RuntimeError::Circuit)?;
        self.audit.append_with(
            epoch,
            AuditSeverity::Info,
            AuditEventKind::CircuitBuilt,
            None,
            Some(id.value()),
        );
        self.telemetry
            .set_circuits_active(self.circuits.len() as u64);
        Ok(id)
    }

    // -----------------------------------------------------------------------
    // Epoch advance
    // -----------------------------------------------------------------------

    /// Advance to a new epoch: rotate stats, evict idle circuits.
    pub fn advance_epoch(&mut self, new_epoch: u64) {
        self.current_epoch = new_epoch;
        self.telemetry.advance_epoch();
        self.guard.reset_epoch();
        let idle_secs = self.config.rotation.idle_rotation_epochs;
        let closed = self.circuits.expire_idle(new_epoch, idle_secs);
        for id in closed {
            self.guard.remove_circuit();
            self.audit.append_with(
                new_epoch,
                AuditSeverity::Info,
                AuditEventKind::CircuitTornDown,
                None,
                Some(id.value()),
            );
        }
        self.telemetry
            .set_circuits_active(self.circuits.len() as u64);
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn state(&self) -> RuntimeState {
        self.state
    }
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
    pub fn node_id(&self) -> [u8; 32] {
        self.config.node_id
    }
    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }
    pub fn audit(&self) -> &RuntimeAuditLog {
        &self.audit
    }
    pub fn telemetry(&self) -> &NetworkTelemetry {
        &self.telemetry
    }
    pub fn policy_mut(&mut self) -> &mut PolicyEngine {
        &mut self.policy
    }
    pub fn mux_mut(&mut self) -> &mut StreamMuxV2 {
        &mut self.mux
    }
    pub fn sessions_mut(&mut self) -> &mut MeshSessionStore {
        &mut self.sessions
    }
    pub fn handshake_rt_mut(&mut self) -> &mut PeerHandshakeRuntime {
        &mut self.handshake_rt
    }
    pub fn relay_mut(&mut self) -> &mut OnionRelayRuntime {
        &mut self.relay
    }
    pub fn build_proto_mut(&mut self) -> &mut LiveCircuitBuildProtocol {
        &mut self.build_proto
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_config::NodeConfig;
    use crate::policy_engine::PolicyRule;

    fn node_id(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn make_runtime(b: u8) -> IntegratedNodeRuntime {
        IntegratedNodeRuntime::new(NodeConfig::new(node_id(b)))
    }

    fn started_runtime(b: u8) -> IntegratedNodeRuntime {
        let mut rt = make_runtime(b);
        rt.configure().unwrap();
        rt.start_bootstrap(1).unwrap();
        rt.complete_bootstrap(1).unwrap();
        rt
    }

    fn packet(circuit_id: u64, next_id: u64) -> Vec<u8> {
        let mut v = circuit_id.to_le_bytes().to_vec();
        v.extend_from_slice(&next_id.to_le_bytes());
        v.extend_from_slice(&[0u8; 16]);
        v
    }

    // INR1: new runtime starts in New state.
    #[test]
    fn inr1_initial_state() {
        let rt = make_runtime(1);
        assert_eq!(rt.state(), RuntimeState::New);
    }

    // INR2: lifecycle progresses New → Configured → Bootstrapping → Running.
    #[test]
    fn inr2_full_start() {
        let mut rt = make_runtime(1);
        rt.configure().unwrap();
        assert_eq!(rt.state(), RuntimeState::Configured);
        rt.start_bootstrap(1).unwrap();
        assert_eq!(rt.state(), RuntimeState::Bootstrapping);
        rt.complete_bootstrap(2).unwrap();
        assert_eq!(rt.state(), RuntimeState::Running);
    }

    // INR3: stop transitions to Stopped; audit records event.
    #[test]
    fn inr3_stop() {
        let mut rt = started_runtime(1);
        rt.stop(10).unwrap();
        assert_eq!(rt.state(), RuntimeState::Stopped);
        let events = rt.audit().events();
        assert!(events.iter().any(|e| e.kind == AuditEventKind::NodeStopped));
    }

    // INR4: ingest_packet while Stopped returns WrongState.
    #[test]
    fn inr4_reject_while_stopped() {
        let mut rt = started_runtime(1);
        rt.stop(5).unwrap();
        let err = rt.ingest_packet(&packet(42, 0), 6).unwrap_err();
        assert_eq!(err, RuntimeError::WrongState(RuntimeState::Stopped));
    }

    // INR5: ingest_packet while Running returns Accepted.
    #[test]
    fn inr5_accept_while_running() {
        let mut rt = started_runtime(2);
        let result = rt.ingest_packet(&packet(1, 0), 2).unwrap();
        assert_eq!(result, PacketDecision::Accepted { circuit_id: 1 });
    }

    // INR6: malformed packet (too short) returns MalformedPacket.
    #[test]
    fn inr6_malformed_packet() {
        let mut rt = started_runtime(3);
        let err = rt.ingest_packet(&[0u8; 4], 1).unwrap_err();
        assert_eq!(err, RuntimeError::MalformedPacket);
    }

    // INR7: configure called twice returns WrongState.
    #[test]
    fn inr7_double_configure() {
        let mut rt = make_runtime(1);
        rt.configure().unwrap();
        let err = rt.configure().unwrap_err();
        assert_eq!(err, RuntimeError::WrongState(RuntimeState::Configured));
    }

    // INR8: mark_degraded while Running → Degraded; packet rejected.
    #[test]
    fn inr8_degraded_rejects_packets() {
        let mut rt = started_runtime(4);
        rt.mark_degraded(3).unwrap();
        assert_eq!(rt.state(), RuntimeState::Degraded);
        let err = rt.ingest_packet(&packet(1, 0), 3).unwrap_err();
        assert_eq!(err, RuntimeError::WrongState(RuntimeState::Degraded));
    }

    // INR9: open_circuit registers circuit and audit records CircuitBuilt.
    #[test]
    fn inr9_open_circuit() {
        let mut rt = started_runtime(5);
        rt.open_circuit(node_id(10), node_id(11), node_id(12), 2)
            .unwrap();
        assert_eq!(rt.circuit_count(), 1);
        let events = rt.audit().events();
        assert!(
            events
                .iter()
                .any(|e| e.kind == AuditEventKind::CircuitBuilt)
        );
    }

    // INR10: policy deny causes PacketDecision::PolicyDenied.
    #[test]
    fn inr10_policy_denied() {
        let mut rt = started_runtime(6);
        // Add a deny-all rule.
        rt.policy_mut().add_rule(PolicyRule {
            name: "deny-all".into(),
            action: crate::policy_engine::PolicyAction::Deny,
            min_trust: 0.0,
            denied_classes: vec![TrafficClass::Normal],
            max_privacy_mode: 0,
        });
        let result = rt.ingest_packet(&packet(99, 0), 1).unwrap();
        assert_eq!(result, PacketDecision::PolicyDenied);
    }
}
