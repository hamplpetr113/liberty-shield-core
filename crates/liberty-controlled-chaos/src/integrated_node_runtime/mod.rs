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

use crate::circuit_build_runtime_driver::{BuildRequest, CircuitBuildRuntimeDriver, DriverConfig};
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
use crate::runtime_epoch_driver::{
    EpochDriverConfig, EpochSubscriber, RuntimeEpochDriver, SubscriberId,
};
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
    epoch_driver: RuntimeEpochDriver,
    build_driver: CircuitBuildRuntimeDriver,
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
            epoch_driver: RuntimeEpochDriver::new(EpochDriverConfig::default()),
            build_driver: CircuitBuildRuntimeDriver::new(DriverConfig::default()),
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
        self.epoch_driver.set_epoch(epoch);
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
    // Epoch driver integration
    // -----------------------------------------------------------------------

    /// Attach an external subscriber to the internal epoch driver.
    pub fn subscribe_epoch(&mut self, sub: Box<dyn EpochSubscriber>) -> SubscriberId {
        self.epoch_driver.subscribe(sub)
    }

    /// Detach a previously attached subscriber.
    pub fn unsubscribe_epoch(&mut self, id: SubscriberId) -> bool {
        self.epoch_driver.unsubscribe(id)
    }

    /// Advance the epoch clock by `n` ticks via the driver.
    ///
    /// Each tick fires all subscribers, then runs `advance_epoch` on the
    /// runtime subsystems.
    pub fn advance_epoch_driven(&mut self, n: u64) {
        for _ in 0..n {
            self.epoch_driver.tick();
            let new_epoch = self.epoch_driver.epoch();
            self.advance_epoch(new_epoch);
            self.build_driver.tick(new_epoch);
        }
    }

    pub fn epoch_driver(&self) -> &RuntimeEpochDriver {
        &self.epoch_driver
    }

    // -----------------------------------------------------------------------
    // Circuit build driver integration
    // -----------------------------------------------------------------------

    /// Enqueue a circuit build request.  Returns false if at capacity.
    pub fn enqueue_circuit_build(&mut self, path: Vec<[u8; 32]>, circuit_id: u64) -> bool {
        let req = BuildRequest {
            circuit_id,
            path,
            queued_at_epoch: self.current_epoch,
        };
        self.build_driver.enqueue(req)
    }

    /// Tick the circuit build driver for the current epoch.
    pub fn tick_circuit_builds(&mut self) {
        self.build_driver.tick(self.current_epoch);
    }

    /// Mark a pending circuit build as complete.
    pub fn complete_circuit_build(&mut self, circuit_id: u64) -> bool {
        self.build_driver.complete(circuit_id, self.current_epoch)
    }

    pub fn build_driver(&self) -> &CircuitBuildRuntimeDriver {
        &self.build_driver
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

    // INR17: enqueue_circuit_build returns true and increments pending count.
    #[test]
    fn inr17_enqueue_circuit_build() {
        let mut rt = started_runtime(1);
        let path = vec![node_id(10), node_id(11), node_id(12)];
        assert!(rt.enqueue_circuit_build(path, 1001));
        assert_eq!(rt.build_driver().pending_count(), 1);
    }

    // INR18: tick_circuit_builds starts pending build.
    #[test]
    fn inr18_tick_starts_build() {
        let mut rt = started_runtime(2);
        rt.enqueue_circuit_build(vec![node_id(10), node_id(11), node_id(12)], 2001);
        rt.tick_circuit_builds();
        assert_eq!(rt.build_driver().in_flight_count(), 1);
        assert_eq!(rt.build_driver().pending_count(), 0);
    }

    // INR19: complete_circuit_build marks build done.
    #[test]
    fn inr19_complete_circuit_build() {
        let mut rt = started_runtime(3);
        rt.enqueue_circuit_build(vec![node_id(10), node_id(11), node_id(12)], 3001);
        rt.tick_circuit_builds();
        assert!(rt.complete_circuit_build(3001));
        assert_eq!(rt.build_driver().in_flight_count(), 0);
        assert_eq!(rt.build_driver().completed_builds().len(), 1);
    }

    // INR20: advance_epoch_driven ticks build driver each step.
    #[test]
    fn inr20_epoch_driven_ticks_build_driver() {
        let mut rt = started_runtime(4);
        rt.enqueue_circuit_build(vec![node_id(10), node_id(11), node_id(12)], 4001);
        rt.advance_epoch_driven(1);
        assert_eq!(rt.build_driver().in_flight_count(), 1);
        assert_eq!(rt.build_driver().metrics().total_started, 1);
    }

    // INR11: advance_epoch_driven advances current_epoch.
    #[test]
    fn inr11_driven_epoch_advances() {
        let mut rt = started_runtime(1);
        assert_eq!(rt.current_epoch(), 1);
        rt.advance_epoch_driven(3);
        assert_eq!(rt.current_epoch(), 4);
    }

    // INR12: epoch_driver() epoch matches current_epoch after advance_epoch_driven.
    #[test]
    fn inr12_driver_epoch_consistent() {
        let mut rt = started_runtime(1);
        rt.advance_epoch_driven(5);
        // driver starts at bootstrap epoch 1; after 5 ticks it's at 6
        assert_eq!(rt.epoch_driver().epoch(), 6);
        assert_eq!(rt.current_epoch(), 6);
    }

    // INR13: subscriber attached to runtime is notified per tick.
    #[test]
    fn inr13_subscriber_notified_via_runtime() {
        struct Counter(u64);
        impl EpochSubscriber for Counter {
            fn on_epoch(&mut self, _e: u64) {
                self.0 += 1;
            }
            fn name(&self) -> &str {
                "counter"
            }
        }
        let mut rt = started_runtime(2);
        rt.subscribe_epoch(Box::new(Counter(0)));
        rt.advance_epoch_driven(4);
        assert_eq!(rt.epoch_driver().metrics().total_subscriber_calls, 4);
    }

    // INR14: unsubscribe stops notifications.
    #[test]
    fn inr14_unsubscribe_stops_notifications() {
        struct Counter;
        impl EpochSubscriber for Counter {
            fn on_epoch(&mut self, _e: u64) {}
            fn name(&self) -> &str {
                "c"
            }
        }
        let mut rt = started_runtime(3);
        let id = rt.subscribe_epoch(Box::new(Counter));
        rt.advance_epoch_driven(2);
        assert_eq!(rt.epoch_driver().metrics().total_subscriber_calls, 2);
        rt.unsubscribe_epoch(id);
        rt.advance_epoch_driven(3);
        assert_eq!(rt.epoch_driver().metrics().total_subscriber_calls, 2);
    }

    // INR15: advance_epoch_driven with n=0 is a no-op.
    #[test]
    fn inr15_zero_ticks_noop() {
        let mut rt = started_runtime(4);
        let epoch_before = rt.current_epoch();
        rt.advance_epoch_driven(0);
        assert_eq!(rt.current_epoch(), epoch_before);
    }

    // INR16: circuits expired by advance_epoch_driven; audit records CircuitTornDown.
    #[test]
    fn inr16_circuits_expire_via_driven() {
        let mut rt = started_runtime(5);
        rt.open_circuit(node_id(10), node_id(11), node_id(12), 1)
            .unwrap();
        let idle = rt.config.rotation.idle_rotation_epochs + 10;
        rt.advance_epoch_driven(idle);
        let events = rt.audit().events();
        assert!(
            events
                .iter()
                .any(|e| e.kind == AuditEventKind::CircuitTornDown)
        );
    }
}
