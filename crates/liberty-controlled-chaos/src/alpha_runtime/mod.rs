//! Alpha runtime — full system composition for the Liberty Shield alpha mesh.
//!
//! `AlphaRuntime` wires together configuration, control plane, audit log,
//! telemetry exporter, privacy profile, policy engine, trust/risk engine,
//! deception traffic, and timing scheduler into a single lifecycle object.
//!
//! This module is the top-level integration point for the alpha milestone;
//! it does not perform real I/O.

use crate::alpha_runtime::lifecycle::{LifecycleError, LifecyclePhase};
use crate::anti_correlation_timing::{TimingPolicy, TimingScheduler};
use crate::control_plane::{ControlCommand, ControlPlane, NodeStatus};
use crate::deception_traffic::{DeceptionEngine, DeceptionLevel};
use crate::policy_engine::{PolicyAction, PolicyEngine, PolicyRequest};
use crate::privacy_profiles::{PrivacyProfile, ProfileLevel};
use crate::readiness_report::ReadinessReportBuilder;
use crate::runtime_audit::{AuditEventKind, AuditSeverity, RuntimeAuditLog};
use crate::telemetry_exporter::TelemetryExporter;
use crate::trust_risk_engine::TrustRiskEngine;

// Re-export lifecycle for tests.
pub mod lifecycle {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum LifecyclePhase {
        Init,
        Bootstrapping,
        Running,
        ShuttingDown,
        Halted,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum LifecycleError {
        InvalidPhaseTransition,
        AlreadyHalted,
        NotRunning,
    }
}

// ---------------------------------------------------------------------------
// AlphaRuntimeConfig
// ---------------------------------------------------------------------------

pub struct AlphaRuntimeConfig {
    pub node_id: [u8; 32],
    pub privacy_level: ProfileLevel,
    pub quarantine_threshold: f64,
    pub max_circuit_lifetime: u64,
    pub real_traffic_estimate: u64,
    pub audit_max_entries: usize,
    pub telemetry_salt: [u8; 8],
}

impl Default for AlphaRuntimeConfig {
    fn default() -> Self {
        Self {
            node_id: [0u8; 32],
            privacy_level: ProfileLevel::Standard,
            quarantine_threshold: 0.7,
            max_circuit_lifetime: 100,
            real_traffic_estimate: 10_000,
            audit_max_entries: 1000,
            telemetry_salt: [1, 2, 3, 4, 5, 6, 7, 8],
        }
    }
}

// ---------------------------------------------------------------------------
// AlphaRuntime
// ---------------------------------------------------------------------------

pub struct AlphaRuntime {
    pub node_id: [u8; 32],
    phase: LifecyclePhase,
    control_plane: ControlPlane,
    audit: RuntimeAuditLog,
    telemetry: TelemetryExporter,
    profile: PrivacyProfile,
    policy: PolicyEngine,
    risk: TrustRiskEngine,
    deception: DeceptionEngine,
    timing: TimingScheduler,
    epoch: u64,
    circuits_built: u64,
    packets_processed: u64,
}

impl AlphaRuntime {
    pub fn new(cfg: AlphaRuntimeConfig) -> Self {
        let deception_level = match cfg.privacy_level {
            ProfileLevel::Standard => DeceptionLevel::Low,
            ProfileLevel::Strong => DeceptionLevel::Medium,
            ProfileLevel::Paranoid | ProfileLevel::DeceptionHeavy => DeceptionLevel::High,
        };
        Self {
            node_id: cfg.node_id,
            phase: LifecyclePhase::Init,
            control_plane: ControlPlane::new(),
            audit: RuntimeAuditLog::new(cfg.audit_max_entries),
            telemetry: TelemetryExporter::new(cfg.telemetry_salt, 50),
            profile: PrivacyProfile::new(cfg.privacy_level),
            policy: PolicyEngine::new(),
            risk: TrustRiskEngine::new(cfg.quarantine_threshold, cfg.max_circuit_lifetime),
            deception: DeceptionEngine::new(deception_level, cfg.real_traffic_estimate),
            timing: TimingScheduler::new(TimingPolicy::default(), 0, 0xDEAD_BEEF),
            epoch: 0,
            circuits_built: 0,
            packets_processed: 0,
        }
    }

    // ----- Lifecycle -------------------------------------------------------

    pub fn start(&mut self) -> Result<(), LifecycleError> {
        if self.phase != LifecyclePhase::Init {
            return Err(LifecycleError::InvalidPhaseTransition);
        }
        self.phase = LifecyclePhase::Bootstrapping;
        self.audit
            .append(self.epoch, AuditSeverity::Info, AuditEventKind::NodeStarted);
        Ok(())
    }

    pub fn complete_bootstrap(&mut self) -> Result<(), LifecycleError> {
        if self.phase != LifecyclePhase::Bootstrapping {
            return Err(LifecycleError::InvalidPhaseTransition);
        }
        self.phase = LifecyclePhase::Running;
        self.control_plane
            .execute(ControlCommand::SetStatus(NodeStatus::Running))
            .ok();
        self.audit.append(
            self.epoch,
            AuditSeverity::Info,
            AuditEventKind::BootstrapCompleted,
        );
        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<(), LifecycleError> {
        if self.phase == LifecyclePhase::Halted {
            return Err(LifecycleError::AlreadyHalted);
        }
        self.phase = LifecyclePhase::ShuttingDown;
        self.control_plane.execute(ControlCommand::Shutdown).ok();
        self.audit
            .append(self.epoch, AuditSeverity::Info, AuditEventKind::NodeStopped);
        self.phase = LifecyclePhase::Halted;
        Ok(())
    }

    // ----- Epoch tick -------------------------------------------------------

    pub fn advance_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
        self.deception.advance_epoch(epoch);
        // Export a telemetry snapshot.
        let snap = self.telemetry.build_snapshot(
            epoch,
            self.circuits_built,
            0,
            self.packets_processed,
            self.profile.params().cover_ratio,
        );
        self.telemetry.push_snapshot(snap);
    }

    // ----- Peer management -------------------------------------------------

    pub fn admit_peer(&mut self, node_id: [u8; 32], trust_score: f64) -> PolicyAction {
        let action = self.policy.evaluate(&PolicyRequest::PeerAdmission {
            node_id,
            trust_score,
        });
        if action == PolicyAction::Allow {
            self.risk.upsert_peer(node_id, trust_score);
            self.audit.append_with(
                self.epoch,
                AuditSeverity::Info,
                AuditEventKind::PeerAdmitted,
                Some(node_id),
                None,
            );
        } else {
            self.audit.append_with(
                self.epoch,
                AuditSeverity::Warning,
                AuditEventKind::PolicyDenied,
                Some(node_id),
                None,
            );
        }
        action
    }

    // ----- Circuit management -----------------------------------------------

    pub fn build_circuit(
        &mut self,
        circuit_id: u64,
        guard: [u8; 32],
        relay: [u8; 32],
        exit: [u8; 32],
    ) {
        self.risk
            .register_circuit(circuit_id, guard, relay, exit, self.epoch);
        self.audit.append_with(
            self.epoch,
            AuditSeverity::Info,
            AuditEventKind::CircuitBuilt,
            None,
            Some(circuit_id),
        );
        self.circuits_built += 1;
    }

    pub fn process_packet(&mut self, data: Vec<u8>) {
        self.timing.schedule(data);
        self.packets_processed += 1;
    }

    // ----- Privacy profile --------------------------------------------------

    pub fn set_privacy_level(&mut self, level: ProfileLevel) {
        self.profile.switch_to(level);
        self.audit
            .append(self.epoch, AuditSeverity::Info, AuditEventKind::KeyRotated);
    }

    // ----- Readiness --------------------------------------------------------

    pub fn readiness_report(&self) -> crate::readiness_report::ReadinessReport {
        let mut b = ReadinessReportBuilder::new(self.epoch);
        b.add_module("control_plane")
            .add_module("runtime_audit")
            .add_module("telemetry_exporter")
            .add_module("privacy_profiles")
            .add_module("policy_engine")
            .add_module("trust_risk_engine")
            .add_module("deception_traffic")
            .add_module("anti_correlation_timing")
            .set_test_count(self.audit.len() as u32);
        if self.phase == LifecyclePhase::Halted {
            b.add_blocker("lifecycle", "node is halted");
        }
        b.build()
    }

    // ----- Accessors --------------------------------------------------------

    pub fn phase(&self) -> LifecyclePhase {
        self.phase
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn circuits_built(&self) -> u64 {
        self.circuits_built
    }

    pub fn packets_processed(&self) -> u64 {
        self.packets_processed
    }

    pub fn audit(&self) -> &RuntimeAuditLog {
        &self.audit
    }

    pub fn telemetry(&self) -> &TelemetryExporter {
        &self.telemetry
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_engine::PolicyRule;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn default_runtime() -> AlphaRuntime {
        AlphaRuntime::new(AlphaRuntimeConfig::default())
    }

    // AR1: initial phase is Init.
    #[test]
    fn ar1_initial_phase() {
        let rt = default_runtime();
        assert_eq!(rt.phase(), LifecyclePhase::Init);
    }

    // AR2: start transitions to Bootstrapping.
    #[test]
    fn ar2_start_transitions() {
        let mut rt = default_runtime();
        rt.start().unwrap();
        assert_eq!(rt.phase(), LifecyclePhase::Bootstrapping);
    }

    // AR3: complete_bootstrap transitions to Running.
    #[test]
    fn ar3_complete_bootstrap() {
        let mut rt = default_runtime();
        rt.start().unwrap();
        rt.complete_bootstrap().unwrap();
        assert_eq!(rt.phase(), LifecyclePhase::Running);
    }

    // AR4: shutdown transitions to Halted.
    #[test]
    fn ar4_shutdown() {
        let mut rt = default_runtime();
        rt.start().unwrap();
        rt.shutdown().unwrap();
        assert_eq!(rt.phase(), LifecyclePhase::Halted);
    }

    // AR5: double shutdown returns AlreadyHalted.
    #[test]
    fn ar5_double_shutdown() {
        let mut rt = default_runtime();
        rt.start().unwrap();
        rt.shutdown().unwrap();
        assert_eq!(rt.shutdown(), Err(LifecycleError::AlreadyHalted));
    }

    // AR6: start on non-Init returns InvalidPhaseTransition.
    #[test]
    fn ar6_invalid_start() {
        let mut rt = default_runtime();
        rt.start().unwrap();
        assert_eq!(rt.start(), Err(LifecycleError::InvalidPhaseTransition));
    }

    // AR7: admit_peer with high trust returns Allow.
    #[test]
    fn ar7_admit_peer_allow() {
        let mut rt = default_runtime();
        rt.start().unwrap();
        let action = rt.admit_peer(nid(1), 0.9);
        assert_eq!(action, PolicyAction::Allow);
    }

    // AR8: build_circuit increments circuits_built.
    #[test]
    fn ar8_build_circuit() {
        let mut rt = default_runtime();
        rt.start().unwrap();
        rt.build_circuit(1, nid(1), nid(2), nid(3));
        assert_eq!(rt.circuits_built(), 1);
    }

    // AR9: process_packet increments packets_processed.
    #[test]
    fn ar9_process_packet() {
        let mut rt = default_runtime();
        rt.start().unwrap();
        rt.process_packet(vec![1, 2, 3]);
        assert_eq!(rt.packets_processed(), 1);
    }

    // AR10: advance_epoch pushes telemetry snapshot.
    #[test]
    fn ar10_advance_epoch_telemetry() {
        let mut rt = default_runtime();
        rt.start().unwrap();
        rt.advance_epoch(5);
        assert!(rt.telemetry().latest().is_some());
    }

    // AR11: audit log records NodeStarted on start().
    #[test]
    fn ar11_audit_node_started() {
        let mut rt = default_runtime();
        rt.start().unwrap();
        let events = rt.audit().by_severity(AuditSeverity::Info);
        assert!(events.iter().any(|e| e.kind == AuditEventKind::NodeStarted));
    }

    // AR12: set_privacy_level changes profile.
    #[test]
    fn ar12_set_privacy_level() {
        let mut rt = default_runtime();
        rt.start().unwrap();
        rt.set_privacy_level(ProfileLevel::Paranoid);
        assert_eq!(rt.profile.active_level(), ProfileLevel::Paranoid);
    }

    // AR13: readiness_report has no blockers when running.
    #[test]
    fn ar13_readiness_no_blockers_running() {
        let mut rt = default_runtime();
        rt.start().unwrap();
        rt.complete_bootstrap().unwrap();
        assert_eq!(rt.readiness_report().blockers().len(), 0);
    }

    // AR14: readiness_report has blocker when halted.
    #[test]
    fn ar14_readiness_blocker_when_halted() {
        let mut rt = default_runtime();
        rt.start().unwrap();
        rt.shutdown().unwrap();
        assert!(!rt.readiness_report().blockers().is_empty());
    }

    // AR15: epoch() reflects last advance_epoch call.
    #[test]
    fn ar15_epoch_tracks() {
        let mut rt = default_runtime();
        rt.start().unwrap();
        rt.advance_epoch(10);
        assert_eq!(rt.epoch(), 10);
    }

    // AR16: multiple advance_epoch calls accumulate snapshots.
    #[test]
    fn ar16_multiple_epochs_multiple_snapshots() {
        let mut rt = default_runtime();
        rt.start().unwrap();
        for i in 1..=5 {
            rt.advance_epoch(i);
        }
        assert_eq!(rt.telemetry().snapshots().len(), 5);
    }

    // AR17: admit_peer records PolicyDenied in audit for low-trust peer when rule exists.
    #[test]
    fn ar17_deny_low_trust_audit() {
        let mut rt = default_runtime();
        rt.policy.add_rule(PolicyRule::deny_low_trust(0.5));
        rt.start().unwrap();
        rt.admit_peer(nid(99), 0.1);
        let warns = rt.audit().by_severity(AuditSeverity::Warning);
        assert!(warns.iter().any(|e| e.kind == AuditEventKind::PolicyDenied));
    }

    // AR18: readiness_report modules_checked is populated.
    #[test]
    fn ar18_readiness_modules() {
        let rt = default_runtime();
        let r = rt.readiness_report();
        assert!(!r.modules_checked.is_empty());
    }

    // AR19: build_circuit records CircuitBuilt in audit.
    #[test]
    fn ar19_circuit_built_audit() {
        let mut rt = default_runtime();
        rt.start().unwrap();
        rt.build_circuit(7, nid(1), nid(2), nid(3));
        let events = rt.audit().by_severity(AuditSeverity::Info);
        assert!(
            events
                .iter()
                .any(|e| e.kind == AuditEventKind::CircuitBuilt)
        );
    }

    // AR20: full lifecycle sequence completes without error.
    #[test]
    fn ar20_full_lifecycle() {
        let mut rt = AlphaRuntime::new(AlphaRuntimeConfig {
            node_id: nid(1),
            privacy_level: ProfileLevel::Strong,
            ..Default::default()
        });
        rt.start().unwrap();
        rt.complete_bootstrap().unwrap();
        rt.admit_peer(nid(2), 0.8);
        rt.build_circuit(1, nid(2), nid(3), nid(4));
        rt.process_packet(vec![0xDE, 0xAD]);
        rt.advance_epoch(1);
        let report = rt.readiness_report();
        assert!(report.is_ready());
        rt.shutdown().unwrap();
        assert_eq!(rt.phase(), LifecyclePhase::Halted);
    }
}
