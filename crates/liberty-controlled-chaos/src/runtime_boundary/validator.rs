//! `RuntimeBoundaryValidator` — the single validation checkpoint between
//! the Controlled Chaos Engine and `StreamMux`.
//!
//! Enforces all six checks from the Runtime Boundary Contract (§5) in order:
//!   V1  KillSwitch inactive
//!   V2  TunnelState is TunnelUp
//!   V3  path_id exists in the active path set
//!   V4  latency_deadline has not elapsed
//!   V5  payload_ref is valid
//!   V6  shadow packet budget not exceeded
//!
//! `validate(&self, ...)` never opens sockets, never calls OS APIs, and never
//! inspects payload bytes.  All state it reads is passed in at construction or
//! as method arguments.

use std::collections::HashSet;

use super::types::{
    ControlledChaosOutput, KillSwitchState, RejectionReason, RuntimePacketIntent,
    RuntimeValidationResult, ShadowBudgetTracker, TunnelState,
};
use crate::transmitter::{InvalidationReason, PathStats, PlanInvalidationEvent};

// ── RuntimeBoundaryValidator ──────────────────────────────────────────────────

/// The single validation checkpoint.  `Send + Sync` — `validate` takes `&self`.
///
/// Runtime state (kill switch, tunnel, path set) is owned here for Sprint 7.
/// Sprint 7+ network integration will replace owned values with
/// `Arc<AtomicBool>` / `Arc<RwLock<...>>` shared with the VPN service.
#[derive(Debug)]
pub struct RuntimeBoundaryValidator {
    kill_switch: KillSwitchState,
    tunnel_state: TunnelState,
    active_paths: HashSet<u64>,
}

impl RuntimeBoundaryValidator {
    pub fn new(
        kill_switch: KillSwitchState,
        tunnel_state: TunnelState,
        active_paths: HashSet<u64>,
    ) -> Self {
        Self {
            kill_switch,
            tunnel_state,
            active_paths,
        }
    }

    pub fn update_kill_switch(&mut self, state: KillSwitchState) {
        self.kill_switch = state;
    }

    pub fn update_tunnel_state(&mut self, state: TunnelState) {
        self.tunnel_state = state;
    }

    pub fn add_path(&mut self, path_id: u64) {
        self.active_paths.insert(path_id);
    }

    pub fn remove_path(&mut self, path_id: u64) {
        self.active_paths.remove(&path_id);
    }

    /// Validate `output` against the six runtime checks (V1–V6).
    ///
    /// Returns `Accept(RuntimePacketIntent)` when all checks pass.
    /// Returns `Reject(reason)` on the first failing check.
    ///
    /// Callers are responsible for surfacing errors to the appropriate layer:
    /// - Real packets: surface `RejectionReason` as an error to the forwarder.
    /// - Shadow/cover packets: drop silently (check `output.packet_class` first).
    pub fn validate(
        &self,
        output: ControlledChaosOutput,
        now_us: u64,
        budget: &mut ShadowBudgetTracker,
    ) -> RuntimeValidationResult {
        // Extract fields needed for rejection payloads before output is consumed.
        let path_id = output.path_id;
        let flow_id = output.flow_id;
        let is_shadow = output.packet_class.is_shadow_or_cover();
        let latency_deadline = output.latency_deadline;
        let payload_length = output.payload_ref.length();

        // V1: KillSwitch must be inactive — highest-priority global gate.
        if self.kill_switch == KillSwitchState::Active {
            return RuntimeValidationResult::Reject(RejectionReason::KillSwitchActive);
        }

        // V2: Tunnel must be up — all traffic requires an active VPN tunnel.
        if !self.tunnel_state.is_up() {
            return RuntimeValidationResult::Reject(RejectionReason::TunnelDown);
        }

        // V3: path_id must exist — checked before deadline (invalid path ⇒ no deadline).
        if !self.active_paths.contains(&path_id) {
            // Emit PlanInvalidationEvent only for real packets (shadow drops silently).
            let invalidation = if !is_shadow {
                Some(PlanInvalidationEvent {
                    reason: InvalidationReason::PathDown { path_id },
                    affected_path: Some(path_id),
                    current_stats: PathStats {
                        path_id,
                        rtt_ms: 0,
                        loss_pct: 0.0,
                        available_kbps: 0,
                    },
                })
            } else {
                None
            };
            return RuntimeValidationResult::Reject(RejectionReason::PathNotFound {
                path_id,
                invalidation,
            });
        }

        // V4: latency_deadline must not have elapsed.
        if now_us > latency_deadline {
            return RuntimeValidationResult::Reject(RejectionReason::DeadlineMissed {
                path_id,
                late_by_us: now_us - latency_deadline,
            });
        }

        // V5: payload_ref must be structurally valid.
        if !output.payload_ref.is_valid() {
            return RuntimeValidationResult::Reject(RejectionReason::PayloadRefInvalid);
        }

        // V6: shadow/cover packets must not exceed per-flow epoch budget.
        if is_shadow {
            if !budget.has_budget(flow_id, payload_length) {
                return RuntimeValidationResult::Reject(RejectionReason::ShadowBudgetExceeded {
                    flow_id,
                });
            }
            budget.consume(flow_id, payload_length);
        }

        RuntimeValidationResult::Accept(RuntimePacketIntent::new(output))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_boundary::types::{PacketClass, PayloadRef};

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn make_validator() -> RuntimeBoundaryValidator {
        let mut paths = HashSet::new();
        paths.insert(1u64);
        RuntimeBoundaryValidator::new(KillSwitchState::Inactive, TunnelState::TunnelUp, paths)
    }

    fn make_budget() -> ShadowBudgetTracker {
        ShadowBudgetTracker::new(10_000)
    }

    fn make_output(
        path_id: u64,
        flow_id: u64,
        class: PacketClass,
        deadline_us: u64,
    ) -> ControlledChaosOutput {
        let shadow_flag = class == PacketClass::Shadow;
        ControlledChaosOutput {
            path_id,
            flow_id,
            fragment_id: 0,
            scheduled_send_time: 0,
            shadow_flag,
            packet_class: class,
            latency_deadline: deadline_us,
            payload_ref: PayloadRef::new(0, 200).unwrap(),
        }
    }

    const NOW: u64 = 1_000_000; // 1 s reference time
    const FUTURE: u64 = NOW + 50_000; // deadline 50 ms from now

    // ── Baseline ─────────────────────────────────────────────────────────────

    #[test]
    fn valid_packet_accepted() {
        let v = make_validator();
        let mut b = make_budget();
        let out = make_output(1, 42, PacketClass::Real, FUTURE);
        let result = v.validate(out, NOW, &mut b);
        assert!(result.is_accepted(), "expected Accept, got {result:?}");
    }

    #[test]
    fn valid_shadow_packet_accepted_and_budget_consumed() {
        let v = make_validator();
        let mut b = make_budget();
        let out = make_output(1, 42, PacketClass::Shadow, FUTURE);
        let result = v.validate(out, NOW, &mut b);
        assert!(result.is_accepted());
        assert_eq!(b.consumed_for(42), 200);
    }

    // ── B1: Kill switch blocks all packet classes ─────────────────────────────

    #[test]
    fn b1_kill_switch_blocks_all_intents() {
        let mut v = make_validator();
        v.update_kill_switch(KillSwitchState::Active);
        let mut b = make_budget();

        for class in [PacketClass::Real, PacketClass::Shadow, PacketClass::Cover] {
            let out = make_output(1, 1, class, FUTURE);
            let result = v.validate(out, NOW, &mut b);
            assert!(
                matches!(
                    result.rejection_reason(),
                    Some(RejectionReason::KillSwitchActive)
                ),
                "kill switch must block all classes"
            );
        }
    }

    // ── B2: Tunnel down blocks all packet classes ─────────────────────────────

    #[test]
    fn b2_tunnel_down_blocks_all_intents() {
        for tunnel_state in [
            TunnelState::TunnelConnecting,
            TunnelState::TunnelFailed,
            TunnelState::TunnelTeardown,
        ] {
            let mut paths = HashSet::new();
            paths.insert(1u64);
            let v = RuntimeBoundaryValidator::new(KillSwitchState::Inactive, tunnel_state, paths);
            let mut b = make_budget();
            let out = make_output(1, 1, PacketClass::Real, FUTURE);
            let result = v.validate(out, NOW, &mut b);
            assert!(
                matches!(result.rejection_reason(), Some(RejectionReason::TunnelDown)),
                "tunnel not TunnelUp must block all intents"
            );
        }
    }

    // ── B3: Invalid path_id rejected with PlanInvalidationEvent ──────────────

    #[test]
    fn b3_invalid_path_rejected() {
        let v = make_validator(); // only path 1 is active
        let mut b = make_budget();
        let out = make_output(99, 1, PacketClass::Real, FUTURE);
        let result = v.validate(out, NOW, &mut b);
        match result.rejection_reason() {
            Some(RejectionReason::PathNotFound {
                path_id,
                invalidation,
            }) => {
                assert_eq!(*path_id, 99);
                assert!(
                    invalidation.is_some(),
                    "real packet on invalid path must carry PlanInvalidationEvent"
                );
            }
            other => panic!("expected PathNotFound, got {other:?}"),
        }
    }

    #[test]
    fn b3_invalid_path_shadow_drops_silently_no_invalidation_event() {
        let v = make_validator();
        let mut b = make_budget();
        let out = make_output(99, 1, PacketClass::Shadow, FUTURE);
        let result = v.validate(out, NOW, &mut b);
        match result.rejection_reason() {
            Some(RejectionReason::PathNotFound { invalidation, .. }) => {
                assert!(
                    invalidation.is_none(),
                    "shadow packet on invalid path must NOT emit PlanInvalidationEvent"
                );
            }
            other => panic!("expected PathNotFound, got {other:?}"),
        }
    }

    // ── Expired deadline rejection ────────────────────────────────────────────

    #[test]
    fn expired_deadline_rejected() {
        let v = make_validator();
        let mut b = make_budget();
        let expired = NOW - 1; // deadline is 1 μs in the past
        let out = make_output(1, 1, PacketClass::Real, expired);
        let result = v.validate(out, NOW, &mut b);
        assert!(
            matches!(
                result.rejection_reason(),
                Some(RejectionReason::DeadlineMissed { late_by_us: 1, .. })
            ),
            "expected DeadlineMissed(1), got {result:?}"
        );
    }

    #[test]
    fn exact_deadline_accepted() {
        let v = make_validator();
        let mut b = make_budget();
        let out = make_output(1, 1, PacketClass::Real, NOW); // now_us == deadline
        let result = v.validate(out, NOW, &mut b);
        assert!(
            result.is_accepted(),
            "now_us == latency_deadline must be accepted"
        );
    }

    // ── V5: Invalid PayloadRef rejected ──────────────────────────────────────

    #[test]
    fn invalid_payload_ref_rejected() {
        let v = make_validator();
        let mut b = make_budget();
        let mut out = make_output(1, 1, PacketClass::Real, FUTURE);
        out.payload_ref = PayloadRef::new_unchecked(0, 0); // length 0 is invalid
        let result = v.validate(out, NOW, &mut b);
        assert!(
            matches!(
                result.rejection_reason(),
                Some(RejectionReason::PayloadRefInvalid)
            ),
            "expected PayloadRefInvalid, got {result:?}"
        );
    }

    // ── B4: Shadow budget enforcement ─────────────────────────────────────────

    #[test]
    fn b4_shadow_packet_over_budget_dropped() {
        let v = make_validator();
        let mut b = ShadowBudgetTracker::new(300); // budget: 300 bytes per flow

        // First two shadow packets fit (200 + 200 = 400 > 300 → second fails).
        let out1 = make_output(1, 42, PacketClass::Shadow, FUTURE);
        assert!(v.validate(out1, NOW, &mut b).is_accepted());
        assert_eq!(b.consumed_for(42), 200);

        let out2 = make_output(1, 42, PacketClass::Shadow, FUTURE);
        let result = v.validate(out2, NOW, &mut b);
        assert!(
            matches!(
                result.rejection_reason(),
                Some(RejectionReason::ShadowBudgetExceeded { flow_id: 42 })
            ),
            "second shadow packet must be rejected when budget exhausted"
        );
        // Budget counter must not have advanced past the first consumption.
        assert_eq!(b.consumed_for(42), 200);
    }

    #[test]
    fn b4_real_packet_not_affected_by_shadow_budget() {
        let v = make_validator();
        let mut b = ShadowBudgetTracker::new(0); // zero shadow budget

        let out = make_output(1, 42, PacketClass::Real, FUTURE);
        let result = v.validate(out, NOW, &mut b);
        assert!(
            result.is_accepted(),
            "real packets must never be blocked by shadow budget"
        );
    }

    // ── B5: Real packets are never silently dropped ───────────────────────────

    #[test]
    fn b5_real_packet_never_silently_dropped() {
        // For every rejection cause, a Real packet must return an explicit Reject,
        // never Accept, and never panic.

        // KillSwitch active
        let mut v = make_validator();
        v.update_kill_switch(KillSwitchState::Active);
        let mut b = make_budget();
        let out = make_output(1, 1, PacketClass::Real, FUTURE);
        let r = v.validate(out, NOW, &mut b);
        assert!(r.is_rejected(), "KillSwitch: real must return Reject");

        // Tunnel down
        let mut v = make_validator();
        v.update_tunnel_state(TunnelState::TunnelFailed);
        let out = make_output(1, 1, PacketClass::Real, FUTURE);
        let r = v.validate(out, NOW, &mut make_budget());
        assert!(r.is_rejected(), "TunnelDown: real must return Reject");

        // Invalid path
        let v = make_validator();
        let out = make_output(99, 1, PacketClass::Real, FUTURE);
        let r = v.validate(out, NOW, &mut make_budget());
        assert!(r.is_rejected(), "PathNotFound: real must return Reject");

        // Deadline missed
        let v = make_validator();
        let out = make_output(1, 1, PacketClass::Real, NOW - 1);
        let r = v.validate(out, NOW, &mut make_budget());
        assert!(r.is_rejected(), "DeadlineMissed: real must return Reject");

        // Invalid payload_ref
        let v = make_validator();
        let mut out = make_output(1, 1, PacketClass::Real, FUTURE);
        out.payload_ref = PayloadRef::new_unchecked(0, 63); // below min 64
        let r = v.validate(out, NOW, &mut make_budget());
        assert!(
            r.is_rejected(),
            "PayloadRefInvalid: real must return Reject"
        );
    }

    // ── B6: No networking dependencies in the crate ───────────────────────────

    #[test]
    fn b6_no_networking_dependencies() {
        let output = match std::process::Command::new("cargo")
            .args(["tree", "-p", "liberty-controlled-chaos"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
        {
            Ok(o) => o,
            Err(_) => return, // cargo not on PATH; skip
        };
        let tree = String::from_utf8_lossy(&output.stdout);
        let forbidden = ["tokio", "mio", "socket2"];
        for name in &forbidden {
            assert!(
                !tree.contains(name),
                "liberty-controlled-chaos must not depend on networking crate '{name}'"
            );
        }
    }
}
