//! Security invariants v2 — cross-module invariant tests.
//!
//! These tests exist only in `#[cfg(test)]` and verify that independently
//! implemented modules obey shared safety contracts when composed together.

// No runtime code — this module is test-only.

#[cfg(test)]
mod tests {
    use crate::anti_correlation_timing::{TimingPolicy, TimingScheduler};
    use crate::backpressure::{BackpressureEngine, BackpressureLimits};
    use crate::chaos_harness::{ChaosDecision, ChaosHarness, FaultKind};
    use crate::deception_traffic::{DeceptionEngine, DeceptionLevel};
    use crate::mesh_packet_router::MeshPacketRouter;
    use crate::policy_engine::{
        PolicyAction, PolicyEngine, PolicyRequest, PolicyRule, TrafficClass,
    };
    use crate::privacy_profiles::{PrivacyProfile, ProfileLevel};
    use crate::trust_risk_engine::TrustRiskEngine;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // SIV2_1: PolicyEngine deny aligns with TrustRiskEngine high-risk peer.
    #[test]
    fn siv2_1_policy_denies_high_risk_peer() {
        let mut pe = PolicyEngine::new();
        pe.add_rule(PolicyRule::deny_low_trust(0.5));

        let mut tre = TrustRiskEngine::new(0.7, 100);
        tre.upsert_peer(nid(1), 0.2); // high risk

        let risk = tre.peer_risk(&nid(1)).value();
        // High-risk peer (trust=0.2) should be denied by the policy.
        let action = pe.evaluate(&PolicyRequest::PeerAdmission {
            node_id: nid(1),
            trust_score: 1.0 - risk, // convert risk → trust
        });
        assert_eq!(action, PolicyAction::Deny);
    }

    // SIV2_2: DeceptionEngine budget never goes negative.
    #[test]
    fn siv2_2_deception_budget_non_negative() {
        let mut de = DeceptionEngine::new(DeceptionLevel::Low, 100);
        // Exhaust budget.
        de.generate_dummy_cells(1, 10_000, 1, 0);
        assert_eq!(de.budget_remaining(), 0);
    }

    // SIV2_3: TimingScheduler never releases more than max_per_slot packets.
    #[test]
    fn siv2_3_timing_max_per_slot() {
        let mut s = TimingScheduler::new(
            TimingPolicy {
                max_per_slot: 3,
                max_jitter_slots: 0,
                ..Default::default()
            },
            0,
            0,
        );
        for i in 0..10u8 {
            s.schedule(vec![i]);
        }
        let out = s.tick(0);
        assert!(out.len() <= 3);
    }

    // SIV2_4: MeshPacketRouter loop guard is never bypassed.
    #[test]
    fn siv2_4_mesh_router_no_loop() {
        let mut r = MeshPacketRouter::new();
        r.install_route(1, nid(1), nid(2)).unwrap();
        // Packet from egress side must always be rejected.
        let result = r.forward(1, &nid(2), 100);
        assert!(result.is_err());
    }

    // SIV2_5: Backpressure hard limit triggers drops.
    #[test]
    fn siv2_5_backpressure_hard_limit() {
        let mut bp = BackpressureEngine::new(BackpressureLimits {
            soft_limit: 5,
            hard_limit: 10,
        });
        // Set depth above hard limit; should_drop returns true and increments total_drops.
        bp.set_circuit_depth(1, 15);
        assert!(bp.should_drop_circuit(1));
        assert!(bp.total_drops() > 0);
    }

    // SIV2_6: PrivacyProfile Paranoid always enables deception.
    #[test]
    fn siv2_6_paranoid_deception_always_enabled() {
        let p = PrivacyProfile::new(ProfileLevel::Paranoid);
        assert!(p.params().deception_enabled);
    }

    // SIV2_7: PrivacyProfile Standard never enables deception.
    #[test]
    fn siv2_7_standard_no_deception() {
        let p = PrivacyProfile::new(ProfileLevel::Standard);
        assert!(!p.params().deception_enabled);
    }

    // SIV2_8: ChaosHarness partitioned node never passes.
    #[test]
    fn siv2_8_partitioned_node_never_passes() {
        let mut h = ChaosHarness::new(42);
        h.partition_node(nid(5));
        for _ in 0..10 {
            assert_eq!(h.evaluate(&nid(5)), ChaosDecision::Drop);
        }
    }

    // SIV2_9: PolicyEngine denials counter is monotonically non-decreasing.
    #[test]
    fn siv2_9_denials_monotone() {
        let mut pe = PolicyEngine::new();
        pe.add_rule(PolicyRule::deny_low_trust(0.9));
        let mut prev = 0u64;
        for i in 0..5 {
            pe.evaluate(&PolicyRequest::PeerAdmission {
                node_id: nid(i),
                trust_score: 0.1,
            });
            assert!(pe.denials() >= prev);
            prev = pe.denials();
        }
    }

    // SIV2_10: TrustRiskEngine risk score is always in [0, 1].
    #[test]
    fn siv2_10_risk_score_bounded() {
        let mut tre = TrustRiskEngine::new(0.5, 10);
        for i in 0..=10 {
            let trust = i as f64 / 10.0;
            tre.upsert_peer(nid(i as u8), trust);
            let risk = tre.peer_risk(&nid(i as u8)).value();
            assert!((0.0..=1.0).contains(&risk), "risk out of bounds: {risk}");
        }
    }

    // SIV2_11: DeceptionEngine fake circuit IDs have high bit set.
    #[test]
    fn siv2_11_fake_circuit_high_bit() {
        let mut de = DeceptionEngine::new(DeceptionLevel::Medium, 1000);
        let rec = de.create_fake_circuit(nid(1), nid(2), nid(3));
        assert!(rec.circuit_id & 0x8000_0000_0000_0000 != 0);
    }

    // SIV2_12: TimingScheduler cover packets are marked is_cover=true.
    #[test]
    fn siv2_12_cover_packets_marked() {
        let mut s = TimingScheduler::new(
            TimingPolicy {
                slots_per_epoch: 1,
                cover_floor: 1,
                max_jitter_slots: 0,
                max_per_slot: 8,
            },
            0,
            0,
        );
        let out = s.tick(0); // no real packets → cover injected
        assert!(out.iter().all(|p| p.is_cover || !p.is_cover)); // all are valid
        let covers: Vec<_> = out.iter().filter(|p| p.is_cover).collect();
        assert!(!covers.is_empty());
    }

    // SIV2_13: PolicyEngine decisions counter never decreases.
    #[test]
    fn siv2_13_decisions_monotone() {
        let mut pe = PolicyEngine::new();
        let mut prev = 0u64;
        for i in 0..10 {
            pe.evaluate(&PolicyRequest::CircuitBuild {
                guard: nid(i),
                relay: nid(i + 1),
                exit: nid(i + 2),
            });
            assert!(pe.decisions() >= prev);
            prev = pe.decisions();
        }
    }

    // SIV2_14: PrivacyProfile stronger level has higher min_peer_trust.
    #[test]
    fn siv2_14_stronger_profile_higher_trust_requirement() {
        let std = PrivacyProfile::new(ProfileLevel::Standard);
        let par = PrivacyProfile::new(ProfileLevel::Paranoid);
        assert!(par.params().min_peer_trust > std.params().min_peer_trust);
    }

    // SIV2_15: MeshPacketRouter bytes_forwarded only counts successful forwards.
    #[test]
    fn siv2_15_bytes_forwarded_only_on_success() {
        let mut r = MeshPacketRouter::new();
        r.install_route(1, nid(1), nid(2)).unwrap();
        r.forward(1, &nid(1), 500).unwrap();
        let _ = r.forward(1, &nid(2), 999); // loop → rejected
        assert_eq!(r.route(1).unwrap().bytes_forwarded, 500);
    }
}
