//! Alpha-to-Beta runtime migration report — structured assessment of the current
//! node runtime architecture, production gaps, and the recommended path forward.
//!
//! ## What was built (Sprints 151-159)
//!
//! | Module | Role |
//! |--------|------|
//! | `integrated_node_runtime` | Lifecycle state machine (New→Running→Stopped) |
//! | `packet_flow_engine` | Full inbound/outbound packet pipeline |
//! | `node_runtime_tests` | 3-virtual-node in-memory simulation |
//! | `runtime_event_bridge` | Fan-out: NodeEventBus + Audit + Telemetry + Health |
//! | `failure_recovery_runtime` | Link failure → penalize → ban → teardown |
//! | `runtime_readiness_gate` | Pre-flight: config + caps + dir + pool gate |
//! | `real_udp_smoke_tests` | OS-level UDP socket loopback tests |
//! | `link_crypto_v2` | key_id, session lifetime, expiry, replay window |
//! | `android_ffi_boundary` | C-ABI surface for JNI (feature-gated) |
//!
//! ## Implemented flow
//!
//! ```text
//! Android JNI / CLI
//!     ↓  liberty_ingest_packet()
//! IntegratedNodeRuntime.ingest_packet()
//!     ↓  policy gate (PolicyEngine)
//!     ↓  resource accounting (ResourceGuard)
//!     ↓  telemetry (NetworkTelemetry)
//!     ↓  relay decision (OnionRelayRuntime)
//!         → Forward(next_hop)   → PacketFlowEngine.build_send_intent()
//!         → LocalDelivery       → delivered to stream layer
//!         → Drop                → logged
//! ```
//!
//! ## Production gaps (must close before Beta)
//!
//! 1. **Real Noise XX handshake** — link_crypto_v2 uses HMAC-SHA256 only.
//!    No confidentiality, no forward secrecy.
//! 2. **Outbound send queue** — `liberty_poll_send_intent` is a stub; the
//!    runtime has no actual outbound buffer between the relay decision and the
//!    JNI caller.
//! 3. **Epoch clock** — all epoch values are caller-provided. There is no
//!    monotonic clock integration; epoch skew is not defended.
//! 4. **Circuit build protocol not wired** — `LiveCircuitBuildProtocol` exists
//!    but `IntegratedNodeRuntime` does not drive CREATE/EXTEND/CREATED sequences.
//! 5. **Directory bootstrap** — `MeshDirectoryService` is populated manually in
//!    tests; no DNS-over-HTTPS or seeded authority list for real bootstrap.
//! 6. **Cover traffic not started** — `PaddingScheduler` and `AdaptiveCover`
//!    modules exist but are not invoked from `IntegratedNodeRuntime`.
//! 7. **Resource limits not connected** — `ResourceGuard` checks per-packet but
//!    does not enforce total memory or circuit-count limits across sessions.
//! 8. **Persistent state** — `SecurityStateStore` journal exists but is not
//!    loaded on restart; session keys are lost on process death.
//! 9. **Android VPN socket integration** — `ShieldVpnService` (Kotlin) is not
//!    wired to `liberty_ingest_packet`; packets are not yet bridged.
//! 10. **No real peer discovery** — `NodeDiscoveryEngine` polls a static list;
//!     gossip-based peer exchange is unimplemented.
//!
//! ## Recommended next 10 sprints (161-170)
//!
//! | Sprint | Title | Goal |
//! |--------|-------|------|
//! | 161 | outbound_send_queue | Ring-buffer of `SendIntent`s; wire into `PacketFlowEngine` and FFI poll |
//! | 162 | epoch_clock | Monotonic epoch ticker; inject into `IntegratedNodeRuntime` |
//! | 163 | circuit_build_wire | Drive `LiveCircuitBuildProtocol` from `IntegratedNodeRuntime.open_circuit` |
//! | 164 | cover_traffic_start | Start `PaddingScheduler` + `AdaptiveCover` from bootstrap completion |
//! | 165 | persistent_session_store | Load/save `SecurityStateStore` journal on init/stop |
//! | 166 | directory_seeded_bootstrap | Hardcoded seed list + `DirectoryClientRuntime` fetch on first boot |
//! | 167 | vpn_bridge_wire | Wire `ShieldVpnService.onPacket()` → JNI → `liberty_ingest_packet` |
//! | 168 | noise_xx_link_layer | Replace HMAC-SHA256 in `link_crypto_v2` with Noise XX (std only) |
//! | 169 | resource_guard_limits | Wire circuit-count + memory limits through `ResourceGuard` |
//! | 170 | beta_integration_test | End-to-end: VPN → relay → exit on two Android emulators |

// ---------------------------------------------------------------------------
// MigrationReport (machine-readable form)
// ---------------------------------------------------------------------------

/// Snapshot of the migration state at the end of Sprint 159.
#[derive(Debug, Clone)]
pub struct MigrationReport {
    pub sprint_range: (u32, u32),
    pub modules_added: Vec<&'static str>,
    pub tests_total: u32,
    pub production_gaps: Vec<&'static str>,
    pub next_sprints: Vec<(u32, &'static str)>,
}

impl MigrationReport {
    /// Build the Sprint 159 migration report.
    pub fn build() -> Self {
        Self {
            sprint_range: (151, 159),
            modules_added: vec![
                "integrated_node_runtime",
                "packet_flow_engine",
                "node_runtime_tests",
                "runtime_event_bridge",
                "failure_recovery_runtime",
                "runtime_readiness_gate",
                "real_udp_smoke_tests",
                "link_crypto_v2 (strengthened)",
                "android_ffi_boundary",
            ],
            tests_total: 1736,
            production_gaps: vec![
                "link_crypto_v2: HMAC-SHA256 only (no Noise XX)",
                "liberty_poll_send_intent: stub — no outbound queue",
                "epoch clock: caller-provided, no monotonic source",
                "circuit build protocol not driven from IntegratedNodeRuntime",
                "directory bootstrap: manual only, no seeded authority",
                "cover traffic not started at bootstrap",
                "resource guard: per-packet only, no total limits",
                "persistent state: SecurityStateStore not loaded on restart",
                "Android VPN bridge: ShieldVpnService not wired to FFI",
                "peer discovery: static list only, no gossip exchange",
            ],
            next_sprints: vec![
                (161, "outbound_send_queue"),
                (162, "epoch_clock"),
                (163, "circuit_build_wire"),
                (164, "cover_traffic_start"),
                (165, "persistent_session_store"),
                (166, "directory_seeded_bootstrap"),
                (167, "vpn_bridge_wire"),
                (168, "noise_xx_link_layer"),
                (169, "resource_guard_limits"),
                (170, "beta_integration_test"),
            ],
        }
    }

    pub fn gap_count(&self) -> usize {
        self.production_gaps.len()
    }

    pub fn module_count(&self) -> usize {
        self.modules_added.len()
    }

    pub fn is_beta_ready(&self) -> bool {
        self.production_gaps.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ATBM1: report builds without panic.
    #[test]
    fn atbm1_report_builds() {
        let r = MigrationReport::build();
        assert_eq!(r.sprint_range, (151, 159));
    }

    // ATBM2: exactly 9 modules listed.
    #[test]
    fn atbm2_module_count() {
        let r = MigrationReport::build();
        assert_eq!(r.module_count(), 9);
    }

    // ATBM3: exactly 10 production gaps listed.
    #[test]
    fn atbm3_gap_count() {
        let r = MigrationReport::build();
        assert_eq!(r.gap_count(), 10);
    }

    // ATBM4: not beta-ready (gaps remain).
    #[test]
    fn atbm4_not_beta_ready() {
        let r = MigrationReport::build();
        assert!(!r.is_beta_ready());
    }

    // ATBM5: 10 recommended next sprints.
    #[test]
    fn atbm5_next_sprints_count() {
        let r = MigrationReport::build();
        assert_eq!(r.next_sprints.len(), 10);
    }

    // ATBM6: test_count matches expected.
    #[test]
    fn atbm6_test_count() {
        let r = MigrationReport::build();
        assert_eq!(r.tests_total, 1736);
    }

    // ATBM7: next sprints start at 161.
    #[test]
    fn atbm7_next_sprint_starts_at_161() {
        let r = MigrationReport::build();
        assert_eq!(r.next_sprints[0].0, 161);
    }

    // ATBM8: noise_xx appears in gap list.
    #[test]
    fn atbm8_noise_xx_in_gaps() {
        let r = MigrationReport::build();
        assert!(r.production_gaps.iter().any(|g| g.contains("Noise XX")));
    }

    // ATBM9: all next sprint numbers are consecutive.
    #[test]
    fn atbm9_sprint_numbers_consecutive() {
        let r = MigrationReport::build();
        for (i, (sprint, _)) in r.next_sprints.iter().enumerate() {
            assert_eq!(*sprint, 161 + i as u32);
        }
    }

    // ATBM10: vpn_bridge_wire sprint is present.
    #[test]
    fn atbm10_vpn_bridge_sprint_present() {
        let r = MigrationReport::build();
        assert!(
            r.next_sprints
                .iter()
                .any(|(_, name)| *name == "vpn_bridge_wire")
        );
    }
}
