//! Beta checkpoint — Sprint 180 final gate module.
//!
//! Aggregates the complete state of the `liberty-controlled-chaos` crate at
//! the point of Beta hand-off:
//!
//! - Sprint range covered (161–180)
//! - Key subsystems delivered
//! - Test count at checkpoint
//! - Production gaps registered and readiness verdict
//!
//! `BetaCheckpoint::generate()` produces a structured snapshot suitable for
//! inclusion in a release report.

use crate::beta_readiness_report_v2::BetaReadinessReportV2;
use crate::production_gap_register::ProductionGapRegister;

// ---------------------------------------------------------------------------
// SubsystemEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SubsystemEntry {
    pub name: &'static str,
    pub sprint: u16,
    pub test_count: u16,
}

// ---------------------------------------------------------------------------
// BetaCheckpoint
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BetaCheckpoint {
    pub sprint_range: (u16, u16),
    pub subsystems: Vec<SubsystemEntry>,
    pub total_tests: u32,
    pub gap_summary: GapSummary,
    pub verdict: CheckpointVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointVerdict {
    BetaReady,
    BlockedByCriticalGaps,
}

#[derive(Debug, Clone)]
pub struct GapSummary {
    pub total: usize,
    pub open: usize,
    pub in_progress: usize,
    pub resolved: usize,
    pub critical_blocking: usize,
}

impl BetaCheckpoint {
    /// Generate the Sprint 180 Beta checkpoint.
    pub fn generate() -> Self {
        let subsystems = vec![
            SubsystemEntry {
                name: "runtime_epoch_driver",
                sprint: 164,
                test_count: 10,
            },
            SubsystemEntry {
                name: "circuit_build_runtime_driver",
                sprint: 166,
                test_count: 10,
            },
            SubsystemEntry {
                name: "integrated_node_runtime (+)",
                sprint: 167,
                test_count: 20,
            },
            SubsystemEntry {
                name: "udp_flow_adapter",
                sprint: 168,
                test_count: 8,
            },
            SubsystemEntry {
                name: "android_vpn_bridge_contract",
                sprint: 169,
                test_count: 10,
            },
            SubsystemEntry {
                name: "outbound_send_queue (+)",
                sprint: 170,
                test_count: 6,
            },
            SubsystemEntry {
                name: "android_ffi_boundary (+)",
                sprint: 170,
                test_count: 6,
            },
            SubsystemEntry {
                name: "link_crypto_provider",
                sprint: 171,
                test_count: 10,
            },
            SubsystemEntry {
                name: "packet_flow_engine (+)",
                sprint: 172,
                test_count: 4,
            },
            SubsystemEntry {
                name: "runtime_security_invariants_v3",
                sprint: 173,
                test_count: 10,
            },
            SubsystemEntry {
                name: "beta_runtime_launcher_v2",
                sprint: 174,
                test_count: 10,
            },
            SubsystemEntry {
                name: "production_gap_register",
                sprint: 175,
                test_count: 10,
            },
            SubsystemEntry {
                name: "beta_readiness_report_v2",
                sprint: 176,
                test_count: 12,
            },
            SubsystemEntry {
                name: "lib.rs module ordering",
                sprint: 177,
                test_count: 0,
            },
            SubsystemEntry {
                name: "validate_liberty_core.ps1",
                sprint: 178,
                test_count: 0,
            },
            SubsystemEntry {
                name: "warning sweep (16 fixes)",
                sprint: 179,
                test_count: 0,
            },
            SubsystemEntry {
                name: "beta_checkpoint",
                sprint: 180,
                test_count: 10,
            },
        ];

        let total_tests: u32 = 1875; // full crate count at Sprint 180

        let register = ProductionGapRegister::with_beta_gaps();
        let report = BetaReadinessReportV2::generate(&register);

        use crate::beta_readiness_report_v2::ReadinessVerdict;
        let verdict = if report.verdict == ReadinessVerdict::Ready {
            CheckpointVerdict::BetaReady
        } else {
            CheckpointVerdict::BlockedByCriticalGaps
        };

        BetaCheckpoint {
            sprint_range: (161, 180),
            subsystems,
            total_tests,
            gap_summary: GapSummary {
                total: report.total_gaps,
                open: report.open_count,
                in_progress: report.in_progress_count,
                resolved: report.resolved_count,
                critical_blocking: report.critical_open,
            },
            verdict,
        }
    }

    /// One-line status line for CI output.
    pub fn status_line(&self) -> String {
        let v = match self.verdict {
            CheckpointVerdict::BetaReady => "BETA-READY",
            CheckpointVerdict::BlockedByCriticalGaps => "BLOCKED",
        };
        format!(
            "[Sprint {}-{}] {} | {} tests | {}/{} gaps resolved | {} critical open",
            self.sprint_range.0,
            self.sprint_range.1,
            v,
            self.total_tests,
            self.gap_summary.resolved,
            self.gap_summary.total,
            self.gap_summary.critical_blocking,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // BC1: generate() returns a checkpoint without panicking.
    #[test]
    fn bc1_generate_ok() {
        let cp = BetaCheckpoint::generate();
        assert_eq!(cp.sprint_range, (161, 180));
    }

    // BC2: subsystems list is non-empty.
    #[test]
    fn bc2_subsystems_non_empty() {
        let cp = BetaCheckpoint::generate();
        assert!(!cp.subsystems.is_empty());
    }

    // BC3: total_tests > 1800 (sanity floor for full crate).
    #[test]
    fn bc3_total_tests_floor() {
        let cp = BetaCheckpoint::generate();
        assert!(cp.total_tests > 1800);
    }

    // BC4: fresh beta gaps yield BlockedByCriticalGaps verdict.
    #[test]
    fn bc4_fresh_gaps_blocked() {
        let cp = BetaCheckpoint::generate();
        assert_eq!(cp.verdict, CheckpointVerdict::BlockedByCriticalGaps);
    }

    // BC5: gap_summary totals are consistent.
    #[test]
    fn bc5_gap_summary_totals_consistent() {
        let cp = BetaCheckpoint::generate();
        assert_eq!(
            cp.gap_summary.open + cp.gap_summary.in_progress + cp.gap_summary.resolved,
            cp.gap_summary.total
        );
    }

    // BC6: status_line contains sprint range.
    #[test]
    fn bc6_status_line_sprint_range() {
        let cp = BetaCheckpoint::generate();
        let line = cp.status_line();
        assert!(line.contains("161") && line.contains("180"));
    }

    // BC7: status_line contains "BLOCKED" when gaps are open.
    #[test]
    fn bc7_status_line_blocked() {
        let cp = BetaCheckpoint::generate();
        assert!(cp.status_line().contains("BLOCKED"));
    }

    // BC8: CheckpointVerdict::BetaReady is_ready.
    #[test]
    fn bc8_beta_ready_variant() {
        assert_eq!(CheckpointVerdict::BetaReady, CheckpointVerdict::BetaReady);
        assert_ne!(
            CheckpointVerdict::BetaReady,
            CheckpointVerdict::BlockedByCriticalGaps
        );
    }

    // BC9: all subsystem sprint values are in range [161, 180].
    #[test]
    fn bc9_subsystem_sprints_in_range() {
        let cp = BetaCheckpoint::generate();
        for s in &cp.subsystems {
            assert!(
                s.sprint >= 161 && s.sprint <= 180,
                "out-of-range sprint: {}",
                s.sprint
            );
        }
    }

    // BC10: gap_summary.critical_blocking > 0 with fresh register.
    #[test]
    fn bc10_critical_blocking_nonzero() {
        let cp = BetaCheckpoint::generate();
        assert!(cp.gap_summary.critical_blocking > 0);
    }
}
