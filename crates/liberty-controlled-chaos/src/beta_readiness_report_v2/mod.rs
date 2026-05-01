//! Beta readiness report v2 — aggregates `ProductionGapRegister` status,
//! `BetaRuntimeLauncherV2` launch health, and subsystem checks into a single
//! structured readiness verdict.
//!
//! `BetaReadinessReportV2::generate()` inspects the gap register and
//! returns a `ReadinessVerdict` (Ready / NotReady) with a human-readable
//! summary and a list of blocking items.

use crate::production_gap_register::{GapPriority, GapStatus, ProductionGapRegister};

// ---------------------------------------------------------------------------
// ReadinessVerdict
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadinessVerdict {
    /// All critical gaps resolved; system may proceed to Beta.
    Ready,
    /// One or more critical gaps remain open; Beta is blocked.
    NotReady,
}

impl ReadinessVerdict {
    pub fn is_ready(&self) -> bool {
        *self == ReadinessVerdict::Ready
    }
}

// ---------------------------------------------------------------------------
// BlockingItem
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BlockingItem {
    pub gap_id: &'static str,
    pub subsystem: &'static str,
    pub description: &'static str,
}

// ---------------------------------------------------------------------------
// BetaReadinessReportV2
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BetaReadinessReportV2 {
    pub verdict: ReadinessVerdict,
    pub total_gaps: usize,
    pub open_count: usize,
    pub in_progress_count: usize,
    pub resolved_count: usize,
    pub critical_open: usize,
    pub blocking_items: Vec<BlockingItem>,
    pub summary: String,
}

impl BetaReadinessReportV2 {
    /// Generate a readiness report from the given gap register.
    pub fn generate(register: &ProductionGapRegister) -> Self {
        let all = register.all();
        let total_gaps = all.len();
        let open_count = register.count_by_status(GapStatus::Open);
        let in_progress_count = register.count_by_status(GapStatus::InProgress);
        let resolved_count = register.count_by_status(GapStatus::Resolved);

        let blocking_items: Vec<BlockingItem> = all
            .iter()
            .filter(|g| {
                g.priority == GapPriority::Critical
                    && (g.status == GapStatus::Open || g.status == GapStatus::InProgress)
            })
            .map(|g| BlockingItem {
                gap_id: g.id,
                subsystem: g.subsystem,
                description: g.description,
            })
            .collect();

        let critical_open = blocking_items.len();
        let verdict = if critical_open == 0 {
            ReadinessVerdict::Ready
        } else {
            ReadinessVerdict::NotReady
        };

        let summary = if verdict.is_ready() {
            format!(
                "BETA READY: {resolved_count}/{total_gaps} gaps resolved, \
                 0 critical blockers remaining"
            )
        } else {
            format!(
                "NOT READY: {critical_open} critical blocker(s) unresolved \
                 ({open_count} open, {in_progress_count} in-progress, \
                 {resolved_count} resolved of {total_gaps} total)"
            )
        };

        Self {
            verdict,
            total_gaps,
            open_count,
            in_progress_count,
            resolved_count,
            critical_open,
            blocking_items,
            summary,
        }
    }

    /// Returns true if the system is Beta-ready.
    pub fn is_ready(&self) -> bool {
        self.verdict.is_ready()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_gap_register::{GapPriority, GapStatus, ProductionGap};

    fn gap_register_all_resolved() -> ProductionGapRegister {
        let mut r = ProductionGapRegister::with_beta_gaps();
        let ids: Vec<&str> = r
            .by_priority(GapPriority::Critical)
            .iter()
            .map(|g| g.id)
            .collect();
        for id in ids {
            r.update_status(id, GapStatus::Resolved);
        }
        r
    }

    // BRR2_1: fresh beta gaps register yields NotReady.
    #[test]
    fn brr2_1_fresh_register_not_ready() {
        let r = ProductionGapRegister::with_beta_gaps();
        let report = BetaReadinessReportV2::generate(&r);
        assert_eq!(report.verdict, ReadinessVerdict::NotReady);
        assert!(!report.is_ready());
    }

    // BRR2_2: resolving all critical gaps yields Ready.
    #[test]
    fn brr2_2_resolved_criticals_ready() {
        let r = gap_register_all_resolved();
        let report = BetaReadinessReportV2::generate(&r);
        assert_eq!(report.verdict, ReadinessVerdict::Ready);
        assert!(report.is_ready());
    }

    // BRR2_3: blocking_items contains only unresolved critical gaps.
    #[test]
    fn brr2_3_blocking_items_only_critical_unresolved() {
        let r = ProductionGapRegister::with_beta_gaps();
        let report = BetaReadinessReportV2::generate(&r);
        for item in &report.blocking_items {
            let gap = r.all().iter().find(|g| g.id == item.gap_id).unwrap();
            assert_eq!(gap.priority, GapPriority::Critical);
            assert_ne!(gap.status, GapStatus::Resolved);
        }
    }

    // BRR2_4: total_gaps matches register length.
    #[test]
    fn brr2_4_total_gaps_count() {
        let r = ProductionGapRegister::with_beta_gaps();
        let report = BetaReadinessReportV2::generate(&r);
        assert_eq!(report.total_gaps, r.all().len());
    }

    // BRR2_5: open + in_progress + resolved = total.
    #[test]
    fn brr2_5_counts_sum_to_total() {
        let r = ProductionGapRegister::with_beta_gaps();
        let report = BetaReadinessReportV2::generate(&r);
        assert_eq!(
            report.open_count + report.in_progress_count + report.resolved_count,
            report.total_gaps
        );
    }

    // BRR2_6: summary starts with "NOT READY" when not ready.
    #[test]
    fn brr2_6_summary_prefix_not_ready() {
        let r = ProductionGapRegister::with_beta_gaps();
        let report = BetaReadinessReportV2::generate(&r);
        assert!(report.summary.starts_with("NOT READY"));
    }

    // BRR2_7: summary starts with "BETA READY" when ready.
    #[test]
    fn brr2_7_summary_prefix_ready() {
        let r = gap_register_all_resolved();
        let report = BetaReadinessReportV2::generate(&r);
        assert!(report.summary.starts_with("BETA READY"));
    }

    // BRR2_8: critical_open reflects the number of blocking items.
    #[test]
    fn brr2_8_critical_open_matches_blocking() {
        let r = ProductionGapRegister::with_beta_gaps();
        let report = BetaReadinessReportV2::generate(&r);
        assert_eq!(report.critical_open, report.blocking_items.len());
    }

    // BRR2_9: InProgress critical gaps are still blocking.
    #[test]
    fn brr2_9_in_progress_critical_is_blocking() {
        let mut r = ProductionGapRegister::with_beta_gaps();
        r.update_status("CRYPTO-001", GapStatus::InProgress);
        let report = BetaReadinessReportV2::generate(&r);
        let ids: Vec<&str> = report.blocking_items.iter().map(|b| b.gap_id).collect();
        assert!(ids.contains(&"CRYPTO-001"));
        assert!(!report.is_ready());
    }

    // BRR2_10: empty register yields Ready with zero counts.
    #[test]
    fn brr2_10_empty_register_is_ready() {
        let r = ProductionGapRegister::new();
        let report = BetaReadinessReportV2::generate(&r);
        assert_eq!(report.verdict, ReadinessVerdict::Ready);
        assert_eq!(report.total_gaps, 0);
        assert_eq!(report.blocking_items.len(), 0);
    }

    // BRR2_11: custom single-gap register — resolved medium gap yields Ready.
    #[test]
    fn brr2_11_medium_gap_resolved_is_ready() {
        let mut r = ProductionGapRegister::new();
        r.add(ProductionGap {
            id: "MED-001",
            subsystem: "test",
            description: "medium gap",
            priority: GapPriority::Medium,
            status: GapStatus::Resolved,
        });
        let report = BetaReadinessReportV2::generate(&r);
        assert!(report.is_ready());
        assert_eq!(report.resolved_count, 1);
    }

    // BRR2_12: ReadinessVerdict::is_ready() returns false for NotReady.
    #[test]
    fn brr2_12_verdict_is_ready_false() {
        assert!(!ReadinessVerdict::NotReady.is_ready());
        assert!(ReadinessVerdict::Ready.is_ready());
    }
}
