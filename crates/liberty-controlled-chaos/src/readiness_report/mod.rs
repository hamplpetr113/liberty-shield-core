//! Readiness report — structured assessment of whether the node stack is ready
//! for a given operational phase.
//!
//! The report is built incrementally by calling `record_*` methods, then
//! finalised with `build()`.  Blocking issues prevent `is_ready()` from
//! returning true; warnings are informational.

// ---------------------------------------------------------------------------
// ReadinessLevel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReadinessLevel {
    /// Not ready — blockers must be resolved.
    NotReady,
    /// Ready with warnings — acceptable for operation but not ideal.
    ReadyWithWarnings,
    /// Fully ready — no blockers, no warnings.
    Ready,
}

// ---------------------------------------------------------------------------
// ReadinessItem
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ReadinessItem {
    pub module: String,
    pub description: String,
    pub is_blocker: bool,
}

// ---------------------------------------------------------------------------
// ReadinessReport
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ReadinessReport {
    pub level: ReadinessLevel,
    pub modules_checked: Vec<String>,
    pub test_count: u32,
    pub items: Vec<ReadinessItem>,
    pub build_epoch: u64,
}

impl ReadinessReport {
    pub fn blockers(&self) -> Vec<&ReadinessItem> {
        self.items.iter().filter(|i| i.is_blocker).collect()
    }

    pub fn warnings(&self) -> Vec<&ReadinessItem> {
        self.items.iter().filter(|i| !i.is_blocker).collect()
    }

    pub fn is_ready(&self) -> bool {
        self.level != ReadinessLevel::NotReady
    }
}

// ---------------------------------------------------------------------------
// ReadinessReportBuilder
// ---------------------------------------------------------------------------

pub struct ReadinessReportBuilder {
    modules: Vec<String>,
    test_count: u32,
    items: Vec<ReadinessItem>,
    build_epoch: u64,
}

impl ReadinessReportBuilder {
    pub fn new(build_epoch: u64) -> Self {
        Self {
            modules: Vec::new(),
            test_count: 0,
            items: Vec::new(),
            build_epoch,
        }
    }

    pub fn add_module(&mut self, name: &str) -> &mut Self {
        self.modules.push(name.into());
        self
    }

    pub fn set_test_count(&mut self, count: u32) -> &mut Self {
        self.test_count = count;
        self
    }

    pub fn add_blocker(&mut self, module: &str, description: &str) -> &mut Self {
        self.items.push(ReadinessItem {
            module: module.into(),
            description: description.into(),
            is_blocker: true,
        });
        self
    }

    pub fn add_warning(&mut self, module: &str, description: &str) -> &mut Self {
        self.items.push(ReadinessItem {
            module: module.into(),
            description: description.into(),
            is_blocker: false,
        });
        self
    }

    pub fn build(self) -> ReadinessReport {
        let has_blockers = self.items.iter().any(|i| i.is_blocker);
        let has_warnings = self.items.iter().any(|i| !i.is_blocker);
        let level = if has_blockers {
            ReadinessLevel::NotReady
        } else if has_warnings {
            ReadinessLevel::ReadyWithWarnings
        } else {
            ReadinessLevel::Ready
        };
        ReadinessReport {
            level,
            modules_checked: self.modules,
            test_count: self.test_count,
            items: self.items,
            build_epoch: self.build_epoch,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // RR1: empty report has level Ready.
    #[test]
    fn rr1_empty_is_ready() {
        let r = ReadinessReportBuilder::new(1).build();
        assert_eq!(r.level, ReadinessLevel::Ready);
    }

    // RR2: blocker makes report NotReady.
    #[test]
    fn rr2_blocker_not_ready() {
        let mut b = ReadinessReportBuilder::new(1);
        b.add_blocker("crypto", "no real key exchange");
        let r = b.build();
        assert_eq!(r.level, ReadinessLevel::NotReady);
    }

    // RR3: warning without blocker gives ReadyWithWarnings.
    #[test]
    fn rr3_warning_ready_with_warnings() {
        let mut b = ReadinessReportBuilder::new(1);
        b.add_warning("telemetry", "metrics not configured");
        let r = b.build();
        assert_eq!(r.level, ReadinessLevel::ReadyWithWarnings);
    }

    // RR4: is_ready() is false when NotReady.
    #[test]
    fn rr4_is_ready_false_when_blocked() {
        let mut b = ReadinessReportBuilder::new(1);
        b.add_blocker("m", "x");
        assert!(!b.build().is_ready());
    }

    // RR5: is_ready() is true for ReadyWithWarnings.
    #[test]
    fn rr5_is_ready_true_with_warnings() {
        let mut b = ReadinessReportBuilder::new(1);
        b.add_warning("m", "w");
        assert!(b.build().is_ready());
    }

    // RR6: modules_checked stores module names.
    #[test]
    fn rr6_modules_tracked() {
        let mut b = ReadinessReportBuilder::new(1);
        b.add_module("alpha_runtime");
        b.add_module("policy_engine");
        let r = b.build();
        assert_eq!(r.modules_checked.len(), 2);
    }

    // RR7: test_count is stored.
    #[test]
    fn rr7_test_count() {
        let mut b = ReadinessReportBuilder::new(1);
        b.set_test_count(1500);
        assert_eq!(b.build().test_count, 1500);
    }

    // RR8: blockers() only returns blockers.
    #[test]
    fn rr8_blockers_filter() {
        let mut b = ReadinessReportBuilder::new(1);
        b.add_blocker("a", "x");
        b.add_warning("b", "y");
        let r = b.build();
        assert_eq!(r.blockers().len(), 1);
    }

    // RR9: warnings() only returns warnings.
    #[test]
    fn rr9_warnings_filter() {
        let mut b = ReadinessReportBuilder::new(1);
        b.add_blocker("a", "x");
        b.add_warning("b", "y");
        b.add_warning("c", "z");
        let r = b.build();
        assert_eq!(r.warnings().len(), 2);
    }

    // RR10: build_epoch is preserved.
    #[test]
    fn rr10_build_epoch() {
        let r = ReadinessReportBuilder::new(42).build();
        assert_eq!(r.build_epoch, 42);
    }
}
