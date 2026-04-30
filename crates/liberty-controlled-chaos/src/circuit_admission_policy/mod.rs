//! Circuit admission policy — evaluates whether a new circuit should be accepted.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecision {
    Accept,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    CapacityExceeded,
    SourceBanned,
    RateLimitHit,
}

#[derive(Debug, Clone)]
pub struct AdmissionPolicy {
    pub max_circuits: usize,
    pub max_per_source: usize,
    pub max_per_epoch: usize,
}

pub struct CircuitAdmissionPolicy {
    policy: AdmissionPolicy,
    active_circuits: usize,
    per_source: HashMap<[u8; 32], usize>,
    epoch_admissions: u64,
    total_accepted: u64,
    total_rejected: u64,
    banned_sources: Vec<[u8; 32]>,
}

impl CircuitAdmissionPolicy {
    pub fn new(policy: AdmissionPolicy) -> Self {
        Self {
            policy,
            active_circuits: 0,
            per_source: HashMap::new(),
            epoch_admissions: 0,
            total_accepted: 0,
            total_rejected: 0,
            banned_sources: Vec::new(),
        }
    }

    pub fn ban_source(&mut self, source: [u8; 32]) {
        if !self.banned_sources.contains(&source) {
            self.banned_sources.push(source);
        }
    }

    pub fn unban_source(&mut self, source: &[u8; 32]) {
        self.banned_sources.retain(|s| s != source);
    }

    pub fn evaluate(&mut self, source: [u8; 32]) -> Result<AdmissionDecision, RejectReason> {
        if self.banned_sources.contains(&source) {
            self.total_rejected += 1;
            return Err(RejectReason::SourceBanned);
        }
        if self.active_circuits >= self.policy.max_circuits {
            self.total_rejected += 1;
            return Err(RejectReason::CapacityExceeded);
        }
        let source_count = self.per_source.get(&source).copied().unwrap_or(0);
        if source_count >= self.policy.max_per_source {
            self.total_rejected += 1;
            return Err(RejectReason::RateLimitHit);
        }
        if self.epoch_admissions >= self.policy.max_per_epoch as u64 {
            self.total_rejected += 1;
            return Err(RejectReason::RateLimitHit);
        }
        *self.per_source.entry(source).or_insert(0) += 1;
        self.active_circuits += 1;
        self.epoch_admissions += 1;
        self.total_accepted += 1;
        Ok(AdmissionDecision::Accept)
    }

    pub fn release(&mut self, source: &[u8; 32]) {
        if self.active_circuits > 0 {
            self.active_circuits -= 1;
        }
        if let Some(n) = self.per_source.get_mut(source).filter(|n| **n > 0) {
            *n -= 1;
        }
    }

    pub fn reset_epoch(&mut self) {
        self.epoch_admissions = 0;
    }

    pub fn active_circuits(&self) -> usize {
        self.active_circuits
    }
    pub fn total_accepted(&self) -> u64 {
        self.total_accepted
    }
    pub fn total_rejected(&self) -> u64 {
        self.total_rejected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn policy() -> AdmissionPolicy {
        AdmissionPolicy {
            max_circuits: 10,
            max_per_source: 3,
            max_per_epoch: 100,
        }
    }

    // CAP1: normal circuit is accepted.
    #[test]
    fn cap1_accept() {
        let mut p = CircuitAdmissionPolicy::new(policy());
        assert_eq!(p.evaluate(src(1)), Ok(AdmissionDecision::Accept));
    }

    // CAP2: capacity exceeded returns CapacityExceeded.
    #[test]
    fn cap2_capacity_exceeded() {
        let mut p = CircuitAdmissionPolicy::new(AdmissionPolicy {
            max_circuits: 1,
            max_per_source: 10,
            max_per_epoch: 100,
        });
        p.evaluate(src(1)).unwrap();
        assert_eq!(p.evaluate(src(2)), Err(RejectReason::CapacityExceeded));
    }

    // CAP3: banned source returns SourceBanned.
    #[test]
    fn cap3_banned() {
        let mut p = CircuitAdmissionPolicy::new(policy());
        p.ban_source(src(1));
        assert_eq!(p.evaluate(src(1)), Err(RejectReason::SourceBanned));
    }

    // CAP4: per-source limit returns RateLimitHit.
    #[test]
    fn cap4_per_source_limit() {
        let mut p = CircuitAdmissionPolicy::new(AdmissionPolicy {
            max_circuits: 100,
            max_per_source: 2,
            max_per_epoch: 100,
        });
        p.evaluate(src(1)).unwrap();
        p.evaluate(src(1)).unwrap();
        assert_eq!(p.evaluate(src(1)), Err(RejectReason::RateLimitHit));
    }

    // CAP5: release decrements active count.
    #[test]
    fn cap5_release() {
        let mut p = CircuitAdmissionPolicy::new(policy());
        p.evaluate(src(1)).unwrap();
        p.release(&src(1));
        assert_eq!(p.active_circuits(), 0);
    }

    // CAP6: total_accepted accumulates.
    #[test]
    fn cap6_total_accepted() {
        let mut p = CircuitAdmissionPolicy::new(policy());
        p.evaluate(src(1)).unwrap();
        p.evaluate(src(2)).unwrap();
        assert_eq!(p.total_accepted(), 2);
    }

    // CAP7: total_rejected accumulates.
    #[test]
    fn cap7_total_rejected() {
        let mut p = CircuitAdmissionPolicy::new(policy());
        p.ban_source(src(1));
        p.evaluate(src(1)).unwrap_err();
        assert_eq!(p.total_rejected(), 1);
    }

    // CAP8: reset_epoch clears epoch counter.
    #[test]
    fn cap8_reset_epoch() {
        let mut p = CircuitAdmissionPolicy::new(AdmissionPolicy {
            max_circuits: 100,
            max_per_source: 100,
            max_per_epoch: 1,
        });
        p.evaluate(src(1)).unwrap();
        assert_eq!(p.evaluate(src(2)), Err(RejectReason::RateLimitHit));
        p.reset_epoch();
        assert_eq!(p.evaluate(src(2)), Ok(AdmissionDecision::Accept));
    }

    // CAP9: unban restores acceptance.
    #[test]
    fn cap9_unban() {
        let mut p = CircuitAdmissionPolicy::new(policy());
        p.ban_source(src(1));
        p.unban_source(&src(1));
        assert_eq!(p.evaluate(src(1)), Ok(AdmissionDecision::Accept));
    }

    // CAP10: multiple sources tracked independently.
    #[test]
    fn cap10_independent_sources() {
        let mut p = CircuitAdmissionPolicy::new(AdmissionPolicy {
            max_circuits: 100,
            max_per_source: 1,
            max_per_epoch: 100,
        });
        p.evaluate(src(1)).unwrap();
        p.evaluate(src(2)).unwrap();
        assert_eq!(p.evaluate(src(1)), Err(RejectReason::RateLimitHit));
        assert_eq!(p.evaluate(src(2)), Err(RejectReason::RateLimitHit));
    }
}
