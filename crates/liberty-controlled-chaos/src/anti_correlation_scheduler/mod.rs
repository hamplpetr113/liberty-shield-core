//! AntiCorrelationScheduler — deterministic real/cover traffic interleaving.
//!
//! Sits above `CoverTrafficGenerator` and `MultiCircuitDistributor`:
//!   AntiCorrelationScheduler → MultiCircuitDistributor → CircuitRuntime → ...
//!
//! No randomness; all timing is caller-supplied.

mod scheduler;
mod types;

pub use scheduler::AntiCorrelationScheduler;
pub use types::{AntiCorrelationPolicy, ScheduledTransmission, SchedulerError, TrafficKind};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::circuit_builder::CircuitId;

    use super::*;

    fn policy() -> AntiCorrelationPolicy {
        AntiCorrelationPolicy {
            drain_real_first: true,
            cover_expiry_slack_us: 500_000,
        }
    }

    fn real(circuit: u64, deadline: u64) -> ScheduledTransmission {
        ScheduledTransmission {
            circuit_id: CircuitId(circuit),
            deadline_us: deadline,
            kind: TrafficKind::Real,
            payload_size: 100,
        }
    }

    fn cover(circuit: u64, deadline: u64) -> ScheduledTransmission {
        ScheduledTransmission {
            circuit_id: CircuitId(circuit),
            deadline_us: deadline,
            kind: TrafficKind::Cover,
            payload_size: 50,
        }
    }

    // ── Real traffic drains before cover ─────────────────────────────────────

    #[test]
    fn ac1_real_drains_before_cover() {
        let mut s = AntiCorrelationScheduler::new();
        s.enqueue(cover(1, 1000));
        s.enqueue(real(2, 2000));
        let t = s.drain_next(&policy(), 0).unwrap();
        assert_eq!(t.kind, TrafficKind::Real);
        assert_eq!(t.circuit_id, CircuitId(2));
    }

    // ── Deadline ordering within same kind ────────────────────────────────────

    #[test]
    fn ac2_deadline_ordering() {
        let mut s = AntiCorrelationScheduler::new();
        s.enqueue(real(1, 3000));
        s.enqueue(real(2, 1000));
        s.enqueue(real(3, 2000));
        let t1 = s.drain_next(&policy(), 0).unwrap();
        let t2 = s.drain_next(&policy(), 0).unwrap();
        let t3 = s.drain_next(&policy(), 0).unwrap();
        assert_eq!(t1.deadline_us, 1000);
        assert_eq!(t2.deadline_us, 2000);
        assert_eq!(t3.deadline_us, 3000);
    }

    // ── Cover is best-effort when no real pending ─────────────────────────────

    #[test]
    fn ac3_cover_best_effort_when_no_real() {
        let mut s = AntiCorrelationScheduler::new();
        s.enqueue(cover(1, 500));
        s.enqueue(cover(2, 100));
        let t = s.drain_next(&policy(), 0).unwrap();
        assert_eq!(t.kind, TrafficKind::Cover);
        assert_eq!(t.deadline_us, 100);
    }

    // ── Deterministic drain order ─────────────────────────────────────────────

    #[test]
    fn ac4_deterministic_drain_order() {
        let mut s1 = AntiCorrelationScheduler::new();
        let mut s2 = AntiCorrelationScheduler::new();
        for (c, d) in [(1u64, 300u64), (2, 100), (3, 200)] {
            s1.enqueue(real(c, d));
            s2.enqueue(real(c, d));
        }
        let p = policy();
        let drain1: Vec<_> = (0..3).map(|_| s1.drain_next(&p, 0).unwrap()).collect();
        let drain2: Vec<_> = (0..3).map(|_| s2.drain_next(&p, 0).unwrap()).collect();
        assert_eq!(drain1, drain2);
    }

    // ── Expired cover is dropped ──────────────────────────────────────────────

    #[test]
    fn ac5_expired_cover_dropped() {
        let mut s = AntiCorrelationScheduler::new();
        // deadline=100, slack=500_000; now=1_000_000 → 100 + 500_000 < 1_000_000 → expired
        s.enqueue(cover(1, 100));
        let err = s.drain_next(&policy(), 1_000_000);
        assert_eq!(err, Err(SchedulerError::EmptyQueue));
    }

    // ── Real deadline preserved ───────────────────────────────────────────────

    #[test]
    fn ac6_real_deadline_preserved() {
        let mut s = AntiCorrelationScheduler::new();
        s.enqueue(real(5, 99_999));
        let t = s.drain_next(&policy(), 0).unwrap();
        assert_eq!(t.deadline_us, 99_999);
        assert_eq!(t.circuit_id, CircuitId(5));
    }

    // ── Empty queue returns error ─────────────────────────────────────────────

    #[test]
    fn ac7_empty_queue_error() {
        let mut s = AntiCorrelationScheduler::new();
        assert_eq!(s.drain_next(&policy(), 0), Err(SchedulerError::EmptyQueue));
    }

    // ── Counts reflect queue state ────────────────────────────────────────────

    #[test]
    fn ac8_counts() {
        let mut s = AntiCorrelationScheduler::new();
        s.enqueue(real(1, 100));
        s.enqueue(real(2, 200));
        s.enqueue(cover(3, 300));
        assert_eq!(s.real_count(), 2);
        assert_eq!(s.cover_count(), 1);
        s.drain_next(&policy(), 0).unwrap();
        assert_eq!(s.real_count(), 1);
    }
}
