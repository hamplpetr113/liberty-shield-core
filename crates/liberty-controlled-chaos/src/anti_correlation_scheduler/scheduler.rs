use super::types::{AntiCorrelationPolicy, ScheduledTransmission, SchedulerError, TrafficKind};

/// Deterministic anti-correlation scheduler.
///
/// Maintains two priority queues (real and cover) sorted by deadline ascending.
/// `drain_next` always prefers real traffic when `policy.drain_real_first` is set
/// and real traffic is available.  Expired cover traffic is silently dropped on
/// each call.
pub struct AntiCorrelationScheduler {
    real_queue: Vec<ScheduledTransmission>,
    cover_queue: Vec<ScheduledTransmission>,
}

impl AntiCorrelationScheduler {
    pub fn new() -> Self {
        Self {
            real_queue: Vec::new(),
            cover_queue: Vec::new(),
        }
    }

    /// Enqueue a transmission.  The queues are kept sorted ascending by
    /// `deadline_us` after each insertion.
    pub fn enqueue(&mut self, tx: ScheduledTransmission) {
        match tx.kind {
            TrafficKind::Real => {
                Self::insert_sorted(&mut self.real_queue, tx);
            }
            TrafficKind::Cover => {
                Self::insert_sorted(&mut self.cover_queue, tx);
            }
        }
    }

    /// Remove and return the next transmission to send at `now_us`.
    ///
    /// Order:
    ///   1. Drop all expired cover entries (deadline + slack < now).
    ///   2. If real queue is non-empty and `drain_real_first`, return the
    ///      earliest-deadline real transmission.
    ///   3. Otherwise return the earliest-deadline cover transmission whose
    ///      deadline has not passed.
    ///   4. If nothing is available, return `EmptyQueue`.
    pub fn drain_next(
        &mut self,
        policy: &AntiCorrelationPolicy,
        now_us: u64,
    ) -> Result<ScheduledTransmission, SchedulerError> {
        // Drop expired cover entries.
        self.cover_queue
            .retain(|tx| tx.deadline_us.saturating_add(policy.cover_expiry_slack_us) >= now_us);

        if policy.drain_real_first && !self.real_queue.is_empty() {
            return Ok(self.real_queue.remove(0));
        }

        if !self.cover_queue.is_empty() {
            return Ok(self.cover_queue.remove(0));
        }

        if !self.real_queue.is_empty() {
            return Ok(self.real_queue.remove(0));
        }

        Err(SchedulerError::EmptyQueue)
    }

    /// Number of pending real transmissions.
    pub fn real_count(&self) -> usize {
        self.real_queue.len()
    }

    /// Number of pending cover transmissions.
    pub fn cover_count(&self) -> usize {
        self.cover_queue.len()
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    fn insert_sorted(queue: &mut Vec<ScheduledTransmission>, tx: ScheduledTransmission) {
        let pos = queue
            .binary_search_by_key(&tx.deadline_us, |t| t.deadline_us)
            .unwrap_or_else(|i| i);
        queue.insert(pos, tx);
    }
}

impl Default for AntiCorrelationScheduler {
    fn default() -> Self {
        Self::new()
    }
}
