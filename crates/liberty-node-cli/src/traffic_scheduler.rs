//! Epoch-based packet scheduler.
//!
//! Mixes real, cover, padding, and control packets in a deterministic order.

/// Distinguishes how a scheduled packet should be treated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficKind {
    Real,
    Cover,
    Padding,
    Control,
}

/// A packet queued for transmission in a given epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledPacket {
    pub kind: TrafficKind,
    pub payload: Vec<u8>,
}

/// Policy controlling how the scheduler behaves each epoch.
#[derive(Debug, Clone)]
pub struct SchedulerPolicy {
    /// Length of one epoch in milliseconds (used for documentation; scheduling is tick-based).
    pub epoch_ms: u64,
    /// Maximum number of Real packets drained per epoch.
    pub max_real_per_epoch: usize,
    /// Minimum number of Cover packets included per epoch (if available).
    pub min_cover_per_epoch: usize,
    /// Minimum number of Padding packets emitted if the epoch drain is otherwise empty.
    pub padding_floor: usize,
    /// Seed for deterministic ordering tie-breaks.
    pub deterministic_seed: u64,
}

impl Default for SchedulerPolicy {
    fn default() -> Self {
        Self {
            epoch_ms: 100,
            max_real_per_epoch: 10,
            min_cover_per_epoch: 2,
            padding_floor: 1,
            deterministic_seed: 0xDEAD_C0DE,
        }
    }
}

/// Epoch-based traffic scheduler.
///
/// Queues are FIFO within each kind.  Control packets have highest priority
/// and are always drained first.
#[derive(Debug)]
pub struct TrafficScheduler {
    policy: SchedulerPolicy,
    real_queue: Vec<ScheduledPacket>,
    cover_queue: Vec<ScheduledPacket>,
    padding_queue: Vec<ScheduledPacket>,
    control_queue: Vec<ScheduledPacket>,
    epoch: u64,
}

impl TrafficScheduler {
    pub fn new(policy: SchedulerPolicy) -> Self {
        Self {
            policy,
            real_queue: Vec::new(),
            cover_queue: Vec::new(),
            padding_queue: Vec::new(),
            control_queue: Vec::new(),
            epoch: 0,
        }
    }

    /// Push a Real packet into the real queue.
    pub fn enqueue_real(&mut self, payload: Vec<u8>) {
        self.real_queue.push(ScheduledPacket {
            kind: TrafficKind::Real,
            payload,
        });
    }

    /// Push a Cover packet into the cover queue.
    pub fn enqueue_cover(&mut self, payload: Vec<u8>) {
        self.cover_queue.push(ScheduledPacket {
            kind: TrafficKind::Cover,
            payload,
        });
    }

    /// Push a Control packet into the control queue.
    pub fn enqueue_control(&mut self, payload: Vec<u8>) {
        self.control_queue.push(ScheduledPacket {
            kind: TrafficKind::Control,
            payload,
        });
    }

    /// Advance one epoch, computing padding and returning the total queue depth.
    pub fn tick_epoch(&mut self) -> usize {
        self.epoch += 1;
        // If the real+cover drain would be empty and padding_floor > 0, enqueue padding.
        let would_be_empty = self.real_queue.is_empty()
            && self.cover_queue.is_empty()
            && self.control_queue.is_empty();
        if would_be_empty && self.policy.padding_floor > 0 {
            for i in 0..self.policy.padding_floor {
                let seed = self
                    .policy
                    .deterministic_seed
                    .wrapping_add(self.epoch)
                    .wrapping_add(i as u64);
                self.padding_queue.push(ScheduledPacket {
                    kind: TrafficKind::Padding,
                    payload: seed.to_le_bytes().to_vec(),
                });
            }
        }
        self.queue_depth()
    }

    /// Drain one epoch's worth of packets according to policy.
    ///
    /// Order: Control (all) → Real (up to max_real_per_epoch) →
    ///        Cover (up to min_cover_per_epoch, then interleaved) → Padding (if any)
    pub fn drain_epoch(&mut self) -> Vec<ScheduledPacket> {
        let mut out = Vec::new();

        // 1. Drain all control packets first.
        out.append(&mut self.control_queue);

        // 2. Drain up to max_real_per_epoch real packets.
        let real_take = self.policy.max_real_per_epoch.min(self.real_queue.len());
        let real_drained: Vec<_> = self.real_queue.drain(..real_take).collect();
        out.extend(real_drained);

        // 3. Ensure at least min_cover_per_epoch cover packets.
        let cover_take = self.policy.min_cover_per_epoch.min(self.cover_queue.len());
        let cover_drained: Vec<_> = self.cover_queue.drain(..cover_take).collect();
        out.extend(cover_drained);

        // 4. Interleave any remaining cover packets with nothing (just append remaining).
        out.append(&mut self.cover_queue);

        // 5. Emit padding if queued.
        out.append(&mut self.padding_queue);

        out
    }

    /// Total pending packets across all queues.
    pub fn queue_depth(&self) -> usize {
        self.real_queue.len()
            + self.cover_queue.len()
            + self.padding_queue.len()
            + self.control_queue.len()
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sched() -> TrafficScheduler {
        TrafficScheduler::new(SchedulerPolicy::default())
    }

    // TS1: enqueue real adds to real queue
    #[test]
    fn ts1_enqueue_real() {
        let mut s = sched();
        s.enqueue_real(b"data".to_vec());
        assert_eq!(s.queue_depth(), 1);
    }

    // TS2: drain_epoch empties queues
    #[test]
    fn ts2_drain_epoch() {
        let mut s = sched();
        s.enqueue_real(b"a".to_vec());
        s.enqueue_cover(b"b".to_vec());
        let drained = s.drain_epoch();
        assert!(!drained.is_empty());
        assert_eq!(s.queue_depth(), 0);
    }

    // TS3: max_real_per_epoch is enforced
    #[test]
    fn ts3_max_real_enforced() {
        let policy = SchedulerPolicy {
            max_real_per_epoch: 3,
            min_cover_per_epoch: 0,
            padding_floor: 0,
            ..SchedulerPolicy::default()
        };
        let mut s = TrafficScheduler::new(policy);
        for i in 0..10u8 {
            s.enqueue_real(vec![i]);
        }
        let drained = s.drain_epoch();
        let real_count = drained
            .iter()
            .filter(|p| p.kind == TrafficKind::Real)
            .count();
        assert_eq!(real_count, 3);
        // Remaining 7 stay in queue
        assert_eq!(s.real_queue.len(), 7);
    }

    // TS4: min_cover_per_epoch is honoured
    #[test]
    fn ts4_min_cover_enforced() {
        let policy = SchedulerPolicy {
            max_real_per_epoch: 10,
            min_cover_per_epoch: 2,
            padding_floor: 0,
            ..SchedulerPolicy::default()
        };
        let mut s = TrafficScheduler::new(policy);
        s.enqueue_real(b"real".to_vec());
        s.enqueue_cover(b"cover1".to_vec());
        s.enqueue_cover(b"cover2".to_vec());
        s.enqueue_cover(b"cover3".to_vec());
        let drained = s.drain_epoch();
        let cover_count = drained
            .iter()
            .filter(|p| p.kind == TrafficKind::Cover)
            .count();
        assert_eq!(cover_count, 3); // all cover drained (min=2 guarantees at least 2)
    }

    // TS5: padding emitted when all queues empty and padding_floor > 0
    #[test]
    fn ts5_padding_emitted() {
        let policy = SchedulerPolicy {
            padding_floor: 2,
            ..SchedulerPolicy::default()
        };
        let mut s = TrafficScheduler::new(policy);
        s.tick_epoch(); // triggers padding generation
        let drained = s.drain_epoch();
        let pad_count = drained
            .iter()
            .filter(|p| p.kind == TrafficKind::Padding)
            .count();
        assert_eq!(pad_count, 2);
    }

    // TS6: drain is deterministic — same sequence of enqueue+drain produces same result
    #[test]
    fn ts6_deterministic_schedule() {
        fn run() -> Vec<Vec<u8>> {
            let mut s = sched();
            s.enqueue_real(b"r1".to_vec());
            s.enqueue_cover(b"c1".to_vec());
            s.drain_epoch().into_iter().map(|p| p.payload).collect()
        }
        assert_eq!(run(), run());
    }

    // TS7: queue_depth reflects total pending packets
    #[test]
    fn ts7_queue_depth() {
        let mut s = sched();
        s.enqueue_real(b"a".to_vec());
        s.enqueue_real(b"b".to_vec());
        s.enqueue_cover(b"c".to_vec());
        assert_eq!(s.queue_depth(), 3);
    }

    // TS8: control packets are drained before real packets
    #[test]
    fn ts8_control_packets_priority() {
        let mut s = sched();
        s.enqueue_real(b"real".to_vec());
        s.enqueue_control(b"ctrl".to_vec());
        let drained = s.drain_epoch();
        assert_eq!(drained[0].kind, TrafficKind::Control);
        assert_eq!(drained[1].kind, TrafficKind::Real);
    }

    // TS9: padding_floor=0 means no padding emitted for empty queue
    #[test]
    fn ts9_no_padding_when_floor_zero() {
        let policy = SchedulerPolicy {
            padding_floor: 0,
            ..SchedulerPolicy::default()
        };
        let mut s = TrafficScheduler::new(policy);
        s.tick_epoch();
        let drained = s.drain_epoch();
        assert!(drained.is_empty());
    }

    // TS10: tick_epoch increments epoch counter
    #[test]
    fn ts10_epoch_increments() {
        let mut s = sched();
        s.tick_epoch();
        s.tick_epoch();
        s.tick_epoch();
        assert_eq!(s.epoch(), 3);
    }
}
