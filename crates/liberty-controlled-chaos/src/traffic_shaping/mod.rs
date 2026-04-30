//! Traffic shaping — jitter, burst smoothing, and constant-rate scheduling.
//!
//! `TrafficShaper` enqueues packets and schedules them for transmission at
//! normalised intervals.  Each packet gets an assigned `scheduled_at_ms`
//! derived from `inter_packet_ms` plus deterministic jitter computed from
//! a caller-supplied seed.
//!
//! Bursts are smoothed by capping the queue at `max_burst_size`; packets
//! that arrive when the queue is full are dropped (counted in `packets_dropped`).

use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// ShapingPolicy
// ---------------------------------------------------------------------------

/// Describes the inter-packet timing and burst-smoothing parameters.
#[derive(Debug, Clone)]
pub struct ShapingPolicy {
    /// Maximum packets that can wait in the queue.
    pub max_burst_size: usize,
    /// Target gap between consecutive packet transmissions, milliseconds.
    pub inter_packet_ms: u64,
    /// Maximum jitter added to each packet's scheduled time, milliseconds.
    pub jitter_ms_max: u64,
}

impl ShapingPolicy {
    pub fn new(max_burst_size: usize, inter_packet_ms: u64, jitter_ms_max: u64) -> Self {
        Self {
            max_burst_size,
            inter_packet_ms,
            jitter_ms_max,
        }
    }
}

// ---------------------------------------------------------------------------
// ShapedPacket
// ---------------------------------------------------------------------------

/// A packet with an assigned scheduled transmission time.
#[derive(Debug, Clone)]
pub struct ShapedPacket {
    pub data: Vec<u8>,
    pub scheduled_at_ms: u64,
}

// ---------------------------------------------------------------------------
// TrafficShaper
// ---------------------------------------------------------------------------

/// Smooths outbound traffic according to a `ShapingPolicy`.
pub struct TrafficShaper {
    policy: ShapingPolicy,
    queue: VecDeque<Vec<u8>>,
    /// Wall-clock ms at which the next packet may be transmitted.
    next_send_ms: u64,
    pub packets_enqueued: u64,
    pub packets_dropped: u64,
    pub packets_drained: u64,
}

impl TrafficShaper {
    pub fn new(policy: ShapingPolicy, start_ms: u64) -> Self {
        Self {
            policy,
            queue: VecDeque::new(),
            next_send_ms: start_ms,
            packets_enqueued: 0,
            packets_dropped: 0,
            packets_drained: 0,
        }
    }

    /// Enqueue a packet.  Returns `false` (and increments `packets_dropped`) if
    /// the queue is already at `max_burst_size`.
    pub fn enqueue(&mut self, data: Vec<u8>) -> bool {
        if self.queue.len() >= self.policy.max_burst_size {
            self.packets_dropped += 1;
            return false;
        }
        self.queue.push_back(data);
        self.packets_enqueued += 1;
        true
    }

    /// Drain all packets whose `scheduled_at_ms <= current_ms`.
    ///
    /// `jitter_seed` is mixed with the packet index to produce deterministic
    /// per-packet jitter (no external RNG dependency).
    pub fn drain(&mut self, current_ms: u64, jitter_seed: u64) -> Vec<ShapedPacket> {
        let mut out = Vec::new();
        let jitter_range = if self.policy.jitter_ms_max > 0 {
            self.policy.jitter_ms_max + 1
        } else {
            1
        };

        while self.queue.front().is_some() {
            let jitter = (jitter_seed ^ self.packets_drained) % jitter_range;
            let scheduled = self.next_send_ms + jitter;
            if scheduled > current_ms {
                break;
            }
            let data = self.queue.pop_front().unwrap();
            out.push(ShapedPacket {
                data,
                scheduled_at_ms: scheduled,
            });
            self.next_send_ms += self.policy.inter_packet_ms;
            self.packets_drained += 1;
        }
        out
    }

    /// Number of packets waiting in the queue.
    pub fn queue_len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Reset timing baseline to `ms` without clearing the queue.
    pub fn reset_timer(&mut self, ms: u64) {
        self.next_send_ms = ms;
    }

    /// The earliest time at which the next queued packet will be scheduled.
    pub fn next_scheduled_ms(&self) -> Option<u64> {
        if self.queue.is_empty() {
            None
        } else {
            Some(self.next_send_ms)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn shaper(burst: usize, gap: u64, jitter: u64) -> TrafficShaper {
        TrafficShaper::new(ShapingPolicy::new(burst, gap, jitter), 0)
    }

    // TS1: enqueue adds packet to queue.
    #[test]
    fn ts1_enqueue() {
        let mut s = shaper(10, 10, 0);
        assert!(s.enqueue(vec![1, 2, 3]));
        assert_eq!(s.queue_len(), 1);
    }

    // TS2: drain releases packet when current_ms >= scheduled.
    #[test]
    fn ts2_drain_releases_packet() {
        let mut s = shaper(10, 10, 0);
        s.enqueue(vec![42]);
        let out = s.drain(0, 0); // scheduled = 0+0 = 0 <= 0
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].data, vec![42]);
    }

    // TS3: drain respects inter_packet_ms spacing.
    #[test]
    fn ts3_inter_packet_spacing() {
        let mut s = shaper(10, 100, 0);
        s.enqueue(vec![1]);
        s.enqueue(vec![2]);
        let out = s.drain(50, 0); // only first packet is due (scheduled at 0 <= 50)
        assert_eq!(out.len(), 1);
        // Second packet now scheduled at 100 ms
        let out2 = s.drain(100, 0);
        assert_eq!(out2.len(), 1);
    }

    // TS4: max_burst_size drops overflow packets.
    #[test]
    fn ts4_burst_limit_drops() {
        let mut s = shaper(2, 10, 0);
        s.enqueue(vec![1]);
        s.enqueue(vec![2]);
        let ok = s.enqueue(vec![3]); // queue full
        assert!(!ok);
        assert_eq!(s.packets_dropped, 1);
    }

    // TS5: packets_drained counter updates.
    #[test]
    fn ts5_drain_counter() {
        let mut s = shaper(10, 10, 0);
        for i in 0..5u8 {
            s.enqueue(vec![i]);
        }
        s.drain(1000, 0); // all due by now
        assert_eq!(s.packets_drained, 5);
    }

    // TS6: packets_enqueued counter.
    #[test]
    fn ts6_enqueue_counter() {
        let mut s = shaper(10, 10, 0);
        s.enqueue(vec![1]);
        s.enqueue(vec![2]);
        assert_eq!(s.packets_enqueued, 2);
    }

    // TS7: zero jitter produces deterministic schedule.
    #[test]
    fn ts7_zero_jitter_deterministic() {
        let mut s = shaper(10, 20, 0);
        s.enqueue(vec![1]);
        s.enqueue(vec![2]);
        let out = s.drain(1000, 42); // seed doesn't matter when jitter_ms_max=0
        assert_eq!(out[0].scheduled_at_ms, 0);
        assert_eq!(out[1].scheduled_at_ms, 20);
    }

    // TS8: jitter shifts scheduled time within [0, jitter_ms_max].
    #[test]
    fn ts8_jitter_within_bounds() {
        let max_j = 10u64;
        let mut s = shaper(10, 50, max_j);
        s.enqueue(vec![1]);
        let out = s.drain(1000, 7);
        assert_eq!(out.len(), 1);
        assert!(out[0].scheduled_at_ms <= max_j);
    }

    // TS9: next_scheduled_ms returns None when empty.
    #[test]
    fn ts9_next_scheduled_empty() {
        let s = shaper(10, 10, 0);
        assert!(s.next_scheduled_ms().is_none());
    }

    // TS10: next_scheduled_ms returns Some when queue non-empty.
    #[test]
    fn ts10_next_scheduled_some() {
        let mut s = shaper(10, 10, 0);
        s.enqueue(vec![1]);
        assert!(s.next_scheduled_ms().is_some());
    }

    // TS11: reset_timer changes the baseline.
    #[test]
    fn ts11_reset_timer() {
        let mut s = shaper(10, 10, 0);
        s.enqueue(vec![1]);
        s.reset_timer(500);
        let out = s.drain(400, 0); // 400 < 500 → not yet due
        assert!(out.is_empty());
        let out2 = s.drain(500, 0);
        assert_eq!(out2.len(), 1);
    }

    // TS12: is_empty reflects queue state.
    #[test]
    fn ts12_is_empty() {
        let mut s = shaper(10, 10, 0);
        assert!(s.is_empty());
        s.enqueue(vec![1]);
        assert!(!s.is_empty());
    }

    // TS13: drain with current_ms < first scheduled returns empty.
    #[test]
    fn ts13_drain_not_yet_due() {
        let mut s = TrafficShaper::new(ShapingPolicy::new(10, 100, 0), 50);
        s.enqueue(vec![1]);
        let out = s.drain(49, 0); // scheduled at 50, not yet due
        assert!(out.is_empty());
    }

    // TS14: multiple enqueue/drain cycles are consistent.
    #[test]
    fn ts14_multiple_cycles() {
        let mut s = shaper(10, 10, 0);
        for i in 0..5u8 {
            s.enqueue(vec![i]);
        }
        let out1 = s.drain(20, 0); // packets 0,1,2 due at 0,10,20
        assert_eq!(out1.len(), 3);
        let out2 = s.drain(40, 0); // packets 3,4 due at 30,40
        assert_eq!(out2.len(), 2);
        assert_eq!(s.packets_drained, 5);
    }
}
