//! Deterministic epoch-based packet scheduler.
//!
//! The `Scheduler` manages one `FragmentQueue` + `TokenBucket` per registered
//! path and enforces the following invariants:
//!
//! * Real packets are always accepted and enqueued with
//!   `deadline_us = arrival_us + latency_guard_us`.
//! * Cover (shadow) packets are accepted only when the per-path token bucket
//!   has sufficient capacity; otherwise the slot is dropped silently.
//! * `drain_ready` returns all packets whose deadline has passed, with all
//!   real packets appearing before cover packets regardless of path order.
//! * No wall-clock state is held internally; callers pass `now_us` explicitly,
//!   making the scheduler fully deterministic for a given input sequence.

use std::collections::HashMap;

use super::queue::FragmentQueue;
use super::timing::TokenBucket;
use super::types::{FlowType, PacketPayload, PathQueueStats, ScheduledPacket};

// ── PathSlot (per-path internal state) ───────────────────────────────────────

struct PathSlot {
    queue: FragmentQueue,
    bucket: TokenBucket,
    /// Monotonic counter used to build even real-packet sequence IDs.
    real_counter: u64,
    /// Monotonic counter used to build odd cover-packet sequence IDs.
    cover_counter: u64,
}

impl PathSlot {
    fn new(cover_bandwidth_kbps: u32, latency_guard_ms: u32, now_us: u64) -> Self {
        Self {
            queue: FragmentQueue::new(cover_bandwidth_kbps, latency_guard_ms),
            bucket: TokenBucket::new(cover_bandwidth_kbps, latency_guard_ms, now_us),
            real_counter: 0,
            cover_counter: 0,
        }
    }

    /// Even IDs for real packets — keeps namespaces disjoint from cover.
    fn next_real_seq(&mut self) -> u64 {
        let id = self.real_counter * 2;
        self.real_counter += 1;
        id
    }

    /// Odd IDs for cover packets.
    fn next_cover_seq(&mut self) -> u64 {
        let id = self.cover_counter * 2 + 1;
        self.cover_counter += 1;
        id
    }
}

// ── Scheduler ─────────────────────────────────────────────────────────────────

/// Per-path deadline scheduler with token-bucket cover-traffic rate limiting.
pub struct Scheduler {
    paths: HashMap<u64, PathSlot>,
    latency_guard_us: u64,
}

impl Scheduler {
    pub fn new(latency_guard_ms: u32) -> Self {
        Self {
            paths: HashMap::new(),
            latency_guard_us: latency_guard_ms as u64 * 1_000,
        }
    }

    // ── Path lifecycle ────────────────────────────────────────────────────────

    /// Register a path.  Idempotent: an already-registered path is not reset.
    ///
    /// `now_us` initialises the token-bucket refill baseline.
    pub fn add_path(&mut self, path_id: u64, cover_bandwidth_kbps: u32, now_us: u64) {
        let guard_ms = (self.latency_guard_us / 1_000) as u32;
        self.paths
            .entry(path_id)
            .or_insert_with(|| PathSlot::new(cover_bandwidth_kbps, guard_ms, now_us));
    }

    /// Remove a path.
    ///
    /// Cover packets on the removed path are dropped.  Real packets are
    /// re-enqueued on `fallback_path_id` with their path_id updated; any
    /// real packets that cannot be redistributed (no fallback registered) are
    /// returned so the caller can handle them.
    pub fn remove_path(
        &mut self,
        path_id: u64,
        fallback_path_id: Option<u64>,
    ) -> Vec<ScheduledPacket> {
        let Some(mut slot) = self.paths.remove(&path_id) else {
            return vec![];
        };

        // Discard all cover packets first.
        slot.queue.drain_all_cover();

        // Collect remaining real packets.
        let real_pkts = slot.queue.drain_ready(u64::MAX);

        if real_pkts.is_empty() {
            return vec![];
        }

        if let Some(fb) = fallback_path_id
            && let Some(fb_slot) = self.paths.get_mut(&fb)
        {
            for pkt in real_pkts {
                fb_slot.queue.push(ScheduledPacket {
                    path_id: fb,
                    flow_type: pkt.flow_type,
                    payload: pkt.payload,
                    deadline_us: pkt.deadline_us,
                    sequence_id: pkt.sequence_id,
                });
            }
            return vec![];
        }

        real_pkts
    }

    /// Drain all cover packets from a path without removing it.
    ///
    /// Called during plan updates to flush stale cover traffic while preserving
    /// real packets already in flight.
    pub fn clear_cover(&mut self, path_id: u64) {
        if let Some(slot) = self.paths.get_mut(&path_id) {
            slot.queue.drain_all_cover();
        }
    }

    // ── Packet admission ──────────────────────────────────────────────────────

    /// Enqueue a real packet.  Always accepted; creates the path on demand if
    /// it was not pre-registered (zero cover budget).
    ///
    /// Returns the absolute deadline assigned to the packet
    /// (`arrival_us + latency_guard_us`).
    pub fn enqueue_real(&mut self, path_id: u64, payload: PacketPayload, arrival_us: u64) -> u64 {
        let deadline = arrival_us.saturating_add(self.latency_guard_us);
        let guard_ms = (self.latency_guard_us / 1_000) as u32;
        let slot = self
            .paths
            .entry(path_id)
            .or_insert_with(|| PathSlot::new(0, guard_ms, arrival_us));
        let seq = slot.next_real_seq();
        slot.queue.push(ScheduledPacket {
            path_id,
            flow_type: FlowType::Real,
            payload,
            deadline_us: deadline,
            sequence_id: seq,
        });
        deadline
    }

    /// Attempt to enqueue a cover packet on `path_id`.
    ///
    /// Returns `true` if the packet was accepted, `false` if it was dropped.
    /// A packet is dropped when:
    /// * the path is not registered, or
    /// * the token bucket cannot supply `size_bytes × 8` bits.
    ///
    /// `offset_us`: relative delay from `now_us`; capped at `latency_guard_us`.
    pub fn try_enqueue_cover(
        &mut self,
        path_id: u64,
        payload: PacketPayload,
        size_bytes: u16,
        offset_us: u32,
        now_us: u64,
    ) -> bool {
        let latency_guard_us = self.latency_guard_us;

        let Some(slot) = self.paths.get_mut(&path_id) else {
            return false;
        };

        // Refill then consume — order matters: refill first so we account for
        // time that has passed since the last operation on this path.
        slot.bucket.refill(now_us);
        if !slot.bucket.try_consume(size_bytes) {
            return false;
        }

        let offset_capped = (offset_us as u64).min(latency_guard_us);
        let deadline = now_us.saturating_add(offset_capped);
        let seq = slot.next_cover_seq();

        slot.queue.push(ScheduledPacket {
            path_id,
            flow_type: FlowType::Shadow,
            payload,
            deadline_us: deadline,
            sequence_id: seq,
        });
        true
    }

    // ── Drain ─────────────────────────────────────────────────────────────────

    /// Return all packets whose `deadline_us ≤ now_us`, with all real packets
    /// preceding all cover packets.  Within each group packets are ordered by
    /// ascending deadline.
    ///
    /// Paths are iterated in ascending `path_id` order for determinism.
    pub fn drain_ready(&mut self, now_us: u64) -> Vec<ScheduledPacket> {
        // Sort path IDs once for deterministic iteration order.
        let mut path_ids: Vec<u64> = self.paths.keys().copied().collect();
        path_ids.sort_unstable();

        let mut real_out: Vec<ScheduledPacket> = Vec::new();
        let mut cover_out: Vec<ScheduledPacket> = Vec::new();

        for pid in &path_ids {
            if let Some(slot) = self.paths.get_mut(pid) {
                // Bring token-bucket state up to date before we drain.
                slot.bucket.refill(now_us);

                for pkt in slot.queue.drain_ready(now_us) {
                    match pkt.flow_type {
                        FlowType::Real => real_out.push(pkt),
                        FlowType::Shadow => cover_out.push(pkt),
                    }
                }
            }
        }

        // Sort within each group by deadline so the most urgent packets lead.
        real_out.sort_unstable_by_key(|p| p.deadline_us);
        cover_out.sort_unstable_by_key(|p| p.deadline_us);

        real_out.extend(cover_out);
        real_out
    }

    // ── Introspection ─────────────────────────────────────────────────────────

    pub fn has_path(&self, path_id: u64) -> bool {
        self.paths.contains_key(&path_id)
    }

    pub fn path_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.paths.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    pub fn token_fill(&self, path_id: u64) -> u64 {
        self.paths.get(&path_id).map_or(0, |s| s.bucket.fill_bits())
    }

    pub fn real_depth(&self, path_id: u64) -> usize {
        self.paths.get(&path_id).map_or(0, |s| s.queue.real_depth())
    }

    pub fn cover_depth(&self, path_id: u64) -> usize {
        self.paths
            .get(&path_id)
            .map_or(0, |s| s.queue.cover_depth())
    }

    pub fn per_path_stats(&self) -> Vec<PathQueueStats> {
        let mut stats: Vec<PathQueueStats> = self
            .paths
            .iter()
            .map(|(&pid, slot)| PathQueueStats {
                path_id: pid,
                real_queue_depth: slot.queue.real_depth(),
                cover_queue_depth: slot.queue.cover_depth(),
                token_fill_bits: slot.bucket.fill_bits(),
                suppressed_by_loss: false, // managed by PathHealthMonitor
            })
            .collect();
        stats.sort_by_key(|s| s.path_id);
        stats
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_payload() -> PacketPayload {
        PacketPayload(vec![])
    }

    fn cover_payload(size: u16) -> PacketPayload {
        PacketPayload(vec![0u8; size as usize])
    }

    // ── U13: real packet deadline = arrival + latency_guard_us ───────────────

    #[test]
    fn u13_real_packet_deadline_equals_arrival_plus_guard() {
        let mut sched = Scheduler::new(80);
        sched.add_path(1, 1000, 0);

        let arrival_us = 500_000u64;
        let deadline = sched.enqueue_real(1, empty_payload(), arrival_us);

        assert_eq!(
            deadline,
            arrival_us + 80_000,
            "deadline must be arrival + latency_guard_us"
        );
    }

    #[test]
    fn real_packet_deadline_invariant_across_many_packets() {
        let guard_ms = 50u32;
        let guard_us = guard_ms as u64 * 1_000;
        let mut sched = Scheduler::new(guard_ms);
        sched.add_path(1, 500, 0);

        for i in 0u64..200 {
            let arrival = i * 1_000;
            let deadline = sched.enqueue_real(1, empty_payload(), arrival);
            assert_eq!(
                deadline,
                arrival + guard_us,
                "packet {i}: deadline {deadline} != {} + {guard_us}",
                arrival
            );
        }
    }

    // ── U14: cover dropped when token bucket empty ────────────────────────────

    #[test]
    fn u14_cover_dropped_when_bucket_empty() {
        let mut sched = Scheduler::new(80);
        // 1 kbps → capacity = 1*80 = 80 bits; tiny cover budget
        sched.add_path(1, 1, 0);

        // Drain the bucket by consuming more than capacity.
        // (We do this by calling try_enqueue_cover enough times at time=0.)
        let mut dropped = false;
        for _ in 0..200 {
            let accepted = sched.try_enqueue_cover(
                1,
                cover_payload(128),
                128,
                1_000,
                0, // now_us = 0, no refill since bucket was created at 0
            );
            if !accepted {
                dropped = true;
                break;
            }
        }
        assert!(
            dropped,
            "cover packets must be dropped once bucket is empty"
        );
    }

    // ── U15: real packets precede cover in drain_ready output ────────────────

    #[test]
    fn u15_real_preempts_cover_in_drain_order() {
        let mut sched = Scheduler::new(80);
        sched.add_path(1, 10_000, 0);

        let now = 0u64;
        // Enqueue cover first, then real.
        sched.try_enqueue_cover(1, cover_payload(64), 64, 0, now);
        sched.enqueue_real(1, empty_payload(), now);

        let ready = sched.drain_ready(now + 80_000 + 1);
        assert_eq!(ready.len(), 2);
        assert_eq!(
            ready[0].flow_type,
            FlowType::Real,
            "real must come before cover"
        );
        assert_eq!(ready[1].flow_type, FlowType::Shadow);
    }

    // ── U16: token bucket refills proportionally ──────────────────────────────

    #[test]
    fn u16_token_bucket_refills_over_time() {
        let mut sched = Scheduler::new(80);
        // 100 kbps → capacity = 8 000 bits; refill rate = 100 000 bps
        sched.add_path(1, 100, 0);

        // Drain the bucket by consuming full capacity (1000 bytes = 8 000 bits).
        assert!(sched.try_enqueue_cover(1, cover_payload(1000), 1000, 1, 0));
        assert_eq!(sched.token_fill(1), 0, "bucket should be empty");

        // Advance 10 ms (10 000 μs). Expected refill = 100 000 bps × 0.01 s = 1 000 bits.
        // Trigger refill via another try_enqueue_cover call.
        let now_after = 10_000u64;
        // Consume 0-byte cover to just trigger refill without consuming.
        // Actually size=0 means 0 bits consumed but try_consume(0)=true.
        // Use drain_ready instead to trigger the refill path.
        sched.drain_ready(now_after);
        assert_eq!(
            sched.token_fill(1),
            1_000,
            "should have 1 000 bits after 10 ms"
        );
    }

    // ── S8: real packets dispatched within guard even under cover load ────────

    #[test]
    fn s8_latency_guard_enforced_under_cover_load() {
        let guard_ms = 80u32;
        let guard_us = guard_ms as u64 * 1_000;
        let mut sched = Scheduler::new(guard_ms);
        sched.add_path(1, 10_000, 0);

        let n_real = 50u64;
        let mut deadlines = Vec::new();

        for i in 0..n_real {
            let arrival = i * 500; // 500 μs between packets
            // Also inject cover on every iteration.
            sched.try_enqueue_cover(1, cover_payload(200), 200, 5_000, arrival);
            let dl = sched.enqueue_real(1, empty_payload(), arrival);
            deadlines.push((arrival, dl));
        }

        for (arrival, deadline) in deadlines {
            assert_eq!(
                deadline,
                arrival + guard_us,
                "real packet at arrival={arrival} has wrong deadline {deadline}"
            );
        }
    }

    // ── Determinism: same inputs → same sequence IDs ─────────────────────────

    #[test]
    fn determinism_same_sequence_ids_for_same_inputs() {
        let run = |seed: u64| {
            let mut sched = Scheduler::new(80);
            sched.add_path(1, 1000, seed);
            let mut ids = Vec::new();
            for i in 0u64..10 {
                let dl = sched.enqueue_real(1, empty_payload(), i * 1_000);
                let pkts = sched.drain_ready(dl);
                for p in pkts {
                    ids.push(p.sequence_id);
                }
            }
            ids
        };

        assert_eq!(
            run(0),
            run(0),
            "same inputs must produce identical sequence IDs"
        );
    }

    // ── Cover offset capped at latency_guard_us ───────────────────────────────

    #[test]
    fn cover_deadline_capped_at_latency_guard() {
        let guard_ms = 80u32;
        let guard_us = guard_ms as u64 * 1_000;
        let mut sched = Scheduler::new(guard_ms);
        sched.add_path(1, 100_000, 0);

        let now = 0u64;
        // offset_us larger than guard — must be capped.
        sched.try_enqueue_cover(1, cover_payload(64), 64, u32::MAX, now);

        let ready = sched.drain_ready(now + guard_us + 1);
        assert_eq!(ready.len(), 1);
        assert!(
            ready[0].deadline_us <= now + guard_us,
            "deadline {} exceeds guard {}",
            ready[0].deadline_us,
            now + guard_us
        );
    }

    // ── Real packets enqueued with no prior add_path ──────────────────────────

    #[test]
    fn enqueue_real_creates_path_on_demand() {
        let mut sched = Scheduler::new(80);
        let dl = sched.enqueue_real(42, empty_payload(), 0);
        assert_eq!(dl, 80_000);
        assert!(sched.has_path(42));
        assert_eq!(sched.cover_depth(42), 0); // no cover budget
    }

    // ── remove_path redistributes real packets ────────────────────────────────

    #[test]
    fn remove_path_redistributes_real_to_fallback() {
        let mut sched = Scheduler::new(80);
        sched.add_path(1, 0, 0);
        sched.add_path(2, 0, 0);

        sched.enqueue_real(1, empty_payload(), 0);
        sched.enqueue_real(1, empty_payload(), 1_000);

        let leftover = sched.remove_path(1, Some(2));
        assert!(
            leftover.is_empty(),
            "all real packets should move to fallback"
        );
        assert!(!sched.has_path(1));
        assert_eq!(sched.real_depth(2), 2, "fallback should hold both packets");
    }

    #[test]
    fn remove_path_drops_cover_and_returns_real_without_fallback() {
        let mut sched = Scheduler::new(80);
        sched.add_path(1, 100_000, 0);

        sched.enqueue_real(1, empty_payload(), 0);
        sched.try_enqueue_cover(1, cover_payload(64), 64, 1_000, 0);

        let leftover = sched.remove_path(1, None);
        assert_eq!(leftover.len(), 1, "one real packet returned");
        assert_eq!(leftover[0].flow_type, FlowType::Real);
    }

    // ── clear_cover preserves real packets ────────────────────────────────────

    #[test]
    fn clear_cover_does_not_evict_real_packets() {
        let mut sched = Scheduler::new(80);
        sched.add_path(1, 100_000, 0);

        sched.enqueue_real(1, empty_payload(), 0);
        sched.try_enqueue_cover(1, cover_payload(64), 64, 1_000, 0);
        assert_eq!(sched.cover_depth(1), 1);

        sched.clear_cover(1);
        assert_eq!(sched.cover_depth(1), 0, "cover drained");
        assert_eq!(sched.real_depth(1), 1, "real preserved");
    }

    // ── path_ids returns sorted list ──────────────────────────────────────────

    #[test]
    fn path_ids_sorted_ascending() {
        let mut sched = Scheduler::new(80);
        for &id in &[5u64, 1, 3, 2, 4] {
            sched.add_path(id, 100, 0);
        }
        assert_eq!(sched.path_ids(), vec![1, 2, 3, 4, 5]);
    }

    // ── per_path_stats sorted and complete ────────────────────────────────────

    #[test]
    fn per_path_stats_covers_all_paths() {
        let mut sched = Scheduler::new(80);
        sched.add_path(10, 100, 0);
        sched.add_path(20, 200, 0);

        let stats = sched.per_path_stats();
        assert_eq!(stats.len(), 2);
        assert_eq!(stats[0].path_id, 10);
        assert_eq!(stats[1].path_id, 20);
    }
}
