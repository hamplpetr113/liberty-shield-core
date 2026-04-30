//! Per-stream queue structures for StreamMux.
//!
//! `StreamQueue` holds two sub-queues:
//!   - `real_heap`:    min-heap by `scheduled_send_time` (soonest first).
//!   - `shadow_deque`: bounded FIFO; oldest entry evicted on overflow.

use std::cmp::Ordering;
use std::collections::{BinaryHeap, VecDeque};

use crate::runtime_boundary::PayloadRef;

// ── RealEntry ─────────────────────────────────────────────────────────────────

pub(super) struct RealEntry {
    pub scheduled_send_time: u64,
    pub latency_deadline: u64,
    pub fragment_id: u64,
    pub payload_ref: PayloadRef,
    pub shadow_flag: bool,
}

impl PartialEq for RealEntry {
    fn eq(&self, other: &Self) -> bool {
        self.scheduled_send_time == other.scheduled_send_time
            && self.latency_deadline == other.latency_deadline
    }
}

impl Eq for RealEntry {}

impl PartialOrd for RealEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RealEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reversed for min-heap: smallest scheduled_send_time at top.
        other
            .scheduled_send_time
            .cmp(&self.scheduled_send_time)
            .then(other.latency_deadline.cmp(&self.latency_deadline))
    }
}

// ── ShadowEntry ───────────────────────────────────────────────────────────────

pub(super) struct ShadowEntry {
    pub scheduled_send_time: u64,
    pub latency_deadline: u64,
    pub fragment_id: u64,
    pub payload_ref: PayloadRef,
}

// ── StreamQueue ───────────────────────────────────────────────────────────────

pub(super) struct StreamQueue {
    real_heap: BinaryHeap<RealEntry>,
    shadow_deque: VecDeque<ShadowEntry>,
    max_shadow_depth: usize,
}

impl StreamQueue {
    pub fn new(max_shadow_depth: usize) -> Self {
        Self {
            real_heap: BinaryHeap::new(),
            shadow_deque: VecDeque::new(),
            max_shadow_depth,
        }
    }

    pub fn push_real(&mut self, entry: RealEntry) {
        self.real_heap.push(entry);
    }

    /// Enqueue a shadow entry. Returns the number of entries evicted (0 or 1).
    pub fn push_shadow(&mut self, entry: ShadowEntry) -> u64 {
        let evicted = if self.shadow_deque.len() >= self.max_shadow_depth {
            self.shadow_deque.pop_front();
            1
        } else {
            0
        };
        self.shadow_deque.push_back(entry);
        evicted
    }

    pub fn real_len(&self) -> usize {
        self.real_heap.len()
    }

    /// Drain real frames eligible for dispatch (`scheduled_send_time <= now_us`).
    /// Returns `(ready, expired)`. Expired real frames have `latency_deadline < now_us`.
    pub fn drain_ready_real(&mut self, now_us: u64) -> (Vec<RealEntry>, Vec<RealEntry>) {
        let mut ready = Vec::new();
        let mut expired = Vec::new();
        while let Some(top) = self.real_heap.peek() {
            if top.scheduled_send_time <= now_us {
                let e = self.real_heap.pop().unwrap();
                if now_us > e.latency_deadline {
                    expired.push(e);
                } else {
                    ready.push(e);
                }
            } else {
                break;
            }
        }
        (ready, expired)
    }

    /// Drain shadow frames eligible for dispatch (`scheduled_send_time <= now_us`).
    /// Returns `(ready, expired_count)`. Expired entries are dropped silently.
    pub fn drain_ready_shadow(&mut self, now_us: u64) -> (Vec<ShadowEntry>, u64) {
        let mut ready = Vec::new();
        let mut expired_count = 0u64;
        let deque = std::mem::take(&mut self.shadow_deque);
        for entry in deque {
            if entry.scheduled_send_time <= now_us {
                if now_us <= entry.latency_deadline {
                    ready.push(entry);
                } else {
                    expired_count += 1;
                }
            } else {
                self.shadow_deque.push_back(entry);
            }
        }
        (ready, expired_count)
    }

    /// Drain all real entries unconditionally (stream reset).
    pub fn drain_all_real(&mut self) -> Vec<RealEntry> {
        let heap = std::mem::take(&mut self.real_heap);
        heap.into_iter().collect()
    }
}
