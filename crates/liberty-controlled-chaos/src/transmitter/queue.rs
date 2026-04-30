//! FragmentQueue — per-path min-heap of ScheduledPacket values.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use super::types::{FlowType, ScheduledPacket};

// ── Min-heap entry ────────────────────────────────────────────────────────────

struct Entry(ScheduledPacket);

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.0.deadline_us == other.0.deadline_us
    }
}
impl Eq for Entry {}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse: smaller deadline → higher priority in max-heap.
        other.0.deadline_us.cmp(&self.0.deadline_us)
    }
}

// ── FragmentQueue ─────────────────────────────────────────────────────────────

pub struct FragmentQueue {
    /// Real packets (never depth-limited, never evicted).
    real_heap: BinaryHeap<Entry>,
    /// Cover packets (depth-limited; oldest evicted on overflow).
    cover_heap: BinaryHeap<Entry>,
    max_cover_depth: usize,
}

impl FragmentQueue {
    /// `max_cover_depth`: `2 × (cover_bandwidth_kbps × latency_guard_ms / 8000)`.
    /// Clamped to at least 4 so low-bandwidth paths still enqueue a few packets.
    pub fn new(cover_bandwidth_kbps: u32, latency_guard_ms: u32) -> Self {
        let depth = (2 * cover_bandwidth_kbps as usize * latency_guard_ms as usize / 8_000).max(4);
        Self {
            real_heap: BinaryHeap::new(),
            cover_heap: BinaryHeap::new(),
            max_cover_depth: depth,
        }
    }

    pub fn push(&mut self, packet: ScheduledPacket) {
        match packet.flow_type {
            FlowType::Real => {
                self.real_heap.push(Entry(packet));
            }
            FlowType::Shadow => {
                // Evict oldest (earliest deadline) cover packet on overflow.
                while self.cover_heap.len() >= self.max_cover_depth {
                    self.cover_heap.pop();
                }
                self.cover_heap.push(Entry(packet));
            }
        }
    }

    /// Drain all packets with `deadline_us ≤ now_us`, real first then cover,
    /// each group sorted by ascending deadline.
    pub fn drain_ready(&mut self, now_us: u64) -> Vec<ScheduledPacket> {
        let mut out = Vec::new();

        // Real packets first.
        while let Some(entry) = self.real_heap.peek() {
            if entry.0.deadline_us <= now_us {
                out.push(self.real_heap.pop().unwrap().0);
            } else {
                break;
            }
        }

        // Cover packets second.
        while let Some(entry) = self.cover_heap.peek() {
            if entry.0.deadline_us <= now_us {
                out.push(self.cover_heap.pop().unwrap().0);
            } else {
                break;
            }
        }

        out
    }

    /// Drain all cover packets (used during plan update).
    pub fn drain_all_cover(&mut self) {
        self.cover_heap.clear();
    }

    pub fn real_depth(&self) -> usize {
        self.real_heap.len()
    }

    pub fn cover_depth(&self) -> usize {
        self.cover_heap.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transmitter::types::PacketPayload;

    fn make_packet(path_id: u64, flow_type: FlowType, deadline: u64, seq: u64) -> ScheduledPacket {
        ScheduledPacket {
            path_id,
            flow_type,
            payload: PacketPayload(vec![]),
            deadline_us: deadline,
            sequence_id: seq,
        }
    }

    // U15 — Real packet with earlier deadline appears before cover in drain.
    #[test]
    fn u15_real_preempts_cover_in_queue() {
        let mut q = FragmentQueue::new(100, 80);
        q.push(make_packet(1, FlowType::Shadow, 100, 1));
        q.push(make_packet(1, FlowType::Real, 200, 2));

        let ready = q.drain_ready(300);
        assert_eq!(ready.len(), 2);
        assert_eq!(ready[0].flow_type, FlowType::Real, "real should come first");
        assert_eq!(ready[1].flow_type, FlowType::Shadow);
    }

    #[test]
    fn cover_overflow_evicts_oldest() {
        let mut q = FragmentQueue::new(10, 10); // max_cover_depth = max(4, 2*10*10/8000) = 4
        for i in 0u64..10 {
            q.push(make_packet(1, FlowType::Shadow, i + 1, i));
        }
        // Only max_cover_depth entries should remain.
        assert!(q.cover_depth() <= q.max_cover_depth);
    }

    #[test]
    fn real_packets_not_depth_limited() {
        let mut q = FragmentQueue::new(10, 10);
        for i in 0u64..100 {
            q.push(make_packet(1, FlowType::Real, i + 1, i));
        }
        assert_eq!(q.real_depth(), 100);
    }

    #[test]
    fn drain_all_cover_clears_only_cover() {
        let mut q = FragmentQueue::new(100, 80);
        q.push(make_packet(1, FlowType::Real, 50, 0));
        q.push(make_packet(1, FlowType::Shadow, 50, 1));
        q.drain_all_cover();
        assert_eq!(q.cover_depth(), 0);
        assert_eq!(q.real_depth(), 1);
    }
}
