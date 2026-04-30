//! Cell dispatch queue — priority-ordered outbound cell queue.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use crate::onion_cell_v2::OnionCellV2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

#[derive(Debug)]
struct Entry {
    priority: Priority,
    sequence: u64,
    cell: OnionCellV2,
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.sequence == other.sequence
    }
}
impl Eq for Entry {}

impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Entry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority
            .cmp(&other.priority)
            .then(Reverse(self.sequence).cmp(&Reverse(other.sequence)))
    }
}

pub struct CellDispatchQueue {
    heap: BinaryHeap<Entry>,
    counter: u64,
    capacity: usize,
    dropped: u64,
}

impl CellDispatchQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            heap: BinaryHeap::new(),
            counter: 0,
            capacity,
            dropped: 0,
        }
    }

    pub fn push(&mut self, cell: OnionCellV2, priority: Priority) -> bool {
        if self.heap.len() >= self.capacity {
            self.dropped += 1;
            return false;
        }
        self.heap.push(Entry {
            priority,
            sequence: self.counter,
            cell,
        });
        self.counter += 1;
        true
    }

    pub fn pop(&mut self) -> Option<OnionCellV2> {
        self.heap.pop().map(|e| e.cell)
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion_cell_v2::{CMD_DATA, OnionCellV2};

    fn cell(seq: u64) -> OnionCellV2 {
        OnionCellV2 {
            command: CMD_DATA,
            circuit_id: 1,
            stream_id: 0,
            sequence: seq,
            header_mac: [0u8; 32],
            payload: [0u8; 1364],
        }
    }

    // CDQ1: push and pop roundtrip.
    #[test]
    fn cdq1_push_pop() {
        let mut q = CellDispatchQueue::new(10);
        q.push(cell(1), Priority::Normal);
        let c = q.pop().unwrap();
        assert_eq!(c.sequence, 1);
    }

    // CDQ2: pop from empty returns None.
    #[test]
    fn cdq2_empty_pop() {
        let mut q = CellDispatchQueue::new(10);
        assert!(q.pop().is_none());
    }

    // CDQ3: high priority dequeued before low.
    #[test]
    fn cdq3_priority_order() {
        let mut q = CellDispatchQueue::new(10);
        q.push(cell(1), Priority::Low);
        q.push(cell(2), Priority::High);
        let c = q.pop().unwrap();
        assert_eq!(c.sequence, 2);
    }

    // CDQ4: same priority preserves FIFO insertion order.
    #[test]
    fn cdq4_fifo_same_priority() {
        let mut q = CellDispatchQueue::new(10);
        q.push(cell(10), Priority::Normal);
        q.push(cell(20), Priority::Normal);
        assert_eq!(q.pop().unwrap().sequence, 10);
    }

    // CDQ5: capacity limit drops cells.
    #[test]
    fn cdq5_capacity_drop() {
        let mut q = CellDispatchQueue::new(1);
        assert!(q.push(cell(1), Priority::Normal));
        assert!(!q.push(cell(2), Priority::Normal));
    }

    // CDQ6: dropped counter increments on drop.
    #[test]
    fn cdq6_dropped_counter() {
        let mut q = CellDispatchQueue::new(1);
        q.push(cell(1), Priority::Normal);
        q.push(cell(2), Priority::Normal);
        assert_eq!(q.dropped(), 1);
    }

    // CDQ7: len returns queue size.
    #[test]
    fn cdq7_len() {
        let mut q = CellDispatchQueue::new(10);
        q.push(cell(1), Priority::Normal);
        q.push(cell(2), Priority::Normal);
        assert_eq!(q.len(), 2);
    }

    // CDQ8: is_empty correct.
    #[test]
    fn cdq8_is_empty() {
        let mut q = CellDispatchQueue::new(10);
        assert!(q.is_empty());
        q.push(cell(1), Priority::Normal);
        assert!(!q.is_empty());
    }

    // CDQ9: critical priority is dequeued first.
    #[test]
    fn cdq9_critical_first() {
        let mut q = CellDispatchQueue::new(10);
        q.push(cell(1), Priority::High);
        q.push(cell(2), Priority::Critical);
        q.push(cell(3), Priority::Normal);
        assert_eq!(q.pop().unwrap().sequence, 2);
    }

    // CDQ10: pop drains all in priority order.
    #[test]
    fn cdq10_full_drain() {
        let mut q = CellDispatchQueue::new(10);
        q.push(cell(1), Priority::Low);
        q.push(cell(2), Priority::High);
        q.push(cell(3), Priority::Normal);
        let first = q.pop().unwrap().sequence;
        let second = q.pop().unwrap().sequence;
        let third = q.pop().unwrap().sequence;
        assert_eq!(first, 2);
        assert_eq!(second, 3);
        assert_eq!(third, 1);
    }
}
