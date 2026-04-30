//! Stream priority queue — prioritizes stream data for relay scheduling.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StreamPriority {
    Background = 0,
    Normal = 1,
    Interactive = 2,
    Realtime = 3,
}

#[derive(Debug)]
struct StreamEntry {
    priority: StreamPriority,
    sequence: u64,
    stream_id: u64,
    bytes: u64,
}

impl PartialEq for StreamEntry {
    fn eq(&self, other: &Self) -> bool {
        self.priority == other.priority && self.sequence == other.sequence
    }
}
impl Eq for StreamEntry {}

impl PartialOrd for StreamEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for StreamEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority
            .cmp(&other.priority)
            .then(Reverse(self.sequence).cmp(&Reverse(other.sequence)))
    }
}

pub struct StreamPriorityQueue {
    heap: BinaryHeap<StreamEntry>,
    counter: u64,
    capacity: usize,
    dropped: u64,
    total_bytes: u64,
}

impl StreamPriorityQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            heap: BinaryHeap::new(),
            counter: 0,
            capacity,
            dropped: 0,
            total_bytes: 0,
        }
    }

    pub fn push(&mut self, stream_id: u64, bytes: u64, priority: StreamPriority) -> bool {
        if self.heap.len() >= self.capacity {
            self.dropped += 1;
            return false;
        }
        self.heap.push(StreamEntry {
            priority,
            sequence: self.counter,
            stream_id,
            bytes,
        });
        self.counter += 1;
        self.total_bytes += bytes;
        true
    }

    pub fn pop(&mut self) -> Option<(u64, u64)> {
        self.heap.pop().map(|e| (e.stream_id, e.bytes))
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
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SPQ1: push and pop roundtrip.
    #[test]
    fn spq1_push_pop() {
        let mut q = StreamPriorityQueue::new(10);
        q.push(1, 100, StreamPriority::Normal);
        assert_eq!(q.pop(), Some((1, 100)));
    }

    // SPQ2: pop from empty returns None.
    #[test]
    fn spq2_empty() {
        let mut q = StreamPriorityQueue::new(10);
        assert!(q.pop().is_none());
    }

    // SPQ3: higher priority dequeued first.
    #[test]
    fn spq3_priority() {
        let mut q = StreamPriorityQueue::new(10);
        q.push(1, 0, StreamPriority::Background);
        q.push(2, 0, StreamPriority::Realtime);
        assert_eq!(q.pop(), Some((2, 0)));
    }

    // SPQ4: same priority FIFO order.
    #[test]
    fn spq4_fifo() {
        let mut q = StreamPriorityQueue::new(10);
        q.push(10, 0, StreamPriority::Normal);
        q.push(20, 0, StreamPriority::Normal);
        assert_eq!(q.pop(), Some((10, 0)));
    }

    // SPQ5: capacity drop increments dropped.
    #[test]
    fn spq5_capacity() {
        let mut q = StreamPriorityQueue::new(1);
        q.push(1, 0, StreamPriority::Normal);
        assert!(!q.push(2, 0, StreamPriority::Normal));
        assert_eq!(q.dropped(), 1);
    }

    // SPQ6: total_bytes accumulates.
    #[test]
    fn spq6_total_bytes() {
        let mut q = StreamPriorityQueue::new(10);
        q.push(1, 100, StreamPriority::Normal);
        q.push(2, 200, StreamPriority::Normal);
        assert_eq!(q.total_bytes(), 300);
    }

    // SPQ7: len returns count.
    #[test]
    fn spq7_len() {
        let mut q = StreamPriorityQueue::new(10);
        q.push(1, 0, StreamPriority::Normal);
        q.push(2, 0, StreamPriority::Normal);
        assert_eq!(q.len(), 2);
    }

    // SPQ8: is_empty correct.
    #[test]
    fn spq8_is_empty() {
        let mut q = StreamPriorityQueue::new(10);
        assert!(q.is_empty());
        q.push(1, 0, StreamPriority::Normal);
        assert!(!q.is_empty());
    }

    // SPQ9: interactive priority above normal.
    #[test]
    fn spq9_interactive() {
        let mut q = StreamPriorityQueue::new(10);
        q.push(1, 0, StreamPriority::Normal);
        q.push(2, 0, StreamPriority::Interactive);
        assert_eq!(q.pop(), Some((2, 0)));
    }

    // SPQ10: background is lowest priority.
    #[test]
    fn spq10_background_last() {
        let mut q = StreamPriorityQueue::new(10);
        q.push(1, 0, StreamPriority::Background);
        q.push(2, 0, StreamPriority::Normal);
        q.pop(); // Normal
        assert_eq!(q.pop(), Some((1, 0))); // Background
    }
}
