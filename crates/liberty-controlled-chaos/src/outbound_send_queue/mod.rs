//! Outbound send queue — bounded FIFO buffer for packets waiting to be written
//! to the network layer or delivered to the Android JNI caller.
//!
//! `OutboundSendQueue` holds `QueuedPacket` items (peer destination + wire bytes).
//! When full it applies one of two overflow policies:
//! - `DropNewest` — discard the incoming packet (default, preserves in-flight order)
//! - `DropOldest` — evict the front item to make room (low-latency preference)

use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// Overflow policy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    /// Discard the newly-arriving packet when the queue is full.
    DropNewest,
    /// Evict the oldest queued packet to make room for the new one.
    DropOldest,
}

// ---------------------------------------------------------------------------
// QueuedPacket
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct QueuedPacket {
    /// Destination peer node ID (32 bytes).
    pub peer_id: [u8; 32],
    /// Fully encoded wire bytes ready for transmission.
    pub wire_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    /// Queue is full and DropNewest policy prevented the push.
    QueueFull,
    /// Queue is empty; nothing to pop.
    Empty,
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct QueueMetrics {
    pub total_pushed: u64,
    pub total_popped: u64,
    pub total_dropped: u64,
    pub peak_depth: usize,
}

// ---------------------------------------------------------------------------
// OutboundSendQueue
// ---------------------------------------------------------------------------

pub struct OutboundSendQueue {
    buf: VecDeque<QueuedPacket>,
    capacity: usize,
    policy: OverflowPolicy,
    metrics: QueueMetrics,
}

impl OutboundSendQueue {
    /// Create a new queue with the given capacity and overflow policy.
    pub fn new(capacity: usize, policy: OverflowPolicy) -> Self {
        Self {
            buf: VecDeque::with_capacity(capacity),
            capacity,
            policy,
            metrics: QueueMetrics::default(),
        }
    }

    // -----------------------------------------------------------------------
    // Write
    // -----------------------------------------------------------------------

    /// Enqueue a packet. Returns `Ok(())` on success.
    /// Returns `Err(QueueError::QueueFull)` if the queue is full and the policy
    /// is `DropNewest`.  With `DropOldest` the return is always `Ok(())`.
    pub fn push(&mut self, pkt: QueuedPacket) -> Result<(), QueueError> {
        if self.buf.len() >= self.capacity {
            self.metrics.total_dropped += 1;
            match self.policy {
                OverflowPolicy::DropNewest => return Err(QueueError::QueueFull),
                OverflowPolicy::DropOldest => {
                    self.buf.pop_front();
                }
            }
        }
        self.buf.push_back(pkt);
        self.metrics.total_pushed += 1;
        if self.buf.len() > self.metrics.peak_depth {
            self.metrics.peak_depth = self.buf.len();
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Read
    // -----------------------------------------------------------------------

    /// Dequeue the oldest packet. Returns `Err(QueueError::Empty)` if empty.
    pub fn pop(&mut self) -> Result<QueuedPacket, QueueError> {
        match self.buf.pop_front() {
            Some(p) => {
                self.metrics.total_popped += 1;
                Ok(p)
            }
            None => Err(QueueError::Empty),
        }
    }

    /// Drain up to `limit` packets into a `Vec`.
    pub fn drain(&mut self, limit: usize) -> Vec<QueuedPacket> {
        let take = limit.min(self.buf.len());
        let mut out = Vec::with_capacity(take);
        for _ in 0..take {
            if let Some(p) = self.buf.pop_front() {
                self.metrics.total_popped += 1;
                out.push(p);
            }
        }
        out
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn dropped_count(&self) -> u64 {
        self.metrics.total_dropped
    }

    pub fn metrics(&self) -> &QueueMetrics {
        &self.metrics
    }

    /// Returns the IDs of all peers currently in the queue (may contain duplicates).
    pub fn pending_peers(&self) -> Vec<[u8; 32]> {
        self.buf.iter().map(|p| p.peer_id).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn pkt(peer: u8, data: &[u8]) -> QueuedPacket {
        QueuedPacket {
            peer_id: nid(peer),
            wire_bytes: data.to_vec(),
        }
    }

    fn make_q(cap: usize) -> OutboundSendQueue {
        OutboundSendQueue::new(cap, OverflowPolicy::DropNewest)
    }

    // OSQ1: push and pop round-trip.
    #[test]
    fn osq1_push_pop_round_trip() {
        let mut q = make_q(8);
        q.push(pkt(1, b"hello")).unwrap();
        let out = q.pop().unwrap();
        assert_eq!(out.peer_id, nid(1));
        assert_eq!(out.wire_bytes, b"hello");
    }

    // OSQ2: FIFO ordering preserved.
    #[test]
    fn osq2_fifo_order() {
        let mut q = make_q(8);
        q.push(pkt(1, b"a")).unwrap();
        q.push(pkt(2, b"b")).unwrap();
        q.push(pkt(3, b"c")).unwrap();
        assert_eq!(q.pop().unwrap().peer_id, nid(1));
        assert_eq!(q.pop().unwrap().peer_id, nid(2));
        assert_eq!(q.pop().unwrap().peer_id, nid(3));
    }

    // OSQ3: DropNewest on full queue returns QueueFull.
    #[test]
    fn osq3_drop_newest_full() {
        let mut q = make_q(2);
        q.push(pkt(1, b"a")).unwrap();
        q.push(pkt(2, b"b")).unwrap();
        let err = q.push(pkt(3, b"c")).unwrap_err();
        assert_eq!(err, QueueError::QueueFull);
        assert_eq!(q.dropped_count(), 1);
        assert_eq!(q.len(), 2);
    }

    // OSQ4: DropOldest evicts front to make room.
    #[test]
    fn osq4_drop_oldest_evicts_front() {
        let mut q = OutboundSendQueue::new(2, OverflowPolicy::DropOldest);
        q.push(pkt(1, b"first")).unwrap();
        q.push(pkt(2, b"second")).unwrap();
        q.push(pkt(3, b"third")).unwrap(); // evicts peer=1
        assert_eq!(q.len(), 2);
        assert_eq!(q.dropped_count(), 1);
        let front = q.pop().unwrap();
        assert_eq!(front.peer_id, nid(2)); // peer=1 was evicted
    }

    // OSQ5: pop on empty queue returns Empty.
    #[test]
    fn osq5_pop_empty_returns_error() {
        let mut q = make_q(4);
        assert_eq!(q.pop().unwrap_err(), QueueError::Empty);
    }

    // OSQ6: drain returns up to limit items.
    #[test]
    fn osq6_drain_limit() {
        let mut q = make_q(8);
        for i in 0u8..5 {
            q.push(pkt(i, b"x")).unwrap();
        }
        let batch = q.drain(3);
        assert_eq!(batch.len(), 3);
        assert_eq!(q.len(), 2);
    }

    // OSQ7: drain more than available returns all.
    #[test]
    fn osq7_drain_more_than_available() {
        let mut q = make_q(4);
        q.push(pkt(1, b"a")).unwrap();
        q.push(pkt(2, b"b")).unwrap();
        let batch = q.drain(100);
        assert_eq!(batch.len(), 2);
        assert!(q.is_empty());
    }

    // OSQ8: metrics track pushed and popped.
    #[test]
    fn osq8_metrics_accurate() {
        let mut q = make_q(8);
        q.push(pkt(1, b"a")).unwrap();
        q.push(pkt(2, b"b")).unwrap();
        q.pop().unwrap();
        let m = q.metrics();
        assert_eq!(m.total_pushed, 2);
        assert_eq!(m.total_popped, 1);
        assert_eq!(m.total_dropped, 0);
        assert_eq!(m.peak_depth, 2);
    }

    // OSQ9: pending_peers reflects all destinations in queue.
    #[test]
    fn osq9_pending_peers() {
        let mut q = make_q(8);
        q.push(pkt(5, b"a")).unwrap();
        q.push(pkt(7, b"b")).unwrap();
        q.push(pkt(5, b"c")).unwrap(); // duplicate peer
        let peers = q.pending_peers();
        assert_eq!(peers.len(), 3);
        assert_eq!(peers[0], nid(5));
        assert_eq!(peers[1], nid(7));
        assert_eq!(peers[2], nid(5));
    }

    // OSQ10: capacity accessor matches construction.
    #[test]
    fn osq10_capacity_reported() {
        let q = make_q(64);
        assert_eq!(q.capacity(), 64);
    }
}
