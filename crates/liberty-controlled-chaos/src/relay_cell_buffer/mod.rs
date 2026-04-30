//! Relay cell buffer — bounded FIFO queue per circuit for relay cells.
//!
//! Provides enqueue/dequeue with capacity enforcement and drop counting.

use std::collections::{HashMap, VecDeque};

use crate::onion_cell_v2::OnionCellV2;

// ---------------------------------------------------------------------------
// BufferError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferError {
    CircuitNotFound,
    BufferFull,
}

// ---------------------------------------------------------------------------
// CircuitBuffer
// ---------------------------------------------------------------------------

struct CircuitBuffer {
    queue: VecDeque<OnionCellV2>,
    capacity: usize,
    total_enqueued: u64,
    total_dropped: u64,
}

impl CircuitBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            queue: VecDeque::with_capacity(capacity),
            capacity,
            total_enqueued: 0,
            total_dropped: 0,
        }
    }

    fn enqueue(&mut self, cell: OnionCellV2) -> Result<(), BufferError> {
        if self.queue.len() >= self.capacity {
            self.total_dropped += 1;
            return Err(BufferError::BufferFull);
        }
        self.queue.push_back(cell);
        self.total_enqueued += 1;
        Ok(())
    }

    fn dequeue(&mut self) -> Option<OnionCellV2> {
        self.queue.pop_front()
    }
}

// ---------------------------------------------------------------------------
// RelayCellBuffer
// ---------------------------------------------------------------------------

pub struct RelayCellBuffer {
    default_capacity: usize,
    buffers: HashMap<u64, CircuitBuffer>,
    global_enqueued: u64,
    global_dropped: u64,
}

impl RelayCellBuffer {
    pub fn new(default_capacity: usize) -> Self {
        Self {
            default_capacity,
            buffers: HashMap::new(),
            global_enqueued: 0,
            global_dropped: 0,
        }
    }

    pub fn register_circuit(&mut self, circuit_id: u64) {
        self.buffers
            .entry(circuit_id)
            .or_insert_with(|| CircuitBuffer::new(self.default_capacity));
    }

    pub fn register_circuit_with_capacity(&mut self, circuit_id: u64, capacity: usize) {
        self.buffers
            .insert(circuit_id, CircuitBuffer::new(capacity));
    }

    pub fn remove_circuit(&mut self, circuit_id: u64) {
        self.buffers.remove(&circuit_id);
    }

    pub fn enqueue(&mut self, circuit_id: u64, cell: OnionCellV2) -> Result<(), BufferError> {
        let buf = self
            .buffers
            .get_mut(&circuit_id)
            .ok_or(BufferError::CircuitNotFound)?;
        match buf.enqueue(cell) {
            Ok(()) => {
                self.global_enqueued += 1;
                Ok(())
            }
            Err(e) => {
                self.global_dropped += 1;
                Err(e)
            }
        }
    }

    pub fn dequeue(&mut self, circuit_id: u64) -> Option<OnionCellV2> {
        self.buffers.get_mut(&circuit_id)?.dequeue()
    }

    pub fn pending(&self, circuit_id: u64) -> usize {
        self.buffers
            .get(&circuit_id)
            .map(|b| b.queue.len())
            .unwrap_or(0)
    }

    pub fn global_enqueued(&self) -> u64 {
        self.global_enqueued
    }

    pub fn global_dropped(&self) -> u64 {
        self.global_dropped
    }

    pub fn circuit_count(&self) -> usize {
        self.buffers.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion_cell_v2::{CMD_DATA, OnionCellV2};

    fn cell(circuit_id: u64, seq: u64) -> OnionCellV2 {
        OnionCellV2 {
            command: CMD_DATA,
            circuit_id,
            stream_id: 0,
            sequence: seq,
            header_mac: [0u8; 32],
            payload: [0u8; 1364],
        }
    }

    // RCB1: enqueue and dequeue roundtrip.
    #[test]
    fn rcb1_enqueue_dequeue() {
        let mut buf = RelayCellBuffer::new(16);
        buf.register_circuit(1);
        buf.enqueue(1, cell(1, 0)).unwrap();
        let c = buf.dequeue(1).unwrap();
        assert_eq!(c.sequence, 0);
    }

    // RCB2: enqueue to unknown circuit returns CircuitNotFound.
    #[test]
    fn rcb2_not_found() {
        let mut buf = RelayCellBuffer::new(16);
        assert_eq!(
            buf.enqueue(99, cell(99, 0)),
            Err(BufferError::CircuitNotFound)
        );
    }

    // RCB3: full buffer returns BufferFull.
    #[test]
    fn rcb3_buffer_full() {
        let mut buf = RelayCellBuffer::new(2);
        buf.register_circuit(1);
        buf.enqueue(1, cell(1, 0)).unwrap();
        buf.enqueue(1, cell(1, 1)).unwrap();
        assert_eq!(buf.enqueue(1, cell(1, 2)), Err(BufferError::BufferFull));
    }

    // RCB4: dequeue from empty circuit returns None.
    #[test]
    fn rcb4_empty_dequeue() {
        let mut buf = RelayCellBuffer::new(16);
        buf.register_circuit(1);
        assert!(buf.dequeue(1).is_none());
    }

    // RCB5: pending returns correct count.
    #[test]
    fn rcb5_pending() {
        let mut buf = RelayCellBuffer::new(16);
        buf.register_circuit(1);
        buf.enqueue(1, cell(1, 0)).unwrap();
        buf.enqueue(1, cell(1, 1)).unwrap();
        assert_eq!(buf.pending(1), 2);
    }

    // RCB6: FIFO ordering preserved.
    #[test]
    fn rcb6_fifo_order() {
        let mut buf = RelayCellBuffer::new(16);
        buf.register_circuit(1);
        for i in 0..5 {
            buf.enqueue(1, cell(1, i)).unwrap();
        }
        for i in 0..5 {
            assert_eq!(buf.dequeue(1).unwrap().sequence, i);
        }
    }

    // RCB7: global_enqueued counter.
    #[test]
    fn rcb7_global_enqueued() {
        let mut buf = RelayCellBuffer::new(16);
        buf.register_circuit(1);
        buf.enqueue(1, cell(1, 0)).unwrap();
        buf.enqueue(1, cell(1, 1)).unwrap();
        assert_eq!(buf.global_enqueued(), 2);
    }

    // RCB8: global_dropped counter.
    #[test]
    fn rcb8_global_dropped() {
        let mut buf = RelayCellBuffer::new(1);
        buf.register_circuit(1);
        buf.enqueue(1, cell(1, 0)).unwrap();
        buf.enqueue(1, cell(1, 1)).unwrap_err();
        assert_eq!(buf.global_dropped(), 1);
    }

    // RCB9: remove_circuit.
    #[test]
    fn rcb9_remove_circuit() {
        let mut buf = RelayCellBuffer::new(16);
        buf.register_circuit(1);
        buf.remove_circuit(1);
        assert_eq!(buf.circuit_count(), 0);
    }

    // RCB10: custom capacity per circuit.
    #[test]
    fn rcb10_custom_capacity() {
        let mut buf = RelayCellBuffer::new(4);
        buf.register_circuit_with_capacity(1, 2);
        buf.enqueue(1, cell(1, 0)).unwrap();
        buf.enqueue(1, cell(1, 1)).unwrap();
        assert_eq!(buf.enqueue(1, cell(1, 2)), Err(BufferError::BufferFull));
    }
}
