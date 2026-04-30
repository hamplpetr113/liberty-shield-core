//! Stream multiplexer v2 — multiplexes logical streams over one circuit.
//!
//! `StreamMuxV2` manages open streams keyed by `stream_id`.  Each stream has
//! its own sequence counter and a receive queue.  Backpressure is signalled
//! when a stream's queue depth reaches `max_queue_depth`.

use std::collections::{HashMap, VecDeque};

// ---------------------------------------------------------------------------
// StreamState
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Open,
    HalfClosed,
    Closed,
}

// ---------------------------------------------------------------------------
// StreamEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct StreamEntry {
    state: StreamState,
    send_sequence: u64,
    recv_queue: VecDeque<Vec<u8>>,
    bytes_sent: u64,
    bytes_received: u64,
}

impl StreamEntry {
    fn new(_stream_id: u32) -> Self {
        Self {
            state: StreamState::Open,
            send_sequence: 0,
            recv_queue: VecDeque::new(),
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// MuxError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MuxError {
    StreamNotFound,
    StreamClosed,
    Backpressure,
    DuplicateStream,
}

// ---------------------------------------------------------------------------
// StreamMuxV2
// ---------------------------------------------------------------------------

pub struct StreamMuxV2 {
    circuit_id: u64,
    streams: HashMap<u32, StreamEntry>,
    max_queue_depth: usize,
    total_bytes_sent: u64,
    total_bytes_received: u64,
}

impl StreamMuxV2 {
    pub fn new(circuit_id: u64, max_queue_depth: usize) -> Self {
        Self {
            circuit_id,
            streams: HashMap::new(),
            max_queue_depth,
            total_bytes_sent: 0,
            total_bytes_received: 0,
        }
    }

    pub fn circuit_id(&self) -> u64 {
        self.circuit_id
    }

    /// Open a new stream.
    pub fn open_stream(&mut self, stream_id: u32) -> Result<(), MuxError> {
        if self.streams.contains_key(&stream_id) {
            return Err(MuxError::DuplicateStream);
        }
        self.streams.insert(stream_id, StreamEntry::new(stream_id));
        Ok(())
    }

    /// Close (half-close) a stream — no more data may be sent.
    pub fn close_stream(&mut self, stream_id: u32) -> Result<(), MuxError> {
        let s = self
            .streams
            .get_mut(&stream_id)
            .ok_or(MuxError::StreamNotFound)?;
        s.state = StreamState::HalfClosed;
        Ok(())
    }

    /// Destroy a stream completely.
    pub fn destroy_stream(&mut self, stream_id: u32) -> Result<(), MuxError> {
        self.streams
            .remove(&stream_id)
            .map(|_| ())
            .ok_or(MuxError::StreamNotFound)
    }

    /// Queue data for sending on a stream.  Returns the outgoing sequence number.
    pub fn send(&mut self, stream_id: u32, data: Vec<u8>) -> Result<u64, MuxError> {
        let s = self
            .streams
            .get_mut(&stream_id)
            .ok_or(MuxError::StreamNotFound)?;
        if s.state != StreamState::Open {
            return Err(MuxError::StreamClosed);
        }
        if s.recv_queue.len() >= self.max_queue_depth {
            return Err(MuxError::Backpressure);
        }
        let seq = s.send_sequence;
        s.send_sequence += 1;
        s.bytes_sent += data.len() as u64;
        self.total_bytes_sent += data.len() as u64;
        // For in-memory mux, data goes directly to the recv queue (loopback).
        s.recv_queue.push_back(data);
        Ok(seq)
    }

    /// Pop one data item from the receive queue.
    pub fn recv(&mut self, stream_id: u32) -> Result<Option<Vec<u8>>, MuxError> {
        let s = self
            .streams
            .get_mut(&stream_id)
            .ok_or(MuxError::StreamNotFound)?;
        let data = s.recv_queue.pop_front();
        if let Some(d) = &data {
            s.bytes_received += d.len() as u64;
            self.total_bytes_received += d.len() as u64;
        }
        Ok(data)
    }

    pub fn stream_state(&self, stream_id: u32) -> Option<StreamState> {
        self.streams.get(&stream_id).map(|s| s.state)
    }

    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    pub fn open_stream_count(&self) -> usize {
        self.streams
            .values()
            .filter(|s| s.state == StreamState::Open)
            .count()
    }

    pub fn queue_depth(&self, stream_id: u32) -> Option<usize> {
        self.streams.get(&stream_id).map(|s| s.recv_queue.len())
    }

    pub fn total_bytes_sent(&self) -> u64 {
        self.total_bytes_sent
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mux() -> StreamMuxV2 {
        StreamMuxV2::new(42, 8)
    }

    // SM2_1: open_stream creates an open stream.
    #[test]
    fn sm2_1_open_stream() {
        let mut m = mux();
        m.open_stream(1).unwrap();
        assert_eq!(m.stream_state(1), Some(StreamState::Open));
    }

    // SM2_2: duplicate stream returns DuplicateStream.
    #[test]
    fn sm2_2_duplicate_stream() {
        let mut m = mux();
        m.open_stream(1).unwrap();
        assert_eq!(m.open_stream(1), Err(MuxError::DuplicateStream));
    }

    // SM2_3: send increments sequence.
    #[test]
    fn sm2_3_send_sequence() {
        let mut m = mux();
        m.open_stream(1).unwrap();
        let seq0 = m.send(1, vec![1]).unwrap();
        let seq1 = m.send(1, vec![2]).unwrap();
        assert_eq!(seq0, 0);
        assert_eq!(seq1, 1);
    }

    // SM2_4: recv retrieves data in order.
    #[test]
    fn sm2_4_recv_ordered() {
        let mut m = mux();
        m.open_stream(1).unwrap();
        m.send(1, vec![1, 2]).unwrap();
        m.send(1, vec![3, 4]).unwrap();
        assert_eq!(m.recv(1).unwrap(), Some(vec![1, 2]));
        assert_eq!(m.recv(1).unwrap(), Some(vec![3, 4]));
    }

    // SM2_5: recv returns None when queue is empty.
    #[test]
    fn sm2_5_recv_empty() {
        let mut m = mux();
        m.open_stream(1).unwrap();
        assert_eq!(m.recv(1).unwrap(), None);
    }

    // SM2_6: backpressure at max_queue_depth.
    #[test]
    fn sm2_6_backpressure() {
        let mut m = StreamMuxV2::new(1, 2);
        m.open_stream(1).unwrap();
        m.send(1, vec![0]).unwrap();
        m.send(1, vec![0]).unwrap();
        assert_eq!(m.send(1, vec![0]), Err(MuxError::Backpressure));
    }

    // SM2_7: close_stream prevents further sends.
    #[test]
    fn sm2_7_close_stream() {
        let mut m = mux();
        m.open_stream(1).unwrap();
        m.close_stream(1).unwrap();
        assert_eq!(m.send(1, vec![1]), Err(MuxError::StreamClosed));
    }

    // SM2_8: destroy_stream removes it.
    #[test]
    fn sm2_8_destroy_stream() {
        let mut m = mux();
        m.open_stream(1).unwrap();
        m.destroy_stream(1).unwrap();
        assert_eq!(m.stream_state(1), None);
    }

    // SM2_9: multiple streams are independent.
    #[test]
    fn sm2_9_independent_streams() {
        let mut m = mux();
        m.open_stream(1).unwrap();
        m.open_stream(2).unwrap();
        m.send(1, vec![0xAA]).unwrap();
        assert_eq!(m.recv(2).unwrap(), None); // stream 2 queue empty
        assert_eq!(m.recv(1).unwrap(), Some(vec![0xAA]));
    }

    // SM2_10: total_bytes_sent accumulates across streams.
    #[test]
    fn sm2_10_total_bytes() {
        let mut m = mux();
        m.open_stream(1).unwrap();
        m.open_stream(2).unwrap();
        m.send(1, vec![0; 100]).unwrap();
        m.send(2, vec![0; 50]).unwrap();
        assert_eq!(m.total_bytes_sent(), 150);
    }
}
