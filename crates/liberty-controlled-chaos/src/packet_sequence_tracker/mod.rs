//! Packet sequence tracker — per-stream ordered delivery with gap detection.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqError {
    StreamNotFound,
    Duplicate,
    OutOfWindow,
}

const WINDOW_SIZE: u64 = 256;

#[derive(Debug)]
struct StreamState {
    next_expected: u64,
    received_bitmap: u64,
    total_received: u64,
    total_gaps: u64,
    total_duplicates: u64,
}

impl StreamState {
    fn new() -> Self {
        Self {
            next_expected: 0,
            received_bitmap: 0,
            total_received: 0,
            total_gaps: 0,
            total_duplicates: 0,
        }
    }

    fn accept(&mut self, seq: u64) -> Result<(), SeqError> {
        if seq < self.next_expected {
            self.total_duplicates += 1;
            return Err(SeqError::Duplicate);
        }
        let offset = seq - self.next_expected;
        if offset >= WINDOW_SIZE {
            return Err(SeqError::OutOfWindow);
        }
        let bit = 1u64 << offset;
        if self.received_bitmap & bit != 0 {
            self.total_duplicates += 1;
            return Err(SeqError::Duplicate);
        }
        self.received_bitmap |= bit;
        self.total_received += 1;
        if offset > 0 {
            self.total_gaps += 1;
        }
        while self.received_bitmap & 1 != 0 {
            self.received_bitmap >>= 1;
            self.next_expected += 1;
        }
        Ok(())
    }
}

pub struct PacketSequenceTracker {
    streams: HashMap<u64, StreamState>,
}

impl PacketSequenceTracker {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    pub fn register_stream(&mut self, stream_id: u64) {
        self.streams
            .entry(stream_id)
            .or_insert_with(StreamState::new);
    }

    pub fn accept(&mut self, stream_id: u64, seq: u64) -> Result<(), SeqError> {
        self.streams
            .get_mut(&stream_id)
            .ok_or(SeqError::StreamNotFound)?
            .accept(seq)
    }

    pub fn next_expected(&self, stream_id: u64) -> Option<u64> {
        self.streams.get(&stream_id).map(|s| s.next_expected)
    }

    pub fn total_received(&self, stream_id: u64) -> Option<u64> {
        self.streams.get(&stream_id).map(|s| s.total_received)
    }

    pub fn total_gaps(&self, stream_id: u64) -> Option<u64> {
        self.streams.get(&stream_id).map(|s| s.total_gaps)
    }

    pub fn total_duplicates(&self, stream_id: u64) -> Option<u64> {
        self.streams.get(&stream_id).map(|s| s.total_duplicates)
    }

    pub fn remove_stream(&mut self, stream_id: u64) {
        self.streams.remove(&stream_id);
    }

    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}

impl Default for PacketSequenceTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // PST1: in-order delivery advances next_expected.
    #[test]
    fn pst1_in_order() {
        let mut t = PacketSequenceTracker::new();
        t.register_stream(1);
        t.accept(1, 0).unwrap();
        assert_eq!(t.next_expected(1), Some(1));
    }

    // PST2: duplicate returns Duplicate.
    #[test]
    fn pst2_duplicate() {
        let mut t = PacketSequenceTracker::new();
        t.register_stream(1);
        t.accept(1, 0).unwrap();
        assert_eq!(t.accept(1, 0), Err(SeqError::Duplicate));
    }

    // PST3: out-of-window returns OutOfWindow.
    #[test]
    fn pst3_out_of_window() {
        let mut t = PacketSequenceTracker::new();
        t.register_stream(1);
        assert_eq!(t.accept(1, 256), Err(SeqError::OutOfWindow));
    }

    // PST4: unknown stream returns StreamNotFound.
    #[test]
    fn pst4_stream_not_found() {
        let mut t = PacketSequenceTracker::new();
        assert_eq!(t.accept(99, 0), Err(SeqError::StreamNotFound));
    }

    // PST5: out-of-order fills gap on arrival.
    #[test]
    fn pst5_out_of_order_fill() {
        let mut t = PacketSequenceTracker::new();
        t.register_stream(1);
        t.accept(1, 1).unwrap(); // gap at 0
        t.accept(1, 0).unwrap(); // fills gap — next should advance to 2
        assert_eq!(t.next_expected(1), Some(2));
    }

    // PST6: total_received counts accepted packets.
    #[test]
    fn pst6_total_received() {
        let mut t = PacketSequenceTracker::new();
        t.register_stream(1);
        t.accept(1, 0).unwrap();
        t.accept(1, 1).unwrap();
        assert_eq!(t.total_received(1), Some(2));
    }

    // PST7: total_gaps counts out-of-order arrivals.
    #[test]
    fn pst7_gaps() {
        let mut t = PacketSequenceTracker::new();
        t.register_stream(1);
        t.accept(1, 2).unwrap(); // gap
        assert_eq!(t.total_gaps(1), Some(1));
    }

    // PST8: total_duplicates counts duplicate attempts.
    #[test]
    fn pst8_duplicates() {
        let mut t = PacketSequenceTracker::new();
        t.register_stream(1);
        t.accept(1, 0).unwrap();
        t.accept(1, 0).unwrap_err();
        assert_eq!(t.total_duplicates(1), Some(1));
    }

    // PST9: remove_stream clears state.
    #[test]
    fn pst9_remove_stream() {
        let mut t = PacketSequenceTracker::new();
        t.register_stream(1);
        t.remove_stream(1);
        assert_eq!(t.stream_count(), 0);
    }

    // PST10: multiple streams are independent.
    #[test]
    fn pst10_independent_streams() {
        let mut t = PacketSequenceTracker::new();
        t.register_stream(1);
        t.register_stream(2);
        t.accept(1, 0).unwrap();
        t.accept(1, 1).unwrap();
        assert_eq!(t.next_expected(2), Some(0));
    }
}
