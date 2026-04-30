//! Cell reassembler — reconstructs ordered byte streams from fragmented cells.

use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReassemblyError {
    DuplicateSequence,
    BufferFull,
}

pub struct CellReassembler {
    next_seq: u64,
    out_of_order: BTreeMap<u64, Vec<u8>>,
    reassembled: VecDeque<Vec<u8>>,
    capacity: usize,
    total_bytes: u64,
    total_gaps: u64,
}

impl CellReassembler {
    pub fn new(capacity: usize) -> Self {
        Self {
            next_seq: 0,
            out_of_order: BTreeMap::new(),
            reassembled: VecDeque::new(),
            capacity,
            total_bytes: 0,
            total_gaps: 0,
        }
    }

    pub fn push(&mut self, seq: u64, data: Vec<u8>) -> Result<(), ReassemblyError> {
        if self.out_of_order.len() >= self.capacity {
            return Err(ReassemblyError::BufferFull);
        }
        if seq < self.next_seq {
            return Err(ReassemblyError::DuplicateSequence);
        }
        if seq == self.next_seq {
            self.total_bytes += data.len() as u64;
            self.reassembled.push_back(data);
            self.next_seq += 1;
            self.flush_ordered();
        } else {
            if self.out_of_order.contains_key(&seq) {
                return Err(ReassemblyError::DuplicateSequence);
            }
            self.total_gaps += 1;
            self.out_of_order.insert(seq, data);
        }
        Ok(())
    }

    fn flush_ordered(&mut self) {
        while let Some(data) = self.out_of_order.remove(&self.next_seq) {
            self.total_bytes += data.len() as u64;
            self.reassembled.push_back(data);
            self.next_seq += 1;
        }
    }

    pub fn pop(&mut self) -> Option<Vec<u8>> {
        self.reassembled.pop_front()
    }

    pub fn pending(&self) -> usize {
        self.out_of_order.len()
    }

    pub fn ready(&self) -> usize {
        self.reassembled.len()
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
    pub fn total_gaps(&self) -> u64 {
        self.total_gaps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CR1: in-order push produces ready data.
    #[test]
    fn cr1_in_order() {
        let mut r = CellReassembler::new(64);
        r.push(0, vec![1, 2, 3]).unwrap();
        assert_eq!(r.ready(), 1);
        assert_eq!(r.pop(), Some(vec![1, 2, 3]));
    }

    // CR2: out-of-order buffered until gap fills.
    #[test]
    fn cr2_out_of_order() {
        let mut r = CellReassembler::new(64);
        r.push(1, vec![2]).unwrap();
        assert_eq!(r.ready(), 0);
        r.push(0, vec![1]).unwrap();
        assert_eq!(r.ready(), 2);
    }

    // CR3: duplicate returns DuplicateSequence.
    #[test]
    fn cr3_duplicate() {
        let mut r = CellReassembler::new(64);
        r.push(0, vec![1]).unwrap();
        assert_eq!(r.push(0, vec![1]), Err(ReassemblyError::DuplicateSequence));
    }

    // CR4: buffer full returns BufferFull.
    #[test]
    fn cr4_buffer_full() {
        let mut r = CellReassembler::new(1);
        r.push(1, vec![1]).unwrap();
        assert_eq!(r.push(2, vec![2]), Err(ReassemblyError::BufferFull));
    }

    // CR5: total_bytes accumulates.
    #[test]
    fn cr5_total_bytes() {
        let mut r = CellReassembler::new(64);
        r.push(0, vec![1, 2]).unwrap();
        r.push(1, vec![3]).unwrap();
        assert_eq!(r.total_bytes(), 3);
    }

    // CR6: total_gaps counts out-of-order arrivals.
    #[test]
    fn cr6_total_gaps() {
        let mut r = CellReassembler::new(64);
        r.push(2, vec![]).unwrap();
        r.push(1, vec![]).unwrap();
        assert_eq!(r.total_gaps(), 2);
    }

    // CR7: pending returns out-of-order count.
    #[test]
    fn cr7_pending() {
        let mut r = CellReassembler::new(64);
        r.push(2, vec![]).unwrap();
        assert_eq!(r.pending(), 1);
    }

    // CR8: next_seq advances correctly.
    #[test]
    fn cr8_next_seq() {
        let mut r = CellReassembler::new(64);
        r.push(0, vec![]).unwrap();
        r.push(1, vec![]).unwrap();
        assert_eq!(r.next_seq(), 2);
    }

    // CR9: multi-gap fill produces correct order.
    #[test]
    fn cr9_multi_gap_fill() {
        let mut r = CellReassembler::new(64);
        r.push(2, vec![3]).unwrap();
        r.push(1, vec![2]).unwrap();
        r.push(0, vec![1]).unwrap();
        assert_eq!(r.pop(), Some(vec![1]));
        assert_eq!(r.pop(), Some(vec![2]));
        assert_eq!(r.pop(), Some(vec![3]));
    }

    // CR10: pop returns None on empty.
    #[test]
    fn cr10_pop_empty() {
        let mut r = CellReassembler::new(64);
        assert!(r.pop().is_none());
    }
}
