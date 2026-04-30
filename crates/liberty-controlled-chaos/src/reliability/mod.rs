//! Reliability layer — ACK tracking and retransmission for packet-loss-prone
//! transports.
//!
//! `ReliabilityEngine` keeps an in-flight window.  When the caller sends a
//! packet it registers a `PendingPacket` with a deadline epoch; when an ACK
//! arrives the packet is removed.  On `tick(epoch)` all expired in-flight
//! packets are moved to the retransmit queue if they have retries remaining,
//! or marked failed.

use std::collections::{HashMap, VecDeque};

// ---------------------------------------------------------------------------
// PendingPacket
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PendingPacket {
    pub sequence: u64,
    pub circuit_id: u64,
    pub data: Vec<u8>,
    pub deadline_epoch: u64,
    pub attempts: u32,
    pub max_attempts: u32,
}

// ---------------------------------------------------------------------------
// ReliabilityError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReliabilityError {
    DuplicateSequence,
    SequenceNotFound,
    MaxRetriesExceeded,
}

// ---------------------------------------------------------------------------
// ReliabilityEngine
// ---------------------------------------------------------------------------

pub struct ReliabilityEngine {
    in_flight: HashMap<u64, PendingPacket>,
    retransmit_queue: VecDeque<PendingPacket>,
    acked_count: u64,
    failed_count: u64,
    retransmit_count: u64,
    /// Epochs after send before a timeout fires.
    timeout_epochs: u64,
    default_max_attempts: u32,
}

impl ReliabilityEngine {
    pub fn new(timeout_epochs: u64, default_max_attempts: u32) -> Self {
        Self {
            in_flight: HashMap::new(),
            retransmit_queue: VecDeque::new(),
            acked_count: 0,
            failed_count: 0,
            retransmit_count: 0,
            timeout_epochs,
            default_max_attempts,
        }
    }

    /// Register a packet as in-flight at `epoch`.
    pub fn on_send(
        &mut self,
        sequence: u64,
        circuit_id: u64,
        data: Vec<u8>,
        epoch: u64,
    ) -> Result<(), ReliabilityError> {
        if self.in_flight.contains_key(&sequence) {
            return Err(ReliabilityError::DuplicateSequence);
        }
        self.in_flight.insert(
            sequence,
            PendingPacket {
                sequence,
                circuit_id,
                data,
                deadline_epoch: epoch + self.timeout_epochs,
                attempts: 1,
                max_attempts: self.default_max_attempts,
            },
        );
        Ok(())
    }

    /// Acknowledge a packet.
    pub fn on_ack(&mut self, sequence: u64) -> Result<(), ReliabilityError> {
        self.in_flight
            .remove(&sequence)
            .ok_or(ReliabilityError::SequenceNotFound)?;
        self.acked_count += 1;
        Ok(())
    }

    /// Advance time.  Timed-out in-flight packets become retransmissions or failures.
    pub fn tick(&mut self, epoch: u64) {
        let expired: Vec<u64> = self
            .in_flight
            .values()
            .filter(|p| epoch >= p.deadline_epoch)
            .map(|p| p.sequence)
            .collect();

        for seq in expired {
            let mut p = self.in_flight.remove(&seq).unwrap();
            if p.attempts < p.max_attempts {
                p.attempts += 1;
                p.deadline_epoch = epoch + self.timeout_epochs;
                self.retransmit_queue.push_back(p);
                self.retransmit_count += 1;
            } else {
                self.failed_count += 1;
            }
        }
    }

    /// Pop one packet from the retransmit queue.
    pub fn pop_retransmit(&mut self) -> Option<PendingPacket> {
        self.retransmit_queue.pop_front()
    }

    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    pub fn retransmit_queue_len(&self) -> usize {
        self.retransmit_queue.len()
    }

    pub fn acked_count(&self) -> u64 {
        self.acked_count
    }

    pub fn failed_count(&self) -> u64 {
        self.failed_count
    }

    pub fn retransmit_count(&self) -> u64 {
        self.retransmit_count
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> ReliabilityEngine {
        ReliabilityEngine::new(3, 2)
    }

    // RL1: on_send registers an in-flight packet.
    #[test]
    fn rl1_on_send() {
        let mut e = engine();
        e.on_send(1, 10, vec![0xAA], 0).unwrap();
        assert_eq!(e.in_flight_count(), 1);
    }

    // RL2: on_ack removes the in-flight packet.
    #[test]
    fn rl2_on_ack() {
        let mut e = engine();
        e.on_send(1, 10, vec![], 0).unwrap();
        e.on_ack(1).unwrap();
        assert_eq!(e.in_flight_count(), 0);
        assert_eq!(e.acked_count(), 1);
    }

    // RL3: duplicate sequence returns DuplicateSequence.
    #[test]
    fn rl3_duplicate_sequence() {
        let mut e = engine();
        e.on_send(1, 10, vec![], 0).unwrap();
        assert_eq!(
            e.on_send(1, 10, vec![], 0),
            Err(ReliabilityError::DuplicateSequence)
        );
    }

    // RL4: ack of unknown sequence returns SequenceNotFound.
    #[test]
    fn rl4_ack_unknown() {
        let mut e = engine();
        assert_eq!(e.on_ack(99), Err(ReliabilityError::SequenceNotFound));
    }

    // RL5: tick moves timed-out packet to retransmit queue.
    #[test]
    fn rl5_tick_retransmit() {
        let mut e = engine(); // timeout=3
        e.on_send(1, 10, vec![], 0).unwrap(); // deadline = epoch 3
        e.tick(3);
        assert_eq!(e.in_flight_count(), 0);
        assert_eq!(e.retransmit_queue_len(), 1);
    }

    // RL6: tick marks packet failed after max_attempts.
    #[test]
    fn rl6_max_retries_failed() {
        let mut e = ReliabilityEngine::new(1, 1); // max_attempts=1
        e.on_send(1, 10, vec![], 0).unwrap(); // deadline = epoch 1
        e.tick(1);
        assert_eq!(e.failed_count(), 1);
        assert_eq!(e.retransmit_queue_len(), 0);
    }

    // RL7: pop_retransmit returns packet.
    #[test]
    fn rl7_pop_retransmit() {
        let mut e = engine();
        e.on_send(1, 10, vec![42], 0).unwrap();
        e.tick(3);
        let p = e.pop_retransmit().unwrap();
        assert_eq!(p.sequence, 1);
        assert_eq!(p.data, vec![42]);
    }

    // RL8: tick does not expire packets before deadline.
    #[test]
    fn rl8_no_early_expiry() {
        let mut e = engine(); // timeout=3
        e.on_send(1, 10, vec![], 0).unwrap();
        e.tick(2); // epoch 2 < deadline 3
        assert_eq!(e.in_flight_count(), 1);
    }

    // RL9: retransmit_count increments on retransmit.
    #[test]
    fn rl9_retransmit_count() {
        let mut e = engine();
        e.on_send(1, 10, vec![], 0).unwrap();
        e.tick(3);
        assert_eq!(e.retransmit_count(), 1);
    }

    // RL10: multiple in-flight packets managed correctly.
    #[test]
    fn rl10_multiple_packets() {
        let mut e = engine();
        for seq in 1..=5 {
            e.on_send(seq, 10, vec![], 0).unwrap();
        }
        e.on_ack(3).unwrap();
        assert_eq!(e.in_flight_count(), 4);
        assert_eq!(e.acked_count(), 1);
    }
}
