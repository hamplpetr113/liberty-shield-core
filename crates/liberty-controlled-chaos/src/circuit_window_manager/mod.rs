//! Circuit window manager — sliding-window ack/nack tracking per circuit.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowError {
    CircuitNotFound,
    AlreadyAcked,
    SeqOutOfWindow,
}

const DEFAULT_WINDOW: u32 = 128;

struct CircuitWindow {
    send_next: u64,
    ack_base: u64,
    window_size: u32,
    acked: u64,
    nacked: u64,
}

impl CircuitWindow {
    fn new(window_size: u32) -> Self {
        Self {
            send_next: 0,
            ack_base: 0,
            window_size,
            acked: 0,
            nacked: 0,
        }
    }

    fn next_seq(&mut self) -> Option<u64> {
        if self.send_next >= self.ack_base + self.window_size as u64 {
            return None;
        }
        let seq = self.send_next;
        self.send_next += 1;
        Some(seq)
    }

    fn ack(&mut self, seq: u64) -> Result<(), WindowError> {
        if seq < self.ack_base || seq >= self.send_next {
            return Err(WindowError::SeqOutOfWindow);
        }
        if seq == self.ack_base {
            self.ack_base += 1;
        }
        self.acked += 1;
        Ok(())
    }

    fn nack(&mut self, _seq: u64) {
        self.nacked += 1;
    }
}

pub struct CircuitWindowManager {
    circuits: HashMap<u64, CircuitWindow>,
}

impl CircuitWindowManager {
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
        }
    }

    pub fn register(&mut self, circuit_id: u64) {
        self.circuits
            .entry(circuit_id)
            .or_insert_with(|| CircuitWindow::new(DEFAULT_WINDOW));
    }

    pub fn register_with_window(&mut self, circuit_id: u64, window_size: u32) {
        self.circuits
            .insert(circuit_id, CircuitWindow::new(window_size));
    }

    pub fn next_seq(&mut self, circuit_id: u64) -> Result<Option<u64>, WindowError> {
        let w = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or(WindowError::CircuitNotFound)?;
        Ok(w.next_seq())
    }

    pub fn ack(&mut self, circuit_id: u64, seq: u64) -> Result<(), WindowError> {
        self.circuits
            .get_mut(&circuit_id)
            .ok_or(WindowError::CircuitNotFound)?
            .ack(seq)
    }

    pub fn nack(&mut self, circuit_id: u64, seq: u64) -> Result<(), WindowError> {
        let w = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or(WindowError::CircuitNotFound)?;
        w.nack(seq);
        Ok(())
    }

    pub fn acked(&self, circuit_id: u64) -> Option<u64> {
        self.circuits.get(&circuit_id).map(|w| w.acked)
    }

    pub fn nacked(&self, circuit_id: u64) -> Option<u64> {
        self.circuits.get(&circuit_id).map(|w| w.nacked)
    }

    pub fn ack_base(&self, circuit_id: u64) -> Option<u64> {
        self.circuits.get(&circuit_id).map(|w| w.ack_base)
    }

    pub fn remove(&mut self, circuit_id: u64) {
        self.circuits.remove(&circuit_id);
    }

    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }
}

impl Default for CircuitWindowManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CWM1: next_seq returns sequential values.
    #[test]
    fn cwm1_next_seq() {
        let mut m = CircuitWindowManager::new();
        m.register(1);
        assert_eq!(m.next_seq(1).unwrap(), Some(0));
        assert_eq!(m.next_seq(1).unwrap(), Some(1));
    }

    // CWM2: window exhaustion returns None.
    #[test]
    fn cwm2_window_exhausted() {
        let mut m = CircuitWindowManager::new();
        m.register_with_window(1, 2);
        m.next_seq(1).unwrap();
        m.next_seq(1).unwrap();
        assert_eq!(m.next_seq(1).unwrap(), None);
    }

    // CWM3: ack advances ack_base.
    #[test]
    fn cwm3_ack_base() {
        let mut m = CircuitWindowManager::new();
        m.register(1);
        m.next_seq(1).unwrap();
        m.ack(1, 0).unwrap();
        assert_eq!(m.ack_base(1), Some(1));
    }

    // CWM4: ack out of window returns SeqOutOfWindow.
    #[test]
    fn cwm4_ack_out_of_window() {
        let mut m = CircuitWindowManager::new();
        m.register(1);
        assert_eq!(m.ack(1, 100), Err(WindowError::SeqOutOfWindow));
    }

    // CWM5: acked counter increments.
    #[test]
    fn cwm5_acked_counter() {
        let mut m = CircuitWindowManager::new();
        m.register(1);
        m.next_seq(1).unwrap();
        m.next_seq(1).unwrap();
        m.ack(1, 0).unwrap();
        m.ack(1, 1).unwrap();
        assert_eq!(m.acked(1), Some(2));
    }

    // CWM6: nack increments nacked counter.
    #[test]
    fn cwm6_nacked_counter() {
        let mut m = CircuitWindowManager::new();
        m.register(1);
        m.nack(1, 0).unwrap();
        assert_eq!(m.nacked(1), Some(1));
    }

    // CWM7: unknown circuit returns CircuitNotFound.
    #[test]
    fn cwm7_not_found() {
        let mut m = CircuitWindowManager::new();
        assert_eq!(m.next_seq(99), Err(WindowError::CircuitNotFound));
    }

    // CWM8: remove circuit.
    #[test]
    fn cwm8_remove() {
        let mut m = CircuitWindowManager::new();
        m.register(1);
        m.remove(1);
        assert_eq!(m.circuit_count(), 0);
    }

    // CWM9: ack expands window after advancing ack_base.
    #[test]
    fn cwm9_window_expansion() {
        let mut m = CircuitWindowManager::new();
        m.register_with_window(1, 1);
        m.next_seq(1).unwrap(); // seq 0
        assert_eq!(m.next_seq(1).unwrap(), None); // window full
        m.ack(1, 0).unwrap(); // advances base
        assert_eq!(m.next_seq(1).unwrap(), Some(1)); // window open again
    }

    // CWM10: circuit_count correct.
    #[test]
    fn cwm10_circuit_count() {
        let mut m = CircuitWindowManager::new();
        m.register(1);
        m.register(2);
        assert_eq!(m.circuit_count(), 2);
    }
}
