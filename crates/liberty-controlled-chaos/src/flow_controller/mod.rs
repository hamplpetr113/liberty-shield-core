//! Flow controller — per-circuit send-window with credit-based backpressure.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowError {
    CircuitNotFound,
    WindowExhausted,
    OverCredit,
}

struct Window {
    capacity: u32,
    available: u32,
    sent: u64,
    acked: u64,
}

impl Window {
    fn new(capacity: u32) -> Self {
        Self {
            capacity,
            available: capacity,
            sent: 0,
            acked: 0,
        }
    }

    fn consume(&mut self, cells: u32) -> Result<(), FlowError> {
        if cells > self.available {
            return Err(FlowError::WindowExhausted);
        }
        self.available -= cells;
        self.sent += cells as u64;
        Ok(())
    }

    fn replenish(&mut self, cells: u32) -> Result<(), FlowError> {
        let new = self.available.saturating_add(cells);
        if new > self.capacity {
            return Err(FlowError::OverCredit);
        }
        self.available = new;
        self.acked += cells as u64;
        Ok(())
    }
}

pub struct FlowController {
    default_window: u32,
    circuits: HashMap<u64, Window>,
}

impl FlowController {
    pub fn new(default_window: u32) -> Self {
        Self {
            default_window,
            circuits: HashMap::new(),
        }
    }

    pub fn register(&mut self, circuit_id: u64) {
        self.circuits
            .entry(circuit_id)
            .or_insert_with(|| Window::new(self.default_window));
    }

    pub fn register_with_window(&mut self, circuit_id: u64, window: u32) {
        self.circuits.insert(circuit_id, Window::new(window));
    }

    pub fn remove(&mut self, circuit_id: u64) {
        self.circuits.remove(&circuit_id);
    }

    pub fn consume(&mut self, circuit_id: u64, cells: u32) -> Result<(), FlowError> {
        self.circuits
            .get_mut(&circuit_id)
            .ok_or(FlowError::CircuitNotFound)?
            .consume(cells)
    }

    pub fn replenish(&mut self, circuit_id: u64, cells: u32) -> Result<(), FlowError> {
        self.circuits
            .get_mut(&circuit_id)
            .ok_or(FlowError::CircuitNotFound)?
            .replenish(cells)
    }

    pub fn available(&self, circuit_id: u64) -> Option<u32> {
        self.circuits.get(&circuit_id).map(|w| w.available)
    }

    pub fn sent(&self, circuit_id: u64) -> Option<u64> {
        self.circuits.get(&circuit_id).map(|w| w.sent)
    }

    pub fn acked(&self, circuit_id: u64) -> Option<u64> {
        self.circuits.get(&circuit_id).map(|w| w.acked)
    }

    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FC1: consume reduces available window.
    #[test]
    fn fc1_consume_reduces_window() {
        let mut fc = FlowController::new(10);
        fc.register(1);
        fc.consume(1, 3).unwrap();
        assert_eq!(fc.available(1), Some(7));
    }

    // FC2: replenish increases available window.
    #[test]
    fn fc2_replenish() {
        let mut fc = FlowController::new(10);
        fc.register(1);
        fc.consume(1, 5).unwrap();
        fc.replenish(1, 3).unwrap();
        assert_eq!(fc.available(1), Some(8));
    }

    // FC3: exhausted window returns WindowExhausted.
    #[test]
    fn fc3_window_exhausted() {
        let mut fc = FlowController::new(2);
        fc.register(1);
        fc.consume(1, 2).unwrap();
        assert_eq!(fc.consume(1, 1), Err(FlowError::WindowExhausted));
    }

    // FC4: over-credit returns OverCredit.
    #[test]
    fn fc4_over_credit() {
        let mut fc = FlowController::new(5);
        fc.register(1);
        assert_eq!(fc.replenish(1, 1), Err(FlowError::OverCredit));
    }

    // FC5: unknown circuit returns CircuitNotFound.
    #[test]
    fn fc5_not_found() {
        let mut fc = FlowController::new(10);
        assert_eq!(fc.consume(99, 1), Err(FlowError::CircuitNotFound));
    }

    // FC6: sent counter increments.
    #[test]
    fn fc6_sent_counter() {
        let mut fc = FlowController::new(10);
        fc.register(1);
        fc.consume(1, 3).unwrap();
        fc.consume(1, 2).unwrap();
        assert_eq!(fc.sent(1), Some(5));
    }

    // FC7: acked counter increments on replenish.
    #[test]
    fn fc7_acked_counter() {
        let mut fc = FlowController::new(10);
        fc.register(1);
        fc.consume(1, 4).unwrap();
        fc.replenish(1, 2).unwrap();
        assert_eq!(fc.acked(1), Some(2));
    }

    // FC8: remove circuit.
    #[test]
    fn fc8_remove() {
        let mut fc = FlowController::new(10);
        fc.register(1);
        fc.remove(1);
        assert_eq!(fc.circuit_count(), 0);
    }

    // FC9: custom window per circuit.
    #[test]
    fn fc9_custom_window() {
        let mut fc = FlowController::new(10);
        fc.register_with_window(1, 3);
        assert_eq!(fc.available(1), Some(3));
    }

    // FC10: multiple circuits are independent.
    #[test]
    fn fc10_independent_circuits() {
        let mut fc = FlowController::new(10);
        fc.register(1);
        fc.register(2);
        fc.consume(1, 5).unwrap();
        assert_eq!(fc.available(2), Some(10));
    }
}
