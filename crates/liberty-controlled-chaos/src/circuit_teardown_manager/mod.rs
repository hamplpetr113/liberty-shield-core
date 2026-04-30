//! Circuit teardown manager — tracks graceful teardown state per circuit.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownState {
    Active,
    DrainPending,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownError {
    CircuitNotFound,
    AlreadyClosed,
    InvalidTransition,
}

#[derive(Debug, Clone)]
struct CircuitTeardown {
    state: TeardownState,
    closed_epoch: Option<u64>,
}

pub struct CircuitTeardownManager {
    circuits: HashMap<u64, CircuitTeardown>,
    total_closed: u64,
}

impl CircuitTeardownManager {
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
            total_closed: 0,
        }
    }

    pub fn register(&mut self, circuit_id: u64, _epoch: u64) {
        self.circuits.insert(
            circuit_id,
            CircuitTeardown {
                state: TeardownState::Active,
                closed_epoch: None,
            },
        );
    }

    pub fn initiate_drain(&mut self, circuit_id: u64) -> Result<(), TeardownError> {
        let td = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or(TeardownError::CircuitNotFound)?;
        if td.state != TeardownState::Active {
            return Err(TeardownError::InvalidTransition);
        }
        td.state = TeardownState::DrainPending;
        Ok(())
    }

    pub fn advance_closing(&mut self, circuit_id: u64) -> Result<(), TeardownError> {
        let td = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or(TeardownError::CircuitNotFound)?;
        if td.state != TeardownState::DrainPending {
            return Err(TeardownError::InvalidTransition);
        }
        td.state = TeardownState::Closing;
        Ok(())
    }

    pub fn close(&mut self, circuit_id: u64, epoch: u64) -> Result<(), TeardownError> {
        let td = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or(TeardownError::CircuitNotFound)?;
        if td.state == TeardownState::Closed {
            return Err(TeardownError::AlreadyClosed);
        }
        td.state = TeardownState::Closed;
        td.closed_epoch = Some(epoch);
        self.total_closed += 1;
        Ok(())
    }

    pub fn state(&self, circuit_id: u64) -> Option<TeardownState> {
        self.circuits.get(&circuit_id).map(|td| td.state)
    }

    pub fn is_closed(&self, circuit_id: u64) -> bool {
        self.circuits
            .get(&circuit_id)
            .map(|td| td.state == TeardownState::Closed)
            .unwrap_or(false)
    }

    pub fn purge_closed(&mut self) -> usize {
        let before = self.circuits.len();
        self.circuits
            .retain(|_, td| td.state != TeardownState::Closed);
        before - self.circuits.len()
    }

    pub fn total_closed(&self) -> u64 {
        self.total_closed
    }

    pub fn active_count(&self) -> usize {
        self.circuits
            .values()
            .filter(|td| td.state != TeardownState::Closed)
            .count()
    }
}

impl Default for CircuitTeardownManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CTM1: freshly registered circuit is Active.
    #[test]
    fn ctm1_register_active() {
        let mut m = CircuitTeardownManager::new();
        m.register(1, 0);
        assert_eq!(m.state(1), Some(TeardownState::Active));
    }

    // CTM2: initiate_drain moves to DrainPending.
    #[test]
    fn ctm2_drain_pending() {
        let mut m = CircuitTeardownManager::new();
        m.register(1, 0);
        m.initiate_drain(1).unwrap();
        assert_eq!(m.state(1), Some(TeardownState::DrainPending));
    }

    // CTM3: advance_closing moves to Closing.
    #[test]
    fn ctm3_closing() {
        let mut m = CircuitTeardownManager::new();
        m.register(1, 0);
        m.initiate_drain(1).unwrap();
        m.advance_closing(1).unwrap();
        assert_eq!(m.state(1), Some(TeardownState::Closing));
    }

    // CTM4: close marks as Closed.
    #[test]
    fn ctm4_close() {
        let mut m = CircuitTeardownManager::new();
        m.register(1, 0);
        m.close(1, 5).unwrap();
        assert!(m.is_closed(1));
    }

    // CTM5: double close returns AlreadyClosed.
    #[test]
    fn ctm5_double_close() {
        let mut m = CircuitTeardownManager::new();
        m.register(1, 0);
        m.close(1, 5).unwrap();
        assert_eq!(m.close(1, 6), Err(TeardownError::AlreadyClosed));
    }

    // CTM6: invalid transition returns InvalidTransition.
    #[test]
    fn ctm6_invalid_transition() {
        let mut m = CircuitTeardownManager::new();
        m.register(1, 0);
        assert_eq!(m.advance_closing(1), Err(TeardownError::InvalidTransition));
    }

    // CTM7: total_closed increments.
    #[test]
    fn ctm7_total_closed() {
        let mut m = CircuitTeardownManager::new();
        m.register(1, 0);
        m.register(2, 0);
        m.close(1, 1).unwrap();
        m.close(2, 1).unwrap();
        assert_eq!(m.total_closed(), 2);
    }

    // CTM8: purge_closed removes closed circuits.
    #[test]
    fn ctm8_purge_closed() {
        let mut m = CircuitTeardownManager::new();
        m.register(1, 0);
        m.register(2, 0);
        m.close(1, 1).unwrap();
        let purged = m.purge_closed();
        assert_eq!(purged, 1);
        assert_eq!(m.active_count(), 1);
    }

    // CTM9: unknown circuit returns CircuitNotFound.
    #[test]
    fn ctm9_not_found() {
        let mut m = CircuitTeardownManager::new();
        assert_eq!(m.initiate_drain(99), Err(TeardownError::CircuitNotFound));
    }

    // CTM10: active_count only counts non-closed.
    #[test]
    fn ctm10_active_count() {
        let mut m = CircuitTeardownManager::new();
        m.register(1, 0);
        m.register(2, 0);
        m.register(3, 0);
        m.close(1, 1).unwrap();
        assert_eq!(m.active_count(), 2);
    }
}
