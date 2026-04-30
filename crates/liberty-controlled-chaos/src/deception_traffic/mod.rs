//! Deception traffic — generates fake circuit metadata and dummy relay cells
//! to increase traffic ambiguity.
//!
//! `DeceptionEngine` maintains a budget of deception bytes per epoch.  When
//! `generate_dummy_cells(epoch, count)` is called it returns dummy cells up to
//! the remaining budget and deducts their cost.

use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// DeceptionLevel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeceptionLevel {
    Low,
    Medium,
    High,
}

impl DeceptionLevel {
    pub fn budget_multiplier(&self) -> f64 {
        match self {
            DeceptionLevel::Low => 0.1,
            DeceptionLevel::Medium => 0.3,
            DeceptionLevel::High => 0.6,
        }
    }
}

// ---------------------------------------------------------------------------
// FakeCircuitRecord
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct FakeCircuitRecord {
    pub circuit_id: u64,
    pub guard_id: [u8; 32],
    pub relay_id: [u8; 32],
    pub exit_id: [u8; 32],
    pub created_epoch: u64,
}

// ---------------------------------------------------------------------------
// DummyCell
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DummyCell {
    pub circuit_id: u64,
    pub payload: Vec<u8>,
    pub epoch: u64,
}

// ---------------------------------------------------------------------------
// DeceptionEngine
// ---------------------------------------------------------------------------

pub struct DeceptionEngine {
    level: DeceptionLevel,
    /// Max real bytes per epoch (used to compute deception budget).
    real_traffic_estimate: u64,
    /// Remaining deception bytes for the current epoch.
    budget_remaining: u64,
    fake_circuits: VecDeque<FakeCircuitRecord>,
    next_fake_circuit_id: u64,
    total_dummy_cells: u64,
    current_epoch: u64,
}

impl DeceptionEngine {
    pub fn new(level: DeceptionLevel, real_traffic_estimate: u64) -> Self {
        let budget = Self::compute_budget(level, real_traffic_estimate);
        Self {
            level,
            real_traffic_estimate,
            budget_remaining: budget,
            fake_circuits: VecDeque::new(),
            next_fake_circuit_id: 0x8000_0000_0000_0000, // high bit set = fake
            total_dummy_cells: 0,
            current_epoch: 0,
        }
    }

    fn compute_budget(level: DeceptionLevel, real: u64) -> u64 {
        (real as f64 * level.budget_multiplier()) as u64
    }

    /// Create a fake circuit record.
    pub fn create_fake_circuit(
        &mut self,
        guard: [u8; 32],
        relay: [u8; 32],
        exit: [u8; 32],
    ) -> FakeCircuitRecord {
        let id = self.next_fake_circuit_id;
        self.next_fake_circuit_id = self.next_fake_circuit_id.wrapping_add(1);
        let record = FakeCircuitRecord {
            circuit_id: id,
            guard_id: guard,
            relay_id: relay,
            exit_id: exit,
            created_epoch: self.current_epoch,
        };
        self.fake_circuits.push_back(record.clone());
        record
    }

    /// Generate `count` dummy cells, limited by remaining budget.
    /// Each dummy cell costs `cell_size_bytes`.
    pub fn generate_dummy_cells(
        &mut self,
        circuit_id: u64,
        count: u64,
        cell_size_bytes: u64,
        epoch: u64,
    ) -> Vec<DummyCell> {
        let mut cells = Vec::new();
        for _ in 0..count {
            if self.budget_remaining < cell_size_bytes {
                break;
            }
            cells.push(DummyCell {
                circuit_id,
                payload: vec![0u8; cell_size_bytes as usize],
                epoch,
            });
            self.budget_remaining -= cell_size_bytes;
            self.total_dummy_cells += 1;
        }
        cells
    }

    /// Advance epoch and refresh the budget.
    pub fn advance_epoch(&mut self, epoch: u64) {
        self.current_epoch = epoch;
        self.budget_remaining = Self::compute_budget(self.level, self.real_traffic_estimate);
    }

    pub fn set_level(&mut self, level: DeceptionLevel) {
        self.level = level;
        self.budget_remaining = Self::compute_budget(level, self.real_traffic_estimate);
    }

    pub fn fake_circuit_count(&self) -> usize {
        self.fake_circuits.len()
    }

    pub fn budget_remaining(&self) -> u64 {
        self.budget_remaining
    }

    pub fn total_dummy_cells(&self) -> u64 {
        self.total_dummy_cells
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

    // DT1: create_fake_circuit returns a record.
    #[test]
    fn dt1_fake_circuit() {
        let mut e = DeceptionEngine::new(DeceptionLevel::Medium, 10_000);
        let r = e.create_fake_circuit(nid(1), nid(2), nid(3));
        assert!(r.circuit_id >= 0x8000_0000_0000_0000);
    }

    // DT2: generate_dummy_cells returns cells up to budget.
    #[test]
    fn dt2_generate_cells() {
        let mut e = DeceptionEngine::new(DeceptionLevel::Medium, 10_000);
        let cells = e.generate_dummy_cells(1, 5, 100, 0);
        assert!(!cells.is_empty());
    }

    // DT3: budget limits dummy cell generation.
    #[test]
    fn dt3_budget_limits_cells() {
        let mut e = DeceptionEngine::new(DeceptionLevel::Low, 1000); // budget = 100
        let cells = e.generate_dummy_cells(1, 1000, 200, 0); // 200 bytes each
        assert!(cells.len() <= 1); // 100 / 200 = 0 cells (budget exhausted immediately)
    }

    // DT4: advance_epoch refreshes budget.
    #[test]
    fn dt4_advance_epoch_refreshes() {
        let mut e = DeceptionEngine::new(DeceptionLevel::Medium, 1000);
        e.generate_dummy_cells(1, 1000, 10, 0); // exhaust budget
        e.advance_epoch(1);
        assert!(e.budget_remaining() > 0);
    }

    // DT5: total_dummy_cells accumulates.
    #[test]
    fn dt5_total_dummy_cells() {
        let mut e = DeceptionEngine::new(DeceptionLevel::High, 100_000);
        e.generate_dummy_cells(1, 3, 10, 0);
        assert_eq!(e.total_dummy_cells(), 3);
    }

    // DT6: set_level changes budget.
    #[test]
    fn dt6_set_level() {
        let mut e = DeceptionEngine::new(DeceptionLevel::Low, 1000);
        let low_budget = e.budget_remaining();
        e.set_level(DeceptionLevel::High);
        assert!(e.budget_remaining() > low_budget);
    }

    // DT7: fake circuits are tracked.
    #[test]
    fn dt7_fake_circuit_tracked() {
        let mut e = DeceptionEngine::new(DeceptionLevel::Low, 1000);
        e.create_fake_circuit(nid(1), nid(2), nid(3));
        e.create_fake_circuit(nid(4), nid(5), nid(6));
        assert_eq!(e.fake_circuit_count(), 2);
    }

    // DT8: dummy cells have correct circuit_id.
    #[test]
    fn dt8_cell_circuit_id() {
        let mut e = DeceptionEngine::new(DeceptionLevel::High, 100_000);
        let cells = e.generate_dummy_cells(42, 1, 10, 0);
        assert_eq!(cells[0].circuit_id, 42);
    }

    // DT9: high level has largest budget multiplier.
    #[test]
    fn dt9_high_level_multiplier() {
        assert!(
            DeceptionLevel::High.budget_multiplier() > DeceptionLevel::Medium.budget_multiplier()
        );
    }

    // DT10: cells have correct epoch.
    #[test]
    fn dt10_cell_epoch() {
        let mut e = DeceptionEngine::new(DeceptionLevel::High, 100_000);
        let cells = e.generate_dummy_cells(1, 1, 10, 7);
        assert_eq!(cells[0].epoch, 7);
    }
}
