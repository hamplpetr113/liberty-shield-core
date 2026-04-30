//! Circuit metrics collector — aggregates per-circuit performance counters.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CircuitMetrics {
    pub circuit_id: u64,
    pub cells_sent: u64,
    pub cells_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub created_epoch: u64,
    pub last_active_epoch: u64,
    pub errors: u64,
}

impl CircuitMetrics {
    fn new(circuit_id: u64, epoch: u64) -> Self {
        Self {
            circuit_id,
            cells_sent: 0,
            cells_recv: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            created_epoch: epoch,
            last_active_epoch: epoch,
            errors: 0,
        }
    }

    pub fn age(&self, current_epoch: u64) -> u64 {
        current_epoch.saturating_sub(self.created_epoch)
    }

    pub fn idle_epochs(&self, current_epoch: u64) -> u64 {
        current_epoch.saturating_sub(self.last_active_epoch)
    }
}

pub struct CircuitMetricsCollector {
    circuits: HashMap<u64, CircuitMetrics>,
    idle_evict_threshold: u64,
    evicted: u64,
}

impl CircuitMetricsCollector {
    pub fn new(idle_evict_threshold: u64) -> Self {
        Self {
            circuits: HashMap::new(),
            idle_evict_threshold,
            evicted: 0,
        }
    }

    pub fn register(&mut self, circuit_id: u64, epoch: u64) {
        self.circuits
            .entry(circuit_id)
            .or_insert_with(|| CircuitMetrics::new(circuit_id, epoch));
    }

    pub fn record_sent(&mut self, circuit_id: u64, bytes: u64, epoch: u64) {
        if let Some(m) = self.circuits.get_mut(&circuit_id) {
            m.cells_sent += 1;
            m.bytes_sent += bytes;
            m.last_active_epoch = epoch;
        }
    }

    pub fn record_recv(&mut self, circuit_id: u64, bytes: u64, epoch: u64) {
        if let Some(m) = self.circuits.get_mut(&circuit_id) {
            m.cells_recv += 1;
            m.bytes_recv += bytes;
            m.last_active_epoch = epoch;
        }
    }

    pub fn record_error(&mut self, circuit_id: u64) {
        if let Some(m) = self.circuits.get_mut(&circuit_id) {
            m.errors += 1;
        }
    }

    pub fn get(&self, circuit_id: u64) -> Option<&CircuitMetrics> {
        self.circuits.get(&circuit_id)
    }

    pub fn evict_idle(&mut self, current_epoch: u64) -> usize {
        let threshold = self.idle_evict_threshold;
        let before = self.circuits.len();
        self.circuits
            .retain(|_, m| m.idle_epochs(current_epoch) < threshold);
        let evicted = before - self.circuits.len();
        self.evicted += evicted as u64;
        evicted
    }

    pub fn remove(&mut self, circuit_id: u64) {
        self.circuits.remove(&circuit_id);
    }

    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    pub fn total_evicted(&self) -> u64 {
        self.evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CMC1: register creates entry.
    #[test]
    fn cmc1_register() {
        let mut c = CircuitMetricsCollector::new(100);
        c.register(1, 0);
        assert!(c.get(1).is_some());
    }

    // CMC2: record_sent increments counters.
    #[test]
    fn cmc2_record_sent() {
        let mut c = CircuitMetricsCollector::new(100);
        c.register(1, 0);
        c.record_sent(1, 512, 1);
        let m = c.get(1).unwrap();
        assert_eq!(m.cells_sent, 1);
        assert_eq!(m.bytes_sent, 512);
    }

    // CMC3: record_recv increments counters.
    #[test]
    fn cmc3_record_recv() {
        let mut c = CircuitMetricsCollector::new(100);
        c.register(1, 0);
        c.record_recv(1, 256, 1);
        assert_eq!(c.get(1).unwrap().bytes_recv, 256);
    }

    // CMC4: record_error increments error count.
    #[test]
    fn cmc4_record_error() {
        let mut c = CircuitMetricsCollector::new(100);
        c.register(1, 0);
        c.record_error(1);
        assert_eq!(c.get(1).unwrap().errors, 1);
    }

    // CMC5: age computes correctly.
    #[test]
    fn cmc5_age() {
        let mut c = CircuitMetricsCollector::new(100);
        c.register(1, 10);
        assert_eq!(c.get(1).unwrap().age(15), 5);
    }

    // CMC6: idle_epochs computed from last_active.
    #[test]
    fn cmc6_idle_epochs() {
        let mut c = CircuitMetricsCollector::new(100);
        c.register(1, 0);
        c.record_sent(1, 100, 5);
        assert_eq!(c.get(1).unwrap().idle_epochs(10), 5);
    }

    // CMC7: evict_idle removes stale circuits.
    #[test]
    fn cmc7_evict_idle() {
        let mut c = CircuitMetricsCollector::new(5);
        c.register(1, 0);
        c.register(2, 0);
        c.record_sent(2, 100, 16); // active at epoch 16 → idle 4 epochs at epoch 20
        let evicted = c.evict_idle(20); // circuit 1 idle 20 epochs, circuit 2 only 4
        assert_eq!(evicted, 1);
    }

    // CMC8: remove deletes circuit.
    #[test]
    fn cmc8_remove() {
        let mut c = CircuitMetricsCollector::new(100);
        c.register(1, 0);
        c.remove(1);
        assert_eq!(c.circuit_count(), 0);
    }

    // CMC9: total_evicted accumulates.
    #[test]
    fn cmc9_total_evicted() {
        let mut c = CircuitMetricsCollector::new(3);
        c.register(1, 0);
        c.evict_idle(10);
        assert_eq!(c.total_evicted(), 1);
    }

    // CMC10: record on unknown circuit is no-op.
    #[test]
    fn cmc10_unknown_noop() {
        let mut c = CircuitMetricsCollector::new(100);
        c.record_sent(99, 100, 1); // no panic
        assert_eq!(c.circuit_count(), 0);
    }
}
