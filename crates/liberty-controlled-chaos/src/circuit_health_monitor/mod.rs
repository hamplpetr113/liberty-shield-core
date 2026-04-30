//! Circuit health monitor — tracks per-circuit quality metrics and flags
//! unhealthy circuits for replacement.
//!
//! Metrics per circuit:
//! - RTT: running EWMA (α = 0.2), milliseconds.
//! - Packet loss: ratio of lost to total packets.
//! - Throughput: bytes per epoch (EWMA, α = 0.2).
//!
//! Health score: `0.4*(1-loss) + 0.4*(1/(1+rtt/100)) + 0.2*(throughput/max_throughput)`
//! A circuit with score < `replacement_threshold` is flagged.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// CircuitHealth
// ---------------------------------------------------------------------------

/// Health snapshot for a single circuit.
#[derive(Debug, Clone)]
pub struct CircuitHealth {
    pub circuit_id: u64,
    /// Smoothed RTT in milliseconds.
    pub rtt_ms: f64,
    /// Smoothed packet loss rate [0.0, 1.0].
    pub loss_rate: f64,
    /// Smoothed throughput in bytes/epoch.
    pub throughput_bpe: f64,
    /// Composite health score [0.0, 1.0].
    pub health_score: f64,
    /// Number of samples collected.
    pub samples: u64,
}

impl CircuitHealth {
    fn new(circuit_id: u64) -> Self {
        Self {
            circuit_id,
            rtt_ms: 100.0,
            loss_rate: 0.0,
            throughput_bpe: 0.0,
            health_score: 1.0,
            samples: 0,
        }
    }

    fn recompute(&mut self, max_throughput: f64) {
        let rtt_factor = 1.0 / (1.0 + self.rtt_ms / 100.0);
        let loss_factor = 1.0 - self.loss_rate;
        let tput_factor = if max_throughput > 0.0 {
            (self.throughput_bpe / max_throughput).min(1.0)
        } else {
            0.0
        };
        self.health_score =
            (0.4 * loss_factor + 0.4 * rtt_factor + 0.2 * tput_factor).clamp(0.0, 1.0);
    }
}

// ---------------------------------------------------------------------------
// HealthMonitor
// ---------------------------------------------------------------------------

/// Monitors health of multiple circuits.
pub struct HealthMonitor {
    circuits: HashMap<u64, CircuitHealth>,
    /// Score below which a circuit is flagged for replacement.
    replacement_threshold: f64,
    /// Expected maximum bytes/epoch (for normalising throughput score).
    max_throughput: f64,
}

impl HealthMonitor {
    pub fn new(replacement_threshold: f64, max_throughput: f64) -> Self {
        Self {
            circuits: HashMap::new(),
            replacement_threshold,
            max_throughput,
        }
    }

    /// Register a new circuit.
    pub fn add_circuit(&mut self, circuit_id: u64) {
        self.circuits
            .entry(circuit_id)
            .or_insert_with(|| CircuitHealth::new(circuit_id));
    }

    /// Remove a circuit.
    pub fn remove_circuit(&mut self, circuit_id: u64) {
        self.circuits.remove(&circuit_id);
    }

    /// Record an RTT sample.
    pub fn record_rtt(&mut self, circuit_id: u64, rtt_ms: f64) {
        if let Some(h) = self.circuits.get_mut(&circuit_id) {
            h.rtt_ms = 0.8 * h.rtt_ms + 0.2 * rtt_ms;
            h.samples += 1;
            h.recompute(self.max_throughput);
        }
    }

    /// Record a loss event (packet_lost=true) or success (false).
    pub fn record_loss(&mut self, circuit_id: u64, packet_lost: bool) {
        if let Some(h) = self.circuits.get_mut(&circuit_id) {
            let sample = if packet_lost { 1.0 } else { 0.0 };
            h.loss_rate = 0.9 * h.loss_rate + 0.1 * sample;
            h.samples += 1;
            h.recompute(self.max_throughput);
        }
    }

    /// Record bytes transferred in an epoch.
    pub fn record_throughput(&mut self, circuit_id: u64, bytes: f64) {
        if let Some(h) = self.circuits.get_mut(&circuit_id) {
            h.throughput_bpe = 0.8 * h.throughput_bpe + 0.2 * bytes;
            h.samples += 1;
            h.recompute(self.max_throughput);
        }
    }

    /// Get health snapshot.
    pub fn health(&self, circuit_id: u64) -> Option<&CircuitHealth> {
        self.circuits.get(&circuit_id)
    }

    /// Return IDs of circuits below the replacement threshold.
    pub fn unhealthy_circuits(&self) -> Vec<u64> {
        self.circuits
            .values()
            .filter(|h| h.health_score < self.replacement_threshold)
            .map(|h| h.circuit_id)
            .collect()
    }

    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mon() -> HealthMonitor {
        HealthMonitor::new(0.5, 10_000.0)
    }

    // CHM1: add_circuit creates a circuit with default health.
    #[test]
    fn chm1_add_circuit() {
        let mut m = mon();
        m.add_circuit(1);
        let h = m.health(1).unwrap();
        assert!((h.health_score - 1.0).abs() < 0.01);
    }

    // CHM2: record_rtt reduces health score for high RTT.
    #[test]
    fn chm2_rtt_degrades_health() {
        let mut m = mon();
        m.add_circuit(1);
        for _ in 0..20 {
            m.record_rtt(1, 5000.0); // very high RTT
        }
        assert!(m.health(1).unwrap().health_score < 0.9);
    }

    // CHM3: record_loss increases loss_rate.
    #[test]
    fn chm3_loss_degrades_health() {
        let mut m = mon();
        m.add_circuit(1);
        for _ in 0..20 {
            m.record_loss(1, true);
        }
        assert!(m.health(1).unwrap().loss_rate > 0.5);
    }

    // CHM4: record_throughput improves throughput score.
    #[test]
    fn chm4_throughput_improves_health() {
        let mut m = HealthMonitor::new(0.5, 1_000.0);
        m.add_circuit(1);
        for _ in 0..20 {
            m.record_throughput(1, 1_000.0);
        }
        // After convergence tput ≈ 1000 = max_throughput → tput_factor ≈ 1.0
        assert!(m.health(1).unwrap().health_score > 0.6);
    }

    // CHM5: unhealthy_circuits returns failing circuits.
    #[test]
    fn chm5_unhealthy_detection() {
        let mut m = HealthMonitor::new(0.7, 10_000.0);
        m.add_circuit(1);
        m.add_circuit(2);
        for _ in 0..30 {
            m.record_rtt(1, 10_000.0);
            m.record_loss(1, true);
        }
        let bad = m.unhealthy_circuits();
        assert!(bad.contains(&1));
        assert!(!bad.contains(&2));
    }

    // CHM6: health score is clamped to [0, 1].
    #[test]
    fn chm6_score_clamped() {
        let mut m = mon();
        m.add_circuit(1);
        for _ in 0..100 {
            m.record_loss(1, true);
            m.record_rtt(1, 99_999.0);
        }
        let score = m.health(1).unwrap().health_score;
        assert!(score >= 0.0 && score <= 1.0);
    }

    // CHM7: remove_circuit removes the entry.
    #[test]
    fn chm7_remove_circuit() {
        let mut m = mon();
        m.add_circuit(1);
        m.remove_circuit(1);
        assert!(m.health(1).is_none());
    }

    // CHM8: samples counter increments on each recording.
    #[test]
    fn chm8_sample_counting() {
        let mut m = mon();
        m.add_circuit(1);
        m.record_rtt(1, 50.0);
        m.record_loss(1, false);
        m.record_throughput(1, 100.0);
        assert_eq!(m.health(1).unwrap().samples, 3);
    }

    // CHM9: no-op on record for unknown circuit.
    #[test]
    fn chm9_unknown_circuit_noop() {
        let mut m = mon();
        m.record_rtt(999, 100.0); // should not panic
        assert!(m.health(999).is_none());
    }

    // CHM10: healthy circuit not flagged even below threshold default.
    #[test]
    fn chm10_healthy_not_flagged() {
        let mut m = HealthMonitor::new(0.3, 10_000.0);
        m.add_circuit(1);
        assert!(m.unhealthy_circuits().is_empty());
    }

    // CHM11: add_circuit is idempotent.
    #[test]
    fn chm11_add_idempotent() {
        let mut m = mon();
        m.add_circuit(1);
        m.add_circuit(1);
        assert_eq!(m.circuit_count(), 1);
    }
}
