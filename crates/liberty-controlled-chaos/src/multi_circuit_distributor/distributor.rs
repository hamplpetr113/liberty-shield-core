use super::types::{CircuitWeight, DistributionDecision, DistributionError, DistributionMode};

/// Distributes cells across multiple circuits without randomness.
///
/// Internal round-robin state is the only mutable state; all other selection
/// modes are pure functions of the input circuit list.
pub struct MultiCircuitDistributor {
    round_robin_index: usize,
}

impl MultiCircuitDistributor {
    pub fn new() -> Self {
        Self {
            round_robin_index: 0,
        }
    }

    /// Select a circuit according to `mode`.
    pub fn select_circuit(
        &mut self,
        circuits: &[CircuitWeight],
        mode: DistributionMode,
    ) -> Result<DistributionDecision, DistributionError> {
        if circuits.is_empty() {
            return Err(DistributionError::EmptyCircuitList);
        }
        match mode {
            DistributionMode::SingleCircuit => self.select_single(circuits),
            DistributionMode::RoundRobin => self.select_next_round_robin(circuits),
            DistributionMode::WeightedReliability => self.select_weighted(circuits),
            DistributionMode::ShadowOnly => self.select_shadow(circuits),
        }
    }

    /// Always picks the active circuit with the lowest `circuit_id`.
    fn select_single(
        &self,
        circuits: &[CircuitWeight],
    ) -> Result<DistributionDecision, DistributionError> {
        let active = Self::active_sorted(circuits);
        active
            .first()
            .map(|c| DistributionDecision {
                circuit_id: c.circuit_id,
                mode: DistributionMode::SingleCircuit,
            })
            .ok_or(DistributionError::NoEligibleCircuit)
    }

    /// Advances the internal index through active circuits sorted by `circuit_id`.
    pub fn select_next_round_robin(
        &mut self,
        circuits: &[CircuitWeight],
    ) -> Result<DistributionDecision, DistributionError> {
        let active = Self::active_sorted(circuits);
        if active.is_empty() {
            return Err(DistributionError::NoEligibleCircuit);
        }
        let idx = self.round_robin_index % active.len();
        let chosen = active[idx].circuit_id;
        self.round_robin_index = self.round_robin_index.wrapping_add(1);
        Ok(DistributionDecision {
            circuit_id: chosen,
            mode: DistributionMode::RoundRobin,
        })
    }

    /// Picks the active circuit with the highest `reliability_score`.
    /// Tie-break: lower `latency_estimate`, then lower `circuit_id`.
    pub fn select_weighted(
        &self,
        circuits: &[CircuitWeight],
    ) -> Result<DistributionDecision, DistributionError> {
        let active = Self::active_sorted(circuits);
        active
            .iter()
            .max_by(|a, b| {
                a.reliability_score
                    .partial_cmp(&b.reliability_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.latency_estimate.cmp(&a.latency_estimate)) // lower latency wins
                    .then_with(|| b.circuit_id.0.cmp(&a.circuit_id.0)) // lower id wins
            })
            .map(|c| DistributionDecision {
                circuit_id: c.circuit_id,
                mode: DistributionMode::WeightedReliability,
            })
            .ok_or(DistributionError::NoEligibleCircuit)
    }

    /// Shadow-only selection: picks the first active circuit, same as
    /// `SingleCircuit` but explicitly restricted to `is_active == true`.
    fn select_shadow(
        &self,
        circuits: &[CircuitWeight],
    ) -> Result<DistributionDecision, DistributionError> {
        let active = Self::active_sorted(circuits);
        active
            .first()
            .map(|c| DistributionDecision {
                circuit_id: c.circuit_id,
                mode: DistributionMode::ShadowOnly,
            })
            .ok_or(DistributionError::NoEligibleCircuit)
    }

    /// Reset the round-robin index to zero.
    pub fn reset_round_robin(&mut self) {
        self.round_robin_index = 0;
    }

    /// Return active circuits sorted by `circuit_id` ascending.
    fn active_sorted(circuits: &[CircuitWeight]) -> Vec<&CircuitWeight> {
        let mut active: Vec<&CircuitWeight> = circuits.iter().filter(|c| c.is_active).collect();
        active.sort_by_key(|c| c.circuit_id.0);
        active
    }
}

impl Default for MultiCircuitDistributor {
    fn default() -> Self {
        Self::new()
    }
}
