use crate::circuit_builder::CircuitId;

/// Strategy used to select which circuit to send a cell through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributionMode {
    /// Always select the circuit with the lowest `CircuitId` (deterministic).
    SingleCircuit,
    /// Cycle through active circuits in order of ascending `CircuitId`.
    RoundRobin,
    /// Choose the circuit with the highest `reliability_score`; ties broken by
    /// ascending `latency_estimate`, then ascending `CircuitId`.
    WeightedReliability,
    /// Select only from active circuits; intended for cover / shadow traffic.
    ShadowOnly,
}

/// Quality weight assigned to one active circuit.
#[derive(Debug, Clone)]
pub struct CircuitWeight {
    pub circuit_id: CircuitId,
    /// Normalised routing weight; higher means more traffic preferred.
    pub weight: f64,
    pub reliability_score: f64,
    pub latency_estimate: u64,
    /// `false` means the circuit is closed / being torn down and must not be
    /// selected for new transmissions.
    pub is_active: bool,
}

/// The outcome of a distribution decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributionDecision {
    pub circuit_id: CircuitId,
    /// The mode that produced this decision.
    pub mode: DistributionMode,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DistributionError {
    /// The supplied circuit list was empty.
    EmptyCircuitList,
    /// All circuits in the list are inactive or none passed the selection filter.
    NoEligibleCircuit,
}
