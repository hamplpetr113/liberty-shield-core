/// Sprint 5 frozen module — stub only.
/// Computes a post-decoupler correlation score in [0.0, 1.0].
/// Consumed by route_shadower as a plain f32.
pub struct CorrelationScoreEngine;

impl CorrelationScoreEngine {
    pub fn new() -> Self {
        CorrelationScoreEngine
    }
}

impl Default for CorrelationScoreEngine {
    fn default() -> Self {
        Self::new()
    }
}
