/// Sprint 5 frozen module — stub only.
/// Produces timing-randomised flows; its output is consumed by the
/// correlation_score_engine as a plain f32 score.
pub struct TemporalDecoupler;

impl TemporalDecoupler {
    pub fn new() -> Self {
        TemporalDecoupler
    }
}

impl Default for TemporalDecoupler {
    fn default() -> Self {
        Self::new()
    }
}
