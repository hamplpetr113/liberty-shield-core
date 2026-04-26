/// Sprint 5 frozen module — stub only.
/// Classifies flows into TrafficClass variants.
/// The TrafficClass enum is defined in route_shadower and re-exported from lib.
pub struct TrafficClassifier;

impl TrafficClassifier {
    pub fn new() -> Self {
        TrafficClassifier
    }
}

impl Default for TrafficClassifier {
    fn default() -> Self {
        Self::new()
    }
}
