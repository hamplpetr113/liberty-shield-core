/// Policy thresholds that control when a circuit should be rotated.
#[derive(Debug, Clone)]
pub struct RotationPolicy {
    /// Maximum circuit lifetime in microseconds before age-based rotation.
    pub max_circuit_age: u64,
    /// Maximum tolerated failure count before forced rotation.
    pub max_failures: u32,
    /// Minimum acceptable success ratio (successes / total).  Below this the
    /// circuit is considered unhealthy.  Only evaluated when total > 0.
    pub min_success_ratio: f64,
    /// Minimum gap between two consecutive rotations of the same circuit, in
    /// microseconds.  Prevents rotation storms.
    pub rotation_cooldown: u64,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            max_circuit_age: 3_600_000_000, // 1 hour
            max_failures: 5,
            min_success_ratio: 0.5,
            rotation_cooldown: 60_000_000, // 1 minute
        }
    }
}
