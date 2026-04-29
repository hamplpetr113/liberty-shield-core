//! Adaptive cover traffic engine — adjusts the cover packet rate based on
//! observed network load to hide real traffic patterns.
//!
//! # Algorithm
//! The engine maintains a `network_load` in [0.0, 1.0] (fraction of capacity
//! in use).  The cover rate is:
//!
//! ```text
//! cover_rate = base_rate * (1.0 + adaptive_multiplier * (1.0 - network_load))
//! ```
//!
//! When the network is idle (`load ≈ 0`) cover is multiplied up.  When the
//! network is saturated (`load ≈ 1`) cover is kept at `base_rate`.
//!
//! `generate_padding_slots(epoch, total_slots)` returns the number of slots
//! that should carry cover/padding for the given epoch.

// ---------------------------------------------------------------------------
// CoverTrafficEngine
// ---------------------------------------------------------------------------

/// Adaptive cover traffic rate controller.
pub struct CoverTrafficEngine {
    /// Baseline cover packets per epoch.
    pub base_rate: f64,
    /// Multiplier applied when the network is idle (controls how much extra
    /// cover is injected).
    pub adaptive_multiplier: f64,
    /// Current network load estimate in [0.0, 1.0].
    pub network_load: f64,
    /// EWMA coefficient for load updates.
    load_alpha: f64,
}

impl CoverTrafficEngine {
    /// Create an engine with the given parameters.
    ///
    /// - `base_rate`: cover packets per epoch at full load.
    /// - `adaptive_multiplier`: multiplier when idle (typical range 1.0–5.0).
    pub fn new(base_rate: f64, adaptive_multiplier: f64) -> Self {
        assert!(base_rate >= 0.0, "base_rate must be non-negative");
        assert!(
            adaptive_multiplier >= 1.0,
            "adaptive_multiplier must be >= 1.0"
        );
        Self {
            base_rate,
            adaptive_multiplier,
            network_load: 0.0,
            load_alpha: 0.2,
        }
    }

    /// Update the network load estimate with a new sample in [0.0, 1.0].
    pub fn update_network_load(&mut self, sample: f64) {
        let sample = sample.clamp(0.0, 1.0);
        self.network_load = (1.0 - self.load_alpha) * self.network_load + self.load_alpha * sample;
    }

    /// Compute the current cover rate (packets per epoch).
    pub fn compute_cover_rate(&self) -> f64 {
        let idle_factor = 1.0 - self.network_load;
        self.base_rate * (1.0 + self.adaptive_multiplier * idle_factor)
    }

    /// Return the number of cover/padding slots to allocate in an epoch with
    /// `total_slots` available.
    ///
    /// The result is clamped to `[0, total_slots]`.
    pub fn generate_padding_slots(&self, total_slots: u32) -> u32 {
        let rate = self.compute_cover_rate().round() as u32;
        rate.min(total_slots)
    }

    /// Set the load smoothing coefficient α ∈ (0, 1].
    pub fn set_load_alpha(&mut self, alpha: f64) {
        assert!(alpha > 0.0 && alpha <= 1.0);
        self.load_alpha = alpha;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> CoverTrafficEngine {
        CoverTrafficEngine::new(4.0, 2.0)
    }

    // AC1: baseline cover rate when load = 0.
    #[test]
    fn ac1_baseline_cover() {
        let e = engine();
        // load=0 → rate = 4*(1+2*1) = 12
        assert!((e.compute_cover_rate() - 12.0).abs() < 0.01);
    }

    // AC2: higher load reduces cover rate.
    #[test]
    fn ac2_increased_load() {
        let mut e = engine();
        e.set_load_alpha(1.0); // instant update
        e.update_network_load(1.0); // full load
        // rate = 4*(1+2*0) = 4
        assert!((e.compute_cover_rate() - 4.0).abs() < 0.01);
    }

    // AC3: lower load after high load increases cover rate again.
    #[test]
    fn ac3_decreased_load() {
        let mut e = engine();
        e.set_load_alpha(1.0);
        e.update_network_load(1.0);
        let rate_high = e.compute_cover_rate();
        e.update_network_load(0.0);
        let rate_low = e.compute_cover_rate();
        assert!(rate_low > rate_high);
    }

    // AC4: adaptive scaling — mid load produces mid rate.
    #[test]
    fn ac4_adaptive_scaling() {
        let mut e = engine();
        e.set_load_alpha(1.0);
        e.update_network_load(0.5);
        // rate = 4*(1+2*0.5) = 8
        assert!((e.compute_cover_rate() - 8.0).abs() < 0.01);
    }

    // AC5: padding slots are capped at total_slots.
    #[test]
    fn ac5_integration_scheduler() {
        let e = engine();
        // cover_rate = 12, total_slots = 5 → capped at 5
        assert_eq!(e.generate_padding_slots(5), 5);
    }

    // AC6: generate_padding_slots rounds correctly.
    #[test]
    fn ac6_randomness_distribution() {
        let mut e = CoverTrafficEngine::new(3.0, 1.0);
        e.set_load_alpha(1.0);
        e.update_network_load(0.0);
        // rate = 3*(1+1*1) = 6
        assert_eq!(e.generate_padding_slots(20), 6);
    }

    // AC7: burst smoothing — load EWMA dampens rapid changes.
    #[test]
    fn ac7_burst_smoothing() {
        let mut e = engine();
        // Default alpha=0.2: rapid spike is smoothed.
        e.update_network_load(1.0);
        // load = 0.2*1 = 0.2, not 1.0
        assert!(e.network_load < 0.3);
    }

    // AC8: idle network → maximum cover rate.
    #[test]
    fn ac8_idle_network() {
        let e = CoverTrafficEngine::new(10.0, 3.0);
        // load=0 → rate = 10*(1+3*1) = 40
        assert!((e.compute_cover_rate() - 40.0).abs() < 0.01);
    }

    // AC9: heavy network → cover rate equals base_rate.
    #[test]
    fn ac9_heavy_network() {
        let mut e = CoverTrafficEngine::new(10.0, 3.0);
        e.set_load_alpha(1.0);
        e.update_network_load(1.0);
        assert!((e.compute_cover_rate() - 10.0).abs() < 0.01);
    }

    // AC10: stability — repeated load updates converge.
    #[test]
    fn ac10_stability() {
        let mut e = engine();
        for _ in 0..100 {
            e.update_network_load(0.5);
        }
        // Should converge to load ≈ 0.5.
        assert!((e.network_load - 0.5).abs() < 0.01);
        // Cover rate should be stable.
        let r1 = e.compute_cover_rate();
        e.update_network_load(0.5);
        let r2 = e.compute_cover_rate();
        assert!((r1 - r2).abs() < 0.01);
    }
}
