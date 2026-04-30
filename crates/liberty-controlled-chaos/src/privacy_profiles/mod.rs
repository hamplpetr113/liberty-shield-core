//! Privacy profiles — named, user-selectable collections of parameters that
//! configure the privacy/performance trade-off for the local node.
//!
//! `PrivacyProfile` acts as a façade over the individual tunable knobs so that
//! operators (or end-users) can switch between well-tested operating points
//! without hand-tuning every parameter.

// ---------------------------------------------------------------------------
// ProfileLevel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileLevel {
    /// Lowest overhead, some metadata leakage allowed.
    Standard,
    /// Balanced — moderate cover traffic and jitter.
    Strong,
    /// Maximum protection — high cover traffic, max jitter, path rotation.
    Paranoid,
    /// Extra deception traffic on top of Paranoid.
    DeceptionHeavy,
}

// ---------------------------------------------------------------------------
// ProfileParams
// ---------------------------------------------------------------------------

/// Concrete parameters produced by a profile.
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileParams {
    /// Cover traffic ratio: injected packets / real packets (0.0 = none).
    pub cover_ratio: f64,
    /// Maximum jitter applied to outbound cells, in milliseconds.
    pub max_jitter_ms: u64,
    /// Circuit rotation interval in epochs (0 = no rotation).
    pub rotation_epochs: u64,
    /// Number of path hops (typically 3 for strong, 5 for paranoid).
    pub hop_count: u32,
    /// Whether to use deception (fake) circuits.
    pub deception_enabled: bool,
    /// Dummy cell injection budget multiplier (0.0-1.0).
    pub dummy_budget_multiplier: f64,
    /// Minimum trust score required for peers in this mode.
    pub min_peer_trust: f64,
}

impl ProfileParams {
    fn standard() -> Self {
        Self {
            cover_ratio: 0.05,
            max_jitter_ms: 20,
            rotation_epochs: 50,
            hop_count: 3,
            deception_enabled: false,
            dummy_budget_multiplier: 0.0,
            min_peer_trust: 0.3,
        }
    }

    fn strong() -> Self {
        Self {
            cover_ratio: 0.2,
            max_jitter_ms: 100,
            rotation_epochs: 20,
            hop_count: 3,
            deception_enabled: false,
            dummy_budget_multiplier: 0.1,
            min_peer_trust: 0.5,
        }
    }

    fn paranoid() -> Self {
        Self {
            cover_ratio: 0.5,
            max_jitter_ms: 300,
            rotation_epochs: 5,
            hop_count: 5,
            deception_enabled: true,
            dummy_budget_multiplier: 0.3,
            min_peer_trust: 0.7,
        }
    }

    fn deception_heavy() -> Self {
        Self {
            cover_ratio: 0.8,
            max_jitter_ms: 500,
            rotation_epochs: 3,
            hop_count: 5,
            deception_enabled: true,
            dummy_budget_multiplier: 0.6,
            min_peer_trust: 0.8,
        }
    }
}

// ---------------------------------------------------------------------------
// PrivacyProfile
// ---------------------------------------------------------------------------

pub struct PrivacyProfile {
    active: ProfileLevel,
    params: ProfileParams,
    switches: u64,
}

impl PrivacyProfile {
    pub fn new(level: ProfileLevel) -> Self {
        Self {
            active: level,
            params: Self::resolve(level),
            switches: 0,
        }
    }

    fn resolve(level: ProfileLevel) -> ProfileParams {
        match level {
            ProfileLevel::Standard => ProfileParams::standard(),
            ProfileLevel::Strong => ProfileParams::strong(),
            ProfileLevel::Paranoid => ProfileParams::paranoid(),
            ProfileLevel::DeceptionHeavy => ProfileParams::deception_heavy(),
        }
    }

    pub fn switch_to(&mut self, level: ProfileLevel) {
        self.active = level;
        self.params = Self::resolve(level);
        self.switches += 1;
    }

    pub fn active_level(&self) -> ProfileLevel {
        self.active
    }

    pub fn params(&self) -> &ProfileParams {
        &self.params
    }

    pub fn switches(&self) -> u64 {
        self.switches
    }

    /// Returns true if the current profile meets or exceeds `minimum` in
    /// terms of protection strength.
    pub fn at_least(&self, minimum: ProfileLevel) -> bool {
        fn rank(l: ProfileLevel) -> u8 {
            match l {
                ProfileLevel::Standard => 0,
                ProfileLevel::Strong => 1,
                ProfileLevel::Paranoid => 2,
                ProfileLevel::DeceptionHeavy => 3,
            }
        }
        rank(self.active) >= rank(minimum)
    }
}

impl Default for PrivacyProfile {
    fn default() -> Self {
        Self::new(ProfileLevel::Standard)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // PP1: default profile is Standard.
    #[test]
    fn pp1_default_is_standard() {
        let p = PrivacyProfile::default();
        assert_eq!(p.active_level(), ProfileLevel::Standard);
    }

    // PP2: Standard has lower cover_ratio than Strong.
    #[test]
    fn pp2_standard_lower_cover_than_strong() {
        let s = ProfileParams::standard();
        let st = ProfileParams::strong();
        assert!(s.cover_ratio < st.cover_ratio);
    }

    // PP3: Paranoid enables deception.
    #[test]
    fn pp3_paranoid_enables_deception() {
        let p = ProfileParams::paranoid();
        assert!(p.deception_enabled);
    }

    // PP4: Standard does not enable deception.
    #[test]
    fn pp4_standard_no_deception() {
        let p = ProfileParams::standard();
        assert!(!p.deception_enabled);
    }

    // PP5: switch_to changes active level.
    #[test]
    fn pp5_switch_changes_level() {
        let mut p = PrivacyProfile::new(ProfileLevel::Standard);
        p.switch_to(ProfileLevel::Paranoid);
        assert_eq!(p.active_level(), ProfileLevel::Paranoid);
    }

    // PP6: switches counter increments on each switch.
    #[test]
    fn pp6_switches_counter() {
        let mut p = PrivacyProfile::new(ProfileLevel::Standard);
        p.switch_to(ProfileLevel::Strong);
        p.switch_to(ProfileLevel::Paranoid);
        assert_eq!(p.switches(), 2);
    }

    // PP7: at_least returns true for equal level.
    #[test]
    fn pp7_at_least_equal() {
        let p = PrivacyProfile::new(ProfileLevel::Strong);
        assert!(p.at_least(ProfileLevel::Strong));
    }

    // PP8: at_least returns false for stricter level.
    #[test]
    fn pp8_at_least_false_for_stricter() {
        let p = PrivacyProfile::new(ProfileLevel::Standard);
        assert!(!p.at_least(ProfileLevel::Paranoid));
    }

    // PP9: DeceptionHeavy has highest dummy_budget_multiplier.
    #[test]
    fn pp9_deception_heavy_highest_budget() {
        let dh = ProfileParams::deception_heavy();
        let p = ProfileParams::paranoid();
        assert!(dh.dummy_budget_multiplier > p.dummy_budget_multiplier);
    }

    // PP10: params reflect active level after switch.
    #[test]
    fn pp10_params_reflect_level() {
        let mut p = PrivacyProfile::new(ProfileLevel::Standard);
        p.switch_to(ProfileLevel::DeceptionHeavy);
        assert_eq!(p.params().hop_count, 5);
    }
}
