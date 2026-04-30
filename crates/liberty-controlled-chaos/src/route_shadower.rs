//! Probabilistic route-shadow decision engine (Sprint 6).
//!
//! `resolve_shadow_params` is the single public entry point. It takes a
//! `DecisionInputs` snapshot and returns a `ShadowDecision` describing how
//! aggressively the caller should shadow the flow. No packets are generated
//! here; the decision feeds the downstream `PathFragmenter`.
//!
//! All logic is deterministic and side-effect-free. Rules are applied in the
//! order defined by `shadow_probability_model.md` §6.

// ── Mode table constants ─────────────────────────────────────────────────────

const NORMAL_SHADOW_PROBABILITY: f32 = 0.10;
const NORMAL_SHADOW_PATHS: u8 = 1;
const NORMAL_COVER_FLOW_RATIO: f32 = 0.15;
const NORMAL_BW_LIMIT_PCT: f32 = 8.0;
const NORMAL_BATTERY_LIMIT: f32 = 0.05;
const NORMAL_LATENCY_MS: u32 = 80;

const PRIVACY_SHADOW_PROBABILITY: f32 = 0.35;
const PRIVACY_SHADOW_PATHS: u8 = 2;
const PRIVACY_COVER_FLOW_RATIO: f32 = 0.40;
const PRIVACY_BW_LIMIT_PCT: f32 = 20.0;
const PRIVACY_BATTERY_LIMIT: f32 = 0.15;
const PRIVACY_LATENCY_MS: u32 = 150;

const PARANOID_SHADOW_PROBABILITY: f32 = 0.70;
const PARANOID_SHADOW_PATHS: u8 = 4;
const PARANOID_COVER_FLOW_RATIO: f32 = 0.90;
const PARANOID_BW_LIMIT_PCT: f32 = 45.0;
const PARANOID_BATTERY_LIMIT: f32 = 0.40;
const PARANOID_LATENCY_MS: u32 = 300;

const STEALTH_SHADOW_PROBABILITY: f32 = 0.20;
const STEALTH_SHADOW_PATHS: u8 = 1;
const STEALTH_COVER_FLOW_RATIO: f32 = 0.25;
const STEALTH_BW_LIMIT_PCT: f32 = 12.0;
const STEALTH_BATTERY_LIMIT: f32 = 0.08;
const STEALTH_LATENCY_MS: u32 = 60;

// ── Public enums ─────────────────────────────────────────────────────────────

pub enum ChargingState {
    Charging,
    Discharging,
    Unknown,
}

pub enum NetworkReputation {
    Trusted,
    Neutral,
    Untrusted,
    Hostile,
}

/// Traffic classification produced by the frozen `traffic_classifier` module.
pub enum TrafficClass {
    Web,
    Voip,
    Streaming,
    Banking,
    Login,
    Dns,
    Background,
    Unknown,
}

/// The four privacy operating modes. STEALTH is never auto-selected by
/// `select_base_mode`; it must be injected via a future user-preference input.
pub enum OperatingMode {
    Normal,
    Privacy,
    Paranoid,
    Stealth,
}

// ── Public structs ───────────────────────────────────────────────────────────

/// All inputs required for a single shadow-probability decision.
pub struct DecisionInputs {
    /// Threat score from the ShieldEngine pipeline, [0.0, 1.0].
    pub threat_score: f32,
    /// Correlation score after temporal decoupling, [0.0, 1.0]. Lower is better.
    pub correlation_score: f32,
    /// Battery charge percentage, 0–100.
    pub battery_level: u8,
    pub charging_state: ChargingState,
    pub network_reputation: NetworkReputation,
    pub traffic_class: TrafficClass,
    /// Number of distinct egress paths currently available to the route manager.
    pub available_paths: u8,
}

/// Output of the shadow-probability decision pipeline.
///
/// `bandwidth_budget` is a dimensionless ratio equal to
/// `shadow_probability * cover_flow_ratio`. The downstream PathFragmenter
/// uses it to size cover flows relative to the real flow.
///
/// `latency_guard_ms` is carried through unchanged; the PathFragmenter
/// enforces it when selecting candidate paths (Rule 6.8).
pub struct ShadowDecision {
    pub shadow_probability: f32,
    pub shadow_paths: u8,
    pub cover_flow_ratio: f32,
    pub bandwidth_budget: f32,
    pub latency_guard_ms: u32,
}

// ── Internal working struct ───────────────────────────────────────────────────

/// Mutable working state threaded through the rule pipeline.
/// `battery_impact_limit_pct_per_h` is tracked but not projected into
/// `ShadowDecision`; it will feed the power-accounting layer in a later sprint.
struct ShadowParams {
    shadow_probability: f32,
    shadow_paths: u8,
    cover_flow_ratio: f32,
    bandwidth_overhead_limit_pct: f32,
    battery_impact_limit_pct_per_h: f32,
    latency_guard_ms: u32,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Compute shadow parameters for a single flow.
///
/// Rules are applied in the order mandated by `shadow_probability_model.md` §6.
/// The function is pure: given the same inputs it always returns the same output.
pub fn resolve_shadow_params(inputs: &DecisionInputs) -> ShadowDecision {
    let mode = select_base_mode(inputs);
    let mut params = params_for_mode(mode);

    apply_hard_exclusion(inputs, &mut params);
    apply_voip_cap(inputs, &mut params);
    apply_low_battery(inputs, &mut params);
    apply_charging_relaxation(inputs, &mut params);
    apply_correlation_escalation(inputs, &mut params);
    apply_path_availability_gate(inputs, &mut params);
    apply_bandwidth_ceiling(&mut params);
    apply_latency_guard(&mut params);

    project_to_decision(params)
}

// ── Stage 1: base mode selection ─────────────────────────────────────────────

fn select_base_mode(inputs: &DecisionInputs) -> OperatingMode {
    // Unknown traffic class → always NORMAL regardless of threat signals (spec §10).
    if matches!(inputs.traffic_class, TrafficClass::Unknown) {
        return OperatingMode::Normal;
    }

    match inputs.network_reputation {
        NetworkReputation::Hostile => return OperatingMode::Paranoid,
        NetworkReputation::Untrusted => return OperatingMode::Privacy,
        _ => {}
    }

    if inputs.threat_score > 0.70 {
        return OperatingMode::Paranoid;
    }
    if inputs.threat_score > 0.40 {
        return OperatingMode::Privacy;
    }
    if inputs.correlation_score > 0.60 {
        return OperatingMode::Privacy;
    }

    OperatingMode::Normal
}

fn params_for_mode(mode: OperatingMode) -> ShadowParams {
    match mode {
        OperatingMode::Normal => ShadowParams {
            shadow_probability: NORMAL_SHADOW_PROBABILITY,
            shadow_paths: NORMAL_SHADOW_PATHS,
            cover_flow_ratio: NORMAL_COVER_FLOW_RATIO,
            bandwidth_overhead_limit_pct: NORMAL_BW_LIMIT_PCT,
            battery_impact_limit_pct_per_h: NORMAL_BATTERY_LIMIT,
            latency_guard_ms: NORMAL_LATENCY_MS,
        },
        OperatingMode::Privacy => ShadowParams {
            shadow_probability: PRIVACY_SHADOW_PROBABILITY,
            shadow_paths: PRIVACY_SHADOW_PATHS,
            cover_flow_ratio: PRIVACY_COVER_FLOW_RATIO,
            bandwidth_overhead_limit_pct: PRIVACY_BW_LIMIT_PCT,
            battery_impact_limit_pct_per_h: PRIVACY_BATTERY_LIMIT,
            latency_guard_ms: PRIVACY_LATENCY_MS,
        },
        OperatingMode::Paranoid => ShadowParams {
            shadow_probability: PARANOID_SHADOW_PROBABILITY,
            shadow_paths: PARANOID_SHADOW_PATHS,
            cover_flow_ratio: PARANOID_COVER_FLOW_RATIO,
            bandwidth_overhead_limit_pct: PARANOID_BW_LIMIT_PCT,
            battery_impact_limit_pct_per_h: PARANOID_BATTERY_LIMIT,
            latency_guard_ms: PARANOID_LATENCY_MS,
        },
        OperatingMode::Stealth => ShadowParams {
            shadow_probability: STEALTH_SHADOW_PROBABILITY,
            shadow_paths: STEALTH_SHADOW_PATHS,
            cover_flow_ratio: STEALTH_COVER_FLOW_RATIO,
            bandwidth_overhead_limit_pct: STEALTH_BW_LIMIT_PCT,
            battery_impact_limit_pct_per_h: STEALTH_BATTERY_LIMIT,
            latency_guard_ms: STEALTH_LATENCY_MS,
        },
    }
}

// ── Stage 2: override rules ───────────────────────────────────────────────────

/// Rule 6.1 — Hard exclusion: banking and login flows must never be shadowed.
///
/// Downstream correlation of shadow traffic near auth/payment sessions can
/// trigger fraud signals at the remote service (account lockouts, 3DS challenges).
fn apply_hard_exclusion(inputs: &DecisionInputs, params: &mut ShadowParams) {
    match inputs.traffic_class {
        TrafficClass::Banking | TrafficClass::Login => {
            params.shadow_probability = 0.0;
            params.shadow_paths = 0;
            params.cover_flow_ratio = 0.0;
        }
        _ => {}
    }
}

/// Rule 6.2 — VoIP soft cap.
///
/// VoIP flows cannot tolerate additional queue contention. One low-probability
/// shadow is the maximum that preserves the 9.2 ms baseline from Sprint 5.
fn apply_voip_cap(inputs: &DecisionInputs, params: &mut ShadowParams) {
    if matches!(inputs.traffic_class, TrafficClass::Voip) {
        if params.shadow_probability > 0.05 {
            params.shadow_probability = 0.05;
        }
        if params.shadow_paths > 1 {
            params.shadow_paths = 1;
        }
        if params.cover_flow_ratio > 0.10 {
            params.cover_flow_ratio = 0.10;
        }
        if params.latency_guard_ms > 40 {
            params.latency_guard_ms = 40;
        }
    }
}

/// Rule 6.3 — Low-battery reduction (< 20 %, not charging).
///
/// Unknown charging state is treated as non-charging: the conservative choice
/// is to protect the battery when the state cannot be confirmed.
fn apply_low_battery(inputs: &DecisionInputs, params: &mut ShadowParams) {
    if inputs.battery_level < 20 {
        let is_charging = matches!(inputs.charging_state, ChargingState::Charging);
        if !is_charging {
            params.shadow_probability *= 0.40;
            if params.shadow_paths > 1 {
                params.shadow_paths = 1;
            }
            params.cover_flow_ratio *= 0.30;
            if params.battery_impact_limit_pct_per_h > 0.03 {
                params.battery_impact_limit_pct_per_h = 0.03;
            }
        }
    }
}

/// Rule 6.4 — Charging relaxation.
///
/// AC power removes the battery constraint; the bandwidth overhead ceiling
/// may be expanded up to 2.5× the mode default, hard-capped at 100 %.
fn apply_charging_relaxation(inputs: &DecisionInputs, params: &mut ShadowParams) {
    if matches!(inputs.charging_state, ChargingState::Charging) {
        let relaxed = params.bandwidth_overhead_limit_pct * 2.5;
        if relaxed > 100.0 {
            params.bandwidth_overhead_limit_pct = 100.0;
        } else {
            params.bandwidth_overhead_limit_pct = relaxed;
        }
    }
}

/// Rule 6.5 — Correlation score escalation.
///
/// When the temporal decoupler did not suppress residual correlation
/// sufficiently, route shadowing compensates by increasing aggressiveness.
///
/// Early return when `shadow_probability == 0.0`: that value is the sentinel
/// set by Rule 6.1 for hard-excluded flows (Banking/Login). Without this guard
/// the `shadow_paths + 1` increment would change the Rule 6.1 zero to 1,
/// which would then pass the `shadow_paths != 0` check on the PARANOID floor
/// and incorrectly re-raise the excluded flow.
fn apply_correlation_escalation(inputs: &DecisionInputs, params: &mut ShadowParams) {
    if params.shadow_probability == 0.0 {
        return;
    }

    if inputs.correlation_score > 0.50 {
        let escalated = params.shadow_probability * (1.0 + inputs.correlation_score);
        if escalated > 0.85 {
            params.shadow_probability = 0.85;
        } else {
            params.shadow_probability = escalated;
        }

        let new_paths = params.shadow_paths + 1;
        if new_paths > 4 {
            params.shadow_paths = 4;
        } else {
            params.shadow_paths = new_paths;
        }
    }

    // Apply PARANOID floors only when correlation is severe AND the flow has
    // not been hard-excluded by Rule 6.1 (shadow_paths == 0 signals exclusion).
    if inputs.correlation_score > 0.75 && params.shadow_paths != 0 {
        if params.shadow_probability < PARANOID_SHADOW_PROBABILITY {
            params.shadow_probability = PARANOID_SHADOW_PROBABILITY;
        }
        if params.shadow_paths < PARANOID_SHADOW_PATHS {
            params.shadow_paths = PARANOID_SHADOW_PATHS;
        }
        if params.cover_flow_ratio < PARANOID_COVER_FLOW_RATIO {
            params.cover_flow_ratio = PARANOID_COVER_FLOW_RATIO;
        }
        if params.bandwidth_overhead_limit_pct < PARANOID_BW_LIMIT_PCT {
            params.bandwidth_overhead_limit_pct = PARANOID_BW_LIMIT_PCT;
        }
        if params.latency_guard_ms < PARANOID_LATENCY_MS {
            params.latency_guard_ms = PARANOID_LATENCY_MS;
        }
    }
}

/// Rule 6.6 — Path availability gate.
///
/// Shadowing requires at least two distinct egress paths. A single-path
/// "shadow" would traverse the same route as the real flow and provide no
/// correlation resistance; it would only add overhead.
fn apply_path_availability_gate(inputs: &DecisionInputs, params: &mut ShadowParams) {
    if inputs.available_paths < 2 {
        params.shadow_probability = 0.0;
        params.shadow_paths = 0;
    }
}

/// Rule 6.7 — Bandwidth overhead ceiling.
///
/// Clamps `cover_flow_ratio` so that `shadow_probability * cover_flow_ratio`
/// never exceeds `bandwidth_overhead_limit_pct / 100`. Division is guarded
/// against zero; when `shadow_probability` is zero the ceiling is moot.
fn apply_bandwidth_ceiling(params: &mut ShadowParams) {
    if params.shadow_probability > 0.0 {
        let expected_overhead = params.shadow_probability * params.cover_flow_ratio;
        let limit = params.bandwidth_overhead_limit_pct / 100.0;
        if expected_overhead > limit {
            params.cover_flow_ratio = limit / params.shadow_probability;
        }
    }
}

/// Rule 6.8 — Latency guard (pass-through).
///
/// Per-path RTT measurement and exclusion is enforced by the downstream
/// PathFragmenter. This module carries `latency_guard_ms` through as an
/// output field without modifying it.
fn apply_latency_guard(_params: &mut ShadowParams) {}

// ── Projection ────────────────────────────────────────────────────────────────

fn project_to_decision(params: ShadowParams) -> ShadowDecision {
    let bandwidth_budget = params.shadow_probability * params.cover_flow_ratio;
    ShadowDecision {
        shadow_probability: params.shadow_probability,
        shadow_paths: params.shadow_paths,
        cover_flow_ratio: params.cover_flow_ratio,
        bandwidth_budget,
        latency_guard_ms: params.latency_guard_ms,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_inputs() -> DecisionInputs {
        DecisionInputs {
            threat_score: 0.10,
            correlation_score: 0.10,
            battery_level: 80,
            charging_state: ChargingState::Discharging,
            network_reputation: NetworkReputation::Neutral,
            traffic_class: TrafficClass::Web,
            available_paths: 3,
        }
    }

    // ── Rule 6.1 ────────────────────────────────────────────────────────────

    #[test]
    fn rule_6_1_banking_zeroes_all() {
        let mut inputs = baseline_inputs();
        inputs.traffic_class = TrafficClass::Banking;
        let d = resolve_shadow_params(&inputs);
        assert_eq!(d.shadow_probability, 0.0);
        assert_eq!(d.shadow_paths, 0);
        assert_eq!(d.cover_flow_ratio, 0.0);
        assert_eq!(d.bandwidth_budget, 0.0);
    }

    #[test]
    fn rule_6_1_login_zeroes_all() {
        let mut inputs = baseline_inputs();
        inputs.traffic_class = TrafficClass::Login;
        let d = resolve_shadow_params(&inputs);
        assert_eq!(d.shadow_probability, 0.0);
        assert_eq!(d.shadow_paths, 0);
        assert_eq!(d.cover_flow_ratio, 0.0);
        assert_eq!(d.bandwidth_budget, 0.0);
    }

    #[test]
    fn rule_6_1_banking_survives_high_correlation() {
        // Rule 6.5 PARANOID floor must not override Rule 6.1 zeroes.
        let mut inputs = baseline_inputs();
        inputs.traffic_class = TrafficClass::Banking;
        inputs.correlation_score = 0.90;
        let d = resolve_shadow_params(&inputs);
        assert_eq!(d.shadow_probability, 0.0);
        assert_eq!(d.shadow_paths, 0);
        assert_eq!(d.cover_flow_ratio, 0.0);
    }

    // ── Rule 6.2 ────────────────────────────────────────────────────────────

    #[test]
    fn rule_6_2_voip_caps_probability() {
        // Use Privacy-triggering threat score so caps are clearly visible.
        let mut inputs = baseline_inputs();
        inputs.traffic_class = TrafficClass::Voip;
        inputs.threat_score = 0.50;
        let d = resolve_shadow_params(&inputs);
        assert!(
            d.shadow_probability <= 0.05,
            "shadow_probability {} > 0.05",
            d.shadow_probability
        );
        assert!(d.shadow_paths <= 1);
        assert!(
            d.cover_flow_ratio <= 0.10,
            "cover_flow_ratio {} > 0.10",
            d.cover_flow_ratio
        );
        assert!(
            d.latency_guard_ms <= 40,
            "latency_guard_ms {} > 40",
            d.latency_guard_ms
        );
    }

    // ── Rule 6.3 ────────────────────────────────────────────────────────────

    #[test]
    fn rule_6_3_low_battery_discharging_reduces() {
        let mut inputs = baseline_inputs();
        inputs.battery_level = 15;
        inputs.charging_state = ChargingState::Discharging;
        let d = resolve_shadow_params(&inputs);
        let expected = NORMAL_SHADOW_PROBABILITY * 0.40;
        assert!(
            (d.shadow_probability - expected).abs() < 1e-6,
            "shadow_probability {} != {}",
            d.shadow_probability,
            expected
        );
        assert!(d.shadow_paths <= 1);
    }

    #[test]
    fn rule_6_3_low_battery_charging_no_reduction() {
        // While charging, Rule 6.3 must not fire even when battery is low.
        let mut inputs = baseline_inputs();
        inputs.battery_level = 15;
        inputs.charging_state = ChargingState::Charging;
        let d = resolve_shadow_params(&inputs);
        // Rule 6.3 skipped; probability should equal NORMAL default.
        assert!(
            (d.shadow_probability - NORMAL_SHADOW_PROBABILITY).abs() < 1e-6,
            "shadow_probability {} != {}",
            d.shadow_probability,
            NORMAL_SHADOW_PROBABILITY
        );
    }

    // ── Rule 6.4 ────────────────────────────────────────────────────────────

    #[test]
    fn rule_6_4_charging_relaxes_bandwidth_ceiling() {
        // Charging should expand the bandwidth limit so a large cover_flow_ratio
        // is NOT clamped down. Use PARANOID mode (45 % limit) + charging:
        // relaxed limit = 45 * 2.5 = 112.5 → capped at 100 %.
        // cover_flow_ratio 0.90 with probability 0.70 → overhead 63 % < 100 %,
        // so it must NOT be reduced.
        let mut inputs = baseline_inputs();
        inputs.threat_score = 0.80; // → Paranoid base mode
        inputs.charging_state = ChargingState::Charging;
        let d = resolve_shadow_params(&inputs);
        // Under Paranoid + charging the cover_flow_ratio should be unclamped.
        assert!(
            (d.cover_flow_ratio - PARANOID_COVER_FLOW_RATIO).abs() < 1e-6,
            "cover_flow_ratio {} unexpectedly clamped (expected {})",
            d.cover_flow_ratio,
            PARANOID_COVER_FLOW_RATIO
        );
    }

    // ── Rule 6.5 ────────────────────────────────────────────────────────────

    #[test]
    fn rule_6_5_correlation_above_50_escalates_probability() {
        let mut inputs = baseline_inputs();
        inputs.correlation_score = 0.65;
        let d = resolve_shadow_params(&inputs);
        assert!(
            d.shadow_probability > NORMAL_SHADOW_PROBABILITY,
            "probability {} not escalated above {}",
            d.shadow_probability,
            NORMAL_SHADOW_PROBABILITY
        );
    }

    #[test]
    fn rule_6_5_correlation_above_75_applies_paranoid_floor() {
        let mut inputs = baseline_inputs();
        inputs.correlation_score = 0.80;
        let d = resolve_shadow_params(&inputs);
        assert!(
            d.shadow_probability >= PARANOID_SHADOW_PROBABILITY,
            "probability {} below PARANOID floor {}",
            d.shadow_probability,
            PARANOID_SHADOW_PROBABILITY
        );
        assert!(
            d.shadow_paths >= PARANOID_SHADOW_PATHS,
            "paths {} below PARANOID floor {}",
            d.shadow_paths,
            PARANOID_SHADOW_PATHS
        );
    }

    #[test]
    fn rule_6_5_correlation_at_50_does_not_escalate() {
        // Exactly 0.50 is not > 0.50; escalation must not fire.
        let mut inputs = baseline_inputs();
        inputs.correlation_score = 0.50;
        let d = resolve_shadow_params(&inputs);
        assert!(
            (d.shadow_probability - NORMAL_SHADOW_PROBABILITY).abs() < 1e-6,
            "probability {} unexpectedly escalated",
            d.shadow_probability
        );
    }

    // ── Rule 6.6 ────────────────────────────────────────────────────────────

    #[test]
    fn rule_6_6_single_path_gates_to_zero() {
        let mut inputs = baseline_inputs();
        inputs.available_paths = 1;
        let d = resolve_shadow_params(&inputs);
        assert_eq!(d.shadow_probability, 0.0);
        assert_eq!(d.shadow_paths, 0);
    }

    #[test]
    fn rule_6_6_zero_paths_gates_to_zero() {
        let mut inputs = baseline_inputs();
        inputs.available_paths = 0;
        let d = resolve_shadow_params(&inputs);
        assert_eq!(d.shadow_probability, 0.0);
        assert_eq!(d.shadow_paths, 0);
    }

    // ── Rule 6.7 ────────────────────────────────────────────────────────────

    #[test]
    fn rule_6_7_bandwidth_ceiling_clamps_cover_flow() {
        // Force PARANOID mode (limit 45 %) with high correlation escalation.
        // After escalation: probability → 0.85 (capped), ratio → 0.90.
        // Expected overhead = 0.85 * 0.90 = 76.5 % > 45 % → must be clamped.
        let mut inputs = baseline_inputs();
        inputs.threat_score = 0.80; // → Paranoid base
        inputs.correlation_score = 0.60; // escalates probability
        let d = resolve_shadow_params(&inputs);
        let actual_overhead = d.shadow_probability * d.cover_flow_ratio;
        assert!(
            actual_overhead <= 0.45 + 1e-6,
            "overhead {} exceeded 45 % limit",
            actual_overhead
        );
    }

    #[test]
    fn rule_6_7_zero_probability_no_divide_panic() {
        // available_paths = 0 → probability zeroed by Rule 6.6 before Rule 6.7.
        // Rule 6.7 must not divide by zero.
        let mut inputs = baseline_inputs();
        inputs.available_paths = 0;
        let d = resolve_shadow_params(&inputs); // must not panic
        assert_eq!(d.bandwidth_budget, 0.0);
    }

    // ── bandwidth_budget projection ─────────────────────────────────────────

    #[test]
    fn bandwidth_budget_equals_probability_times_ratio() {
        let inputs = baseline_inputs();
        let d = resolve_shadow_params(&inputs);
        let expected = d.shadow_probability * d.cover_flow_ratio;
        assert!(
            (d.bandwidth_budget - expected).abs() < 1e-6,
            "bandwidth_budget {} != prob*ratio {}",
            d.bandwidth_budget,
            expected
        );
    }

    // ── Base mode selection ─────────────────────────────────────────────────

    #[test]
    fn base_mode_hostile_network_is_paranoid() {
        let mut inputs = baseline_inputs();
        inputs.network_reputation = NetworkReputation::Hostile;
        let d = resolve_shadow_params(&inputs);
        assert!(
            d.shadow_probability >= PARANOID_SHADOW_PROBABILITY,
            "probability {} below PARANOID for hostile network",
            d.shadow_probability
        );
    }

    #[test]
    fn base_mode_high_threat_score_is_paranoid() {
        let mut inputs = baseline_inputs();
        inputs.threat_score = 0.80;
        let d = resolve_shadow_params(&inputs);
        assert!(
            d.shadow_probability >= PARANOID_SHADOW_PROBABILITY,
            "probability {} below PARANOID for threat 0.80",
            d.shadow_probability
        );
    }

    #[test]
    fn base_mode_normal_defaults() {
        let inputs = baseline_inputs();
        let d = resolve_shadow_params(&inputs);
        assert!(
            (d.shadow_probability - NORMAL_SHADOW_PROBABILITY).abs() < 1e-6,
            "probability {} != NORMAL default {}",
            d.shadow_probability,
            NORMAL_SHADOW_PROBABILITY
        );
        assert_eq!(d.shadow_paths, NORMAL_SHADOW_PATHS);
        assert!((d.cover_flow_ratio - NORMAL_COVER_FLOW_RATIO).abs() < 1e-6);
        assert_eq!(d.latency_guard_ms, NORMAL_LATENCY_MS);
    }
}
