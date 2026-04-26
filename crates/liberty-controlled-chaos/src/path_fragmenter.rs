//! PathFragmenter — Sprint 6 Phase 2.
//!
//! Translates a `ShadowDecision` from `route_shadower` into a concrete
//! `FragmentPlan` that assigns cover-traffic bandwidth to specific egress paths.
//!
//! The function is deterministic and side-effect-free. The caller is responsible
//! for the probabilistic coin flip against `shadow_probability` before calling
//! `build_fragment_plan`. No packets are generated here.

use crate::route_shadower::ShadowDecision;

// ── Public types ──────────────────────────────────────────────────────────────

/// A single egress path offered by the route manager.
pub struct CandidatePath {
    /// Stable identifier assigned by the route manager.
    /// Used as the deterministic tiebreaker in all ranking and iteration steps.
    pub path_id: u64,
    /// Most recent measured RTT in milliseconds.
    /// Compared against `ShadowDecision::latency_guard_ms` (inclusive ≤).
    pub measured_rtt_ms: u32,
    /// Available bandwidth headroom on this path in kbps. Per-path allocation cap.
    pub available_bandwidth_kbps: u32,
    /// Historical delivery success rate, [0.0, 1.0]. Primary distribution weight.
    pub reliability_score: f32,
}

/// Bandwidth assignment for one selected shadow path.
pub struct PathAllocation {
    pub path_id: u64,
    /// Fraction of total cover bandwidth on this path, (0.0, 1.0].
    /// All weights in a non-empty plan sum to 1.0 within f32 epsilon.
    pub weight: f32,
    /// Absolute cover-traffic bandwidth in kbps.
    pub cover_bandwidth_kbps: u32,
}

/// Reason the plan was produced below requested capacity.
pub enum DegradationReason {
    /// All candidate paths exceeded `latency_guard_ms`. Allocations are empty.
    /// Caller should rely on temporal decoupling only.
    NoEligiblePaths,
    /// Fewer eligible paths than `shadow_paths` requested. Partial plan returned.
    InsufficientPaths { requested: u8, available: u8 },
    /// Combined path capacity is less than the full cover budget.
    /// Cover was scaled down to the maximum the selected paths can carry.
    BandwidthConstrained {
        requested_kbps: u32,
        available_kbps: u32,
    },
}

/// Complete shadow allocation plan for one flow.
///
/// Always returned — never an error. `degraded` and `degradation_reason` signal
/// any shortfall; the caller logs and adapts without branching on a `Result`.
/// `allocations` is sorted by `path_id` ascending for stable, reproducible output.
pub struct FragmentPlan {
    pub allocations: Vec<PathAllocation>,
    pub total_cover_bandwidth_kbps: u32,
    /// Actual path count used; may be less than `ShadowDecision::shadow_paths`.
    pub effective_shadow_paths: u8,
    pub degraded: bool,
    pub degradation_reason: Option<DegradationReason>,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Compute the shadow path allocation plan for a single flow.
///
/// `candidates` may arrive in any order; output is fully deterministic regardless.
/// Never panics. Always returns a `FragmentPlan` even when all paths are ineligible.
pub fn build_fragment_plan(
    decision: &ShadowDecision,
    candidates: &[CandidatePath],
    real_flow_bandwidth_kbps: u32,
) -> FragmentPlan {
    // shadow_paths == 0: spec fulfilled exactly — no degradation.
    if decision.shadow_paths == 0 {
        return FragmentPlan {
            allocations: vec![],
            total_cover_bandwidth_kbps: 0,
            effective_shadow_paths: 0,
            degraded: false,
            degradation_reason: None,
        };
    }

    // Step 1 — latency filter (Rule 6.8 enforcement).
    let eligible: Vec<usize> = candidates
        .iter()
        .enumerate()
        .filter(|(_, p)| p.measured_rtt_ms <= decision.latency_guard_ms)
        .map(|(i, _)| i)
        .collect();

    if eligible.is_empty() {
        return empty_plan(DegradationReason::NoEligiblePaths);
    }

    // Step 2 — rank eligible paths deterministically.
    let ranked = rank_eligible(candidates, &eligible);

    // Step 3 — select up to shadow_paths.
    let n_select = ranked.len().min(decision.shadow_paths as usize);
    let path_degradation: Option<DegradationReason> = if n_select < decision.shadow_paths as usize {
        Some(DegradationReason::InsufficientPaths {
            requested: decision.shadow_paths,
            available: n_select as u8,
        })
    } else {
        None
    };

    // Collect selected paths, sorted by path_id for deterministic iteration.
    let mut selected: Vec<&CandidatePath> =
        ranked[..n_select].iter().map(|&i| &candidates[i]).collect();
    selected.sort_by_key(|p| p.path_id);

    // Step 4 — compute total cover budget.
    let total_cover_kbps =
        compute_total_cover_kbps(real_flow_bandwidth_kbps, decision.cover_flow_ratio);

    // Step 5 — water-fill bandwidth distribution.
    let (allocations, bw_degradation) = water_fill(&selected, total_cover_kbps);

    // Step 6 — resolve final degradation.
    // BandwidthConstrained takes priority over InsufficientPaths (design §9.2).
    let (degraded, degradation_reason) = match (path_degradation, bw_degradation) {
        (_, Some(bw)) => (true, Some(bw)),
        (Some(path), None) => (true, Some(path)),
        (None, None) => (false, None),
    };

    let total_cover_bandwidth_kbps = allocations.iter().map(|a| a.cover_bandwidth_kbps).sum();
    let effective_shadow_paths = allocations.len() as u8;

    FragmentPlan {
        allocations,
        total_cover_bandwidth_kbps,
        effective_shadow_paths,
        degraded,
        degradation_reason,
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn empty_plan(reason: DegradationReason) -> FragmentPlan {
    FragmentPlan {
        allocations: vec![],
        total_cover_bandwidth_kbps: 0,
        effective_shadow_paths: 0,
        degraded: true,
        degradation_reason: Some(reason),
    }
}

/// Convert `f32` reliability to fixed-point `u32` safe for integer comparison.
/// NaN and out-of-range values map to 0 or 1_000_000 respectively.
fn reliability_fixed(r: f32) -> u32 {
    if r.is_nan() || r <= 0.0 {
        0
    } else if r >= 1.0 {
        1_000_000
    } else {
        (r * 1_000_000.0) as u32
    }
}

/// Composite ranking key for descending sort:
///   (reliability_fixed, available_bandwidth_kbps, u64::MAX − path_id)
///
/// Higher tuple = better rank. The tiebreaker `u64::MAX − path_id` is larger
/// for lower `path_id` values, so lower IDs win ties.
fn ranking_key(path: &CandidatePath) -> (u32, u32, u64) {
    (
        reliability_fixed(path.reliability_score),
        path.available_bandwidth_kbps,
        u64::MAX - path.path_id,
    )
}

fn rank_eligible(candidates: &[CandidatePath], eligible_indices: &[usize]) -> Vec<usize> {
    let mut ranked = eligible_indices.to_vec();
    // Descending: compare (b, a) so higher keys sort first.
    ranked.sort_by(|&a, &b| ranking_key(&candidates[b]).cmp(&ranking_key(&candidates[a])));
    ranked
}

/// Convert `cover_flow_ratio` × `real_flow_kbps` to an integer kbps budget.
/// Uses saturating arithmetic to prevent overflow on large flows.
fn compute_total_cover_kbps(real_flow_kbps: u32, cover_flow_ratio: f32) -> u32 {
    if cover_flow_ratio <= 0.0 || real_flow_kbps == 0 {
        return 0;
    }
    // Scale ratio to fixed-point (×1000) then divide back out.
    let ratio_fixed = (cover_flow_ratio.clamp(0.0, 100.0) * 1000.0) as u32;
    real_flow_kbps.saturating_mul(ratio_fixed) / 1000
}

/// Distribute `total_cover_kbps` across `selected` paths using the water-fill
/// algorithm (design §6). `selected` must already be sorted by `path_id`.
///
/// Returns `(allocations, bw_degradation)`. `bw_degradation` is
/// `Some(BandwidthConstrained)` when combined path capacity is insufficient.
fn water_fill(
    selected: &[&CandidatePath],
    total_cover_kbps: u32,
) -> (Vec<PathAllocation>, Option<DegradationReason>) {
    let n = selected.len();

    // Bandwidth constraint pre-check.
    let total_capacity: u32 = selected
        .iter()
        .map(|p| p.available_bandwidth_kbps)
        .fold(0u32, |acc, x| acc.saturating_add(x));

    let bw_degradation = if total_capacity < total_cover_kbps {
        Some(DegradationReason::BandwidthConstrained {
            requested_kbps: total_cover_kbps,
            available_kbps: total_capacity,
        })
    } else {
        None
    };

    // Initial weights from reliability scores.
    let total_reliability: f32 = selected.iter().map(|p| p.reliability_score.max(0.0)).sum();
    let weights: Vec<f32> = if total_reliability <= 0.0 {
        // All paths have zero or negative reliability: fall back to uniform.
        vec![1.0 / n as f32; n]
    } else {
        selected
            .iter()
            .map(|p| p.reliability_score.max(0.0) / total_reliability)
            .collect()
    };

    // Water-fill iteration.
    let mut allocated = vec![0u32; n];
    let mut capped = vec![false; n];
    let mut remaining = total_cover_kbps;

    loop {
        let active_weight_sum: f32 = weights
            .iter()
            .enumerate()
            .filter(|(i, _)| !capped[*i])
            .map(|(_, &w)| w)
            .sum();

        if active_weight_sum <= 0.0 {
            break;
        }

        let mut any_newly_capped = false;

        // Iterate in ascending path_id order (selected is pre-sorted).
        for i in 0..n {
            if capped[i] {
                continue;
            }
            let share = ((remaining as f32) * weights[i] / active_weight_sum).round() as u32;
            let cap = selected[i].available_bandwidth_kbps;

            if share >= cap {
                allocated[i] = cap;
                remaining = remaining.saturating_sub(cap);
                capped[i] = true;
                any_newly_capped = true;
            } else {
                allocated[i] = share;
            }
        }

        if !any_newly_capped {
            break;
        }
    }

    // Normalise weights from actual allocations so weight reflects reality.
    let actual_total: u32 = allocated.iter().sum();
    let final_weights: Vec<f32> = if actual_total > 0 {
        allocated
            .iter()
            .map(|&a| a as f32 / actual_total as f32)
            .collect()
    } else {
        vec![0.0; n]
    };

    // Assemble output. `selected` is already in path_id order.
    let allocations = selected
        .iter()
        .zip(allocated.iter())
        .zip(final_weights.iter())
        .map(|((path, &bw), &w)| PathAllocation {
            path_id: path.path_id,
            weight: w,
            cover_bandwidth_kbps: bw,
        })
        .collect();

    (allocations, bw_degradation)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_shadower::ShadowDecision;

    fn candidate(id: u64, rtt: u32, bw: u32, rel: f32) -> CandidatePath {
        CandidatePath {
            path_id: id,
            measured_rtt_ms: rtt,
            available_bandwidth_kbps: bw,
            reliability_score: rel,
        }
    }

    fn baseline_decision() -> ShadowDecision {
        ShadowDecision {
            shadow_probability: 0.10,
            shadow_paths: 2,
            cover_flow_ratio: 0.15,
            bandwidth_budget: 0.015,
            latency_guard_ms: 80,
        }
    }

    fn is_no_eligible_paths(r: &Option<DegradationReason>) -> bool {
        matches!(r, Some(DegradationReason::NoEligiblePaths))
    }

    fn is_insufficient_paths(r: &Option<DegradationReason>, req: u8, avail: u8) -> bool {
        matches!(
            r,
            Some(DegradationReason::InsufficientPaths {
                requested,
                available,
            }) if *requested == req && *available == avail
        )
    }

    fn is_bandwidth_constrained(r: &Option<DegradationReason>) -> bool {
        matches!(r, Some(DegradationReason::BandwidthConstrained { .. }))
    }

    // ── Test 1 ───────────────────────────────────────────────────────────────

    #[test]
    fn single_eligible_path_allocated() {
        let decision = ShadowDecision {
            shadow_probability: 0.35,
            shadow_paths: 1,
            cover_flow_ratio: 0.5,
            bandwidth_budget: 0.175,
            latency_guard_ms: 80,
        };
        let candidates = [candidate(1, 50, 1000, 0.8)];
        let plan = build_fragment_plan(&decision, &candidates, 1000);

        assert_eq!(plan.allocations.len(), 1);
        assert_eq!(plan.effective_shadow_paths, 1);
        assert!(!plan.degraded);
        assert!(plan.degradation_reason.is_none());
        assert!((plan.allocations[0].weight - 1.0).abs() < 1e-5);
        assert_eq!(plan.allocations[0].path_id, 1);
    }

    // ── Test 2 ───────────────────────────────────────────────────────────────

    #[test]
    fn all_paths_exceed_latency_guard() {
        let candidates = [candidate(1, 100, 500, 0.8), candidate(2, 200, 500, 0.9)];
        let plan = build_fragment_plan(&baseline_decision(), &candidates, 1000);

        assert_eq!(plan.allocations.len(), 0);
        assert_eq!(plan.effective_shadow_paths, 0);
        assert!(plan.degraded);
        assert!(is_no_eligible_paths(&plan.degradation_reason));
    }

    // ── Test 3 ───────────────────────────────────────────────────────────────

    #[test]
    fn latency_guard_boundary_inclusive() {
        let decision = ShadowDecision {
            shadow_probability: 0.35,
            shadow_paths: 2,
            cover_flow_ratio: 0.4,
            bandwidth_budget: 0.14,
            latency_guard_ms: 80,
        };
        // id=1 at RTT==80 is eligible; id=2 at RTT==81 is not.
        let candidates = [candidate(1, 80, 500, 0.8), candidate(2, 81, 500, 0.8)];
        let plan = build_fragment_plan(&decision, &candidates, 1000);

        assert_eq!(plan.effective_shadow_paths, 1);
        assert_eq!(plan.allocations[0].path_id, 1);
        assert!(plan.degraded);
        assert!(is_insufficient_paths(&plan.degradation_reason, 2, 1));
    }

    // ── Test 4 ───────────────────────────────────────────────────────────────

    #[test]
    fn insufficient_paths_degradation() {
        let decision = ShadowDecision {
            shadow_probability: 0.70,
            shadow_paths: 4,
            cover_flow_ratio: 0.9,
            bandwidth_budget: 0.63,
            latency_guard_ms: 300,
        };
        let candidates = [candidate(1, 50, 500, 0.7), candidate(2, 80, 500, 0.6)];
        let plan = build_fragment_plan(&decision, &candidates, 1000);

        assert_eq!(plan.effective_shadow_paths, 2);
        assert!(plan.degraded);
        assert!(is_insufficient_paths(&plan.degradation_reason, 4, 2));
    }

    // ── Test 5 ───────────────────────────────────────────────────────────────

    #[test]
    fn bandwidth_constrained_scales_down() {
        // total cap = 30 + 30 = 60; cover budget = 1000 * 0.15 = 150 > 60.
        let candidates = [candidate(1, 20, 30, 0.5), candidate(2, 20, 30, 0.5)];
        let plan = build_fragment_plan(&baseline_decision(), &candidates, 1000);

        assert!(plan.degraded);
        assert!(is_bandwidth_constrained(&plan.degradation_reason));
        assert!(plan.total_cover_bandwidth_kbps <= 60);
    }

    // ── Test 6 ───────────────────────────────────────────────────────────────

    #[test]
    fn weights_sum_to_one() {
        let decision = ShadowDecision {
            shadow_probability: 0.70,
            shadow_paths: 3,
            cover_flow_ratio: 0.4,
            bandwidth_budget: 0.28,
            latency_guard_ms: 150,
        };
        let candidates = [
            candidate(1, 30, 500, 0.5),
            candidate(2, 40, 500, 0.3),
            candidate(3, 50, 500, 0.2),
        ];
        let plan = build_fragment_plan(&decision, &candidates, 1000);

        let weight_sum: f32 = plan.allocations.iter().map(|a| a.weight).sum();
        assert!(
            (weight_sum - 1.0).abs() < 1e-5,
            "weights sum {weight_sum} != 1.0"
        );
    }

    // ── Test 7 ───────────────────────────────────────────────────────────────

    #[test]
    fn bandwidth_budget_equals_cover_ratio_times_flow() {
        // Two equal paths with plenty of capacity — no capping, no constraint.
        let decision = ShadowDecision {
            shadow_probability: 0.35,
            shadow_paths: 2,
            cover_flow_ratio: 0.4,
            bandwidth_budget: 0.14,
            latency_guard_ms: 150,
        };
        let candidates = [candidate(1, 30, 5000, 0.5), candidate(2, 30, 5000, 0.5)];
        let plan = build_fragment_plan(&decision, &candidates, 1000);

        // Expected: 1000 * 0.4 = 400 kbps. Allow ±2 for integer rounding.
        let expected = 400u32;
        assert!(
            plan.total_cover_bandwidth_kbps.abs_diff(expected) <= 2,
            "total {} != expected {}",
            plan.total_cover_bandwidth_kbps,
            expected
        );
    }

    // ── Test 8 ───────────────────────────────────────────────────────────────

    #[test]
    fn higher_reliability_gets_more_bandwidth() {
        let decision = ShadowDecision {
            shadow_probability: 0.35,
            shadow_paths: 2,
            cover_flow_ratio: 0.5,
            bandwidth_budget: 0.175,
            latency_guard_ms: 150,
        };
        // id=1: rel=0.8 (higher), id=2: rel=0.2 (lower). Equal caps.
        let candidates = [candidate(1, 20, 2000, 0.8), candidate(2, 20, 2000, 0.2)];
        let plan = build_fragment_plan(&decision, &candidates, 1000);

        let alloc_1 = plan.allocations.iter().find(|a| a.path_id == 1).unwrap();
        let alloc_2 = plan.allocations.iter().find(|a| a.path_id == 2).unwrap();
        assert!(
            alloc_1.cover_bandwidth_kbps > alloc_2.cover_bandwidth_kbps,
            "rel=0.8 path got {} kbps, rel=0.2 path got {} kbps",
            alloc_1.cover_bandwidth_kbps,
            alloc_2.cover_bandwidth_kbps
        );
    }

    // ── Test 9 ───────────────────────────────────────────────────────────────

    #[test]
    fn zero_reliability_gets_uniform_fallback() {
        let decision = ShadowDecision {
            shadow_probability: 0.35,
            shadow_paths: 2,
            cover_flow_ratio: 0.5,
            bandwidth_budget: 0.175,
            latency_guard_ms: 150,
        };
        // Both paths have reliability 0.0 — must fall back to uniform distribution.
        let candidates = [candidate(1, 20, 2000, 0.0), candidate(2, 20, 2000, 0.0)];
        let plan = build_fragment_plan(&decision, &candidates, 1000);

        let alloc_1 = plan.allocations.iter().find(|a| a.path_id == 1).unwrap();
        let alloc_2 = plan.allocations.iter().find(|a| a.path_id == 2).unwrap();
        // Uniform: each weight ≈ 0.5, bandwidths should be equal.
        assert!(
            (alloc_1.weight - alloc_2.weight).abs() < 1e-5,
            "uniform fallback weights differ: {} vs {}",
            alloc_1.weight,
            alloc_2.weight
        );
    }

    // ── Test 10 ──────────────────────────────────────────────────────────────

    #[test]
    fn zero_cover_ratio_no_bandwidth_no_degradation() {
        let decision = ShadowDecision {
            shadow_probability: 0.35,
            shadow_paths: 1,
            cover_flow_ratio: 0.0,
            bandwidth_budget: 0.0,
            latency_guard_ms: 80,
        };
        let candidates = [candidate(1, 30, 500, 0.8)];
        let plan = build_fragment_plan(&decision, &candidates, 1000);

        assert!(!plan.degraded);
        assert!(plan.degradation_reason.is_none());
        assert!(plan.allocations.iter().all(|a| a.cover_bandwidth_kbps == 0));
    }

    // ── Test 11 ──────────────────────────────────────────────────────────────

    #[test]
    fn shadow_paths_zero_returns_empty_no_degradation() {
        let decision = ShadowDecision {
            shadow_probability: 0.0,
            shadow_paths: 0,
            cover_flow_ratio: 0.0,
            bandwidth_budget: 0.0,
            latency_guard_ms: 80,
        };
        let candidates = [candidate(1, 10, 1000, 0.9)];
        let plan = build_fragment_plan(&decision, &candidates, 1000);

        assert_eq!(plan.allocations.len(), 0);
        assert_eq!(plan.effective_shadow_paths, 0);
        assert!(!plan.degraded);
        assert!(plan.degradation_reason.is_none());
    }

    // ── Test 12 ──────────────────────────────────────────────────────────────

    #[test]
    fn output_sorted_by_path_id() {
        let decision = ShadowDecision {
            shadow_probability: 0.70,
            shadow_paths: 3,
            cover_flow_ratio: 0.4,
            bandwidth_budget: 0.28,
            latency_guard_ms: 150,
        };
        // Supply candidates in reverse path_id order.
        let candidates = [
            candidate(30, 40, 500, 0.4),
            candidate(10, 40, 500, 0.3),
            candidate(20, 40, 500, 0.3),
        ];
        let plan = build_fragment_plan(&decision, &candidates, 1000);

        let ids: Vec<u64> = plan.allocations.iter().map(|a| a.path_id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "allocations not sorted by path_id: {ids:?}");
    }

    // ── Test 13 ──────────────────────────────────────────────────────────────

    #[test]
    fn determinism_input_order_invariant() {
        let decision = ShadowDecision {
            shadow_probability: 0.35,
            shadow_paths: 2,
            cover_flow_ratio: 0.4,
            bandwidth_budget: 0.14,
            latency_guard_ms: 150,
        };
        let order_a = [candidate(1, 30, 400, 0.7), candidate(2, 40, 600, 0.3)];
        let order_b = [candidate(2, 40, 600, 0.3), candidate(1, 30, 400, 0.7)];

        let plan_a = build_fragment_plan(&decision, &order_a, 1000);
        let plan_b = build_fragment_plan(&decision, &order_b, 1000);

        assert_eq!(plan_a.allocations.len(), plan_b.allocations.len());
        assert_eq!(
            plan_a.total_cover_bandwidth_kbps,
            plan_b.total_cover_bandwidth_kbps
        );
        assert_eq!(plan_a.effective_shadow_paths, plan_b.effective_shadow_paths);
        assert_eq!(plan_a.degraded, plan_b.degraded);
        for (a, b) in plan_a.allocations.iter().zip(plan_b.allocations.iter()) {
            assert_eq!(a.path_id, b.path_id);
            assert_eq!(a.cover_bandwidth_kbps, b.cover_bandwidth_kbps);
            assert!((a.weight - b.weight).abs() < 1e-6);
        }
    }

    // ── Test 14 ──────────────────────────────────────────────────────────────

    #[test]
    fn cap_triggers_redistribution() {
        // Path 1: high reliability but low cap (20 kbps). Gets capped quickly.
        // Path 2: low reliability but high cap (500 kbps). Must absorb overflow.
        let decision = ShadowDecision {
            shadow_probability: 0.35,
            shadow_paths: 2,
            cover_flow_ratio: 0.4,
            bandwidth_budget: 0.14,
            latency_guard_ms: 150,
        };
        let candidates = [candidate(1, 20, 20, 0.8), candidate(2, 20, 500, 0.2)];
        let plan = build_fragment_plan(&decision, &candidates, 1000);
        // total_cover = 1000 * 400/1000 = 400.
        // Initial: p1 gets 320 (capped to 20), remainder 380 goes to p2.
        let alloc_1 = plan.allocations.iter().find(|a| a.path_id == 1).unwrap();
        let alloc_2 = plan.allocations.iter().find(|a| a.path_id == 2).unwrap();

        assert_eq!(alloc_1.cover_bandwidth_kbps, 20);
        // p2 must have absorbed the overflow — well above its unredistributed share.
        assert!(
            alloc_2.cover_bandwidth_kbps > 80,
            "redistribution did not occur: p2 got only {} kbps",
            alloc_2.cover_bandwidth_kbps
        );
    }

    // ── Test 15 ──────────────────────────────────────────────────────────────

    #[test]
    fn path_with_zero_bandwidth_cap_excluded() {
        let decision = ShadowDecision {
            shadow_probability: 0.35,
            shadow_paths: 2,
            cover_flow_ratio: 0.4,
            bandwidth_budget: 0.14,
            latency_guard_ms: 150,
        };
        // Path 1 has cap=0; all cover traffic must go to path 2.
        let candidates = [candidate(1, 20, 0, 0.8), candidate(2, 20, 500, 0.2)];
        let plan = build_fragment_plan(&decision, &candidates, 1000);

        let alloc_1 = plan.allocations.iter().find(|a| a.path_id == 1).unwrap();
        let alloc_2 = plan.allocations.iter().find(|a| a.path_id == 2).unwrap();

        assert_eq!(alloc_1.cover_bandwidth_kbps, 0);
        assert!((alloc_1.weight - 0.0).abs() < 1e-6);
        assert!(alloc_2.cover_bandwidth_kbps > 0);
    }

    // ── Test 16 ──────────────────────────────────────────────────────────────

    #[test]
    fn empty_candidates_slice() {
        let plan = build_fragment_plan(&baseline_decision(), &[], 1000);

        assert_eq!(plan.allocations.len(), 0);
        assert!(plan.degraded);
        assert!(is_no_eligible_paths(&plan.degradation_reason));
    }

    // ── Test 17 ──────────────────────────────────────────────────────────────

    #[test]
    fn tiebreaker_lower_path_id_wins() {
        // Paths are identical except for path_id. Only 1 selected.
        let decision = ShadowDecision {
            shadow_probability: 0.10,
            shadow_paths: 1,
            cover_flow_ratio: 0.15,
            bandwidth_budget: 0.015,
            latency_guard_ms: 80,
        };
        let candidates = [candidate(10, 30, 100, 0.5), candidate(5, 30, 100, 0.5)];
        let plan = build_fragment_plan(&decision, &candidates, 1000);

        assert_eq!(plan.allocations.len(), 1);
        assert_eq!(
            plan.allocations[0].path_id, 5,
            "lower path_id should win the tiebreak"
        );
    }

    // ── Test 18 ──────────────────────────────────────────────────────────────

    #[test]
    fn voip_latency_guard_40ms_enforced() {
        // VoIP guard: latency_guard_ms = 40. A path at RTT=41 must be excluded.
        let decision = ShadowDecision {
            shadow_probability: 0.05,
            shadow_paths: 1,
            cover_flow_ratio: 0.10,
            bandwidth_budget: 0.005,
            latency_guard_ms: 40,
        };
        let candidates = [candidate(1, 41, 500, 0.8)];
        let plan = build_fragment_plan(&decision, &candidates, 1000);

        assert_eq!(plan.allocations.len(), 0);
        assert!(plan.degraded);
        assert!(is_no_eligible_paths(&plan.degradation_reason));
    }
}
