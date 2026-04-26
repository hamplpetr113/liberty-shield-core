# PathFragmenter — Architecture Design
# Sprint 6 Phase 2

**Status:** Design (pre-implementation)
**Sprint:** 6 Phase 2
**Date:** 2026-04-26
**Depends on:** Sprint 6 Phase 1 — RouteShadower (`route_shadower.rs`, frozen)

---

## 1. Position in the Pipeline

```
DecisionInputs
    │
    ▼
route_shadower::resolve_shadow_params()
    │
    ▼
ShadowDecision
{ shadow_probability, shadow_paths, cover_flow_ratio,
  bandwidth_budget, latency_guard_ms }
    │
    │  [Caller flips coin: rand_f32() < shadow_probability]
    │  [Only calls PathFragmenter when coin = true]
    │
    ▼
path_fragmenter::build_fragment_plan(decision, candidates, real_flow_kbps)
    │
    ▼
FragmentPlan
{ allocations: Vec<PathAllocation>, total_cover_kbps,
  effective_shadow_paths, degraded, degradation_reason }
    │
    ▼
(Sprint 6 Phase 3) Transmitter::execute(plan)
```

`build_fragment_plan` is called only when shadowing has already been decided by
the probabilistic coin flip. This keeps the function fully deterministic — it
never calls a random number generator.

---

## 2. Module Responsibilities

PathFragmenter translates the abstract shadow parameters from RouteShadower into
a concrete, path-specific allocation plan. It does not transmit packets.

Specific responsibilities:

1. **Enforce `latency_guard_ms`** — filter out any candidate path whose measured
   RTT exceeds the guard (Rule 6.8, deferred from Phase 1).

2. **Select paths** — choose up to `shadow_paths` paths from the eligible set
   using a deterministic ranking function.

3. **Distribute bandwidth** — assign a share of the cover bandwidth budget to
   each selected path, proportional to reliability, capped by path capacity.

4. **Handle degradation** — when fewer paths than requested are available, or
   when combined path capacity is insufficient, produce the best plan possible
   and record the degradation condition rather than returning an error.

5. **Guarantee determinism** — given identical inputs (regardless of slice
   ordering), always produce identical output. No mutable global state.

What PathFragmenter does **not** do:

- Transmit cover packets.
- Measure RTT or bandwidth (those values are provided by the caller).
- Flip the probabilistic coin against `shadow_probability` (the caller does that).
- Hold state between calls.

---

## 3. Data Structures

### 3.1 Inputs

```rust
/// A single egress path offered by the route manager.
pub struct CandidatePath {
    /// Stable identifier assigned by the route manager.
    /// Used as the tiebreaker in all ranking and redistribution steps to
    /// guarantee determinism regardless of input slice order.
    pub path_id: u64,

    /// Most recent measured round-trip time in milliseconds.
    /// Compared against ShadowDecision::latency_guard_ms for Rule 6.8.
    pub measured_rtt_ms: u32,

    /// Available bandwidth headroom on this path in kbps.
    /// Allocations are capped at this value per path.
    pub available_bandwidth_kbps: u32,

    /// Historical delivery success rate, [0.0, 1.0].
    /// Used as the primary weight in bandwidth distribution.
    /// A path with reliability 0.0 is excluded from weighting.
    pub reliability_score: f32,
}
```

### 3.2 Output

```rust
/// The bandwidth assignment for one selected shadow path.
pub struct PathAllocation {
    pub path_id: u64,

    /// Fraction of total cover bandwidth assigned to this path, in (0.0, 1.0].
    /// All weights across a FragmentPlan sum to 1.0 (within f32 epsilon)
    /// unless the plan is empty.
    pub weight: f32,

    /// Absolute bandwidth to generate as cover traffic on this path, in kbps.
    /// Equals total_cover_kbps * weight, capped at CandidatePath::available_bandwidth_kbps.
    pub cover_bandwidth_kbps: u32,
}

/// Reason the plan was produced at reduced capacity.
pub enum DegradationReason {
    /// All candidate paths exceeded latency_guard_ms.
    /// allocations will be empty. Caller should rely on temporal decoupling only.
    NoEligiblePaths,

    /// Fewer eligible paths than shadow_paths requested.
    /// Shadowing proceeds at reduced path count.
    InsufficientPaths { requested: u8, available: u8 },

    /// Combined capacity of selected paths is less than the full cover budget.
    /// Cover was scaled down to the maximum the paths can carry.
    BandwidthConstrained { requested_kbps: u32, available_kbps: u32 },
}

/// The complete shadow allocation plan for one flow.
///
/// Always returned — never an error. Degradation is signalled via `degraded`
/// and `degradation_reason` so the caller can log or adjust without branching
/// on a Result.
///
/// `allocations` is sorted by `path_id` ascending for stable, reproducible output.
pub struct FragmentPlan {
    pub allocations: Vec<PathAllocation>,
    pub total_cover_bandwidth_kbps: u32,
    /// May be less than ShadowDecision::shadow_paths when paths were degraded.
    pub effective_shadow_paths: u8,
    pub degraded: bool,
    pub degradation_reason: Option<DegradationReason>,
}
```

### 3.3 Public API

```rust
/// Compute the shadow path allocation plan for a single flow.
///
/// `decision`               — output of resolve_shadow_params(); caller has
///                            already decided to shadow this flow.
/// `candidates`             — current snapshot of available egress paths from
///                            the route manager; may be in any order.
/// `real_flow_bandwidth_kbps` — measured or estimated bandwidth of the real
///                            flow; used to convert cover_flow_ratio to kbps.
///
/// Returns a FragmentPlan. Never panics. Always returns even when all paths
/// are ineligible (returns an empty, degraded plan).
pub fn build_fragment_plan(
    decision: &ShadowDecision,
    candidates: &[CandidatePath],
    real_flow_bandwidth_kbps: u32,
) -> FragmentPlan
```

---

## 4. Internal Function Decomposition

All helpers are private (`fn`, not `pub fn`). Each is a pure function.

```
build_fragment_plan(decision, candidates, real_flow_kbps) → FragmentPlan
  │
  ├── filter_by_latency(candidates, guard_ms) → Vec<usize>
  │     Returns indices into `candidates` where measured_rtt_ms ≤ guard_ms.
  │
  ├── rank_eligible(candidates, eligible_indices) → Vec<usize>
  │     Sorts eligible indices by composite ranking key (descending).
  │     Ties broken by path_id ascending (stable, deterministic).
  │
  ├── ranking_key(path) → (u32, u32, u64)
  │     (reliability_fixed_point, available_bandwidth_kbps, u64::MAX - path_id)
  │     Converts f32 reliability to u32 fixed-point to avoid float sort issues.
  │
  ├── select_paths(ranked_indices, shadow_paths) → (Vec<usize>, Option<DegradationReason>)
  │     Takes min(len, shadow_paths) indices; signals InsufficientPaths if needed.
  │
  ├── compute_total_cover_kbps(real_flow_kbps, cover_flow_ratio) → u32
  │     Saturating multiply to avoid overflow on large flows.
  │
  ├── water_fill(candidates, selected_indices, total_cover_kbps)
  │       → (Vec<PathAllocation>, Option<DegradationReason>)
  │     Core bandwidth distribution algorithm (Section 6).
  │
  └── empty_plan(reason) → FragmentPlan
        Produces a zero-allocation plan with degraded=true for early-exit cases.
```

---

## 5. Path Selection Algorithm

### Step 1 — Latency Filter (Rule 6.8 Enforcement)

```
eligible_indices = candidates
    .iter()
    .enumerate()
    .filter(|(_, p)| p.measured_rtt_ms <= decision.latency_guard_ms)
    .map(|(i, _)| i)
    .collect()

if eligible_indices.is_empty():
    return empty_plan(DegradationReason::NoEligiblePaths)
```

`latency_guard_ms` values by mode:

| Mode | latency_guard_ms |
|------|-----------------|
| NORMAL | 80 |
| PRIVACY | 150 |
| PARANOID | 300 |
| STEALTH | 60 |

### Step 2 — Ranking

Eligible paths are ranked by a three-component key, compared lexicographically
in descending order:

```
ranking_key(p) = (
    (p.reliability_score * 1_000_000.0) as u32,   // component A: reliability
    p.available_bandwidth_kbps,                     // component B: bandwidth
    u64::MAX - p.path_id,                           // component C: tiebreaker (lower id wins)
)
```

**Component A — reliability** is the primary criterion. A more reliable path
wastes fewer cover packets to drops. Converting to fixed-point integer avoids
undefined behaviour from f32 NaN/infinity comparisons and makes the sort
fully deterministic.

**Component B — available bandwidth** is the secondary criterion. Paths with
more headroom are preferred as shadow carriers; they are less likely to become
bandwidth-constrained during the water-fill phase.

**Component C — path_id tiebreaker** ensures total ordering even when two paths
have identical reliability and bandwidth. Using `u64::MAX - path_id` in a
descending sort means lower `path_id` values win ties, giving preference to
paths that have been in the route manager's list longest (lower IDs assigned
earlier).

### Step 3 — Selection

```
n_select = min(eligible_indices.len(), decision.shadow_paths as usize)
selected = ranked_indices[0..n_select]

degradation = if n_select < decision.shadow_paths:
    Some(DegradationReason::InsufficientPaths {
        requested: decision.shadow_paths,
        available: n_select as u8,
    })
  else:
    None
```

---

## 6. Bandwidth Distribution — Water-Fill Algorithm

### 6.1 Total Cover Budget

```
total_cover_kbps = real_flow_bandwidth_kbps
    .saturating_mul((decision.cover_flow_ratio * 1000.0) as u32)
    / 1000
```

Saturating arithmetic prevents overflow on very high-bandwidth flows. The
`/1000` corrects for the intermediate fixed-point scale.

If `total_cover_kbps == 0` (zero `cover_flow_ratio` or zero `real_flow_kbps`):
return a plan with allocations present but all `cover_bandwidth_kbps = 0`.
This correctly represents the situation without false degradation signals.

### 6.2 Initial Weights

Weights are proportional to `reliability_score` across selected paths:

```
total_reliability = selected.iter().map(|p| p.reliability_score).sum()

if total_reliability == 0.0:
    // All selected paths have reliability 0.0.
    // Fall back to uniform distribution.
    weight[i] = 1.0 / n_select

else:
    weight[i] = path[i].reliability_score / total_reliability
```

### 6.3 Water-Fill Iteration

Cover bandwidth is distributed iteratively to respect per-path capacity caps.

```
remaining_budget = total_cover_kbps
allocated = [0u32; n_select]      // result array
capped    = [false; n_select]     // true once a path reaches its cap

loop:
    // Compute weight sum among uncapped paths only.
    active_weight_sum = sum(weight[i] for i where !capped[i])

    if active_weight_sum == 0.0: break

    any_newly_capped = false

    for i in 0..n_select (ascending path_id order for determinism):
        if capped[i]: continue

        share = (remaining_budget as f32 * weight[i] / active_weight_sum)
                    .round() as u32

        cap = selected_paths[i].available_bandwidth_kbps

        if share >= cap:
            allocated[i] = cap
            remaining_budget -= cap
            capped[i] = true
            any_newly_capped = true
        else:
            allocated[i] = share

    if !any_newly_capped: break
```

Convergence: each iteration caps at least one path. With `n_select` paths,
the loop terminates in at most `n_select` iterations.

### 6.4 Bandwidth Constraint Detection

Before the loop, check whether total capacity across selected paths is
sufficient:

```
total_path_capacity = selected.iter().map(|p| p.available_bandwidth_kbps).sum()

if total_path_capacity < total_cover_kbps:
    // Scale down: we will fill to capacity but no more.
    degradation = Some(DegradationReason::BandwidthConstrained {
        requested_kbps: total_cover_kbps,
        available_kbps: total_path_capacity,
    })
    // Proceed with water-fill; all paths will be capped.
```

### 6.5 Final Weight Normalisation

After the water-fill loop, recompute weights from actual allocations so that
`weight` in each `PathAllocation` accurately reflects what was assigned:

```
actual_total = allocated.iter().sum()

if actual_total > 0:
    weight[i] = allocated[i] as f32 / actual_total as f32
else:
    weight[i] = 0.0   // zero-budget plan
```

### 6.6 Output Assembly

```
allocations = selected_paths
    .iter()
    .zip(allocated.iter())
    .zip(weights.iter())
    .map(|((path, &bw), &w)| PathAllocation {
        path_id: path.path_id,
        weight: w,
        cover_bandwidth_kbps: bw,
    })
    .sorted_by_key(|a| a.path_id)   // ascending path_id for deterministic output
    .collect()
```

---

## 7. Latency Guard Enforcement Details

`latency_guard_ms` is set by RouteShadower based on operating mode and is
already adjusted for VoIP (capped at 40 ms by Rule 6.2). PathFragmenter
enforces it strictly:

- A path with `measured_rtt_ms == latency_guard_ms` is **eligible** (≤, not <).
- A path with `measured_rtt_ms == latency_guard_ms + 1` is **ineligible**.
- RTT jitter is the caller's responsibility: PathFragmenter acts only on the
  snapshot value provided. If the caller wants jitter margin, it should subtract
  a headroom value before passing `measured_rtt_ms`.

This boundary behaviour is testable and must be verified by unit tests.

---

## 8. Interaction with RouteShadower

### 8.1 Contract

RouteShadower produces a `ShadowDecision`. PathFragmenter consumes it.
PathFragmenter **does not call** `resolve_shadow_params` — it only reads
the decision struct fields:

| `ShadowDecision` field | How PathFragmenter uses it |
|------------------------|---------------------------|
| `shadow_probability` | Not consumed by PathFragmenter. Caller uses it for the coin flip before calling `build_fragment_plan`. |
| `shadow_paths` | Upper bound on `n_select` in Step 3 of path selection. |
| `cover_flow_ratio` | Multiplied by `real_flow_bandwidth_kbps` to compute `total_cover_kbps`. |
| `bandwidth_budget` | Not directly used. It equals `shadow_probability * cover_flow_ratio` and is the budget the caller expects. PathFragmenter works only with `cover_flow_ratio`. |
| `latency_guard_ms` | Threshold for the latency filter (Step 1). |

### 8.2 `shadow_paths = 0` Handling

When RouteShadower sets `shadow_paths = 0` (Rule 6.1 Banking/Login exclusion,
or Rule 6.6 path availability gate), the call to `build_fragment_plan` should
not occur. However, if it is called with `shadow_paths = 0`, PathFragmenter
returns an empty plan without degradation signalling (zero paths is the
requested spec; it was fulfilled exactly).

```
if decision.shadow_paths == 0:
    return FragmentPlan {
        allocations: vec![],
        total_cover_bandwidth_kbps: 0,
        effective_shadow_paths: 0,
        degraded: false,
        degradation_reason: None,
    }
```

### 8.3 Probabilistic Sampling Boundary

The `shadow_probability` field exists for the **caller** to decide whether
to shadow a given flow at all. PathFragmenter is only called when the answer
is yes. This design choice keeps PathFragmenter deterministic:

```
// Caller code (not in PathFragmenter)
let decision = resolve_shadow_params(&inputs);
if sampled_f32 < decision.shadow_probability {
    let plan = build_fragment_plan(&decision, &candidates, real_flow_kbps);
    transmitter.execute(plan);
}
```

---

## 9. Failure Handling — Path Degradation

### 9.1 Taxonomy

| Condition | `degraded` | `degradation_reason` | `allocations` |
|-----------|------------|---------------------|---------------|
| All paths pass latency guard, capacity sufficient | false | None | Full plan |
| All paths exceed latency guard | true | `NoEligiblePaths` | Empty |
| Some paths eligible, fewer than `shadow_paths` | true | `InsufficientPaths` | Partial plan |
| Combined capacity < cover budget | true | `BandwidthConstrained` | Scaled-down plan |
| Multiple conditions | true | Most severe (see §9.2) | Best possible |

### 9.2 Multiple Simultaneous Conditions

When both `InsufficientPaths` and `BandwidthConstrained` apply simultaneously
(e.g. only 1 of 4 requested paths is eligible, and that path lacks capacity),
report `BandwidthConstrained` because it more accurately describes the
operative limit on cover-traffic effectiveness. The `effective_shadow_paths`
field records the actual path count regardless.

### 9.3 Caller Behaviour on Degradation

PathFragmenter does not take corrective action. It informs the caller. The
caller's expected behaviour is:

| `degradation_reason` | Caller action |
|---------------------|---------------|
| `NoEligiblePaths` | Log at INFO level; proceed without shadow routes; temporal decoupling provides residual protection |
| `InsufficientPaths` | Use the partial plan; log at DEBUG level |
| `BandwidthConstrained` | Use the scaled plan; consider reducing `cover_flow_ratio` in future RouteShadower inputs if this recurs |

### 9.4 Degradation Does Not Cascade to RouteShadower

PathFragmenter never feeds back into RouteShadower within the same call.
The two modules are strictly layered. If persistent degradation warrants
parameter adjustment (e.g. reducing `shadow_paths` to match persistent path
availability), that is a higher-level policy concern resolved outside both
modules.

---

## 10. Determinism Guarantee

Every source of non-determinism is explicitly eliminated:

| Potential source | Elimination |
|-----------------|-------------|
| Input slice ordering | Sort by `path_id` before processing; all intermediate steps iterate in `path_id` order |
| f32 sort instability | Convert `reliability_score` to fixed-point `u32` before sorting |
| f32 rounding in water-fill | Use integer arithmetic (u32 kbps) throughout; f32 used only for weight ratios, never for control flow |
| Multiple degradation conditions | Deterministic priority rule (§9.2) |
| Zero reliability scores | Explicit fallback to uniform distribution |
| Zero cover budget | Explicit early return before weight computation |

The function is also free of interior mutability, global state, thread-locals,
and I/O — all preconditions for side-effect freedom.

---

## 11. Edge Cases

| Input | Expected behaviour |
|-------|--------------------|
| `candidates` is empty | `NoEligiblePaths` (empty slice passes the filter with no results) |
| `shadow_paths = 0` | Empty plan, `degraded = false` (spec was met) |
| `cover_flow_ratio = 0.0` | `total_cover_kbps = 0`; allocations present with `cover_bandwidth_kbps = 0`; `degraded = false` |
| `real_flow_bandwidth_kbps = 0` | Same as above |
| All paths have `reliability_score = 0.0` | Uniform weight distribution applied |
| Single path available, `shadow_paths = 4` | `InsufficientPaths { requested: 4, available: 1 }` |
| Path with `available_bandwidth_kbps = 0` | Cap = 0 kbps; immediately capped in water-fill; receives `weight = 0.0`, `cover_bandwidth_kbps = 0` |
| `latency_guard_ms = 0` | All paths with `measured_rtt_ms > 0` are ineligible; only paths reporting 0 ms RTT pass (degenerate but handled) |
| `measured_rtt_ms == latency_guard_ms` | Eligible (boundary is inclusive ≤) |

---

## 12. Unit Test Specification

Tests live in `#[cfg(test)] mod tests` inside `path_fragmenter.rs`.
A `candidate(id, rtt, bw, rel)` helper constructs `CandidatePath` values.
A `baseline_decision()` helper returns a NORMAL-mode `ShadowDecision`.

| # | Test name | Key assertion |
|---|-----------|---------------|
| 1 | `single_eligible_path_allocated` | 1 candidate within guard → 1 allocation, weight = 1.0 |
| 2 | `all_paths_exceed_latency_guard` | all RTT > guard → empty plan, `NoEligiblePaths` |
| 3 | `latency_guard_boundary_inclusive` | RTT == guard → eligible; RTT == guard + 1 → ineligible |
| 4 | `insufficient_paths_degradation` | 2 eligible, shadow_paths = 4 → `InsufficientPaths { requested: 4, available: 2 }` |
| 5 | `bandwidth_constrained_scales_down` | combined capacity < cover budget → `BandwidthConstrained`, actual total ≤ capacity |
| 6 | `weights_sum_to_one` | standard 3-path plan → `weights.sum() ≈ 1.0` (within 1e-5) |
| 7 | `bandwidth_budget_equals_cover_ratio_times_flow` | total_cover_kbps ≈ real_flow_kbps * cover_flow_ratio |
| 8 | `higher_reliability_gets_more_bandwidth` | path with rel=0.8 gets more kbps than path with rel=0.2 |
| 9 | `zero_reliability_gets_uniform_fallback` | all paths rel=0.0 → equal weights |
| 10 | `zero_cover_ratio_no_bandwidth_no_degradation` | cover_flow_ratio = 0.0 → all allocs 0 kbps, `degraded = false` |
| 11 | `shadow_paths_zero_returns_empty_no_degradation` | shadow_paths = 0 → empty plan, `degraded = false` |
| 12 | `output_sorted_by_path_id` | allocations always in ascending path_id order |
| 13 | `determinism_input_order_invariant` | shuffle candidates → identical FragmentPlan |
| 14 | `cap_triggers_redistribution` | one path capped → excess flows to remaining paths |
| 15 | `path_with_zero_bandwidth_cap_excluded` | path cap = 0 → weight = 0.0, `cover_bandwidth_kbps = 0` |
| 16 | `empty_candidates_slice` | no candidates → `NoEligiblePaths` |
| 17 | `tiebreaker_lower_path_id_wins` | equal reliability + bandwidth → lower path_id selected first |
| 18 | `voip_latency_guard_40ms_enforced` | guard = 40, RTT = 41 → path excluded |

---

## 13. Acceptance Criteria for Phase 2

| Criterion | Target |
|-----------|--------|
| Latency guard strictly enforced | Paths with `measured_rtt_ms > latency_guard_ms` never appear in `allocations` |
| Bandwidth ceiling respected | `total_cover_bandwidth_kbps ≤ real_flow_kbps * cover_flow_ratio` always |
| Path count does not exceed request | `effective_shadow_paths ≤ shadow_paths` always |
| Determinism | Identical inputs → identical output, regardless of slice order |
| No panic on any input combination | Verified by edge-case tests |
| Weights sum to 1.0 (or 0.0 for empty plan) | Within f32 epsilon |
| `cargo test -p liberty-controlled-chaos` | All tests pass |
| `cargo clippy -p liberty-controlled-chaos -- -D warnings` | Zero warnings |

---

## 14. Module Integration into `lib.rs`

When implemented, `path_fragmenter.rs` is added as a public module:

```rust
// In lib.rs — additions for Phase 2
pub mod path_fragmenter;

pub use path_fragmenter::{
    CandidatePath, PathAllocation, DegradationReason, FragmentPlan,
    build_fragment_plan,
};
```

The frozen Sprint 5 stubs (`temporal_decoupler.rs`, `traffic_classifier.rs`,
`correlation_score_engine.rs`) are not modified.

---

## 15. Open Questions Resolved by This Design

Phase 1 left six open questions (Q1–Q6 in `shadow_probability_model.md §11`).
PathFragmenter's design resolves the ones within its scope:

| Q# | Question | Resolution |
|----|----------|------------|
| Q1 | How does the route manager expose `available_paths`? | Caller passes a `&[CandidatePath]` snapshot. Route manager API shape is outside PathFragmenter's scope. |
| Q2 | Is RTT measured per-candidate-path or cached? Cache TTL? | PathFragmenter acts on whatever `measured_rtt_ms` the caller provides. Staleness is the caller's concern. |
| Q3 | Where does `avg_flow_bandwidth_estimate` come from? | PathFragmenter accepts `real_flow_bandwidth_kbps: u32` as a direct parameter. Source (measured vs. estimated) is the caller's decision. |
| Q5 | How are shadow flows torn down when the real flow ends? | FragmentPlan is stateless. Teardown is the Transmitter's responsibility (Phase 3). |

Q4 (shadow destination selection) and Q6 (per-flow vs. global correlation score)
remain open and are Phase 3 / post-Phase 2 concerns.

---

## 16. Sprint 6 Completion State After Phase 2

```
Sprint 6 Phase 1  ✓  route_shadower.rs       — COMPLETE, frozen
Sprint 6 Phase 2  ·  path_fragmenter.rs      — This design; implementation next
Sprint 6 Phase 3  ·  Transmitter             — Executes FragmentPlan; packet generation
```

The post-shadowing peak cross-correlation target of ≤ 0.12 (versus Sprint 5's
0.21 baseline) is measurable only after Phase 3 generates actual cover traffic.
Phase 2 provides the allocation plan that Phase 3 will execute.
