# Sprint 6 — Route Shadower (Phase 1)

Status: COMPLETE

Implemented module:
crates/liberty-controlled-chaos/src/route_shadower.rs

Purpose:
Deterministic decision engine that computes probabilistic route shadowing parameters
based on threat score, correlation score, battery state, network reputation, and traffic class.

Key design properties:
- Pure computation
- No packet generation
- Deterministic output
- Side-effect free

Outputs:
ShadowDecision {
    shadow_probability
    shadow_paths
    cover_flow_ratio
    bandwidth_budget
    latency_guard_ms
}

Security rule enforcement:
Rule 6.1 — Hard exclusion for Banking/Login traffic
Rule 6.2 — VoIP latency protection
Rule 6.3 — Low battery reduction
Rule 6.4 — Charging relaxation
Rule 6.5 — Correlation escalation
Rule 6.6 — Path availability gate
Rule 6.7 — Bandwidth ceiling
Rule 6.8 — Latency guard pass-through

Bug discovered and fixed:
Correlation escalation could reactivate Banking/Login flows due to shadow_paths increment.
Fixed by early-return guard:

if params.shadow_probability == 0.0 {
    return;
}

Test status:
18 / 18 unit tests passing

Static analysis:
cargo clippy clean

Notes:
This module only decides shadow parameters.
Actual shadow path allocation will be implemented in Sprint 6 Phase 2 (PathFragmenter).
