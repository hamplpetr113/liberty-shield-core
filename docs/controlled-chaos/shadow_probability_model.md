# Shadow Probability Model — Sprint 6: Probabilistic Route Shadowing

**Status:** Design phase (pre-implementation)
**Sprint:** 6
**Author:** Liberty Shield AI
**Date:** 2026-04-26
**Depends on:** Sprint 5 — Temporal Decoupler (frozen)

---

## 1. Purpose

Route shadowing generates synthetic cover flows that mimic the shape and destination patterns of real user flows. Combined with Sprint 5's temporal decoupling (which reduced timing/burst/volume similarity to correlation scores ≤ 0.21), route shadowing adds **path-level diversity** to defeat adversaries who correlate users by which network paths their traffic traverses.

The key constraint is that shadowing must never cost more than it defends: it must not degrade VoIP quality, must not touch sensitive flows (banking, auth), and must respect battery and bandwidth limits.

---

## 2. Definitions

| Term | Meaning |
|------|---------|
| **Shadow route** | A synthetic flow that mirrors a real flow's approximate size and destination class, sent over a different path |
| **Cover flow** | Any traffic sent for privacy reasons rather than application need |
| **Shadow probability** | Per-flow probability [0.0, 1.0] that a shadow route is spawned |
| **Shadow paths** | Maximum number of concurrent shadow paths for a single real flow |
| **Cover flow ratio** | Ratio of cover bytes to real bytes; 0.5 means shadow traffic is 50 % of real volume |
| **Temporal decoupler score** | Output of `correlation_score_engine` after Sprint 5 processing; range [0.0, 1.0] lower is better |
| **Available paths** | Count of distinct egress routes (VPN hops, onion layers, multi-path interfaces) currently reachable |

---

## 3. Operating Modes

### 3.1 Mode Table

| Parameter | NORMAL | PRIVACY | PARANOID | STEALTH |
|-----------|--------|---------|----------|---------|
| `shadow_probability` | 0.10 | 0.35 | 0.70 | 0.20 |
| `shadow_paths` | 1 | 2 | 4 | 1 |
| `cover_flow_ratio` | 0.15 | 0.40 | 0.90 | 0.25 |
| `bandwidth_overhead_limit` | 8 % | 20 % | 45 % | 12 % |
| `battery_impact_limit` | +0.05 %/h | +0.15 %/h | +0.40 %/h | +0.08 %/h |
| `latency_guard` | 80 ms | 150 ms | 300 ms | 60 ms |

### 3.2 Mode Semantics

**NORMAL** — Default mode. Shadow a small fraction of flows to provide a baseline of path diversity without perceptible overhead. Suitable when threat signals are low and the device is on battery.

**PRIVACY** — Moderate shadowing. Activated when the user explicitly prefers privacy or when threat signals are elevated. Accepts up to 20 % bandwidth overhead and ~0.15 %/h battery overhead as a fair trade-off.

**PARANOID** — Aggressive shadowing. Activated when correlation scores remain high after temporal decoupling, or when operating on hostile networks. Accepts significant overhead; appropriate when the user is on AC power in a high-risk environment.

**STEALTH** — Minimal, surgical shadowing. Counter-intuitive: STEALTH is *less aggressive than PARANOID* because generating a large shadow footprint on a hostile network can itself attract attention. One carefully timed shadow per flow, low bandwidth overhead, strict latency guard. Optimised for low-volume, high-sensitivity scenarios.

---

## 4. Decision Inputs

| Input | Type | Range / Values | Source |
|-------|------|---------------|--------|
| `threat_score` | f32 | [0.0, 1.0] | `ShieldEngine` threat pipeline |
| `correlation_score` | f32 | [0.0, 1.0] | `correlation_score_engine` (post-decoupler) |
| `battery_level` | u8 | [0, 100] (%) | OS battery API |
| `charging_state` | enum | `CHARGING`, `DISCHARGING`, `UNKNOWN` | OS battery API |
| `network_reputation` | enum | `TRUSTED`, `NEUTRAL`, `UNTRUSTED`, `HOSTILE` | Network threat detector |
| `traffic_class` | enum | `WEB`, `VOIP`, `STREAMING`, `BANKING`, `LOGIN`, `DNS`, `BACKGROUND`, `UNKNOWN` | `traffic_classifier` (frozen, Sprint 5) |
| `available_paths` | u8 | [0, N] | Route manager |

---

## 5. Base Mode Selection

Mode is resolved in two stages: **base selection** then **override rules** (Section 6).

```
base_mode:
  if network_reputation == HOSTILE        → PARANOID
  elif network_reputation == UNTRUSTED    → PRIVACY
  elif threat_score > 0.70               → PARANOID
  elif threat_score > 0.40               → PRIVACY
  elif correlation_score > 0.60          → PRIVACY   (residual correlation after temporal decoupling)
  else                                   → NORMAL
```

STEALTH is never selected automatically by base logic. It is either set explicitly by the user or promoted by override rule 6.5.

---

## 6. Override Rules

Override rules are evaluated **after** base mode selection and **after** the effective parameters are loaded from the mode table. They clamp or zero out parameters without changing the declared mode label.

Rules are evaluated in the order listed; later rules can further restrict but never relax an earlier restriction.

### 6.1 — Hard exclusion: banking, payment, auth flows

```
if traffic_class in [BANKING, LOGIN]:
    shadow_probability  = 0.0
    shadow_paths        = 0
    cover_flow_ratio    = 0.0
```

**Rationale:** Shadow traffic originating near a login or payment session can be mistaken for credential stuffing or fraud signals by downstream services. The risk of account lockout and the sensitivity of these flows outweigh any privacy benefit.

### 6.2 — Soft cap: VoIP flows

```
if traffic_class == VOIP:
    shadow_probability  = min(shadow_probability, 0.05)
    shadow_paths        = min(shadow_paths, 1)
    cover_flow_ratio    = min(cover_flow_ratio, 0.10)
    latency_guard       = min(latency_guard, 40)   # strict 40 ms cap for VoIP
```

**Rationale:** VoIP flows are highly latency-sensitive. Aggressive shadowing on the same path competes for queue depth. A single low-probability shadow is the maximum that can be tolerated without audible degradation. The VPN's observed VoIP latency after Sprint 5 is 9.2 ms; the 40 ms latency guard preserves that headroom.

### 6.3 — Battery: low-battery reduction

```
if battery_level < 20 and charging_state != CHARGING:
    shadow_probability       = shadow_probability * 0.40
    shadow_paths             = min(shadow_paths, 1)
    cover_flow_ratio         = cover_flow_ratio  * 0.30
    battery_impact_limit     = min(battery_impact_limit, 0.03)  # %/h hard ceiling
```

**Rationale:** Below 20 % charge the user's primary concern is device function, not privacy hardening. Reducing shadow volume by ~60–70 % preserves the session without draining the battery.

### 6.4 — Battery: charging relaxation

```
if charging_state == CHARGING:
    battery_impact_limit = battery_impact_limit * 2.5   # up to 2.5× mode default
```

**Rationale:** AC power removes the battery constraint. Paranoid and Privacy modes may use their full overhead budget without penalty.

### 6.5 — Correlation score escalation

```
if correlation_score > 0.50:
    # Temporal decoupler did not suppress correlation sufficiently.
    # Escalate shadow aggressiveness.
    shadow_probability  = min(shadow_probability * (1.0 + correlation_score), 0.85)
    shadow_paths        = min(shadow_paths + 1, 4)
```

```
if correlation_score > 0.75:
    # Severe residual correlation — promote mode to PARANOID parameters,
    # but only if current mode is weaker than PARANOID.
    apply_paranoid_floor()   # clamp each parameter up to PARANOID table value
```

**Rationale:** The temporal decoupler achieved a peak cross-correlation of 0.21 in Sprint 5. If a particular traffic pattern still scores above 0.50 post-decoupling, route shadowing must compensate. The 0.75 threshold triggers a floor to PARANOID parameters so the two layers act as a combined defence.

### 6.6 — Path availability gate

```
if available_paths < 2:
    shadow_probability = 0.0
    shadow_paths       = 0
```

**Rationale:** Route shadowing requires at least two distinct egress paths. Without alternates, any "shadow" traffic would traverse the same path as the real flow and provide no correlation resistance. In this case the system falls back to temporal decoupling alone.

### 6.7 — Bandwidth overhead enforcement

After all parameter adjustments, recompute the expected bandwidth overhead:

```
expected_overhead = shadow_probability * cover_flow_ratio * avg_flow_bandwidth_estimate
```

If `expected_overhead > bandwidth_overhead_limit` (from mode table, possibly relaxed by rule 6.4):

```
cover_flow_ratio = bandwidth_overhead_limit / (shadow_probability * avg_flow_bandwidth_estimate)
```

This ensures that even after escalation (rule 6.5), the bandwidth ceiling is never breached.

### 6.8 — Latency guard enforcement

Before committing a shadow path, measure the round-trip time of the candidate alternate path. If `measured_rtt > latency_guard`, the path is excluded from the shadow candidate set. If the candidate set becomes empty, `shadow_probability = 0.0` for that flow.

---

## 7. Combined Decision Function

The following pseudocode summarises the full decision pipeline. This is the specification that `route_shadower.rs` will implement.

```
fn resolve_shadow_params(inputs: DecisionInputs) -> ShadowParams {
    // Stage 1: base mode
    let mut params = base_mode_params(inputs);

    // Stage 2: overrides (order matters)
    apply_hard_exclusion(inputs, &mut params);     // rule 6.1
    apply_voip_cap(inputs, &mut params);           // rule 6.2
    apply_low_battery(inputs, &mut params);        // rule 6.3
    apply_charging_relaxation(inputs, &mut params);// rule 6.4
    apply_correlation_escalation(inputs, &mut params); // rule 6.5
    apply_path_availability_gate(inputs, &mut params); // rule 6.6
    apply_bandwidth_ceiling(inputs, &mut params);  // rule 6.7
    apply_latency_guard(inputs, &mut params);      // rule 6.8

    params
}
```

Each rule function is a pure function that mutates `params` in place. Rules are stateless with respect to prior invocations; the inputs carry all necessary state.

---

## 8. Parameter Interaction Matrix

This table shows which inputs affect which parameters and in which direction.

| Input | shadow_probability | shadow_paths | cover_flow_ratio | bandwidth_overhead_limit | battery_impact_limit | latency_guard |
|-------|--------------------|--------------|------------------|--------------------------|-----------------------|---------------|
| `threat_score` high | ↑ (via mode) | ↑ (via mode) | ↑ (via mode) | ↑ (via mode) | ↑ (via mode) | ↑ (via mode) |
| `correlation_score` > 0.50 | ↑ rule 6.5 | ↑ rule 6.5 | — | — | — | — |
| `traffic_class == BANKING` | → 0.0 | → 0 | → 0.0 | — | — | — |
| `traffic_class == VOIP` | ↓ cap 0.05 | ↓ cap 1 | ↓ cap 0.10 | — | — | ↓ cap 40 ms |
| `battery_level < 20 %` | ↓ ×0.40 | ↓ cap 1 | ↓ ×0.30 | — | ↓ cap 0.03 | — |
| `charging_state == CHARGING` | — | — | — | ↑ ×2.5 | ↑ ×2.5 | — |
| `network_reputation == HOSTILE` | ↑ (via mode) | ↑ (via mode) | ↑ (via mode) | ↑ (via mode) | ↑ (via mode) | — |
| `available_paths < 2` | → 0.0 | → 0 | — | — | — | — |
| overhead > limit | — | — | ↓ clamped | — | — | — |
| RTT > latency_guard | path excluded | path excluded | — | — | — | — |

---

## 9. Bandwidth and Battery Budget Estimates

These estimates inform `route_shadower.rs` implementation. They are not enforced at design time but must be validated in Sprint 6 benchmarks.

### 9.1 Bandwidth overhead formula

```
overhead_pct = (shadow_probability * cover_flow_ratio * 100)
```

Example — PRIVACY mode, no overrides:
```
0.35 * 0.40 * 100 = 14.0 %   (within 20 % limit ✓)
```

Example — PARANOID mode under rule 6.5 escalation (correlation_score = 0.65):
```
shadow_probability = min(0.70 * (1.0 + 0.65), 0.85) = 0.85 (clamped)
overhead = 0.85 * 0.90 * 100 = 76.5 %   → rule 6.7 clamps cover_flow_ratio
cover_flow_ratio = 0.45 / 0.85 = 0.529  (ceiling enforced ✓)
```

### 9.2 Battery impact

Sprint 5 baseline: +0.12 %/h from temporal decoupling.

Target Sprint 6 additions at each mode (unloaded device, 4G connection):

| Mode | Shadow addition | Combined total |
|------|----------------|----------------|
| NORMAL | +0.03 %/h | +0.15 %/h |
| PRIVACY | +0.10 %/h | +0.22 %/h |
| PARANOID | +0.28 %/h | +0.40 %/h |
| STEALTH | +0.05 %/h | +0.17 %/h |

These are targets. `battery_impact_limit` from the mode table is the hard ceiling the implementation must enforce.

---

## 10. Traffic Class Reference

These are the traffic classes produced by `traffic_classifier.rs` (frozen). The shadow probability model must treat them as opaque enum values.

| Class | Shadow eligible | Notes |
|-------|----------------|-------|
| `WEB` | Yes | Standard HTTPS browsing; primary shadow target |
| `STREAMING` | Partial | Shadow at reduced ratio; large flows make overhead % easy to control |
| `VOIP` | Capped (rule 6.2) | Max 5 % probability, 1 path |
| `BANKING` | No (rule 6.1) | Hard exclusion |
| `LOGIN` | No (rule 6.1) | Hard exclusion; includes OAuth, SSO, password managers |
| `DNS` | No | DNS is already handled by Sprint 5's decoupler; adding shadow DNS creates amplification risk |
| `BACKGROUND` | Yes | Low-priority app syncs; good cover flow candidates |
| `UNKNOWN` | Partial | Apply NORMAL-mode parameters regardless of declared mode |

---

## 11. Open Questions for Implementation

The following must be resolved before `route_shadower.rs` is written.

| # | Question | Impact |
|---|----------|--------|
| Q1 | How does the route manager expose `available_paths`? Synchronous query or subscription? | Affects API design of `resolve_shadow_params` |
| Q2 | Is RTT measured per-candidate-path or cached? Cache TTL? | Determines whether `latency_guard` enforcement is per-flow or amortised |
| Q3 | Does `avg_flow_bandwidth_estimate` come from the traffic classifier or is it measured inline? | Needed for rule 6.7 bandwidth ceiling |
| Q4 | Shadow flows: same destination host, different path — or different destination with similar traffic fingerprint? | Core architectural choice for the `route_shadower` |
| Q5 | How are shadow flows torn down when the real flow ends? | Lifecycle ownership question |
| Q6 | Is `correlation_score` computed per-flow or globally? Sprint 5 correlation engine returns a global score. | Determines granularity of rule 6.5 |

---

## 12. Acceptance Criteria for Sprint 6

These criteria apply to the implemented `route_shadower.rs`, not this document.

| Criterion | Target |
|-----------|--------|
| Post-shadowing peak cross-correlation | ≤ 0.12 (improvement over Sprint 5's 0.21) |
| Bandwidth overhead in PRIVACY mode | ≤ 20 % |
| Bandwidth overhead in NORMAL mode | ≤ 8 % |
| VoIP latency added by shadowing | ≤ 2 ms (total must remain well below 15 ms) |
| Battery impact in NORMAL mode | ≤ +0.05 %/h from shadowing alone |
| No shadow traffic on BANKING/LOGIN flows | 100 % — zero tolerance |
| Shadow traffic correctly suppressed when battery < 20 % | Verified by unit test |
| Rule evaluation is pure / side-effect-free | All rules pass without mutating global state |

---

## 13. Frozen Dependencies

The following Sprint 5 modules are **read-only** inputs to this sprint.

| Module | Role in Sprint 6 |
|--------|-----------------|
| `temporal_decoupler.rs` | Produces timing-randomised flows that shadow routes overlay |
| `traffic_classifier.rs` | Provides `traffic_class` enum consumed by rules 6.1 and 6.2 |
| `correlation_score_engine.rs` | Produces `correlation_score` consumed by rule 6.5 |

Do not modify these files. If the shadow probability model requires different behaviour from them, open a new sprint.
