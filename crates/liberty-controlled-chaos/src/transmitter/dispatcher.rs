//! PacketDispatcher — deterministic path assignment for real packets and
//! highest-weight shadow path selection.

use std::collections::HashMap;

use crate::path_fragmenter::{FragmentPlan, PathAllocation};

// ── SipHash-1-3 (single 64-bit message) ──────────────────────────────────────

// Fixed non-secret keys for distribution (not used for security).
const SIPHASH_K0: u64 = 0x0706_0504_0302_0100;
const SIPHASH_K1: u64 = 0x0f0e_0d0c_0b0a_0908;

fn siphash13(val: u64) -> u64 {
    macro_rules! sip_round {
        ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {
            $v0 = $v0.wrapping_add($v1);
            $v1 = $v1.rotate_left(13);
            $v1 ^= $v0;
            $v0 = $v0.rotate_left(32);
            $v2 = $v2.wrapping_add($v3);
            $v3 = $v3.rotate_left(16);
            $v3 ^= $v2;
            $v0 = $v0.wrapping_add($v3);
            $v3 = $v3.rotate_left(21);
            $v3 ^= $v0;
            $v2 = $v2.wrapping_add($v1);
            $v1 = $v1.rotate_left(17);
            $v1 ^= $v2;
            $v2 = $v2.rotate_left(32);
        };
    }

    let mut v0 = SIPHASH_K0 ^ 0x736f_6d65_7073_6575u64;
    let mut v1 = SIPHASH_K1 ^ 0x646f_7261_6e64_6f6du64;
    let mut v2 = SIPHASH_K0 ^ 0x6c79_6765_6e65_7261u64;
    let mut v3 = SIPHASH_K1 ^ 0x7465_6462_7974_6573u64;

    // 1 compression round.
    v3 ^= val;
    sip_round!(v0, v1, v2, v3);
    v0 ^= val;

    // 3 finalisation rounds.
    v2 ^= 0xff;
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);

    v0 ^ v1 ^ v2 ^ v3
}

// ── Weighted selection from cumulative weights ────────────────────────────────

/// Convert a `u64` hash uniformly to `[0.0, 1.0)`, then walk cumulative weights.
fn weighted_select(hash: u64, allocations: &[PathAllocation]) -> u64 {
    debug_assert!(!allocations.is_empty());
    let r = hash as f64 / (u64::MAX as f64 + 1.0);
    let mut cumulative = 0.0f32;
    for alloc in allocations {
        cumulative += alloc.weight;
        if r < cumulative as f64 {
            return alloc.path_id;
        }
    }
    allocations.last().unwrap().path_id
}

// ── PacketDispatcher ──────────────────────────────────────────────────────────

pub struct PacketDispatcher {
    /// Per-flow monotonic counter for XOR-based distribution.
    flow_seq: HashMap<u64, u64>,
}

impl Default for PacketDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketDispatcher {
    pub fn new() -> Self {
        Self {
            flow_seq: HashMap::new(),
        }
    }

    /// Deterministically assign `flow_id` to a path in `plan.allocations`.
    /// Returns `None` when allocations is empty (pass-through mode).
    pub fn assign_path(&mut self, flow_id: u64, plan: &FragmentPlan) -> Option<u64> {
        if plan.allocations.is_empty() {
            return None;
        }
        let seq = self.flow_seq.entry(flow_id).or_insert(0);
        let hash = siphash13(flow_id ^ *seq);
        *seq += 1;
        Some(weighted_select(hash, &plan.allocations))
    }

    /// Return the path with the highest weight in `plan.allocations` that is
    /// not `excluded_path`.  Returns `None` when no alternative exists.
    pub fn shadow_path_for(plan: &FragmentPlan, excluded_path: u64) -> Option<u64> {
        plan.allocations
            .iter()
            .filter(|a| a.path_id != excluded_path)
            .max_by(|a, b| {
                a.weight
                    .partial_cmp(&b.weight)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|a| a.path_id)
    }

    pub fn reset_flow(&mut self, flow_id: u64) {
        self.flow_seq.remove(&flow_id);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path_fragmenter::{CandidatePath, build_fragment_plan};
    use crate::route_shadower::ShadowDecision;

    fn two_path_plan() -> FragmentPlan {
        let decision = ShadowDecision {
            shadow_probability: 0.35,
            shadow_paths: 2,
            cover_flow_ratio: 0.4,
            bandwidth_budget: 0.14,
            latency_guard_ms: 150,
        };
        let candidates = [
            CandidatePath {
                path_id: 1,
                measured_rtt_ms: 30,
                available_bandwidth_kbps: 5000,
                reliability_score: 0.6,
            },
            CandidatePath {
                path_id: 2,
                measured_rtt_ms: 40,
                available_bandwidth_kbps: 5000,
                reliability_score: 0.4,
            },
        ];
        build_fragment_plan(&decision, &candidates, 1000)
    }

    // U8 — Assigned path_id ∈ plan.allocations.
    #[test]
    fn u8_real_packet_assigned_to_valid_path() {
        let plan = two_path_plan();
        let valid: Vec<u64> = plan.allocations.iter().map(|a| a.path_id).collect();
        let mut dispatcher = PacketDispatcher::new();
        for i in 0..100u64 {
            let path = dispatcher.assign_path(i % 3, &plan).unwrap();
            assert!(valid.contains(&path), "path {path} not in plan");
        }
    }

    // U9 — 10 000 packets → per-path count within 5% of weight × total.
    #[test]
    fn u9_weight_distribution_approximated() {
        let plan = two_path_plan();
        let mut dispatcher = PacketDispatcher::new();
        let n = 10_000u64;
        let mut counts: HashMap<u64, u64> = HashMap::new();
        for _i in 0..n {
            let p = dispatcher.assign_path(42, &plan).unwrap(); // same flow_id
            *counts.entry(p).or_insert(0) += 1;
        }
        for alloc in &plan.allocations {
            let expected = alloc.weight * n as f32;
            let actual = *counts.get(&alloc.path_id).unwrap_or(&0) as f32;
            let dev = (actual - expected).abs() / expected;
            assert!(
                dev < 0.05,
                "path {} got {actual:.0}, expected {expected:.0} (dev {dev:.3})",
                alloc.path_id
            );
        }
    }

    // U10 — Shadow path ≠ real packet path.
    #[test]
    fn u10_shadow_excluded_from_real_path() {
        let plan = two_path_plan();
        let mut dispatcher = PacketDispatcher::new();
        for _ in 0..50 {
            let real_path = dispatcher.assign_path(1, &plan).unwrap();
            let shadow_path = PacketDispatcher::shadow_path_for(&plan, real_path);
            if let Some(sp) = shadow_path {
                assert_ne!(sp, real_path, "shadow must not be on the real path");
            }
        }
    }

    // U11 — Empty allocations → assign_path returns None.
    #[test]
    fn u11_no_shadow_when_pass_through() {
        let plan = FragmentPlan {
            allocations: vec![],
            total_cover_bandwidth_kbps: 0,
            effective_shadow_paths: 0,
            degraded: false,
            degradation_reason: None,
        };
        let mut dispatcher = PacketDispatcher::new();
        assert!(dispatcher.assign_path(1, &plan).is_none());
    }
}
