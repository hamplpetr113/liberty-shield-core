//! PathHealthMonitor — tracks path quality and emits PlanInvalidationEvents.

use std::collections::HashMap;

use super::types::{InvalidationReason, PathEvent, PathStats, PlanInvalidationEvent};
use crate::path_fragmenter::FragmentPlan;

// ── Per-path state ────────────────────────────────────────────────────────────

const HYSTERESIS_COUNT: u32 = 3;
const LOSS_WINDOW_PACKETS: usize = 50; // sliding window approximation

struct PathHealth {
    // Baseline values from first observed measurement.
    baseline_rtt_ms: Option<u32>,
    baseline_bw_kbps: Option<u32>,
    plan_bw_kbps: u32,

    // Hysteresis counters.
    rtt_breach_count: u32,
    bw_breach_count: u32,

    // Loss tracking: ring of bool (true=lost) over last N packets.
    loss_window: Vec<bool>,
    loss_idx: usize,
    loss_count: u32,

    // Running stats for PlanInvalidationEvent payload.
    last_rtt_ms: u32,
    last_bw_kbps: u32,

    // Suppressed-by-loss flag.
    pub suppressed: bool,
}

impl PathHealth {
    fn new(plan_bw_kbps: u32) -> Self {
        Self {
            baseline_rtt_ms: None,
            baseline_bw_kbps: None,
            plan_bw_kbps,
            rtt_breach_count: 0,
            bw_breach_count: 0,
            loss_window: vec![false; LOSS_WINDOW_PACKETS],
            loss_idx: 0,
            loss_count: 0,
            last_rtt_ms: 0,
            last_bw_kbps: 0,
            suppressed: false,
        }
    }

    fn record_rtt(&mut self, rtt_ms: u32) -> Option<InvalidationReason> {
        self.last_rtt_ms = rtt_ms;

        let baseline = match self.baseline_rtt_ms {
            None => {
                self.baseline_rtt_ms = Some(rtt_ms);
                return None;
            }
            Some(b) => b,
        };

        if rtt_ms > baseline.saturating_mul(2) {
            self.rtt_breach_count += 1;
            if self.rtt_breach_count >= HYSTERESIS_COUNT {
                self.rtt_breach_count = 0;
                return Some(InvalidationReason::LatencyExceeded {
                    path_id: 0, // caller fills in path_id
                    observed_rtt_ms: rtt_ms,
                });
            }
        } else {
            self.rtt_breach_count = 0;
        }
        None
    }

    fn record_loss(&mut self, lost: bool) {
        let old = self.loss_window[self.loss_idx];
        self.loss_window[self.loss_idx] = lost;
        self.loss_idx = (self.loss_idx + 1) % LOSS_WINDOW_PACKETS;

        if old && !lost {
            self.loss_count -= 1;
        } else if !old && lost {
            self.loss_count += 1;
        }

        let loss_pct = self.loss_count as f32 / LOSS_WINDOW_PACKETS as f32;
        self.suppressed = loss_pct > 0.10;
    }

    fn record_bandwidth(&mut self, available_kbps: u32) -> Option<InvalidationReason> {
        self.last_bw_kbps = available_kbps;

        if self.baseline_bw_kbps.is_none() {
            self.baseline_bw_kbps = Some(available_kbps);
        }

        // Threshold: available < 0.5 × plan allocation.
        if available_kbps < self.plan_bw_kbps / 2 {
            self.bw_breach_count += 1;
            if self.bw_breach_count >= HYSTERESIS_COUNT {
                self.bw_breach_count = 0;
                return Some(InvalidationReason::BandwidthShrunk {
                    path_id: 0,
                    available_kbps,
                });
            }
        } else {
            self.bw_breach_count = 0;
        }
        None
    }

    fn stats(&self, path_id: u64) -> PathStats {
        PathStats {
            path_id,
            rtt_ms: self.last_rtt_ms,
            loss_pct: self.loss_count as f32 / LOSS_WINDOW_PACKETS as f32,
            available_kbps: self.last_bw_kbps,
        }
    }
}

// ── PathHealthMonitor ─────────────────────────────────────────────────────────

pub struct PathHealthMonitor {
    paths: HashMap<u64, PathHealth>,
}

impl PathHealthMonitor {
    pub fn new() -> Self {
        Self { paths: HashMap::new() }
    }

    pub fn init_from_plan(&mut self, plan: &FragmentPlan) {
        for alloc in &plan.allocations {
            self.paths
                .entry(alloc.path_id)
                .or_insert_with(|| PathHealth::new(alloc.cover_bandwidth_kbps));
        }
    }

    /// Remove health state for paths no longer in the plan.
    pub fn prune_to_plan(&mut self, plan: &FragmentPlan) {
        let ids: std::collections::HashSet<u64> =
            plan.allocations.iter().map(|a| a.path_id).collect();
        self.paths.retain(|k, _| ids.contains(k));
    }

    /// Process a path event.  Returns a `PlanInvalidationEvent` if the path
    /// degrades past the hysteresis threshold, or immediately for `PathDown`.
    pub fn handle_event(
        &mut self,
        event: PathEvent,
    ) -> Option<PlanInvalidationEvent> {
        match event {
            PathEvent::RttSample { path_id, rtt_ms } => {
                let h = self.paths.entry(path_id).or_insert_with(|| PathHealth::new(0));
                let reason = h.record_rtt(rtt_ms)?;
                let stats = h.stats(path_id);
                let reason = patch_path_id(reason, path_id);
                Some(PlanInvalidationEvent {
                    reason,
                    affected_path: Some(path_id),
                    current_stats: stats,
                })
            }

            PathEvent::PacketLost { path_id } => {
                let h = self.paths.entry(path_id).or_insert_with(|| PathHealth::new(0));
                h.record_loss(true);
                None
            }

            PathEvent::PacketAcked { path_id } => {
                let h = self.paths.entry(path_id).or_insert_with(|| PathHealth::new(0));
                h.record_loss(false);
                None
            }

            PathEvent::BandwidthEstimate { path_id, available_kbps } => {
                let h = self.paths.entry(path_id).or_insert_with(|| PathHealth::new(0));
                let reason = h.record_bandwidth(available_kbps)?;
                let stats = h.stats(path_id);
                let reason = patch_path_id(reason, path_id);
                Some(PlanInvalidationEvent {
                    reason,
                    affected_path: Some(path_id),
                    current_stats: stats,
                })
            }

            PathEvent::PathDown { path_id } => {
                let h = self.paths.entry(path_id).or_insert_with(|| PathHealth::new(0));
                let stats = h.stats(path_id);
                Some(PlanInvalidationEvent {
                    reason: InvalidationReason::PathDown { path_id },
                    affected_path: Some(path_id),
                    current_stats: stats,
                })
            }

            PathEvent::PathRestored { path_id, rtt_ms, available_kbps } => {
                let h = self.paths.entry(path_id).or_insert_with(|| PathHealth::new(0));
                h.last_rtt_ms = rtt_ms;
                h.last_bw_kbps = available_kbps;
                h.rtt_breach_count = 0;
                h.bw_breach_count = 0;
                h.suppressed = false;
                None
            }
        }
    }

    pub fn is_suppressed(&self, path_id: u64) -> bool {
        self.paths.get(&path_id).map_or(false, |h| h.suppressed)
    }

    pub fn stats(&self, path_id: u64) -> PathStats {
        self.paths
            .get(&path_id)
            .map(|h| h.stats(path_id))
            .unwrap_or(PathStats { path_id, rtt_ms: 0, loss_pct: 0.0, available_kbps: 0 })
    }
}

fn patch_path_id(reason: InvalidationReason, path_id: u64) -> InvalidationReason {
    match reason {
        InvalidationReason::LatencyExceeded { observed_rtt_ms, .. } => {
            InvalidationReason::LatencyExceeded { path_id, observed_rtt_ms }
        }
        InvalidationReason::BandwidthShrunk { available_kbps, .. } => {
            InvalidationReason::BandwidthShrunk { path_id, available_kbps }
        }
        other => other,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn rtt_event(path_id: u64, rtt_ms: u32) -> PathEvent {
        PathEvent::RttSample { path_id, rtt_ms }
    }

    // U17 — One RTT spike → no event (hysteresis).
    #[test]
    fn u17_single_rtt_spike_no_invalidation() {
        let mut mon = PathHealthMonitor::new();
        // Establish baseline.
        mon.handle_event(rtt_event(1, 20));
        // Single spike: 2× baseline = threshold, so > 2× fires; just at threshold means no event.
        let result = mon.handle_event(rtt_event(1, 41)); // 41 > 2×20
        assert!(result.is_none(), "single spike should not emit event");
    }

    // U18 — Three consecutive RTT spikes → PlanInvalidationEvent.
    #[test]
    fn u18_three_rtt_spikes_emits_event() {
        let mut mon = PathHealthMonitor::new();
        mon.handle_event(rtt_event(1, 20)); // baseline = 20
        mon.handle_event(rtt_event(1, 50)); // breach 1 (>40)
        mon.handle_event(rtt_event(1, 50)); // breach 2
        let result = mon.handle_event(rtt_event(1, 50)); // breach 3 → event
        assert!(result.is_some(), "three spikes should emit PlanInvalidationEvent");
        match result.unwrap().reason {
            InvalidationReason::LatencyExceeded { path_id, observed_rtt_ms } => {
                assert_eq!(path_id, 1);
                assert_eq!(observed_rtt_ms, 50);
            }
            other => panic!("unexpected reason: {other:?}"),
        }
    }

    // U19 — PathDown → immediate event, no hysteresis.
    #[test]
    fn u19_path_down_immediate_event() {
        let mut mon = PathHealthMonitor::new();
        let result = mon.handle_event(PathEvent::PathDown { path_id: 2 });
        assert!(result.is_some(), "PathDown must emit event immediately");
        match result.unwrap().reason {
            InvalidationReason::PathDown { path_id } => assert_eq!(path_id, 2),
            other => panic!("unexpected reason: {other:?}"),
        }
    }

    // U20 — Loss rate > 10% → path suppressed (cover dropped on that path).
    #[test]
    fn u20_cover_suppressed_on_high_loss() {
        let mut mon = PathHealthMonitor::new();
        // Send 6 losses out of 50-packet window to exceed 10%.
        for _ in 0..6 {
            mon.handle_event(PathEvent::PacketLost { path_id: 3 });
        }
        for _ in 0..44 {
            mon.handle_event(PathEvent::PacketAcked { path_id: 3 });
        }
        assert!(mon.is_suppressed(3), "should be suppressed at >10% loss");
    }
}
