use std::cmp::Ordering;
use std::collections::HashSet;

use crate::node_discovery::NodeDescriptor;

use super::guard_set::GuardSet;
use super::policy::GuardPolicy;
use super::types::{GuardNode, GuardScore, GuardSelectionError};

pub struct GuardSelector;

impl GuardSelector {
    /// Compute a quality score for a `NodeDescriptor` candidate.
    ///
    /// Formula: `reliability_score * 1000.0 - latency_estimate`
    ///
    /// `failure_penalty` is 0 because `NodeDescriptor` carries no failure count.
    pub fn score_guard_candidate(node: &NodeDescriptor) -> GuardScore {
        let score = node.reliability_score * 1_000.0 - node.latency_estimate as f64;
        GuardScore {
            node_id: node.node_id,
            score,
        }
    }

    /// Select `count` guard nodes from `nodes`, filtered by `policy`.
    ///
    /// Selection is deterministic: candidates are ranked by descending score,
    /// then ascending latency, then ascending `node_id`.
    ///
    /// Returns `NotEnoughCandidates` when fewer than `count` nodes pass the
    /// policy filter (after deduplication by `node_id`).
    pub fn select_initial_guards(
        nodes: &[NodeDescriptor],
        policy: &GuardPolicy,
        count: usize,
    ) -> Result<GuardSet, GuardSelectionError> {
        // Deduplicate by node_id (first occurrence wins), then filter by policy.
        let mut seen: HashSet<u64> = HashSet::new();
        let mut eligible: Vec<&NodeDescriptor> = nodes
            .iter()
            .filter(|n| seen.insert(n.node_id.0) && policy.accepts(n))
            .collect();

        if eligible.len() < count {
            return Err(GuardSelectionError::NotEnoughCandidates);
        }

        Self::sort_candidates(&mut eligible);

        let guards: Vec<GuardNode> = eligible[..count]
            .iter()
            .map(|n| guard_from_node(n))
            .collect();

        Ok(GuardSet::from_guards(guards))
    }

    /// Refresh `current` guards against updated `candidates`.
    ///
    /// Strategy:
    ///   1. Keep guards that still pass `policy.accepts_guard`.
    ///   2. Fill vacated slots from `candidates` (not already in the kept set).
    ///   3. Return `NotEnoughCandidates` if the combined count cannot reach the
    ///      original guard count.
    pub fn refresh_guards(
        current: &GuardSet,
        candidates: &[NodeDescriptor],
        policy: &GuardPolicy,
    ) -> Result<GuardSet, GuardSelectionError> {
        let target = current.active_count();

        let valid: Vec<GuardNode> = current
            .list_guards()
            .into_iter()
            .filter(|g| policy.accepts_guard(g))
            .cloned()
            .collect();

        let needed = target.saturating_sub(valid.len());

        if needed == 0 {
            return Ok(GuardSet::from_guards(valid));
        }

        let valid_ids: HashSet<u64> = valid.iter().map(|g| g.node_id.0).collect();

        // Track evicted guard IDs (failed policy) so they are not immediately
        // re-added from the candidate pool.
        let evicted_ids: HashSet<u64> = current
            .list_guards()
            .iter()
            .map(|g| g.node_id.0)
            .filter(|id| !valid_ids.contains(id))
            .collect();

        // Deduplicate candidates, exclude kept and evicted guards, apply policy.
        let mut seen: HashSet<u64> = HashSet::new();
        let mut fresh: Vec<&NodeDescriptor> = candidates
            .iter()
            .filter(|n| {
                seen.insert(n.node_id.0)
                    && !valid_ids.contains(&n.node_id.0)
                    && !evicted_ids.contains(&n.node_id.0)
                    && policy.accepts(n)
            })
            .collect();

        if fresh.len() < needed {
            return Err(GuardSelectionError::NotEnoughCandidates);
        }

        Self::sort_candidates(&mut fresh);

        let mut result = valid;
        for node in fresh.iter().take(needed) {
            result.push(guard_from_node(node));
        }

        Ok(GuardSet::from_guards(result))
    }

    /// Sort candidates: higher score first → lower latency first → lower node_id first.
    fn sort_candidates(candidates: &mut Vec<&NodeDescriptor>) {
        candidates.sort_by(|a, b| {
            let sa = Self::score_guard_candidate(a).score;
            let sb = Self::score_guard_candidate(b).score;
            sb.partial_cmp(&sa)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.latency_estimate.cmp(&b.latency_estimate))
                .then_with(|| a.node_id.cmp(&b.node_id))
        });
    }
}

/// Convert a `NodeDescriptor` into a freshly-initialised `GuardNode`.
pub(super) fn guard_from_node(node: &NodeDescriptor) -> GuardNode {
    GuardNode {
        node_id: node.node_id,
        public_key: node.public_key,
        peer_address: node.peer_address.clone(),
        latency_estimate: node.latency_estimate.min(u32::MAX as u64) as u32,
        reliability_score: node.reliability_score,
        first_seen_timestamp: node.last_seen_timestamp,
        last_seen_timestamp: node.last_seen_timestamp,
        failure_count: 0,
        success_count: 0,
    }
}
