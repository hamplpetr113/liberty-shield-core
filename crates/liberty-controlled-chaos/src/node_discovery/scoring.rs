use std::cmp::Ordering;
use std::collections::HashSet;

use super::types::{NodeDescriptor, NodeDiscoveryError, NodeScore};

/// Composite quality score for a node:
///   score = reliability_score / (latency_estimate + 1)
///
/// Higher is better.  Ties are broken by lowest `node_id`.
fn compute_score(node: &NodeDescriptor) -> f64 {
    node.reliability_score / (node.latency_estimate as f64 + 1.0)
}

/// Rank `nodes` by descending score.  Ties are broken by ascending `node_id`.
///
/// Returns a `Vec<NodeScore>` in that order.  Input order does not affect output.
pub fn rank_nodes(nodes: &[NodeDescriptor]) -> Vec<NodeScore> {
    let mut scores: Vec<NodeScore> = nodes
        .iter()
        .map(|n| NodeScore {
            node_id: n.node_id,
            score: compute_score(n),
        })
        .collect();

    scores.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.node_id.cmp(&b.node_id))
    });

    scores
}

/// Select the top `count` unique nodes by score.
///
/// Returns `NotEnoughNodes` when `nodes` contains fewer than `count` entries
/// (after deduplication by `node_id`).
pub fn select_relays(
    nodes: &[NodeDescriptor],
    count: usize,
) -> Result<Vec<NodeDescriptor>, NodeDiscoveryError> {
    // Deduplicate by node_id, keeping first occurrence (input order).
    let mut seen: HashSet<u64> = HashSet::new();
    let unique: Vec<&NodeDescriptor> = nodes.iter().filter(|n| seen.insert(n.node_id.0)).collect();

    if unique.len() < count {
        return Err(NodeDiscoveryError::NotEnoughNodes {
            requested: count,
            available: unique.len(),
        });
    }

    // Rank the unique set and take the top `count`.
    let unique_owned: Vec<NodeDescriptor> = unique.iter().map(|&n| n.clone()).collect();
    let ranked = rank_nodes(&unique_owned);

    let selected: Vec<NodeDescriptor> = ranked
        .iter()
        .take(count)
        .filter_map(|ns| {
            unique_owned
                .iter()
                .find(|n| n.node_id == ns.node_id)
                .cloned()
        })
        .collect();

    Ok(selected)
}
