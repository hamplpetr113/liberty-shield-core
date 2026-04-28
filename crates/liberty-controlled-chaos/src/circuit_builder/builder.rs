use std::collections::HashSet;

use crate::onion_layer::OnionLayerKey;

use super::circuit::Circuit;
use super::types::{CircuitError, CircuitId, NodeDescriptor};

pub struct CircuitBuilder;

impl CircuitBuilder {
    /// Build a deterministic circuit from `nodes`, selecting `hop_count` hops.
    ///
    /// Rules (applied in order):
    ///   1. `hop_count < 3`                       → `BelowMinimumHops`
    ///   2. `nodes` contains duplicate `NodeId`   → `DuplicateNode`
    ///   3. `nodes.len() < hop_count`             → `NotEnoughNodes`
    ///
    /// Selection is deterministic: nodes are sorted by `node_id` ascending and
    /// the first `hop_count` entries are taken.
    ///
    /// Each hop receives an `OnionLayerKey` derived deterministically from the
    /// node's `public_key` XOR'd with a per-position nonce:
    ///   `key[i].bytes = public_key ^ expand(circuit_id, i)`
    pub fn build_circuit(
        nodes: &[NodeDescriptor],
        hop_count: usize,
    ) -> Result<Circuit, CircuitError> {
        if hop_count < 3 {
            return Err(CircuitError::BelowMinimumHops);
        }

        // Detect duplicates before anything else.
        let mut seen: HashSet<u64> = HashSet::new();
        for node in nodes {
            if !seen.insert(node.node_id.0) {
                return Err(CircuitError::DuplicateNode(node.node_id));
            }
        }

        if nodes.len() < hop_count {
            return Err(CircuitError::NotEnoughNodes);
        }

        // Deterministic ordering: sort by NodeId ascending, take first hop_count.
        let mut sorted: Vec<&NodeDescriptor> = nodes.iter().collect();
        sorted.sort_by_key(|n| n.node_id.0);
        let selected: Vec<NodeDescriptor> =
            sorted[..hop_count].iter().map(|&n| n.clone()).collect();

        // CircuitId derived deterministically from the XOR of all selected node ids.
        let circuit_id_raw: u64 = selected
            .iter()
            .map(|n| n.node_id.0)
            .fold(0u64, |acc, id| acc.wrapping_add(id).rotate_left(7));
        let circuit_id = CircuitId(circuit_id_raw);

        // Per-hop onion keys derived from public_key XOR expand(circuit_id, hop_index).
        let onion_keys: Vec<OnionLayerKey> = selected
            .iter()
            .enumerate()
            .map(|(i, node)| {
                let mut key_bytes = node.public_key;
                let nonce = derive_key_nonce(circuit_id.0, i as u64);
                for (b, n) in key_bytes.iter_mut().zip(nonce.iter()) {
                    *b ^= n;
                }
                OnionLayerKey { bytes: key_bytes }
            })
            .collect();

        Ok(Circuit::new(circuit_id, selected, onion_keys))
    }
}

/// Expand `(circuit_id, hop_index)` into 32 bytes for key derivation.
///
/// Simple but deterministic: fill with alternating LE encodings of
/// `circuit_id ^ (hop_index * 0x9e3779b97f4a7c15)`.
fn derive_key_nonce(circuit_id: u64, hop_index: u64) -> [u8; 32] {
    let mixed = circuit_id ^ hop_index.wrapping_mul(0x9e3779b97f4a7c15);
    let mut out = [0u8; 32];
    for chunk in 0..4usize {
        let v = mixed.wrapping_add(chunk as u64);
        out[chunk * 8..(chunk + 1) * 8].copy_from_slice(&v.to_le_bytes());
    }
    out
}
