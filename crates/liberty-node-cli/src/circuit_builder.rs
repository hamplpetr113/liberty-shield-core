use std::collections::HashSet;

use crate::guard_selection::{GuardSelectionError, select_guard};
use crate::peer_directory::{PeerDescriptor, PeerDirectoryNodeId, PeerRole};

/// Errors produced by the circuit builder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitBuildError {
    /// Fewer than 3 distinct hops are available.
    TooFewHops,
    /// Guard node could not be selected.
    NoGuard(GuardSelectionError),
    /// No node with Exit role is available.
    NoExit,
    /// The constructed path contains a duplicate node.
    DuplicateNode,
}

impl From<GuardSelectionError> for CircuitBuildError {
    fn from(e: GuardSelectionError) -> Self {
        CircuitBuildError::NoGuard(e)
    }
}

/// A built circuit: an ordered sequence of node IDs [guard, relay…, exit].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltCircuit {
    /// Ordered hop IDs from guard (index 0) to exit (last index).
    pub hops: Vec<PeerDirectoryNodeId>,
}

impl BuiltCircuit {
    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }
}

/// Builds onion circuits from a peer directory slice.
///
/// Rules enforced:
/// - Minimum 3 hops
/// - No duplicate node IDs
/// - First hop must be a Guard
/// - Last hop must be an Exit
pub struct CircuitBuilder;

impl CircuitBuilder {
    /// Build a minimum 3-hop circuit from `peers`.
    ///
    /// Algorithm:
    ///   1. Select the lowest-node-id Guard as hop 0.
    ///   2. Select the lowest-node-id Exit (excluding the guard) as the last hop.
    ///   3. Fill the middle hop(s) with Relay nodes not already used.
    ///      If no Relay is available, fall back to any unused node.
    ///   4. Validate: ≥3 hops, no duplicates.
    pub fn build_circuit(peers: &[PeerDescriptor]) -> Result<BuiltCircuit, CircuitBuildError> {
        if peers.len() < 3 {
            return Err(CircuitBuildError::TooFewHops);
        }

        let guard = select_guard(peers)?;
        let guard_id = guard.node_id;

        // Select exit: lowest node_id Exit that isn't the guard
        let exit = {
            let mut exits: Vec<&PeerDescriptor> = peers
                .iter()
                .filter(|d| d.role == PeerRole::Exit && d.node_id != guard_id)
                .collect();
            exits.sort_by_key(|d| d.node_id.0);
            exits.into_iter().next().ok_or(CircuitBuildError::NoExit)?
        };
        let exit_id = exit.node_id;

        let used: HashSet<u64> = [guard_id.0, exit_id.0].iter().copied().collect();

        // Middle hops: prefer Relay nodes, sorted by node_id
        let mut middle: Vec<&PeerDescriptor> = peers
            .iter()
            .filter(|d| !used.contains(&d.node_id.0) && d.role == PeerRole::Relay)
            .collect();
        middle.sort_by_key(|d| d.node_id.0);

        // If no Relay is available, fall back to any unused node
        if middle.is_empty() {
            let mut fallback: Vec<&PeerDescriptor> = peers
                .iter()
                .filter(|d| !used.contains(&d.node_id.0))
                .collect();
            fallback.sort_by_key(|d| d.node_id.0);
            if let Some(node) = fallback.into_iter().next() {
                middle.push(node);
            }
        }

        if middle.is_empty() {
            return Err(CircuitBuildError::TooFewHops);
        }

        // Take exactly one middle hop (minimum circuit)
        let relay = middle[0];

        let hops = vec![guard_id, relay.node_id, exit_id];

        // Duplicate check
        let unique: HashSet<u64> = hops.iter().map(|id| id.0).collect();
        if unique.len() != hops.len() {
            return Err(CircuitBuildError::DuplicateNode);
        }

        Ok(BuiltCircuit { hops })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_directory::PeerDescriptor;

    fn peers(ids: &[u64]) -> Vec<PeerDescriptor> {
        ids.iter()
            .map(|&id| PeerDescriptor::deterministic(id, 45000))
            .collect()
    }

    // CB1: builds a valid 3-hop circuit with guard at 0, exit at last
    #[test]
    fn cb1_builds_valid_3_hop_circuit() {
        // node_id % 3: 3→Guard, 1→Relay, 2→Exit
        let p = peers(&[1, 2, 3]);
        let circuit = CircuitBuilder::build_circuit(&p).unwrap();
        assert_eq!(circuit.hop_count(), 3);
        // guard is first
        assert_eq!(circuit.hops[0].0 % 3, 0, "first hop must be a Guard");
        // exit is last
        assert_eq!(circuit.hops[2].0 % 3, 2, "last hop must be an Exit");
    }

    // CB2: fewer than 3 peers → error
    #[test]
    fn cb2_too_few_peers_error() {
        let p = peers(&[1, 2]);
        assert_eq!(
            CircuitBuilder::build_circuit(&p).unwrap_err(),
            CircuitBuildError::TooFewHops
        );
    }

    // CB3: no guard → error
    #[test]
    fn cb3_no_guard_error() {
        // 1 % 3 = 1 Relay; 2 % 3 = 2 Exit; 4 % 3 = 1 Relay — no Guard
        let p = peers(&[1, 2, 4]);
        assert!(matches!(
            CircuitBuilder::build_circuit(&p).unwrap_err(),
            CircuitBuildError::NoGuard(_)
        ));
    }

    // CB4: no exit → error
    #[test]
    fn cb4_no_exit_error() {
        // 3 % 3 = 0 Guard; 1 % 3 = 1 Relay; 4 % 3 = 1 Relay — no Exit
        let p = peers(&[1, 3, 4]);
        assert_eq!(
            CircuitBuilder::build_circuit(&p).unwrap_err(),
            CircuitBuildError::NoExit
        );
    }

    // CB5: no duplicate nodes in circuit
    #[test]
    fn cb5_no_duplicate_nodes() {
        let p = peers(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let circuit = CircuitBuilder::build_circuit(&p).unwrap();
        let ids: Vec<u64> = circuit.hops.iter().map(|id| id.0).collect();
        let unique: HashSet<u64> = ids.iter().copied().collect();
        assert_eq!(ids.len(), unique.len());
    }

    // CB6: deterministic — same input always produces the same circuit
    #[test]
    fn cb6_deterministic_circuit_building() {
        let p = peers(&[1, 2, 3, 4, 5, 6]);
        let c1 = CircuitBuilder::build_circuit(&p).unwrap();
        let c2 = CircuitBuilder::build_circuit(&p).unwrap();
        assert_eq!(c1, c2);
    }

    // CB7: first hop always has Guard role
    #[test]
    fn cb7_first_hop_is_guard() {
        let p = peers(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let circuit = CircuitBuilder::build_circuit(&p).unwrap();
        assert_eq!(circuit.hops[0].0 % 3, 0);
    }

    // CB8: last hop always has Exit role
    #[test]
    fn cb8_last_hop_is_exit() {
        let p = peers(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let circuit = CircuitBuilder::build_circuit(&p).unwrap();
        let last = circuit.hops.last().unwrap();
        assert_eq!(last.0 % 3, 2);
    }
}
