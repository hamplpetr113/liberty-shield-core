use crate::peer_directory::{PeerDescriptor, PeerRole};

/// Errors from guard selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardSelectionError {
    /// No candidate has the Guard role.
    NoGuardAvailable,
}

/// Select the first guard node from a sorted slice of peer descriptors.
///
/// Algorithm: sort candidates by `node_id` ascending, return the first
/// entry whose role is `Guard`. Deterministic for any given input set.
pub fn select_guard(candidates: &[PeerDescriptor]) -> Result<&PeerDescriptor, GuardSelectionError> {
    let mut sorted: Vec<&PeerDescriptor> = candidates.iter().collect();
    sorted.sort_by_key(|d| d.node_id.0);
    sorted
        .into_iter()
        .find(|d| d.role == PeerRole::Guard)
        .ok_or(GuardSelectionError::NoGuardAvailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_directory::PeerDescriptor;

    fn descs(ids: &[u64]) -> Vec<PeerDescriptor> {
        ids.iter()
            .map(|&id| PeerDescriptor::deterministic(id, 45000))
            .collect()
    }

    // GS1: deterministic — same set always returns the same guard
    #[test]
    fn gs1_deterministic_guard_selection() {
        let nodes = descs(&[3, 6, 9, 1, 4]);
        let g1 = select_guard(&nodes).unwrap();
        let g2 = select_guard(&nodes).unwrap();
        assert_eq!(g1.node_id, g2.node_id);
    }

    // GS2: selected node always has role Guard
    #[test]
    fn gs2_guard_always_has_guard_role() {
        let nodes = descs(&[1, 2, 3, 4, 5, 6]);
        let guard = select_guard(&nodes).unwrap();
        assert_eq!(guard.role, PeerRole::Guard);
    }

    // GS3: smallest node_id with Guard role is selected
    #[test]
    fn gs3_selects_lowest_node_id_guard() {
        // node_id % 3 == 0 → Guard; ids 3, 6, 9 are guards
        let nodes = descs(&[9, 3, 6, 1, 2]);
        let guard = select_guard(&nodes).unwrap();
        assert_eq!(guard.node_id.0, 3); // 3 is the smallest guard
    }

    // GS4: no guards → error
    #[test]
    fn gs4_no_guard_returns_error() {
        // node_id % 3 == 1 → Relay; node_id % 3 == 2 → Exit
        let nodes = descs(&[1, 2, 4, 5]);
        assert_eq!(
            select_guard(&nodes).unwrap_err(),
            GuardSelectionError::NoGuardAvailable
        );
    }

    // GS5: single guard in a large set
    #[test]
    fn gs5_single_guard_in_large_set() {
        // Only node 3 is a Guard (3 % 3 == 0)
        let nodes = descs(&[1, 2, 3, 4, 5]);
        let guard = select_guard(&nodes).unwrap();
        assert_eq!(guard.node_id.0, 3);
        assert_eq!(guard.role, PeerRole::Guard);
    }

    // GS6: empty candidates → error
    #[test]
    fn gs6_empty_candidates_error() {
        assert_eq!(
            select_guard(&[]).unwrap_err(),
            GuardSelectionError::NoGuardAvailable
        );
    }
}
