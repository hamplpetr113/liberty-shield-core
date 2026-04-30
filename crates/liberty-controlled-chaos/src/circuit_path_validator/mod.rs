//! Circuit path validator — checks hop lists for diversity and policy constraints.
//!
//! Validates that circuits do not reuse nodes, respect minimum hop counts,
//! and obey geographic/subnet diversity rules (modelled as node groups here).

use std::collections::HashSet;

// ---------------------------------------------------------------------------
// ValidationError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    TooFewHops,
    TooManyHops,
    DuplicateNode,
    SameGroupConsecutive,
    FirstHopBanned,
}

// ---------------------------------------------------------------------------
// PathConstraints
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PathConstraints {
    pub min_hops: usize,
    pub max_hops: usize,
    pub allow_consecutive_same_group: bool,
}

impl Default for PathConstraints {
    fn default() -> Self {
        Self {
            min_hops: 2,
            max_hops: 8,
            allow_consecutive_same_group: false,
        }
    }
}

// ---------------------------------------------------------------------------
// CircuitPathValidator
// ---------------------------------------------------------------------------

pub struct CircuitPathValidator {
    constraints: PathConstraints,
    banned_entry_nodes: HashSet<[u8; 32]>,
    /// Maps node_id → group_id for diversity checking.
    node_groups: std::collections::HashMap<[u8; 32], u32>,
    validations_ok: u64,
    validations_failed: u64,
}

impl CircuitPathValidator {
    pub fn new(constraints: PathConstraints) -> Self {
        Self {
            constraints,
            banned_entry_nodes: HashSet::new(),
            node_groups: std::collections::HashMap::new(),
            validations_ok: 0,
            validations_failed: 0,
        }
    }

    pub fn ban_entry_node(&mut self, node_id: [u8; 32]) {
        self.banned_entry_nodes.insert(node_id);
    }

    pub fn set_node_group(&mut self, node_id: [u8; 32], group: u32) {
        self.node_groups.insert(node_id, group);
    }

    pub fn validate(&mut self, path: &[[u8; 32]]) -> Result<(), ValidationError> {
        if path.len() < self.constraints.min_hops {
            self.validations_failed += 1;
            return Err(ValidationError::TooFewHops);
        }
        if path.len() > self.constraints.max_hops {
            self.validations_failed += 1;
            return Err(ValidationError::TooManyHops);
        }
        if !path.is_empty() && self.banned_entry_nodes.contains(&path[0]) {
            self.validations_failed += 1;
            return Err(ValidationError::FirstHopBanned);
        }
        // Duplicate detection.
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for &node in path {
            if !seen.insert(node) {
                self.validations_failed += 1;
                return Err(ValidationError::DuplicateNode);
            }
        }
        // Consecutive group check.
        if !self.constraints.allow_consecutive_same_group && path.len() >= 2 {
            for i in 0..path.len() - 1 {
                let g1 = self.node_groups.get(&path[i]).copied();
                let g2 = self.node_groups.get(&path[i + 1]).copied();
                if matches!((g1, g2), (Some(a), Some(b)) if a == b) {
                    self.validations_failed += 1;
                    return Err(ValidationError::SameGroupConsecutive);
                }
            }
        }
        self.validations_ok += 1;
        Ok(())
    }

    pub fn validations_ok(&self) -> u64 {
        self.validations_ok
    }

    pub fn validations_failed(&self) -> u64 {
        self.validations_failed
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn validator() -> CircuitPathValidator {
        CircuitPathValidator::new(PathConstraints::default())
    }

    // CPV1: valid 3-hop path passes.
    #[test]
    fn cpv1_valid_path() {
        let mut v = validator();
        assert!(v.validate(&[nid(1), nid(2), nid(3)]).is_ok());
    }

    // CPV2: too few hops rejected.
    #[test]
    fn cpv2_too_few() {
        let mut v = validator();
        assert_eq!(v.validate(&[nid(1)]), Err(ValidationError::TooFewHops));
    }

    // CPV3: too many hops rejected.
    #[test]
    fn cpv3_too_many() {
        let mut v = CircuitPathValidator::new(PathConstraints {
            min_hops: 2,
            max_hops: 3,
            allow_consecutive_same_group: false,
        });
        let path = [nid(1), nid(2), nid(3), nid(4)];
        assert_eq!(v.validate(&path), Err(ValidationError::TooManyHops));
    }

    // CPV4: duplicate node rejected.
    #[test]
    fn cpv4_duplicate_node() {
        let mut v = validator();
        assert_eq!(
            v.validate(&[nid(1), nid(2), nid(1)]),
            Err(ValidationError::DuplicateNode)
        );
    }

    // CPV5: banned entry node rejected.
    #[test]
    fn cpv5_banned_entry() {
        let mut v = validator();
        v.ban_entry_node(nid(1));
        assert_eq!(
            v.validate(&[nid(1), nid(2), nid(3)]),
            Err(ValidationError::FirstHopBanned)
        );
    }

    // CPV6: consecutive same-group rejected.
    #[test]
    fn cpv6_same_group() {
        let mut v = validator();
        v.set_node_group(nid(1), 10);
        v.set_node_group(nid(2), 10);
        v.set_node_group(nid(3), 20);
        assert_eq!(
            v.validate(&[nid(1), nid(2), nid(3)]),
            Err(ValidationError::SameGroupConsecutive)
        );
    }

    // CPV7: allow_consecutive_same_group flag bypasses group check.
    #[test]
    fn cpv7_allow_same_group() {
        let mut v = CircuitPathValidator::new(PathConstraints {
            min_hops: 2,
            max_hops: 8,
            allow_consecutive_same_group: true,
        });
        v.set_node_group(nid(1), 10);
        v.set_node_group(nid(2), 10);
        assert!(v.validate(&[nid(1), nid(2)]).is_ok());
    }

    // CPV8: validations_ok counter increments.
    #[test]
    fn cpv8_ok_counter() {
        let mut v = validator();
        v.validate(&[nid(1), nid(2)]).unwrap();
        assert_eq!(v.validations_ok(), 1);
    }

    // CPV9: validations_failed counter increments.
    #[test]
    fn cpv9_fail_counter() {
        let mut v = validator();
        v.validate(&[nid(1)]).unwrap_err();
        assert_eq!(v.validations_failed(), 1);
    }

    // CPV10: nodes without group assigned are skipped in group check.
    #[test]
    fn cpv10_ungrouped_nodes_ok() {
        let mut v = validator();
        // No groups assigned — no SameGroupConsecutive error.
        assert!(v.validate(&[nid(1), nid(2), nid(3)]).is_ok());
    }
}
