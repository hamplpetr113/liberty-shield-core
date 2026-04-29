//! Path selection v2 — deterministic 3-hop Guard → Relay → Exit path builder.
//!
//! Peers are scored by `score(node_id) = u64::from_le_bytes(SHA256(node_id)[0..8])`.
//! Within the same role, higher score wins (ties broken by node_id ascending).
//! Banned nodes are never selected.

use std::collections::HashSet;

use crate::crypto::sha256;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The role a peer can play in a circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerRole {
    Guard,
    Relay,
    Exit,
}

/// A candidate peer for path selection.
#[derive(Debug, Clone)]
pub struct CandidatePeer {
    /// SHA-256 derived node identifier (32 bytes).
    pub node_id: [u8; 32],
    /// Long-term public key.
    pub public_key: [u8; 32],
    /// The role(s) this peer is eligible for.
    pub role: PeerRole,
}

/// A fully selected 3-hop path.
#[derive(Debug, Clone)]
pub struct HopPath {
    pub guard: CandidatePeer,
    pub relay: CandidatePeer,
    pub exit: CandidatePeer,
}

impl HopPath {
    /// Return the three node_ids as an array.
    pub fn node_ids(&self) -> [[u8; 32]; 3] {
        [self.guard.node_id, self.relay.node_id, self.exit.node_id]
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum PathError {
    /// No eligible Guard candidates remain after filtering.
    NoGuardAvailable,
    /// No eligible Relay candidates remain after filtering.
    NoRelayAvailable,
    /// No eligible Exit candidates remain after filtering.
    NoExitAvailable,
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathError::NoGuardAvailable => write!(f, "no guard candidate available"),
            PathError::NoRelayAvailable => write!(f, "no relay candidate available"),
            PathError::NoExitAvailable => write!(f, "no exit candidate available"),
        }
    }
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/// Deterministic per-node score derived from its node_id.
fn peer_score(node_id: &[u8; 32]) -> u64 {
    let digest = sha256(node_id);
    u64::from_le_bytes(digest[0..8].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// PathSelector
// ---------------------------------------------------------------------------

/// Selects deterministic 3-hop paths from candidate pools.
pub struct PathSelector {
    /// node_ids that must never appear in any path.
    banned: HashSet<[u8; 32]>,
}

impl PathSelector {
    pub fn new() -> Self {
        Self {
            banned: HashSet::new(),
        }
    }

    /// Ban a node from future path selections.
    pub fn ban(&mut self, node_id: [u8; 32]) {
        self.banned.insert(node_id);
    }

    /// Unban a node.
    pub fn unban(&mut self, node_id: &[u8; 32]) {
        self.banned.remove(node_id);
    }

    /// Select a 3-hop Guard → Relay → Exit path from `candidates`.
    ///
    /// - Each hop uses the highest-scoring eligible peer of the correct role.
    /// - No node appears more than once in the path.
    /// - Banned nodes are excluded.
    pub fn select(&self, candidates: &[CandidatePeer]) -> Result<HopPath, PathError> {
        let guard = self
            .best_with_role(candidates, PeerRole::Guard, &[])
            .ok_or(PathError::NoGuardAvailable)?;

        let relay = self
            .best_with_role(candidates, PeerRole::Relay, &[guard.node_id])
            .ok_or(PathError::NoRelayAvailable)?;

        let exit = self
            .best_with_role(candidates, PeerRole::Exit, &[guard.node_id, relay.node_id])
            .ok_or(PathError::NoExitAvailable)?;

        Ok(HopPath {
            guard: guard.clone(),
            relay: relay.clone(),
            exit: exit.clone(),
        })
    }

    /// Return the highest-scoring peer with the given role, excluding `used` node_ids.
    fn best_with_role<'a>(
        &self,
        candidates: &'a [CandidatePeer],
        role: PeerRole,
        used: &[[u8; 32]],
    ) -> Option<&'a CandidatePeer> {
        let mut eligible: Vec<&CandidatePeer> = candidates
            .iter()
            .filter(|p| {
                p.role == role && !self.banned.contains(&p.node_id) && !used.contains(&p.node_id)
            })
            .collect();

        // Sort descending by score, then ascending by node_id for determinism.
        eligible.sort_by(|a, b| {
            peer_score(&b.node_id)
                .cmp(&peer_score(&a.node_id))
                .then_with(|| a.node_id.cmp(&b.node_id))
        });

        eligible.into_iter().next()
    }
}

impl Default for PathSelector {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_identity::NodeIdentity;

    fn peer(seed: u8, role: PeerRole) -> CandidatePeer {
        let id = NodeIdentity::generate_from_seed([seed; 32]);
        CandidatePeer {
            node_id: id.node_id,
            public_key: id.public_key,
            role,
        }
    }

    fn three_hop_pool() -> Vec<CandidatePeer> {
        vec![
            peer(0x01, PeerRole::Guard),
            peer(0x02, PeerRole::Guard),
            peer(0x03, PeerRole::Relay),
            peer(0x04, PeerRole::Relay),
            peer(0x05, PeerRole::Exit),
            peer(0x06, PeerRole::Exit),
        ]
    }

    // PS1: valid 3-hop path selected from pool.
    #[test]
    fn ps1_valid_path() {
        let sel = PathSelector::new();
        let path = sel.select(&three_hop_pool()).unwrap();
        assert_eq!(path.guard.role, PeerRole::Guard);
        assert_eq!(path.relay.role, PeerRole::Relay);
        assert_eq!(path.exit.role, PeerRole::Exit);
    }

    // PS2: no duplicate nodes in path.
    #[test]
    fn ps2_no_duplicate_nodes() {
        let sel = PathSelector::new();
        // Pool where some peers have multiple roles — use same-node for two roles.
        // We simulate by having a single-node for guard + relay (distinct node_ids).
        let path = sel.select(&three_hop_pool()).unwrap();
        let ids = path.node_ids();
        assert_eq!(ids[0], path.guard.node_id);
        assert_eq!(ids[1], path.relay.node_id);
        assert_eq!(ids[2], path.exit.node_id);
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[0], ids[2]);
        assert_ne!(ids[1], ids[2]);
    }

    // PS3: no guard available returns NoGuardAvailable.
    #[test]
    fn ps3_no_guard_available() {
        let sel = PathSelector::new();
        let pool: Vec<CandidatePeer> =
            vec![peer(0x01, PeerRole::Relay), peer(0x02, PeerRole::Exit)];
        assert_eq!(sel.select(&pool).unwrap_err(), PathError::NoGuardAvailable);
    }

    // PS4: no exit available returns NoExitAvailable.
    #[test]
    fn ps4_no_exit_available() {
        let sel = PathSelector::new();
        let pool: Vec<CandidatePeer> =
            vec![peer(0x01, PeerRole::Guard), peer(0x02, PeerRole::Relay)];
        assert_eq!(sel.select(&pool).unwrap_err(), PathError::NoExitAvailable);
    }

    // PS5: banned node is excluded.
    #[test]
    fn ps5_banned_node_excluded() {
        let mut sel = PathSelector::new();
        let pool = three_hop_pool();
        // Ban the first guard.
        let guard1 = peer(0x01, PeerRole::Guard);
        sel.ban(guard1.node_id);
        let path = sel.select(&pool).unwrap();
        assert_ne!(path.guard.node_id, guard1.node_id);
    }

    // PS6: deterministic — same pool produces same path.
    #[test]
    fn ps6_deterministic_output() {
        let sel = PathSelector::new();
        let pool = three_hop_pool();
        let path1 = sel.select(&pool).unwrap();
        let path2 = sel.select(&pool).unwrap();
        assert_eq!(path1.guard.node_id, path2.guard.node_id);
        assert_eq!(path1.relay.node_id, path2.relay.node_id);
        assert_eq!(path1.exit.node_id, path2.exit.node_id);
    }

    // PS7: banning all guards returns error.
    #[test]
    fn ps7_all_guards_banned() {
        let mut sel = PathSelector::new();
        let pool = three_hop_pool();
        sel.ban(peer(0x01, PeerRole::Guard).node_id);
        sel.ban(peer(0x02, PeerRole::Guard).node_id);
        assert_eq!(sel.select(&pool).unwrap_err(), PathError::NoGuardAvailable);
    }

    // PS8: unban restores a node to eligibility.
    #[test]
    fn ps8_unban_restores() {
        let mut sel = PathSelector::new();
        let pool = three_hop_pool();
        let g1 = peer(0x01, PeerRole::Guard);
        sel.ban(g1.node_id);
        sel.unban(&g1.node_id);
        // Should succeed again.
        assert!(sel.select(&pool).is_ok());
    }

    // PS9: no relay available returns NoRelayAvailable.
    #[test]
    fn ps9_no_relay_available() {
        let sel = PathSelector::new();
        let pool: Vec<CandidatePeer> =
            vec![peer(0x01, PeerRole::Guard), peer(0x02, PeerRole::Exit)];
        assert_eq!(sel.select(&pool).unwrap_err(), PathError::NoRelayAvailable);
    }

    // PS10: higher-scored guard is preferred.
    #[test]
    fn ps10_best_score_selected() {
        let sel = PathSelector::new();
        // Build a pool with known nodes and check that the highest-scored guard wins.
        let pool = three_hop_pool();
        let path = sel.select(&pool).unwrap();
        // The selected guard should have the highest score among guards.
        let guards: Vec<&CandidatePeer> =
            pool.iter().filter(|p| p.role == PeerRole::Guard).collect();
        let best_score = guards.iter().map(|p| peer_score(&p.node_id)).max().unwrap();
        assert_eq!(peer_score(&path.guard.node_id), best_score);
    }
}
