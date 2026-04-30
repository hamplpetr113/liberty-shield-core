//! Path selection engine — multi-factor guard/relay/exit selection.
//!
//! Candidates are scored by a weighted combination of:
//! - **reputation**: direct score from caller [0.0, 1.0]
//! - **latency**: `1.0 / (1.0 + latency_ms / 100.0)` [0.0, 1.0]
//! - **diversity**: penalise nodes used in `excluded_ids` (-0.5 each occurrence)
//!
//! `PathConstraints` lets the caller mandate minimum scores and excluded nodes.

use std::collections::HashSet;

// ---------------------------------------------------------------------------
// PathCandidate
// ---------------------------------------------------------------------------

/// A node eligible for inclusion in a circuit.
#[derive(Debug, Clone)]
pub struct PathCandidate {
    pub node_id: [u8; 32],
    /// Reputation score [0.0, 1.0].
    pub reputation: f64,
    /// Measured latency in milliseconds.
    pub latency_ms: f64,
    /// Role hint: 0=Guard, 1=Relay, 2=Exit.
    pub role: u8,
}

impl PathCandidate {
    pub fn composite_score(&self) -> f64 {
        let latency_factor = 1.0 / (1.0 + self.latency_ms / 100.0);
        (self.reputation * 0.6 + latency_factor * 0.4).clamp(0.0, 1.0)
    }
}

// ---------------------------------------------------------------------------
// PathConstraints
// ---------------------------------------------------------------------------

/// Constraints applied during path selection.
#[derive(Debug, Clone, Default)]
pub struct PathConstraints {
    /// Minimum acceptable composite score for any hop.
    pub min_score: f64,
    /// node_ids that must never appear in the path.
    pub excluded_ids: HashSet<[u8; 32]>,
}

impl PathConstraints {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_min_score(mut self, score: f64) -> Self {
        self.min_score = score;
        self
    }

    pub fn with_excluded(mut self, node_id: [u8; 32]) -> Self {
        self.excluded_ids.insert(node_id);
        self
    }
}

// ---------------------------------------------------------------------------
// SelectedPath
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SelectedPath {
    pub guard: PathCandidate,
    pub relay: PathCandidate,
    pub exit: PathCandidate,
}

impl SelectedPath {
    pub fn node_ids(&self) -> [[u8; 32]; 3] {
        [self.guard.node_id, self.relay.node_id, self.exit.node_id]
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionError {
    NoGuardAvailable,
    NoRelayAvailable,
    NoExitAvailable,
}

impl std::fmt::Display for SelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelectionError::NoGuardAvailable => write!(f, "no guard available"),
            SelectionError::NoRelayAvailable => write!(f, "no relay available"),
            SelectionError::NoExitAvailable => write!(f, "no exit available"),
        }
    }
}

// ---------------------------------------------------------------------------
// PathSelector
// ---------------------------------------------------------------------------

/// Multi-factor path selector.
pub struct PathSelector {
    /// node_ids permanently banned.
    banned: HashSet<[u8; 32]>,
}

impl PathSelector {
    pub fn new() -> Self {
        Self {
            banned: HashSet::new(),
        }
    }

    pub fn ban(&mut self, node_id: [u8; 32]) {
        self.banned.insert(node_id);
    }

    pub fn unban(&mut self, node_id: &[u8; 32]) {
        self.banned.remove(node_id);
    }

    /// Select a Guard→Relay→Exit path from `candidates`.
    ///
    /// Candidates with `role == 0` are guards, `role == 1` relays, `role == 2` exits.
    /// Applies `constraints.min_score` and `constraints.excluded_ids`.
    pub fn select(
        &self,
        candidates: &[PathCandidate],
        constraints: &PathConstraints,
    ) -> Result<SelectedPath, SelectionError> {
        let guard = self
            .best(candidates, 0, &[], constraints)
            .ok_or(SelectionError::NoGuardAvailable)?;

        let relay = self
            .best(candidates, 1, &[guard.node_id], constraints)
            .ok_or(SelectionError::NoRelayAvailable)?;

        let exit = self
            .best(candidates, 2, &[guard.node_id, relay.node_id], constraints)
            .ok_or(SelectionError::NoExitAvailable)?;

        Ok(SelectedPath {
            guard: guard.clone(),
            relay: relay.clone(),
            exit: exit.clone(),
        })
    }

    fn best<'a>(
        &self,
        candidates: &'a [PathCandidate],
        role: u8,
        used: &[[u8; 32]],
        constraints: &PathConstraints,
    ) -> Option<&'a PathCandidate> {
        let mut eligible: Vec<&PathCandidate> = candidates
            .iter()
            .filter(|c| {
                c.role == role
                    && !self.banned.contains(&c.node_id)
                    && !constraints.excluded_ids.contains(&c.node_id)
                    && !used.contains(&c.node_id)
                    && c.composite_score() >= constraints.min_score
            })
            .collect();

        eligible.sort_by(|a, b| {
            b.composite_score()
                .partial_cmp(&a.composite_score())
                .unwrap_or(std::cmp::Ordering::Equal)
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

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn cand(id: u8, role: u8, rep: f64, lat: f64) -> PathCandidate {
        PathCandidate {
            node_id: nid(id),
            reputation: rep,
            latency_ms: lat,
            role,
        }
    }

    fn pool() -> Vec<PathCandidate> {
        vec![
            cand(1, 0, 0.9, 10.0), // guard
            cand(2, 0, 0.7, 20.0), // guard
            cand(3, 1, 0.8, 15.0), // relay
            cand(4, 1, 0.6, 30.0), // relay
            cand(5, 2, 0.95, 5.0), // exit
            cand(6, 2, 0.5, 50.0), // exit
        ]
    }

    // PS1: valid path selected from pool.
    #[test]
    fn ps1_valid_path() {
        let sel = PathSelector::new();
        let path = sel.select(&pool(), &PathConstraints::new()).unwrap();
        assert_eq!(path.guard.role, 0);
        assert_eq!(path.relay.role, 1);
        assert_eq!(path.exit.role, 2);
    }

    // PS2: no duplicate nodes in path.
    #[test]
    fn ps2_no_duplicates() {
        let sel = PathSelector::new();
        let path = sel.select(&pool(), &PathConstraints::new()).unwrap();
        let ids = path.node_ids();
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[0], ids[2]);
        assert_ne!(ids[1], ids[2]);
    }

    // PS3: best-scoring guard wins.
    #[test]
    fn ps3_best_score_selected() {
        let sel = PathSelector::new();
        let path = sel.select(&pool(), &PathConstraints::new()).unwrap();
        // cand(1,guard,0.9,10) vs cand(2,guard,0.7,20) — cand(1) should win
        assert_eq!(path.guard.node_id, nid(1));
    }

    // PS4: banned node is excluded.
    #[test]
    fn ps4_banned_excluded() {
        let mut sel = PathSelector::new();
        sel.ban(nid(1));
        let path = sel.select(&pool(), &PathConstraints::new()).unwrap();
        assert_ne!(path.guard.node_id, nid(1));
    }

    // PS5: min_score constraint filters low-scoring nodes.
    #[test]
    fn ps5_min_score_constraint() {
        let sel = PathSelector::new();
        let c = PathConstraints::new().with_min_score(0.8);
        // cand(6, exit, 0.5, 50) should be excluded; cand(5, exit, 0.95, 5) passes
        let path = sel.select(&pool(), &c).unwrap();
        assert_eq!(path.exit.node_id, nid(5));
    }

    // PS6: no guard returns NoGuardAvailable.
    #[test]
    fn ps6_no_guard_error() {
        let sel = PathSelector::new();
        let no_guards: Vec<PathCandidate> = pool().into_iter().filter(|c| c.role != 0).collect();
        assert_eq!(
            sel.select(&no_guards, &PathConstraints::new()).unwrap_err(),
            SelectionError::NoGuardAvailable
        );
    }

    // PS7: no relay returns NoRelayAvailable.
    #[test]
    fn ps7_no_relay_error() {
        let sel = PathSelector::new();
        let no_relays: Vec<PathCandidate> = pool().into_iter().filter(|c| c.role != 1).collect();
        assert_eq!(
            sel.select(&no_relays, &PathConstraints::new()).unwrap_err(),
            SelectionError::NoRelayAvailable
        );
    }

    // PS8: excluded_ids constraint blocks a specific node.
    #[test]
    fn ps8_excluded_ids() {
        let sel = PathSelector::new();
        let c = PathConstraints::new().with_excluded(nid(5));
        let path = sel.select(&pool(), &c).unwrap();
        assert_ne!(path.exit.node_id, nid(5));
    }

    // PS9: unban restores a node.
    #[test]
    fn ps9_unban_restores() {
        let mut sel = PathSelector::new();
        sel.ban(nid(1));
        sel.unban(&nid(1));
        let path = sel.select(&pool(), &PathConstraints::new()).unwrap();
        assert_eq!(path.guard.node_id, nid(1));
    }

    // PS10: composite_score is in [0, 1].
    #[test]
    fn ps10_composite_score_range() {
        let c = cand(1, 0, 1.0, 0.0);
        let score = c.composite_score();
        assert!(score >= 0.0 && score <= 1.0);
    }

    // PS11: deterministic — same pool always gives same path.
    #[test]
    fn ps11_deterministic() {
        let sel = PathSelector::new();
        let p1 = sel.select(&pool(), &PathConstraints::new()).unwrap();
        let p2 = sel.select(&pool(), &PathConstraints::new()).unwrap();
        assert_eq!(p1.guard.node_id, p2.guard.node_id);
    }
}
