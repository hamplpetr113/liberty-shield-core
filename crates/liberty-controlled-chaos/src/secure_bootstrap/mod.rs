//! Secure bootstrap — validates the initial join of a Liberty Shield node.
//!
//! `BootstrapEngine` manages the state of bootstrap from seed peers:
//! each seed must supply a valid nonce that falls within `max_epoch_skew` of
//! the local epoch, and replayed nonces are rejected.  Once `required_seeds`
//! valid seeds are collected the bootstrap is complete.

use std::collections::HashSet;

// ---------------------------------------------------------------------------
// BootstrapSeed
// ---------------------------------------------------------------------------

/// Information about a single bootstrap seed candidate.
#[derive(Debug, Clone)]
pub struct BootstrapSeed {
    pub node_id: [u8; 32],
    pub address: String,
    /// Nonce carried in the seed's handshake message.
    pub nonce: u64,
    /// Epoch reported by the seed.
    pub epoch: u64,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapError {
    EpochSkewTooLarge,
    ReplayedNonce,
    UnsignedPeer,
    AlreadyComplete,
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootstrapError::EpochSkewTooLarge => write!(f, "epoch skew too large"),
            BootstrapError::ReplayedNonce => write!(f, "replayed bootstrap nonce"),
            BootstrapError::UnsignedPeer => write!(f, "peer has no valid signature"),
            BootstrapError::AlreadyComplete => write!(f, "bootstrap already complete"),
        }
    }
}

// ---------------------------------------------------------------------------
// BootstrapEngine
// ---------------------------------------------------------------------------

/// Drives secure bootstrap from seed nodes.
pub struct BootstrapEngine {
    local_epoch: u64,
    max_epoch_skew: u64,
    required_seeds: usize,
    seen_nonces: HashSet<u64>,
    verified_seeds: Vec<BootstrapSeed>,
    /// node_ids that must be excluded (e.g. banned from directory).
    banned_ids: HashSet<[u8; 32]>,
}

impl BootstrapEngine {
    pub fn new(local_epoch: u64, max_epoch_skew: u64, required_seeds: usize) -> Self {
        Self {
            local_epoch,
            max_epoch_skew,
            required_seeds,
            seen_nonces: HashSet::new(),
            verified_seeds: Vec::new(),
            banned_ids: HashSet::new(),
        }
    }

    pub fn ban(&mut self, node_id: [u8; 32]) {
        self.banned_ids.insert(node_id);
    }

    /// Attempt to accept a seed peer.
    ///
    /// Rejects if epoch skew exceeds `max_epoch_skew`, nonce is replayed,
    /// peer is banned, or bootstrap is already complete.
    pub fn accept_seed(&mut self, seed: BootstrapSeed) -> Result<(), BootstrapError> {
        if self.is_complete() {
            return Err(BootstrapError::AlreadyComplete);
        }
        if self.banned_ids.contains(&seed.node_id) {
            return Err(BootstrapError::UnsignedPeer);
        }
        let skew = self.local_epoch.abs_diff(seed.epoch);
        if skew > self.max_epoch_skew {
            return Err(BootstrapError::EpochSkewTooLarge);
        }
        if !self.seen_nonces.insert(seed.nonce) {
            return Err(BootstrapError::ReplayedNonce);
        }
        self.verified_seeds.push(seed);
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.verified_seeds.len() >= self.required_seeds
    }

    pub fn verified_count(&self) -> usize {
        self.verified_seeds.len()
    }

    pub fn verified_seeds(&self) -> &[BootstrapSeed] {
        &self.verified_seeds
    }

    pub fn advance_epoch(&mut self, epoch: u64) {
        self.local_epoch = epoch;
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

    fn seed(id: u8, nonce: u64, epoch: u64) -> BootstrapSeed {
        BootstrapSeed {
            node_id: nid(id),
            address: format!("127.0.0.1:{}", 9000 + id as u16),
            nonce,
            epoch,
        }
    }

    // SB1: valid seed is accepted.
    #[test]
    fn sb1_valid_seed_accepted() {
        let mut e = BootstrapEngine::new(10, 3, 1);
        e.accept_seed(seed(1, 100, 10)).unwrap();
        assert_eq!(e.verified_count(), 1);
    }

    // SB2: epoch skew too large is rejected.
    #[test]
    fn sb2_epoch_skew_rejected() {
        let mut e = BootstrapEngine::new(10, 3, 1);
        assert_eq!(
            e.accept_seed(seed(1, 100, 20)),
            Err(BootstrapError::EpochSkewTooLarge)
        );
    }

    // SB3: replayed nonce is rejected.
    #[test]
    fn sb3_replay_rejected() {
        let mut e = BootstrapEngine::new(10, 5, 2);
        e.accept_seed(seed(1, 100, 10)).unwrap();
        assert_eq!(
            e.accept_seed(seed(2, 100, 10)),
            Err(BootstrapError::ReplayedNonce)
        );
    }

    // SB4: bootstrap is complete after required_seeds.
    #[test]
    fn sb4_complete_after_required() {
        let mut e = BootstrapEngine::new(10, 3, 2);
        e.accept_seed(seed(1, 1, 10)).unwrap();
        assert!(!e.is_complete());
        e.accept_seed(seed(2, 2, 10)).unwrap();
        assert!(e.is_complete());
    }

    // SB5: banned peer is rejected.
    #[test]
    fn sb5_banned_peer_rejected() {
        let mut e = BootstrapEngine::new(10, 5, 2);
        e.ban(nid(1));
        assert_eq!(
            e.accept_seed(seed(1, 100, 10)),
            Err(BootstrapError::UnsignedPeer)
        );
    }

    // SB6: accept_seed after completion returns AlreadyComplete.
    #[test]
    fn sb6_already_complete() {
        let mut e = BootstrapEngine::new(10, 5, 1);
        e.accept_seed(seed(1, 1, 10)).unwrap();
        assert_eq!(
            e.accept_seed(seed(2, 2, 10)),
            Err(BootstrapError::AlreadyComplete)
        );
    }

    // SB7: advance_epoch updates local epoch.
    #[test]
    fn sb7_advance_epoch() {
        let mut e = BootstrapEngine::new(5, 3, 1);
        e.advance_epoch(20);
        // Seed with epoch 20 should now pass skew check
        e.accept_seed(seed(1, 1, 20)).unwrap();
        assert_eq!(e.verified_count(), 1);
    }

    // SB8: verified_seeds returns all accepted seeds.
    #[test]
    fn sb8_verified_seeds_list() {
        let mut e = BootstrapEngine::new(10, 5, 3);
        for i in 1..=3u8 {
            e.accept_seed(seed(i, i as u64, 10)).unwrap();
        }
        assert_eq!(e.verified_seeds().len(), 3);
    }

    // SB9: skew=0 (exact epoch match) is allowed.
    #[test]
    fn sb9_exact_epoch_match() {
        let mut e = BootstrapEngine::new(10, 0, 1);
        e.accept_seed(seed(1, 1, 10)).unwrap();
        assert_eq!(e.verified_count(), 1);
    }

    // SB10: skew exactly at max_epoch_skew is allowed.
    #[test]
    fn sb10_skew_at_limit() {
        let mut e = BootstrapEngine::new(10, 3, 1);
        e.accept_seed(seed(1, 1, 13)).unwrap(); // skew=3 == max_epoch_skew=3
        assert_eq!(e.verified_count(), 1);
    }
}
