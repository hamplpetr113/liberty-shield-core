//! Beta node bootstrap — validates config and seed peers before joining the mesh.
//!
//! Builds on `secure_bootstrap::BootstrapEngine` by adding address validation,
//! seed deduplication, and minimum-seed enforcement.

use std::collections::HashSet;

use crate::secure_bootstrap::{BootstrapEngine, BootstrapError, BootstrapSeed};

// ---------------------------------------------------------------------------
// BootstrapConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    pub local_epoch: u64,
    pub max_epoch_skew: u64,
    pub required_seeds: usize,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            local_epoch: 0,
            max_epoch_skew: 5,
            required_seeds: 2,
        }
    }
}

// ---------------------------------------------------------------------------
// BetaBootstrapError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BetaBootstrapError {
    InvalidAddress,
    DuplicateSeed,
    NotEnoughSeeds,
    EpochSkew,
    ReplayedNonce,
    UnsignedPeer,
    AlreadyComplete,
}

impl From<BootstrapError> for BetaBootstrapError {
    fn from(e: BootstrapError) -> Self {
        match e {
            BootstrapError::EpochSkewTooLarge => BetaBootstrapError::EpochSkew,
            BootstrapError::ReplayedNonce => BetaBootstrapError::ReplayedNonce,
            BootstrapError::UnsignedPeer => BetaBootstrapError::UnsignedPeer,
            BootstrapError::AlreadyComplete => BetaBootstrapError::AlreadyComplete,
        }
    }
}

// ---------------------------------------------------------------------------
// BootstrapResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapResult {
    pub verified_peers: Vec<[u8; 32]>,
    pub epoch: u64,
}

// ---------------------------------------------------------------------------
// BetaBootstrapper
// ---------------------------------------------------------------------------

pub struct BetaBootstrapper {
    config: BootstrapConfig,
    engine: BootstrapEngine,
    seen_addresses: HashSet<String>,
    accepted: Vec<BootstrapSeed>,
}

impl BetaBootstrapper {
    pub fn new(config: BootstrapConfig) -> Self {
        let engine = BootstrapEngine::new(
            config.local_epoch,
            config.max_epoch_skew,
            config.required_seeds,
        );
        Self {
            config,
            engine,
            seen_addresses: HashSet::new(),
            accepted: Vec::new(),
        }
    }

    fn is_valid_address(addr: &str) -> bool {
        addr.parse::<std::net::SocketAddr>().is_ok()
    }

    /// Attempt to accept a seed peer.
    pub fn accept_seed(&mut self, seed: BootstrapSeed) -> Result<(), BetaBootstrapError> {
        if !Self::is_valid_address(&seed.address) {
            return Err(BetaBootstrapError::InvalidAddress);
        }
        if !self.seen_addresses.insert(seed.address.clone()) {
            return Err(BetaBootstrapError::DuplicateSeed);
        }
        self.engine
            .accept_seed(seed.clone())
            .map_err(BetaBootstrapError::from)?;
        self.accepted.push(seed);
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.engine.is_complete()
    }

    pub fn accepted_count(&self) -> usize {
        self.accepted.len()
    }

    /// Produce a `BootstrapResult` when bootstrap is complete.
    pub fn finish(&self) -> Result<BootstrapResult, BetaBootstrapError> {
        if !self.engine.is_complete() {
            return Err(BetaBootstrapError::NotEnoughSeeds);
        }
        let verified_peers = self
            .engine
            .verified_seeds()
            .iter()
            .map(|s| s.node_id)
            .collect();
        Ok(BootstrapResult {
            verified_peers,
            epoch: self.config.local_epoch,
        })
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

    fn seed(b: u8, addr: &str, nonce: u64, epoch: u64) -> BootstrapSeed {
        BootstrapSeed {
            node_id: nid(b),
            address: addr.to_string(),
            nonce,
            epoch,
        }
    }

    fn cfg() -> BootstrapConfig {
        BootstrapConfig {
            local_epoch: 10,
            max_epoch_skew: 3,
            required_seeds: 2,
        }
    }

    // BBB1: valid bootstrap with two seeds succeeds.
    #[test]
    fn bbb1_valid_bootstrap() {
        let mut b = BetaBootstrapper::new(cfg());
        b.accept_seed(seed(1, "127.0.0.1:9001", 1, 10)).unwrap();
        b.accept_seed(seed(2, "127.0.0.1:9002", 2, 10)).unwrap();
        assert!(b.is_complete());
        assert!(b.finish().is_ok());
    }

    // BBB2: duplicate address rejected.
    #[test]
    fn bbb2_duplicate_address_rejected() {
        let mut b = BetaBootstrapper::new(cfg());
        b.accept_seed(seed(1, "127.0.0.1:9001", 1, 10)).unwrap();
        assert_eq!(
            b.accept_seed(seed(2, "127.0.0.1:9001", 2, 10)),
            Err(BetaBootstrapError::DuplicateSeed)
        );
    }

    // BBB3: invalid address rejected.
    #[test]
    fn bbb3_invalid_address_rejected() {
        let mut b = BetaBootstrapper::new(cfg());
        assert_eq!(
            b.accept_seed(seed(1, "not-an-address", 1, 10)),
            Err(BetaBootstrapError::InvalidAddress)
        );
    }

    // BBB4: finish before enough seeds returns NotEnoughSeeds.
    #[test]
    fn bbb4_not_enough_seeds() {
        let mut b = BetaBootstrapper::new(cfg());
        b.accept_seed(seed(1, "127.0.0.1:9001", 1, 10)).unwrap();
        assert_eq!(b.finish(), Err(BetaBootstrapError::NotEnoughSeeds));
    }

    // BBB5: epoch skew rejected.
    #[test]
    fn bbb5_epoch_skew_rejected() {
        let mut b = BetaBootstrapper::new(cfg());
        assert_eq!(
            b.accept_seed(seed(1, "127.0.0.1:9001", 1, 99)),
            Err(BetaBootstrapError::EpochSkew)
        );
    }

    // BBB6: replayed nonce rejected.
    #[test]
    fn bbb6_replayed_nonce_rejected() {
        let mut b = BetaBootstrapper::new(cfg());
        b.accept_seed(seed(1, "127.0.0.1:9001", 42, 10)).unwrap();
        assert_eq!(
            b.accept_seed(seed(2, "127.0.0.1:9002", 42, 10)),
            Err(BetaBootstrapError::ReplayedNonce)
        );
    }

    // BBB7: accepted_count increments for each valid seed.
    #[test]
    fn bbb7_accepted_count() {
        let mut b = BetaBootstrapper::new(cfg());
        b.accept_seed(seed(1, "127.0.0.1:9001", 1, 10)).unwrap();
        assert_eq!(b.accepted_count(), 1);
    }

    // BBB8: bootstrap result contains verified peer IDs.
    #[test]
    fn bbb8_result_contains_peers() {
        let mut b = BetaBootstrapper::new(cfg());
        b.accept_seed(seed(1, "127.0.0.1:9001", 1, 10)).unwrap();
        b.accept_seed(seed(2, "127.0.0.1:9002", 2, 10)).unwrap();
        let r = b.finish().unwrap();
        assert_eq!(r.verified_peers.len(), 2);
    }

    // BBB9: config epoch is reflected in result.
    #[test]
    fn bbb9_epoch_in_result() {
        let mut b = BetaBootstrapper::new(cfg());
        b.accept_seed(seed(1, "127.0.0.1:9001", 1, 10)).unwrap();
        b.accept_seed(seed(2, "127.0.0.1:9002", 2, 10)).unwrap();
        let r = b.finish().unwrap();
        assert_eq!(r.epoch, 10);
    }

    // BBB10: single required_seeds=1 completes after one valid seed.
    #[test]
    fn bbb10_single_seed_required() {
        let mut b = BetaBootstrapper::new(BootstrapConfig {
            local_epoch: 5,
            max_epoch_skew: 2,
            required_seeds: 1,
        });
        b.accept_seed(seed(1, "127.0.0.1:9001", 1, 5)).unwrap();
        assert!(b.is_complete());
    }
}
