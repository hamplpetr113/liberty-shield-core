//! Peer admission control — decides whether a discovered peer may enter the mesh.
//!
//! `PeerAdmissionController` enforces:
//! - Minimum reputation threshold.
//! - Rate limiting: at most `max_admissions_per_epoch` per epoch.
//! - Duplicate identity rejection.
//! - Banned peer rejection.

use std::collections::HashSet;

// ---------------------------------------------------------------------------
// AdmissionPolicy
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AdmissionPolicy {
    /// Minimum trust score [0.0, 1.0] required for admission.
    pub min_trust_score: f64,
    /// Maximum new peers admitted in a single epoch.
    pub max_admissions_per_epoch: u32,
    /// Minimum epoch at which a peer descriptor is valid.
    pub require_min_epoch: u64,
}

impl Default for AdmissionPolicy {
    fn default() -> Self {
        Self {
            min_trust_score: 0.4,
            max_admissions_per_epoch: 16,
            require_min_epoch: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// AdmissionRequest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AdmissionRequest {
    pub node_id: [u8; 32],
    pub trust_score: f64,
    pub descriptor_epoch: u64,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    TrustScoreTooLow,
    RateLimitExceeded,
    DuplicateIdentity,
    BannedPeer,
    StaleDescriptor,
}

impl std::fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdmissionError::TrustScoreTooLow => write!(f, "trust score below threshold"),
            AdmissionError::RateLimitExceeded => write!(f, "admission rate limit exceeded"),
            AdmissionError::DuplicateIdentity => write!(f, "peer already admitted"),
            AdmissionError::BannedPeer => write!(f, "peer is banned"),
            AdmissionError::StaleDescriptor => write!(f, "peer descriptor is stale"),
        }
    }
}

// ---------------------------------------------------------------------------
// PeerAdmissionController
// ---------------------------------------------------------------------------

pub struct PeerAdmissionController {
    policy: AdmissionPolicy,
    admitted: HashSet<[u8; 32]>,
    banned: HashSet<[u8; 32]>,
    current_epoch: u64,
    admissions_this_epoch: u32,
}

impl PeerAdmissionController {
    pub fn new(policy: AdmissionPolicy) -> Self {
        Self {
            policy,
            admitted: HashSet::new(),
            banned: HashSet::new(),
            current_epoch: 0,
            admissions_this_epoch: 0,
        }
    }

    pub fn ban(&mut self, node_id: [u8; 32]) {
        self.banned.insert(node_id);
        self.admitted.remove(&node_id);
    }

    pub fn unban(&mut self, node_id: &[u8; 32]) {
        self.banned.remove(node_id);
    }

    /// Try to admit a peer.  Priority: Banned > Duplicate > Stale > RateLimit > TrustScore.
    pub fn admit(&mut self, req: AdmissionRequest) -> Result<(), AdmissionError> {
        if self.banned.contains(&req.node_id) {
            return Err(AdmissionError::BannedPeer);
        }
        if self.admitted.contains(&req.node_id) {
            return Err(AdmissionError::DuplicateIdentity);
        }
        if req.descriptor_epoch < self.policy.require_min_epoch {
            return Err(AdmissionError::StaleDescriptor);
        }
        if self.admissions_this_epoch >= self.policy.max_admissions_per_epoch {
            return Err(AdmissionError::RateLimitExceeded);
        }
        if req.trust_score < self.policy.min_trust_score {
            return Err(AdmissionError::TrustScoreTooLow);
        }
        self.admitted.insert(req.node_id);
        self.admissions_this_epoch += 1;
        Ok(())
    }

    /// Remove a peer (e.g. when it disconnects).
    pub fn evict(&mut self, node_id: &[u8; 32]) {
        self.admitted.remove(node_id);
    }

    pub fn advance_epoch(&mut self, epoch: u64) {
        self.current_epoch = epoch;
        self.admissions_this_epoch = 0;
    }

    pub fn admitted_count(&self) -> usize {
        self.admitted.len()
    }

    pub fn is_admitted(&self, node_id: &[u8; 32]) -> bool {
        self.admitted.contains(node_id)
    }

    pub fn is_banned(&self, node_id: &[u8; 32]) -> bool {
        self.banned.contains(node_id)
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

    fn req(id: u8, score: f64) -> AdmissionRequest {
        AdmissionRequest {
            node_id: nid(id),
            trust_score: score,
            descriptor_epoch: 0,
        }
    }

    fn controller() -> PeerAdmissionController {
        PeerAdmissionController::new(AdmissionPolicy::default())
    }

    // PAC1: peer with sufficient trust is admitted.
    #[test]
    fn pac1_admit_trusted() {
        let mut c = controller();
        c.admit(req(1, 0.8)).unwrap();
        assert!(c.is_admitted(&nid(1)));
    }

    // PAC2: peer below trust threshold is rejected.
    #[test]
    fn pac2_low_trust_rejected() {
        let mut c = controller();
        assert_eq!(c.admit(req(1, 0.1)), Err(AdmissionError::TrustScoreTooLow));
    }

    // PAC3: banned peer is rejected.
    #[test]
    fn pac3_banned_rejected() {
        let mut c = controller();
        c.ban(nid(1));
        assert_eq!(c.admit(req(1, 0.9)), Err(AdmissionError::BannedPeer));
    }

    // PAC4: duplicate admission is rejected.
    #[test]
    fn pac4_duplicate_rejected() {
        let mut c = controller();
        c.admit(req(1, 0.8)).unwrap();
        assert_eq!(c.admit(req(1, 0.9)), Err(AdmissionError::DuplicateIdentity));
    }

    // PAC5: rate limit blocks excess admissions in one epoch.
    #[test]
    fn pac5_rate_limit() {
        let policy = AdmissionPolicy {
            max_admissions_per_epoch: 2,
            ..Default::default()
        };
        let mut c = PeerAdmissionController::new(policy);
        c.admit(req(1, 0.8)).unwrap();
        c.admit(req(2, 0.8)).unwrap();
        assert_eq!(c.admit(req(3, 0.8)), Err(AdmissionError::RateLimitExceeded));
    }

    // PAC6: advance_epoch resets rate limit counter.
    #[test]
    fn pac6_advance_epoch_resets_rate() {
        let policy = AdmissionPolicy {
            max_admissions_per_epoch: 1,
            ..Default::default()
        };
        let mut c = PeerAdmissionController::new(policy);
        c.admit(req(1, 0.8)).unwrap();
        c.advance_epoch(1);
        c.admit(req(2, 0.8)).unwrap(); // should succeed now
        assert_eq!(c.admitted_count(), 2);
    }

    // PAC7: evict removes an admitted peer.
    #[test]
    fn pac7_evict() {
        let mut c = controller();
        c.admit(req(1, 0.8)).unwrap();
        c.evict(&nid(1));
        assert!(!c.is_admitted(&nid(1)));
    }

    // PAC8: unban allows re-admission.
    #[test]
    fn pac8_unban_allows_readmit() {
        let mut c = controller();
        c.ban(nid(1));
        c.unban(&nid(1));
        c.admit(req(1, 0.8)).unwrap();
        assert!(c.is_admitted(&nid(1)));
    }

    // PAC9: stale descriptor is rejected.
    #[test]
    fn pac9_stale_descriptor() {
        let policy = AdmissionPolicy {
            require_min_epoch: 5,
            ..Default::default()
        };
        let mut c = PeerAdmissionController::new(policy);
        let stale = AdmissionRequest {
            node_id: nid(1),
            trust_score: 0.9,
            descriptor_epoch: 3,
        };
        assert_eq!(c.admit(stale), Err(AdmissionError::StaleDescriptor));
    }

    // PAC10: ban removes from admitted set.
    #[test]
    fn pac10_ban_removes_admitted() {
        let mut c = controller();
        c.admit(req(1, 0.8)).unwrap();
        c.ban(nid(1));
        assert!(!c.is_admitted(&nid(1)));
        assert!(c.is_banned(&nid(1)));
    }
}
