//! Directory client — ingests signed consensus documents and builds candidate pools.
//!
//! Integrates with:
//! - `directory_authority::DirectoryConsensus` for signature verification and epoch tracking.
//! - `path_selection::{CandidatePeer, PathSelector, PeerRole}` for path building.
//!
//! Role assignment: `sha256(node_id)[0] % 3` →  0 = Guard, 1 = Relay, 2 = Exit.

use crate::crypto::sha256;
use crate::directory_authority::{AuthorityIdentity, DirectoryConsensus};
use crate::path_selection::{CandidatePeer, HopPath, PathError, PathSelector, PeerRole};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum ClientError {
    /// The consensus signature did not verify.
    InvalidSignature,
    /// The proposed epoch is not newer than the current one.
    StaleEpoch { current: u64, proposed: u64 },
    /// A node_id appears more than once in the consensus.
    DuplicateNodeId([u8; 32]),
    /// The consensus contains no descriptors.
    EmptyConsensus,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::InvalidSignature => write!(f, "consensus signature invalid"),
            ClientError::StaleEpoch { current, proposed } => {
                write!(f, "stale epoch: proposed {proposed} <= current {current}")
            }
            ClientError::DuplicateNodeId(_) => write!(f, "duplicate node_id in consensus"),
            ClientError::EmptyConsensus => write!(f, "consensus contains no descriptors"),
        }
    }
}

// ---------------------------------------------------------------------------
// Role assignment
// ---------------------------------------------------------------------------

fn assign_role(node_id: &[u8; 32]) -> PeerRole {
    let digest = sha256(node_id);
    match digest[0] % 3 {
        0 => PeerRole::Guard,
        1 => PeerRole::Relay,
        _ => PeerRole::Exit,
    }
}

// ---------------------------------------------------------------------------
// DirectoryClient
// ---------------------------------------------------------------------------

/// Client that consumes consensus documents and exposes a `PathSelector`.
pub struct DirectoryClient {
    authority: AuthorityIdentity,
    current_epoch: u64,
    candidates: Vec<CandidatePeer>,
}

impl DirectoryClient {
    /// Create a client that trusts `authority` to sign consensus documents.
    pub fn new(authority: AuthorityIdentity) -> Self {
        Self {
            authority,
            current_epoch: 0,
            candidates: Vec::new(),
        }
    }

    /// Verify `consensus` against the stored authority (does not update state).
    pub fn verify_consensus(&self, consensus: &DirectoryConsensus) -> bool {
        consensus.verify(&self.authority)
    }

    /// Ingest a consensus document:
    /// 1. Verify signature.
    /// 2. Check epoch is strictly newer.
    /// 3. Check for duplicate node_ids.
    /// 4. Rebuild the candidate pool.
    pub fn ingest_consensus(&mut self, consensus: &DirectoryConsensus) -> Result<(), ClientError> {
        if !consensus.verify(&self.authority) {
            return Err(ClientError::InvalidSignature);
        }
        if consensus.epoch <= self.current_epoch {
            return Err(ClientError::StaleEpoch {
                current: self.current_epoch,
                proposed: consensus.epoch,
            });
        }
        if consensus.descriptors.is_empty() {
            return Err(ClientError::EmptyConsensus);
        }
        // Check for duplicates.
        let mut seen = std::collections::HashSet::new();
        for sd in &consensus.descriptors {
            if !seen.insert(sd.descriptor.node_id) {
                return Err(ClientError::DuplicateNodeId(sd.descriptor.node_id));
            }
        }
        // Build candidate pool.
        let candidates = consensus
            .descriptors
            .iter()
            .map(|sd| {
                let node_id = sd.descriptor.node_id;
                let public_key = sd.descriptor.public_key;
                let role = assign_role(&node_id);
                CandidatePeer {
                    node_id,
                    public_key,
                    role,
                }
            })
            .collect();

        self.current_epoch = consensus.epoch;
        self.candidates = candidates;
        Ok(())
    }

    /// Build a 3-hop path from the current candidate pool.
    pub fn build_path(&self) -> Result<HopPath, PathError> {
        PathSelector::new().select(&self.candidates)
    }

    /// All candidates in the current pool.
    pub fn candidates(&self) -> &[CandidatePeer] {
        &self.candidates
    }

    /// Guards in the current pool.
    pub fn guards(&self) -> Vec<&CandidatePeer> {
        self.candidates
            .iter()
            .filter(|p| p.role == PeerRole::Guard)
            .collect()
    }

    /// Relays in the current pool.
    pub fn relays(&self) -> Vec<&CandidatePeer> {
        self.candidates
            .iter()
            .filter(|p| p.role == PeerRole::Relay)
            .collect()
    }

    /// Exits in the current pool.
    pub fn exits(&self) -> Vec<&CandidatePeer> {
        self.candidates
            .iter()
            .filter(|p| p.role == PeerRole::Exit)
            .collect()
    }

    /// Current epoch number.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::directory_authority::{AuthorityIdentity, DirectoryConsensus};
    use crate::node_descriptor::NodeDescriptor;
    use crate::node_identity::NodeIdentity;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn make_authority(seed: u8) -> AuthorityIdentity {
        AuthorityIdentity::new(NodeIdentity::generate_from_seed([seed; 32]))
    }

    fn make_descriptor(
        auth: &AuthorityIdentity,
        seed: u8,
    ) -> crate::directory_authority::SignedNodeDescriptor {
        let pk = NodeIdentity::generate_from_seed([seed; 32]).public_key;
        let desc = NodeDescriptor::new(pk, addr(9000 + seed as u16));
        auth.sign_descriptor(desc)
    }

    /// Build a consensus with `n` descriptors, epoch = `epoch`, prev = `prev_epoch`.
    fn make_consensus(
        auth: &AuthorityIdentity,
        seeds: &[u8],
        epoch: u64,
        prev_epoch: u64,
    ) -> DirectoryConsensus {
        let mut builder = DirectoryConsensus::begin(auth, epoch, prev_epoch).unwrap();
        for &seed in seeds {
            builder.add_descriptor(make_descriptor(auth, seed)).unwrap();
        }
        builder.finalise(auth)
    }

    fn client(auth: AuthorityIdentity) -> DirectoryClient {
        DirectoryClient::new(auth)
    }

    // DCL1: valid consensus is accepted.
    #[test]
    fn dcl1_valid_consensus_accepted() {
        let auth = make_authority(0x01);
        let consensus = make_consensus(&auth, &[10, 20, 30], 1, 0);
        let mut c = client(auth);
        assert!(c.ingest_consensus(&consensus).is_ok());
        assert_eq!(c.current_epoch(), 1);
        assert_eq!(c.candidates().len(), 3);
    }

    // DCL2: invalid signature is rejected.
    #[test]
    fn dcl2_invalid_signature_rejected() {
        let auth = make_authority(0x02);
        let mut consensus = make_consensus(&auth, &[10, 20, 30], 1, 0);
        consensus.signature[0] ^= 0xFF; // tamper
        let mut c = client(auth);
        assert_eq!(
            c.ingest_consensus(&consensus).unwrap_err(),
            ClientError::InvalidSignature
        );
    }

    // DCL3: stale epoch is rejected.
    #[test]
    fn dcl3_stale_epoch_rejected() {
        let auth = make_authority(0x03);
        let c1 = make_consensus(&auth, &[10, 20, 30], 5, 0);
        let c2 = make_consensus(&auth, &[11, 21, 31], 5, 4);
        let mut c = client(auth);
        c.ingest_consensus(&c1).unwrap();
        assert!(matches!(
            c.ingest_consensus(&c2).unwrap_err(),
            ClientError::StaleEpoch { .. }
        ));
    }

    // DCL4: empty consensus is rejected.
    #[test]
    fn dcl4_empty_consensus_rejected() {
        let auth = make_authority(0x04);
        let consensus = make_consensus(&auth, &[], 1, 0);
        let mut c = client(auth);
        assert_eq!(
            c.ingest_consensus(&consensus).unwrap_err(),
            ClientError::EmptyConsensus
        );
    }

    // DCL5: verify_consensus returns true for valid, false for tampered.
    #[test]
    fn dcl5_verify_consensus() {
        let auth = make_authority(0x05);
        let consensus = make_consensus(&auth, &[10, 20], 1, 0);
        let c = client(auth);
        assert!(c.verify_consensus(&consensus));

        let auth2 = make_authority(0x06);
        let c2 = client(auth2); // different authority
        assert!(!c2.verify_consensus(&consensus));
    }

    // DCL6: guard extraction returns only Guard-role peers.
    #[test]
    fn dcl6_guard_extraction() {
        let auth = make_authority(0x07);
        // Use enough nodes to guarantee at least one of each role via hash distribution.
        let seeds: Vec<u8> = (0x10..0x20).collect();
        let consensus = make_consensus(&auth, &seeds, 1, 0);
        let mut c = client(auth);
        c.ingest_consensus(&consensus).unwrap();
        for g in c.guards() {
            assert_eq!(g.role, PeerRole::Guard);
        }
    }

    // DCL7: relay extraction returns only Relay-role peers.
    #[test]
    fn dcl7_relay_extraction() {
        let auth = make_authority(0x08);
        let seeds: Vec<u8> = (0x10..0x20).collect();
        let consensus = make_consensus(&auth, &seeds, 1, 0);
        let mut c = client(auth);
        c.ingest_consensus(&consensus).unwrap();
        for r in c.relays() {
            assert_eq!(r.role, PeerRole::Relay);
        }
    }

    // DCL8: exit extraction returns only Exit-role peers.
    #[test]
    fn dcl8_exit_extraction() {
        let auth = make_authority(0x09);
        let seeds: Vec<u8> = (0x10..0x20).collect();
        let consensus = make_consensus(&auth, &seeds, 1, 0);
        let mut c = client(auth);
        c.ingest_consensus(&consensus).unwrap();
        for e in c.exits() {
            assert_eq!(e.role, PeerRole::Exit);
        }
    }

    // DCL9: build_path returns a valid 3-hop path (when pool is large enough).
    #[test]
    fn dcl9_build_path() {
        let auth = make_authority(0x0A);
        let seeds: Vec<u8> = (0x10..0x20).collect(); // 16 nodes
        let consensus = make_consensus(&auth, &seeds, 1, 0);
        let mut c = client(auth);
        c.ingest_consensus(&consensus).unwrap();
        // Path building works if we have at least one of each role.
        if !c.guards().is_empty() && !c.relays().is_empty() && !c.exits().is_empty() {
            let path = c.build_path().unwrap();
            assert_eq!(path.guard.role, PeerRole::Guard);
            assert_eq!(path.relay.role, PeerRole::Relay);
            assert_eq!(path.exit.role, PeerRole::Exit);
        }
    }

    // DCL10: epoch advances correctly after multiple ingests.
    #[test]
    fn dcl10_epoch_advances() {
        let auth = make_authority(0x0B);
        let mut c = client(auth.clone());
        // Use different auth clone for building consensuses (sharing same authority).
        let auth2 = make_authority(0x0B);
        let c1 = make_consensus(&auth, &[10, 20, 30], 1, 0);
        let c2 = make_consensus(&auth2, &[11, 21, 31], 2, 1);
        c.ingest_consensus(&c1).unwrap();
        assert_eq!(c.current_epoch(), 1);
        // Can't reuse auth after it was moved — need to rebuild client
        let mut c3 = DirectoryClient::new(make_authority(0x0B));
        c3.ingest_consensus(&c1).unwrap();
        c3.ingest_consensus(&c2).unwrap();
        assert_eq!(c3.current_epoch(), 2);
    }
}
