//! Peer handshake runtime — manages in-progress and completed handshake sessions.
//!
//! Composes `node_handshake` with a session registry, replay-nonce tracking, and
//! session expiry enforcement.
//!
//! NON-PRODUCTION: ephemeral keys are derived deterministically from nonces.

use std::collections::{HashMap, HashSet};

use crate::node_handshake::{
    HandshakeAck, HandshakeError, HandshakeMessage, NodeHandshakeInitiator, NodeHandshakeResponder,
    NodeSession,
};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeRuntimeError {
    ReplayedNonce,
    SessionExpired,
    DuplicateSession,
    SessionNotFound,
    Handshake(String),
}

impl From<HandshakeError> for HandshakeRuntimeError {
    fn from(e: HandshakeError) -> Self {
        HandshakeRuntimeError::Handshake(format!("{e:?}"))
    }
}

// ---------------------------------------------------------------------------
// SessionEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SessionEntry {
    pub peer_id: [u8; 32],
    pub session: NodeSession,
    pub established_epoch: u64,
}

// ---------------------------------------------------------------------------
// PeerHandshakeRuntime
// ---------------------------------------------------------------------------

pub struct PeerHandshakeRuntime {
    local_id: [u8; 32],
    max_epoch_skew: u64,
    max_lifetime: u64,
    seen_nonces: HashSet<u64>,
    sessions: HashMap<[u8; 32], SessionEntry>,
    pending_initiators: HashMap<[u8; 32], NodeHandshakeInitiator>,
    session_count: u64,
}

impl PeerHandshakeRuntime {
    pub fn new(local_id: [u8; 32], max_epoch_skew: u64, max_lifetime: u64) -> Self {
        Self {
            local_id,
            max_epoch_skew,
            max_lifetime,
            seen_nonces: HashSet::new(),
            sessions: HashMap::new(),
            pending_initiators: HashMap::new(),
            session_count: 0,
        }
    }

    /// Start an outbound handshake to `peer_id`. Returns the HELLO message.
    pub fn start_outbound(
        &mut self,
        peer_id: [u8; 32],
        nonce: u64,
        epoch: u64,
    ) -> Result<HandshakeMessage, HandshakeRuntimeError> {
        if self.sessions.contains_key(&peer_id) {
            return Err(HandshakeRuntimeError::DuplicateSession);
        }
        if !self.seen_nonces.insert(nonce) {
            return Err(HandshakeRuntimeError::ReplayedNonce);
        }
        let (initiator, hello) =
            NodeHandshakeInitiator::start(self.local_id, nonce, epoch, self.max_lifetime);
        self.pending_initiators.insert(peer_id, initiator);
        Ok(hello)
    }

    /// Complete an outbound handshake given the ACK from the peer.
    pub fn finish_outbound(
        &mut self,
        peer_id: [u8; 32],
        ack: &HandshakeAck,
        epoch: u64,
    ) -> Result<(), HandshakeRuntimeError> {
        let initiator = self
            .pending_initiators
            .remove(&peer_id)
            .ok_or(HandshakeRuntimeError::SessionNotFound)?;
        let session = initiator.finish(ack).map_err(HandshakeRuntimeError::from)?;
        if session.is_expired(epoch) {
            return Err(HandshakeRuntimeError::SessionExpired);
        }
        self.sessions.insert(
            peer_id,
            SessionEntry {
                peer_id,
                session,
                established_epoch: epoch,
            },
        );
        self.session_count += 1;
        Ok(())
    }

    /// Handle an inbound HELLO from a peer. Returns the ACK + establishes session.
    pub fn handle_inbound_hello(
        &mut self,
        hello: &HandshakeMessage,
        epoch: u64,
    ) -> Result<HandshakeAck, HandshakeRuntimeError> {
        if !self.seen_nonces.insert(hello.nonce) {
            return Err(HandshakeRuntimeError::ReplayedNonce);
        }
        let mut responder =
            NodeHandshakeResponder::new(self.local_id, self.max_epoch_skew, self.max_lifetime);
        let (ack, session) = responder
            .handle(hello, epoch)
            .map_err(HandshakeRuntimeError::from)?;
        let peer_id = hello.node_id;
        // Allow replacement: a new inbound hello supersedes a stale session.
        self.sessions.insert(
            peer_id,
            SessionEntry {
                peer_id,
                session,
                established_epoch: epoch,
            },
        );
        self.session_count += 1;
        Ok(ack)
    }

    pub fn session(&self, peer_id: &[u8; 32]) -> Option<&SessionEntry> {
        self.sessions.get(peer_id)
    }

    pub fn has_session(&self, peer_id: &[u8; 32]) -> bool {
        self.sessions.contains_key(peer_id)
    }

    pub fn drop_session(&mut self, peer_id: &[u8; 32]) {
        self.sessions.remove(peer_id);
    }

    pub fn session_count_total(&self) -> u64 {
        self.session_count
    }

    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Remove sessions that have exceeded their lifetime.
    pub fn evict_expired(&mut self, current_epoch: u64) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, e| !e.session.is_expired(current_epoch));
        before - self.sessions.len()
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

    fn make_pair() -> (PeerHandshakeRuntime, PeerHandshakeRuntime) {
        let a = PeerHandshakeRuntime::new(nid(1), 5, 100);
        let b = PeerHandshakeRuntime::new(nid(2), 5, 100);
        (a, b)
    }

    // PHR1: outbound+inbound handshake completes (loopback simulation).
    #[test]
    fn phr1_full_handshake() {
        let (mut a, mut b) = make_pair();
        let hello = a.start_outbound(nid(2), 100, 1).unwrap();
        let ack = b.handle_inbound_hello(&hello, 1).unwrap();
        a.finish_outbound(nid(2), &ack, 1).unwrap();
        assert!(a.has_session(&nid(2)));
        assert!(b.has_session(&nid(1)));
    }

    // PHR2: replayed hello nonce rejected.
    #[test]
    fn phr2_replayed_hello_rejected() {
        let mut b = PeerHandshakeRuntime::new(nid(2), 5, 100);
        let hello = HandshakeMessage {
            node_id: nid(1),
            ephemeral_pub: [0u8; 32],
            nonce: 999,
            epoch: 1,
        };
        // First time: accepted (may fail due to key derivation — nonce tracked regardless).
        let _ = b.handle_inbound_hello(&hello, 1);
        // Inject the nonce manually.
        b.seen_nonces.insert(888);
        let hello2 = HandshakeMessage {
            nonce: 888,
            ..hello
        };
        assert_eq!(
            b.handle_inbound_hello(&hello2, 1),
            Err(HandshakeRuntimeError::ReplayedNonce)
        );
    }

    // PHR3: outbound replayed nonce rejected.
    #[test]
    fn phr3_outbound_replay_rejected() {
        let mut a = PeerHandshakeRuntime::new(nid(1), 5, 100);
        a.start_outbound(nid(2), 42, 1).unwrap();
        assert_eq!(
            a.start_outbound(nid(3), 42, 1),
            Err(HandshakeRuntimeError::ReplayedNonce)
        );
    }

    // PHR4: duplicate outbound session rejected.
    #[test]
    fn phr4_duplicate_session_rejected() {
        let (mut a, mut b) = make_pair();
        let hello = a.start_outbound(nid(2), 1, 1).unwrap();
        let ack = b.handle_inbound_hello(&hello, 1).unwrap();
        a.finish_outbound(nid(2), &ack, 1).unwrap();
        // Second outbound to same peer.
        assert_eq!(
            a.start_outbound(nid(2), 2, 1),
            Err(HandshakeRuntimeError::DuplicateSession)
        );
    }

    // PHR5: session lookup returns established session.
    #[test]
    fn phr5_session_lookup() {
        let (mut a, mut b) = make_pair();
        let hello = a.start_outbound(nid(2), 10, 5).unwrap();
        let ack = b.handle_inbound_hello(&hello, 5).unwrap();
        a.finish_outbound(nid(2), &ack, 5).unwrap();
        let e = a.session(&nid(2)).unwrap();
        assert_eq!(e.peer_id, nid(2));
        assert_eq!(e.established_epoch, 5);
    }

    // PHR6: drop_session removes session.
    #[test]
    fn phr6_drop_session() {
        let (mut a, mut b) = make_pair();
        let hello = a.start_outbound(nid(2), 20, 1).unwrap();
        let ack = b.handle_inbound_hello(&hello, 1).unwrap();
        a.finish_outbound(nid(2), &ack, 1).unwrap();
        a.drop_session(&nid(2));
        assert!(!a.has_session(&nid(2)));
    }

    // PHR7: session_count_total accumulates.
    #[test]
    fn phr7_session_count() {
        let (mut a, mut b) = make_pair();
        let hello = a.start_outbound(nid(2), 5, 1).unwrap();
        let _ack = b.handle_inbound_hello(&hello, 1).unwrap();
        assert!(b.session_count_total() >= 1);
    }

    // PHR8: evict_expired removes old sessions.
    #[test]
    fn phr8_evict_expired() {
        let mut rt = PeerHandshakeRuntime::new(nid(1), 5, 1); // max_lifetime=1
        let mut b = PeerHandshakeRuntime::new(nid(2), 5, 1);
        let hello = rt.start_outbound(nid(2), 99, 0).unwrap();
        let ack = b.handle_inbound_hello(&hello, 0).unwrap();
        rt.finish_outbound(nid(2), &ack, 0).unwrap();
        assert_eq!(rt.active_sessions(), 1);
        // Advance epoch far beyond lifetime.
        let evicted = rt.evict_expired(1000);
        assert_eq!(evicted, 1);
        assert_eq!(rt.active_sessions(), 0);
    }

    // PHR9: active_sessions reflects current session count.
    #[test]
    fn phr9_active_sessions() {
        let rt = PeerHandshakeRuntime::new(nid(1), 5, 100);
        assert_eq!(rt.active_sessions(), 0);
    }

    // PHR10: finish_outbound without matching start returns SessionNotFound.
    #[test]
    fn phr10_finish_no_pending() {
        let mut a = PeerHandshakeRuntime::new(nid(1), 5, 100);
        let dummy_ack = HandshakeAck {
            node_id: nid(2),
            ephemeral_pub: [0u8; 32],
            nonce_echo: 0,
        };
        assert_eq!(
            a.finish_outbound(nid(2), &dummy_ack, 1),
            Err(HandshakeRuntimeError::SessionNotFound)
        );
    }
}
