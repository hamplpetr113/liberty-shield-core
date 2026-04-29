// NON-PRODUCTION: deterministic placeholder handshake manager.
// Manages per-peer handshake state machines for one local node.

use std::collections::HashMap;

use crate::handshake_message::HandshakeMessage;
use crate::handshake_state::PeerHandshake;
use crate::handshake_types::{HandshakeError, HandshakeNodeId, HandshakeState};

/// Manages all in-progress and completed handshakes for one node.
#[derive(Debug)]
pub struct HandshakeManager {
    local_id: HandshakeNodeId,
    handshakes: HashMap<u64, PeerHandshake>,
}

impl HandshakeManager {
    pub fn new(local_id: HandshakeNodeId) -> Self {
        Self {
            local_id,
            handshakes: HashMap::new(),
        }
    }

    pub fn local_id(&self) -> HandshakeNodeId {
        self.local_id
    }

    /// Begin a handshake as initiator toward `peer`.
    /// Returns the first message (ClientHello) to send to the peer.
    pub fn start_handshake(
        &mut self,
        peer: HandshakeNodeId,
    ) -> Result<HandshakeMessage, HandshakeError> {
        if self.handshakes.contains_key(&peer.0) {
            let state = self.handshakes[&peer.0].state();
            if state == HandshakeState::Established {
                return Err(HandshakeError::AlreadyEstablished);
            }
        }
        let mut hs = PeerHandshake::new_initiator(self.local_id, peer);
        let msg = hs.next_message(self.local_id)?;
        self.handshakes.insert(peer.0, hs);
        Ok(msg)
    }

    /// Process an inbound handshake message.
    ///
    /// - If the peer is unknown and the message is a `ClientHello`, a responder
    ///   session is auto-created.
    /// - Returns `Some(reply)` when a response must be sent back to the peer.
    /// - Returns `None` when no response is needed (handshake complete on this side).
    pub fn receive_message(
        &mut self,
        msg: HandshakeMessage,
    ) -> Result<Option<HandshakeMessage>, HandshakeError> {
        let peer_id = msg.source_node;
        // Auto-create responder state if we haven't seen this peer yet.
        if !self.handshakes.contains_key(&peer_id.0) {
            let hs = PeerHandshake::new_responder(self.local_id, peer_id);
            self.handshakes.insert(peer_id.0, hs);
        }
        let hs = self.handshakes.get_mut(&peer_id.0).unwrap();
        hs.receive(&msg, self.local_id)
    }

    /// Returns `true` when the handshake with `peer` has reached `Established`.
    pub fn is_established(&self, peer: HandshakeNodeId) -> bool {
        self.handshakes
            .get(&peer.0)
            .map(|hs| hs.state() == HandshakeState::Established)
            .unwrap_or(false)
    }

    /// Derive `(send_seed, recv_seed)` for an established peer session.
    ///
    /// Returns `Err(UnknownPeer)` if no handshake exists for the peer.
    /// Returns `Err(InvalidState)` if the handshake is not yet established.
    pub fn derive_session_seeds(
        &self,
        peer: HandshakeNodeId,
    ) -> Result<(u64, u64), HandshakeError> {
        self.handshakes
            .get(&peer.0)
            .ok_or(HandshakeError::UnknownPeer)?
            .derive_seeds()
    }

    /// Number of tracked peer handshakes (regardless of state).
    pub fn peer_count(&self) -> usize {
        self.handshakes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake_types::HandshakeError;

    const ID_A: HandshakeNodeId = HandshakeNodeId(1);
    const ID_B: HandshakeNodeId = HandshakeNodeId(2);
    const ID_C: HandshakeNodeId = HandshakeNodeId(3);

    /// Run a full 3-message handshake between `a` and `b`.
    fn complete_handshake(a: &mut HandshakeManager, b: &mut HandshakeManager) {
        let m1 = a.start_handshake(ID_B).unwrap();
        let m2 = b.receive_message(m1).unwrap().unwrap();
        let m3 = a.receive_message(m2).unwrap().unwrap();
        b.receive_message(m3).unwrap();
    }

    // H1: initiator handshake produces ClientHello and advances state
    #[test]
    fn h1_initiator_handshake() {
        let mut mgr = HandshakeManager::new(ID_A);
        let msg = mgr.start_handshake(ID_B).unwrap();
        assert_eq!(
            msg.message_type,
            crate::handshake_types::HandshakeMessageType::ClientHello
        );
        assert_eq!(msg.source_node, ID_A);
        assert_eq!(msg.target_node, ID_B);
        assert!(!mgr.is_established(ID_B));
    }

    // H2: responder handshake auto-creates state and replies
    #[test]
    fn h2_responder_handshake() {
        let mut a = HandshakeManager::new(ID_A);
        let mut b = HandshakeManager::new(ID_B);
        let m1 = a.start_handshake(ID_B).unwrap();
        let m2 = b.receive_message(m1).unwrap().unwrap();
        assert_eq!(
            m2.message_type,
            crate::handshake_types::HandshakeMessageType::ServerHello
        );
        assert_eq!(m2.source_node, ID_B);
        assert!(!b.is_established(ID_A));
    }

    // H3: out of order message rejected
    #[test]
    fn h3_out_of_order_rejected() {
        let mut a = HandshakeManager::new(ID_A);
        let mut b = HandshakeManager::new(ID_B);
        let m1 = a.start_handshake(ID_B).unwrap();
        let m2 = b.receive_message(m1).unwrap().unwrap();
        // Re-send m2 to B (B already sent ServerHello, now receives ServerHello again)
        assert_eq!(
            b.receive_message(m2).unwrap_err(),
            HandshakeError::OutOfOrder
        );
    }

    // H4: duplicate message rejected
    #[test]
    fn h4_duplicate_message_rejected() {
        let mut a = HandshakeManager::new(ID_A);
        let mut b = HandshakeManager::new(ID_B);
        let m1 = a.start_handshake(ID_B).unwrap();
        b.receive_message(m1.clone()).unwrap();
        assert_eq!(
            b.receive_message(m1).unwrap_err(),
            HandshakeError::Duplicate
        );
    }

    // H5: deterministic seed derivation — same IDs always produce same seeds
    #[test]
    fn h5_deterministic_seed_derivation() {
        let seeds1 = {
            let mut a = HandshakeManager::new(ID_A);
            let mut b = HandshakeManager::new(ID_B);
            complete_handshake(&mut a, &mut b);
            a.derive_session_seeds(ID_B).unwrap()
        };
        let seeds2 = {
            let mut a = HandshakeManager::new(ID_A);
            let mut b = HandshakeManager::new(ID_B);
            complete_handshake(&mut a, &mut b);
            a.derive_session_seeds(ID_B).unwrap()
        };
        assert_eq!(seeds1, seeds2);
    }

    // H6: unknown peer rejected on derive_session_seeds
    #[test]
    fn h6_unknown_peer_rejected() {
        let mgr = HandshakeManager::new(ID_A);
        assert_eq!(
            mgr.derive_session_seeds(ID_C).unwrap_err(),
            HandshakeError::UnknownPeer
        );
        assert!(!mgr.is_established(ID_C));
    }

    // H7: reject message transitions peer to Failed
    #[test]
    fn h7_reject_transitions_failed() {
        use crate::handshake_types::HandshakeMessageType;
        let mut b = HandshakeManager::new(ID_B);
        let reject = HandshakeMessage {
            source_node: ID_A,
            target_node: ID_B,
            message_type: HandshakeMessageType::Reject,
            sequence: 0,
            payload: Vec::new(),
        };
        let err = b.receive_message(reject).unwrap_err();
        assert_eq!(err, HandshakeError::PeerRejected);
        // State after reject is Failed; session seeds are unavailable
        assert_eq!(
            b.derive_session_seeds(ID_A).unwrap_err(),
            HandshakeError::InvalidState
        );
    }

    // H8: complete handshake between two managers — both established, seeds match
    #[test]
    fn h8_handshake_completion_between_two_managers() {
        let mut a = HandshakeManager::new(ID_A);
        let mut b = HandshakeManager::new(ID_B);
        complete_handshake(&mut a, &mut b);
        assert!(a.is_established(ID_B));
        assert!(b.is_established(ID_A));
        let (a_send, a_recv) = a.derive_session_seeds(ID_B).unwrap();
        let (b_send, b_recv) = b.derive_session_seeds(ID_A).unwrap();
        assert_eq!(a_send, b_recv, "A send_seed must equal B recv_seed");
        assert_eq!(b_send, a_recv, "B send_seed must equal A recv_seed");
        // Seeds are nonzero
        assert_ne!(a_send, 0);
        assert_ne!(a_recv, 0);
    }

    // H9: already-established peer rejected on second start_handshake
    #[test]
    fn h9_already_established_rejected() {
        let mut a = HandshakeManager::new(ID_A);
        let mut b = HandshakeManager::new(ID_B);
        complete_handshake(&mut a, &mut b);
        assert_eq!(
            a.start_handshake(ID_B).unwrap_err(),
            HandshakeError::AlreadyEstablished
        );
    }
}
