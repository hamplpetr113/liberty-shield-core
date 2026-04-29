// NON-PRODUCTION: deterministic handshake state machine.
// Nonces are derived from node IDs, not from random ephemeral values.
// Replace with real ephemeral key generation for production.

use crate::handshake_message::HandshakeMessage;
use crate::handshake_types::{
    HandshakeError, HandshakeMessageType, HandshakeNodeId, HandshakeRole, HandshakeState,
};

/// Derive a deterministic nonce from a node ID.
/// NON-PRODUCTION: not random; just a well-mixed hash.
fn nonce_from_id(id: HandshakeNodeId) -> u64 {
    id.0.wrapping_mul(0x9e3779b97f4a7c15)
        .wrapping_add(0x6c62272e07bb0142)
}

/// Derive the send and receive session seeds from two nonces.
///
/// Given initiator nonce `na` and responder nonce `nb`:
///   - send_seed(A→B) = mix(na, nb)   recv_seed(A→B) = mix(nb, na)
///   - send_seed(B→A) = mix(nb, na)   recv_seed(B→A) = mix(na, nb)
///
/// This guarantees A.send_seed == B.recv_seed and B.send_seed == A.recv_seed.
/// NON-PRODUCTION: use HKDF in production.
fn mix(a: u64, b: u64) -> u64 {
    a.wrapping_mul(0xbf58476d1ce4e5b9)
        .wrapping_add(b)
        .wrapping_mul(0x94d049bb133111eb)
}

/// Per-peer handshake state for one half of the exchange.
#[derive(Debug)]
pub struct PeerHandshake {
    pub peer_id: HandshakeNodeId,
    pub role: HandshakeRole,
    pub state: HandshakeState,
    local_nonce: u64,
    remote_nonce: u64,
    seen_sequences: Vec<u32>,
}

impl PeerHandshake {
    pub fn new_initiator(local_id: HandshakeNodeId, peer_id: HandshakeNodeId) -> Self {
        Self {
            peer_id,
            role: HandshakeRole::Initiator,
            state: HandshakeState::Created,
            local_nonce: nonce_from_id(local_id),
            remote_nonce: 0,
            seen_sequences: Vec::new(),
        }
    }

    pub fn new_responder(local_id: HandshakeNodeId, peer_id: HandshakeNodeId) -> Self {
        Self {
            peer_id,
            role: HandshakeRole::Responder,
            state: HandshakeState::Created,
            local_nonce: nonce_from_id(local_id),
            remote_nonce: 0,
            seen_sequences: Vec::new(),
        }
    }

    /// Produce the next outbound message (without receiving one first).
    /// Valid only for the initiator from `Created` state.
    pub fn next_message(
        &mut self,
        local_id: HandshakeNodeId,
    ) -> Result<HandshakeMessage, HandshakeError> {
        match (self.role, self.state) {
            (HandshakeRole::Initiator, HandshakeState::Created) => {
                self.state = HandshakeState::Message1Sent;
                Ok(HandshakeMessage {
                    source_node: local_id,
                    target_node: self.peer_id,
                    message_type: HandshakeMessageType::ClientHello,
                    sequence: 0,
                    payload: HandshakeMessage::nonce_payload(self.local_nonce),
                })
            }
            _ => Err(HandshakeError::InvalidState),
        }
    }

    /// Process an inbound message; returns a reply if one is required.
    pub fn receive(
        &mut self,
        msg: &HandshakeMessage,
        local_id: HandshakeNodeId,
    ) -> Result<Option<HandshakeMessage>, HandshakeError> {
        // Reject duplicate sequences.
        if self.seen_sequences.contains(&msg.sequence) {
            return Err(HandshakeError::Duplicate);
        }

        // Handle Reject from the remote side.
        if msg.message_type == HandshakeMessageType::Reject {
            self.state = HandshakeState::Failed;
            return Err(HandshakeError::PeerRejected);
        }

        match (self.role, self.state, msg.message_type) {
            // Responder: Created → receives ClientHello → sends ServerHello
            (
                HandshakeRole::Responder,
                HandshakeState::Created,
                HandshakeMessageType::ClientHello,
            ) => {
                if msg.sequence != 0 {
                    return Err(HandshakeError::OutOfOrder);
                }
                self.remote_nonce = msg.extract_nonce();
                self.seen_sequences.push(msg.sequence);
                self.state = HandshakeState::Message1Received;
                // Immediately reply with ServerHello and advance to Message2Sent.
                self.state = HandshakeState::Message2Sent;
                Ok(Some(HandshakeMessage {
                    source_node: local_id,
                    target_node: msg.source_node,
                    message_type: HandshakeMessageType::ServerHello,
                    sequence: 1,
                    payload: HandshakeMessage::nonce_payload(self.local_nonce),
                }))
            }

            // Initiator: Message1Sent → receives ServerHello → sends ClientFinish
            (
                HandshakeRole::Initiator,
                HandshakeState::Message1Sent,
                HandshakeMessageType::ServerHello,
            ) => {
                if msg.sequence != 1 {
                    return Err(HandshakeError::OutOfOrder);
                }
                self.remote_nonce = msg.extract_nonce();
                self.seen_sequences.push(msg.sequence);
                self.state = HandshakeState::Message2Received;
                // Reply with ClientFinish and transition to Established.
                self.state = HandshakeState::Established;
                Ok(Some(HandshakeMessage {
                    source_node: local_id,
                    target_node: msg.source_node,
                    message_type: HandshakeMessageType::ClientFinish,
                    sequence: 2,
                    payload: Vec::new(),
                }))
            }

            // Responder: Message2Sent → receives ClientFinish → Established
            (
                HandshakeRole::Responder,
                HandshakeState::Message2Sent,
                HandshakeMessageType::ClientFinish,
            ) => {
                if msg.sequence != 2 {
                    return Err(HandshakeError::OutOfOrder);
                }
                self.seen_sequences.push(msg.sequence);
                self.state = HandshakeState::Established;
                Ok(None)
            }

            // Any other combination is invalid.
            _ => {
                self.state = HandshakeState::Failed;
                Err(HandshakeError::OutOfOrder)
            }
        }
    }

    /// Derive session seeds once the handshake is `Established`.
    ///
    /// Returns `(send_seed, recv_seed)` from this node's perspective.
    /// `send_seed` encrypts data sent to the peer; `recv_seed` decrypts data from the peer.
    pub fn derive_seeds(&self) -> Result<(u64, u64), HandshakeError> {
        if self.state != HandshakeState::Established {
            return Err(HandshakeError::InvalidState);
        }
        let send_seed = mix(self.local_nonce, self.remote_nonce);
        let recv_seed = mix(self.remote_nonce, self.local_nonce);
        Ok((send_seed, recv_seed))
    }

    pub fn state(&self) -> HandshakeState {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID_A: HandshakeNodeId = HandshakeNodeId(1);
    const ID_B: HandshakeNodeId = HandshakeNodeId(2);

    // HS1: initiator next_message produces ClientHello from Created
    #[test]
    fn hs1_initiator_produces_client_hello() {
        let mut hs = PeerHandshake::new_initiator(ID_A, ID_B);
        let msg = hs.next_message(ID_A).unwrap();
        assert_eq!(msg.message_type, HandshakeMessageType::ClientHello);
        assert_eq!(msg.sequence, 0);
        assert_eq!(msg.source_node, ID_A);
        assert_eq!(msg.target_node, ID_B);
        assert_eq!(hs.state(), HandshakeState::Message1Sent);
    }

    // HS2: responder receives ClientHello, produces ServerHello
    #[test]
    fn hs2_responder_receives_client_hello() {
        let mut init = PeerHandshake::new_initiator(ID_A, ID_B);
        let mut resp = PeerHandshake::new_responder(ID_B, ID_A);
        let hello = init.next_message(ID_A).unwrap();
        let reply = resp.receive(&hello, ID_B).unwrap().unwrap();
        assert_eq!(reply.message_type, HandshakeMessageType::ServerHello);
        assert_eq!(reply.sequence, 1);
        assert_eq!(resp.state(), HandshakeState::Message2Sent);
    }

    // HS3: initiator receives ServerHello, produces ClientFinish, state=Established
    #[test]
    fn hs3_initiator_receives_server_hello() {
        let mut init = PeerHandshake::new_initiator(ID_A, ID_B);
        let mut resp = PeerHandshake::new_responder(ID_B, ID_A);
        let hello = init.next_message(ID_A).unwrap();
        let server_hello = resp.receive(&hello, ID_B).unwrap().unwrap();
        let finish = init.receive(&server_hello, ID_A).unwrap().unwrap();
        assert_eq!(finish.message_type, HandshakeMessageType::ClientFinish);
        assert_eq!(finish.sequence, 2);
        assert_eq!(init.state(), HandshakeState::Established);
    }

    // HS4: responder receives ClientFinish, state=Established
    #[test]
    fn hs4_full_exchange_both_established() {
        let mut init = PeerHandshake::new_initiator(ID_A, ID_B);
        let mut resp = PeerHandshake::new_responder(ID_B, ID_A);
        let m1 = init.next_message(ID_A).unwrap();
        let m2 = resp.receive(&m1, ID_B).unwrap().unwrap();
        let m3 = init.receive(&m2, ID_A).unwrap().unwrap();
        resp.receive(&m3, ID_B).unwrap();
        assert_eq!(init.state(), HandshakeState::Established);
        assert_eq!(resp.state(), HandshakeState::Established);
    }

    // HS5: derived seeds are symmetric (A.send == B.recv, B.send == A.recv)
    #[test]
    fn hs5_seeds_symmetric() {
        let mut init = PeerHandshake::new_initiator(ID_A, ID_B);
        let mut resp = PeerHandshake::new_responder(ID_B, ID_A);
        let m1 = init.next_message(ID_A).unwrap();
        let m2 = resp.receive(&m1, ID_B).unwrap().unwrap();
        let m3 = init.receive(&m2, ID_A).unwrap().unwrap();
        resp.receive(&m3, ID_B).unwrap();
        let (a_send, a_recv) = init.derive_seeds().unwrap();
        let (b_send, b_recv) = resp.derive_seeds().unwrap();
        assert_eq!(a_send, b_recv, "A.send must equal B.recv");
        assert_eq!(b_send, a_recv, "B.send must equal A.recv");
    }

    // HS6: derive_seeds fails before Established
    #[test]
    fn hs6_derive_seeds_requires_established() {
        let hs = PeerHandshake::new_initiator(ID_A, ID_B);
        assert_eq!(hs.derive_seeds().unwrap_err(), HandshakeError::InvalidState);
    }

    // HS7: out-of-order message is rejected
    #[test]
    fn hs7_out_of_order_rejected() {
        let mut init = PeerHandshake::new_initiator(ID_A, ID_B);
        let mut resp = PeerHandshake::new_responder(ID_B, ID_A);
        let m1 = init.next_message(ID_A).unwrap();
        // Inject wrong sequence
        let wrong = HandshakeMessage {
            sequence: 99,
            ..m1.clone()
        };
        assert_eq!(
            resp.receive(&wrong, ID_B).unwrap_err(),
            HandshakeError::OutOfOrder
        );
        // Original message still works
        let _ = resp.receive(&m1, ID_B).unwrap().unwrap();
    }

    // HS8: duplicate sequence rejected
    #[test]
    fn hs8_duplicate_rejected() {
        let mut init = PeerHandshake::new_initiator(ID_A, ID_B);
        let mut resp = PeerHandshake::new_responder(ID_B, ID_A);
        let m1 = init.next_message(ID_A).unwrap();
        resp.receive(&m1, ID_B).unwrap();
        // Resend the same message
        assert_eq!(
            resp.receive(&m1, ID_B).unwrap_err(),
            HandshakeError::Duplicate
        );
    }

    // HS9: reject message transitions to Failed
    #[test]
    fn hs9_reject_transitions_to_failed() {
        let mut resp = PeerHandshake::new_responder(ID_B, ID_A);
        let reject = HandshakeMessage {
            source_node: ID_A,
            target_node: ID_B,
            message_type: HandshakeMessageType::Reject,
            sequence: 0,
            payload: Vec::new(),
        };
        let err = resp.receive(&reject, ID_B).unwrap_err();
        assert_eq!(err, HandshakeError::PeerRejected);
        assert_eq!(resp.state(), HandshakeState::Failed);
    }

    // HS10: next_message fails when not in Created (responder)
    #[test]
    fn hs10_next_message_invalid_for_responder() {
        let mut resp = PeerHandshake::new_responder(ID_B, ID_A);
        assert_eq!(
            resp.next_message(ID_B).unwrap_err(),
            HandshakeError::InvalidState
        );
    }
}
