// NON-PRODUCTION: deterministic placeholder handshake types.
// This module implements a 3-message handshake state machine for the loopback
// testnet only. Real keys are NOT negotiated; seeds are derived deterministically
// from node IDs. Replace with a full Noise XX handshake for production.

use crate::encrypted_udp_types::EncryptedUdpNodeId;

/// Opaque identity used within the handshake layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandshakeNodeId(pub u64);

impl From<EncryptedUdpNodeId> for HandshakeNodeId {
    fn from(id: EncryptedUdpNodeId) -> Self {
        HandshakeNodeId(id.0)
    }
}

impl From<HandshakeNodeId> for EncryptedUdpNodeId {
    fn from(id: HandshakeNodeId) -> Self {
        EncryptedUdpNodeId(id.0)
    }
}

/// Which side of the handshake a node plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

/// Message type carried in a `HandshakeMessage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeMessageType {
    /// Initiator → Responder: open handshake, carries initiator nonce.
    ClientHello,
    /// Responder → Initiator: acknowledge, carries responder nonce.
    ServerHello,
    /// Initiator → Responder: confirm, completes the handshake.
    ClientFinish,
    /// Either side: abort and signal failure.
    Reject,
}

/// Per-peer state of a handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Not yet started.
    Created,
    /// Initiator sent ClientHello; waiting for ServerHello.
    Message1Sent,
    /// Responder received ClientHello; about to send ServerHello.
    Message1Received,
    /// Responder sent ServerHello; waiting for ClientFinish.
    Message2Sent,
    /// Initiator received ServerHello; about to send ClientFinish.
    Message2Received,
    /// 3-message exchange complete; session seeds available.
    Established,
    /// Handshake aborted (reject received or invalid transition).
    Failed,
}

/// Errors produced by the handshake layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// Message received in the wrong order.
    OutOfOrder,
    /// Duplicate message sequence number detected.
    Duplicate,
    /// No handshake state found for the referenced peer.
    UnknownPeer,
    /// The current state does not allow this operation.
    InvalidState,
    /// Handshake already completed for this peer.
    AlreadyEstablished,
    /// Remote peer sent a Reject message.
    PeerRejected,
}

#[cfg(test)]
mod tests {
    use super::*;

    // HT1: HandshakeNodeId round-trips through EncryptedUdpNodeId
    #[test]
    fn ht1_node_id_roundtrip() {
        let enc = EncryptedUdpNodeId(42);
        let hs: HandshakeNodeId = enc.into();
        let back: EncryptedUdpNodeId = hs.into();
        assert_eq!(enc, back);
    }

    // HT2: HandshakeState default is Created
    #[test]
    fn ht2_states_are_distinct() {
        assert_ne!(HandshakeState::Created, HandshakeState::Established);
        assert_ne!(HandshakeState::Failed, HandshakeState::Established);
    }

    // HT3: HandshakeRole variants are distinct
    #[test]
    fn ht3_roles_distinct() {
        assert_ne!(HandshakeRole::Initiator, HandshakeRole::Responder);
    }
}
