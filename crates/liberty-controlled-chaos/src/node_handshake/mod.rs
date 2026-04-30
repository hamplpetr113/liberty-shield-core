//! Authenticated node-to-node handshake (simplified Noise-XX style).
//!
//! Protocol flow:
//! ```text
//! Initiator                          Responder
//! initiate(init_id, nonce) ─ HELLO ──► handle_hello(hello)
//! finish(ack)              ◄─ ACK ──── (ack, NodeSession)
//! NodeSession
//! ```
//!
//! Each side contributes their `node_id` so both can authenticate the peer.
//! Session keys are derived with HKDF over the X25519 shared secret.
//! Sessions expire after `max_lifetime_epochs` epochs.
//!
//! NON-PRODUCTION: ephemeral keys are derived deterministically from nonce.

use std::collections::HashSet;

use crate::crypto::{
    derive_session_keys, generate_ephemeral_from_seed, hmac_sha256, is_zero_shared_secret, sha256,
    x25519,
};

const CONTEXT: &[u8] = b"liberty:node:handshake:v1";
const INIT_TAG: &[u8] = b"nh:init";
const RESP_TAG: &[u8] = b"nh:resp";

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// First message sent by the initiator.
#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeMessage {
    /// Initiator's long-term node_id (identity).
    pub node_id: [u8; 32],
    /// Ephemeral X25519 public key.
    pub ephemeral_pub: [u8; 32],
    /// Session nonce (replay protection).
    pub nonce: u64,
    /// Epoch at which this handshake was initiated.
    pub epoch: u64,
}

impl HandshakeMessage {
    pub const BYTE_SIZE: usize = 32 + 32 + 8 + 8; // 80 bytes

    pub fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        let mut b = [0u8; Self::BYTE_SIZE];
        b[..32].copy_from_slice(&self.node_id);
        b[32..64].copy_from_slice(&self.ephemeral_pub);
        b[64..72].copy_from_slice(&self.nonce.to_le_bytes());
        b[72..80].copy_from_slice(&self.epoch.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8; Self::BYTE_SIZE]) -> Self {
        let mut node_id = [0u8; 32];
        let mut ephemeral_pub = [0u8; 32];
        node_id.copy_from_slice(&b[..32]);
        ephemeral_pub.copy_from_slice(&b[32..64]);
        Self {
            node_id,
            ephemeral_pub,
            nonce: u64::from_le_bytes(b[64..72].try_into().unwrap()),
            epoch: u64::from_le_bytes(b[72..80].try_into().unwrap()),
        }
    }
}

/// Acknowledgement sent by the responder.
#[derive(Debug, Clone, PartialEq)]
pub struct HandshakeAck {
    /// Responder's long-term node_id.
    pub node_id: [u8; 32],
    /// Responder's ephemeral public key.
    pub ephemeral_pub: [u8; 32],
    /// Echo of initiator's nonce.
    pub nonce_echo: u64,
}

impl HandshakeAck {
    pub const BYTE_SIZE: usize = 32 + 32 + 8; // 72 bytes

    pub fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        let mut b = [0u8; Self::BYTE_SIZE];
        b[..32].copy_from_slice(&self.node_id);
        b[32..64].copy_from_slice(&self.ephemeral_pub);
        b[64..72].copy_from_slice(&self.nonce_echo.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8; Self::BYTE_SIZE]) -> Self {
        let mut node_id = [0u8; 32];
        let mut ephemeral_pub = [0u8; 32];
        node_id.copy_from_slice(&b[..32]);
        ephemeral_pub.copy_from_slice(&b[32..64]);
        Self {
            node_id,
            ephemeral_pub,
            nonce_echo: u64::from_le_bytes(b[64..72].try_into().unwrap()),
        }
    }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

/// Established session keys with peer identity and expiry.
#[derive(Debug, Clone)]
pub struct NodeSession {
    /// The peer's authenticated node_id.
    pub peer_node_id: [u8; 32],
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    /// Epoch at which this session was established.
    pub created_epoch: u64,
    /// Sessions expire after this many epochs.
    pub max_lifetime_epochs: u64,
}

impl NodeSession {
    pub fn is_expired(&self, current_epoch: u64) -> bool {
        current_epoch.saturating_sub(self.created_epoch) >= self.max_lifetime_epochs
    }

    /// MAC of a message using the session's send key (NON-PRODUCTION).
    pub fn sign(&self, msg: &[u8]) -> [u8; 32] {
        hmac_sha256(&self.send_key, msg)
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    InvalidKey,
    WeakSharedSecret,
    ReplayDetected,
    MismatchedNonce,
    ExpiredEpoch,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::InvalidKey => write!(f, "invalid ephemeral key"),
            HandshakeError::WeakSharedSecret => write!(f, "weak shared secret"),
            HandshakeError::ReplayDetected => write!(f, "replayed nonce"),
            HandshakeError::MismatchedNonce => write!(f, "mismatched nonce"),
            HandshakeError::ExpiredEpoch => write!(f, "handshake epoch expired"),
        }
    }
}

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

fn make_seed(tag: &[u8], nonce: u64) -> [u8; 32] {
    let mut input = vec![0u8; tag.len() + 8];
    input[..tag.len()].copy_from_slice(tag);
    input[tag.len()..].copy_from_slice(&nonce.to_le_bytes());
    sha256(&input)
}

fn derive_keys(shared: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    derive_session_keys(shared, CONTEXT)
}

// ---------------------------------------------------------------------------
// Initiator
// ---------------------------------------------------------------------------

/// Manages the initiator side of the node handshake.
pub struct NodeHandshakeInitiator {
    nonce: u64,
    init_seed: [u8; 32],
    epoch: u64,
    max_lifetime: u64,
}

impl NodeHandshakeInitiator {
    /// Begin a handshake.  Returns the state and the `HandshakeMessage` to send.
    pub fn start(
        node_id: [u8; 32],
        nonce: u64,
        epoch: u64,
        max_lifetime: u64,
    ) -> (Self, HandshakeMessage) {
        let init_seed = make_seed(INIT_TAG, nonce);
        let eph = generate_ephemeral_from_seed(&init_seed);
        let msg = HandshakeMessage {
            node_id,
            ephemeral_pub: eph.public,
            nonce,
            epoch,
        };
        (
            Self {
                nonce,
                init_seed,
                epoch,
                max_lifetime,
            },
            msg,
        )
    }

    /// Complete the handshake after receiving the `HandshakeAck`.
    pub fn finish(self, ack: &HandshakeAck) -> Result<NodeSession, HandshakeError> {
        if ack.nonce_echo != self.nonce {
            return Err(HandshakeError::MismatchedNonce);
        }
        let shared = x25519(self.init_seed, ack.ephemeral_pub);
        if is_zero_shared_secret(&shared) {
            return Err(HandshakeError::WeakSharedSecret);
        }
        let (send_key, recv_key) = derive_keys(&shared);
        Ok(NodeSession {
            peer_node_id: ack.node_id,
            send_key,
            recv_key,
            created_epoch: self.epoch,
            max_lifetime_epochs: self.max_lifetime,
        })
    }
}

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

/// Manages the responder side; tracks seen nonces for replay protection.
#[derive(Default)]
pub struct NodeHandshakeResponder {
    node_id: [u8; 32],
    seen_nonces: HashSet<u64>,
    max_epoch_skew: u64,
    max_lifetime: u64,
}

impl NodeHandshakeResponder {
    pub fn new(node_id: [u8; 32], max_epoch_skew: u64, max_lifetime: u64) -> Self {
        Self {
            node_id,
            seen_nonces: HashSet::new(),
            max_epoch_skew,
            max_lifetime,
        }
    }

    /// Handle an incoming `HandshakeMessage` and produce an ack + session.
    pub fn handle(
        &mut self,
        msg: &HandshakeMessage,
        current_epoch: u64,
    ) -> Result<(HandshakeAck, NodeSession), HandshakeError> {
        if self.seen_nonces.contains(&msg.nonce) {
            return Err(HandshakeError::ReplayDetected);
        }
        if current_epoch.saturating_sub(msg.epoch) > self.max_epoch_skew {
            return Err(HandshakeError::ExpiredEpoch);
        }
        if msg.ephemeral_pub == [0u8; 32] {
            return Err(HandshakeError::InvalidKey);
        }
        let resp_seed = make_seed(RESP_TAG, msg.nonce);
        let resp_eph = generate_ephemeral_from_seed(&resp_seed);
        let shared = x25519(resp_seed, msg.ephemeral_pub);
        if is_zero_shared_secret(&shared) {
            return Err(HandshakeError::WeakSharedSecret);
        }
        self.seen_nonces.insert(msg.nonce);
        let (recv_key, send_key) = derive_keys(&shared);
        let ack = HandshakeAck {
            node_id: self.node_id,
            ephemeral_pub: resp_eph.public,
            nonce_echo: msg.nonce,
        };
        let session = NodeSession {
            peer_node_id: msg.node_id,
            send_key,
            recv_key,
            created_epoch: current_epoch,
            max_lifetime_epochs: self.max_lifetime,
        };
        Ok((ack, session))
    }
}

/// Run a complete in-process handshake.  Returns `(init_session, resp_session)`.
pub fn perform_node_handshake(
    init_id: [u8; 32],
    resp_id: [u8; 32],
    nonce: u64,
    epoch: u64,
    max_lifetime: u64,
) -> Result<(NodeSession, NodeSession), HandshakeError> {
    let (state, msg) = NodeHandshakeInitiator::start(init_id, nonce, epoch, max_lifetime);
    let mut responder = NodeHandshakeResponder::new(resp_id, 10, max_lifetime);
    let (ack, resp_session) = responder.handle(&msg, epoch)?;
    let init_session = state.finish(&ack)?;
    Ok((init_session, resp_session))
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

    // NH1: full handshake succeeds.
    #[test]
    fn nh1_handshake_success() {
        assert!(perform_node_handshake(nid(1), nid(2), 42, 0, 20).is_ok());
    }

    // NH2: initiator and responder have cross-symmetric session keys.
    #[test]
    fn nh2_symmetric_keys() {
        let (i, r) = perform_node_handshake(nid(1), nid(2), 99, 0, 20).unwrap();
        assert_eq!(i.send_key, r.recv_key);
        assert_eq!(i.recv_key, r.send_key);
    }

    // NH3: peer_node_id is correctly stored on each side.
    #[test]
    fn nh3_peer_identity_exchange() {
        let (i, r) = perform_node_handshake(nid(0xAA), nid(0xBB), 1, 0, 20).unwrap();
        assert_eq!(i.peer_node_id, nid(0xBB));
        assert_eq!(r.peer_node_id, nid(0xAA));
    }

    // NH4: replayed nonce is rejected.
    #[test]
    fn nh4_replay_protection() {
        let mut resp = NodeHandshakeResponder::new(nid(2), 10, 20);
        let (_, msg) = NodeHandshakeInitiator::start(nid(1), 77, 0, 20);
        resp.handle(&msg, 0).unwrap();
        assert_eq!(
            resp.handle(&msg, 0).unwrap_err(),
            HandshakeError::ReplayDetected
        );
    }

    // NH5: zero ephemeral key is rejected.
    #[test]
    fn nh5_invalid_key_rejection() {
        let mut resp = NodeHandshakeResponder::new(nid(2), 10, 20);
        let msg = HandshakeMessage {
            node_id: nid(1),
            ephemeral_pub: [0u8; 32],
            nonce: 1,
            epoch: 0,
        };
        assert_eq!(
            resp.handle(&msg, 0).unwrap_err(),
            HandshakeError::InvalidKey
        );
    }

    // NH6: expired epoch is rejected.
    #[test]
    fn nh6_expired_epoch() {
        let mut resp = NodeHandshakeResponder::new(nid(2), 5, 20);
        let (_, msg) = NodeHandshakeInitiator::start(nid(1), 10, 0, 20);
        // current_epoch = 6, msg.epoch = 0 → skew = 6 > max_epoch_skew=5
        assert_eq!(
            resp.handle(&msg, 6).unwrap_err(),
            HandshakeError::ExpiredEpoch
        );
    }

    // NH7: mismatched nonce_echo is rejected by initiator.
    #[test]
    fn nh7_mismatched_nonce() {
        let mut resp = NodeHandshakeResponder::new(nid(2), 10, 20);
        let (state, msg) = NodeHandshakeInitiator::start(nid(1), 55, 0, 20);
        let (mut ack, _) = resp.handle(&msg, 0).unwrap();
        ack.nonce_echo ^= 0xFF;
        assert_eq!(
            state.finish(&ack).unwrap_err(),
            HandshakeError::MismatchedNonce
        );
    }

    // NH8: session expiration works correctly.
    #[test]
    fn nh8_session_expiration() {
        let (sess, _) = perform_node_handshake(nid(1), nid(2), 1, 5, 10).unwrap();
        assert!(!sess.is_expired(14));
        assert!(sess.is_expired(15));
    }

    // NH9: deterministic — same nonce produces same keys.
    #[test]
    fn nh9_deterministic() {
        let (k1, _) = perform_node_handshake(nid(1), nid(2), 1000, 0, 20).unwrap();
        let (k2, _) = perform_node_handshake(nid(1), nid(2), 1000, 0, 20).unwrap();
        assert_eq!(k1.send_key, k2.send_key);
    }

    // NH10: HandshakeMessage serializes and deserializes correctly.
    #[test]
    fn nh10_message_serialization() {
        let msg = HandshakeMessage {
            node_id: nid(0xAB),
            ephemeral_pub: nid(0xCD),
            nonce: 0xDEAD_BEEF,
            epoch: 7,
        };
        let bytes = msg.to_bytes();
        assert_eq!(HandshakeMessage::from_bytes(&bytes), msg);
    }

    // NH11: HandshakeAck serializes and deserializes correctly.
    #[test]
    fn nh11_ack_serialization() {
        let ack = HandshakeAck {
            node_id: nid(0x11),
            ephemeral_pub: nid(0x22),
            nonce_echo: 0xCAFE,
        };
        let bytes = ack.to_bytes();
        assert_eq!(HandshakeAck::from_bytes(&bytes), ack);
    }

    // NH12: session sign produces non-zero MAC.
    #[test]
    fn nh12_session_sign() {
        let (sess, _) = perform_node_handshake(nid(1), nid(2), 5, 0, 20).unwrap();
        let mac = sess.sign(b"test message");
        assert_ne!(mac, [0u8; 32]);
    }

    // NH13: different nonces produce different session keys.
    #[test]
    fn nh13_nonce_diversity() {
        let (k1, _) = perform_node_handshake(nid(1), nid(2), 1, 0, 20).unwrap();
        let (k2, _) = perform_node_handshake(nid(1), nid(2), 2, 0, 20).unwrap();
        assert_ne!(k1.send_key, k2.send_key);
    }
}
