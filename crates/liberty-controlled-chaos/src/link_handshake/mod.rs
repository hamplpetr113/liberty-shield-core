//! Simplified Noise-style X25519 link handshake.
//!
//! Two-message flow:
//! ```text
//!  Initiator                         Responder
//!  start(nonce) ──── HELLO ────────► handle_hello(hello)
//!  finish(ack)  ◄─── HELLO_ACK ───── (ack, LinkSessionKeys)
//!  LinkSessionKeys
//! ```
//!
//! Key derivation:
//!  init_seed = SHA-256("link:init" ‖ nonce_le8)
//!  resp_seed = SHA-256("link:resp" ‖ nonce_le8)   [same nonce — NON-PRODUCTION]
//!  shared    = X25519(init_seed, resp_eph_pub)
//!           == X25519(resp_seed, init_eph_pub)
//!  (send_key, recv_key) = HKDF(shared, "liberty:link:handshake:v1")
//!
//! NON-PRODUCTION: seeds are deterministic from the nonce.

use std::collections::HashSet;

use crate::crypto::{
    derive_session_keys, generate_ephemeral_from_seed, is_zero_shared_secret, sha256, x25519,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CONTEXT: &[u8] = b"liberty:link:handshake:v1";
const INIT_TAG: &[u8] = b"link:init";
const RESP_TAG: &[u8] = b"link:resp";

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// `HELLO` sent by the initiator.
///
/// Wire size: ephemeral_pub(32) ‖ nonce(8) = 40 bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct HelloMessage {
    pub ephemeral_pub: [u8; 32],
    pub nonce: u64,
}

impl HelloMessage {
    pub const BYTE_SIZE: usize = 40;

    pub fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        let mut b = [0u8; Self::BYTE_SIZE];
        b[..32].copy_from_slice(&self.ephemeral_pub);
        b[32..40].copy_from_slice(&self.nonce.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8; Self::BYTE_SIZE]) -> Self {
        let mut ephemeral_pub = [0u8; 32];
        ephemeral_pub.copy_from_slice(&b[..32]);
        let nonce = u64::from_le_bytes(b[32..40].try_into().unwrap());
        Self {
            ephemeral_pub,
            nonce,
        }
    }
}

/// `HELLO_ACK` sent by the responder.
///
/// Wire size: ephemeral_pub(32) ‖ init_nonce(8) = 40 bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct HelloAckMessage {
    pub ephemeral_pub: [u8; 32],
    /// Echo of the initiator's nonce — the initiator verifies this.
    pub init_nonce: u64,
}

impl HelloAckMessage {
    pub const BYTE_SIZE: usize = 40;

    pub fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        let mut b = [0u8; Self::BYTE_SIZE];
        b[..32].copy_from_slice(&self.ephemeral_pub);
        b[32..40].copy_from_slice(&self.init_nonce.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8; Self::BYTE_SIZE]) -> Self {
        let mut ephemeral_pub = [0u8; 32];
        ephemeral_pub.copy_from_slice(&b[..32]);
        let init_nonce = u64::from_le_bytes(b[32..40].try_into().unwrap());
        Self {
            ephemeral_pub,
            init_nonce,
        }
    }
}

// ---------------------------------------------------------------------------
// Session keys
// ---------------------------------------------------------------------------

/// Symmetric keys derived by the link handshake.
#[derive(Debug, Clone)]
pub struct LinkSessionKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
pub enum HandshakeError {
    /// X25519 produced the all-zero weak/invalid shared secret.
    InvalidKey,
    /// X25519 produced the all-zero weak shared secret (alias for clarity).
    WeakSharedSecret,
    /// This nonce has already been processed (replay attack detected).
    ReplayDetected,
    /// The echoed nonce in `HelloAckMessage` does not match what was sent.
    MismatchedNonce,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::InvalidKey => write!(f, "invalid ephemeral key"),
            HandshakeError::WeakSharedSecret => write!(f, "X25519 produced a weak shared secret"),
            HandshakeError::ReplayDetected => write!(f, "replayed nonce detected"),
            HandshakeError::MismatchedNonce => write!(f, "echoed nonce does not match sent nonce"),
        }
    }
}

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

fn make_init_seed(nonce: u64) -> [u8; 32] {
    let mut input = [0u8; INIT_TAG.len() + 8];
    input[..INIT_TAG.len()].copy_from_slice(INIT_TAG);
    input[INIT_TAG.len()..].copy_from_slice(&nonce.to_le_bytes());
    sha256(&input)
}

fn make_resp_seed(nonce: u64) -> [u8; 32] {
    let mut input = [0u8; RESP_TAG.len() + 8];
    input[..RESP_TAG.len()].copy_from_slice(RESP_TAG);
    input[RESP_TAG.len()..].copy_from_slice(&nonce.to_le_bytes());
    sha256(&input)
}

fn derive_keys(shared: &[u8; 32]) -> (LinkSessionKeys, LinkSessionKeys) {
    let (k_ir, k_ri) = derive_session_keys(shared, CONTEXT);
    let initiator = LinkSessionKeys {
        send_key: k_ir,
        recv_key: k_ri,
    };
    let responder = LinkSessionKeys {
        send_key: k_ri,
        recv_key: k_ir,
    };
    (initiator, responder)
}

// ---------------------------------------------------------------------------
// Initiator
// ---------------------------------------------------------------------------

/// Manages the initiator side of the link handshake.
pub struct LinkHandshakeInitiator {
    nonce: u64,
    init_seed: [u8; 32],
}

impl LinkHandshakeInitiator {
    /// Start the handshake.  Returns the state and the `HelloMessage` to send.
    pub fn start(nonce: u64) -> (Self, HelloMessage) {
        let init_seed = make_init_seed(nonce);
        let eph = generate_ephemeral_from_seed(&init_seed);
        let hello = HelloMessage {
            ephemeral_pub: eph.public,
            nonce,
        };
        (Self { nonce, init_seed }, hello)
    }

    /// Finish the handshake after receiving `HelloAckMessage`.
    ///
    /// Errors:
    /// - `MismatchedNonce` if the echoed nonce doesn't match.
    /// - `WeakSharedSecret` if DH produced a zero output.
    pub fn finish(self, ack: &HelloAckMessage) -> Result<LinkSessionKeys, HandshakeError> {
        if ack.init_nonce != self.nonce {
            return Err(HandshakeError::MismatchedNonce);
        }
        let shared = x25519(self.init_seed, ack.ephemeral_pub);
        if is_zero_shared_secret(&shared) {
            return Err(HandshakeError::WeakSharedSecret);
        }
        let (initiator_keys, _) = derive_keys(&shared);
        Ok(initiator_keys)
    }
}

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

/// Manages the responder side; tracks seen nonces to detect replays.
#[derive(Default)]
pub struct LinkHandshakeResponder {
    seen_nonces: HashSet<u64>,
}

impl LinkHandshakeResponder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Handle an incoming `HelloMessage`.
    ///
    /// Errors:
    /// - `ReplayDetected` if this nonce was seen before.
    /// - `InvalidKey` if the initiator's public key is the zero point.
    /// - `WeakSharedSecret` if DH produced a zero output.
    pub fn handle_hello(
        &mut self,
        hello: &HelloMessage,
    ) -> Result<(HelloAckMessage, LinkSessionKeys), HandshakeError> {
        if self.seen_nonces.contains(&hello.nonce) {
            return Err(HandshakeError::ReplayDetected);
        }
        // All-zero ephemeral public key is the identity point — invalid.
        if hello.ephemeral_pub == [0u8; 32] {
            return Err(HandshakeError::InvalidKey);
        }
        let resp_seed = make_resp_seed(hello.nonce);
        let resp_eph = generate_ephemeral_from_seed(&resp_seed);
        let shared = x25519(resp_seed, hello.ephemeral_pub);
        if is_zero_shared_secret(&shared) {
            return Err(HandshakeError::WeakSharedSecret);
        }
        self.seen_nonces.insert(hello.nonce);
        let (_, responder_keys) = derive_keys(&shared);
        let ack = HelloAckMessage {
            ephemeral_pub: resp_eph.public,
            init_nonce: hello.nonce,
        };
        Ok((ack, responder_keys))
    }
}

// ---------------------------------------------------------------------------
// Convenience: run full handshake in-process
// ---------------------------------------------------------------------------

/// Run the complete handshake between an initiator and a responder.
///
/// Returns `(initiator_keys, responder_keys)`.  Both sides will be able
/// to communicate using their respective send/recv keys.
pub fn perform_link_handshake(
    nonce: u64,
    responder: &mut LinkHandshakeResponder,
) -> Result<(LinkSessionKeys, LinkSessionKeys), HandshakeError> {
    let (initiator_state, hello) = LinkHandshakeInitiator::start(nonce);
    let (ack, resp_keys) = responder.handle_hello(&hello)?;
    let init_keys = initiator_state.finish(&ack)?;
    Ok((init_keys, resp_keys))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // LH1: full handshake succeeds.
    #[test]
    fn lh1_handshake_success() {
        let mut resp = LinkHandshakeResponder::new();
        let result = perform_link_handshake(42, &mut resp);
        assert!(result.is_ok());
    }

    // LH2: initiator and responder agree on symmetric session keys.
    #[test]
    fn lh2_symmetric_key_agreement() {
        let mut resp = LinkHandshakeResponder::new();
        let (init_keys, resp_keys) = perform_link_handshake(99, &mut resp).unwrap();
        // Cross-direction: init's send == resp's recv; init's recv == resp's send.
        assert_eq!(init_keys.send_key, resp_keys.recv_key);
        assert_eq!(init_keys.recv_key, resp_keys.send_key);
    }

    // LH3: zero ephemeral key is rejected by responder.
    #[test]
    fn lh3_invalid_key_rejection() {
        let mut resp = LinkHandshakeResponder::new();
        let hello = HelloMessage {
            ephemeral_pub: [0u8; 32],
            nonce: 1,
        };
        assert_eq!(
            resp.handle_hello(&hello).unwrap_err(),
            HandshakeError::InvalidKey
        );
    }

    // LH4: replayed HELLO is rejected.
    #[test]
    fn lh4_replay_protection() {
        let mut resp = LinkHandshakeResponder::new();
        let (_, hello) = LinkHandshakeInitiator::start(77);
        resp.handle_hello(&hello).unwrap();
        // Second use of the same nonce is a replay.
        assert_eq!(
            resp.handle_hello(&hello).unwrap_err(),
            HandshakeError::ReplayDetected
        );
    }

    // LH5: mismatched nonce in HELLO_ACK is rejected by initiator.
    #[test]
    fn lh5_mismatched_nonce() {
        let mut resp = LinkHandshakeResponder::new();
        let (state, hello) = LinkHandshakeInitiator::start(55);
        let (mut ack, _) = resp.handle_hello(&hello).unwrap();
        ack.init_nonce ^= 0xFF; // tamper with the echoed nonce
        assert_eq!(
            state.finish(&ack).unwrap_err(),
            HandshakeError::MismatchedNonce
        );
    }

    // LH6: deterministic — same nonce always produces same keys.
    #[test]
    fn lh6_deterministic_seed_test() {
        let mut r1 = LinkHandshakeResponder::new();
        let (k1, _) = perform_link_handshake(1000, &mut r1).unwrap();
        let mut r2 = LinkHandshakeResponder::new();
        let (k2, _) = perform_link_handshake(1000, &mut r2).unwrap();
        assert_eq!(k1.send_key, k2.send_key);
        assert_eq!(k1.recv_key, k2.recv_key);
    }

    // LH7: HELLO and HELLO_ACK serialize/deserialize correctly.
    #[test]
    fn lh7_handshake_serialization() {
        let hello = HelloMessage {
            ephemeral_pub: [0xAAu8; 32],
            nonce: 0xDEAD_BEEF_0102_0304,
        };
        let bytes = hello.to_bytes();
        let restored = HelloMessage::from_bytes(&bytes);
        assert_eq!(hello, restored);

        let ack = HelloAckMessage {
            ephemeral_pub: [0xBBu8; 32],
            init_nonce: 0xCAFE_BABE,
        };
        let ack_bytes = ack.to_bytes();
        let ack_restored = HelloAckMessage::from_bytes(&ack_bytes);
        assert_eq!(ack, ack_restored);
    }

    // LH8: tampered HELLO_ACK ephemeral key produces wrong keys (not an error,
    //      but cross-decryption fails).
    #[test]
    fn lh8_handshake_corruption() {
        let mut resp = LinkHandshakeResponder::new();
        let (state, hello) = LinkHandshakeInitiator::start(333);
        let (mut ack, resp_keys) = resp.handle_hello(&hello).unwrap();
        // Corrupt the responder's ephemeral key → initiator gets wrong shared secret.
        ack.ephemeral_pub[0] ^= 0xFF;
        // finish() may succeed (different shared secret) or fail with WeakSharedSecret.
        // Either way the keys will differ from the responder's.
        match state.finish(&ack) {
            Ok(bad_keys) => {
                // Keys must differ from the legitimate responder keys.
                assert_ne!(bad_keys.send_key, resp_keys.send_key);
            }
            Err(HandshakeError::WeakSharedSecret) => {} // also acceptable
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    // LH9: different nonces produce different ephemeral keys.
    #[test]
    fn lh9_ephemeral_uniqueness() {
        let (_, h1) = LinkHandshakeInitiator::start(10);
        let (_, h2) = LinkHandshakeInitiator::start(20);
        assert_ne!(h1.ephemeral_pub, h2.ephemeral_pub);
    }

    // LH10: shared secret can be verified — initiator and responder share the same DH output.
    #[test]
    fn lh10_shared_secret_verification() {
        let mut resp = LinkHandshakeResponder::new();
        let (init_keys, resp_keys) = perform_link_handshake(7777, &mut resp).unwrap();
        // The keys are each other's mirror: what one sends the other receives.
        assert_eq!(init_keys.send_key, resp_keys.recv_key);
        assert_eq!(resp_keys.send_key, init_keys.recv_key);
        // Keys are not all-zero (weak secret would have been caught earlier).
        assert_ne!(init_keys.send_key, [0u8; 32]);
    }
}
