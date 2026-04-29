//! Session rekey protocol — Sprint 38.
//!
//! Provides ephemeral forward-secret key renegotiation for an established
//! onion circuit session.  Both parties perform a one-round X25519 DH
//! exchange using freshly generated ephemeral keys; the resulting shared
//! secret is fed into HKDF to produce a new `SessionKeys` pair.
//!
//! # Protocol flow
//!
//! ```text
//! Initiator                         Responder
//!   │                                   │
//!   │── RekeyRequest { eph_pub, nonce }─►│
//!   │                                   │  check nonce not replayed
//!   │                                   │  DH(resp_eph_priv, init_eph_pub)
//!   │◄─ RekeyResponse { eph_pub, nonce }─│
//!   │                                   │
//!   │  DH(init_eph_priv, resp_eph_pub)   │
//!   │  derive new SessionKeys            │  derive new SessionKeys
//! ```
//!
//! After `finalize_rekey` succeeds both parties hold a fresh `SessionKeys`
//! whose keys are independent of the original session material.

use std::collections::HashSet;

use crate::crypto::{
    EphemeralKeypair, SessionKeys, derive_ephemeral_shared, derive_session_keys,
    generate_ephemeral_from_seed, is_zero_shared_secret,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the rekey protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RekeyError {
    /// X25519 produced an all-zero shared secret (low-order input point).
    WeakSharedSecret,
    /// The nonce in the response does not match the one in the request.
    NonceMismatch,
    /// This nonce has already been processed (replay attack).
    AlreadySeen,
}

// ---------------------------------------------------------------------------
// Wire messages
// ---------------------------------------------------------------------------

/// Sent by the initiator to start a rekey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeyRequest {
    /// Initiator's ephemeral X25519 public key.
    pub initiator_pub: [u8; 32],
    /// Random 16-byte nonce — binds the response and prevents replay.
    pub nonce: [u8; 16],
}

/// Sent by the responder in reply to a `RekeyRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeyResponse {
    /// Responder's ephemeral X25519 public key.
    pub responder_pub: [u8; 32],
    /// Echo of the request nonce — ties response to the specific request.
    pub request_nonce: [u8; 16],
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

/// Outcome of a completed rekey: the fresh `SessionKeys` for one party.
#[derive(Debug)]
pub struct RekeyResult {
    /// New session keys derived from the ephemeral DH shared secret.
    pub session: SessionKeys,
}

// ---------------------------------------------------------------------------
// Stateful initiator context
// ---------------------------------------------------------------------------

/// Initiator-side state held between sending the request and receiving the response.
pub struct RekeyInitiator {
    ephemeral: EphemeralKeypair,
    nonce: [u8; 16],
}

// ---------------------------------------------------------------------------
// Anti-replay guard
// ---------------------------------------------------------------------------

/// Tracks request nonces seen by the responder to prevent replay attacks.
#[derive(Debug, Default)]
pub struct RekeyGuard {
    seen: HashSet<[u8; 16]>,
}

impl RekeyGuard {
    /// Create a new, empty guard.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `nonce` and return `true` if it is fresh, `false` if replayed.
    pub fn check_and_record(&mut self, nonce: [u8; 16]) -> bool {
        self.seen.insert(nonce)
    }
}

// ---------------------------------------------------------------------------
// Protocol functions
// ---------------------------------------------------------------------------

/// Begin a rekey as the initiator.
///
/// `ephemeral_seed` is used as the private scalar for the ephemeral keypair;
/// in production it **must** come from a CSPRNG.  `nonce` should be 16 random
/// bytes unique to this exchange.
///
/// Returns an opaque `RekeyInitiator` (held until `finalize_rekey`) and the
/// `RekeyRequest` message to send to the peer.
pub fn initiate_rekey(
    ephemeral_seed: &[u8; 32],
    nonce: [u8; 16],
) -> (RekeyInitiator, RekeyRequest) {
    let ephemeral = generate_ephemeral_from_seed(ephemeral_seed);
    let request = RekeyRequest {
        initiator_pub: ephemeral.public,
        nonce,
    };
    let state = RekeyInitiator { ephemeral, nonce };
    (state, request)
}

/// Handle an incoming `RekeyRequest` as the responder.
///
/// `guard` prevents replay of the same request nonce.
/// `responder_seed` is used as the responder's ephemeral private scalar.
///
/// Returns `(RekeyResponse, RekeyResult)` on success; the caller must send
/// `RekeyResponse` to the initiator and then replace its session with
/// `RekeyResult::session`.
pub fn handle_rekey_request(
    guard: &mut RekeyGuard,
    request: &RekeyRequest,
    responder_seed: &[u8; 32],
) -> Result<(RekeyResponse, RekeyResult), RekeyError> {
    if !guard.check_and_record(request.nonce) {
        return Err(RekeyError::AlreadySeen);
    }

    let resp_ephemeral = generate_ephemeral_from_seed(responder_seed);

    // DH: x25519(resp_priv, init_pub)
    let shared = derive_ephemeral_shared(&resp_ephemeral, &request.initiator_pub);
    if is_zero_shared_secret(&shared) {
        return Err(RekeyError::WeakSharedSecret);
    }

    let context = build_context(&request.nonce);
    let (k_send, k_recv) = derive_session_keys(&shared, &context);

    // Responder's session: send direction is mirrored w.r.t. the initiator.
    let response = RekeyResponse {
        responder_pub: resp_ephemeral.public,
        request_nonce: request.nonce,
    };
    let result = RekeyResult {
        session: SessionKeys::new(k_recv, k_send),
    };
    Ok((response, result))
}

/// Complete the rekey as the initiator after receiving `RekeyResponse`.
///
/// Verifies the echoed nonce, performs DH, and derives the new `SessionKeys`.
/// The initiator must replace its session with `RekeyResult::session`.
pub fn finalize_rekey(
    state: &RekeyInitiator,
    response: &RekeyResponse,
) -> Result<RekeyResult, RekeyError> {
    if response.request_nonce != state.nonce {
        return Err(RekeyError::NonceMismatch);
    }

    // DH: x25519(init_priv, resp_pub) — equals responder's x25519(resp_priv, init_pub)
    let shared = derive_ephemeral_shared(&state.ephemeral, &response.responder_pub);
    if is_zero_shared_secret(&shared) {
        return Err(RekeyError::WeakSharedSecret);
    }

    let context = build_context(&state.nonce);
    let (k_send, k_recv) = derive_session_keys(&shared, &context);

    Ok(RekeyResult {
        session: SessionKeys::new(k_send, k_recv),
    })
}

/// Build a per-rekey HKDF context that binds the nonce to the derived keys.
fn build_context(nonce: &[u8; 16]) -> Vec<u8> {
    let mut ctx = b"liberty-shield:rekey:".to_vec();
    ctx.extend_from_slice(nonce);
    ctx
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // RK1: a completed rekey produces non-zero, non-trivial session keys
    #[test]
    fn rk1_rekey_produces_new_keys() {
        let nonce = [0x01u8; 16];
        let (state, request) = initiate_rekey(&[0xAAu8; 32], nonce);
        let mut guard = RekeyGuard::new();
        let (_resp, resp_result) =
            handle_rekey_request(&mut guard, &request, &[0xBBu8; 32]).unwrap();
        let init_result = finalize_rekey(&state, &_resp).unwrap();

        // Both sessions must be usable (send_sequence starts at 0).
        assert_eq!(init_result.session.send_sequence(), 0);
        assert_eq!(resp_result.session.send_sequence(), 0);
    }

    // RK2: initiator and responder derive symmetric session keys
    #[test]
    fn rk2_rekey_symmetric_agreement() {
        let nonce = [0x02u8; 16];
        let (state, request) = initiate_rekey(&[0x11u8; 32], nonce);
        let mut guard = RekeyGuard::new();
        let (response, mut resp_session) =
            handle_rekey_request(&mut guard, &request, &[0x22u8; 32]).unwrap();
        let mut init_session = finalize_rekey(&state, &response).unwrap();

        // Initiator encrypts → responder decrypts.
        let ct = init_session
            .session
            .encrypt_packet(b"rk2", b"hello from init")
            .unwrap();
        let plain = resp_session.session.decrypt_packet(b"rk2", 0, &ct).unwrap();
        assert_eq!(&plain, b"hello from init");

        // Responder encrypts → initiator decrypts.
        let ct2 = resp_session
            .session
            .encrypt_packet(b"rk2", b"hello from resp")
            .unwrap();
        let plain2 = init_session
            .session
            .decrypt_packet(b"rk2", 0, &ct2)
            .unwrap();
        assert_eq!(&plain2, b"hello from resp");
    }

    // RK3: new session keys produce different ciphertext than old ones
    #[test]
    fn rk3_rekey_changes_aead_ciphertext() {
        use crate::crypto::SessionKeys;

        let old_key = [0x55u8; 32];
        let mut old_session = SessionKeys::new(old_key, old_key);
        let old_ct = old_session.encrypt_packet(b"", b"same plaintext").unwrap();

        let nonce = [0x03u8; 16];
        let (state, request) = initiate_rekey(&[0xCCu8; 32], nonce);
        let mut guard = RekeyGuard::new();
        let (response, _) = handle_rekey_request(&mut guard, &request, &[0xDDu8; 32]).unwrap();
        let mut new_session = finalize_rekey(&state, &response).unwrap();

        let new_ct = new_session
            .session
            .encrypt_packet(b"", b"same plaintext")
            .unwrap();

        assert_ne!(
            old_ct, new_ct,
            "new session keys must produce different ciphertext"
        );
    }

    // RK4: replaying the same RekeyRequest is rejected by the guard
    #[test]
    fn rk4_replayed_rekey_rejected() {
        let nonce = [0x04u8; 16];
        let (_state, request) = initiate_rekey(&[0xEEu8; 32], nonce);
        let mut guard = RekeyGuard::new();

        // First processing succeeds.
        handle_rekey_request(&mut guard, &request, &[0xFFu8; 32]).unwrap();

        // Replaying the exact same request is rejected.
        assert_eq!(
            handle_rekey_request(&mut guard, &request, &[0xFFu8; 32]).unwrap_err(),
            RekeyError::AlreadySeen
        );
    }
}
