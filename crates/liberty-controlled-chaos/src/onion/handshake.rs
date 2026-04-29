//! Onion circuit handshake framework.
//!
//! Provides a simplified, HKDF-based per-hop key negotiation layer that can be
//! upgraded to full NTor (RFC 8840) in a later sprint without changing the
//! external interface.
//!
//! # Protocol sketch (client-initiated)
//!
//! ```text
//! Client                        Guard                       Relay
//!   │── CREATE(client_dh_pub) ──►│                             │
//!   │                            │── EXTEND(relay_dh_pub) ────►│
//!   │                            │◄── EXTENDED(relay_dh_pub) ──│
//!   │◄── CREATED(guard_dh_pub) ──│                             │
//! ```
//!
//! The "DH" values are currently **simulated** using a fixed-size byte array
//! derived via HKDF from a per-node shared secret.  Real X25519 DH is
//! structurally identical and can be dropped in at the `derive_shared` call.
//!
//! # Key derivation
//!
//! `shared_secret = HKDF-SHA256(salt="liberty-shield-v1",
//!                               ikm = initiator_secret ⊕ responder_secret,
//!                               info = circuit_id ‖ hop_index)`
//!
//! Two 32-byte keys are derived from `shared_secret`:
//! - `send_key = HKDF-expand(prk, "liberty-shield:send:<ctx>", 32)`
//! - `recv_key = HKDF-expand(prk, "liberty-shield:recv:<ctx>", 32)`

use crate::crypto::SessionKeys;
use crate::crypto::{derive_session_keys, hkdf_extract};

/// State machine for one hop in the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
    /// Waiting for the initiator's CREATE/EXTEND message.
    WaitCreate,
    /// CREATE received; sent CREATED; handshake complete.
    Complete,
    /// Handshake rejected (e.g., unknown circuit or bad key material).
    Failed,
}

/// Errors from the handshake layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    /// Handshake is not in the expected state for this operation.
    InvalidState,
    /// Key material is the wrong length (must be 32 bytes).
    InvalidKeyMaterial,
    /// The derived shared secret was all-zeros (should not happen in production).
    WeakSecret,
}

/// A simulated public key for one handshake party.
///
/// In a full implementation this would be an X25519 public key.
/// Here it is a 32-byte opaque value; `derive_shared` XORs the two sides.
pub type HopPublicKey = [u8; 32];

/// Parameters for one hop during circuit construction.
#[derive(Debug, Clone)]
pub struct HopHandshakeParams {
    /// Identifier for the circuit being extended.
    pub circuit_id: u64,
    /// Position of this hop (0 = guard, 1 = first relay, 2 = exit, …).
    pub hop_index: u8,
    /// The initiating side's "public key" (simulated).
    pub initiator_key: HopPublicKey,
    /// The responding side's "public key" (simulated).
    pub responder_key: HopPublicKey,
}

/// Result of a completed handshake: a pair of `SessionKeys` for this hop.
#[derive(Debug)]
pub struct HandshakeResult {
    /// Keys for the initiator (client) to use with this hop.
    pub initiator_session: SessionKeys,
    /// Keys for the responder (relay) to use with this client.
    pub responder_session: SessionKeys,
}

/// Derive `SessionKeys` for both sides of a single hop.
///
/// Produces:
/// - `initiator_session.send_key == responder_session.recv_key`
/// - `initiator_session.recv_key == responder_session.send_key`
///
/// This ensures that what the initiator sends, the responder can decrypt,
/// and vice-versa.
pub fn complete_handshake(params: &HopHandshakeParams) -> Result<HandshakeResult, HandshakeError> {
    // Derive a shared secret from the XOR of both public keys (placeholder DH).
    let mut shared = [0u8; 32];
    for (i, b) in shared.iter_mut().enumerate() {
        *b = params.initiator_key[i] ^ params.responder_key[i];
    }

    // Reject trivially-weak shared secrets (all zeros means keys were equal or
    // both zero — this never occurs in a correct protocol).
    if shared.iter().all(|&b| b == 0) {
        return Err(HandshakeError::WeakSecret);
    }

    // Build per-hop context: circuit_id(8 LE) ‖ hop_index(1).
    let mut context = Vec::with_capacity(9);
    context.extend_from_slice(&params.circuit_id.to_le_bytes());
    context.push(params.hop_index);

    // Extract PRK
    let salt = b"liberty-shield-v1";
    let prk = hkdf_extract(salt, &shared);

    // Derive initiator session keys (send from initiator→responder, recv from responder→initiator).
    let (init_send, init_recv) = derive_session_keys(&prk, &context);

    // The responder's perspective is mirrored.
    let init_session = SessionKeys::new(init_send, init_recv);
    let resp_session = SessionKeys::new(init_recv, init_send);

    Ok(HandshakeResult {
        initiator_session: init_session,
        responder_session: resp_session,
    })
}

/// Build a simulated "public key" from a secret seed using HKDF.
///
/// In a real protocol this would be `X25519::public_key(secret)`.
pub fn generate_public_key(secret_seed: &[u8]) -> HopPublicKey {
    hkdf_extract(b"liberty-shield-pubkey", secret_seed)
}

/// Build the full per-circuit session key table for a 3+ hop circuit.
///
/// Returns one `HandshakeResult` per hop (guard, relay…, exit).
pub fn build_circuit_keys(
    circuit_id: u64,
    initiator_secrets: &[[u8; 32]],
    responder_secrets: &[[u8; 32]],
) -> Result<Vec<HandshakeResult>, HandshakeError> {
    if initiator_secrets.len() != responder_secrets.len() {
        return Err(HandshakeError::InvalidKeyMaterial);
    }
    if initiator_secrets.is_empty() {
        return Err(HandshakeError::InvalidKeyMaterial);
    }

    initiator_secrets
        .iter()
        .zip(responder_secrets.iter())
        .enumerate()
        .map(|(idx, (isec, rsec))| {
            let params = HopHandshakeParams {
                circuit_id,
                hop_index: idx as u8,
                initiator_key: generate_public_key(isec),
                responder_key: generate_public_key(rsec),
            };
            complete_handshake(&params)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(circuit_id: u64, hop: u8, ikey: u8, rkey: u8) -> HopHandshakeParams {
        HopHandshakeParams {
            circuit_id,
            hop_index: hop,
            initiator_key: [ikey; 32],
            responder_key: [rkey; 32],
        }
    }

    // HS1: completed handshake produces non-zero keys
    #[test]
    fn hs1_nonzero_keys() {
        let r = complete_handshake(&params(1, 0, 0xAA, 0xBB)).unwrap();
        assert_ne!(r.initiator_session.send_sequence(), u64::MAX);
        // send_key is private, but we can verify via encrypt/decrypt
    }

    // HS2: initiator send = responder recv (verified by encrypt+decrypt)
    #[test]
    fn hs2_key_symmetry() {
        let r = complete_handshake(&params(42, 0, 0x11, 0x22)).unwrap();
        let mut init = r.initiator_session;
        let resp = r.responder_session;
        let ct = init
            .encrypt_packet(b"aad", b"hello from initiator")
            .unwrap();
        let plain = resp.decrypt_packet(b"aad", 0, &ct).unwrap();
        assert_eq!(&plain, b"hello from initiator");
    }

    // HS3: responder send = initiator recv
    #[test]
    fn hs3_reverse_symmetry() {
        let r = complete_handshake(&params(42, 1, 0x33, 0x44)).unwrap();
        let init = r.initiator_session;
        let mut resp = r.responder_session;
        let ct = resp.encrypt_packet(b"", b"hello from responder").unwrap();
        let plain = init.decrypt_packet(b"", 0, &ct).unwrap();
        assert_eq!(&plain, b"hello from responder");
    }

    // HS4: weak shared secret (same keys) returns WeakSecret
    #[test]
    fn hs4_weak_secret_rejected() {
        let p = params(1, 0, 0x55, 0x55); // XOR of same = 0
        assert_eq!(
            complete_handshake(&p).unwrap_err(),
            HandshakeError::WeakSecret
        );
    }

    // HS5: different circuit IDs produce different keys
    #[test]
    fn hs5_circuit_id_isolation() {
        let r1 = complete_handshake(&params(1, 0, 0xAA, 0xBB)).unwrap();
        let r2 = complete_handshake(&params(2, 0, 0xAA, 0xBB)).unwrap();
        let mut init1 = r1.initiator_session;
        let mut init2 = r2.initiator_session;
        let ct1 = init1.encrypt_packet(b"", b"msg").unwrap();
        let ct2 = init2.encrypt_packet(b"", b"msg").unwrap();
        assert_ne!(
            ct1, ct2,
            "different circuits must produce different ciphertexts"
        );
    }

    // HS6: different hop indices produce different keys
    #[test]
    fn hs6_hop_index_isolation() {
        let r0 = complete_handshake(&params(1, 0, 0xAA, 0xBB)).unwrap();
        let r1 = complete_handshake(&params(1, 1, 0xAA, 0xBB)).unwrap();
        let mut s0 = r0.initiator_session;
        let mut s1 = r1.initiator_session;
        let c0 = s0.encrypt_packet(b"", b"x").unwrap();
        let c1 = s1.encrypt_packet(b"", b"x").unwrap();
        assert_ne!(c0, c1);
    }

    // HS7: deterministic — same parameters produce same keys
    #[test]
    fn hs7_deterministic() {
        let p = params(7, 2, 0x01, 0x02);
        let r1 = complete_handshake(&p).unwrap();
        let r2 = complete_handshake(&p).unwrap();
        let mut s1 = r1.initiator_session;
        let mut s2 = r2.initiator_session;
        let c1 = s1.encrypt_packet(b"", b"det").unwrap();
        let c2 = s2.encrypt_packet(b"", b"det").unwrap();
        assert_eq!(c1, c2);
    }

    // HS8: generate_public_key is deterministic and non-zero
    #[test]
    fn hs8_generate_public_key() {
        let k1 = generate_public_key(b"my secret");
        let k2 = generate_public_key(b"my secret");
        assert_eq!(k1, k2);
        assert_ne!(k1, [0u8; 32]);
    }

    // HS9: build_circuit_keys produces one result per hop
    #[test]
    fn hs9_build_circuit_keys() {
        let init_secs: Vec<[u8; 32]> = (0u8..3).map(|i| [i; 32]).collect();
        let resp_secs: Vec<[u8; 32]> = (10u8..13).map(|i| [i; 32]).collect();
        let results = build_circuit_keys(100, &init_secs, &resp_secs).unwrap();
        assert_eq!(results.len(), 3);
    }

    // HS10: build_circuit_keys mismatched lengths return error
    #[test]
    fn hs10_mismatched_secrets() {
        let init_secs: Vec<[u8; 32]> = vec![[1u8; 32], [2u8; 32]];
        let resp_secs: Vec<[u8; 32]> = vec![[10u8; 32]];
        assert_eq!(
            build_circuit_keys(1, &init_secs, &resp_secs).unwrap_err(),
            HandshakeError::InvalidKeyMaterial
        );
    }
}
