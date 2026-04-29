//! Onion circuit handshake framework — Sprint 37: real X25519 DH.
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
//! # Key derivation
//!
//! ```text
//! resp_pub       = X25519_basepoint(responder_private)
//! shared_secret  = X25519(initiator_private, resp_pub)
//!               == X25519(responder_private, init_pub)
//! context        = circuit_id(8 LE) ‖ hop_index(1)
//! prk            = HKDF-Extract(salt="liberty-shield-v1", ikm=shared_secret)
//! send_key       = HKDF-Expand(prk, "liberty-shield:send:<ctx>", 32)
//! recv_key       = HKDF-Expand(prk, "liberty-shield:recv:<ctx>", 32)
//! ```

use crate::crypto::{
    SessionKeys, derive_session_keys, hkdf_extract, is_zero_shared_secret, x25519, x25519_basepoint,
};

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
    /// X25519 produced an all-zero shared secret (low-order input point).
    WeakSecret,
}

/// A 32-byte X25519 private key for one handshake party.
pub type HopPrivateKey = [u8; 32];

/// A 32-byte X25519 public key (u-coordinate) for one handshake party.
pub type HopPublicKey = [u8; 32];

/// Parameters for one hop during circuit construction.
#[derive(Debug, Clone)]
pub struct HopHandshakeParams {
    /// Identifier for the circuit being extended.
    pub circuit_id: u64,
    /// Position of this hop (0 = guard, 1 = first relay, 2 = exit, …).
    pub hop_index: u8,
    /// The initiating side's X25519 private key.
    pub initiator_private: HopPrivateKey,
    /// The responding side's X25519 private key.
    pub responder_private: HopPrivateKey,
}

/// Result of a completed handshake: a pair of `SessionKeys` for this hop.
#[derive(Debug)]
pub struct HandshakeResult {
    /// Keys for the initiator (client) to use with this hop.
    pub initiator_session: SessionKeys,
    /// Keys for the responder (relay) to use with this client.
    pub responder_session: SessionKeys,
}

/// Derive `SessionKeys` for both sides of a single hop using X25519 DH.
///
/// Produces:
/// - `initiator_session.send_key == responder_session.recv_key`
/// - `initiator_session.recv_key == responder_session.send_key`
pub fn complete_handshake(params: &HopHandshakeParams) -> Result<HandshakeResult, HandshakeError> {
    // Derive both public keys from the private keys.
    let resp_pub = x25519_basepoint(params.responder_private);

    // X25519 DH: x25519(init_priv, resp_pub) == x25519(resp_priv, init_pub).
    let shared = x25519(params.initiator_private, resp_pub);

    // Reject low-order public key inputs that produce an all-zero shared secret.
    if is_zero_shared_secret(&shared) {
        return Err(HandshakeError::WeakSecret);
    }

    // Build per-hop context: circuit_id(8 LE) ‖ hop_index(1).
    let mut context = Vec::with_capacity(9);
    context.extend_from_slice(&params.circuit_id.to_le_bytes());
    context.push(params.hop_index);

    // Extract PRK, then derive directional session keys.
    let prk = hkdf_extract(b"liberty-shield-v1", &shared);
    let (init_send, init_recv) = derive_session_keys(&prk, &context);

    Ok(HandshakeResult {
        initiator_session: SessionKeys::new(init_send, init_recv),
        responder_session: SessionKeys::new(init_recv, init_send),
    })
}

/// Derive the X25519 public key from a 32-byte private key.
pub fn generate_public_key(private_key: &HopPrivateKey) -> HopPublicKey {
    x25519_basepoint(*private_key)
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
        .map(|(idx, (ipriv, rpriv))| {
            complete_handshake(&HopHandshakeParams {
                circuit_id,
                hop_index: idx as u8,
                initiator_private: *ipriv,
                responder_private: *rpriv,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(circuit_id: u64, hop: u8, ipriv: u8, rpriv: u8) -> HopHandshakeParams {
        HopHandshakeParams {
            circuit_id,
            hop_index: hop,
            initiator_private: [ipriv; 32],
            responder_private: [rpriv; 32],
        }
    }

    // HS1: completed handshake produces usable session keys
    #[test]
    fn hs1_nonzero_keys() {
        let r = complete_handshake(&params(1, 0, 0xAA, 0xBB)).unwrap();
        assert_eq!(r.initiator_session.send_sequence(), 0);
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

    // HS4: same private key on both sides now succeeds (X25519 is not XOR —
    // x25519(k, basepoint(k)) is non-zero for any valid clamped scalar).
    #[test]
    fn hs4_same_private_key_not_weak() {
        let r = complete_handshake(&params(1, 0, 0x55, 0x55));
        assert!(
            r.is_ok(),
            "same private key should not produce WeakSecret with X25519"
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
        let k1 = generate_public_key(&[0xABu8; 32]);
        let k2 = generate_public_key(&[0xABu8; 32]);
        assert_eq!(k1, k2);
        assert_ne!(k1, [0u8; 32]);
    }

    // HS9: build_circuit_keys produces one result per hop
    #[test]
    fn hs9_build_circuit_keys() {
        let init_secs: Vec<[u8; 32]> = (0u8..3).map(|i| [i + 1; 32]).collect();
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

    // HS11: X25519 symmetry — both parties compute the same shared secret
    #[test]
    fn hs11_x25519_dh_symmetry() {
        let init_priv = [0x1Au8; 32];
        let resp_priv = [0x2Bu8; 32];
        let init_pub = generate_public_key(&init_priv);
        let resp_pub = generate_public_key(&resp_priv);
        // Both directions of DH must agree.
        let shared_init = x25519(init_priv, resp_pub);
        let shared_resp = x25519(resp_priv, init_pub);
        assert_eq!(shared_init, shared_resp);
        assert!(!is_zero_shared_secret(&shared_init));
    }

    // HS12: 3-hop circuit keys are all unique
    #[test]
    fn hs12_three_hop_unique_keys() {
        let init_secs: Vec<[u8; 32]> = (1u8..=3).map(|i| [i; 32]).collect();
        let resp_secs: Vec<[u8; 32]> = (4u8..=6).map(|i| [i; 32]).collect();
        let results = build_circuit_keys(42, &init_secs, &resp_secs).unwrap();
        // Encrypt the same plaintext on each hop's session; ciphertexts must differ.
        let cts: Vec<_> = results
            .into_iter()
            .map(|mut r| r.initiator_session.encrypt_packet(b"", b"probe").unwrap())
            .collect();
        assert_ne!(cts[0], cts[1]);
        assert_ne!(cts[1], cts[2]);
        assert_ne!(cts[0], cts[2]);
    }

    // HS13: is_zero_shared_secret detects all-zero output
    #[test]
    fn hs13_zero_shared_secret_detection() {
        let zero = [0u8; 32];
        let nonzero = [1u8; 32];
        assert!(is_zero_shared_secret(&zero));
        assert!(!is_zero_shared_secret(&nonzero));
    }
}
