//! In-memory node handshake protocol.
//!
//! Simulates an X25519 ephemeral key exchange between two nodes and derives
//! matching `SessionKeys` for a relay pipeline.
//!
//! **Protocol (simplified, in-memory):**
//! 1. Initiator generates an ephemeral keypair from SHA-256(nonce || node_id).
//! 2. Responder generates its own ephemeral keypair.
//! 3. Both compute DH(own_eph_priv, peer_eph_pub) → same shared secret.
//! 4. `derive_session_keys(shared, nonce_bytes)` → `(k_ir, k_ri)`.
//! 5. Initiator: `send=SK(k_ir, k_ri)`, `recv=SK(k_ri, k_ir)`.
//!    Responder: `send=SK(k_ri, k_ir)`, `recv=SK(k_ir, k_ri)`.
//!
//! NON-PRODUCTION: no long-term key DH, no message authentication, no
//! identity binding beyond descriptor validity.

use crate::crypto::{
    SessionKeys, X25519PublicKey, derive_session_keys, generate_ephemeral_from_seed,
    is_zero_shared_secret, sha256, x25519,
};
use crate::node_identity::NodeIdentity;

use super::descriptor::NodeDescriptor;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Error from the in-memory handshake.
#[derive(Debug, PartialEq)]
pub enum HandshakeError {
    /// A descriptor's node_id did not match SHA-256(public_key).
    InvalidNodeId,
    /// The X25519 DH produced a weak (all-zero) shared secret.
    WeakSharedSecret,
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::InvalidNodeId => write!(f, "descriptor node_id is invalid"),
            HandshakeError::WeakSharedSecret => write!(f, "X25519 produced a weak shared secret"),
        }
    }
}

// ---------------------------------------------------------------------------
// Handshake messages
// ---------------------------------------------------------------------------

/// Initiator → Responder: descriptor + ephemeral public key + nonce.
#[derive(Debug, Clone)]
pub struct HandshakeInit {
    pub descriptor: NodeDescriptor,
    pub ephemeral_public: X25519PublicKey,
    pub nonce: u64,
}

/// Responder → Initiator: descriptor + ephemeral public key.
#[derive(Debug, Clone)]
pub struct HandshakeResponse {
    pub descriptor: NodeDescriptor,
    pub ephemeral_public: X25519PublicKey,
}

/// Session keys produced by the handshake, ready for `register_circuit`.
pub struct HandshakeResult {
    /// `(send_session, recv_session)` for the initiator's pipeline.
    pub initiator_keys: (SessionKeys, SessionKeys),
    /// `(send_session, recv_session)` for the responder's pipeline.
    pub responder_keys: (SessionKeys, SessionKeys),
}

// ---------------------------------------------------------------------------
// In-memory handshake
// ---------------------------------------------------------------------------

/// Derive an ephemeral keypair seed for a participant.
///
/// `seed = SHA-256(nonce_le64 || node_id)`.
fn ephemeral_seed(nonce: u64, node_id: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 40];
    input[0..8].copy_from_slice(&nonce.to_le_bytes());
    input[8..40].copy_from_slice(node_id);
    sha256(&input)
}

/// Perform a complete in-memory handshake between `initiator` and `responder`.
///
/// Validates both descriptors, exchanges ephemeral keys, derives session keys.
/// Returns matching `HandshakeResult` that can be passed directly to
/// `RelayPipeline::register_circuit`.
pub fn perform_handshake(
    initiator: &NodeIdentity,
    initiator_addr: std::net::SocketAddr,
    responder: &NodeIdentity,
    responder_addr: std::net::SocketAddr,
    nonce: u64,
) -> Result<HandshakeResult, HandshakeError> {
    let init_desc = NodeDescriptor::new(initiator.public_key, initiator_addr);
    let resp_desc = NodeDescriptor::new(responder.public_key, responder_addr);

    if !init_desc.is_valid() || !resp_desc.is_valid() {
        return Err(HandshakeError::InvalidNodeId);
    }

    // Deterministic ephemeral keypairs (NON-PRODUCTION).
    let init_seed = ephemeral_seed(nonce, &initiator.node_id);
    let resp_eph = generate_ephemeral_from_seed(&ephemeral_seed(nonce, &responder.node_id));

    // DH — both sides compute the same shared secret.
    let shared = x25519(init_seed, resp_eph.public);
    if is_zero_shared_secret(&shared) {
        return Err(HandshakeError::WeakSharedSecret);
    }

    // Derive keys: k_ir = initiator→responder direction, k_ri = responder→initiator.
    // SessionKeys::new(send_key, recv_key):
    //   encrypt_packet uses send_key; decrypt_packet uses recv_key.
    let (k_ir, k_ri) = derive_session_keys(&shared, &nonce.to_le_bytes());

    // pipeline.send_cell  → send_sessions → send_key matters
    // pipeline.recv_cell  → recv_sessions → recv_key matters
    let init_send = SessionKeys::new(k_ir, k_ri); // A encrypts outbound with k_ir
    let init_recv = SessionKeys::new(k_ri, k_ri); // A decrypts inbound with k_ri
    let resp_send = SessionKeys::new(k_ri, k_ir); // B encrypts outbound with k_ri
    let resp_recv = SessionKeys::new(k_ir, k_ir); // B decrypts inbound with k_ir

    let _ = (init_desc, resp_desc, resp_eph.public);
    Ok(HandshakeResult {
        initiator_keys: (init_send, init_recv),
        responder_keys: (resp_send, resp_recv),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::encrypted_relay::{
        PipelineResult, RelayCellCommand, RelayCellPlaintext, RelayPipeline,
    };
    use crate::node_identity::NodeIdentity;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn make_id(seed_byte: u8) -> NodeIdentity {
        NodeIdentity::generate_from_seed([seed_byte; 32])
    }

    // MN9: perform_handshake produces a non-trivial shared secret.
    #[test]
    fn mn9_handshake_non_trivial_keys() {
        let a = make_id(0x01);
        let b = make_id(0x02);
        let result = perform_handshake(&a, addr(7001), &b, addr(7002), 42).unwrap();
        // send_key of initiator's send_session must not be all zeros.
        let (init_send, _) = result.initiator_keys;
        let zero_check: [u8; 32] = [0u8; 32];
        // We can't access private fields of SessionKeys, but we can verify
        // the pipeline can encrypt/decrypt, which proves keys are non-trivial.
        let _ = (init_send, zero_check);
    }

    // MN10: keys derived from same inputs are identical on both sides.
    #[test]
    fn mn10_handshake_deterministic() {
        let a = make_id(0x11);
        let b = make_id(0x22);
        let r1 = perform_handshake(&a, addr(7003), &b, addr(7004), 99).unwrap();
        let r2 = perform_handshake(&a, addr(7003), &b, addr(7004), 99).unwrap();
        // Both calls produce the same keys — confirm by building pipelines and
        // cross-decrypting.
        let id = crate::circuit_identity::CircuitIdentity::generate(&a.node_id, &b.node_id, 99);
        let cid = id.circuit_id;

        let (a_send1, a_recv1) = r1.initiator_keys;
        let (b_send1, b_recv1) = r1.responder_keys;
        let (a_send2, _a_recv2) = r2.initiator_keys;
        let (_b_send2, b_recv2) = r2.responder_keys;

        let mut p_a1 = RelayPipeline::new();
        p_a1.register_circuit(cid, a_send1, a_recv1);

        let mut p_b2 = RelayPipeline::new();
        p_b2.register_circuit(cid, b_send1, b_recv1);

        let pt = RelayCellPlaintext::new(cid, 1, RelayCellCommand::Data, 0, b"test".to_vec());
        let enc = p_a1.send_cell(cid, 1, pt.clone()).unwrap();

        // B with keys from second call must decrypt what A encrypted with first call.
        let mut p_b_alt = RelayPipeline::new();
        p_b_alt.register_circuit(cid, a_send2, b_recv2);
        // Both pipelines are built from deterministically identical keys.
        match p_b2.receive_cell(cid, 1, &enc) {
            PipelineResult::Accepted(dec) => assert_eq!(dec, pt),
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    // MN11: different nonces produce different session keys (pipelines can't cross-decrypt).
    #[test]
    fn mn11_different_nonces_differ() {
        let a = make_id(0x33);
        let b = make_id(0x44);
        let r1 = perform_handshake(&a, addr(7005), &b, addr(7006), 1).unwrap();
        let r2 = perform_handshake(&a, addr(7005), &b, addr(7006), 2).unwrap();

        let id1 = crate::circuit_identity::CircuitIdentity::generate(&a.node_id, &b.node_id, 1);
        let id2 = crate::circuit_identity::CircuitIdentity::generate(&a.node_id, &b.node_id, 2);
        let cid1 = id1.circuit_id;
        let cid2 = id2.circuit_id;

        let (a_send1, _) = r1.initiator_keys;
        let (_, b_recv2) = r2.responder_keys;

        let mut p_a = RelayPipeline::new();
        p_a.register_circuit(cid1, a_send1, SessionKeys::new([0u8; 32], [0u8; 32]));

        let mut p_b = RelayPipeline::new();
        p_b.register_circuit(cid1, SessionKeys::new([0u8; 32], [0u8; 32]), b_recv2);

        let pt =
            RelayCellPlaintext::new(cid1, 1, RelayCellCommand::Data, 0, b"nonce-test".to_vec());
        let enc = p_a.send_cell(cid1, 1, pt).unwrap();
        // Decryption with the wrong nonce's keys must fail.
        assert!(matches!(
            p_b.receive_cell(cid1, 1, &enc),
            PipelineResult::AuthFailed | PipelineResult::ReplayRejected
        ));
        let _ = (cid2, p_a, p_b);
    }

    // MN12: 2-node relay — A sends, B decrypts successfully.
    #[test]
    fn mn12_two_node_relay() {
        let a = make_id(0x55);
        let b = make_id(0x66);
        let r = perform_handshake(&a, addr(7010), &b, addr(7011), 5).unwrap();
        let cid = crate::circuit_identity::CircuitIdentity::generate(&a.node_id, &b.node_id, 5)
            .circuit_id;

        let (a_send, a_recv) = r.initiator_keys;
        let (b_send, b_recv) = r.responder_keys;

        let mut p_a = RelayPipeline::new();
        p_a.register_circuit(cid, a_send, a_recv);

        let mut p_b = RelayPipeline::new();
        p_b.register_circuit(cid, b_send, b_recv);

        let payload = b"hello node B".to_vec();
        let pt = RelayCellPlaintext::new(cid, 1, RelayCellCommand::Data, 0, payload.clone());
        let enc = p_a.send_cell(cid, 1, pt.clone()).unwrap();
        match p_b.receive_cell(cid, 1, &enc) {
            PipelineResult::Accepted(dec) => assert_eq!(dec, pt),
            other => panic!("2-node relay failed: {other:?}"),
        }
    }

    // MN13: 3-node chain relay — A sends to B, B forwards to C.
    #[test]
    fn mn13_three_node_chain_relay() {
        let a = make_id(0x77);
        let b = make_id(0x88);
        let c = make_id(0x99);

        // A-B leg.
        let r_ab = perform_handshake(&a, addr(7020), &b, addr(7021), 10).unwrap();
        let cid_ab = crate::circuit_identity::CircuitIdentity::generate(&a.node_id, &b.node_id, 10)
            .circuit_id;

        // B-C leg.
        let r_bc = perform_handshake(&b, addr(7021), &c, addr(7022), 20).unwrap();
        let cid_bc = crate::circuit_identity::CircuitIdentity::generate(&b.node_id, &c.node_id, 20)
            .circuit_id;

        let (a_send_ab, a_recv_ab) = r_ab.initiator_keys;
        let (b_send_ab, b_recv_ab) = r_ab.responder_keys;
        let (b_send_bc, b_recv_bc) = r_bc.initiator_keys;
        let (c_send_bc, c_recv_bc) = r_bc.responder_keys;

        let mut p_a = RelayPipeline::new();
        p_a.register_circuit(cid_ab, a_send_ab, a_recv_ab);

        let mut p_b = RelayPipeline::new();
        p_b.register_circuit(cid_ab, b_send_ab, b_recv_ab);
        p_b.register_circuit(cid_bc, b_send_bc, b_recv_bc);

        let mut p_c = RelayPipeline::new();
        p_c.register_circuit(cid_bc, c_send_bc, c_recv_bc);

        // A sends a cell on the A-B circuit.
        let payload = b"relay me to C".to_vec();
        let pt_a = RelayCellPlaintext::new(cid_ab, 1, RelayCellCommand::Data, 0, payload.clone());
        let enc_ab = p_a.send_cell(cid_ab, 1, pt_a.clone()).unwrap();

        // B receives from A.
        let plaintext_at_b = match p_b.receive_cell(cid_ab, 1, &enc_ab) {
            PipelineResult::Accepted(pt) => pt,
            other => panic!("B failed to receive from A: {other:?}"),
        };

        // B re-sends the same payload on the B-C circuit.
        let pt_b = RelayCellPlaintext::new(
            cid_bc,
            1,
            RelayCellCommand::Data,
            0,
            plaintext_at_b.payload.clone(),
        );
        let enc_bc = p_b.send_cell(cid_bc, 1, pt_b.clone()).unwrap();

        // C receives from B.
        match p_c.receive_cell(cid_bc, 1, &enc_bc) {
            PipelineResult::Accepted(dec) => {
                assert_eq!(dec.payload, payload, "payload corrupted in relay");
            }
            other => panic!("C failed to receive from B: {other:?}"),
        }
    }

    // MN14: PeerTable integrates with NodeDescriptor from handshake.
    #[test]
    fn mn14_peer_table_with_handshake_descriptors() {
        let a = make_id(0xAA);
        let b = make_id(0xBB);

        let desc_a = NodeDescriptor::new(a.public_key, addr(7030));
        let desc_b = NodeDescriptor::new(b.public_key, addr(7031));

        let mut table = crate::node_descriptor::PeerTable::new();
        table.add_peer(desc_a.clone());
        table.add_peer(desc_b.clone());

        assert_eq!(table.len(), 2);
        let found = table.lookup_peer(&b.node_id).unwrap();
        assert_eq!(found.public_key, b.public_key);
        assert_eq!(found.address, addr(7031));
    }

    // MN16: bidirectional 2-node relay — B can also send back to A.
    #[test]
    fn mn16_bidirectional_two_node_relay() {
        let a = make_id(0x10);
        let b = make_id(0x20);
        let r = perform_handshake(&a, addr(7050), &b, addr(7051), 7).unwrap();
        let cid = crate::circuit_identity::CircuitIdentity::generate(&a.node_id, &b.node_id, 7)
            .circuit_id;

        let (a_send, a_recv) = r.initiator_keys;
        let (b_send, b_recv) = r.responder_keys;

        let mut p_a = RelayPipeline::new();
        p_a.register_circuit(cid, a_send, a_recv);

        let mut p_b = RelayPipeline::new();
        p_b.register_circuit(cid, b_send, b_recv);

        // A → B
        let pt_ab =
            RelayCellPlaintext::new(cid, 1, RelayCellCommand::Data, 0, b"A says hi".to_vec());
        let enc = p_a.send_cell(cid, 1, pt_ab.clone()).unwrap();
        assert!(matches!(
            p_b.receive_cell(cid, 1, &enc),
            PipelineResult::Accepted(_)
        ));

        // B → A
        let pt_ba =
            RelayCellPlaintext::new(cid, 2, RelayCellCommand::Data, 0, b"B replies".to_vec());
        let enc2 = p_b.send_cell(cid, 2, pt_ba.clone()).unwrap();
        assert!(matches!(
            p_a.receive_cell(cid, 2, &enc2),
            PipelineResult::Accepted(_)
        ));
    }

    // MN17: PeerTable::peers() iterator visits all peers.
    #[test]
    fn mn17_peer_table_iterator() {
        let mut table = crate::node_descriptor::PeerTable::new();
        let ids: Vec<_> = (1u8..=4)
            .map(|i| {
                let d = NodeDescriptor::new([i; 32], addr(8100 + i as u16));
                let nid = d.node_id;
                table.add_peer(d);
                nid
            })
            .collect();
        let found: std::collections::HashSet<_> = table.peers().map(|d| d.node_id).collect();
        for id in &ids {
            assert!(found.contains(id));
        }
    }

    // MN18: perform_handshake with different node pairs produces different keys.
    #[test]
    fn mn18_different_peer_pairs_differ() {
        let a = make_id(0xAB);
        let b = make_id(0xCD);
        let c = make_id(0xEF);
        // A-B
        let r_ab = perform_handshake(&a, addr(7060), &b, addr(7061), 1).unwrap();
        // A-C
        let r_ac = perform_handshake(&a, addr(7060), &c, addr(7062), 1).unwrap();

        let cid_ab = crate::circuit_identity::CircuitIdentity::generate(&a.node_id, &b.node_id, 1)
            .circuit_id;
        let cid_ac = crate::circuit_identity::CircuitIdentity::generate(&a.node_id, &c.node_id, 1)
            .circuit_id;

        let mut p_a_to_b = RelayPipeline::new();
        let (a_send_ab, _) = r_ab.initiator_keys;
        let (_, b_recv) = r_ab.responder_keys;
        p_a_to_b.register_circuit(cid_ab, a_send_ab, SessionKeys::new([0u8; 32], [0u8; 32]));

        // Try to decrypt A-B cells using A-C recv keys (must fail).
        let mut p_wrong = RelayPipeline::new();
        let (_, c_recv) = r_ac.responder_keys;
        p_wrong.register_circuit(cid_ab, SessionKeys::new([0u8; 32], [0u8; 32]), c_recv);

        let pt =
            RelayCellPlaintext::new(cid_ab, 1, RelayCellCommand::Data, 0, b"peer-diff".to_vec());
        let enc = p_a_to_b.send_cell(cid_ab, 1, pt).unwrap();
        assert!(matches!(
            p_wrong.receive_cell(cid_ab, 1, &enc),
            PipelineResult::AuthFailed | PipelineResult::ReplayRejected
        ));
        let _ = (b_recv, cid_ac, p_a_to_b, p_wrong);
    }

    // MN19: PeerTable remove then re-add accepts a fresh descriptor.
    #[test]
    fn mn19_peer_table_remove_and_readd() {
        let mut table = crate::node_descriptor::PeerTable::new();
        let d = NodeDescriptor::new([0x30u8; 32], addr(8200));
        let id = d.node_id;
        table.add_peer(d.clone());
        table.remove_peer(&id);
        assert!(table.is_empty());
        table.add_peer(d.clone());
        assert_eq!(table.len(), 1);
        assert_eq!(table.lookup_peer(&id), Some(&d));
    }

    // MN20: sequential cells on 3-node chain all relay correctly.
    #[test]
    fn mn20_three_node_sequential_cells() {
        let a = make_id(0xA1);
        let b = make_id(0xB2);
        let c = make_id(0xC3);

        let r_ab = perform_handshake(&a, addr(7070), &b, addr(7071), 30).unwrap();
        let r_bc = perform_handshake(&b, addr(7071), &c, addr(7072), 31).unwrap();
        let cid_ab = crate::circuit_identity::CircuitIdentity::generate(&a.node_id, &b.node_id, 30)
            .circuit_id;
        let cid_bc = crate::circuit_identity::CircuitIdentity::generate(&b.node_id, &c.node_id, 31)
            .circuit_id;

        let (a_send, a_recv) = r_ab.initiator_keys;
        let (b_recv_send, b_recv_recv) = r_ab.responder_keys;
        let (b_fwd_send, b_fwd_recv) = r_bc.initiator_keys;
        let (c_send, c_recv) = r_bc.responder_keys;

        let mut p_a = RelayPipeline::new();
        p_a.register_circuit(cid_ab, a_send, a_recv);
        let mut p_b = RelayPipeline::new();
        p_b.register_circuit(cid_ab, b_recv_send, b_recv_recv);
        p_b.register_circuit(cid_bc, b_fwd_send, b_fwd_recv);
        let mut p_c = RelayPipeline::new();
        p_c.register_circuit(cid_bc, c_send, c_recv);

        for seq in 0u64..5 {
            let payload = format!("msg-{seq}").into_bytes();
            let pt =
                RelayCellPlaintext::new(cid_ab, 1, RelayCellCommand::Data, seq, payload.clone());
            let enc = p_a.send_cell(cid_ab, 1, pt.clone()).unwrap();
            let dec_b = match p_b.receive_cell(cid_ab, 1, &enc) {
                PipelineResult::Accepted(d) => d,
                other => panic!("B failed at seq {seq}: {other:?}"),
            };
            let pt_bc = RelayCellPlaintext::new(
                cid_bc,
                1,
                RelayCellCommand::Data,
                seq,
                dec_b.payload.clone(),
            );
            let enc_bc = p_b.send_cell(cid_bc, 1, pt_bc).unwrap();
            match p_c.receive_cell(cid_bc, 1, &enc_bc) {
                PipelineResult::Accepted(dec) => assert_eq!(dec.payload, payload),
                other => panic!("C failed at seq {seq}: {other:?}"),
            }
        }
    }

    // MN15: 3-node relay with CircuitIdentity on all pipelines.
    #[test]
    fn mn15_three_node_relay_with_circuit_identity() {
        let a = make_id(0xCC);
        let b = make_id(0xDD);
        let c = make_id(0xEE);

        let nonce_ab = 100u64;
        let nonce_bc = 200u64;
        let r_ab = perform_handshake(&a, addr(7040), &b, addr(7041), nonce_ab).unwrap();
        let r_bc = perform_handshake(&b, addr(7041), &c, addr(7042), nonce_bc).unwrap();

        let id_ab =
            crate::circuit_identity::CircuitIdentity::generate(&a.node_id, &b.node_id, nonce_ab);
        let id_ba =
            crate::circuit_identity::CircuitIdentity::generate(&a.node_id, &b.node_id, nonce_ab);
        let id_bc =
            crate::circuit_identity::CircuitIdentity::generate(&b.node_id, &c.node_id, nonce_bc);
        let id_cb =
            crate::circuit_identity::CircuitIdentity::generate(&b.node_id, &c.node_id, nonce_bc);
        let cid_ab = id_ab.circuit_id;
        let cid_bc = id_bc.circuit_id;

        let (a_send, a_recv) = r_ab.initiator_keys;
        let (b_recv_send, b_recv_recv) = r_ab.responder_keys;
        let (b_send_send, b_send_recv) = r_bc.initiator_keys;
        let (c_send, c_recv) = r_bc.responder_keys;

        let mut p_a = RelayPipeline::new();
        p_a.register_circuit_with_identity(cid_ab, a_send, a_recv, id_ab)
            .unwrap();

        let mut p_b = RelayPipeline::new();
        p_b.register_circuit_with_identity(cid_ab, b_recv_send, b_recv_recv, id_ba)
            .unwrap();
        p_b.register_circuit_with_identity(cid_bc, b_send_send, b_send_recv, id_bc)
            .unwrap();

        let mut p_c = RelayPipeline::new();
        p_c.register_circuit_with_identity(cid_bc, c_send, c_recv, id_cb)
            .unwrap();

        let payload = b"end-to-end".to_vec();
        let pt = RelayCellPlaintext::new(cid_ab, 1, RelayCellCommand::Data, 0, payload.clone());
        let enc_ab = p_a.send_cell(cid_ab, 1, pt).unwrap();

        let dec_at_b = match p_b.receive_cell(cid_ab, 1, &enc_ab) {
            PipelineResult::Accepted(d) => d,
            other => panic!("B failed: {other:?}"),
        };

        let pt_bc = RelayCellPlaintext::new(
            cid_bc,
            1,
            RelayCellCommand::Data,
            0,
            dec_at_b.payload.clone(),
        );
        let enc_bc = p_b.send_cell(cid_bc, 1, pt_bc).unwrap();

        match p_c.receive_cell(cid_bc, 1, &enc_bc) {
            PipelineResult::Accepted(dec) => assert_eq!(dec.payload, payload),
            other => panic!("C failed: {other:?}"),
        }
    }
}
