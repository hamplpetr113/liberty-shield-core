//! Circuit establishment protocol — CREATE / CREATED.
//!
//! Two-message handshake for establishing a keyed relay circuit between an
//! initiator (A) and a responder (B):
//!
//! ```text
//!  A                              B
//!  initiate(circuit_id, nonce) ──────►  handle_create(msg)
//!  handle_created(msg)          ◄──────  (session keys, CreatedMessage)
//! ```
//!
//! Key derivation:
//!  init_seed = SHA-256("circuit:init" ‖ nonce_le8 ‖ circuit_id_le8)
//!  resp_seed = SHA-256("circuit:resp" ‖ nonce_le8 ‖ circuit_id_le8)
//!  shared    = X25519(init_seed, x25519_basepoint(resp_seed))
//!           == X25519(resp_seed, x25519_basepoint(init_seed))
//!  (k_ir, k_ri) = derive_session_keys(shared, "liberty:circuit:create:v1")
//!
//! NON-PRODUCTION: seeds are deterministic from the nonce.

use std::collections::{HashMap, HashSet};

use crate::crypto::{
    SessionKeys, X25519PublicKey, derive_session_keys, generate_ephemeral_from_seed,
    is_zero_shared_secret, sha256, x25519,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CONTEXT: &[u8] = b"liberty:circuit:create:v1";
const INIT_TAG: &[u8] = b"circuit:init";
const RESP_TAG: &[u8] = b"circuit:resp";

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// `CREATE` message sent by the initiator to establish a circuit.
#[derive(Debug, Clone, PartialEq)]
pub struct CreateMessage {
    pub circuit_id: u64,
    pub ephemeral_pub: X25519PublicKey,
    pub nonce: u64,
}

impl CreateMessage {
    /// Wire size: circuit_id(8) ‖ ephemeral_pub(32) ‖ nonce(8) = 48 bytes.
    pub const BYTE_SIZE: usize = 48;

    pub fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        let mut b = [0u8; Self::BYTE_SIZE];
        b[0..8].copy_from_slice(&self.circuit_id.to_le_bytes());
        b[8..40].copy_from_slice(&self.ephemeral_pub);
        b[40..48].copy_from_slice(&self.nonce.to_le_bytes());
        b
    }

    pub fn from_bytes(b: &[u8; Self::BYTE_SIZE]) -> Self {
        let circuit_id = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let mut ephemeral_pub = [0u8; 32];
        ephemeral_pub.copy_from_slice(&b[8..40]);
        let nonce = u64::from_le_bytes(b[40..48].try_into().unwrap());
        Self {
            circuit_id,
            ephemeral_pub,
            nonce,
        }
    }
}

/// `CREATED` message sent by the responder to complete the handshake.
#[derive(Debug, Clone, PartialEq)]
pub struct CreatedMessage {
    pub circuit_id: u64,
    pub ephemeral_pub: X25519PublicKey,
}

impl CreatedMessage {
    /// Wire size: circuit_id(8) ‖ ephemeral_pub(32) = 40 bytes.
    pub const BYTE_SIZE: usize = 40;

    pub fn to_bytes(&self) -> [u8; Self::BYTE_SIZE] {
        let mut b = [0u8; Self::BYTE_SIZE];
        b[0..8].copy_from_slice(&self.circuit_id.to_le_bytes());
        b[8..40].copy_from_slice(&self.ephemeral_pub);
        b
    }

    pub fn from_bytes(b: &[u8; Self::BYTE_SIZE]) -> Self {
        let circuit_id = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let mut ephemeral_pub = [0u8; 32];
        ephemeral_pub.copy_from_slice(&b[8..40]);
        Self {
            circuit_id,
            ephemeral_pub,
        }
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from the circuit establishment protocol.
#[derive(Debug, PartialEq)]
pub enum EstablishError {
    /// A circuit with this ID is already registered.
    DuplicateCircuit(u64),
    /// No pending initiation found for this circuit_id.
    UnknownCircuit(u64),
    /// The CREATED circuit_id does not match the pending one.
    CircuitIdMismatch,
    /// X25519 DH produced a weak (all-zero) shared secret.
    WeakSharedSecret,
}

impl std::fmt::Display for EstablishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EstablishError::DuplicateCircuit(id) => write!(f, "circuit {id} already exists"),
            EstablishError::UnknownCircuit(id) => write!(f, "no pending circuit {id}"),
            EstablishError::CircuitIdMismatch => write!(f, "circuit_id mismatch in CREATED"),
            EstablishError::WeakSharedSecret => write!(f, "X25519 produced a weak shared secret"),
        }
    }
}

// ---------------------------------------------------------------------------
// Seed helpers
// ---------------------------------------------------------------------------

fn make_init_seed(nonce: u64, circuit_id: u64) -> [u8; 32] {
    let mut input = [0u8; INIT_TAG.len() + 16];
    input[..INIT_TAG.len()].copy_from_slice(INIT_TAG);
    let off = INIT_TAG.len();
    input[off..off + 8].copy_from_slice(&nonce.to_le_bytes());
    input[off + 8..off + 16].copy_from_slice(&circuit_id.to_le_bytes());
    sha256(&input)
}

fn make_resp_seed(nonce: u64, circuit_id: u64) -> [u8; 32] {
    let mut input = [0u8; RESP_TAG.len() + 16];
    input[..RESP_TAG.len()].copy_from_slice(RESP_TAG);
    let off = RESP_TAG.len();
    input[off..off + 8].copy_from_slice(&nonce.to_le_bytes());
    input[off + 8..off + 16].copy_from_slice(&circuit_id.to_le_bytes());
    sha256(&input)
}

// ---------------------------------------------------------------------------
// Session key helper
// ---------------------------------------------------------------------------
//
// Key convention (same as Sprint 43 `perform_handshake`):
//   k_ir = initiator→responder direction
//   k_ri = responder→initiator direction
//
//   SessionKeys::new(send_key, recv_key):
//     encrypt_packet uses send_key
//     decrypt_packet uses recv_key
//
//   Initiator: register_circuit(cid, SK(k_ir, k_ri), SK(k_ri, k_ri))
//   Responder: register_circuit(cid, SK(k_ri, k_ir), SK(k_ir, k_ir))

fn derive(shared: &[u8; 32]) -> (SessionKeys, SessionKeys, SessionKeys, SessionKeys) {
    let (k_ir, k_ri) = derive_session_keys(shared, CONTEXT);
    let init_send = SessionKeys::new(k_ir, k_ri);
    let init_recv = SessionKeys::new(k_ri, k_ri);
    let resp_send = SessionKeys::new(k_ri, k_ir);
    let resp_recv = SessionKeys::new(k_ir, k_ir);
    (init_send, init_recv, resp_send, resp_recv)
}

/// Output of `CircuitEstablisher::handle_create`.
///
/// `(created_msg, initiator_keys, responder_keys)` where each key tuple is
/// `(send_session, recv_session)`.
pub type HandleCreateResult = (
    CreatedMessage,
    (SessionKeys, SessionKeys),
    (SessionKeys, SessionKeys),
);

// ---------------------------------------------------------------------------
// CircuitEstablisher
// ---------------------------------------------------------------------------

/// Manages the CREATE/CREATED state machine for one node.
///
/// A single `CircuitEstablisher` handles multiple concurrent initiations and
/// multiple incoming CREATE requests.
#[derive(Default)]
pub struct CircuitEstablisher {
    /// Initiator pending state: circuit_id → init_seed.
    pending: HashMap<u64, [u8; 32]>,
    /// Set of fully established circuit IDs.
    established: HashSet<u64>,
}

impl CircuitEstablisher {
    pub fn new() -> Self {
        Self::default()
    }

    /// **Initiator:** generate a `CreateMessage` and record pending state.
    pub fn initiate(
        &mut self,
        circuit_id: u64,
        nonce: u64,
    ) -> Result<CreateMessage, EstablishError> {
        if self.established.contains(&circuit_id) || self.pending.contains_key(&circuit_id) {
            return Err(EstablishError::DuplicateCircuit(circuit_id));
        }
        let init_seed = make_init_seed(nonce, circuit_id);
        let eph = generate_ephemeral_from_seed(&init_seed);
        self.pending.insert(circuit_id, init_seed);
        Ok(CreateMessage {
            circuit_id,
            ephemeral_pub: eph.public,
            nonce,
        })
    }

    /// **Responder:** process a `CreateMessage` and produce session keys +
    /// a `CreatedMessage` to send back.
    ///
    /// Returns `(CreatedMessage, initiator_keys, responder_keys)` where each key
    /// tuple is `(send_session, recv_session)` ready for `register_circuit`.
    pub fn handle_create(
        &mut self,
        msg: &CreateMessage,
    ) -> Result<HandleCreateResult, EstablishError> {
        if self.established.contains(&msg.circuit_id) {
            return Err(EstablishError::DuplicateCircuit(msg.circuit_id));
        }
        let resp_seed = make_resp_seed(msg.nonce, msg.circuit_id);
        let resp_eph = generate_ephemeral_from_seed(&resp_seed);
        let shared = x25519(resp_seed, msg.ephemeral_pub);
        if is_zero_shared_secret(&shared) {
            return Err(EstablishError::WeakSharedSecret);
        }
        let (init_send, init_recv, resp_send, resp_recv) = derive(&shared);
        self.established.insert(msg.circuit_id);
        let created = CreatedMessage {
            circuit_id: msg.circuit_id,
            ephemeral_pub: resp_eph.public,
        };
        Ok((created, (init_send, init_recv), (resp_send, resp_recv)))
    }

    /// **Initiator:** process a `CreatedMessage` and derive session keys.
    ///
    /// Returns `(initiator_send_session, initiator_recv_session)`.
    pub fn handle_created(
        &mut self,
        msg: &CreatedMessage,
    ) -> Result<(SessionKeys, SessionKeys), EstablishError> {
        let init_seed = self
            .pending
            .remove(&msg.circuit_id)
            .ok_or(EstablishError::UnknownCircuit(msg.circuit_id))?;
        let shared = x25519(init_seed, msg.ephemeral_pub);
        if is_zero_shared_secret(&shared) {
            return Err(EstablishError::WeakSharedSecret);
        }
        let (init_send, init_recv, _, _) = derive(&shared);
        self.established.insert(msg.circuit_id);
        Ok((init_send, init_recv))
    }

    /// Return `true` if `circuit_id` is fully established.
    pub fn is_established(&self, circuit_id: u64) -> bool {
        self.established.contains(&circuit_id)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypted_relay::{
        PipelineResult, RelayCellCommand, RelayCellPlaintext, RelayPipeline,
    };

    fn run_handshake(
        circuit_id: u64,
        nonce: u64,
    ) -> ((SessionKeys, SessionKeys), (SessionKeys, SessionKeys)) {
        let mut a = CircuitEstablisher::new();
        let mut b = CircuitEstablisher::new();
        let create = a.initiate(circuit_id, nonce).unwrap();
        let (created, init_keys, resp_keys) = b.handle_create(&create).unwrap();
        let init_keys2 = a.handle_created(&created).unwrap();
        // init_keys (from handle_create) == init_keys2 (from handle_created)
        // because both derive from the same DH output.
        let _ = init_keys;
        (init_keys2, resp_keys)
    }

    // CE1: full CREATE/CREATED handshake completes.
    #[test]
    fn ce1_full_handshake() {
        let mut a = CircuitEstablisher::new();
        let mut b = CircuitEstablisher::new();
        let create = a.initiate(1, 100).unwrap();
        let (created, _, _) = b.handle_create(&create).unwrap();
        a.handle_created(&created).unwrap();
        assert!(a.is_established(1));
        assert!(b.is_established(1));
    }

    // CE2: established circuit enables pipeline send/recv.
    #[test]
    fn ce2_pipeline_send_recv() {
        let (a_keys, b_keys) = run_handshake(10, 42);
        let (a_send, a_recv) = a_keys;
        let (b_send, b_recv) = b_keys;

        let mut pipeline_a = RelayPipeline::new();
        pipeline_a.register_circuit(10, a_send, a_recv);
        let mut pipeline_b = RelayPipeline::new();
        pipeline_b.register_circuit(10, b_send, b_recv);

        let pt = RelayCellPlaintext::new(10, 1, RelayCellCommand::Data, 0, b"hello".to_vec());
        let enc = pipeline_a.send_cell(10, 1, pt.clone()).unwrap();
        assert!(matches!(
            pipeline_b.receive_cell(10, 1, &enc),
            PipelineResult::Accepted(_)
        ));
    }

    // CE3: duplicate circuit_id is rejected.
    #[test]
    fn ce3_duplicate_circuit_rejected() {
        let mut est = CircuitEstablisher::new();
        est.initiate(5, 1).unwrap();
        assert_eq!(est.initiate(5, 2), Err(EstablishError::DuplicateCircuit(5)));
    }

    // CE4: handle_created with unknown circuit_id returns UnknownCircuit.
    #[test]
    fn ce4_unknown_circuit_id() {
        let mut a = CircuitEstablisher::new();
        let fake = CreatedMessage {
            circuit_id: 99,
            ephemeral_pub: [0x55u8; 32],
        };
        assert_eq!(
            a.handle_created(&fake).unwrap_err(),
            EstablishError::UnknownCircuit(99)
        );
    }

    // CE5: duplicate CREATE on the responder is rejected.
    #[test]
    fn ce5_duplicate_create_rejected() {
        let mut a = CircuitEstablisher::new();
        let mut b = CircuitEstablisher::new();
        let create = a.initiate(7, 10).unwrap();
        b.handle_create(&create).unwrap();
        assert_eq!(
            b.handle_create(&create).unwrap_err(),
            EstablishError::DuplicateCircuit(7)
        );
    }

    // CE6: CreateMessage binary serialization round-trip.
    #[test]
    fn ce6_create_message_roundtrip() {
        let msg = CreateMessage {
            circuit_id: 0xDEAD_BEEF_0102_0304,
            ephemeral_pub: [0xABu8; 32],
            nonce: 0xCAFE_BABE_1234_5678,
        };
        let bytes = msg.to_bytes();
        let restored = CreateMessage::from_bytes(&bytes);
        assert_eq!(msg, restored);
    }

    // CE7: CreatedMessage binary serialization round-trip.
    #[test]
    fn ce7_created_message_roundtrip() {
        let msg = CreatedMessage {
            circuit_id: 0x1122_3344_5566_7788,
            ephemeral_pub: [0xBBu8; 32],
        };
        let bytes = msg.to_bytes();
        let restored = CreatedMessage::from_bytes(&bytes);
        assert_eq!(msg, restored);
    }

    // CE8: different nonces produce different session keys.
    #[test]
    fn ce8_different_nonces_differ() {
        let (a1, _b1) = run_handshake(1, 111);
        let (a2, _b2) = run_handshake(1, 222);
        // The pipelines are built from different keys; cross-decryption must fail.
        let (a1_send, a1_recv) = a1;
        let (a2_send, a2_recv) = a2;
        let mut p1 = RelayPipeline::new();
        p1.register_circuit(1, a1_send, a1_recv);
        let mut p2 = RelayPipeline::new();
        p2.register_circuit(1, a2_send, a2_recv);
        let pt = RelayCellPlaintext::new(1, 1, RelayCellCommand::Data, 0, b"x".to_vec());
        let enc = p1.send_cell(1, 1, pt).unwrap();
        assert!(!matches!(
            p2.receive_cell(1, 1, &enc),
            PipelineResult::Accepted(_)
        ));
    }

    // CE9: initiator keys from handle_created match the responder's view.
    #[test]
    fn ce9_symmetric_key_derivation() {
        let mut a = CircuitEstablisher::new();
        let mut b = CircuitEstablisher::new();
        let create = a.initiate(20, 77).unwrap();
        let (created, init_from_b, resp_from_b) = b.handle_create(&create).unwrap();
        let init_from_a = a.handle_created(&created).unwrap();

        // Both pipelines should be able to exchange cells.
        let (a_send, a_recv) = init_from_a;
        let (b_send, b_recv) = resp_from_b;
        let (b_init_view_send, b_init_view_recv) = init_from_b;

        let mut p_a = RelayPipeline::new();
        p_a.register_circuit(20, a_send, a_recv);

        let mut p_b = RelayPipeline::new();
        p_b.register_circuit(20, b_send, b_recv);

        // A → B
        let pt = RelayCellPlaintext::new(20, 1, RelayCellCommand::Data, 0, b"from A".to_vec());
        let enc = p_a.send_cell(20, 1, pt.clone()).unwrap();
        assert!(matches!(
            p_b.receive_cell(20, 1, &enc),
            PipelineResult::Accepted(_)
        ));

        // B → A (using bidirectional keys)
        let pt2 = RelayCellPlaintext::new(20, 2, RelayCellCommand::Data, 0, b"from B".to_vec());
        let enc2 = p_b.send_cell(20, 2, pt2.clone()).unwrap();
        assert!(matches!(
            p_a.receive_cell(20, 2, &enc2),
            PipelineResult::Accepted(_)
        ));

        let _ = (b_init_view_send, b_init_view_recv);
    }

    // CE10: multiple circuits can be established concurrently.
    #[test]
    fn ce10_multiple_circuits() {
        let mut a = CircuitEstablisher::new();
        let mut b = CircuitEstablisher::new();

        let mut pipeline_a = RelayPipeline::new();
        let mut pipeline_b = RelayPipeline::new();

        for cid in [100u64, 200, 300] {
            let create = a.initiate(cid, cid).unwrap();
            let (created, _, b_keys) = b.handle_create(&create).unwrap();
            let a_keys = a.handle_created(&created).unwrap();

            let (a_send, a_recv) = a_keys;
            let (b_send, b_recv) = b_keys;
            pipeline_a.register_circuit(cid, a_send, a_recv);
            pipeline_b.register_circuit(cid, b_send, b_recv);
        }

        for cid in [100u64, 200, 300] {
            let pt = RelayCellPlaintext::new(cid, 1, RelayCellCommand::Data, 0, vec![cid as u8]);
            let enc = pipeline_a.send_cell(cid, 1, pt.clone()).unwrap();
            match pipeline_b.receive_cell(cid, 1, &enc) {
                PipelineResult::Accepted(dec) => assert_eq!(dec, pt),
                other => panic!("circuit {cid} failed: {other:?}"),
            }
        }
    }
}
