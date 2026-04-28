//! OnionLayer — wraps `EncryptedCell` in N concentric encryption layers.
//!
//! Sits between `MeshRouter` and `NoiseLink` in the send path:
//!   CellEncoder → NoiseLink → OnionLayer → MeshRouter → UDPTransport
//!
//! On the receive path each relay peels one layer with `LayerDecryptor::peel`.
//! The final hop extracts the inner `EncryptedCell` with `into_encrypted_cell`.
//!
//! All crypto is NON-PRODUCTION (ChaCha8-XOR + SipHash-2-4-128).

mod layer_decryptor;
mod layer_encryptor;
mod types;

pub use layer_decryptor::LayerDecryptor;
pub use layer_encryptor::LayerEncryptor;
pub use types::{OnionError, OnionLayerKey, OnionPacket, ONION_PACKET_SIZE};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::cell_encoder::CELL_SIZE;
    use crate::noise_link::EncryptedCell;

    use super::*;

    fn make_key(seed: u8) -> OnionLayerKey {
        OnionLayerKey {
            bytes: [seed; 32],
        }
    }

    fn make_cell(path_id: u64, nonce: u64) -> EncryptedCell {
        EncryptedCell {
            path_id,
            nonce,
            ciphertext: [0xab; CELL_SIZE],
            auth_tag: [0xcd; 16],
        }
    }

    // ── O1: single-layer roundtrip ────────────────────────────────────────────

    #[test]
    fn o1_single_layer_roundtrip() {
        let key = make_key(1);
        let cell = make_cell(42, 7);

        let packet = LayerEncryptor::wrap(&cell, &[key.clone()]).unwrap();
        assert_eq!(packet.layer_count, 1);

        let recovered = LayerDecryptor::unwrap(packet, &key).unwrap();
        assert_eq!(recovered.path_id, 42);
        assert_eq!(recovered.nonce, 7);
        assert_eq!(recovered.ciphertext, cell.ciphertext);
        assert_eq!(recovered.auth_tag, cell.auth_tag);
    }

    // ── O2: multi-layer 3-hop roundtrip ──────────────────────────────────────

    #[test]
    fn o2_multi_layer_three_hop_roundtrip() {
        let keys = [make_key(10), make_key(20), make_key(30)];
        let cell = make_cell(99, 1234);

        let packet = LayerEncryptor::wrap(&cell, &keys).unwrap();
        assert_eq!(packet.layer_count, 3);

        // Peel outermost (key[2]) → middle (key[1]) → innermost (key[0])
        let p2 = LayerDecryptor::peel(packet, &keys[2]).unwrap();
        assert_eq!(p2.layer_count, 2);

        let p1 = LayerDecryptor::peel(p2, &keys[1]).unwrap();
        assert_eq!(p1.layer_count, 1);

        let p0 = LayerDecryptor::peel(p1, &keys[0]).unwrap();
        assert_eq!(p0.layer_count, 0);

        let recovered = LayerDecryptor::into_encrypted_cell(p0).unwrap();
        assert_eq!(recovered.path_id, 99);
        assert_eq!(recovered.nonce, 1234);
        assert_eq!(recovered.ciphertext, cell.ciphertext);
        assert_eq!(recovered.auth_tag, cell.auth_tag);
    }

    // ── O3: invalid auth tag rejected ────────────────────────────────────────

    #[test]
    fn o3_invalid_auth_rejected() {
        let key = make_key(5);
        let mut packet = LayerEncryptor::wrap(&make_cell(1, 1), &[key.clone()]).unwrap();
        packet.outer_auth[0] ^= 0xff; // flip a byte
        assert!(matches!(
            LayerDecryptor::peel(packet, &key),
            Err(OnionError::InvalidLayer)
        ));
    }

    // ── O4: constant packet size ──────────────────────────────────────────────

    #[test]
    fn o4_constant_packet_size() {
        let key = make_key(7);
        let packet = LayerEncryptor::wrap(&make_cell(0, 0), &[key]).unwrap();
        // payload is always ENCRYPTED_CELL_SIZE bytes
        assert_eq!(packet.payload.len(), crate::noise_link::ENCRYPTED_CELL_SIZE);
        // struct field layout matches ONION_PACKET_SIZE
        assert_eq!(ONION_PACKET_SIZE, 1 + 8 + crate::noise_link::ENCRYPTED_CELL_SIZE + 16);
    }

    // ── O5: peel on zero-layer packet returns NoLayersRemaining ──────────────

    #[test]
    fn o5_peel_no_layers_remaining() {
        let key = make_key(3);
        let packet = LayerEncryptor::wrap(&make_cell(0, 0), &[key.clone()]).unwrap();
        let peeled = LayerDecryptor::peel(packet, &key).unwrap();
        assert_eq!(peeled.layer_count, 0);
        assert!(matches!(
            LayerDecryptor::peel(peeled, &key),
            Err(OnionError::NoLayersRemaining)
        ));
    }

    // ── O6: empty key set rejected ────────────────────────────────────────────

    #[test]
    fn o6_empty_key_set_rejected() {
        assert!(matches!(
            LayerEncryptor::wrap(&make_cell(0, 0), &[]),
            Err(OnionError::EmptyKeySet)
        ));
    }

    // ── O7: wrap is deterministic ─────────────────────────────────────────────

    #[test]
    fn o7_wrap_is_deterministic() {
        let key = make_key(9);
        let cell = make_cell(77, 88);
        let p1 = LayerEncryptor::wrap(&cell, &[key.clone()]).unwrap();
        let p2 = LayerEncryptor::wrap(&cell, &[key]).unwrap();
        assert_eq!(p1.layer_count, p2.layer_count);
        assert_eq!(p1.nonce, p2.nonce);
        assert_eq!(p1.payload, p2.payload);
        assert_eq!(p1.outer_auth, p2.outer_auth);
    }

    // ── O8: into_encrypted_cell with layers remaining returns error ───────────

    #[test]
    fn o8_premature_extraction_rejected() {
        let keys = [make_key(11), make_key(22)];
        let packet = LayerEncryptor::wrap(&make_cell(5, 5), &keys).unwrap();
        assert_eq!(packet.layer_count, 2);
        assert!(matches!(
            LayerDecryptor::into_encrypted_cell(packet),
            Err(OnionError::LayersRemaining(2))
        ));
    }
}
