use crate::noise_link::EncryptedCell;

use super::types::{
    OnionError, OnionLayerKey, OnionPacket, bytes_to_cell, compute_onion_tag, ct_eq,
    xor_keystream_layer,
};

pub struct LayerDecryptor;

impl LayerDecryptor {
    /// Remove one onion layer using `key`.
    ///
    /// If `outer_auth` is non-zero the tag is verified before peeling; a
    /// mismatch returns `InvalidLayer`.  Inner layers carry `outer_auth = [0;16]`
    /// (NON-PRODUCTION — only the outermost tag is authenticated).
    pub fn peel(packet: OnionPacket, key: &OnionLayerKey) -> Result<OnionPacket, OnionError> {
        if packet.layer_count == 0 {
            return Err(OnionError::NoLayersRemaining);
        }

        let zeros = [0u8; 16];
        if !ct_eq(&packet.outer_auth, &zeros) {
            let expected =
                compute_onion_tag(key, packet.nonce, packet.layer_count, &packet.payload);
            if !ct_eq(&expected, &packet.outer_auth) {
                return Err(OnionError::InvalidLayer);
            }
        }

        // layer_nonce = nonce ^ layer_count  (= nonce ^ (layer_index + 1))
        let layer_nonce = packet.nonce ^ (packet.layer_count as u64);
        let mut payload = packet.payload;
        xor_keystream_layer(&mut payload, &key.bytes, layer_nonce);

        Ok(OnionPacket {
            layer_count: packet.layer_count - 1,
            nonce: packet.nonce,
            payload,
            outer_auth: [0u8; 16],
        })
    }

    /// Extract the inner `EncryptedCell` once all layers have been peeled.
    ///
    /// Returns `LayersRemaining(n)` if `layer_count > 0`.
    pub fn into_encrypted_cell(packet: OnionPacket) -> Result<EncryptedCell, OnionError> {
        if packet.layer_count != 0 {
            return Err(OnionError::LayersRemaining(packet.layer_count));
        }
        Ok(bytes_to_cell(packet.payload))
    }

    /// Peel one layer and, if `layer_count` reaches zero, extract the cell.
    ///
    /// Convenience for single-layer (1-hop) packets.
    pub fn unwrap(packet: OnionPacket, key: &OnionLayerKey) -> Result<EncryptedCell, OnionError> {
        let peeled = Self::peel(packet, key)?;
        Self::into_encrypted_cell(peeled)
    }
}
