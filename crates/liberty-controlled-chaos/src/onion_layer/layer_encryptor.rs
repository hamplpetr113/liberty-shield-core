use crate::noise_link::EncryptedCell;

use super::types::{
    OnionError, OnionLayerKey, OnionPacket, cell_to_bytes, compute_onion_tag, xor_keystream_layer,
};

pub struct LayerEncryptor;

impl LayerEncryptor {
    /// Wrap `cell` in `keys.len()` onion layers.
    ///
    /// Layer 0 (innermost) uses `keys[0]`; layer N-1 (outermost) uses
    /// `keys[N-1]`.  The packet nonce is derived from the first 8 bytes of
    /// `keys[0].bytes`.
    ///
    /// Layers are applied innermost-first so that the outermost layer is
    /// peeled first by the first relay.
    pub fn wrap(cell: &EncryptedCell, keys: &[OnionLayerKey]) -> Result<OnionPacket, OnionError> {
        if keys.is_empty() {
            return Err(OnionError::EmptyKeySet);
        }
        if keys.len() > 255 {
            return Err(OnionError::TooManyLayers);
        }

        let layer_count = keys.len() as u8;
        let nonce = u64::from_le_bytes(keys[0].bytes[0..8].try_into().unwrap());
        let mut payload = cell_to_bytes(cell);

        // Apply innermost → outermost.
        for (i, key) in keys.iter().enumerate() {
            let layer_nonce = nonce ^ ((i as u64) + 1);
            xor_keystream_layer(&mut payload, &key.bytes, layer_nonce);
        }

        // Auth tag covers only the outermost layer.
        let outer_auth = compute_onion_tag(&keys[keys.len() - 1], nonce, layer_count, &payload);

        Ok(OnionPacket {
            layer_count,
            nonce,
            payload,
            outer_auth,
        })
    }
}
