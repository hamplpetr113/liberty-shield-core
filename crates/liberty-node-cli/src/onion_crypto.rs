//! Deterministic placeholder crypto for the onion routing layer.
//!
//! NON-PRODUCTION: XOR with keys derived from (node_id, hop_index).
//! Real crypto replaces this in a later sprint.

/// Derive a deterministic 8-byte key from a node identity and hop position.
/// Uses FNV-style mixing so the output changes meaningfully for every input pair.
pub fn derive_layer_key(node_id: u64, hop_index: usize) -> [u8; 8] {
    let mut h = 0xcbf29ce484222325u64;
    h = h.wrapping_mul(0x100000001b3).wrapping_add(node_id);
    h = h.wrapping_mul(0x100000001b3).wrapping_add(hop_index as u64);
    h = h.wrapping_mul(0x100000001b3).wrapping_add(0xdeadbeef);
    h.to_le_bytes()
}

/// Encrypt a payload slice in-place by XOR-ing each byte with the repeating key.
pub fn encrypt_layer(payload: &[u8], key: [u8; 8]) -> Vec<u8> {
    payload
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % 8])
        .collect()
}

/// Decrypt a payload slice in-place. XOR is its own inverse, so this is
/// identical to `encrypt_layer` — kept as a separate function for clarity.
pub fn decrypt_layer(payload: &[u8], key: [u8; 8]) -> Vec<u8> {
    encrypt_layer(payload, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OC1: encrypt → decrypt roundtrip restores original bytes
    #[test]
    fn oc1_encrypt_decrypt_symmetry() {
        let plaintext = b"hello onion world!";
        let key = derive_layer_key(42, 0);
        let ciphertext = encrypt_layer(plaintext, key);
        let recovered = decrypt_layer(&ciphertext, key);
        assert_eq!(recovered, plaintext);
    }

    // OC2: same inputs always produce the same key
    #[test]
    fn oc2_deterministic_key_derivation() {
        let k1 = derive_layer_key(7, 2);
        let k2 = derive_layer_key(7, 2);
        assert_eq!(k1, k2);
    }

    // OC3: different (node_id, hop_index) pairs produce different keys
    #[test]
    fn oc3_different_inputs_produce_different_keys() {
        let k1 = derive_layer_key(1, 0);
        let k2 = derive_layer_key(2, 0);
        let k3 = derive_layer_key(1, 1);
        assert_ne!(k1, k2);
        assert_ne!(k1, k3);
        assert_ne!(k2, k3);
    }

    // OC4: decrypting with wrong key does NOT restore original
    #[test]
    fn oc4_wrong_key_fails() {
        let plaintext = b"secret data";
        let correct_key = derive_layer_key(10, 0);
        let wrong_key = derive_layer_key(99, 5);
        let ciphertext = encrypt_layer(plaintext, correct_key);
        let bad_decrypt = decrypt_layer(&ciphertext, wrong_key);
        assert_ne!(bad_decrypt, plaintext.as_ref());
    }

    // OC5: encrypt changes the bytes (plaintext ≠ ciphertext for non-zero key)
    #[test]
    fn oc5_encryption_changes_bytes() {
        let plaintext = vec![0xAAu8; 16];
        let key = derive_layer_key(5, 1);
        let ciphertext = encrypt_layer(&plaintext, key);
        // At least one byte must differ unless the key is all zeros
        if key != [0u8; 8] {
            assert_ne!(ciphertext, plaintext);
        }
    }

    // OC6: empty payload is handled without panic
    #[test]
    fn oc6_empty_payload() {
        let key = derive_layer_key(0, 0);
        let enc = encrypt_layer(&[], key);
        let dec = decrypt_layer(&enc, key);
        assert!(enc.is_empty());
        assert!(dec.is_empty());
    }
}
