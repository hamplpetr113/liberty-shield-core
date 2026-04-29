//! ChaCha20 stream cipher per RFC 8439 §2.1–2.3.
//!
//! 20 rounds, 256-bit key, 96-bit nonce, 32-bit counter.
//! Zero-dependency, no unsafe code.

/// Produce one 64-byte ChaCha20 keystream block.
///
/// `key` is 32 bytes, `nonce` is 12 bytes (96-bit), `counter` is the block counter.
fn chacha20_block(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u8; 64] {
    let mut s = [0u32; 16];
    // Constants "expand 32-byte k"
    s[0] = 0x6170_7865;
    s[1] = 0x3320_646e;
    s[2] = 0x7962_2d32;
    s[3] = 0x6b20_6574;
    // Key (little-endian u32s)
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    s[12] = counter;
    s[13] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
    s[14] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
    s[15] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());

    let initial = s;

    macro_rules! qr {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            s[$a] = s[$a].wrapping_add(s[$b]);
            s[$d] ^= s[$a];
            s[$d] = s[$d].rotate_left(16);
            s[$c] = s[$c].wrapping_add(s[$d]);
            s[$b] ^= s[$c];
            s[$b] = s[$b].rotate_left(12);
            s[$a] = s[$a].wrapping_add(s[$b]);
            s[$d] ^= s[$a];
            s[$d] = s[$d].rotate_left(8);
            s[$c] = s[$c].wrapping_add(s[$d]);
            s[$b] ^= s[$c];
            s[$b] = s[$b].rotate_left(7);
        };
    }

    // 20 rounds = 10 double-rounds
    for _ in 0..10 {
        // Column rounds
        qr!(0, 4, 8, 12);
        qr!(1, 5, 9, 13);
        qr!(2, 6, 10, 14);
        qr!(3, 7, 11, 15);
        // Diagonal rounds
        qr!(0, 5, 10, 15);
        qr!(1, 6, 11, 12);
        qr!(2, 7, 8, 13);
        qr!(3, 4, 9, 14);
    }

    // Add initial state
    for i in 0..16 {
        s[i] = s[i].wrapping_add(initial[i]);
    }

    // Serialize to bytes (little-endian)
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&s[i].to_le_bytes());
    }
    out
}

/// XOR `data` with the ChaCha20 keystream.
///
/// - `key`:     32 bytes
/// - `nonce`:   12 bytes
/// - `counter`: starting block counter (usually 1 for AEAD; 0 for key generation)
///
/// Returns a new `Vec<u8>` with the same length as `data`.
pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let blocks = data.len() / 64;
    for i in 0..blocks {
        let ks = chacha20_block(key, nonce, counter.wrapping_add(i as u32));
        for j in 0..64 {
            out.push(data[i * 64 + j] ^ ks[j]);
        }
    }
    let remaining = data.len() % 64;
    if remaining > 0 {
        let ks = chacha20_block(key, nonce, counter.wrapping_add(blocks as u32));
        let base = blocks * 64;
        for j in 0..remaining {
            out.push(data[base + j] ^ ks[j]);
        }
    }
    out
}

/// Generate 32 bytes of keystream at counter=0 (used for Poly1305 key derivation).
pub fn chacha20_key_stream_block0(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 64] {
    chacha20_block(key, nonce, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // CC1: RFC 8439 §2.1.1 test vector — block function
    #[test]
    fn cc1_block_test_vector() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let block = chacha20_block(&key, &nonce, 1);
        // First 4 bytes from RFC 8439 §2.1.1
        assert_eq!(&block[0..4], &[0x10, 0xf1, 0xe7, 0xe4]);
    }

    // CC2: encrypt then decrypt recovers plaintext
    #[test]
    fn cc2_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let plaintext = b"Hello, Liberty Shield!";
        let cipher = chacha20_xor(&key, &nonce, 1, plaintext);
        assert_ne!(cipher, plaintext.as_slice());
        let recovered = chacha20_xor(&key, &nonce, 1, &cipher);
        assert_eq!(&recovered, plaintext);
    }

    // CC3: different keys produce different ciphertext
    #[test]
    fn cc3_different_keys() {
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];
        let nonce = [0u8; 12];
        let data = [0u8; 64];
        let c1 = chacha20_xor(&key1, &nonce, 1, &data);
        let c2 = chacha20_xor(&key2, &nonce, 1, &data);
        assert_ne!(c1, c2);
    }

    // CC4: deterministic — same inputs → same output
    #[test]
    fn cc4_deterministic() {
        let key = [0xABu8; 32];
        let nonce = [0x00u8; 12];
        let data = [0xFFu8; 200];
        let c1 = chacha20_xor(&key, &nonce, 1, &data);
        let c2 = chacha20_xor(&key, &nonce, 1, &data);
        assert_eq!(c1, c2);
    }

    // CC5: output length equals input length
    #[test]
    fn cc5_output_length() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        for len in [0, 1, 63, 64, 65, 128, 200] {
            let data = vec![0u8; len];
            let out = chacha20_xor(&key, &nonce, 1, &data);
            assert_eq!(out.len(), len);
        }
    }

    // CC6: encrypt a large buffer (multiple blocks)
    #[test]
    fn cc6_multi_block() {
        let key = [0xCCu8; 32];
        let nonce = [0x01u8; 12];
        let plain = vec![0x55u8; 512];
        let enc = chacha20_xor(&key, &nonce, 1, &plain);
        let dec = chacha20_xor(&key, &nonce, 1, &enc);
        assert_eq!(dec, plain);
    }
}
