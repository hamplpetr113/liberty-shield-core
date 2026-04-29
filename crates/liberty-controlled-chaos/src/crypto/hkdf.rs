//! HKDF-SHA256 per RFC 5869.
//!
//! Key derivation: extract + expand.
//! Zero-dependency, no unsafe code.

use super::sha256::hmac_sha256;

/// HKDF-Extract: produces a pseudorandom key from input keying material.
///
/// - `salt`: optional salt; if empty, uses a 32-zero-byte default
/// - `ikm`:  input keying material
///
/// Returns a 32-byte pseudorandom key (PRK).
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    const DEFAULT_SALT: [u8; 32] = [0u8; 32];
    let s = if salt.is_empty() { &DEFAULT_SALT } else { salt };
    hmac_sha256(s, ikm)
}

/// HKDF-Expand: expands a PRK into `length` bytes of output keying material.
///
/// - `prk`:   32-byte pseudorandom key from `hkdf_extract`
/// - `info`:  context and application-specific string
/// - `length`: desired output length (must be ≤ 255 × 32 = 8160 bytes)
///
/// Panics if `length > 8160`.
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
    assert!(length <= 255 * 32, "HKDF-Expand: length exceeds maximum");

    let n = length.div_ceil(32);
    let mut okm = Vec::with_capacity(n * 32);
    let mut t = Vec::<u8>::new();

    for counter in 1u8..=(n as u8) {
        let mut input = Vec::with_capacity(t.len() + info.len() + 1);
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(counter);
        t = hmac_sha256(prk, &input).to_vec();
        okm.extend_from_slice(&t);
    }

    okm.truncate(length);
    okm
}

/// Convenience: extract-then-expand in one call.
///
/// Derives `length` bytes of output keying material from:
/// - `salt`:  optional salt
/// - `ikm`:   input keying material (e.g., a shared secret)
/// - `info`:  context label
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, length)
}

/// Derive two 32-byte keys from a shared secret (e.g., for send/recv).
pub fn derive_session_keys(shared_secret: &[u8], context: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut send_label = b"liberty-shield:send:".to_vec();
    send_label.extend_from_slice(context);
    let mut recv_label = b"liberty-shield:recv:".to_vec();
    recv_label.extend_from_slice(context);

    let salt = b"liberty-shield-v1";
    let send = hkdf(salt, shared_secret, &send_label, 32);
    let recv = hkdf(salt, shared_secret, &recv_label, 32);

    let mut k_send = [0u8; 32];
    let mut k_recv = [0u8; 32];
    k_send.copy_from_slice(&send);
    k_recv.copy_from_slice(&recv);
    (k_send, k_recv)
}

#[cfg(test)]
mod tests {
    use super::*;

    // HK1: RFC 5869 Test Case 1
    #[test]
    fn hk1_rfc5869_test_case1() {
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

        let prk = hkdf_extract(&salt, &ikm);
        // RFC 5869 TC1 PRK
        let expected_prk: [u8; 32] = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        assert_eq!(prk, expected_prk);

        let okm = hkdf_expand(&prk, &info, 42);
        let expected_okm: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        assert_eq!(&okm, &expected_okm);
    }

    // HK2: different secrets produce different keys
    #[test]
    fn hk2_different_secrets() {
        let k1 = hkdf(b"salt", b"secret1", b"info", 32);
        let k2 = hkdf(b"salt", b"secret2", b"info", 32);
        assert_ne!(k1, k2);
    }

    // HK3: different info labels produce different keys
    #[test]
    fn hk3_different_info() {
        let k1 = hkdf(b"salt", b"secret", b"context-a", 32);
        let k2 = hkdf(b"salt", b"secret", b"context-b", 32);
        assert_ne!(k1, k2);
    }

    // HK4: output length respected
    #[test]
    fn hk4_output_length() {
        for len in [1, 16, 32, 64, 100] {
            let out = hkdf(b"", b"ikm", b"info", len);
            assert_eq!(out.len(), len);
        }
    }

    // HK5: derive_session_keys produces two distinct keys
    #[test]
    fn hk5_session_keys_distinct() {
        let (k_send, k_recv) = derive_session_keys(b"shared_secret", b"hop1");
        assert_ne!(k_send, k_recv);
        assert_ne!(k_send, [0u8; 32]);
        assert_ne!(k_recv, [0u8; 32]);
    }

    // HK6: deterministic
    #[test]
    fn hk6_deterministic() {
        let k1 = hkdf(b"s", b"ikm", b"context", 32);
        let k2 = hkdf(b"s", b"ikm", b"context", 32);
        assert_eq!(k1, k2);
    }

    // HK7: empty salt falls back to zero-salt
    #[test]
    fn hk7_empty_salt() {
        let with_empty = hkdf(b"", b"ikm", b"ctx", 32);
        let with_zeros = hkdf(&[0u8; 32], b"ikm", b"ctx", 32);
        assert_eq!(with_empty, with_zeros);
    }
}
