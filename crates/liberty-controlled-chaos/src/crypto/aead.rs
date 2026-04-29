//! ChaCha20-Poly1305 AEAD per RFC 8439 §2.8.
//!
//! Authenticated encryption with additional data.
//! Zero-dependency, no unsafe code.

use super::chacha20::{chacha20_key_stream_block0, chacha20_xor};
use super::poly1305::{ct_eq_16, poly1305_mac};

/// Errors produced by the AEAD layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    /// Authentication tag verification failed — ciphertext was tampered.
    AuthenticationFailed,
    /// Nonce must be exactly 12 bytes.
    InvalidNonce,
}

/// Seal plaintext with ChaCha20-Poly1305.
///
/// - `key`:    32-byte symmetric key
/// - `nonce`:  12-byte (96-bit) unique nonce per (key, message)
/// - `aad`:    additional authenticated data (not encrypted, but authenticated)
/// - `plaintext`: message to encrypt
///
/// Returns `ciphertext ‖ tag` (tag is the last 16 bytes).
pub fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    // Step 1: derive Poly1305 one-time key from block 0
    let otk_block = chacha20_key_stream_block0(key, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&otk_block[0..32]);

    // Step 2: encrypt with ChaCha20 starting at counter=1
    let ciphertext = chacha20_xor(key, nonce, 1, plaintext);

    // Step 3: compute Poly1305 over AAD ‖ pad ‖ ciphertext ‖ pad ‖ lengths
    let tag = compute_tag(&otk, aad, &ciphertext);

    let mut out = ciphertext;
    out.extend_from_slice(&tag);
    out
}

/// Open a ChaCha20-Poly1305-sealed ciphertext.
///
/// `ciphertext_and_tag` must be at least 16 bytes (the tag).
/// Returns the decrypted plaintext, or `AuthenticationFailed`.
pub fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if ciphertext_and_tag.len() < 16 {
        return Err(AeadError::AuthenticationFailed);
    }
    let split = ciphertext_and_tag.len() - 16;
    let ciphertext = &ciphertext_and_tag[..split];
    let tag: &[u8; 16] = ciphertext_and_tag[split..].try_into().unwrap();

    // Derive Poly1305 one-time key
    let otk_block = chacha20_key_stream_block0(key, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&otk_block[0..32]);

    // Verify tag before decrypting (authenticate-then-decrypt)
    let expected = compute_tag(&otk, aad, ciphertext);
    if !ct_eq_16(&expected, tag) {
        return Err(AeadError::AuthenticationFailed);
    }

    // Decrypt
    let plaintext = chacha20_xor(key, nonce, 1, ciphertext);
    Ok(plaintext)
}

/// Build the Poly1305 input per RFC 8439 §2.8:
/// AAD ‖ pad(AAD) ‖ ciphertext ‖ pad(ciphertext) ‖ len(AAD,8) ‖ len(CT,8)
fn compute_tag(otk: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    fn pad16(v: &[u8]) -> usize {
        let rem = v.len() % 16;
        if rem == 0 { 0 } else { 16 - rem }
    }

    let mut mac_input =
        Vec::with_capacity(aad.len() + pad16(aad) + ciphertext.len() + pad16(ciphertext) + 16);
    mac_input.extend_from_slice(aad);
    mac_input.extend(std::iter::repeat_n(0u8, pad16(aad)));
    mac_input.extend_from_slice(ciphertext);
    mac_input.extend(std::iter::repeat_n(0u8, pad16(ciphertext)));
    mac_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_input.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    poly1305_mac(otk, &mac_input)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [0x80u8; 32]
    }
    fn nonce() -> [u8; 12] {
        [0x01u8; 12]
    }

    // AE1: RFC 8439 §2.8.2 test vector
    #[test]
    fn ae1_rfc8439_test_vector() {
        let key: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: &[u8] = &[
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let sealed = aead_seal(&key, &nonce, aad, plaintext);
        // Verify the tag (last 16 bytes) from the RFC
        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];
        let actual_tag: [u8; 16] = sealed[sealed.len() - 16..].try_into().unwrap();
        assert_eq!(actual_tag, expected_tag, "RFC 8439 tag mismatch");

        // Verify roundtrip
        let decrypted = aead_open(&key, &nonce, aad, &sealed).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    // AE2: encrypt then decrypt (roundtrip)
    #[test]
    fn ae2_roundtrip() {
        let k = key();
        let n = nonce();
        let aad = b"header";
        let pt = b"secret message for Liberty Shield";
        let sealed = aead_seal(&k, &n, aad, pt);
        let plain = aead_open(&k, &n, aad, &sealed).unwrap();
        assert_eq!(&plain, pt);
    }

    // AE3: tampered ciphertext → authentication failure
    #[test]
    fn ae3_tamper_ciphertext() {
        let k = key();
        let n = nonce();
        let mut sealed = aead_seal(&k, &n, b"", b"test");
        sealed[0] ^= 0xFF;
        assert_eq!(
            aead_open(&k, &n, b"", &sealed).unwrap_err(),
            AeadError::AuthenticationFailed
        );
    }

    // AE4: tampered tag → authentication failure
    #[test]
    fn ae4_tamper_tag() {
        let k = key();
        let n = nonce();
        let mut sealed = aead_seal(&k, &n, b"", b"test");
        let last = sealed.len() - 1;
        sealed[last] ^= 0xFF;
        assert_eq!(
            aead_open(&k, &n, b"", &sealed).unwrap_err(),
            AeadError::AuthenticationFailed
        );
    }

    // AE5: tampered AAD → authentication failure
    #[test]
    fn ae5_tamper_aad() {
        let k = key();
        let n = nonce();
        let sealed = aead_seal(&k, &n, b"aad1", b"test");
        assert_eq!(
            aead_open(&k, &n, b"aad2", &sealed).unwrap_err(),
            AeadError::AuthenticationFailed
        );
    }

    // AE6: wrong key → authentication failure
    #[test]
    fn ae6_wrong_key() {
        let k1 = [0x11u8; 32];
        let k2 = [0x22u8; 32];
        let n = nonce();
        let sealed = aead_seal(&k1, &n, b"", b"message");
        assert_eq!(
            aead_open(&k2, &n, b"", &sealed).unwrap_err(),
            AeadError::AuthenticationFailed
        );
    }

    // AE7: empty plaintext
    #[test]
    fn ae7_empty_plaintext() {
        let k = key();
        let n = nonce();
        let sealed = aead_seal(&k, &n, b"", b"");
        assert_eq!(sealed.len(), 16); // just the tag
        let plain = aead_open(&k, &n, b"", &sealed).unwrap();
        assert!(plain.is_empty());
    }

    // AE8: deterministic sealing
    #[test]
    fn ae8_deterministic() {
        let k = key();
        let n = nonce();
        let pt = b"test";
        let s1 = aead_seal(&k, &n, b"", pt);
        let s2 = aead_seal(&k, &n, b"", pt);
        assert_eq!(s1, s2);
    }

    // AE9: sealed output length = plaintext length + 16 (tag)
    #[test]
    fn ae9_output_length() {
        let k = key();
        let n = nonce();
        let pt = b"hello world";
        let sealed = aead_seal(&k, &n, b"", pt);
        assert_eq!(sealed.len(), pt.len() + 16);
    }

    // AE10: too-short input rejected
    #[test]
    fn ae10_short_input_rejected() {
        let k = key();
        let n = nonce();
        let result = aead_open(&k, &n, b"", &[0u8; 10]);
        assert_eq!(result.unwrap_err(), AeadError::AuthenticationFailed);
    }
}
