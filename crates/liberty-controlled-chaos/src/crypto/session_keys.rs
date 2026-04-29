//! Per-session encryption/decryption using ChaCha20-Poly1305 AEAD.
//!
//! `SessionKeys` holds a send key, a receive key, and a monotonic send-nonce
//! counter.  The nonce is constructed per RFC 8439 §2.3: the 12-byte nonce
//! is the 4-byte fixed part (zeroed) followed by the 8-byte send counter.

use super::aead::{AeadError, aead_open, aead_seal};
use super::hkdf::derive_session_keys;

/// Maximum allowed sequence number before a session must be renegotiated.
/// (2^64-1 is the hard limit; we soft-expire at 2^48 for safety margin.)
pub const MAX_SEQUENCE: u64 = (1u64 << 48) - 1;

/// Errors from `SessionKeys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// AEAD authentication failed (tamper, wrong key, wrong nonce).
    AuthenticationFailed,
    /// Send nonce exhausted; session must be renegotiated.
    NonceExhausted,
}

impl From<AeadError> for SessionError {
    fn from(_: AeadError) -> Self {
        SessionError::AuthenticationFailed
    }
}

/// Holds symmetric send/receive keys and the monotonic send nonce.
///
/// Constructed from a shared secret via HKDF; the caller is responsible
/// for ensuring the shared secret is distinct per session.
#[derive(Debug)]
pub struct SessionKeys {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    /// Monotonically-increasing nonce for the send direction.
    send_sequence: u64,
}

impl SessionKeys {
    /// Build `SessionKeys` from raw send/receive keys.
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            send_key,
            recv_key,
            send_sequence: 0,
        }
    }

    /// Derive `SessionKeys` from a shared secret and a per-hop context label.
    ///
    /// Uses HKDF-SHA256 to produce independent send and receive keys.
    pub fn from_shared_secret(shared_secret: &[u8], context: &[u8]) -> Self {
        let (send_key, recv_key) = derive_session_keys(shared_secret, context);
        Self::new(send_key, recv_key)
    }

    /// Return the current send sequence number.
    pub fn send_sequence(&self) -> u64 {
        self.send_sequence
    }

    /// Encrypt `plaintext` with the send key.
    ///
    /// The 12-byte nonce is `[0u8; 4] ‖ send_sequence.to_le_bytes()`.
    /// `aad` is additional authenticated data (may be empty).
    ///
    /// Returns `ciphertext ‖ 16-byte tag`.
    pub fn encrypt_packet(
        &mut self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        if self.send_sequence > MAX_SEQUENCE {
            return Err(SessionError::NonceExhausted);
        }
        let nonce = build_nonce(self.send_sequence);
        let sealed = aead_seal(&self.send_key, &nonce, aad, plaintext);
        self.send_sequence = self.send_sequence.wrapping_add(1);
        Ok(sealed)
    }

    /// Decrypt a packet received from the remote side.
    ///
    /// `sequence` is the sequence number carried in the packet header; the
    /// nonce is reconstructed the same way as on the send side.
    pub fn decrypt_packet(
        &self,
        aad: &[u8],
        sequence: u64,
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        let nonce = build_nonce(sequence);
        aead_open(&self.recv_key, &nonce, aad, ciphertext_and_tag).map_err(Into::into)
    }

    /// Rotate keys (e.g., after a renegotiation) and reset the send nonce.
    pub fn rotate(&mut self, new_send: [u8; 32], new_recv: [u8; 32]) {
        self.send_key = new_send;
        self.recv_key = new_recv;
        self.send_sequence = 0;
    }

    /// Return `true` when the session is approaching nonce exhaustion and
    /// should be renegotiated soon.  Triggers at 87.5 % of `MAX_SEQUENCE`
    /// (i.e. with 12.5 % of the nonce space remaining) to leave headroom.
    pub fn requires_rotation(&self) -> bool {
        self.send_sequence >= (MAX_SEQUENCE / 8) * 7
    }

    /// Return the number of packets that can still be sent before
    /// `NonceExhausted` is returned.  Returns 0 when already exhausted.
    pub fn remaining_packets(&self) -> u64 {
        MAX_SEQUENCE.saturating_sub(self.send_sequence)
    }
}

/// Build a 12-byte nonce from a sequence number.
/// Layout: 4 bytes zero ‖ 8-byte LE sequence.
fn build_nonce(sequence: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(&sequence.to_le_bytes());
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symmetric_keys() -> SessionKeys {
        let key = [0xABu8; 32];
        // For test symmetry, both sides use the same key as send/recv
        SessionKeys::new(key, key)
    }

    // SK1: encrypt → decrypt roundtrip
    #[test]
    fn sk1_roundtrip() {
        let mut sender = symmetric_keys();
        let receiver = symmetric_keys();
        let pt = b"Liberty Shield session test";
        let ct = sender.encrypt_packet(b"aad", pt).unwrap();
        let seq = sender.send_sequence() - 1;
        let plain = receiver.decrypt_packet(b"aad", seq, &ct).unwrap();
        assert_eq!(&plain, pt);
    }

    // SK2: sequence number advances after each encrypt
    #[test]
    fn sk2_sequence_advances() {
        let mut keys = symmetric_keys();
        assert_eq!(keys.send_sequence(), 0);
        keys.encrypt_packet(b"", b"msg1").unwrap();
        assert_eq!(keys.send_sequence(), 1);
        keys.encrypt_packet(b"", b"msg2").unwrap();
        assert_eq!(keys.send_sequence(), 2);
    }

    // SK3: tampered ciphertext → AuthenticationFailed
    #[test]
    fn sk3_tamper_detected() {
        let mut sender = symmetric_keys();
        let receiver = symmetric_keys();
        let mut ct = sender.encrypt_packet(b"", b"secret").unwrap();
        ct[0] ^= 0xFF;
        assert_eq!(
            receiver.decrypt_packet(b"", 0, &ct).unwrap_err(),
            SessionError::AuthenticationFailed
        );
    }

    // SK4: wrong sequence number → authentication failure
    #[test]
    fn sk4_wrong_sequence() {
        let mut sender = symmetric_keys();
        let receiver = symmetric_keys();
        let ct = sender.encrypt_packet(b"", b"test").unwrap();
        // Use sequence=99 instead of 0
        assert_eq!(
            receiver.decrypt_packet(b"", 99, &ct).unwrap_err(),
            SessionError::AuthenticationFailed
        );
    }

    // SK5: from_shared_secret produces non-zero keys
    #[test]
    fn sk5_from_shared_secret() {
        let keys = SessionKeys::from_shared_secret(b"test_shared_secret", b"hop1");
        assert_ne!(keys.send_key, [0u8; 32]);
        assert_ne!(keys.recv_key, [0u8; 32]);
        assert_ne!(keys.send_key, keys.recv_key);
    }

    // SK6: from_shared_secret — different contexts → different keys
    #[test]
    fn sk6_context_isolation() {
        let k1 = SessionKeys::from_shared_secret(b"secret", b"hop1");
        let k2 = SessionKeys::from_shared_secret(b"secret", b"hop2");
        assert_ne!(k1.send_key, k2.send_key);
        assert_ne!(k1.recv_key, k2.recv_key);
    }

    // SK7: multiple sequential encrypts+decrypts succeed
    #[test]
    fn sk7_multi_packet() {
        let mut sender = symmetric_keys();
        let receiver = symmetric_keys();
        for i in 0u64..10 {
            let pt = format!("packet {i}");
            let ct = sender.encrypt_packet(b"hdr", pt.as_bytes()).unwrap();
            let plain = receiver.decrypt_packet(b"hdr", i, &ct).unwrap();
            assert_eq!(&plain, pt.as_bytes());
        }
    }

    // SK8: rotate replaces keys and resets sequence
    #[test]
    fn sk8_rotate_resets_sequence() {
        let mut keys = symmetric_keys();
        keys.encrypt_packet(b"", b"msg").unwrap();
        assert_eq!(keys.send_sequence(), 1);
        keys.rotate([0x11u8; 32], [0x22u8; 32]);
        assert_eq!(keys.send_sequence(), 0);
    }

    // SK9: deterministic — same key+sequence produces same ciphertext
    #[test]
    fn sk9_deterministic() {
        let mut k1 = symmetric_keys();
        let mut k2 = symmetric_keys();
        let ct1 = k1.encrypt_packet(b"", b"test").unwrap();
        let ct2 = k2.encrypt_packet(b"", b"test").unwrap();
        assert_eq!(ct1, ct2);
    }

    // SK10: build_nonce uses correct layout
    #[test]
    fn sk10_nonce_layout() {
        let n = build_nonce(0x0102030405060708);
        assert_eq!(&n[0..4], &[0u8; 4]);
        assert_eq!(&n[4..12], &0x0102030405060708u64.to_le_bytes());
    }

    // SK11: requires_rotation is false early, true near MAX_SEQUENCE
    #[test]
    fn sk11_requires_rotation_threshold() {
        let mut keys = symmetric_keys();
        assert!(!keys.requires_rotation());
        // Simulate a sequence just below the 87.5 % threshold.
        let threshold = (MAX_SEQUENCE / 8) * 7;
        keys.send_sequence = threshold - 1;
        assert!(!keys.requires_rotation());
        keys.send_sequence = threshold;
        assert!(keys.requires_rotation());
        keys.send_sequence = MAX_SEQUENCE;
        assert!(keys.requires_rotation());
    }

    // SK12: remaining_packets counts down correctly
    #[test]
    fn sk12_remaining_packets() {
        let mut keys = symmetric_keys();
        assert_eq!(keys.remaining_packets(), MAX_SEQUENCE);
        keys.send_sequence = MAX_SEQUENCE;
        assert_eq!(keys.remaining_packets(), 0);
        keys.send_sequence = MAX_SEQUENCE - 100;
        assert_eq!(keys.remaining_packets(), 100);
    }

    // SK13: remaining_packets saturates at 0 (no underflow)
    #[test]
    fn sk13_remaining_saturates_at_zero() {
        let mut keys = symmetric_keys();
        keys.send_sequence = MAX_SEQUENCE + 1; // past limit
        assert_eq!(keys.remaining_packets(), 0);
    }
}
