//! Per-session encryption/decryption using ChaCha20-Poly1305 AEAD.
//!
//! `SessionKeys` holds a send key, a receive key, and a monotonic send-nonce
//! counter.  The nonce is constructed per RFC 8439 §2.3: the 12-byte nonce
//! is the 4-byte fixed part (zeroed) followed by the 8-byte send counter.

use super::aead::{AeadError, aead_open, aead_seal};
use super::bitmap_window::BitmapReplayWindow;
use super::hkdf::derive_session_keys;

/// Maximum allowed sequence number before a session must be renegotiated.
/// (2^64-1 is the hard limit; we soft-expire at 2^48 for safety margin.)
pub const MAX_SEQUENCE: u64 = (1u64 << 48) - 1;

/// Lifecycle state of a `SessionKeys` instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Normal operation — packets can be sent and received.
    Active,
    /// A rekey exchange is in progress; the session is still usable but
    /// should not accept further long-term traffic until `complete_rekey` is
    /// called.
    Rekeying,
    /// The session has been explicitly expired and must not be used.
    Expired,
}

/// Errors from `SessionKeys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// AEAD authentication failed (tamper, wrong key, wrong nonce).
    AuthenticationFailed,
    /// Send nonce exhausted; session must be renegotiated.
    NonceExhausted,
    /// Sequence number already seen or outside the replay window — only from
    /// `decrypt_packet_in_order` and `decrypt_packet_with_window`; the basic
    /// `decrypt_packet` does not track order.
    ReplayDetected,
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
    /// Highest sequence number accepted by `decrypt_packet_in_order`.
    /// `None` means no packet has been received yet on this session.
    last_recv_sequence: Option<u64>,
    /// Bitmap sliding window for `decrypt_packet_with_window`.
    replay_window: BitmapReplayWindow,
    /// Current lifecycle state of this session.
    state: SessionState,
}

impl SessionKeys {
    /// Build `SessionKeys` from raw send/receive keys.
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            send_key,
            recv_key,
            send_sequence: 0,
            last_recv_sequence: None,
            replay_window: BitmapReplayWindow::new(),
            state: SessionState::Active,
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

    /// Return the current session lifecycle state.
    pub fn state(&self) -> SessionState {
        self.state
    }

    /// Return `true` when the session may still process traffic
    /// (`Active` or `Rekeying`).
    pub fn is_usable(&self) -> bool {
        matches!(self.state, SessionState::Active | SessionState::Rekeying)
    }

    /// Transition to `Rekeying`; call before starting a rekey exchange.
    pub fn begin_rekey(&mut self) {
        self.state = SessionState::Rekeying;
    }

    /// Complete a rekey: install new keys and return to `Active`.
    ///
    /// Equivalent to `rotate_keys` + state transition.  Call after both
    /// sides have derived fresh keys from the ephemeral DH.
    pub fn complete_rekey(&mut self, new_send: [u8; 32], new_recv: [u8; 32]) {
        self.rotate(new_send, new_recv);
        self.state = SessionState::Active;
    }

    /// Mark the session as expired.  An expired session must not be used;
    /// all encrypt/decrypt calls will still execute but callers should check
    /// `is_usable()` before sending.
    pub fn expire(&mut self) {
        self.state = SessionState::Expired;
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

    /// Rotate keys (e.g., after a renegotiation) and reset all state.
    pub fn rotate(&mut self, new_send: [u8; 32], new_recv: [u8; 32]) {
        self.send_key = new_send;
        self.recv_key = new_recv;
        self.send_sequence = 0;
        self.last_recv_sequence = None;
        self.replay_window.reset();
    }

    /// Rotate keys using an explicit name.  Equivalent to `rotate`.
    pub fn rotate_keys(&mut self, new_send: [u8; 32], new_recv: [u8; 32]) {
        self.rotate(new_send, new_recv);
    }

    /// Decrypt a packet and enforce strictly-increasing sequence numbers.
    ///
    /// Unlike `decrypt_packet`, this method is `&mut self` and rejects any
    /// packet whose sequence number is ≤ the last accepted sequence.  Use it
    /// when you want the session itself to enforce anti-replay ordering.
    ///
    /// Returns `ReplayDetected` when `sequence <= last_recv_sequence`.
    pub fn decrypt_packet_in_order(
        &mut self,
        aad: &[u8],
        sequence: u64,
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        if self.last_recv_sequence.is_some_and(|last| sequence <= last) {
            return Err(SessionError::ReplayDetected);
        }
        let nonce = build_nonce(sequence);
        let plaintext = aead_open(&self.recv_key, &nonce, aad, ciphertext_and_tag)
            .map_err(|_| SessionError::AuthenticationFailed)?;
        self.last_recv_sequence = Some(sequence);
        Ok(plaintext)
    }

    /// Decrypt a packet using the 128-packet bitmap sliding window.
    ///
    /// Accepts out-of-order delivery within a 128-sequence window; rejects
    /// duplicates and packets older than 128 behind the highest seen.
    /// Returns `ReplayDetected` for both duplicates and too-old sequences.
    pub fn decrypt_packet_with_window(
        &mut self,
        aad: &[u8],
        sequence: u64,
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, SessionError> {
        self.replay_window
            .check_and_record(sequence)
            .map_err(|_| SessionError::ReplayDetected)?;
        let nonce = build_nonce(sequence);
        aead_open(&self.recv_key, &nonce, aad, ciphertext_and_tag)
            .map_err(|_| SessionError::AuthenticationFailed)
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
        keys.send_sequence = MAX_SEQUENCE + 1;
        assert_eq!(keys.remaining_packets(), 0);
    }

    // SK14: rotate_keys resets send sequence and last_recv_sequence
    #[test]
    fn sk14_rotate_keys_resets_sequence() {
        let mut keys = symmetric_keys();
        keys.encrypt_packet(b"", b"msg").unwrap();
        assert_eq!(keys.send_sequence(), 1);
        let new_send = [0x11u8; 32];
        let new_recv = [0x22u8; 32];
        keys.rotate_keys(new_send, new_recv);
        assert_eq!(
            keys.send_sequence(),
            0,
            "sequence must reset after rotate_keys"
        );
        assert!(
            keys.last_recv_sequence.is_none(),
            "last_recv_sequence must reset after rotate_keys"
        );
    }

    // SK15: rotating to new keys produces different ciphertext for same plaintext
    #[test]
    fn sk15_rotate_keys_changes_ciphertext() {
        let mut k = symmetric_keys();
        let ct_before = k.encrypt_packet(b"", b"test").unwrap();
        k.rotate_keys([0x55u8; 32], [0x55u8; 32]);
        let ct_after = k.encrypt_packet(b"", b"test").unwrap();
        assert_ne!(
            ct_before, ct_after,
            "new keys must produce different ciphertext"
        );
    }

    // SK16: after rotate_keys both sides can still encrypt/decrypt
    #[test]
    fn sk16_rotate_keys_decrypt_compatibility() {
        let new_key = [0xCCu8; 32];
        let mut sender = symmetric_keys();
        let mut receiver = symmetric_keys();
        sender.rotate_keys(new_key, new_key);
        receiver.rotate_keys(new_key, new_key);
        let ct = sender.encrypt_packet(b"aad", b"post-rotation").unwrap();
        let seq = sender.send_sequence() - 1;
        let plain = receiver.decrypt_packet(b"aad", seq, &ct).unwrap();
        assert_eq!(&plain, b"post-rotation");
    }

    // AE1: nonce exhaustion prevents further encryption
    #[test]
    fn ae1_nonce_exhaustion_blocks_encrypt() {
        let mut keys = symmetric_keys();
        keys.send_sequence = MAX_SEQUENCE + 1;
        assert_eq!(
            keys.encrypt_packet(b"", b"payload").unwrap_err(),
            SessionError::NonceExhausted
        );
    }

    // AE2: decrypt_packet_in_order rejects an exact replay (same sequence)
    #[test]
    fn ae2_replay_rejected_in_order() {
        let mut sender = symmetric_keys();
        let mut receiver = symmetric_keys();
        let ct = sender.encrypt_packet(b"", b"data").unwrap();
        receiver.decrypt_packet_in_order(b"", 0, &ct).unwrap();
        assert_eq!(
            receiver.decrypt_packet_in_order(b"", 0, &ct).unwrap_err(),
            SessionError::ReplayDetected
        );
    }

    // AE3: decrypt_packet_in_order rejects a lower sequence (out-of-order)
    #[test]
    fn ae3_out_of_order_rejected() {
        let mut sender = symmetric_keys();
        let mut receiver = symmetric_keys();
        let ct0 = sender.encrypt_packet(b"", b"p0").unwrap();
        let ct1 = sender.encrypt_packet(b"", b"p1").unwrap();
        let ct2 = sender.encrypt_packet(b"", b"p2").unwrap();
        receiver.decrypt_packet_in_order(b"", 2, &ct2).unwrap();
        assert_eq!(
            receiver.decrypt_packet_in_order(b"", 1, &ct1).unwrap_err(),
            SessionError::ReplayDetected
        );
        assert_eq!(
            receiver.decrypt_packet_in_order(b"", 0, &ct0).unwrap_err(),
            SessionError::ReplayDetected
        );
    }

    // DW1: decrypt_packet_with_window — roundtrip succeeds
    #[test]
    fn dw1_window_roundtrip() {
        let mut sender = symmetric_keys();
        let mut receiver = symmetric_keys();
        let ct = sender.encrypt_packet(b"w", b"hello").unwrap();
        let plain = receiver.decrypt_packet_with_window(b"w", 0, &ct).unwrap();
        assert_eq!(&plain, b"hello");
    }

    // DW2: decrypt_packet_with_window — duplicate sequence rejected
    #[test]
    fn dw2_window_replay_rejected() {
        let mut sender = symmetric_keys();
        let mut receiver = symmetric_keys();
        let ct = sender.encrypt_packet(b"", b"data").unwrap();
        receiver.decrypt_packet_with_window(b"", 0, &ct).unwrap();
        assert_eq!(
            receiver
                .decrypt_packet_with_window(b"", 0, &ct)
                .unwrap_err(),
            SessionError::ReplayDetected
        );
    }

    // DW3: decrypt_packet_with_window — out-of-order within window accepted
    #[test]
    fn dw3_window_out_of_order_accepted() {
        let mut sender = symmetric_keys();
        let mut receiver = symmetric_keys();
        // Send 3 packets in order, receive out-of-order.
        let ct0 = sender.encrypt_packet(b"", b"p0").unwrap();
        let ct1 = sender.encrypt_packet(b"", b"p1").unwrap();
        let ct2 = sender.encrypt_packet(b"", b"p2").unwrap();
        // Receive 2 first, then 0 and 1 (out-of-order but within window).
        receiver.decrypt_packet_with_window(b"", 2, &ct2).unwrap();
        receiver.decrypt_packet_with_window(b"", 0, &ct0).unwrap();
        receiver.decrypt_packet_with_window(b"", 1, &ct1).unwrap();
    }

    // SL1: initial state is Active
    #[test]
    fn sl1_initial_state_active() {
        let keys = symmetric_keys();
        assert_eq!(keys.state(), SessionState::Active);
        assert!(keys.is_usable());
    }

    // SL2: state transitions Active → Rekeying → Expired
    #[test]
    fn sl2_state_transitions() {
        let mut keys = symmetric_keys();
        keys.begin_rekey();
        assert_eq!(keys.state(), SessionState::Rekeying);
        assert!(keys.is_usable());
        keys.expire();
        assert_eq!(keys.state(), SessionState::Expired);
        assert!(!keys.is_usable());
    }

    // SL3: complete_rekey installs new keys and restores Active state
    #[test]
    fn sl3_complete_rekey_restores_active() {
        let new_key = [0xDDu8; 32];
        let mut sender = symmetric_keys();
        let mut receiver = symmetric_keys();

        sender.begin_rekey();
        assert_eq!(sender.state(), SessionState::Rekeying);

        sender.complete_rekey(new_key, new_key);
        receiver.complete_rekey(new_key, new_key);

        assert_eq!(sender.state(), SessionState::Active);
        assert_eq!(sender.send_sequence(), 0);

        // Keys work after rekey.
        let ct = sender.encrypt_packet(b"sl3", b"post-rekey").unwrap();
        let plain = receiver.decrypt_packet(b"sl3", 0, &ct).unwrap();
        assert_eq!(&plain, b"post-rekey");
    }
}
