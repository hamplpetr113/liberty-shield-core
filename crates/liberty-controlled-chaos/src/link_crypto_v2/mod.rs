//! Link encryption v2 — per-link AEAD with sequence numbers, a replay window,
//! and a rekey trigger.
//!
//! `LinkSession` holds direction-separated send/recv keys derived from the
//! shared X25519 secret.  Each frame carries a sequence number; the receiver
//! maintains a bitmap replay window to reject duplicates.  A rekey is
//! signalled when `rekey_interval` sends have been completed.
//!
//! NON-PRODUCTION: frame "encryption" is HMAC-SHA256 of the payload.

use crate::crypto::hmac_sha256;

// ---------------------------------------------------------------------------
// Replay window (64-bit bitmap)
// ---------------------------------------------------------------------------

const WINDOW_SIZE: u64 = 64;

struct ReplayWindow {
    highest_seq: u64,
    bitmap: u64,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            highest_seq: 0,
            bitmap: 0,
        }
    }

    /// Returns `true` if the sequence number is valid (not a replay).
    fn check_and_advance(&mut self, seq: u64) -> bool {
        if seq > self.highest_seq {
            let shift = seq - self.highest_seq;
            self.bitmap = if shift >= WINDOW_SIZE {
                0
            } else {
                self.bitmap << shift
            };
            self.bitmap |= 1;
            self.highest_seq = seq;
            true
        } else {
            let diff = self.highest_seq - seq;
            if diff >= WINDOW_SIZE {
                return false; // too old
            }
            let bit = 1u64 << diff;
            if self.bitmap & bit != 0 {
                return false; // replay
            }
            self.bitmap |= bit;
            true
        }
    }
}

// ---------------------------------------------------------------------------
// LinkFrame
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkFrame {
    pub sequence: u64,
    pub payload: Vec<u8>,
    /// HMAC-SHA256(send_key, payload || sequence_le8).
    pub auth_tag: [u8; 32],
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkCryptoError {
    AuthenticationFailure,
    ReplayDetected,
    RekeyRequired,
}

// ---------------------------------------------------------------------------
// LinkSession
// ---------------------------------------------------------------------------

pub struct LinkSession {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_sequence: u64,
    replay_window: ReplayWindow,
    rekey_interval: u64,
    needs_rekey: bool,
    /// Logical identifier for this session (e.g. derived from handshake nonce).
    key_id: u32,
    /// Epoch at which this session was created.
    creation_epoch: u64,
    /// Maximum lifetime in epochs (0 = unlimited).
    max_lifetime_epochs: u64,
}

impl LinkSession {
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32], rekey_interval: u64) -> Self {
        Self {
            send_key,
            recv_key,
            send_sequence: 0,
            replay_window: ReplayWindow::new(),
            rekey_interval,
            needs_rekey: false,
            key_id: 0,
            creation_epoch: 0,
            max_lifetime_epochs: 0,
        }
    }

    /// Assign a key ID for session identification.
    pub fn with_key_id(mut self, id: u32) -> Self {
        self.key_id = id;
        self
    }

    /// Set the creation epoch and maximum lifetime in epochs.
    pub fn with_lifetime(mut self, creation_epoch: u64, max_lifetime_epochs: u64) -> Self {
        self.creation_epoch = creation_epoch;
        self.max_lifetime_epochs = max_lifetime_epochs;
        self
    }

    fn compute_tag(key: &[u8; 32], payload: &[u8], sequence: u64) -> [u8; 32] {
        let mut msg = Vec::with_capacity(payload.len() + 8);
        msg.extend_from_slice(payload);
        msg.extend_from_slice(&sequence.to_le_bytes());
        hmac_sha256(key, &msg)
    }

    /// Seal a payload into a `LinkFrame`.
    pub fn seal(&mut self, payload: Vec<u8>) -> Result<LinkFrame, LinkCryptoError> {
        if self.needs_rekey {
            return Err(LinkCryptoError::RekeyRequired);
        }
        let sequence = self.send_sequence;
        let auth_tag = Self::compute_tag(&self.send_key, &payload, sequence);
        self.send_sequence += 1;
        if self.rekey_interval > 0 && self.send_sequence.is_multiple_of(self.rekey_interval) {
            self.needs_rekey = true;
        }
        Ok(LinkFrame {
            sequence,
            payload,
            auth_tag,
        })
    }

    /// Open (verify + accept) a received `LinkFrame`.
    pub fn open(&mut self, frame: LinkFrame) -> Result<Vec<u8>, LinkCryptoError> {
        let expected = Self::compute_tag(&self.recv_key, &frame.payload, frame.sequence);
        if expected != frame.auth_tag {
            return Err(LinkCryptoError::AuthenticationFailure);
        }
        if !self.replay_window.check_and_advance(frame.sequence) {
            return Err(LinkCryptoError::ReplayDetected);
        }
        Ok(frame.payload)
    }

    /// Complete rekey: install new keys and reset counters.
    pub fn rekey(&mut self, new_send_key: [u8; 32], new_recv_key: [u8; 32]) {
        self.send_key = new_send_key;
        self.recv_key = new_recv_key;
        self.send_sequence = 0;
        self.replay_window = ReplayWindow::new();
        self.needs_rekey = false;
    }

    pub fn needs_rekey(&self) -> bool {
        self.needs_rekey
    }

    pub fn send_sequence(&self) -> u64 {
        self.send_sequence
    }

    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    pub fn creation_epoch(&self) -> u64 {
        self.creation_epoch
    }

    /// Returns `true` if this session has exceeded its maximum lifetime.
    pub fn is_expired(&self, current_epoch: u64) -> bool {
        self.max_lifetime_epochs > 0
            && current_epoch.saturating_sub(self.creation_epoch) >= self.max_lifetime_epochs
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> ([u8; 32], [u8; 32]) {
        ([0xAAu8; 32], [0xBBu8; 32])
    }

    fn session() -> LinkSession {
        let (sk, rk) = keys();
        LinkSession::new(sk, rk, 100)
    }

    fn loopback_session() -> LinkSession {
        // send and recv use same key for loopback test
        LinkSession::new([0xAAu8; 32], [0xAAu8; 32], 100)
    }

    // LC2_1: seal produces a frame.
    #[test]
    fn lc2_1_seal() {
        let mut s = session();
        let frame = s.seal(vec![1, 2, 3]).unwrap();
        assert_eq!(frame.sequence, 0);
        assert_eq!(frame.payload, vec![1, 2, 3]);
    }

    // LC2_2: open accepts a valid frame.
    #[test]
    fn lc2_2_open_valid() {
        let mut s = loopback_session();
        let frame = s.seal(vec![42]).unwrap();
        let data = s.open(frame).unwrap();
        assert_eq!(data, vec![42]);
    }

    // LC2_3: open rejects tampered auth_tag.
    #[test]
    fn lc2_3_tampered_tag_rejected() {
        let mut s = loopback_session();
        let mut frame = s.seal(vec![1]).unwrap();
        frame.auth_tag[0] ^= 0xFF;
        assert_eq!(s.open(frame), Err(LinkCryptoError::AuthenticationFailure));
    }

    // LC2_4: replay is rejected.
    #[test]
    fn lc2_4_replay_rejected() {
        let mut s = loopback_session();
        let frame = s.seal(vec![1]).unwrap();
        // clone and open twice
        let frame2 = frame.clone();
        s.open(frame).unwrap();
        assert_eq!(s.open(frame2), Err(LinkCryptoError::ReplayDetected));
    }

    // LC2_5: send_sequence increments per frame.
    #[test]
    fn lc2_5_sequence_increments() {
        let mut s = session();
        s.seal(vec![]).unwrap();
        s.seal(vec![]).unwrap();
        assert_eq!(s.send_sequence(), 2);
    }

    // LC2_6: rekey trigger fires at interval.
    #[test]
    fn lc2_6_rekey_trigger() {
        let (sk, rk) = keys();
        let mut s = LinkSession::new(sk, rk, 2);
        s.seal(vec![]).unwrap(); // seq=0
        s.seal(vec![]).unwrap(); // seq=1 → 2 sends → needs_rekey
        assert!(s.needs_rekey());
    }

    // LC2_7: seal returns RekeyRequired when rekey needed.
    #[test]
    fn lc2_7_seal_blocked_after_rekey_needed() {
        let (sk, rk) = keys();
        let mut s = LinkSession::new(sk, rk, 1);
        s.seal(vec![]).unwrap(); // seq=0 → 1 send → needs_rekey
        assert_eq!(s.seal(vec![]), Err(LinkCryptoError::RekeyRequired));
    }

    // LC2_8: rekey resets sequence and allows sending.
    #[test]
    fn lc2_8_rekey_resets() {
        let (sk, rk) = keys();
        let mut s = LinkSession::new(sk, rk, 1);
        s.seal(vec![]).unwrap();
        s.rekey([0xCCu8; 32], [0xCCu8; 32]);
        assert_eq!(s.send_sequence(), 0);
        assert!(!s.needs_rekey());
    }

    // LC2_9: direction-separated keys: wrong recv key fails auth.
    #[test]
    fn lc2_9_direction_keys_separated() {
        let mut s = session(); // send=[AA], recv=[BB] — different keys
        let frame = s.seal(vec![5]).unwrap();
        // open with wrong recv key → auth failure
        assert_eq!(s.open(frame), Err(LinkCryptoError::AuthenticationFailure));
    }

    // LC2_10: out-of-order frames (within window) are accepted.
    #[test]
    fn lc2_10_out_of_order_accepted() {
        let mut s = loopback_session();
        let f0 = s.seal(vec![0]).unwrap();
        let f1 = s.seal(vec![1]).unwrap();
        // deliver out of order
        s.open(f1).unwrap();
        s.open(f0).unwrap();
    }

    // LC2_11: key_id defaults to 0.
    #[test]
    fn lc2_11_key_id_default() {
        let s = session();
        assert_eq!(s.key_id(), 0);
    }

    // LC2_12: with_key_id stores and returns the key ID.
    #[test]
    fn lc2_12_key_id_set() {
        let (sk, rk) = keys();
        let s = LinkSession::new(sk, rk, 100).with_key_id(42);
        assert_eq!(s.key_id(), 42);
    }

    // LC2_13: session not expired within lifetime.
    #[test]
    fn lc2_13_session_not_expired() {
        let (sk, rk) = keys();
        let s = LinkSession::new(sk, rk, 0).with_lifetime(10, 100);
        assert!(!s.is_expired(50)); // 50 - 10 = 40 < 100
    }

    // LC2_14: session expired after lifetime.
    #[test]
    fn lc2_14_session_expired() {
        let (sk, rk) = keys();
        let s = LinkSession::new(sk, rk, 0).with_lifetime(10, 50);
        assert!(s.is_expired(60)); // 60 - 10 = 50 >= 50
    }

    // LC2_15: session with max_lifetime=0 never expires.
    #[test]
    fn lc2_15_no_expiry() {
        let (sk, rk) = keys();
        let s = LinkSession::new(sk, rk, 0).with_lifetime(0, 0);
        assert!(!s.is_expired(u64::MAX));
    }

    // LC2_16: replay window boundary — sequence too old is rejected.
    #[test]
    fn lc2_16_replay_window_boundary() {
        let mut s = loopback_session();
        // Save the seq=0 frame before it gets consumed.
        let f0 = s.seal(vec![0]).unwrap();
        let saved_f0 = f0.clone();
        s.open(f0).unwrap();
        // Advance window by 64 more frames so seq=0 falls outside.
        for i in 1u8..=64 {
            let f = s.seal(vec![i]).unwrap();
            s.open(f).unwrap();
        }
        // seq=0 is now beyond the 64-frame window — replay rejection.
        assert_eq!(s.open(saved_f0), Err(LinkCryptoError::ReplayDetected));
    }

    // LC2_17: tampered payload (not tag) triggers auth failure.
    #[test]
    fn lc2_17_tampered_payload_rejected() {
        let mut s = loopback_session();
        let mut frame = s.seal(vec![1, 2, 3]).unwrap();
        frame.payload[0] ^= 0x01; // flip one bit in payload
        assert_eq!(s.open(frame), Err(LinkCryptoError::AuthenticationFailure));
    }

    // LC2_18: creation_epoch stored correctly.
    #[test]
    fn lc2_18_creation_epoch_stored() {
        let (sk, rk) = keys();
        let s = LinkSession::new(sk, rk, 0).with_lifetime(42, 100);
        assert_eq!(s.creation_epoch(), 42);
    }

    // LC2_19: rekey after expiry allows sending with new keys.
    #[test]
    fn lc2_19_rekey_clears_expiry_state() {
        let (sk, rk) = keys();
        let mut s = LinkSession::new(sk, rk, 1).with_lifetime(0, 5);
        // Trigger needs_rekey.
        s.seal(vec![]).unwrap();
        assert!(s.needs_rekey());
        // Rekey clears needs_rekey (expiry is separate field; caller must re-set lifetime).
        s.rekey([0xEEu8; 32], [0xEEu8; 32]);
        assert!(!s.needs_rekey());
        // Can send again.
        s.seal(vec![99]).unwrap();
    }

    // LC2_20: tampered sequence number causes auth failure (tag covers sequence).
    #[test]
    fn lc2_20_tampered_sequence_rejected() {
        let mut s = loopback_session();
        let mut frame = s.seal(vec![5]).unwrap();
        frame.sequence += 1; // change the sequence without updating the tag
        assert_eq!(s.open(frame), Err(LinkCryptoError::AuthenticationFailure));
    }
}
