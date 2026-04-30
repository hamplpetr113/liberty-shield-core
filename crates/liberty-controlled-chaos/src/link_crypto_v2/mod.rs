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
        }
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
}
